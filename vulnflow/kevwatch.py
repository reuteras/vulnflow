"""New KEV entries -> chat, with what they hit in our estate (`vulnflow kev-watch`).

The catalog is CISA KEV, plus VulnCheck KEV when VULNCHECK_API_TOKEN is set (intel.py);
each entry is labelled with the catalog that lists it ("CISA KEV" when both do).

The receiver only hears about a KEV addition when OpenCVE reports a change for a product a
team follows. This watches the catalog itself: every run compares it with the CVE IDs seen
before (`kev-seen.json` in the data directory) and, for each new entry, looks for

- open Dependency-Track findings with that CVE (the team, project and component), and
- teams whose OpenCVE subscriptions name the vendor. KEV names vendors for people
  ("Palo Alto Networks"), NVD with slugs (`paloaltonetworks`); both are compared with
  everything but letters and digits removed. Vendor level only: KEV's product names
  don't map onto NVD's.

The team channel gets the entries that hit something, mentioning the teams; the SOC
channel (VULNFLOW_SOC_WEBHOOK) gets every new entry. The first run only records what is
in the catalog, so it doesn't post the whole list; the same goes for the first run with a
new source (adding a VulnCheck token would otherwise post its 4000+ extra entries). An
entry counts as seen once its messages were delivered, so a failed delivery is retried on
the next run. A CVE is seen once, whichever catalog listed it first: VulnCheck often lists
one before CISA, and CISA adding it later is not posted again.
"""

from __future__ import annotations

import json
import logging
import re
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .config import Inventory
from .intel import CISA

log = logging.getLogger(__name__)
STATE_FILE = "kev-seen.json"
LOG_FILE = "kev-new.jsonl"  # next to the state: one line per entry posted, for the reports

# (team, project label, component and version, CVE id) of one open finding
Finding = tuple[str, str, str, str]


def _norm(s: str) -> str:
    return re.sub(r"[^a-z0-9]", "", s.lower())


@dataclass
class KevHit:
    cve: str
    vendor: str
    product: str
    name: str
    date_added: str
    ransomware: bool
    source: str = CISA  # the catalog that lists it: CISA or VulnCheck
    findings: dict[str, list[str]] = field(default_factory=dict)  # team -> "project: component"
    follows: list[str] = field(default_factory=list)  # teams following the vendor

    @property
    def matched(self) -> bool:
        return bool(self.findings or self.follows)

    def teams(self) -> list[str]:
        return sorted(set(self.findings) | set(self.follows))

    def where(self) -> str:
        found = [f"findings in {t}" for t in sorted(self.findings)]
        return ", ".join([*found, *(f"{t} follows" for t in self.follows)]) or "nothing of ours"


@dataclass
class WatchResult:
    baseline: int = 0  # first run (of a source): entries recorded, nothing posted
    baseline_sources: list[str] = field(default_factory=list)
    new: list[KevHit] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


def load_seen(path: Path) -> tuple[set[str], set[str]] | None:
    """(the CVE IDs seen before, the sources they came from), or None on the first run. A
    file written before VulnCheck support has no `sources`: it was CISA's."""
    if not path.is_file():
        return None
    data = json.loads(path.read_text(encoding="utf-8"))
    sources = {str(x) for x in data.get("sources", [CISA])}
    return {str(c).upper() for c in data.get("seen", [])}, sources


def save_seen(path: Path, seen: set[str], sources: set[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(
        json.dumps({"seen": sorted(seen), "sources": sorted(sources)}) + "\n", encoding="utf-8"
    )
    tmp.replace(path)


def _source(e: dict[str, Any]) -> str:
    return str(e.get("kevSource") or CISA)


def followers(inv: Inventory, vendor: str) -> list[str]:
    """Teams whose OpenCVE subscriptions (vendors, or products of a vendor) name it."""
    v = _norm(vendor)
    return sorted(
        key for key, t in inv.teams.items() if v and v in {_norm(x) for x in [*t.vendors, *t.products]}
    )


def match(inv: Inventory, entries: list[dict[str, Any]], findings: Iterable[Finding]) -> list[KevHit]:
    by_cve: dict[str, dict[str, list[str]]] = {}
    for team, project, component, cve in findings:
        by_cve.setdefault(cve.upper(), {}).setdefault(team, []).append(f"{project}: {component}")
    hits = []
    for e in entries:
        cve = str(e.get("cveID", "")).upper()
        vendor = str(e.get("vendorProject", ""))
        hits.append(
            KevHit(
                cve=cve,
                vendor=vendor,
                product=str(e.get("product", "")),
                name=str(e.get("vulnerabilityName", "")),
                date_added=str(e.get("dateAdded", "")),
                ransomware=str(e.get("knownRansomwareCampaignUse", "")).lower() == "known",
                source=_source(e),
                findings={t: sorted(set(v)) for t, v in by_cve.get(cve, {}).items()},
                follows=followers(inv, vendor),
            )
        )
    return hits


def _head(h: KevHit) -> str:
    extra = ", ransomware use" if h.ransomware else ""
    return f"{h.cve} {h.vendor} {h.product}: {h.name} ({h.source} KEV, added {h.date_added}{extra})"


def format_team(hits: list[KevHit], inv: Inventory, opencve_url: str = "") -> str | None:
    """The team channel: new entries that hit an open finding or a followed vendor."""
    hot = [h for h in hits if h.matched]
    if not hot:
        return None
    mentions = sorted(
        {inv.teams[t].chat_mention for h in hot for t in h.teams() if t in inv.teams} - {""}
    )
    lines = [f"{' '.join(mentions) + ' ' if mentions else ''}New in KEV ({len(hot)}):"]
    for h in hot:
        link = f" {opencve_url.rstrip('/')}/cve/{h.cve}" if opencve_url else ""
        lines.append(f"- {_head(h)}{link}")
        for team, where in sorted(h.findings.items()):
            shown = "; ".join(where[:3]) + (f" (+{len(where) - 3} more)" if len(where) > 3 else "")
            lines.append(f"  open finding, team {team}: {shown}")
        if h.follows:
            lines.append(f"  vendor followed by: {', '.join(h.follows)}")
    return "\n".join(lines)


def format_soc(hits: list[KevHit]) -> str | None:
    """The SOC channel: every new entry, with what it hits."""
    if not hits:
        return None
    lines = [f"SOC: new in KEV ({len(hits)}):"]
    for h in hits:
        lines.append(f"- {_head(h)} -> {h.where()}")
    return "\n".join(lines)


def watch(
    inv: Inventory,
    index: dict[str, dict[str, Any]],
    state: Path,
    findings: Callable[[], Iterable[Finding]],
    team_send: Callable[[str], None] | None = None,
    soc_send: Callable[[str], None] | None = None,
    *,
    opencve_url: str = "",
    dry_run: bool = False,
) -> WatchResult:
    """One run: new KEV entries since the last one, matched and posted. findings is only
    called when there is something new (it asks Dependency-Track)."""
    res = WatchResult()
    current = {c.upper() for c in index}
    sources = {_source(e) for e in index.values()}
    loaded = load_seen(state)
    if loaded is None:
        res.baseline, res.baseline_sources = len(current), sorted(sources)
        if not dry_run:
            save_seen(state, current, sources)
        return res
    seen, known = loaded
    unseen = current - seen
    # a source seen for the first time: record its entries, don't post them
    quiet = {c for c in unseen if _source(index[c]) not in known}
    if quiet:
        res.baseline, res.baseline_sources = len(quiet), sorted(sources - known)
        seen = seen | quiet
        if not dry_run:
            save_seen(state, seen, known | sources)
    known = known | sources
    fresh = sorted(unseen - quiet, key=lambda c: (str(index[c].get("dateAdded", "")), c))
    if not fresh:
        return res
    try:
        found = list(findings())
    except Exception as e:
        res.errors.append(f"Dependency-Track findings: {e}")
        found = []
    res.new = match(inv, [index[c] for c in fresh], found)
    if dry_run:
        return res
    delivered = True
    for send, msg, what in (
        (team_send, format_team(res.new, inv, opencve_url), "chat"),
        (soc_send, format_soc(res.new), "SOC chat"),
    ):
        if send is None or msg is None:
            continue
        try:
            send(msg)
        except Exception as e:
            delivered = False
            res.errors.append(f"{what} delivery failed: {e}")
    if delivered:
        append_log(state.parent / LOG_FILE, res.new)
        save_seen(state, seen | set(fresh), known)
    return res


def append_log(path: Path, hits: list[KevHit], now: datetime | None = None) -> None:
    """One JSON line per new entry, read by `vulnflow report` (the new-KEV section)."""
    at = (now or datetime.now(UTC)).isoformat(timespec="seconds")
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as f:
        for h in hits:
            line = {
                "seen_at": at,
                "cve": h.cve,
                "vendor": h.vendor,
                "product": h.product,
                "name": h.name,
                "date_added": h.date_added,
                "ransomware": h.ransomware,
                "source": h.source,
                "findings": h.findings,
                "follows": h.follows,
            }
            f.write(json.dumps(line, ensure_ascii=False) + "\n")
