"""Daily and weekly email digests (`vulnflow report daily|weekly`).

`./poc.sh report <kind>` runs this and mails the output with the host's own `sendmail`;
`./poc.sh schedule install` sets up the systemd timers in deploy/timers/ that call it.
Nothing here sends mail or talks to Docker: poc.sh passes the receiver's alerts.jsonl in.

Sections:

    updates    check-updates lines that need action (daily) or all of them (weekly)
    alerts     P1/P2 alerts the receiver logged since the last report of this kind
               (OpenCVE watch path)
    findings   Dependency-Track findings that are new or gone since the last report of
               this kind (match path). The daily lists new critical/high/KEV ones; the
               weekly lists those, counts the rest and the resolved ones, and adds the
               open totals per team
    machines   own hosts that stopped pushing SBOMs

A finding is keyed on team, project name, component name and vulnerability id, not on
the versions: a new image tag or package version that still has the CVE is not "new".
The state (last alert time, the previous findings) is kept per kind in
data/report-state.json, so the weekly compares with last week's run, not yesterday's.
The first run of a kind only records a baseline.

Exit code: 0, or 1 when a section could not be built (the error is in the report).
"""

from __future__ import annotations

import json
import os
import time
from collections import Counter
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .clients import DependencyTrack
from .config import Inventory, Machines
from .machines import host_scans, project_name
from .patches import open_findings
from .upstreams import Status

KINDS = ("daily", "weekly")
IMPORTANT = ("CRITICAL", "HIGH")
SEVERITY_ORDER = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "UNASSIGNED")
LIST_MAX = 40  # listed lines per section; the rest is counted


@dataclass
class Section:
    title: str
    lines: list[str] = field(default_factory=list)
    notable: bool = False  # something to act on: a quiet daily is not sent without one
    error: bool = False


@dataclass
class OpenFinding:
    team: str
    project: str
    project_version: str
    component: str
    version: str
    vuln_id: str
    severity: str

    @property
    def key(self) -> str:
        return "|".join((self.team, self.project, self.component, self.vuln_id))

    def to_json(self) -> dict[str, str]:
        return {
            "pv": self.project_version,
            "v": self.version,
            "sev": self.severity,
        }

    def label(self, kev: bool) -> str:
        where = f"{self.project}@{self.project_version}" if self.project_version else self.project
        mark = " KEV" if kev else ""
        return f"  {self.severity:<8} {self.vuln_id}{mark}  {self.component} {self.version}  ({where})"


def _cut(lines: list[str], limit: int = LIST_MAX) -> list[str]:
    if len(lines) <= limit:
        return lines
    return [*lines[:limit], f"  ... and {len(lines) - limit} more"]


# ---- updates ---------------------------------------------------------------------------


def updates_section(statuses: list[Status], *, everything: bool) -> Section:
    s = Section("Upstream updates")
    for st in statuses:
        if st.actionable or st.error:
            s.notable = True
            s.lines += st.lines()
        elif everything:
            s.lines += st.lines()
    if not s.lines:
        s.lines.append("Nothing to do.")
    return s


# ---- alerts ----------------------------------------------------------------------------


def alerts_section(lines: Iterable[str], since: str, max_tier: int = 2) -> tuple[Section, str]:
    """P1..P<max_tier> alerts received after `since` (ISO 8601; empty = all), one line per
    team and CVE with the highest tier. Returns the section and the newest received_at."""
    s = Section(f"New P1-P{max_tier} alerts from OpenCVE")
    newest = since
    best: dict[tuple[str, str], dict[str, Any]] = {}
    for raw in lines:
        raw = raw.strip()
        if not raw:
            continue
        try:
            a = json.loads(raw)
        except ValueError:
            continue
        at = str(a.get("received_at", ""))
        newest = max(newest, at)
        if (since and at <= since) or int(a.get("tier", 9)) > max_tier:
            continue
        k = (str(a.get("team", "")), str(a.get("cve", "")))
        if k not in best or int(a["tier"]) < int(best[k]["tier"]):
            best[k] = a
    for (team, cve), a in sorted(best.items(), key=lambda kv: (kv[1]["tier"], kv[0])):
        epss = a.get("epss")
        cvss = a.get("cvss31")
        bits = [
            f"CVSS {cvss}" if cvss is not None else "CVSS n/a",
            "KEV" if a.get("kev") else "",
            f"EPSS {epss:.3f}" if isinstance(epss, int | float) else "",
        ]
        s.lines.append(
            f"  [{a.get('tier_name', '')}] {cve}  team {team}  {' '.join(b for b in bits if b)}"
        )
    s.notable = bool(best)
    if not best:
        s.lines.append("None.")
    s.lines = _cut(s.lines)
    return s, newest


# ---- findings --------------------------------------------------------------------------


def collect_findings(inv: Inventory, dt: DependencyTrack, errors: list[str]) -> dict[str, OpenFinding]:
    out: dict[str, OpenFinding] = {}
    for team, p, f in open_findings(inv, dt, None, errors):
        comp, vuln = f.get("component") or {}, f.get("vulnerability") or {}
        of = OpenFinding(
            team=team,
            project=p.name,
            project_version=p.version,
            component=str(comp.get("name", "")),
            version=str(comp.get("version", "")),
            vuln_id=str(vuln.get("vulnId", "")),
            severity=str(vuln.get("severity") or "UNASSIGNED").upper(),
        )
        out.setdefault(of.key, of)
    return out


def _sev_rank(sev: str) -> int:
    return SEVERITY_ORDER.index(sev) if sev in SEVERITY_ORDER else len(SEVERITY_ORDER)


def findings_section(
    previous: dict[str, Any] | None,
    current: dict[str, OpenFinding],
    kev: set[str],
    *,
    weekly: bool,
) -> Section:
    s = Section("Dependency-Track findings")
    if previous is None:
        s.lines.append(
            f"First report: baseline of {len(current)} open findings recorded; changes are "
            "listed from the next one."
        )
        return s
    new = [current[k] for k in current.keys() - previous.keys()]
    gone = previous.keys() - current.keys()
    important = [f for f in new if f.severity in IMPORTANT or f.vuln_id in kev]
    important.sort(key=lambda f: (f.vuln_id not in kev, _sev_rank(f.severity), f.team, f.vuln_id))
    s.notable = bool(important)
    s.lines.append(
        f"{len(new)} new, {len(gone)} resolved or suppressed since the last "
        f"{'weekly' if weekly else 'daily'} report; {len(important)} new critical/high/KEV:"
    )
    s.lines += _cut([f.label(f.vuln_id in kev) for f in important]) or ["  none"]
    if weekly:
        listed = {f.key for f in important}
        rest = Counter(f.team for f in new if f.key not in listed)
        if rest:
            s.lines.append(
                "Other new findings per team: " + ", ".join(f"{t} {n}" for t, n in sorted(rest.items()))
            )
        resolved = Counter(k.split("|", 1)[0] for k in gone)
        if resolved:
            s.lines.append(
                "Resolved per team: " + ", ".join(f"{t} {n}" for t, n in sorted(resolved.items()))
            )
        s.lines.append("Open findings per team:")
        per: dict[str, Counter[str]] = {}
        for f in current.values():
            per.setdefault(f.team, Counter())[f.severity] += 1
        for team, c in sorted(per.items()):
            parts = [f"{sev.lower()} {c[sev]}" for sev in SEVERITY_ORDER if c[sev]]
            s.lines.append(f"  {team:<10} {sum(c.values()):>5}  ({', '.join(parts)})")
    return s


# ---- machines --------------------------------------------------------------------------


def machines_section(
    machines: Machines, pushes: dict[str, float], stale_days: float, now: float | None = None
) -> Section:
    now = time.time() if now is None else now
    s = Section(f"Hosts that stopped pushing (more than {stale_days:g} days)")
    for m in sorted(machines.hosts.values(), key=lambda m: (m.group, m.name)):
        if not host_scans(m):
            continue
        seen = pushes.get(project_name(m))
        if seen is None:
            s.lines.append(f"  {m.name:<20} {m.team:<8} never pushed")
        elif (now - seen) / 86400 > stale_days:
            s.lines.append(f"  {m.name:<20} {m.team:<8} last push {(now - seen) / 86400:.1f} days ago")
    s.notable = bool(s.lines)
    if not s.lines:
        s.lines.append("None.")
    return s


# ---- state and output ------------------------------------------------------------------


def load_state(path: Path) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def save_state(path: Path, state: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(state, f, separators=(",", ":"))
    tmp.replace(path)


def render(kind: str, sections: list[Section], now: datetime | None = None) -> str:
    now = now or datetime.now(UTC)
    out = [f"vulnflow {kind} report, {now:%Y-%m-%d %H:%M} UTC", ""]
    for s in sections:
        out += [f"== {s.title}{' (ERROR)' if s.error else ''}", *s.lines, ""]
    return "\n".join(out).rstrip() + "\n"


def error_section(title: str, message: str) -> Section:
    return Section(title, [f"  {message}"], notable=True, error=True)
