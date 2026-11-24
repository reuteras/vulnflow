"""What the Debian security tracker says about open findings on Debian components.

Old CVEs on Debian-based images (and hosts) are often ones Debian has triaged as
`unimportant` or `end-of-life`, or has already fixed in its own package version while NVD
still shows the upstream range as vulnerable. NVD-only scanners flag them anyway.

Source: https://security-tracker.debian.org/tracker/data/json, one public file, downloaded
and cached; nothing about your components is sent. Shape (checked against a download,
2026-11-24):

    {source_package: {"CVE-YYYY-N": {"releases": {codename: {"status": "open|resolved|
     undetermined", "urgency": "unimportant|low|medium|high|end-of-life|not yet assigned",
     "fixed_version": "...", "repositories": {suite: version},
     "nodsa": "Minor issue", "nodsa_reason": "|postponed|ignored",
     "next_point_update": true}}}}}

`nodsa`, `nodsa_reason` and `next_point_update` appear only on some entries; they say why an
open entry has no security update (`note` on the row).

Each match also gets an `action`, by comparing the installed version with the tracker's
`fixed_version` (Debian version order, vulnflow/debver.py):

    update   installed is older than the fix: an update is available
    fixed    installed is the fix or newer: Debian already fixed it here (NVD's upstream range
             ignores backports), a candidate for `vulnflow ignore`. fixed_version "0" means
             Debian says this release was never affected.
    no-fix   open or undetermined in Debian, no fix yet
    unknown  cannot compare safely (resolved without a version, or only one side has an epoch)

The installed version is the *source* version from the purl's `upstream=` when present (the
tracker works on source packages), else the component version. The verdicts were checked by
hand against the tracker for 17 rows of 5 packages on bookworm and trixie (2026-11-24),
including epochs, `~debNNuN` and `+debNNuN`. Not yet seen on real findings: fixed_version
"0" and a purl `upstream=` that carries a version.

The tracker is keyed by *source* package. A finding is matched on its CVE id plus the
component's own deb name or the `upstream=` source name in its purl (syft writes it), and the
release comes from the purl's `distro=debian-13` (or --release). No match means no answer,
never a guess.
"""

from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, unquote

from . import debver
from .clients import DependencyTrack
from .config import Inventory
from .net import Http, Transport
from .patches import open_findings

log = logging.getLogger(__name__)

TRACKER_URL = "https://security-tracker.debian.org/tracker/data/json"
CODENAMES = {"10": "buster", "11": "bullseye", "12": "bookworm", "13": "trixie", "14": "forky"}
IGNORABLE = ("unimportant", "end-of-life")
_URGENCY_ORDER = ("high", "medium", "low", "not yet assigned", "unimportant", "end-of-life")


@dataclass
class DebianInfo:
    package: str
    release: str
    status: str
    urgency: str
    fixed: str
    note: str = ""


def tracker_note(rel: dict[str, Any]) -> str:
    """Debian's reason an entry has no security update yet, from `nodsa`, `nodsa_reason` and
    `next_point_update`; "" when the tracker gives none."""
    parts = []
    if rel.get("next_point_update"):
        parts.append("fix queued for the next point release")
    nodsa = str(rel.get("nodsa") or "").strip()
    if nodsa:
        why = str(rel.get("nodsa_reason") or "").strip()
        parts.append(f"no DSA: {nodsa}" + (f" [{why}]" if why else ""))
    return "; ".join(parts)


@dataclass
class DebianFinding:
    team: str
    project: str
    component: str
    version: str
    vuln_id: str
    severity: str
    package: str
    release: str
    status: str
    urgency: str
    fixed: str
    # what `ignore` needs to write an analysis back to Dependency-Track
    project_uuid: str = ""
    component_uuid: str = ""
    vuln_uuid: str = ""
    installed: str = ""  # the version that was compared with `fixed`
    action: str = "unknown"  # update | fixed | no-fix | unknown
    note: str = ""  # why Debian has no fix yet (no-dsa, next point release), when it says
    project_version: str = ""


class DebianTracker:
    """Downloads the tracker JSON and caches it on disk (default TTL 24 h)."""

    def __init__(
        self,
        cache_dir: Path,
        transport: Transport | None = None,
        ttl_seconds: int = 24 * 3600,
        url: str = TRACKER_URL,
    ):
        self.path = cache_dir / "debian-tracker.json"
        self.ttl = ttl_seconds
        self.http = Http(url, transport=transport, timeout=180)
        self._index: dict[str, dict[str, dict[str, Any]]] | None = None

    def _fresh_on_disk(self) -> bool:
        return self.path.is_file() and (time.time() - self.path.stat().st_mtime) < self.ttl

    def index(self) -> dict[str, dict[str, dict[str, Any]]]:
        """{CVE id: {source package: releases}}"""
        if self._index is not None:
            return self._index
        if not self._fresh_on_disk():
            r = self.http.get("")
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self.path.write_bytes(r.body)
        data = json.loads(self.path.read_bytes())
        idx: dict[str, dict[str, dict[str, Any]]] = {}
        for pkg, cves in data.items():
            for cve, info in (cves or {}).items():
                if cve.startswith("CVE-"):
                    idx.setdefault(cve, {})[pkg.lower()] = (info or {}).get("releases") or {}
        self._index = idx
        log.info("Debian tracker loaded: %d CVEs", len(idx))
        return idx

    def lookup(self, cve: str, packages: set[str], release: str) -> DebianInfo | None:
        by_pkg = self.index().get(cve.upper()) or {}
        for pkg in sorted(packages):
            rel = (by_pkg.get(pkg) or {}).get(release)
            if rel:
                return DebianInfo(
                    package=pkg,
                    release=release,
                    status=str(rel.get("status") or ""),
                    urgency=str(rel.get("urgency") or ""),
                    fixed=str(rel.get("fixed_version") or ""),
                    note=tracker_note(rel),
                )
        return None


def parse_deb_purl(purl: str) -> tuple[set[str], str] | None:
    """(candidate source/binary package names, release codename or "") for a Debian purl;
    None for anything that isn't pkg:deb/debian/..."""
    if not purl.startswith("pkg:deb/debian/"):
        return None
    path, _, query = purl.partition("?")
    name = unquote(path.split("/", 2)[2].split("@", 1)[0]).lower()
    q = parse_qs(query)
    names = {name}
    upstream = (q.get("upstream") or [""])[0]
    if upstream:
        names.add(unquote(upstream).split("@", 1)[0].lower())
    distro = ((q.get("distro") or [""])[0]).removeprefix("debian-")
    release = CODENAMES.get(distro.split(".", 1)[0], distro if distro in CODENAMES.values() else "")
    return names, release


ACTIONS = ("update", "fixed", "no-fix", "unknown")


def installed_version(purl: str, component_version: str) -> str:
    """Source version from the purl's upstream=name@version if there is one, else the
    component's own version."""
    upstream = (parse_qs(purl.partition("?")[2]).get("upstream") or [""])[0]
    _, at, ver = unquote(upstream).partition("@")
    return ver if at and ver else component_version


def fix_action(installed: str, status: str, fixed: str) -> str:
    """One of ACTIONS; see the module docstring."""
    if fixed:
        if not installed or debver.has_epoch(installed) != debver.has_epoch(fixed):
            return "unknown"  # a missing epoch would make every comparison wrong
        return "update" if debver.compare(installed, fixed) < 0 else "fixed"
    return "no-fix" if status in ("open", "undetermined") else "unknown"


def debian_findings(
    inv: Inventory,
    dt: DependencyTrack,
    tracker: DebianTracker,
    team: str | None = None,
    release: str | None = None,
    ignorable_only: bool = False,
) -> tuple[list[DebianFinding], int, list[str]]:
    """(findings the tracker has an entry for, CVE findings on Debian components it has none
    for, errors). CVE findings on non-Debian components are not counted."""
    rows: list[DebianFinding] = []
    errors: list[str] = []
    unmatched = 0
    try:
        tracker.index()
    except Exception as e:
        return [], 0, [f"Debian tracker: {e}"]
    for key, proj, f in open_findings(inv, dt, team, errors):
        v: dict[str, Any] = f.get("vulnerability") or {}
        vid = str(v.get("vulnId") or "")
        c: dict[str, Any] = f.get("component") or {}
        parsed = parse_deb_purl(str(c.get("purl") or ""))
        if not vid.startswith("CVE-") or parsed is None:
            continue
        names, purl_release = parsed
        info = tracker.lookup(vid, names, release or purl_release) if (release or purl_release) else None
        if info is None:
            unmatched += 1
            continue
        if ignorable_only and info.urgency not in IGNORABLE:
            continue
        installed = installed_version(str(c.get("purl") or ""), str(c.get("version") or ""))
        rows.append(
            DebianFinding(
                team=key,
                project=proj.name,
                project_version=proj.version,
                component=c.get("name", ""),
                version=c.get("version", ""),
                vuln_id=vid,
                severity=v.get("severity", ""),
                package=info.package,
                release=info.release,
                status=info.status,
                urgency=info.urgency,
                fixed=info.fixed,
                note=info.note,
                project_uuid=proj.uuid,
                component_uuid=str(c.get("uuid") or ""),
                vuln_uuid=str(v.get("uuid") or ""),
                installed=installed,
                action=fix_action(installed, info.status, info.fixed),
            )
        )
    rank = {u: i for i, u in enumerate(_URGENCY_ORDER)}
    rows.sort(key=lambda r: (rank.get(r.urgency, 99), r.team, r.project, r.component, r.vuln_id))
    return rows, unmatched, errors
