"""What the Debian security tracker says about open findings on Debian components.

Old CVEs on Debian-based images (and hosts) are often ones Debian has triaged as
`unimportant` or `end-of-life`, or has already fixed in its own package version while NVD
still shows the upstream range as vulnerable. NVD-only scanners flag them anyway.

Source: https://security-tracker.debian.org/tracker/data/json, one public file, downloaded
and cached; nothing about your components is sent. Shape (ASSUMED from memory, not checked
against a download in this repo):

    {source_package: {"CVE-YYYY-N": {"releases": {codename: {"status": "open|resolved|
     undetermined", "urgency": "unimportant|low|medium|high|end-of-life|not yet assigned",
     "fixed_version": "..."}}}}}

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
    for key, project, f in open_findings(inv, dt, team, errors):
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
        rows.append(
            DebianFinding(
                team=key,
                project=project,
                component=c.get("name", ""),
                version=c.get("version", ""),
                vuln_id=vid,
                severity=v.get("severity", ""),
                package=info.package,
                release=info.release,
                status=info.status,
                urgency=info.urgency,
                fixed=info.fixed,
            )
        )
    rank = {u: i for i, u in enumerate(_URGENCY_ORDER)}
    rows.sort(key=lambda r: (rank.get(r.urgency, 99), r.team, r.project, r.component, r.vuln_id))
    return rows, unmatched, errors
