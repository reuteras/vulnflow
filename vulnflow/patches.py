"""Which open Dependency-Track findings have a patched release.

DT only knows a fix version when the vulnerability source supplied one (GitHub advisories,
OSV); NVD entries have none. "No patched version recorded" therefore means *unknown*, not
"no fix exists".

With an OSV client, findings DT has no fix for are looked up on osv.dev by the component's
package URL (marked via="osv"). That sends package URLs to an outside service.
"""

from __future__ import annotations

import logging
from collections.abc import Iterator
from dataclasses import dataclass
from typing import Any

from .clients import OSV, DependencyTrack
from .config import Inventory

log = logging.getLogger(__name__)


@dataclass
class PatchedFinding:
    team: str
    project: str
    component: str
    version: str
    source: str
    vuln_id: str
    severity: str
    patched: str
    via: str = "dt"  # where the fix version came from: dt or osv


def open_findings(
    inv: Inventory, dt: DependencyTrack, team: str | None, errors: list[str]
) -> Iterator[tuple[str, str, dict[str, Any]]]:
    """(team key, project name, finding) for every unsuppressed finding of the teams'
    active projects. Per-project failures go to `errors` and the walk carries on."""
    for key, t in sorted(inv.teams.items()):
        if team and key != team:
            continue
        try:
            projects = [p for p in dt.projects_by_tag(t.dtrack_tag) if p.active]
        except Exception as e:
            errors.append(f"list DT projects for '{t.dtrack_tag}': {e}")
            continue
        for p in projects:
            try:
                findings = dt.findings(p.uuid)
            except Exception as e:
                errors.append(f"findings of {p.name}: {e}")
                continue
            for f in findings:
                if not (f.get("analysis") or {}).get("isSuppressed"):
                    yield key, p.name, f


def patched_findings(
    inv: Inventory, dt: DependencyTrack, team: str | None = None, osv: OSV | None = None
) -> tuple[list[PatchedFinding], int, list[str]]:
    """(findings with a recorded fix, count of open findings without one, errors)."""
    rows: list[PatchedFinding] = []
    errors: list[str] = []
    unknown = 0
    cache: dict[tuple[str, str], str] = {}
    osv_cache: dict[str, list[dict[str, Any]] | None] = {}
    for key, project, f in open_findings(inv, dt, team, errors):
        v: dict[str, Any] = f.get("vulnerability") or {}
        src, vid = v.get("source", ""), v.get("vulnId", "")
        if not src or not vid:
            continue
        if (src, vid) not in cache:
            try:
                rec = dt.vulnerability(src, vid) or {}
            except Exception as e:
                errors.append(f"{src}/{vid}: {e}")
                rec = {}
            cache[(src, vid)] = str(rec.get("patchedVersions") or "").strip()
        patched = cache[(src, vid)]
        via = "dt"
        c = f.get("component") or {}
        purl = str(c.get("purl") or "")
        if not patched and osv and purl:
            if purl not in osv_cache:
                try:
                    osv_cache[purl] = osv.vulns_for(purl)
                except Exception as e:
                    errors.append(f"OSV {purl}: {e}")
                    osv_cache[purl] = None
            fixed = OSV.fixed_in(osv_cache[purl] or [], vid, str(c.get("name", "")))
            if fixed:
                patched, via = ", ".join(fixed), "osv"
        if not patched:
            unknown += 1
            continue
        rows.append(
            PatchedFinding(
                team=key,
                project=project,
                component=c.get("name", ""),
                version=c.get("version", ""),
                source=src,
                vuln_id=vid,
                severity=v.get("severity", ""),
                patched=patched,
                via=via,
            )
        )
    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    rows.sort(key=lambda r: (order.get(r.severity, 9), r.team, r.project, r.component, r.vuln_id))
    return rows, unknown, errors
