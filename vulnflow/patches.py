"""Which open Dependency-Track findings have a patched release.

DT only knows a fix version when the vulnerability source supplied one (GitHub advisories,
OSV); NVD entries have none. "No patched version recorded" therefore means *unknown*, not
"no fix exists".
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any

from .clients import DependencyTrack
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


def patched_findings(
    inv: Inventory, dt: DependencyTrack, team: str | None = None
) -> tuple[list[PatchedFinding], int, list[str]]:
    """(findings with a recorded fix, count of open findings without one, errors)."""
    rows: list[PatchedFinding] = []
    errors: list[str] = []
    unknown = 0
    cache: dict[tuple[str, str], str] = {}
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
                if (f.get("analysis") or {}).get("isSuppressed"):
                    continue
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
                if not patched:
                    unknown += 1
                    continue
                c = f.get("component") or {}
                rows.append(
                    PatchedFinding(
                        team=key,
                        project=p.name,
                        component=c.get("name", ""),
                        version=c.get("version", ""),
                        source=src,
                        vuln_id=vid,
                        severity=v.get("severity", ""),
                        patched=patched,
                    )
                )
    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    rows.sort(key=lambda r: (order.get(r.severity, 9), r.team, r.project, r.component, r.vuln_id))
    return rows, unknown, errors
