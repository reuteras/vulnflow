"""Which open Dependency-Track findings have a patched release.

DT only knows a fix version when the vulnerability source supplied one (GitHub advisories,
OSV); NVD entries have none. "No patched version recorded" therefore means *unknown*, not
"no fix exists".

With an OSV client, findings DT has no fix for are looked up on osv.dev by the component's
package URL (marked via="osv"). That sends package URLs to an outside service. OSV lists
the fix of every maintained branch, so `recommended` picks the one for the installed
version (see versions.recommend).

Components whose version is unknown (the SBOM tool could not resolve it, shown as UNKNOWN)
are not sent to OSV: with no version every historic CVE of the package matches and the
"fixes" would mean nothing. They are counted separately.

Go modules built from a commit instead of a release carry a pseudo-version
(`v0.0.0-20261105150651-e2e28adeee2c`, `v1.5.1-0.20260910130453-bcfe9f230c1d`). It sorts
before every release, so every advisory matches and the "fix" is often older than what runs
(seen live, 2026-11-24: a Prometheus built on 2026-11-05 was told to go to 0.305.2). Those
are skipped and counted too; the commit date in the version is the thing to check.
"""

from __future__ import annotations

import logging
import re
from collections.abc import Iterator
from dataclasses import dataclass
from typing import Any

from .clients import OSV, DependencyTrack, DTProject
from .config import Inventory
from .versions import recommend

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
    recommended: str = ""  # the fix for the installed version, when it can be worked out
    project_version: str = ""


def open_findings(
    inv: Inventory, dt: DependencyTrack, team: str | None, errors: list[str]
) -> Iterator[tuple[str, DTProject, dict[str, Any]]]:
    """(team key, project, finding) for every unsuppressed finding of the teams'
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
                    yield key, p, f


UNKNOWN_VERSIONS = ("", "unknown", "(devel)", "devel")
# vX.0.0-<14-digit UTC time>-<12 hex>, vX.Y.Z-0.<time>-<hex>, vX.Y.Z-pre.0.<time>-<hex>,
# optionally +incompatible / +dirty (https://go.dev/ref/mod#pseudo-versions)
_GO_PSEUDO = re.compile(r"(?:^v?\d+\.\d+\.\d+-|\.)\d{14}-[0-9a-f]{12}(?:\+[0-9A-Za-z.]+)?$")


def is_go_pseudo_version(purl: str, version: str) -> bool:
    return purl.startswith("pkg:golang/") and bool(_GO_PSEUDO.search(version.strip()))


def patched_findings(
    inv: Inventory, dt: DependencyTrack, team: str | None = None, osv: OSV | None = None
) -> tuple[list[PatchedFinding], int, int, int, list[str]]:
    """(findings with a recorded fix, count of open findings without one, count skipped
    because the component version is unknown, count skipped because it is a Go
    pseudo-version, errors)."""
    rows: list[PatchedFinding] = []
    errors: list[str] = []
    unknown = 0
    unversioned = 0
    pseudo = 0
    cache: dict[tuple[str, str], str] = {}
    osv_cache: dict[str, list[dict[str, Any]] | None] = {}
    for key, proj, f in open_findings(inv, dt, team, errors):
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
        recommended = ""
        via = "dt"
        c = f.get("component") or {}
        purl = str(c.get("purl") or "")
        version = str(c.get("version") or "")
        if not patched and version.strip().lower() in UNKNOWN_VERSIONS:
            unversioned += 1
            continue
        if not patched and is_go_pseudo_version(purl, version):
            pseudo += 1
            continue
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
                recommended = recommend(version, fixed)
        if not patched:
            unknown += 1
            continue
        rows.append(
            PatchedFinding(
                team=key,
                project=proj.name,
                project_version=proj.version,
                component=c.get("name", ""),
                version=c.get("version", ""),
                source=src,
                vuln_id=vid,
                severity=v.get("severity", ""),
                patched=patched,
                via=via,
                recommended=recommended,
            )
        )
    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    rows.sort(key=lambda r: (order.get(r.severity, 9), r.team, r.project, r.component, r.vuln_id))
    return rows, unknown, unversioned, pseudo, errors
