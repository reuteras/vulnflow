"""Where a component is on disk: the file paths syft recorded for it.

The agents' SBOMs carry syft's `syft:location:<n>:path` properties (for a Go binary's
`stdlib`, the binary; for a Python package, its dist-info), and Dependency-Track keeps them
as component properties (group `syft`, name `location:<n>:path`). Findings and the
component list leave them out, so a finding on `stdlib go1.23.3` says nothing about which
program to update; `vulnflow where stdlib --version go1.23.3` does. Container paths are
inside the image. Since the agent merges duplicates, one component lists every binary that
has it (`MAX_LOCATIONS`); SBOMs uploaded before that kept only the first.

DT endpoints (seen live on 5.2.2): GET /api/v1/component/project/{uuid},
GET /api/v1/component/{uuid}/property.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from .clients import DependencyTrack
from .config import Inventory

_PATH = re.compile(r"^(?:syft:)?location:\d+:path$")


@dataclass
class Located:
    team: str
    project: str
    project_version: str
    component: str
    version: str
    purl: str
    paths: list[str] = field(default_factory=list)


def paths_of(props: list[dict[str, Any]]) -> list[str]:
    """syft's location paths, absolute, in the order syft numbered them."""

    def index(p: dict[str, Any]) -> int:
        return int(str(p.get("propertyName", "")).split(":")[-2])

    found = [
        p
        for p in props
        if str(p.get("groupName") or "") in ("syft", "")
        and _PATH.match(str(p.get("propertyName") or ""))
    ]
    out: list[str] = []
    for p in sorted(found, key=index):
        v = str(p.get("propertyValue") or "")
        v = v if v.startswith("/") else f"/{v}"
        if v not in out:
            out.append(v)
    return out


def locate(
    inv: Inventory,
    dt: DependencyTrack,
    name: str,
    version: str | None = None,
    project: str | None = None,
    team: str | None = None,
) -> tuple[list[Located], list[str]]:
    """Components called `name` (case-insensitive) in the teams' active projects, with
    their paths; optionally only one version, projects whose name contains `project`."""
    rows: list[Located] = []
    errors: list[str] = []
    seen: set[str] = set()
    for key, t in sorted(inv.teams.items()):
        if team and key != team:
            continue
        try:
            projects = [p for p in dt.projects_by_tag(t.dtrack_tag) if p.active]
        except Exception as e:
            errors.append(f"list DT projects for '{t.dtrack_tag}': {e}")
            continue
        for p in projects:
            if p.uuid in seen or (project and project.lower() not in p.name.lower()):
                continue
            seen.add(p.uuid)
            try:
                comps = dt.components(p.uuid)
            except Exception as e:
                errors.append(f"components of {p.name}: {e}")
                continue
            for c in comps:
                if str(c.get("name") or "").lower() != name.lower():
                    continue
                if version and str(c.get("version") or "") != version:
                    continue
                try:
                    paths = paths_of(dt.component_properties(str(c["uuid"])))
                except Exception as e:
                    errors.append(f"properties of {c.get('name')} in {p.name}: {e}")
                    paths = []
                rows.append(
                    Located(
                        team=key,
                        project=p.name,
                        project_version=p.version,
                        component=str(c.get("name") or ""),
                        version=str(c.get("version") or ""),
                        purl=str(c.get("purl") or ""),
                        paths=paths,
                    )
                )
    rows.sort(key=lambda r: (r.component, r.version, r.team, r.project))
    return rows, errors
