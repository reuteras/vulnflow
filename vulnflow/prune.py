"""Keep Dependency-Track (and so DefectDojo) to what actually runs.

Every image tag, OS release or code version an agent uploads becomes its own DT project
(`container:nginx@1.31.8`). Nothing removed the old ones, and DT keeps an analysis per
project + component + vulnerability, so a decision made on one version was gone in the next
and the old version's findings stayed open for ever. `prune` fixes both, for the projects
the agents create (tagged `kind-*`), grouped by name and host (`host-*` tag; `host:<name>`
projects are one group each):

- carry forward: a NOT_AFFECTED or FALSE_POSITIVE, suppressed analysis on one version is
  copied to the other active versions of the group, for the same component (identical
  package URL, i.e. the same build) and the same vulnerability, where nobody has triaged
  the finding yet. The newest decision wins. The comment says where it came from and ends
  "via vulnflow", so `unignore --from` can revert a copy (back to NOT_SET).
- deactivate: a project whose last upload is older than `superseded_days` while a newer
  version of the group exists, or older than `gone_days` when it is the newest (nothing
  runs it any more). Its findings in DefectDojo are closed by re-importing an empty
  finding list into its test (close_old_findings); dt2dojo skips inactive projects.
- reactivate: an inactive project that is the newest upload of its group again (a
  rollback; DT accepts uploads to an inactive project and leaves it inactive).

Runs at the start of every `dt2dojo` round with DT_MAINTENANCE_API_KEY (team
vulnflow-maintenance, see bootstrap.DT_MAINTENANCE_PERMISSIONS), and by hand as
`vulnflow prune` (dry run unless --apply). Projects never uploaded (lastBomImport unset,
e.g. created by `sync --create-projects`) are left alone.

DT fields used (DT 5.2.2 source): finding `analysis` {state, isSuppressed}
(Finding.java); GET/PUT /api/v1/analysis (AnalysisResource); PATCH /api/v1/project/{uuid}
{"active"} (ProjectResource.patchProject); `/project/tag/{tag}` lists inactive projects
too unless excludeInactive.
"""

from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass, field
from typing import Any

from .clients import DefectDojo, DependencyTrack, DTProject, project_label
from .config import Inventory, Team
from .triage import MARKER, UNSET, current_analysis

log = logging.getLogger(__name__)

CARRY_STATES = ("NOT_AFFECTED", "FALSE_POSITIVE")
# comments DT writes itself on every analysis change; the human/vulnflow reason is the rest
_DT_AUDIT = ("Analysis:", "Justification:", "Vendor Response:", "Details:", "Suppressed", "Unsuppressed")
DAY = 86400


@dataclass
class PruneReport:
    carried: list[str] = field(default_factory=list)
    deactivated: list[str] = field(default_factory=list)
    reactivated: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    @property
    def changed(self) -> bool:
        return bool(self.carried or self.deactivated or self.reactivated)


@dataclass
class _Proj:
    team: Team
    p: DTProject

    @property
    def label(self) -> str:
        return project_label(self.p.name, self.p.version)


def groups(inv: Inventory, dt: DependencyTrack, errors: list[str]) -> list[list[_Proj]]:
    """Agent projects per (name, host), newest upload first."""
    by_key: dict[tuple[str, str], list[_Proj]] = {}
    seen: set[str] = set()
    for team in inv.teams.values():
        try:
            projects = dt.projects_by_tag(team.dtrack_tag)
        except Exception as e:
            errors.append(f"list DT projects for '{team.dtrack_tag}': {e}")
            continue
        for p in projects:
            if p.uuid in seen or not any(t.startswith("kind-") for t in p.tags):
                continue
            seen.add(p.uuid)
            host = next((t for t in p.tags if t.startswith("host-")), "")
            by_key.setdefault((p.name, host), []).append(_Proj(team, p))
    out = []
    for members in by_key.values():
        members.sort(key=lambda m: m.p.last_bom_import or 0, reverse=True)
        out.append(members)
    return out


def _state(f: dict[str, Any]) -> tuple[str, bool]:
    a = f.get("analysis") or {}
    return str(a.get("state") or ""), bool(a.get("isSuppressed"))


def _key(f: dict[str, Any]) -> tuple[str, str]:
    c = f.get("component") or {}
    v = f.get("vulnerability") or {}
    comp = str(c.get("purl") or "") or f"{c.get('name', '')}@{c.get('version', '')}"
    return comp, str(v.get("vulnId") or "")


def _reason(analysis: dict[str, Any]) -> str:
    """The last comment that isn't one of DT's own audit lines."""
    for c in reversed(analysis.get("analysisComments") or []):
        text = str((c or {}).get("comment") or "").strip()
        if text and not text.startswith(_DT_AUDIT):
            return " ".join(text.split())[:300]
    return ""


def _carry(
    dt: DependencyTrack, group: list[_Proj], targets: list[_Proj], apply: bool, rep: PruneReport
) -> None:
    """Copy decisions within one group into `targets` (its active members)."""
    decided: dict[tuple[str, str], tuple[_Proj, dict[str, Any]]] = {}
    for src in group:  # newest first: the first decision for a key wins
        try:
            for f in dt.findings(src.p.uuid, suppressed=True):
                state, suppressed = _state(f)
                if suppressed and state in CARRY_STATES and all(_key(f)):
                    decided.setdefault(_key(f), (src, f))
        except Exception as e:
            rep.errors.append(f"findings of {src.label}: {e}")
    if not decided:
        return
    for dst in targets:
        try:
            findings = dt.findings(dst.p.uuid)  # unsuppressed only
        except Exception as e:
            rep.errors.append(f"findings of {dst.label}: {e}")
            continue
        for f in findings:
            hit = decided.get(_key(f))
            if hit is None or hit[0].p.uuid == dst.p.uuid or _state(f)[0] not in UNSET:
                continue
            src, sf = hit
            comp, vid = _key(f)
            line = f"{dst.team.key}/{dst.label}: {comp} {vid} <- {_state(sf)[0]} from {src.label}"
            if not apply:
                rep.carried.append(line)
                continue
            try:
                a = current_analysis(
                    dt.http,
                    src.p.uuid,
                    str(sf["component"]["uuid"]),
                    str(sf["vulnerability"]["uuid"]),
                )
                why = _reason(a).removesuffix(MARKER).rstrip("; ")
                if not why.startswith("Carried forward from "):  # keep the original source
                    why = f"Carried forward from {src.label}" + (f": {why}" if why else "")
                body: dict[str, Any] = {
                    "project": dst.p.uuid,
                    "component": str(f["component"]["uuid"]),
                    "vulnerability": str(f["vulnerability"]["uuid"]),
                    "analysisState": a.get("analysisState") or _state(sf)[0],
                    "isSuppressed": True,
                    "comment": f"{why}; {MARKER}",
                }
                if a.get("analysisJustification"):
                    body["analysisJustification"] = a["analysisJustification"]
                dt.http.put("api/v1/analysis", json_body=body)
                rep.carried.append(line)
            except Exception as e:
                rep.errors.append(f"{line}: {e}")


def close_in_dojo(dt: DependencyTrack, dojo: DefectDojo, m: _Proj, engagement: str) -> None:
    """Close the project's findings in DefectDojo: re-import its export with no findings."""
    from .jobs import reimport_project

    fpf = json.loads(dt.export_fpf(m.p.uuid) or b"{}")
    fpf["findings"] = []
    reimport_project(dojo, m.team, m.p, json.dumps(fpf).encode(), engagement)


def prune(
    inv: Inventory,
    dt: DependencyTrack,
    dojo: DefectDojo | None = None,
    *,
    apply: bool = False,
    superseded_days: float = 2,
    gone_days: float = 7,
    engagement: str = "Dependency-Track",
    now: float | None = None,
) -> PruneReport:
    rep = PruneReport()
    now = time.time() if now is None else now
    for group in groups(inv, dt, rep.errors):
        uploaded = [m for m in group if m.p.last_bom_import]
        if not uploaded:
            continue
        newest = uploaded[0]
        for m in uploaded:
            age = now - (m.p.last_bom_import or 0)
            limit = gone_days if m is newest else superseded_days
            if m is newest and not m.p.active and age < superseded_days * DAY:
                rep.reactivated.append(f"{m.team.key}/{m.label}")
                if apply:
                    try:
                        dt.set_active(m.p.uuid, True)
                    except Exception as e:
                        rep.errors.append(f"reactivate {m.label}: {e}")
                        continue
                m.p.active = True
            elif m.p.active and age > limit * DAY:
                why = "newer version uploaded" if m is not newest else "no upload"
                rep.deactivated.append(f"{m.team.key}/{m.label} ({why}; last {age / DAY:.1f} days ago)")
                if apply:
                    try:
                        if dojo is not None:
                            close_in_dojo(dt, dojo, m, engagement)
                        dt.set_active(m.p.uuid, False)
                    except Exception as e:
                        rep.errors.append(f"deactivate {m.label}: {e}")
                        continue
                m.p.active = False
        targets = [m for m in group if m.p.active]
        if len(group) > 1 and targets:
            _carry(dt, group, targets, apply, rep)
    for lines in (rep.carried, rep.deactivated, rep.reactivated):
        lines.sort()
    return rep
