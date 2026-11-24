"""Keep Dependency-Track (and so DefectDojo) to what actually runs.

Every image tag, OS release or code version an agent uploads becomes its own DT project
(`container:nginx@1.31.8`). Nothing removed the old ones, and DT keeps an analysis per
project + component + vulnerability, so a decision made on one version was gone in the next
and the old version's findings stayed open for ever. `prune` fixes both, for the projects
the agents create (tagged `kind-*`), grouped by name and host (`host-*` tag; `host:<name>`
projects are one group each):

- carry forward: a suppressed decision on one version (NOT_AFFECTED, FALSE_POSITIVE, or an
  accepted risk: EXPLOITABLE with response WILL_NOT_FIX or CAN_NOT_FIX) is copied to the
  other active versions of the group, for the same component (identical package URL, i.e.
  the same build) and the same vulnerability, where nobody has triaged the finding yet. The
  newest decision wins; state, justification, response and comment go along. The comment
  says where it came from and ends "via vulnflow", so `unignore --from` can revert a copy.
- review dates: a suppressed decision whose comment says "review by YYYY-MM-DD" (`ignore
  --review-by`) is unsuppressed after that day, so it shows up again in the lists and, at
  the next export, in DefectDojo. That is the expiry DT's analyses lack, and why accepted
  risks live in DT: DefectDojo's own risk acceptances stay with one version's test.
- deactivate: a project whose last upload is older than `superseded_days` while a newer
  version of the group exists, or older than `gone_days` when it is the newest (nothing
  runs it any more). Its findings in DefectDojo are closed by re-importing an empty
  finding list into its test (close_old_findings); dt2dojo skips inactive projects.
- reactivate: an inactive project uploaded again after it was deactivated (lastBomImport
  newer than DT's inactiveSince): a rollback, or a version that runs next to a newer one
  (two postgres containers on one host) and was deactivated while its host was offline.
  DT accepts uploads to an inactive project and leaves it inactive. A version retired
  early (by hand, or with a small --superseded-days) and not uploaded since stays retired.
  Without inactiveSince (older DT) only the newest version of a group comes back, when it
  was uploaded within `superseded_days`.

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
from datetime import date
from typing import Any

from .clients import DefectDojo, DependencyTrack, DTProject, project_label
from .config import Inventory, Team
from .triage import ACCEPT_RESPONSES, MARKER, UNSET, current_analysis, review_date

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
    reopened: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    @property
    def changed(self) -> bool:
        return bool(self.carried or self.deactivated or self.reactivated or self.reopened)


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


def _suppressed(
    dt: DependencyTrack, m: _Proj, rep: PruneReport
) -> list[tuple[dict[str, Any], dict[str, Any]]]:
    """(finding, its analysis) for every suppressed finding of a project."""
    out = []
    try:
        for f in dt.findings(m.p.uuid, suppressed=True):
            if _state(f)[1] and all(_key(f)):
                a = current_analysis(
                    dt.http, m.p.uuid, str(f["component"]["uuid"]), str(f["vulnerability"]["uuid"])
                )
                out.append((f, a))
    except Exception as e:
        rep.errors.append(f"findings of {m.label}: {e}")
    return out


def _is_decision(a: dict[str, Any]) -> bool:
    state = str(a.get("analysisState") or "")
    if not a.get("isSuppressed"):
        return False
    if state == "EXPLOITABLE":  # an accepted risk, not "exploitable, fix it"
        return str(a.get("analysisResponse") or "") in ACCEPT_RESPONSES
    return state in CARRY_STATES


def _reopen(
    dt: DependencyTrack,
    m: _Proj,
    found: list[tuple[dict[str, Any], dict[str, Any]]],
    today: date,
    apply: bool,
    rep: PruneReport,
) -> None:
    """Lift the suppression of decisions whose "review by" date has passed (mutates `found`:
    a reopened analysis is no longer a decision to carry)."""
    for f, a in found:
        due = review_date(_reason(a))
        if due is None or due >= today:
            continue
        comp, vid = _key(f)
        rep.reopened.append(
            f"{m.team.key}/{m.label}: {comp} {vid} ({a.get('analysisState')}, review by {due})"
        )
        a["isSuppressed"] = False
        if not apply:
            continue
        body: dict[str, Any] = {
            "project": m.p.uuid,
            "component": str(f["component"]["uuid"]),
            "vulnerability": str(f["vulnerability"]["uuid"]),
            "analysisState": a.get("analysisState"),
            "isSuppressed": False,
            "comment": f"Review date {due} passed: shown again; {MARKER}",
        }
        for k in ("analysisJustification", "analysisResponse"):
            if a.get(k):
                body[k] = a[k]
        try:
            dt.http.put("api/v1/analysis", json_body=body)
        except Exception as e:
            rep.errors.append(f"reopen {m.label}: {comp} {vid}: {e}")


def _carry(
    dt: DependencyTrack,
    sources: list[tuple[_Proj, list[tuple[dict[str, Any], dict[str, Any]]]]],
    targets: list[_Proj],
    apply: bool,
    rep: PruneReport,
) -> None:
    """Copy decisions within one group (`sources` newest first) into `targets`."""
    decided: dict[tuple[str, str], tuple[_Proj, dict[str, Any]]] = {}
    for src, found in sources:  # newest first: the first decision for a key wins
        for f, a in found:
            if _is_decision(a):
                decided.setdefault(_key(f), (src, a))
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
            src, a = hit
            comp, vid = _key(f)
            state = str(a.get("analysisState"))
            if a.get("analysisResponse") and state == "EXPLOITABLE":
                state += f"/{a['analysisResponse']}"
            line = f"{dst.team.key}/{dst.label}: {comp} {vid} <- {state} from {src.label}"
            if not apply:
                rep.carried.append(line)
                continue
            why = _reason(a).removesuffix(MARKER).rstrip("; ")
            if not why.startswith("Carried forward from "):  # keep the original source
                why = f"Carried forward from {src.label}" + (f": {why}" if why else "")
            body: dict[str, Any] = {
                "project": dst.p.uuid,
                "component": str(f["component"]["uuid"]),
                "vulnerability": str(f["vulnerability"]["uuid"]),
                "analysisState": a.get("analysisState"),
                "isSuppressed": True,
                "comment": f"{why}; {MARKER}",
            }
            for k in ("analysisJustification", "analysisResponse"):
                if a.get(k):
                    body[k] = a[k]
            try:
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


def _uploaded_since_deactivation(m: _Proj, newest: bool, age: float, superseded_days: float) -> bool:
    """Whether an inactive project was uploaded after it was deactivated."""
    since, last = m.p.inactive_since, m.p.last_bom_import
    if since is not None and last is not None:
        return last > since
    return newest and age < superseded_days * DAY  # no inactiveSince: the old rule


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
    today = date.fromtimestamp(now)
    for group in groups(inv, dt, rep.errors):
        uploaded = [m for m in group if m.p.last_bom_import]
        if not uploaded:
            continue
        newest = uploaded[0]
        for m in uploaded:
            age = now - (m.p.last_bom_import or 0)
            limit = gone_days if m is newest else superseded_days
            if not m.p.active and _uploaded_since_deactivation(m, m is newest, age, superseded_days):
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
        # inactive versions only matter as a source of decisions for the active ones
        sources = [
            (m, _suppressed(dt, m, rep)) for m in group if m.p.active or (len(group) > 1 and targets)
        ]
        for m, found in sources:
            if m.p.active:
                _reopen(dt, m, found, today, apply, rep)
        if len(group) > 1 and targets:
            _carry(dt, sources, targets, apply, rep)
    for lines in (rep.carried, rep.deactivated, rep.reactivated, rep.reopened):
        lines.sort()
    return rep
