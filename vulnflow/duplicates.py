"""Suppress the extra findings when one vulnerability is reported under several ids.

OSV's PyPI data has both the PYSEC and the GHSA record of most issues, and Dependency-Track
makes a finding of each (GHSA-* under source GITHUB, PYSEC-* under OSV), so the same
vulnerability on the same component shows up twice in DT, in DefectDojo and in every count.
With OSV alias sync on (`dt-bootstrap`), DT records that the ids are aliases and returns
them with each finding (`vulnerability.aliases`: {cveId, ghsaId, osvId, ...}); on the server
that merged 3194 open findings into 2451 issues (2026-11-27).

For each alias group (findings on one component whose ids overlap), one finding stays open
and the others are suppressed with the analysis state left NOT_SET (they are not false
positives, just tracked elsewhere) and a comment naming the one kept. The one kept is the
KEV-listed one, else the most severe, else GHSA before CVE before the rest, else the lowest
id. If that choice changes later (a new alias, a new severity), the round swaps them.

A group somebody has triaged is left alone: any member with an analysis state, or suppressed
without vulnflow's comment. Unsuppressing a duplicate vulnflow suppressed is an override too:
`data/duplicates.json` remembers what vulnflow suppressed, so such a group is never touched
again. Without that file (a fresh data dir) a suppressed member is recognised by its comment
and taken back into the record, but an override made before the file was lost is not known
any more: that duplicate is suppressed again.

Runs in every `dt2dojo` round after `prune`, with DT_MAINTENANCE_API_KEY (team
vulnflow-maintenance has VULNERABILITY_ANALYSIS), and by hand as `vulnflow duplicates`
(dry run unless --apply). Suppressed findings drop out of DT's FPF export, so DefectDojo
closes them at the next re-import.

DT (5.2.2 source): finding `analysis` {state, isSuppressed} and `vulnerability.aliases`
(Finding.java, FindingDao JSONB_VULN_ALIASES); PUT /api/v1/analysis takes isSuppressed
independently of analysisState (AnalysisResource).
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from datetime import date
from pathlib import Path
from typing import Any

from .clients import DependencyTrack, project_label
from .config import Inventory
from .triage import MARKER, UNSET, current_analysis

log = logging.getLogger(__name__)

TAG = "Duplicate of "  # starts every comment this module writes
SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "UNASSIGNED")
ID_PREFERENCE = ("GHSA", "CVE")  # which id to keep when nothing else decides


# ----------------------------------------------------------------------------- grouping
def vulnerability_ids(vuln: dict[str, Any]) -> set[str]:
    """The finding's own id and every alias DT recorded for it. DT gives aliases as a list
    of objects keyed by source (`cveId`, `ghsaId`, `osvId`, …); every string value counts."""
    ids = {str(vuln.get("vulnId") or "")}
    for alias in vuln.get("aliases") or []:
        if isinstance(alias, dict):
            ids.update(str(v) for v in alias.values() if isinstance(v, str) and v)
    ids.discard("")
    return ids


def component_key(component: dict[str, Any]) -> str:
    return str(component.get("uuid") or f"{component.get('name')}@{component.get('version')}")


def alias_groups(findings: list[dict[str, Any]]) -> list[list[dict[str, Any]]]:
    """Findings grouped per component and vulnerability: findings on the same component whose
    ids or aliases overlap end up in one group (also transitively, A~B and B~C). Every
    finding is in exactly one group, most in a group of one."""
    groups: dict[str, list[tuple[set[str], list[dict[str, Any]]]]] = {}
    for f in findings:
        ids = vulnerability_ids(f.get("vulnerability") or {})
        if not ids:
            continue
        on_component = groups.setdefault(component_key(f.get("component") or {}), [])
        merged_ids, merged = set(ids), [f]
        for other in [g for g in on_component if g[0] & ids]:
            on_component.remove(other)
            merged_ids |= other[0]
            merged = other[1] + merged
        on_component.append((merged_ids, merged))
    return [members for on_component in groups.values() for _, members in on_component]


def _severity_rank(f: dict[str, Any]) -> int:
    severity = str((f.get("vulnerability") or {}).get("severity") or "UNASSIGNED")
    return SEVERITIES.index(severity) if severity in SEVERITIES else len(SEVERITIES)


def keeper_order(f: dict[str, Any]) -> tuple[bool, int, int, str]:
    """Sort key: the first finding of a group is the one to keep open."""
    vuln = f.get("vulnerability") or {}
    vuln_id = str(vuln.get("vulnId") or "")
    prefix = vuln_id.split("-", 1)[0]
    id_rank = ID_PREFERENCE.index(prefix) if prefix in ID_PREFERENCE else len(ID_PREFERENCE)
    return (not vuln.get("isKev"), _severity_rank(f), id_rank, vuln_id)


# ------------------------------------------------------------------------------ record
class Record:
    """What this module suppressed: `{project/component/vuln uuid: {"keeper", "since"}}`,
    plus `"overridden": true` once somebody unsuppressed it."""

    def __init__(self, path: Path | None):
        self.path = path
        self.entries: dict[str, dict[str, Any]] = {}
        if path is not None and path.is_file():
            try:
                self.entries = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError) as e:
                log.warning("ignoring unreadable %s: %s", path, e)

    def save(self) -> None:
        if self.path is None:
            return
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps(self.entries, indent=1, sort_keys=True), encoding="utf-8")
        tmp.replace(self.path)


def finding_key(project_uuid: str, f: dict[str, Any]) -> str:
    return f"{project_uuid}/{f['component']['uuid']}/{f['vulnerability']['uuid']}"


# ----------------------------------------------------------------------------- reconcile
@dataclass
class DuplicatesReport:
    groups: int = 0  # alias groups of two or more findings
    suppressed: list[str] = field(default_factory=list)
    restored: list[str] = field(default_factory=list)  # a former duplicate now kept open
    left_alone: list[str] = field(default_factory=list)  # somebody triaged the group
    errors: list[str] = field(default_factory=list)


def _vuln_id(f: dict[str, Any]) -> str:
    return str((f.get("vulnerability") or {}).get("vulnId") or "")


def _analysis(f: dict[str, Any]) -> tuple[str, bool]:
    a = f.get("analysis") or {}
    return str(a.get("state") or ""), bool(a.get("isSuppressed"))


def _keeper_from_comment(dt: DependencyTrack, project_uuid: str, f: dict[str, Any]) -> str | None:
    """The id a duplicate points to, from the last "Duplicate of <id> ..." comment on its
    analysis; None when vulnflow never wrote one (suppressed by somebody else)."""
    a = current_analysis(
        dt.http, project_uuid, str(f["component"]["uuid"]), str(f["vulnerability"]["uuid"])
    )
    for c in reversed(a.get("analysisComments") or []):
        text = str((c or {}).get("comment") or "")
        if text.startswith(TAG):
            return text.removeprefix(TAG).split(" ", 1)[0]
    return None


def _put(
    dt: DependencyTrack, project_uuid: str, f: dict[str, Any], suppressed: bool, comment: str
) -> None:
    dt.http.put(
        "api/v1/analysis",
        json_body={
            "project": project_uuid,
            "component": str(f["component"]["uuid"]),
            "vulnerability": str(f["vulnerability"]["uuid"]),
            "analysisState": "NOT_SET",
            "isSuppressed": suppressed,
            "comment": comment,
        },
    )


def reconcile_group(
    dt: DependencyTrack,
    project_uuid: str,
    label: str,
    group: list[dict[str, Any]],
    record: Record,
    rep: DuplicatesReport,
    *,
    apply: bool,
    today: date,
) -> None:
    """Keep one finding of an alias group open and the rest suppressed (see module doc)."""
    component = str(group[0]["component"].get("name") or "")
    ids = ", ".join(sorted(_vuln_id(f) for f in group))
    ours: dict[str, str] = {}  # finding key -> the id it was suppressed as a duplicate of
    for f in group:
        key = finding_key(project_uuid, f)
        state, suppressed = _analysis(f)
        entry = record.entries.get(key)
        if entry is not None and (entry.get("overridden") or not suppressed):
            if not entry.get("overridden") and apply:  # unsuppressed by somebody: hands off
                entry["overridden"] = True
            rep.left_alone.append(f"{label}: {component} {ids} (a duplicate was unsuppressed)")
            return
        if state not in UNSET:
            rep.left_alone.append(f"{label}: {component} {ids} ({_vuln_id(f)} is {state})")
            return
        if suppressed:
            points_to = entry["keeper"] if entry else _keeper_from_comment(dt, project_uuid, f)
            if points_to is None:
                rep.left_alone.append(f"{label}: {component} {ids} ({_vuln_id(f)} suppressed by hand)")
                return
            ours[key] = str(points_to)
            if entry is None and apply:  # record lost: take it back from the comment
                record.entries[key] = {"keeper": ours[key], "since": today.isoformat()}

    keeper, *others = sorted(group, key=keeper_order)
    if finding_key(project_uuid, keeper) in ours:
        line = f"{label}: {component} {_vuln_id(keeper)} kept open again"
        rep.restored.append(line)
        if apply:
            _put(
                dt, project_uuid, keeper, False, f"No longer a duplicate: kept open for {ids}; {MARKER}"
            )
            record.entries.pop(finding_key(project_uuid, keeper), None)
    for f in others:
        if ours.get(finding_key(project_uuid, f)) == _vuln_id(keeper):
            continue  # already as it should be
        line = f"{label}: {component} {_vuln_id(f)} duplicate of {_vuln_id(keeper)}"
        rep.suppressed.append(line)
        if not apply:
            continue
        comment = f"{TAG}{_vuln_id(keeper)} on this component (aliases: {ids}); tracked there; {MARKER}"
        _put(dt, project_uuid, f, True, comment)
        record.entries[finding_key(project_uuid, f)] = {
            "keeper": _vuln_id(keeper),
            "since": today.isoformat(),
        }


def suppress_duplicates(
    inv: Inventory,
    dt: DependencyTrack,
    *,
    apply: bool = False,
    record_path: Path | None = None,
    team: str | None = None,
    today: date | None = None,
) -> DuplicatesReport:
    """Reconcile every alias group in the teams' active projects."""
    rep = DuplicatesReport()
    record = Record(record_path)
    today = today or date.today()
    seen: set[str] = set()
    for key, t in sorted(inv.teams.items()):
        if team and key != team:
            continue
        try:
            projects = [p for p in dt.projects_by_tag(t.dtrack_tag) if p.active]
        except Exception as e:
            rep.errors.append(f"list DT projects for '{t.dtrack_tag}': {e}")
            continue
        for p in projects:
            if p.uuid in seen:
                continue
            seen.add(p.uuid)
            label = f"{key}/{project_label(p.name, p.version)}"
            try:
                findings = dt.findings(p.uuid, suppressed=True)
            except Exception as e:
                rep.errors.append(f"findings of {label}: {e}")
                continue
            for group in alias_groups(findings):
                if len(group) < 2:
                    continue
                rep.groups += 1
                try:
                    reconcile_group(dt, p.uuid, label, group, record, rep, apply=apply, today=today)
                except Exception as e:
                    rep.errors.append(f"{label}: {', '.join(_vuln_id(f) for f in group)}: {e}")
    if apply:
        record.save()
    for lines in (rep.suppressed, rep.restored, rep.left_alone):
        lines.sort()
    return rep
