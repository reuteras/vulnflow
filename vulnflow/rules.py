"""Apply the reviewed decisions in machines.toml's [triage.*] to matching findings, unattended.

A rule says "this vulnerability on this component does not affect us, because ...", once,
and every `dt2dojo` round applies it to each open finding it matches, in every project and
version, now and later. Example: Airflow's Sqoop provider advisory on apache-airflow, where
the provider is not installed.

    [triage.airflow-sqoop]
    vulnerabilities = ["PYSEC-2023-314"]
    component = "apache-airflow"
    projects = ["container:opencve-airflow-*"]
    state = "NOT_AFFECTED"
    justification = "CODE_NOT_PRESENT"
    reason = "apache-airflow-providers-sqoop is not installed"
    review_by = 2027-05-27

A finding matches when its id or one of its DT aliases is in `vulnerabilities`, the
component name is `component` (case-insensitive) and, when given, its version is in
`versions`, the project name matches one of `projects` (fnmatch) and its team is in `teams`.
KEV-listed vulnerabilities (DT's `isKev`, or in vulnflow's catalog: CISA, plus VulnCheck
with a token) are skipped unless `allow_kev = true`: known exploitation is a
reason to look again, not to stay quiet.

Writing goes through `triage.apply_ignores`, the same as `vulnflow ignore`: a finding
somebody already triaged is left alone, every write is in the ledger (data/ignored.jsonl, so
`vulnflow unignore` takes it back) and the comment says which rule wrote it:
"<reason>; rule triage.<name>; review by <date>; reviewed <day> via vulnflow". After
`review_by` the rule no longer applies, and `prune` lifts the suppressions it wrote (it
reads the "review by" date in the comment), so the findings show up again for a fresh look.
`load_machines` refuses a rule without a reason or review date, or more than a year ahead.

Runs in every `dt2dojo` round after `prune`, with DT_MAINTENANCE_API_KEY, and by hand as
`vulnflow triage-rules` (dry run unless --apply).
"""

from __future__ import annotations

import fnmatch
from collections.abc import Collection
from dataclasses import dataclass, field
from datetime import date
from pathlib import Path
from typing import Any

from .clients import DependencyTrack, project_label
from .config import Inventory, TriageRule
from .duplicates import vulnerability_ids
from .triage import UNSET, IgnoreItem, apply_ignores

RULE_TAG = "rule triage."  # in every comment a rule writes: `rule triage.<name>`


@dataclass
class RulesReport:
    written: list[str] = field(default_factory=list)
    already: int = 0  # matched and already in the rule's state
    kept: list[str] = field(default_factory=list)  # somebody had triaged it otherwise
    kev_skipped: list[str] = field(default_factory=list)
    expired: list[str] = field(default_factory=list)  # rules past review_by
    unused: list[str] = field(default_factory=list)  # rules that matched no finding
    errors: list[str] = field(default_factory=list)


def comment(rule: TriageRule, today: date) -> str:
    return (
        f"{rule.reason}; {RULE_TAG}{rule.name}; review by {rule.review_by}; "
        f"reviewed {today} via vulnflow"
    )


def matches(rule: TriageRule, team: str, project: str, f: dict[str, Any]) -> bool:
    """Does the rule cover this finding (KEV aside)?"""
    comp = f.get("component") or {}
    if str(comp.get("name") or "").lower() != rule.component.lower():
        return False
    if rule.versions and str(comp.get("version") or "") not in rule.versions:
        return False
    if rule.teams and team not in rule.teams:
        return False
    if rule.projects and not any(fnmatch.fnmatchcase(project, p) for p in rule.projects):
        return False
    return bool(vulnerability_ids(f.get("vulnerability") or {}) & set(rule.vulnerabilities))


def _item(team: str, p: Any, f: dict[str, Any], text: str) -> IgnoreItem:
    comp, vuln = f["component"], f["vulnerability"]
    return IgnoreItem(
        team=team,
        project=p.name,
        project_uuid=p.uuid,
        component=str(comp.get("name") or ""),
        version=str(comp.get("version") or ""),
        component_uuid=str(comp["uuid"]),
        vuln_id=str(vuln.get("vulnId") or ""),
        vuln_uuid=str(vuln["uuid"]),
        comment=text,
        project_version=p.version,
    )


def apply_rules(
    inv: Inventory,
    dt: DependencyTrack,
    rules: dict[str, TriageRule],
    *,
    apply: bool = False,
    ledger: Path | None = None,
    today: date | None = None,
    kev: Collection[str] = (),
) -> RulesReport:
    """Match the rules against the open findings of the teams' active projects and, with
    `apply`, write their decisions (see module doc). `kev` is vulnflow's KEV catalog (CISA,
    plus VulnCheck with a token); DT's own `isKev` counts too."""
    rep = RulesReport()
    today = today or date.today()
    live = {}
    for name, rule in sorted(rules.items()):
        if rule.review_by < today:
            rep.expired.append(f"{name} (review by {rule.review_by})")
        else:
            live[name] = rule
    if not live:
        return rep

    todo: dict[str, list[IgnoreItem]] = {name: [] for name in live}
    seen: set[str] = set()
    for team_key, t in sorted(inv.teams.items()):
        try:
            projects = [p for p in dt.projects_by_tag(t.dtrack_tag) if p.active]
        except Exception as e:
            rep.errors.append(f"list DT projects for '{t.dtrack_tag}': {e}")
            continue
        for p in projects:
            if p.uuid in seen:
                continue
            seen.add(p.uuid)
            label = f"{team_key}/{project_label(p.name, p.version)}"
            try:
                findings = dt.findings(p.uuid)  # open ones: suppressed are decided already
            except Exception as e:
                rep.errors.append(f"findings of {label}: {e}")
                continue
            for f in findings:
                for name, rule in live.items():
                    if not matches(rule, team_key, p.name, f):
                        continue
                    vuln = f["vulnerability"]
                    state = str((f.get("analysis") or {}).get("state") or "")
                    what = f"{f['component'].get('name')} {vuln.get('vulnId')}"
                    if state not in UNSET:  # somebody is on it (IN_TRIAGE, ...)
                        rep.kept.append(f"{label}: {what} is {state} ({name})")
                        break
                    # an alias counts: a GHSA finding whose CVE is in KEV
                    in_kev = vuln.get("isKev") or any(i.upper() in kev for i in vulnerability_ids(vuln))
                    if in_kev and not rule.allow_kev:
                        rep.kev_skipped.append(
                            f"{label}: {rule.component} {vuln.get('vulnId')} ({name})"
                        )
                        continue
                    todo[name].append(_item(team_key, p, f, comment(rule, today)))
                    break  # the first rule (by name) that matches decides

    for name, items in todo.items():
        rule = live[name]
        if not items:
            rep.unused.append(name)
            continue
        if not apply:
            rep.written += [
                f"{it.label}: {it.component} {it.vuln_id} <- {rule.state} ({name})" for it in items
            ]
            continue
        written, skipped, kept, errors = apply_ignores(
            dt.http,
            items,
            rule.state,
            rule.justification,
            ledger=ledger,
            response=rule.response,
        )
        rep.written += [
            f"{it.label}: {it.component} {it.vuln_id} <- {rule.state} ({name})" for it in written
        ]
        rep.already += len(skipped)
        rep.kept += [
            f"{k.item.label}: {k.item.component} {k.item.vuln_id} is {k.state} ({name})" for k in kept
        ]
        rep.errors += [f"{name}: {e}" for e in errors]
    for lines in (rep.written, rep.kept, rep.kev_skipped):
        lines.sort()
    return rep
