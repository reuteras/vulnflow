"""Where the open findings come from: counts per project kind, project, component,
ecosystem and advisory source, and the vulnerabilities spread over the most projects.

One vulnerability often arrives as several findings on the same component, one per advisory
source (GHSA from GitHub, PYSEC from OSV PyPI, the CVE from NVD). When Dependency-Track knows
their aliases (the finding's `vulnerability.aliases`, filled by alias sync), those findings
are counted once, as one *issue*; without aliases every finding is its own issue. The
`findings` totals are always the raw number Dependency-Track shows.

Reads only the teams' active projects (`team-<team>` tags), like `where`, with the read-only
vulnflow key. DT endpoints: GET /api/v1/project/tag/{tag}, GET /api/v1/finding/project/{uuid}.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from typing import Any

from .clients import DependencyTrack, project_label
from .config import Inventory
from .duplicates import SEVERITIES, alias_groups, vulnerability_ids


@dataclass
class Tally:
    """Issues counted under one key, by severity, and the projects they were seen in."""

    issues: int = 0
    severities: Counter[str] = field(default_factory=Counter)
    projects: set[str] = field(default_factory=set)

    def add(self, severity: str, project: str) -> None:
        self.issues += 1
        self.severities[severity] += 1
        self.projects.add(project)

    def severity_summary(self) -> str:
        """`C2 H10 M3`: initial and count of each severity present, most severe first."""
        return " ".join(f"{s[0]}{self.severities[s]}" for s in SEVERITIES if self.severities[s])


@dataclass
class Issue:
    """One vulnerability on one component: its findings merged by alias."""

    vuln_id: str  # the id shown: the CVE when one of the findings has it
    ids: set[str]
    severity: str
    sources: set[str]
    component: str
    ecosystem: str


@dataclass
class Stats:
    projects: int = 0
    findings: int = 0
    by_kind: dict[str, Tally] = field(default_factory=dict)
    by_project: dict[str, Tally] = field(default_factory=dict)
    by_component: dict[str, Tally] = field(default_factory=dict)
    by_ecosystem: dict[str, Tally] = field(default_factory=dict)
    by_source: dict[str, Tally] = field(default_factory=dict)
    by_vulnerability: dict[str, Tally] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)

    @property
    def issues(self) -> int:
        return sum(t.issues for t in self.by_project.values())


def _tally(table: dict[str, Tally], key: str) -> Tally:
    return table.setdefault(key, Tally())


def project_kind(name: str) -> str:
    """`host`, `container`, `code`, `net`, …: the prefix of the project name."""
    kind, sep, _ = name.partition(":")
    return kind if sep else "other"


def ecosystem(component: dict[str, Any]) -> str:
    """The purl type (`pypi`, `deb`, `golang`, …), `cpe` for a CPE-only component."""
    purl = str(component.get("purl") or "")
    if purl.startswith("pkg:"):
        return purl[4:].split("/", 1)[0]
    return "cpe" if component.get("cpe") else "unknown"


def component_name(component: dict[str, Any]) -> str:
    group, name = component.get("group"), str(component.get("name") or "")
    return f"{group}/{name}" if group else name


def _display_id(ids: set[str]) -> str:
    """A CVE id when there is one, else the alphabetically first id."""
    cves = sorted(i for i in ids if i.startswith("CVE-"))
    return cves[0] if cves else sorted(ids)[0]


def merge_aliases(findings: list[dict[str, Any]]) -> list[Issue]:
    """One Issue per alias group (`duplicates.alias_groups`), at its highest severity."""
    out = []
    for group in alias_groups(findings):
        vulns = [f.get("vulnerability") or {} for f in group]
        ids = set().union(*(vulnerability_ids(v) for v in vulns))
        severities = [str(v.get("severity") or "UNASSIGNED") for v in vulns]
        comp = group[0].get("component") or {}
        out.append(
            Issue(
                vuln_id=_display_id(ids),
                ids=ids,
                severity=min(severities, key=lambda s: SEVERITIES.index(s) if s in SEVERITIES else 99),
                sources={str(v.get("source") or "unknown") for v in vulns},
                component=component_name(comp),
                ecosystem=ecosystem(comp),
            )
        )
    return out


def collect(inv: Inventory, dt: DependencyTrack, team: str | None = None) -> Stats:
    """Count the open (unsuppressed) findings of the teams' active projects."""
    stats = Stats()
    seen: set[str] = set()
    for key, t in sorted(inv.teams.items()):
        if team and key != team:
            continue
        try:
            projects = [p for p in dt.projects_by_tag(t.dtrack_tag) if p.active]
        except Exception as e:
            stats.errors.append(f"list DT projects for '{t.dtrack_tag}': {e}")
            continue
        for p in projects:
            if p.uuid in seen:  # a project tagged for two teams is counted once
                continue
            seen.add(p.uuid)
            try:
                findings = dt.findings(p.uuid)
            except Exception as e:
                stats.errors.append(f"findings of {p.name}: {e}")
                continue
            label = project_label(p.name, p.version)
            stats.projects += 1
            stats.findings += len(findings)
            _tally(stats.by_project, label)  # list projects without findings too
            for f in findings:
                source = str((f.get("vulnerability") or {}).get("source") or "unknown")
                _tally(stats.by_source, source).add(
                    str((f.get("vulnerability") or {}).get("severity") or "UNASSIGNED"), label
                )
            for issue in merge_aliases(findings):
                for table, k in (
                    (stats.by_kind, project_kind(p.name)),
                    (stats.by_project, label),
                    (stats.by_component, issue.component),
                    (stats.by_ecosystem, issue.ecosystem),
                    (stats.by_vulnerability, issue.vuln_id),
                ):
                    _tally(table, k).add(issue.severity, label)
    return stats


def _ranked(table: dict[str, Tally], top: int, by_spread: bool = False) -> list[tuple[str, Tally]]:
    def order(kv: tuple[str, Tally]) -> tuple[int, int, str]:
        name, t = kv
        first, second = (len(t.projects), t.issues) if by_spread else (t.issues, len(t.projects))
        return (-first, -second, name)

    rows = sorted(table.items(), key=order)
    return rows[:top] if top > 0 else rows


def render(stats: Stats, top: int = 20) -> str:
    """The report as plain text, one section per table."""
    lines = [
        f"{stats.projects} active projects, {stats.findings} open findings, "
        f"{stats.issues} issues after merging aliases, "
        f"{len(stats.by_vulnerability)} distinct vulnerabilities"
    ]

    def section(title: str, rows: list[tuple[str, Tally]], show_projects: bool) -> None:
        lines.extend(["", f"== {title}"])
        width = max((len(name) for name, _ in rows), default=0)
        for name, t in rows:
            spread = f"  {len(t.projects):3} projects" if show_projects else ""
            lines.append(f"{t.issues:6}  {name:{width}}{spread}  {t.severity_summary()}")

    section("by project kind", _ranked(stats.by_kind, 0), show_projects=True)
    section(f"top {top} projects", _ranked(stats.by_project, top), show_projects=False)
    section(f"top {top} components", _ranked(stats.by_component, top), show_projects=True)
    section("by ecosystem", _ranked(stats.by_ecosystem, 0), show_projects=True)
    section("by advisory source (raw findings)", _ranked(stats.by_source, 0), show_projects=True)
    section(
        f"top {top} vulnerabilities by spread",
        _ranked(stats.by_vulnerability, top, by_spread=True),
        show_projects=True,
    )
    return "\n".join(lines)


def to_json(stats: Stats, top: int = 0) -> dict[str, Any]:
    """The report as JSON-ready data; `top` > 0 cuts the per-project/component/vulnerability
    tables to that many rows."""

    def table(t: dict[str, Tally], cut: int, by_spread: bool = False) -> list[dict[str, Any]]:
        return [
            {
                "name": name,
                "issues": tally.issues,
                "projects": len(tally.projects),
                "severities": {s: tally.severities[s] for s in SEVERITIES if tally.severities[s]},
            }
            for name, tally in _ranked(t, cut, by_spread)
        ]

    return {
        "projects": stats.projects,
        "findings": stats.findings,
        "issues": stats.issues,
        "vulnerabilities": len(stats.by_vulnerability),
        "by_kind": table(stats.by_kind, 0),
        "by_project": table(stats.by_project, top),
        "by_component": table(stats.by_component, top),
        "by_ecosystem": table(stats.by_ecosystem, 0),
        "by_source": table(stats.by_source, 0),
        "by_vulnerability": table(stats.by_vulnerability, top, by_spread=True),
        "errors": stats.errors,
    }
