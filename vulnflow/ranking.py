"""Tiers for Dependency-Track findings: threat and asset context (docs/exposure.md, step 2).

Each open finding gets a tier from priority.assess with

- the threat: KEV (the cached CISA catalog, plus VulnCheck KEV with a token), EPSS and
  CVSS v3 score as Dependency-Track reports them on the finding (DT keeps its own EPSS
  copy; no CIRCL lookups here: one request per CVE for thousands of findings);
- the asset context from machines.toml (as `context` reads it), or from the project's tags
  (exposure-*, input-*, crit-*) when machines.toml isn't given or has nothing for the
  project, and `kind-laptop` for the laptop rule;
- the CVSS v3 vector, which findings leave out: read per vulnerability from Dependency-Track
  once and cached in the data directory (cvss-vectors.json, refreshed after 30 days).

A project without context tags keeps the threat-only tier.

Two refinements:

- `[hosts.<h>.packages]` in machines.toml: a host project holds every OS package and every
  module built into the host's binaries, so one exposure for all of them is too coarse.
  A package entry (name, or glob) overrides the host's context for that package's
  findings, field by field (nginx `internet`, the rest of the OS `internal`).
- A finding without a CVSS v3 score (many GO-, GHSA- and DEBIAN- advisories) is ranked by
  Dependency-Track's severity instead: CRITICAL as 9.0, HIGH as 7.5, labelled as such.
"""

from __future__ import annotations

import fnmatch
import json
import time
from collections.abc import Callable, Collection, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .clients import DependencyTrack, DTProject, project_label
from .config import (
    CRITICALITIES,
    EXPOSURES,
    INPUTS,
    AssetContext,
    Inventory,
    Machines,
    PriorityRules,
)
from .duplicates import vulnerability_ids
from .intel import Signals, kev_source
from .patches import open_findings
from .priority import Verdict, assess

VECTOR_FILE = "cvss-vectors.json"
VECTOR_TTL = 30 * 86400
# a stand-in score when a finding has no CVSS v3 score (only HIGH and up can change a tier)
SEVERITY_SCORES = {"CRITICAL": 9.0, "HIGH": 7.5}


def package_context(
    machines: Machines | None, p: DTProject, component: str, base: AssetContext | None
) -> tuple[AssetContext | None, str]:
    """The context for a package in a host project: [hosts.<h>.packages] over the host's,
    field by field. Returns (context, the matching pattern or "")."""
    kind, _, host = p.name.partition(":")
    if machines is None or kind != "host" or host not in machines.hosts:
        return base, ""
    pkgs = machines.hosts[host].packages
    exact = [k for k in pkgs if not any(c in k for c in "*?[")]
    globs = sorted((k for k in pkgs if k not in exact), key=len, reverse=True)
    for pattern in [*exact, *globs]:
        if pattern in exact and component != pattern:
            continue
        if pattern not in exact and not fnmatch.fnmatchcase(component, pattern):
            continue
        over = pkgs[pattern]
        if not over:
            continue  # an empty entry doesn't hide a broader one
        b = base or AssetContext()
        return (
            AssetContext(
                exposure=over.exposure or b.exposure,
                input=over.input or b.input,
                criticality=over.criticality or b.criticality,
                eol=over.eol or b.eol,
                certified=over.certified or b.certified,
            ),
            pattern,
        )
    return base, ""


def context_from_tags(tags: list[str]) -> tuple[AssetContext | None, bool]:
    """(the context in a project's tags or None, whether it is a laptop)."""

    def pick(prefix: str, allowed: tuple[str, ...]) -> str:
        return next(
            (t[len(prefix) :] for t in tags if t.startswith(prefix) and t[len(prefix) :] in allowed), ""
        )

    ctx = AssetContext(
        exposure=pick("exposure-", EXPOSURES),
        input=pick("input-", INPUTS),
        criticality=pick("crit-", CRITICALITIES),
        eol="flag-eol" in tags,
        certified="flag-certified" in tags,
    )
    return (ctx if ctx else None), "kind-laptop" in tags


class VectorCache:
    """CVSS v3 vectors per vulnerability (source, id), from Dependency-Track, cached on disk."""

    def __init__(self, dt: DependencyTrack | None, path: Path, now: Callable[[], float] = time.time):
        self.dt, self.path, self.now = dt, path, now
        self.errors: list[str] = []
        self._dirty = False
        try:
            self.data: dict[str, Any] = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            self.data = {}

    def get(self, source: str, vuln_id: str) -> str:
        key = f"{source}/{vuln_id}"
        hit = self.data.get(key)
        if isinstance(hit, dict) and self.now() - float(hit.get("at", 0)) < VECTOR_TTL:
            return str(hit.get("v", ""))
        if self.dt is None or not source or not vuln_id:
            return str(hit.get("v", "")) if isinstance(hit, dict) else ""
        try:
            rec = self.dt.vulnerability(source, vuln_id) or {}
        except Exception as e:  # keep ranking without the vector
            if len(self.errors) < 3:
                self.errors.append(f"CVSS vector for {vuln_id}: {e}")
            return str(hit.get("v", "")) if isinstance(hit, dict) else ""
        vector = str(rec.get("cvssV3Vector") or "")
        self.data[key] = {"v": vector, "at": self.now()}
        self._dirty = True
        return vector

    def save(self) -> None:
        if not self._dirty:
            return
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps(self.data, sort_keys=True) + "\n", encoding="utf-8")
        tmp.replace(self.path)
        self._dirty = False


def _num(v: Any) -> float | None:
    try:
        return None if v in (None, "") else float(v)
    except (TypeError, ValueError):
        return None


def rank_finding(
    p: DTProject,
    f: dict[str, Any],
    rules: PriorityRules,
    kev: Collection[str],
    vectors: VectorCache | None,
    machines: Machines | None = None,
) -> tuple[Verdict, float | None, float | None]:
    """(verdict, CVSS v3 score, EPSS) for one finding of project p. `kev` is the KEV index
    (CVE id -> entry; the reason then names its catalog) or a set of ids."""
    v = f.get("vulnerability") or {}
    vid = str(v.get("vulnId", ""))
    cvss = _num(v.get("cvssV3BaseScore"))
    epss = _num(v.get("epssScore"))
    label = ""
    severity = str(v.get("severity") or "").upper()
    if cvss is None and severity in SEVERITY_SCORES:
        cvss, label = SEVERITY_SCORES[severity], f"severity {severity} (no CVSS score)"
    sig = Signals(
        cve=vid,
        kev=vid.upper() in kev,
        kev_source=kev_source(kev, vid),
        epss=epss,
        epss_percentile=_num(v.get("epssPercentile")),
    )
    ctx, laptop = context_from_tags(p.tags)
    if machines is not None:
        # machines.toml as it is now, not the tags the last `context` run set: an edit
        # shows at once and agrees with the package entries; tags only as a fallback
        from .context import context_for

        ctx = context_for(machines, p) or ctx
    component = str((f.get("component") or {}).get("name", ""))
    ctx, pattern = package_context(machines, p, component, ctx)
    vector = vectors.get(str(v.get("source", "")), vid) if vectors is not None and ctx else ""
    verdict = assess(cvss, sig, rules, ctx, vector, laptop, label)
    verdict.criticality = ctx.criticality if ctx else ""
    verdict.exposure = ctx.exposure if ctx else ""
    if pattern:
        verdict.reasons.append(f"package {pattern!r} in machines.toml")
    return verdict, (None if label else cvss), epss


@dataclass
class Ranked:
    team: str
    project: str
    project_version: str
    component: str
    version: str
    vuln_id: str
    severity: str
    tier: int
    tier_name: str
    reasons: list[str] = field(default_factory=list)
    cvss: float | None = None
    epss: float | None = None
    kev: bool = False
    criticality: str = ""  # the asset's ("" = unknown)
    title: str = ""  # KEV's name, the vulnerability's title or its description's first sentence
    cpe: str = ""  # the component's, if it has one ([chat.*] channels match on it)
    component_uuid: str = ""  # DT's, for a link to the component
    aliases: list[str] = field(default_factory=list)  # the vulnerability's other ids (DT aliases)

    @property
    def where(self) -> str:
        return project_label(self.project, self.project_version)


def finding_title(v: dict[str, Any], kev_name: str = "") -> str:
    if kev_name:
        return kev_name
    if v.get("title"):
        return str(v["title"])
    first = " ".join(str(v.get("description") or "").split()).split(". ")[0]
    return first if len(first) <= 100 else first[:97].rstrip() + "..."


def to_ranked(
    team: str,
    p: DTProject,
    f: dict[str, Any],
    verdict: Verdict,
    cvss: float | None,
    epss: float | None,
    kev: Collection[str],
) -> Ranked:
    c, v = f.get("component") or {}, f.get("vulnerability") or {}
    vid = str(v.get("vulnId", ""))
    entry = kev.get(vid.upper()) if isinstance(kev, Mapping) else None
    return Ranked(
        team=team,
        project=p.name,
        project_version=p.version,
        component=str(c.get("name", "")),
        version=str(c.get("version", "")),
        vuln_id=vid,
        severity=str(v.get("severity") or "UNASSIGNED").upper(),
        tier=verdict.tier,
        tier_name=verdict.name,
        reasons=verdict.reasons,
        cvss=cvss,
        epss=epss,
        kev=vid.upper() in kev,
        criticality=verdict.criticality,
        title=finding_title(v, str((entry or {}).get("vulnerabilityName", ""))),
        cpe=str(c.get("cpe") or ""),
        component_uuid=str(c.get("uuid") or ""),
        aliases=sorted(vulnerability_ids(v) - {vid}),
    )


def rank_findings(
    inv: Inventory,
    dt: DependencyTrack,
    kev: Collection[str],
    vectors: VectorCache | None,
    errors: list[str],
    team: str | None = None,
    machines: Machines | None = None,
) -> list[Ranked]:
    """Every unsuppressed finding of the teams' active projects, by tier then severity."""
    out = []
    for t, p, f in open_findings(inv, dt, team, errors):
        verdict, cvss, epss = rank_finding(p, f, inv.rules, kev, vectors, machines)
        out.append(to_ranked(t, p, f, verdict, cvss, epss, kev))
    if vectors is not None:
        vectors.save()
        errors += vectors.errors
    sev = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "UNASSIGNED")
    out.sort(
        key=lambda r: (r.tier, sev.index(r.severity) if r.severity in sev else 9, r.team, r.vuln_id)
    )
    return out


@dataclass
class Ranker:
    """What ranking needs, bundled for dt2dojo: the rules, the KEV catalog (id -> entry),
    the vector cache and machines.toml. With `record` set, every unsuppressed finding ranked
    for a team is kept there too (finding-watch notifies from it after the round)."""

    rules: PriorityRules
    kev: dict[str, dict[str, Any]] = field(default_factory=dict)
    vectors: VectorCache | None = None
    machines: Machines | None = None
    record: list[Ranked] | None = None

    def rank(self, p: DTProject, f: dict[str, Any], team: str = "") -> Verdict:
        verdict, cvss, epss = rank_finding(p, f, self.rules, self.kev, self.vectors, self.machines)
        suppressed = (f.get("analysis") or {}).get("isSuppressed")
        if self.record is not None and team and not suppressed:
            self.record.append(to_ranked(team, p, f, verdict, cvss, epss, self.kev))
        return verdict
