"""Tiers for Dependency-Track findings: threat and asset context (docs/exposure.md, step 2).

Each open finding gets a tier from priority.assess with

- the threat: KEV (the cached CISA catalog), EPSS and CVSS v3 score as Dependency-Track
  reports them on the finding (DT keeps its own EPSS copy; no CIRCL lookups here: one
  request per CVE for thousands of findings);
- the asset context from the project's tags (exposure-*, input-*, crit-*; set from
  machines.toml by `context`), and `kind-laptop` for the laptop rule;
- the CVSS v3 vector, which findings leave out: read per vulnerability from Dependency-Track
  once and cached in the data directory (cvss-vectors.json, refreshed after 30 days).

A project without context tags keeps the threat-only tier.
"""

from __future__ import annotations

import json
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .clients import DependencyTrack, DTProject, project_label
from .config import CRITICALITIES, EXPOSURES, INPUTS, AssetContext, Inventory, PriorityRules
from .intel import Signals
from .patches import open_findings
from .priority import Verdict, assess

VECTOR_FILE = "cvss-vectors.json"
VECTOR_TTL = 30 * 86400


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
    p: DTProject, f: dict[str, Any], rules: PriorityRules, kev: set[str], vectors: VectorCache | None
) -> tuple[Verdict, float | None, float | None]:
    """(verdict, CVSS v3 score, EPSS) for one finding of project p."""
    v = f.get("vulnerability") or {}
    vid = str(v.get("vulnId", ""))
    cvss = _num(v.get("cvssV3BaseScore"))
    epss = _num(v.get("epssScore"))
    sig = Signals(
        cve=vid, kev=vid.upper() in kev, epss=epss, epss_percentile=_num(v.get("epssPercentile"))
    )
    ctx, laptop = context_from_tags(p.tags)
    vector = vectors.get(str(v.get("source", "")), vid) if vectors is not None and ctx else ""
    return assess(cvss, sig, rules, ctx, vector, laptop), cvss, epss


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

    @property
    def where(self) -> str:
        return project_label(self.project, self.project_version)


def rank_findings(
    inv: Inventory,
    dt: DependencyTrack,
    kev: set[str],
    vectors: VectorCache | None,
    errors: list[str],
    team: str | None = None,
) -> list[Ranked]:
    """Every unsuppressed finding of the teams' active projects, by tier then severity."""
    out = []
    for t, p, f in open_findings(inv, dt, team, errors):
        verdict, cvss, epss = rank_finding(p, f, inv.rules, kev, vectors)
        c, v = f.get("component") or {}, f.get("vulnerability") or {}
        vid = str(v.get("vulnId", ""))
        out.append(
            Ranked(
                team=t,
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
            )
        )
    if vectors is not None:
        vectors.save()
        errors += vectors.errors
    sev = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "UNASSIGNED")
    out.sort(
        key=lambda r: (r.tier, sev.index(r.severity) if r.severity in sev else 9, r.team, r.vuln_id)
    )
    return out
