"""DefectDojo works from the tiers (docs/exposure.md, step 3), without code in DefectDojo.

After each re-import, dt2dojo ranks the project's findings (the FPF it just uploaded,
ranking.py) and updates the DefectDojo findings of that test through the API:

- tag `tier-p1` .. `tier-p4` (the previous tier tag replaced, other tags kept; the
  re-import only adds tags, so the tag survives the next round);
- `known_exploited`, `ransomware_used`, `kev_date` from the CISA KEV catalog (DefectDojo's
  own Dependency-Track parser already copies EPSS);
- `planned_remediation_date`: the finding's date plus `[priority] sla_days` for its tier
  (P1 7, P2 30, P3 90 days, P4 none by default). Only a date vulnflow set is changed: an
  empty one, or one that equals what the previous tier tag gave. A date someone set by
  hand stays.

DefectDojo's own SLA dates still follow severity; replacing that would need code inside
DefectDojo (its FINDING_SLA_PERIOD_METHOD hook), which vulnflow doesn't add.

The match is exact: DefectDojo stores Dependency-Track's finding `matrix` as
`unique_id_from_tool` (dojo/tools/dependency_track/parser.py, 3.5.300).
"""

from __future__ import annotations

import json
from datetime import date, timedelta
from typing import Any

from .clients import DefectDojo, DTProject
from .ranking import Ranker

TIER_TAGS = tuple(f"tier-p{t}" for t in (1, 2, 3, 4))


def _planned(found: str, tier: int, sla_days: dict[str, int]) -> str | None:
    days = sla_days.get(f"p{tier}")
    if days is None or not found:
        return None
    try:
        return (date.fromisoformat(found[:10]) + timedelta(days=int(days))).isoformat()
    except ValueError:
        return None


def desired(
    dd: dict[str, Any], tier: int, kev: dict[str, Any] | None, sla_days: dict[str, int]
) -> dict[str, Any]:
    """The PATCH body that brings one DefectDojo finding in line ({} if it already is)."""
    body: dict[str, Any] = {}
    tags = [str(t) for t in dd.get("tags") or []]
    old_tier = next((int(t[-1]) for t in tags if t in TIER_TAGS), 0)
    want_tags = sorted({t for t in tags if t not in TIER_TAGS} | {f"tier-p{tier}"})
    if sorted(tags) != want_tags:
        body["tags"] = want_tags
    known = kev is not None
    ransomware = False
    added = None
    if kev is not None:
        ransomware = str(kev.get("knownRansomwareCampaignUse", "")).lower() == "known"
        added = str(kev.get("dateAdded", ""))[:10] or None
    if bool(dd.get("known_exploited")) != known:
        body["known_exploited"] = known
    if bool(dd.get("ransomware_used")) != ransomware:
        body["ransomware_used"] = ransomware
    if (dd.get("kev_date") or None) != (added or None):
        body["kev_date"] = added or None
    found = str(dd.get("date") or "")
    current = dd.get("planned_remediation_date") or None
    ours = current is None or (old_tier and current == _planned(found, old_tier, sla_days))
    want = _planned(found, tier, sla_days)
    if ours and current != want:
        body["planned_remediation_date"] = want
    return body


def apply_tiers(
    dojo: DefectDojo, test_id: int, p: DTProject, fpf: bytes, ranker: Ranker
) -> tuple[int, int]:
    """(findings updated, findings ranked) for one re-imported test."""
    findings = (json.loads(fpf) or {}).get("findings") or []
    by_matrix: dict[str, tuple[int, str]] = {}
    for f in findings:
        matrix = str(f.get("matrix") or (f.get("vulnerability") or {}).get("matrix") or "")
        if matrix:
            vid = str((f.get("vulnerability") or {}).get("vulnId", "")).upper()
            by_matrix[matrix] = (ranker.rank(p, f).tier, vid)
    updated = 0
    for dd in dojo.test_findings(test_id):
        hit = by_matrix.get(str(dd.get("unique_id_from_tool") or ""))
        if hit is None:
            continue
        tier, vid = hit
        body = desired(dd, tier, ranker.kev.get(vid), ranker.rules.sla_days)
        if body:
            dojo.patch_finding(int(dd["id"]), body)
            updated += 1
    return updated, len(by_matrix)
