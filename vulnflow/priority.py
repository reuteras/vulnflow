"""Turn signals into a tier. Deliberately simple and explainable (every tier has reasons)."""

from __future__ import annotations

from dataclasses import dataclass

from .config import PriorityRules
from .intel import Signals

TIER_NAMES = {1: "P1 Act", 2: "P2 Attend", 3: "P3 Track", 4: "P4 Watch"}


@dataclass
class Verdict:
    tier: int
    reasons: list[str]

    @property
    def name(self) -> str:
        return TIER_NAMES[self.tier]


def assess(cvss: float | None, sig: Signals, rules: PriorityRules) -> Verdict:
    reasons: list[str] = []
    if sig.kev:
        reasons.append("in CISA KEV" + (" (ransomware use)" if sig.kev_ransomware else ""))
    if sig.exploited_sightings:
        reasons.append(f"{sig.exploited_sightings} 'exploited' sighting(s) (CIRCL)")
    if reasons:
        return Verdict(1, reasons)

    epss = sig.epss
    if epss is not None and epss >= rules.epss_attend:
        return Verdict(2, [f"EPSS {epss:.3f} >= {rules.epss_attend}"])
    if (
        cvss is not None
        and cvss >= rules.cvss_critical
        and epss is not None
        and epss >= rules.epss_floor
    ):
        return Verdict(2, [f"CVSS {cvss} critical and EPSS {epss:.3f} >= {rules.epss_floor}"])
    if cvss is not None and cvss >= rules.cvss_high:
        why = [f"CVSS {cvss} >= {rules.cvss_high}"]
        if epss is None:
            why.append("no EPSS yet")
        return Verdict(3, why)

    why = []
    if cvss is None:
        why.append("no CVSS (likely unenriched in NVD - check CNA/vendor advisory)")
    else:
        why.append(f"CVSS {cvss}")
    if sig.sightings.get("seen"):
        why.append(f"{sig.sightings['seen']} 'seen' sighting(s)")
    return Verdict(4, why)
