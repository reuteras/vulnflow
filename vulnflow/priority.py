"""Turn signals into a tier. Deliberately simple and explainable (every tier has reasons).

The threat (KEV and exploited sightings, EPSS, CVSS) gives a row; the asset context
(docs/exposure.md: exposure, input, criticality) picks the column and adjusts:

    threat \\ where          internet/public  external-auth  internal  restricted+staff
    KEV or exploited               P1              P1            P1           P2
    high EPSS, or critical+EPSS    P1              P2            P2           P3
    CVSS high                      P2              P3            P3           P4
    other                          P3              P4            P4           P4

- Without context the column is `internal`, which is exactly the threat-only tier vulnflow
  had before context existed (OpenCVE alerts, unknown projects).
- `input = "public"` and `hostile-device` count as the internet column.
- The CVSS attack vector decides whether reachability matters: a Local or Physical bug
  is ranked in the restricted column, an Adjacent one at most as internal. On a laptop a
  network bug that needs user interaction (browser, mail, PDF; UI:R) counts as internet,
  because its users open what attackers send.
- criticality `critical`/`high` raises one step, but only a real threat (KEV or exploited,
  high EPSS, CVSS high): a finding with nothing behind it stays where the matrix puts it.
  `low` lowers one step. KEV or an exploited sighting on a `critical` asset is P1.
"""

from __future__ import annotations

from dataclasses import dataclass

from .config import AssetContext, PriorityRules
from .intel import Signals

TIER_NAMES = {1: "P1 Act", 2: "P2 Attend", 3: "P3 Track", 4: "P4 Watch"}

# columns
INTERNET, EXTERNAL_AUTH, INTERNAL, RESTRICTED = range(4)
COLUMN_NAMES = {
    INTERNET: "internet",
    EXTERNAL_AUTH: "external-auth",
    INTERNAL: "internal",
    RESTRICTED: "restricted",
}
MATRIX = (  # row = threat (0 = KEV/exploited .. 3 = other), column as above -> tier
    (1, 1, 1, 2),
    (1, 2, 2, 3),
    (2, 3, 3, 4),
    (3, 4, 4, 4),
)
EXPOSURE_COLUMNS = {
    "internet": INTERNET,
    "hostile-device": INTERNET,
    "external-auth": EXTERNAL_AUTH,
    "internal": INTERNAL,
    "restricted": RESTRICTED,
}


@dataclass
class Verdict:
    tier: int
    reasons: list[str]

    @property
    def name(self) -> str:
        return TIER_NAMES[self.tier]


def threat(
    cvss: float | None, sig: Signals, rules: PriorityRules, cvss_label: str = ""
) -> tuple[int, list[str]]:
    """The matrix row (0 = KEV or exploited .. 3 = other) and why. cvss_label names where a
    stand-in score came from (e.g. "severity HIGH, no CVSS score") instead of "CVSS x"."""
    name = cvss_label or f"CVSS {cvss}"
    reasons: list[str] = []
    if sig.kev:
        reasons.append("in CISA KEV" + (" (ransomware use)" if sig.kev_ransomware else ""))
    if sig.exploited_sightings:
        reasons.append(f"{sig.exploited_sightings} 'exploited' sighting(s) (CIRCL)")
    if reasons:
        return 0, reasons

    epss = sig.epss
    if epss is not None and epss >= rules.epss_attend:
        return 1, [f"EPSS {epss:.3f} >= {rules.epss_attend}"]
    if (
        cvss is not None
        and cvss >= rules.cvss_critical
        and epss is not None
        and epss >= rules.epss_floor
    ):
        return 1, [f"{name} critical and EPSS {epss:.3f} >= {rules.epss_floor}"]
    if cvss is not None and cvss >= rules.cvss_high:
        why = [name if cvss_label else f"CVSS {cvss} >= {rules.cvss_high}"]
        if epss is None:
            why.append("no EPSS yet")
        return 2, why

    why = []
    if cvss is None:
        why.append("no CVSS (likely unenriched in NVD - check CNA/vendor advisory)")
    else:
        why.append(name)
    if sig.sightings.get("seen"):
        why.append(f"{sig.sightings['seen']} 'seen' sighting(s)")
    return 3, why


def vector_metrics(vector: str) -> dict[str, str]:
    """`CVSS:3.1/AV:N/AC:L/PR:N/UI:R/...` -> {"AV": "N", "UI": "R", ...}; {} if none."""
    out = {}
    for part in vector.split("/"):
        k, sep, v = part.partition(":")
        if sep and k != "CVSS":
            out[k] = v
    return out


def column(
    context: AssetContext | None, vector: str = "", laptop: bool = False
) -> tuple[int, list[str]]:
    """The matrix column for this asset and CVE, and why (empty without context)."""
    if not context or not (context.exposure or context.input == "public"):
        return INTERNAL, []
    col = EXPOSURE_COLUMNS.get(context.exposure, INTERNAL)
    why = [context.exposure] if context.exposure else []
    if context.input == "public" and col != INTERNET:
        col = INTERNET
        why.append("public input")
    m = vector_metrics(vector)
    av, ui = m.get("AV", ""), m.get("UI", "")
    if laptop and av == "N" and ui == "R" and col != INTERNET:
        col = INTERNET
        why.append("laptop: needs a user to open something (UI:R)")
    elif av in ("L", "P") and col != RESTRICTED:
        col = RESTRICTED
        why.append(f"{'local' if av == 'L' else 'physical'} access needed (AV:{av})")
    elif av == "A" and col < INTERNAL:
        col = INTERNAL
        why.append("adjacent network only (AV:A)")
    return col, why


def assess(
    cvss: float | None,
    sig: Signals,
    rules: PriorityRules,
    context: AssetContext | None = None,
    vector: str = "",
    laptop: bool = False,
    cvss_label: str = "",
) -> Verdict:
    row, reasons = threat(cvss, sig, rules, cvss_label)
    col, where = column(context, vector, laptop)
    tier = MATRIX[row][col]
    crit = context.criticality if context else ""
    if crit in ("critical", "high") and row <= 2:  # only lift a real threat
        tier = max(1, tier - 1)
        where.append(f"{crit} asset")
    elif crit == "low":
        tier = min(4, tier + 1)
        where.append("low criticality")
    if row == 0 and crit == "critical":
        tier = 1
    return Verdict(tier, reasons + where)
