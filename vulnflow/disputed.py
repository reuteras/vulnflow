"""Open findings whose CVE record says it is disputed or rejected.

NVD (and so Dependency-Track's copy) puts a marker at the start of the description when a
supplier disputes that a CVE is a vulnerability, or when the CVE was withdrawn:

    ** DISPUTED ** An issue was discovered in ...
    ** REJECT ** DO NOT USE THIS CANDIDATE NUMBER. ...

No new data is fetched: the description comes with the finding (or, if the finding lacks
one, from the vulnerability record, which DT already holds).

A marker is a signal for review, not a verdict. Who disputes it varies (sometimes the
maintainer says "working as intended", sometimes a vendor disputes a researcher). The rows
use the same shape as `vulnflow debian --json`, so after review `vulnflow ignore` can apply
them; the `reason` field becomes the analysis comment.

Finding/vulnerability field names (`vulnerability.description`, `uuid`) are ASSUMED from
memory of the DT 5.x API, not checked against a tag.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from typing import Any

from .clients import DependencyTrack
from .config import Inventory
from .patches import open_findings

log = logging.getLogger(__name__)

# The marker leads the description; anchoring avoids matching a CVE that merely mentions it.
MARKER = re.compile(r"\s*\*\*\s*(DISPUTED|REJECT(?:ED)?)\s*\*\*\s*(.*)", re.IGNORECASE | re.DOTALL)
SNIPPET = 160


@dataclass
class DisputedFinding:
    team: str
    project: str
    component: str
    version: str
    vuln_id: str
    severity: str
    marker: str
    reason: str
    project_uuid: str = ""
    component_uuid: str = ""
    vuln_uuid: str = ""


def disputed_marker(description: str) -> tuple[str, str] | None:
    """(DISPUTED|REJECT, text after the marker) if the description starts with one."""
    m = MARKER.match(description or "")
    if not m:
        return None
    return ("REJECT" if m.group(1).upper().startswith("REJECT") else "DISPUTED"), m.group(2).strip()


def _reason(vuln_id: str, marker: str, text: str) -> str:
    snippet = " ".join(text.split())
    if len(snippet) > SNIPPET:
        snippet = snippet[: SNIPPET - 1].rstrip() + "…"
    return f"{vuln_id} is marked {marker} in its CVE record" + (f': "{snippet}"' if snippet else "")


def disputed_findings(
    inv: Inventory, dt: DependencyTrack, team: str | None = None
) -> tuple[list[DisputedFinding], int, list[str]]:
    """(findings with a marker, count of open findings checked, errors)."""
    rows: list[DisputedFinding] = []
    errors: list[str] = []
    checked = 0
    records: dict[tuple[str, str], str] = {}  # description lookups for findings without one
    for key, proj, f in open_findings(inv, dt, team, errors):
        v: dict[str, Any] = f.get("vulnerability") or {}
        src, vid = str(v.get("source") or ""), str(v.get("vulnId") or "")
        if not vid:
            continue
        checked += 1
        desc = str(v.get("description") or "")
        if not desc and src:
            if (src, vid) not in records:
                try:
                    rec = dt.vulnerability(src, vid) or {}
                    records[(src, vid)] = str(rec.get("description") or "")
                except Exception as e:
                    errors.append(f"{src}/{vid}: {e}")
                    records[(src, vid)] = ""
            desc = records[(src, vid)]
        hit = disputed_marker(desc)
        if hit is None:
            continue
        marker, text = hit
        c: dict[str, Any] = f.get("component") or {}
        rows.append(
            DisputedFinding(
                team=key,
                project=proj.name,
                component=c.get("name", ""),
                version=c.get("version", ""),
                vuln_id=vid,
                severity=v.get("severity", ""),
                marker=marker,
                reason=_reason(vid, marker, text),
                project_uuid=proj.uuid,
                component_uuid=str(c.get("uuid") or ""),
                vuln_uuid=str(v.get("uuid") or ""),
            )
        )
    # withdrawn candidates first: they are the clearest cases
    rows.sort(key=lambda r: (r.marker != "REJECT", r.team, r.project, r.component, r.vuln_id))
    return rows, checked, errors
