"""Write a reviewed "this can be ignored" decision back to Dependency-Track.

Input is the JSON that `vulnflow debian --json` prints, which the operator has edited down to
the findings they agree with. Nothing is decided here: every row in the file is applied, as a
Dependency-Track analysis (`NOT_AFFECTED` or `FALSE_POSITIVE`, suppressed) on that project's
component, with a comment saying where the call came from. DefectDojo follows through the
normal `dt2dojo` re-import.

Needs an admin login (DT_ADMIN_PASSWORD, like `agent-bundle`), not the vulnflow team key:
that key is what the unattended glue runs with and stays read-only.

Dependency-Track API (ASSUMED from memory of the 5.x source, not checked against a tag):
  GET /api/v1/analysis?project=&component=&vulnerability=   current analysis (404 or empty
      if none)
  PUT /api/v1/analysis  {"project","component","vulnerability" (UUIDs), "analysisState",
      "analysisJustification" (optional), "comment", "isSuppressed"}
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from datetime import date
from pathlib import Path
from typing import Any

from .net import Http

log = logging.getLogger(__name__)

STATES = ("NOT_AFFECTED", "FALSE_POSITIVE")
REQUIRED = (
    "team",
    "project",
    "project_uuid",
    "component",
    "component_uuid",
    "vuln_id",
    "vuln_uuid",
    "urgency",
    "release",
    "package",
)


class ReviewFileError(ValueError):
    pass


@dataclass
class IgnoreItem:
    team: str
    project: str
    project_uuid: str
    component: str
    version: str
    component_uuid: str
    vuln_id: str
    vuln_uuid: str
    comment: str


def load_review(path: Path, today: date | None = None) -> list[IgnoreItem]:
    """Read and validate a review file. Any bad row rejects the whole file: a half-applied
    list is worse than none."""
    try:
        rows = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as e:
        raise ReviewFileError(f"cannot read {path}: {e}") from e
    if not isinstance(rows, list):
        raise ReviewFileError(f"{path}: expected a JSON list (the output of `vulnflow debian --json`)")
    day = (today or date.today()).isoformat()
    items: dict[tuple[str, str, str], IgnoreItem] = {}
    for i, row in enumerate(rows):
        if not isinstance(row, dict):
            raise ReviewFileError(f"{path}: row {i} is not an object")
        missing = [k for k in REQUIRED if not str(row.get(k) or "").strip()]
        if missing:
            raise ReviewFileError(
                f"{path}: row {i} ({row.get('vuln_id', '?')}) lacks {', '.join(missing)}; "
                "use output of `vulnflow debian --json` from a Dependency-Track that returns UUIDs"
            )
        status = str(row.get("status") or "")
        comment = (
            f"Debian tracker: {row['urgency']}"
            f"{f' ({status})' if status else ''} in {row['release']}, source package "
            f"{row['package']}; reviewed {day} via vulnflow"
        )
        item = IgnoreItem(
            team=str(row["team"]),
            project=str(row["project"]),
            project_uuid=str(row["project_uuid"]),
            component=str(row["component"]),
            version=str(row.get("version") or ""),
            component_uuid=str(row["component_uuid"]),
            vuln_id=str(row["vuln_id"]),
            vuln_uuid=str(row["vuln_uuid"]),
            comment=comment,
        )
        items[(item.project_uuid, item.component_uuid, item.vuln_uuid)] = item
    return list(items.values())


def current_analysis(http: Http, item: IgnoreItem) -> dict[str, Any]:
    path = (
        f"api/v1/analysis?project={item.project_uuid}"
        f"&component={item.component_uuid}&vulnerability={item.vuln_uuid}"
    )
    r = http.get(path, expect_ok=False)
    if r.status == 404:
        return {}
    if not r.ok:
        http.get(path)  # raise with details
    return r.json() or {}


def apply_ignores(
    http: Http, items: list[IgnoreItem], state: str, justification: str | None = None
) -> tuple[list[IgnoreItem], list[IgnoreItem], list[str]]:
    """(written, already in that state, errors). Rewriting an identical analysis would only
    add a duplicate comment, so those are left alone."""
    if state not in STATES:
        raise ValueError(f"state must be one of {STATES}")
    written: list[IgnoreItem] = []
    skipped: list[IgnoreItem] = []
    errors: list[str] = []
    for it in items:
        try:
            cur = current_analysis(http, it)
            if cur.get("analysisState") == state and cur.get("isSuppressed"):
                skipped.append(it)
                continue
            body: dict[str, Any] = {
                "project": it.project_uuid,
                "component": it.component_uuid,
                "vulnerability": it.vuln_uuid,
                "analysisState": state,
                "comment": it.comment,
                "isSuppressed": True,
            }
            if justification:
                body["analysisJustification"] = justification
            http.put("api/v1/analysis", json_body=body)
            written.append(it)
        except Exception as e:
            errors.append(f"{it.team}/{it.project}: {it.component} {it.vuln_id}: {e}")
    return written, skipped, errors
