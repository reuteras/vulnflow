"""Write a reviewed "this can be ignored" decision back to Dependency-Track.

Input is the JSON that `vulnflow debian --json` or `vulnflow disputed --json` prints, which
the operator has edited down to the findings they agree with. Nothing is decided here: every
row in the file is applied, as a Dependency-Track analysis (`NOT_AFFECTED` or
`FALSE_POSITIVE`, suppressed) on that project's component, with a comment saying where the
call came from. DefectDojo follows through the normal `dt2dojo` re-import.

Needs an admin login (DT_ADMIN_PASSWORD, like `agent-bundle`), not the vulnflow team key:
that key is what the unattended glue runs with and stays read-only.

Every write is logged to a ledger (data/ignored.jsonl) with the analysis it replaced, so
`vulnflow unignore` can put it back. `ignore` does not override a finding somebody has
already triaged (any state other than unset) unless asked to; `unignore` only reverts a
finding that is still exactly as vulnflow left it. A finding somebody changed since stays
in the ledger (and in every later `unignore` list) until `unignore --forget-changed` drops
it: the person's decision then stands and vulnflow no longer tracks it.

Dependency-Track API (ASSUMED from memory of the 5.x source; `PUT` and the `GET` fields
`analysisState`/`isSuppressed` have been run against a real instance, the rest has not):
  GET /api/v1/analysis?project=&component=&vulnerability=   current analysis (404 or empty
      if none); analysisComments[] {comment} is ASSUMED
  PUT /api/v1/analysis  {"project","component","vulnerability" (UUIDs), "analysisState",
      "analysisJustification" (optional), "comment", "isSuppressed"}
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import asdict, dataclass
from datetime import UTC, date, datetime
from pathlib import Path
from typing import Any

from .clients import project_label
from .net import Http

log = logging.getLogger(__name__)

STATES = ("NOT_AFFECTED", "FALSE_POSITIVE", "EXPLOITABLE")
# EXPLOITABLE is only written as an accepted risk, with one of these responses (DT 5.2.2
# AnalysisResponse: CAN_NOT_FIX, WILL_NOT_FIX, UPDATE, ROLLBACK, WORKAROUND_AVAILABLE)
ACCEPT_RESPONSES = ("WILL_NOT_FIX", "CAN_NOT_FIX")
# "review by 2027-03-01" in the comment: `prune` lifts the suppression after that day
REVIEW_BY = re.compile(r"\breview by (\d{4}-\d{2}-\d{2})\b")
UNSET = ("", "NOT_SET")


def _set(value: Any) -> str | None:
    """A DT analysis field, with its unset spellings as None."""
    v = str(value or "")
    return None if v in UNSET else v


MARKER = "via vulnflow"  # ends every comment `ignore` writes
REQUIRED = (
    "team",
    "project",
    "project_uuid",
    "component",
    "component_uuid",
    "vuln_id",
    "vuln_uuid",
)
# plus either a `reason` (disputed) or the Debian tracker fields:
DEBIAN_FIELDS = ("urgency", "release", "package")


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
    project_version: str = ""

    @property
    def label(self) -> str:
        return f"{self.team}/{project_label(self.project, self.project_version)}"


def review_date(text: str) -> date | None:
    """The last "review by YYYY-MM-DD" in a comment."""
    found = REVIEW_BY.findall(text or "")
    try:
        return date.fromisoformat(found[-1]) if found else None
    except ValueError:
        return None


def load_review(
    path: Path, today: date | None = None, review_by: date | None = None
) -> list[IgnoreItem]:
    """Read and validate a review file. Any bad row rejects the whole file: a half-applied
    list is worse than none. With review_by, every comment gets "review by <date>", after
    which `prune` shows the finding again."""
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
        need = REQUIRED if str(row.get("reason") or "").strip() else REQUIRED + DEBIAN_FIELDS
        missing = [k for k in need if not str(row.get(k) or "").strip()]
        if missing:
            raise ReviewFileError(
                f"{path}: row {i} ({row.get('vuln_id', '?')}) lacks {', '.join(missing)}; "
                "use output of `vulnflow debian --json` or `disputed --json` from a Dependency-Track "
                "that returns UUIDs"
            )
        if str(row.get("reason") or "").strip():
            comment = f"{str(row['reason']).strip()}; reviewed {day} via vulnflow"
        elif row.get("action") == "fixed" and row.get("fixed") and row.get("installed"):
            # installed version is the fix or newer: NVD's upstream range ignores backports
            if str(row["fixed"]) == "0":
                what = "not affected (Debian fixed_version 0)"
            else:
                what = f"fixed in {row['fixed']}, installed {row['installed']} is not older"
            comment = (
                f"Debian tracker: {what} in {row['release']}, source package "
                f"{row['package']}; reviewed {day} via vulnflow"
            )
        else:
            status = str(row.get("status") or "")
            comment = (
                f"Debian tracker: {row['urgency']}"
                f"{f' ({status})' if status else ''} in {row['release']}, source package "
                f"{row['package']}; reviewed {day} via vulnflow"
            )
        if review_by is not None:
            comment = comment.replace(
                f"; reviewed {day} via vulnflow", f"; review by {review_by}; reviewed {day} via vulnflow"
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
            project_version=str(row.get("project_version") or ""),
        )
        items[(item.project_uuid, item.component_uuid, item.vuln_uuid)] = item
    return list(items.values())


def current_analysis(http: Http, project: str, component: str, vulnerability: str) -> dict[str, Any]:
    path = f"api/v1/analysis?project={project}&component={component}&vulnerability={vulnerability}"
    r = http.get(path, expect_ok=False)
    if r.status == 404:
        return {}
    if not r.ok:
        http.get(path)  # raise with details
    return r.json() or {}


@dataclass
class Kept:
    item: IgnoreItem
    state: str  # what somebody had already set


def _put_body(it: IgnoreItem | RevertItem, state: str, comment: str, suppressed: bool) -> dict[str, Any]:
    return {
        "project": it.project_uuid,
        "component": it.component_uuid,
        "vulnerability": it.vuln_uuid,
        "analysisState": state,
        "comment": comment,
        "isSuppressed": suppressed,
    }


def apply_ignores(
    http: Http,
    items: list[IgnoreItem],
    state: str,
    justification: str | None = None,
    *,
    overwrite: bool = False,
    ledger: Path | None = None,
    response: str | None = None,
) -> tuple[list[IgnoreItem], list[IgnoreItem], list[Kept], list[str]]:
    """(written, already in that state, kept because somebody already triaged them, errors).
    Rewriting an identical analysis would only add a duplicate comment, so those are left
    alone; a different existing analysis is left alone too unless `overwrite`. With
    `overwrite`, a finding already suppressed in `state` is rewritten when its
    justification or response differs (correcting a reason); without it, it counts as
    done. Each write goes to the ledger together with the analysis it replaced."""
    if state not in STATES:
        raise ValueError(f"state must be one of {STATES}")
    if state == "EXPLOITABLE" and response not in ACCEPT_RESPONSES:
        raise ValueError(f"EXPLOITABLE is an accepted risk: response must be one of {ACCEPT_RESPONSES}")
    written: list[IgnoreItem] = []
    skipped: list[IgnoreItem] = []
    kept: list[Kept] = []
    errors: list[str] = []
    for it in items:
        try:
            cur = current_analysis(http, it.project_uuid, it.component_uuid, it.vuln_uuid)
            cur_state = str(cur.get("analysisState") or "")
            if cur_state == state and cur.get("isSuppressed"):
                same = (
                    justification is None or _set(cur.get("analysisJustification")) == justification
                ) and (response is None or _set(cur.get("analysisResponse")) == response)
                if same or not overwrite:
                    skipped.append(it)
                    continue
            if cur_state not in (*UNSET, state) and not overwrite:
                kept.append(Kept(it, cur_state))
                continue
            body = _put_body(it, state, it.comment, True)
            if justification:
                body["analysisJustification"] = justification
            if response:
                body["analysisResponse"] = response
            http.put("api/v1/analysis", json_body=body)
            written.append(it)
            if ledger is not None:
                _append(
                    ledger,
                    {
                        "op": "ignore",
                        **asdict(it),
                        "state": state,
                        "previous_state": cur_state or "NOT_SET",
                        "previous_suppressed": bool(cur.get("isSuppressed")),
                        "previous_justification": _set(cur.get("analysisJustification")) or "NOT_SET",
                    },
                )
        except Exception as e:
            errors.append(f"{it.label}: {it.component} {it.vuln_id}: {e}")
    return written, skipped, kept, errors


# ------------------------------------------------------------------------------- undo
@dataclass
class RevertItem:
    team: str
    project: str
    project_uuid: str
    component: str
    component_uuid: str
    vuln_id: str
    vuln_uuid: str
    expected_state: str  # what vulnflow set, and so what must still be there
    previous_state: str = "NOT_SET"  # what to put back
    previous_suppressed: bool = False
    from_ledger: bool = False
    project_version: str = ""

    @property
    def label(self) -> str:
        return f"{self.team}/{project_label(self.project, self.project_version)}"


def _append(ledger: Path, entry: dict[str, Any]) -> None:
    ledger.parent.mkdir(parents=True, exist_ok=True)
    entry["at"] = datetime.now(UTC).isoformat(timespec="seconds")
    with ledger.open("a", encoding="utf-8") as f:
        f.write(json.dumps(entry) + "\n")


def _key(e: dict[str, Any]) -> tuple[str, str, str]:
    return str(e["project_uuid"]), str(e["component_uuid"]), str(e["vuln_uuid"])


def outstanding(ledger: Path) -> list[RevertItem]:
    """Ledger entries that were written and not reverted since, oldest first. A finding that
    was ignored twice (after a revert) counts once, with its latest previous state."""
    live: dict[tuple[str, str, str], RevertItem] = {}
    if not ledger.is_file():
        return []
    for n, line in enumerate(ledger.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        try:
            e = json.loads(line)
            k = _key(e)
        except (json.JSONDecodeError, KeyError, TypeError) as err:
            raise ReviewFileError(f"{ledger}: line {n} is not a ledger entry ({err})") from err
        if e.get("op") in ("revert", "forget"):
            live.pop(k, None)
        elif e.get("op") == "ignore":
            live[k] = RevertItem(
                team=str(e.get("team", "")),
                project=str(e.get("project", "")),
                project_uuid=k[0],
                component=str(e.get("component", "")),
                component_uuid=k[1],
                vuln_id=str(e.get("vuln_id", "")),
                vuln_uuid=k[2],
                expected_state=str(e.get("state", "")),
                previous_state=str(e.get("previous_state") or "NOT_SET"),
                previous_suppressed=bool(e.get("previous_suppressed")),
                from_ledger=True,
                project_version=str(e.get("project_version") or ""),
            )
    return list(live.values())


def plan_reverts(
    ledger: Path, rows: list[IgnoreItem] | None = None, state: str = "NOT_AFFECTED"
) -> list[RevertItem]:
    """What to undo: every outstanding ledger entry, or, with a review file, just those rows
    (a row that is not in the ledger, e.g. ignored before it existed, goes back to unset)."""
    logged = {(r.project_uuid, r.component_uuid, r.vuln_uuid): r for r in outstanding(ledger)}
    if rows is None:
        return list(logged.values())
    out: list[RevertItem] = []
    for it in rows:
        k = (it.project_uuid, it.component_uuid, it.vuln_uuid)
        out.append(
            logged.get(k)
            or RevertItem(
                it.team,
                it.project,
                it.project_uuid,
                it.component,
                it.component_uuid,
                it.vuln_id,
                it.vuln_uuid,
                expected_state=state,
                project_version=it.project_version,
            )
        )
    return out


def apply_reverts(
    http: Http, items: list[RevertItem], ledger: Path | None = None, *, forget_changed: bool = False
) -> tuple[list[RevertItem], list[tuple[RevertItem, str]], list[str]]:
    """(reverted, skipped with the reason, errors). Only a finding that is still suppressed
    and in the state vulnflow set is touched, so a later human decision is never undone.
    With forget_changed, a ledger entry whose finding somebody changed is closed in the
    ledger (op "forget") instead of being listed again next time."""
    reverted: list[RevertItem] = []
    skipped: list[tuple[RevertItem, str]] = []
    errors: list[str] = []
    for it in items:
        try:
            cur = current_analysis(http, it.project_uuid, it.component_uuid, it.vuln_uuid)
            cur_state = str(cur.get("analysisState") or "")
            if not (cur.get("isSuppressed") and cur_state == it.expected_state):
                now = (cur_state or "NOT_SET") + (", suppressed" if cur.get("isSuppressed") else "")
                why = f"now {now}: not as vulnflow left it ({it.expected_state})"
                if forget_changed and it.from_ledger and ledger is not None:
                    _append(
                        ledger,
                        {
                            "op": "forget",
                            "project_uuid": it.project_uuid,
                            "component_uuid": it.component_uuid,
                            "vuln_uuid": it.vuln_uuid,
                            "found_state": cur_state or "NOT_SET",
                        },
                    )
                    why += "; dropped from the ledger"
                skipped.append((it, why))
                continue
            comments = cur.get("analysisComments")
            if not it.from_ledger and isinstance(comments, list):
                texts = [str(c.get("comment", "")) for c in comments if isinstance(c, dict)]
                if not any(MARKER in t for t in texts):
                    skipped.append((it, f"no comment ending '{MARKER}': not written by vulnflow"))
                    continue
            back = it.previous_state
            note = "Reverted via vulnflow: back to " + back
            if it.previous_suppressed:
                note += " (suppressed)"
            http.put("api/v1/analysis", json_body=_put_body(it, back, note, it.previous_suppressed))
            reverted.append(it)
            if ledger is not None:
                _append(
                    ledger,
                    {
                        "op": "revert",
                        "project_uuid": it.project_uuid,
                        "component_uuid": it.component_uuid,
                        "vuln_uuid": it.vuln_uuid,
                        "restored_state": back,
                    },
                )
        except Exception as e:
            errors.append(f"{it.label}: {it.component} {it.vuln_id}: {e}")
    return reverted, skipped, errors
