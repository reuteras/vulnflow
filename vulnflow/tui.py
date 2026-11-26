"""Terminal UI: `vulnflow tui` (`./poc.sh tui` passes the receiver's alert log in).

Four tabs, read from the same places as the reports:

    1 Findings   open Dependency-Track findings of every team (active projects,
                 unsuppressed), with KEV marks; filter by team, severity and text;
                 Enter shows one (description, where on disk), `m` marks it
    2 Alerts     the receiver's alerts.jsonl, newest first; filter by team, tier, KEV
                 and text; Enter shows one (reasons, scores, description, OpenCVE link)
    3 Hosts      own machines and their last SBOM upload
    4 Updates    check-updates (asks GitHub, so only when the tab is opened)

Triage (`m` on a finding, or on the findings selected with space) writes the same
Dependency-Track analysis as `vulnflow ignore`, through `triage.apply_ignores`: Not
Affected with a justification, False Positive, or an accepted risk (Exploitable + Will
Not Fix / Can Not Fix) with a review date. It needs a reason, shows what it will write
and asks for `y` first, logs to the same ledger (data/ignored.jsonl), so `vulnflow
unignore` takes it back. Writing needs DT_ADMIN_PASSWORD, like `ignore`; without it the
TUI is read-only.

The screen logic works on any object with curses' addnstr/getmaxyx/erase/refresh/getch,
so the tests drive it with a fake screen; curses itself is only used by run().
"""

from __future__ import annotations

import curses
import json
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from datetime import date
from pathlib import Path
from typing import Any, Protocol

from .clients import DependencyTrack
from .config import Inventory, Machines
from .machines import host_scans, project_name
from .net import Http
from .patches import open_findings
from .triage import ACCEPT_RESPONSES, IgnoreItem, apply_ignores
from .where import paths_of

SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "UNASSIGNED")
JUSTIFICATIONS = (  # Dependency-Track 5.2.2 AnalysisJustification
    "CODE_NOT_PRESENT",
    "CODE_NOT_REACHABLE",
    "REQUIRES_CONFIGURATION",
    "REQUIRES_DEPENDENCY",
    "REQUIRES_ENVIRONMENT",
    "PROTECTED_BY_COMPILER",
    "PROTECTED_AT_RUNTIME",
    "PROTECTED_AT_PERIMETER",
    "PROTECTED_BY_MITIGATING_CONTROL",
)
TABS = ("Findings", "Alerts", "Hosts", "Updates")
ESC = 27
ENTER_KEYS = (10, 13, curses.KEY_ENTER)
HELP = (
    "1-4 tabs  j/k move  / text  t team  s severity  space select  "
    "Enter show (J/K next/prev)  m mark  r reload  q quit"
)
ALERT_HELP = (
    "1-4 tabs  j/k move  / text  t team  p tier  e KEV only  "
    "Enter show (J/K next/prev)  r reload  q quit"
)
TIER_LIMITS = (0, 1, 2, 3)  # `p` steps through: all, P1, P1-P2, P1-P3


class Screen(Protocol):
    def addnstr(self, y: int, x: int, s: str, n: int, attr: int = 0) -> None: ...
    def getmaxyx(self) -> tuple[int, int]: ...
    def erase(self) -> None: ...
    def refresh(self) -> None: ...
    def getch(self) -> int: ...


@dataclass
class FindingRow:
    team: str
    project: str
    project_version: str
    project_uuid: str
    component: str
    version: str
    component_uuid: str
    vuln_id: str
    vuln_uuid: str
    severity: str
    source: str = ""
    description: str = ""
    purl: str = ""
    kev: bool = False

    @property
    def key(self) -> tuple[str, str, str]:
        return (self.project_uuid, self.component_uuid, self.vuln_uuid)

    @property
    def where(self) -> str:
        return f"{self.project}@{self.project_version}" if self.project_version else self.project


def load_findings(
    inv: Inventory, dt: DependencyTrack, kev: set[str], errors: list[str]
) -> list[FindingRow]:
    rows = []
    for team, p, f in open_findings(inv, dt, None, errors):
        c, v = f.get("component") or {}, f.get("vulnerability") or {}
        vid = str(v.get("vulnId", ""))
        rows.append(
            FindingRow(
                team=team,
                project=p.name,
                project_version=p.version,
                project_uuid=p.uuid,
                component=str(c.get("name", "")),
                version=str(c.get("version", "")),
                component_uuid=str(c.get("uuid", "")),
                vuln_id=vid,
                vuln_uuid=str(v.get("uuid", "")),
                severity=str(v.get("severity") or "UNASSIGNED").upper(),
                source=str(v.get("source", "")),
                description=" ".join(str(v.get("description") or "").split()),
                purl=str(c.get("purl", "")),
                kev=vid in kev,
            )
        )
    return sort_rows(rows)


def _sev_rank(sev: str) -> int:
    return SEVERITIES.index(sev) if sev in SEVERITIES else len(SEVERITIES)


def sort_rows(rows: Iterable[FindingRow]) -> list[FindingRow]:
    return sorted(rows, key=lambda r: (not r.kev, _sev_rank(r.severity), r.team, r.vuln_id, r.where))


def filter_rows(
    rows: list[FindingRow], team: str = "", min_sev: str = "", text: str = ""
) -> list[FindingRow]:
    limit = _sev_rank(min_sev) if min_sev else len(SEVERITIES)
    needle = text.lower()
    return [
        r
        for r in rows
        if (not team or r.team == team)
        and _sev_rank(r.severity) <= limit
        and (not needle or needle in f"{r.vuln_id} {r.component} {r.version} {r.where} {r.purl}".lower())
    ]


def finding_line(r: FindingRow, width: int, selected: bool = False) -> str:
    mark = "*" if selected else " "
    kev = "KEV" if r.kev else "   "
    head = f"{mark} {r.severity[:4]:<4} {kev} {r.vuln_id:<20} {r.team:<7}"
    return f"{head} {r.component} {r.version}  {r.where}"[:width]


@dataclass
class Decision:
    state: str  # NOT_AFFECTED, FALSE_POSITIVE, EXPLOITABLE
    reason: str
    justification: str | None = None
    response: str | None = None
    review_by: date | None = None
    invalid: str = ""  # input that could not be read, e.g. a bad date

    def problems(self, today: date) -> list[str]:
        out = [self.invalid] if self.invalid else []
        if not self.reason.strip():
            out.append("a reason is required")
        if self.state == "EXPLOITABLE":
            if self.response not in ACCEPT_RESPONSES:
                out.append("an accepted risk needs Will Not Fix or Can Not Fix")
            if self.review_by is None:
                out.append("an accepted risk needs a review date")
        if self.review_by is not None and self.review_by <= today:
            out.append("the review date must be in the future")
        return out

    def label(self) -> str:
        bits = [self.state]
        if self.justification:
            bits.append(self.justification)
        if self.response:
            bits.append(self.response)
        if self.review_by:
            bits.append(f"review by {self.review_by}")
        return ", ".join(bits)


def ignore_item(r: FindingRow, d: Decision, today: date) -> IgnoreItem:
    """The same comment shape `ignore` writes, so `prune` and `unignore` read it alike."""
    review = f"; review by {d.review_by}" if d.review_by else ""
    return IgnoreItem(
        team=r.team,
        project=r.project,
        project_uuid=r.project_uuid,
        component=r.component,
        version=r.version,
        component_uuid=r.component_uuid,
        vuln_id=r.vuln_id,
        vuln_uuid=r.vuln_uuid,
        comment=f"{' '.join(d.reason.split())}{review}; reviewed {today} via vulnflow tui",
        project_version=r.project_version,
    )


@dataclass
class AlertRow:
    """One line of the receiver's alerts.jsonl (vulnflow.receiver.Alert as written)."""

    received_at: str
    cve: str
    team: str
    tier: int
    tier_name: str
    kev: bool = False
    epss: float | None = None
    epss_percentile: float | None = None
    cvss31: float | None = None
    project: str = ""
    organization: str = ""
    event_types: list[str] = field(default_factory=list)
    reasons: list[str] = field(default_factory=list)
    sightings: dict[str, int] = field(default_factory=dict)
    description: str = ""
    enrichment_errors: list[str] = field(default_factory=list)


def _num(v: Any) -> float | None:
    return float(v) if isinstance(v, int | float) and not isinstance(v, bool) else None


def parse_alerts(raw: Iterable[str]) -> tuple[list[str], list[AlertRow]]:
    """(notes from read_alerts, alerts newest first); unreadable lines are skipped."""
    notes: list[str] = []
    rows: list[AlertRow] = []
    for line in raw:
        if line.startswith("("):  # a note from read_alerts, not a log line
            notes.append(line)
            continue
        try:
            a = json.loads(line)
        except ValueError:
            continue
        if not isinstance(a, dict):
            continue
        tier = a.get("tier")
        rows.append(
            AlertRow(
                received_at=str(a.get("received_at", "")),
                cve=str(a.get("cve", "")),
                team=str(a.get("team", "")),
                tier=tier if isinstance(tier, int) and not isinstance(tier, bool) else 4,
                tier_name=str(a.get("tier_name", "")),
                kev=bool(a.get("kev")),
                epss=_num(a.get("epss")),
                epss_percentile=_num(a.get("epss_percentile")),
                cvss31=_num(a.get("cvss31")),
                project=str(a.get("project", "")),
                organization=str(a.get("organization", "")),
                event_types=[str(t) for t in a.get("event_types") or []],
                reasons=[str(r) for r in a.get("reasons") or []],
                sightings={
                    str(k): v for k, v in (a.get("sightings") or {}).items() if isinstance(v, int)
                },
                description=" ".join(str(a.get("description") or "").split()),
                enrichment_errors=[str(e) for e in a.get("enrichment_errors") or []],
            )
        )
    rows.sort(key=lambda r: r.received_at, reverse=True)
    return notes, rows


def filter_alerts(
    rows: list[AlertRow], team: str = "", max_tier: int = 0, kev_only: bool = False, text: str = ""
) -> list[AlertRow]:
    needle = text.lower()
    return [
        r
        for r in rows
        if (not team or r.team == team)
        and (not max_tier or r.tier <= max_tier)
        and (not kev_only or r.kev)
        and (not needle or needle in f"{r.cve} {r.project} {r.description}".lower())
    ]


def alert_line(r: AlertRow, width: int) -> str:
    kev = "KEV" if r.kev else "   "
    e = f"EPSS {r.epss:.3f}" if r.epss is not None else ""
    return f"{r.received_at[:16]} {r.tier_name:<10} {kev} {r.cve:<18} {r.team:<8} {e}"[:width]


def alert_lines(raw: Iterable[str], width: int) -> list[str]:
    notes, rows = parse_alerts(raw)
    return [n[:width] for n in notes] + [alert_line(r, width) for r in rows] or ["No alerts logged."]


def alert_details(r: AlertRow, opencve_url: str = "") -> list[str]:
    epss = "n/a"
    if r.epss is not None:
        epss = f"{r.epss:.4f}" + (
            f" (percentile {r.epss_percentile:.2f})" if r.epss_percentile is not None else ""
        )
    sightings = ", ".join(f"{k} {v}" for k, v in sorted(r.sightings.items())) or "none"
    out = [
        f"Tier:       {r.tier_name or f'P{r.tier}'}",
        *(f"  - {reason}" for reason in r.reasons),
        f"Team:       {r.team or '-'} (OpenCVE project {r.project or '-'}"
        + (f", organization {r.organization})" if r.organization else ")"),
        f"Received:   {r.received_at}",
        f"Events:     {', '.join(r.event_types) or 'change'}",
        f"CVSS 3.1:   {r.cvss31 if r.cvss31 is not None else 'n/a'}",
        f"EPSS:       {epss}",
        f"KEV:        {'yes, in CISA KEV' if r.kev else 'no'}",
        f"Sightings:  {sightings}",
    ]
    if opencve_url:
        out.append(f"OpenCVE:    {opencve_url.rstrip('/')}/cve/{r.cve}")
    out += ["", r.description or "(no description in the webhook)"]
    if r.enrichment_errors:
        out += ["", "Enrichment errors:", *(f"  {e}" for e in r.enrichment_errors)]
    return out


def host_lines(machines: Machines, pushes: dict[str, float] | None, width: int, now: float) -> list[str]:
    out = []
    for m in sorted(machines.hosts.values(), key=lambda m: (m.group, m.name)):
        seen = pushes.get(project_name(m)) if pushes is not None and host_scans(m) else None
        if pushes is None or not host_scans(m):
            last = "-"
        elif seen is None:
            last = "never pushed"
        else:
            last = f"{(now - seen) / 86400:.1f} days ago"
        out.append(f"{m.group or '-':<10} {m.name:<20} {m.team:<8} {m.kind:<6} {last}"[:width])
    return out or ["No hosts in machines.toml."]


@dataclass
class Sources:
    """Where the tabs get their data; functions so tests can hand in fakes."""

    findings: Callable[[], tuple[list[FindingRow], list[str]]]
    alerts: Callable[[], list[str]]
    hosts: Callable[[int], list[str]]
    updates: Callable[[], list[str]]
    details: Callable[[FindingRow], list[str]]
    # (status line, keys now suppressed in that state); None: read-only
    write: Callable[[list[FindingRow], Decision], tuple[str, set[tuple[str, str, str]]]] | None
    opencve_url: str = ""  # browser-facing, for the link in an alert's details


@dataclass
class App:
    src: Sources
    today: date = field(default_factory=date.today)
    tab: int = 0
    rows: list[FindingRow] = field(default_factory=list)
    team: str = ""
    min_sev: str = ""
    text: str = ""
    pos: int = 0
    top: int = 0
    selected: set[tuple[str, str, str]] = field(default_factory=set)
    status: str = ""
    cache: dict[int, list[str]] = field(default_factory=dict)
    # Alerts tab: read on first open and on `r`; its own filters
    alerts: list[AlertRow] | None = None
    alert_notes: list[str] = field(default_factory=list)
    a_team: str = ""
    a_tier: int = 0
    a_kev: bool = False
    a_text: str = ""

    # ---- data
    def reload(self) -> None:
        self.cache.clear()
        self.alerts = None
        rows, errors = self.src.findings()
        self.rows = rows
        self.selected &= {r.key for r in rows}
        self.status = f"{len(rows)} open findings" + (
            f"; {len(errors)} error(s): {errors[0]}" if errors else ""
        )

    def visible(self) -> list[FindingRow]:
        return filter_rows(self.rows, self.team, self.min_sev, self.text)

    def teams(self) -> list[str]:
        return sorted({r.team for r in self.rows})

    def all_alerts(self) -> list[AlertRow]:
        if self.alerts is None:
            self.alert_notes, self.alerts = parse_alerts(self.src.alerts())
        return self.alerts

    def visible_alerts(self) -> list[AlertRow]:
        return filter_alerts(self.all_alerts(), self.a_team, self.a_tier, self.a_kev, self.a_text)

    def tab_lines(self, width: int, height: int) -> list[str]:
        if self.tab not in self.cache:
            if self.tab == 2:
                self.cache[2] = self.src.hosts(width)
            else:
                self.cache[3] = [line[:width] for line in self.src.updates()]
        return self.cache[self.tab]

    # ---- drawing
    def draw(self, scr: Screen) -> None:
        h, w = scr.getmaxyx()
        scr.erase()
        tabs = "  ".join(
            f"[{i + 1} {t}]" if i == self.tab else f" {i + 1} {t} " for i, t in enumerate(TABS)
        )
        _put(scr, 0, tabs, w, curses.A_BOLD)
        body = h - 3
        if self.tab == 1:
            alerts = self.visible_alerts()
            notes = [n for n in self.alert_notes if n]
            body -= len(notes)
            self._follow(len(alerts), body)
            tier = f"<=P{self.a_tier}" if self.a_tier else "all"
            filt = (
                f"team={self.a_team or 'all'} tier={tier} kev={'only' if self.a_kev else 'any'} "
                f"text={self.a_text or '-'}"
            )
            _put(scr, 1, f"{len(alerts)} of {len(self.all_alerts())} alerts shown   {filt}", w)
            for i, n in enumerate(notes):
                _put(scr, 2 + i, n, w)
            if not alerts:
                _put(
                    scr,
                    2 + len(notes),
                    "No alerts logged." if not self.alerts else "No alert matches the filter.",
                    w,
                )
            for i, a in enumerate(alerts[self.top : self.top + body]):
                attr = curses.A_REVERSE if self.top + i == self.pos else 0
                _put(scr, 2 + len(notes) + i, alert_line(a, w), w, attr)
        elif self.tab == 0:
            rows = self.visible()
            self._follow(len(rows), body)
            filt = f"team={self.team or 'all'} severity>={self.min_sev or 'any'} text={self.text or '-'}"
            _put(scr, 1, f"{len(rows)} shown, {len(self.selected)} selected   {filt}", w)
            for i, r in enumerate(rows[self.top : self.top + body]):
                attr = curses.A_REVERSE if self.top + i == self.pos else 0
                _put(scr, 2 + i, finding_line(r, w, r.key in self.selected), w, attr)
        else:
            lines = self.tab_lines(w, body)
            self.pos = max(0, min(self.pos, len(lines) - 1))
            self.top = max(0, min(self.top, max(0, len(lines) - body)))
            for i, line in enumerate(lines[self.top : self.top + body]):
                _put(scr, 1 + i, line, w)
        _put(scr, h - 1, (self.status or (ALERT_HELP if self.tab == 1 else HELP)), w, curses.A_BOLD)
        scr.refresh()

    def _follow(self, n: int, body: int) -> None:
        """Keep the cursor on a row and the view on the cursor."""
        self.pos = max(0, min(self.pos, n - 1))
        if self.pos < self.top:
            self.top = self.pos
        elif self.pos >= self.top + max(1, body):
            self.top = self.pos - max(1, body) + 1

    # ---- input
    def handle(self, scr: Screen, k: int) -> bool:
        """One key; False to quit."""
        h, _ = scr.getmaxyx()
        page = max(1, h - 4)
        self.status = ""
        if k in (ord("q"), ord("Q")):
            return False
        scroll = self.tab >= 2  # Hosts and Updates scroll; Findings and Alerts move a cursor
        if ord("1") <= k <= ord("4"):
            self.tab, self.pos, self.top = k - ord("1"), 0, 0
        elif k in (ord("j"), curses.KEY_DOWN):
            self.pos += 1
            if scroll:
                self.top += 1
        elif k in (ord("k"), curses.KEY_UP):
            self.pos = max(0, self.pos - 1)
            if scroll:
                self.top = max(0, self.top - 1)
        elif k in (curses.KEY_NPAGE, ord(" ")) and scroll:
            self.top += page
        elif k == curses.KEY_NPAGE:
            self.pos += page
        elif k == curses.KEY_PPAGE:
            self.pos, self.top = max(0, self.pos - page), max(0, self.top - page)
        elif k == ord("r"):
            self.reload()
        elif self.tab == 0:
            self._findings_key(scr, k)
        elif self.tab == 1:
            self._alerts_key(scr, k)
        return True

    def current_alert(self) -> AlertRow | None:
        rows = self.visible_alerts()
        return rows[self.pos] if 0 <= self.pos < len(rows) else None

    def _alerts_key(self, scr: Screen, k: int) -> None:
        if k == ord("/"):
            got = prompt(scr, "Filter (CVE, project, description; empty = none): ", self.a_text)
            if got is not None:
                self.a_text, self.pos, self.top = got.strip(), 0, 0
        elif k == ord("t"):
            teams = ["", *sorted({a.team for a in self.all_alerts()})]
            self.a_team = (
                teams[(teams.index(self.a_team) + 1) % len(teams)] if self.a_team in teams else ""
            )
            self.pos = self.top = 0
        elif k == ord("p"):
            self.a_tier = TIER_LIMITS[(TIER_LIMITS.index(self.a_tier) + 1) % len(TIER_LIMITS)]
            self.pos = self.top = 0
        elif k == ord("e"):
            self.a_kev = not self.a_kev
            self.pos = self.top = 0
        elif k in ENTER_KEYS:
            self._view_alert(scr)

    def _view_alert(self, scr: Screen) -> None:
        """Details of the current alert; J/K step to the next/previous one in the list."""
        while (a := self.current_alert()) is not None:
            k = pager(scr, f"{a.tier_name} {a.cve} ({a.team})", alert_details(a, self.src.opencve_url))
            n = len(self.visible_alerts())
            if k == ord("J") and self.pos < n - 1:
                self.pos += 1
            elif k == ord("K") and self.pos > 0:
                self.pos -= 1
            elif k in (ord("J"), ord("K")):
                continue  # already at the end of the list
            else:
                return

    def current(self) -> FindingRow | None:
        rows = self.visible()
        return rows[self.pos] if 0 <= self.pos < len(rows) else None

    def _findings_key(self, scr: Screen, k: int) -> None:
        if k == ord("/"):
            got = prompt(scr, "Filter (CVE, component, project; empty = none): ", self.text)
            if got is not None:
                self.text, self.pos, self.top = got.strip(), 0, 0
        elif k == ord("t"):
            teams = ["", *self.teams()]
            self.team = teams[(teams.index(self.team) + 1) % len(teams)] if self.team in teams else ""
            self.pos = self.top = 0
        elif k == ord("s"):
            levels = ["", "CRITICAL", "HIGH", "MEDIUM", "LOW"]
            self.min_sev = levels[(levels.index(self.min_sev) + 1) % len(levels)]
            self.pos = self.top = 0
        elif k == ord(" "):
            r = self.current()
            if r:
                self.selected ^= {r.key}
                self.pos += 1
        elif k in ENTER_KEYS:
            self._view(scr)
        elif k == ord("m"):
            self._mark(scr)

    def _view(self, scr: Screen) -> None:
        """Details of the current finding; J/K step to the next/previous one in the list."""
        while (r := self.current()) is not None:
            k = pager(scr, f"{r.vuln_id} in {r.component} {r.version}", self.src.details(r))
            n = len(self.visible())
            if k == ord("J") and self.pos < n - 1:
                self.pos += 1
            elif k == ord("K") and self.pos > 0:
                self.pos -= 1
            elif k in (ord("J"), ord("K")):
                continue  # already at the end of the list
            else:
                return

    def _mark(self, scr: Screen) -> None:
        if self.src.write is None:
            self.status = "read-only: set DT_ADMIN_PASSWORD in .env to mark findings"
            return
        targets = [r for r in self.rows if r.key in self.selected] or [r for r in [self.current()] if r]
        if not targets:
            return
        d = ask_decision(scr, len(targets), self.today)
        if d is None:
            self.status = "cancelled"
            return
        bad = d.problems(self.today)
        if bad:
            self.status = "not written: " + "; ".join(bad)
            return
        lines = [f"Write to Dependency-Track: {d.label()}", f"Reason: {d.reason}", ""]
        lines += [f"  {r.team}/{r.where}: {r.component} {r.version} {r.vuln_id}" for r in targets]
        lines += ["", "y = write and suppress, any other key = cancel"]
        if pager(scr, "Confirm", lines, confirm=True) != ord("y"):
            self.status = "cancelled, nothing written"
            return
        self.status, done = self.src.write(targets, d)
        self.rows = [r for r in self.rows if r.key not in done]
        self.selected -= done


def _put(scr: Screen, y: int, s: str, w: int, attr: int = 0) -> None:
    try:
        scr.addnstr(y, 0, s, max(0, w - 1), attr)
    except curses.error:  # the bottom-right cell
        pass


def prompt(scr: Screen, label: str, initial: str = "") -> str | None:
    """A one-line editor on the last row: Enter accepts, Esc cancels."""
    buf = initial
    while True:
        h, w = scr.getmaxyx()
        _put(scr, h - 1, " " * (w - 1), w)
        _put(scr, h - 1, label + buf, w, curses.A_BOLD)
        scr.refresh()
        k = scr.getch()
        if k == ESC:
            return None
        if k in ENTER_KEYS:
            return buf
        if k in (curses.KEY_BACKSPACE, 127, 8):
            buf = buf[:-1]
        elif 32 <= k < 127:
            buf += chr(k)


def choose(scr: Screen, title: str, options: list[str]) -> int | None:
    """Numbered menu; the index chosen, or None on Esc."""
    while True:
        scr.erase()
        h, w = scr.getmaxyx()
        _put(scr, 0, title, w, curses.A_BOLD)
        for i, o in enumerate(options[: h - 3]):
            _put(scr, 2 + i, f"{i + 1}  {o}", w)
        _put(scr, h - 1, "number = choose, Esc = cancel", w, curses.A_BOLD)
        scr.refresh()
        k = scr.getch()
        if k == ESC:
            return None
        if ord("1") <= k <= ord("9") and k - ord("1") < len(options):
            return k - ord("1")


def ask_decision(scr: Screen, n: int, today: date) -> Decision | None:
    what = choose(
        scr,
        f"Mark {n} finding(s) in Dependency-Track as",
        [
            "Not Affected (choose a justification)",
            "False Positive (the match is wrong)",
            "Accepted risk: Will Not Fix (review date required)",
            "Accepted risk: Can Not Fix (review date required)",
        ],
    )
    if what is None:
        return None
    d = Decision(state=("NOT_AFFECTED", "FALSE_POSITIVE", "EXPLOITABLE", "EXPLOITABLE")[what], reason="")
    if what == 0:
        j = choose(scr, "Justification", list(JUSTIFICATIONS))
        if j is None:
            return None
        d.justification = JUSTIFICATIONS[j]
    if what >= 2:
        d.response = ACCEPT_RESPONSES[what - 2]
    reason = prompt(scr, "Reason (goes into the analysis comment): ")
    if reason is None:
        return None
    d.reason = reason
    need = "required" if d.state == "EXPLOITABLE" else "optional"
    due = prompt(scr, f"Review by YYYY-MM-DD ({need}, empty = none): ")
    if due is None:
        return None
    if due.strip():
        try:
            d.review_by = date.fromisoformat(due.strip())
        except ValueError:
            d.invalid = f"{due.strip()!r} is not a date (YYYY-MM-DD)"
    return d


def pager(scr: Screen, title: str, lines: list[str], confirm: bool = False) -> int:
    """Show lines (wrapped) until a key: with confirm, any key returns it; otherwise
    j/k/space scroll, q, Esc or Enter close, and J/K are returned so the caller can
    move to the next/previous item."""
    top = 0
    while True:
        scr.erase()
        h, w = scr.getmaxyx()
        wrapped = [chunk for line in lines for chunk in (_wrap(line, w - 1) or [""])]
        _put(scr, 0, title, w, curses.A_BOLD)
        for i, line in enumerate(wrapped[top : top + h - 3]):
            _put(scr, 2 + i, line, w)
        if not confirm:
            _put(scr, h - 1, "j/k/space scroll, J/K next/prev, q/Enter close", w, curses.A_BOLD)
        scr.refresh()
        k = scr.getch()
        if confirm:
            return k
        if k in (ord("q"), ord("J"), ord("K"), ESC, *ENTER_KEYS):
            return k
        if k in (ord("j"), curses.KEY_DOWN):
            top = min(top + 1, max(0, len(wrapped) - 1))
        elif k in (ord("k"), curses.KEY_UP):
            top = max(0, top - 1)
        elif k == ord(" "):
            top = min(top + h - 4, max(0, len(wrapped) - 1))


def _wrap(s: str, w: int) -> list[str]:
    w = max(10, w)
    return [s[i : i + w] for i in range(0, len(s), w)]


def finding_details(r: FindingRow, dt: DependencyTrack | None) -> list[str]:
    out = [
        f"Team:       {r.team}",
        f"Project:    {r.where}",
        f"Component:  {r.component} {r.version}",
        f"purl:       {r.purl or '-'}",
        f"CVE:        {r.vuln_id} ({r.source or '?'}), severity {r.severity.lower()}"
        + (", in CISA KEV" if r.kev else ""),
        "",
        r.description or "(no description in Dependency-Track)",
        "",
    ]
    if dt is not None and r.component_uuid:
        try:
            paths = paths_of(dt.component_properties(r.component_uuid))
        except Exception as e:
            paths = [f"(could not read: {e})"]
        out += ["On disk (syft):", *(f"  {p}" for p in paths or ["  (no paths recorded)"])]
    return out


def run(app: App) -> None:  # pragma: no cover - needs a terminal
    def main(scr: Any) -> None:
        curses.curs_set(0)
        scr.keypad(True)
        app.status = "loading findings..."
        app.draw(scr)
        app.reload()
        while True:
            app.draw(scr)
            if not app.handle(scr, scr.getch()):
                return

    curses.wrapper(main)


def make_writer(
    admin: Callable[[], Http], ledger: Path, today: Callable[[], date] = date.today
) -> Callable[[list[FindingRow], Decision], tuple[str, set[tuple[str, str, str]]]]:
    """Write a decision like `vulnflow ignore --apply` (same ledger). `admin` logs in on
    first use. Findings somebody else already triaged are left alone and stay listed."""
    session: list[Http] = []

    def write(rows: list[FindingRow], d: Decision) -> tuple[str, set[tuple[str, str, str]]]:
        try:
            if not session:
                session.append(admin())
        except Exception as e:
            return f"not written: Dependency-Track admin login failed: {e}", set()
        by_key = {r.key: r for r in rows}
        items = [ignore_item(r, d, today()) for r in rows]
        written, skipped, kept, errors = apply_ignores(
            session[0], items, d.state, d.justification, ledger=ledger, response=d.response
        )
        done = {(i.project_uuid, i.component_uuid, i.vuln_uuid) for i in [*written, *skipped]}
        msg = f"{len(written)} written, {len(skipped)} already {d.state}"
        if kept:
            msg += f", {len(kept)} left alone (already triaged as {kept[0].state})"
        if errors:
            msg += f"; {len(errors)} error(s): {errors[0]}"
        return msg, done & set(by_key)

    return write


def read_alerts(path: Path | None) -> list[str]:
    if path is None:
        return ["(no alert log: run through ./poc.sh tui)"]
    try:
        return path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError as e:
        return [f"(cannot read {path}: {e})"]
