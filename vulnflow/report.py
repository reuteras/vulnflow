"""Daily and weekly email digests (`vulnflow report daily|weekly`).

`./poc.sh report <kind>` runs this and mails the result with the host's own `sendmail`;
`./poc.sh schedule install` sets up the systemd timers in deploy/timers/ that call it.
Nothing here sends mail or talks to Docker: poc.sh passes the receiver's alerts.jsonl in.

Output: Markdown (default), or with --mime a complete multipart/alternative message (the
Markdown as text/plain, an HTML rendering of the same sections as text/html) for
`sendmail -t`. Both renderers work from the same blocks (paragraph, list, table); no
Markdown is parsed. Inline `code` and **bold** are the only marks, and the HTML side
escapes everything before turning those two into tags.

Sections:

    updates    check-updates lines that need action (daily) or all of them (weekly)
    alerts     P1/P2 alerts the receiver logged since the last report of this kind
               (OpenCVE watch path)
    findings   Dependency-Track findings that are new or gone since the last report of
               this kind (match path). The daily lists new critical/high/KEV ones; the
               weekly lists those, counts the rest and the resolved ones, and adds the
               open totals per team
    machines   own hosts that stopped pushing SBOMs

A finding is keyed on team, project name, component name and vulnerability id, not on
the versions: a new image tag or package version that still has the CVE is not "new".
The state (last alert time, the previous findings) is kept per kind in
data/report-state.json, so the weekly compares with last week's run, not yesterday's.
The first run of a kind only records a baseline.

Exit code: 0, or 1 when a section could not be built (the error is in the report).
"""

from __future__ import annotations

import html
import json
import os
import re
import time
from collections import Counter
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from email.message import EmailMessage
from email.utils import formatdate, make_msgid
from pathlib import Path
from typing import Any

from .clients import DependencyTrack
from .config import Inventory, Machines
from .machines import host_scans, project_name
from .patches import open_findings
from .receiver import NOTIFY_LABELS
from .upstreams import Status

KINDS = ("daily", "weekly")
IMPORTANT = ("CRITICAL", "HIGH")
SEVERITY_ORDER = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "UNASSIGNED")
LIST_MAX = 40  # listed rows per table/list; the rest is counted


@dataclass
class Para:
    text: str


@dataclass
class Items:
    items: list[str]


@dataclass
class Table:
    header: list[str]
    rows: list[list[str]]


Block = Para | Items | Table


@dataclass
class Section:
    title: str
    blocks: list[Block] = field(default_factory=list)
    notable: bool = False  # something to act on: a quiet daily is not sent without one
    error: bool = False

    def text(self) -> str:
        """All of the section as plain text, for tests and logs."""
        out: list[str] = []
        for b in self.blocks:
            if isinstance(b, Para):
                out.append(b.text)
            elif isinstance(b, Items):
                out += b.items
            else:
                out += [" | ".join(r) for r in b.rows]
        return "\n".join(out)


def code(s: str) -> str:
    return f"`{s.replace('`', '')}`" if s else ""


def _cut_rows(rows: list[list[str]], limit: int = LIST_MAX) -> tuple[list[list[str]], int]:
    return rows[:limit], max(0, len(rows) - limit)


def _table(section: Section, header: list[str], rows: list[list[str]]) -> None:
    shown, more = _cut_rows(rows)
    section.blocks.append(Table(header, shown))
    if more:
        section.blocks.append(Para(f"... and {more} more."))


@dataclass
class OpenFinding:
    team: str
    project: str
    project_version: str
    component: str
    version: str
    vuln_id: str
    severity: str

    @property
    def key(self) -> str:
        return "|".join((self.team, self.project, self.component, self.vuln_id))

    def to_json(self) -> dict[str, str]:
        return {
            "pv": self.project_version,
            "v": self.version,
            "sev": self.severity,
        }

    def row(self, kev: bool) -> list[str]:
        where = f"{self.project}@{self.project_version}" if self.project_version else self.project
        return [
            self.severity.lower(),
            code(self.vuln_id),
            "**KEV**" if kev else "",
            f"{code(self.component)} {self.version}".strip(),
            code(where),
        ]


# ---- updates ---------------------------------------------------------------------------


def _status_blocks(st: Status) -> list[Block]:
    head, *rest = st.lines()
    title, _, tail = head.partition(": ")
    blocks: list[Block] = [Para(f"**{title}**: {tail}")]
    if rest:
        blocks.append(Items([" ".join(r.split()) for r in rest]))
    return blocks


def updates_section(statuses: list[Status], *, everything: bool) -> Section:
    s = Section("Upstream updates")
    for st in statuses:
        if st.actionable or st.error:
            s.notable = True
            s.blocks += _status_blocks(st)
        elif everything:
            s.blocks += _status_blocks(st)
    if not s.blocks:
        s.blocks.append(Para("Nothing to do."))
    return s


# ---- alerts ----------------------------------------------------------------------------


def _alert_what(a: dict[str, Any]) -> str:
    """The chat line's description: title (or the description's first sentence for log
    lines from before titles were recorded) and the products it matched."""
    title = " ".join(str(a.get("title") or "").split())
    if not title:
        first = " ".join(str(a.get("description") or "").split()).split(". ")[0]
        title = first if len(first) <= 100 else first[:97].rstrip() + "..."
    products = [str(p) for p in a.get("products") or []]
    return title + (f" ({', '.join(products)})" if products else "")


def kev_section(lines: Iterable[str], since: str) -> tuple[Section, str]:
    """New CISA KEV entries kev-watch posted after `since` (its kev-new.jsonl), the same
    entries and matches as the chat messages. Notable when one hits something of ours."""
    s = Section("New in CISA KEV")
    newest = since
    rows = []
    matched = False
    for raw in lines:
        raw = raw.strip()
        if not raw:
            continue
        try:
            e = json.loads(raw)
        except ValueError:
            continue
        at = str(e.get("seen_at", ""))
        newest = max(newest, at)
        if since and at <= since:
            continue
        findings = e.get("findings") or {}
        follows = [str(t) for t in e.get("follows") or []]
        where = [f"findings in {t}" for t in sorted(findings)] + [f"{t} follows" for t in follows]
        matched = matched or bool(where)
        name = f"{e.get('vendor', '')} {e.get('product', '')}: {e.get('name', '')}"
        rows.append(
            [
                str(e.get("date_added", ""))[:10],
                code(str(e.get("cve", ""))),
                name + (" **(ransomware use)**" if e.get("ransomware") else ""),
                ", ".join(where) or "nothing of ours",
            ]
        )
    rows.sort(key=lambda r: r[0], reverse=True)  # newest first,
    rows.sort(key=lambda r: r[3] == "nothing of ours")  # those that hit something on top
    s.notable = matched
    if rows:
        _table(s, ["Added", "CVE", "Vulnerability", "Hits"], rows)
    else:
        s.blocks.append(Para("None."))
    return s, newest


def alerts_section(lines: Iterable[str], since: str, max_tier: int = 2) -> tuple[Section, str]:
    """P1..P<max_tier> alerts received after `since` (ISO 8601; empty = all), one row per
    team and CVE with the highest tier. Returns the section and the newest received_at."""
    s = Section(f"New P1-P{max_tier} alerts from OpenCVE")
    newest = since
    best: dict[tuple[str, str], dict[str, Any]] = {}
    for raw in lines:
        raw = raw.strip()
        if not raw:
            continue
        try:
            a = json.loads(raw)
        except ValueError:
            continue
        at = str(a.get("received_at", ""))
        newest = max(newest, at)
        if (since and at <= since) or int(a.get("tier", 9)) > max_tier:
            continue
        if "notify" in a and not a["notify"]:
            continue  # logged only (e.g. a title edit on an old KEV entry); older lines have no key
        k = (str(a.get("team", "")), str(a.get("cve", "")))
        if k not in best or int(a["tier"]) < int(best[k]["tier"]):
            best[k] = a
    rows = []
    for (team, cve), a in sorted(best.items(), key=lambda kv: (kv[1]["tier"], kv[0])):
        epss, cvss = a.get("epss"), a.get("cvss31")
        rows.append(
            [
                f"**{a.get('tier_name', '')}**",
                code(cve),
                _alert_what(a),
                NOTIFY_LABELS.get(str(a.get("notify", "")), str(a.get("notify") or "")),
                team,
                str(cvss) if cvss is not None else "n/a",
                "**KEV**" if a.get("kev") else "",
                f"{epss:.3f}" if isinstance(epss, int | float) else "",
            ]
        )
    s.notable = bool(rows)
    if rows:
        _table(s, ["Tier", "CVE", "What", "Why", "Team", "CVSS", "KEV", "EPSS"], rows)
    else:
        s.blocks.append(Para("None."))
    return s, newest


# ---- findings --------------------------------------------------------------------------


def collect_findings(inv: Inventory, dt: DependencyTrack, errors: list[str]) -> dict[str, OpenFinding]:
    out: dict[str, OpenFinding] = {}
    for team, p, f in open_findings(inv, dt, None, errors):
        comp, vuln = f.get("component") or {}, f.get("vulnerability") or {}
        of = OpenFinding(
            team=team,
            project=p.name,
            project_version=p.version,
            component=str(comp.get("name", "")),
            version=str(comp.get("version", "")),
            vuln_id=str(vuln.get("vulnId", "")),
            severity=str(vuln.get("severity") or "UNASSIGNED").upper(),
        )
        out.setdefault(of.key, of)
    return out


def _sev_rank(sev: str) -> int:
    return SEVERITY_ORDER.index(sev) if sev in SEVERITY_ORDER else len(SEVERITY_ORDER)


def findings_section(
    previous: dict[str, Any] | None,
    current: dict[str, OpenFinding],
    kev: set[str],
    *,
    weekly: bool,
) -> Section:
    s = Section("Dependency-Track findings")
    if previous is None:
        s.blocks.append(
            Para(
                f"First report: baseline of {len(current)} open findings recorded; changes are "
                "listed from the next one."
            )
        )
        return s
    new = [current[k] for k in current.keys() - previous.keys()]
    gone = previous.keys() - current.keys()
    important = [f for f in new if f.severity in IMPORTANT or f.vuln_id in kev]
    important.sort(key=lambda f: (f.vuln_id not in kev, _sev_rank(f.severity), f.team, f.vuln_id))
    s.notable = bool(important)
    s.blocks.append(
        Para(
            f"**{len(new)}** new, **{len(gone)}** resolved or suppressed since the last "
            f"{'weekly' if weekly else 'daily'} report; **{len(important)}** new "
            "critical/high/KEV."
        )
    )
    if important:
        _table(
            s,
            ["Severity", "CVE", "KEV", "Component", "Project"],
            [f.row(f.vuln_id in kev) for f in important],
        )
    if weekly:
        listed = {f.key for f in important}
        rest = Counter(f.team for f in new if f.key not in listed)
        resolved = Counter(k.split("|", 1)[0] for k in gone)
        per: dict[str, Counter[str]] = {}
        for f in current.values():
            per.setdefault(f.team, Counter())[f.severity] += 1
        teams = sorted(set(per) | set(rest) | set(resolved))
        sevs = [sev for sev in SEVERITY_ORDER if any(c[sev] for c in per.values())]
        s.blocks.append(Para("Per team:"))
        s.blocks.append(
            Table(
                ["Team", "Open", *(x.lower() for x in sevs), "Other new", "Resolved"],
                [
                    [
                        t,
                        str(sum(per.get(t, Counter()).values())),
                        *(str(per.get(t, Counter())[x]) for x in sevs),
                        str(rest[t]),
                        str(resolved[t]),
                    ]
                    for t in teams
                ],
            )
        )
    return s


# ---- machines --------------------------------------------------------------------------


def machines_section(
    machines: Machines, pushes: dict[str, float], stale_days: float, now: float | None = None
) -> Section:
    now = time.time() if now is None else now
    s = Section(f"Hosts that stopped pushing (more than {stale_days:g} days)")
    rows = []
    for m in sorted(machines.hosts.values(), key=lambda m: (m.group, m.name)):
        if not host_scans(m):
            continue
        seen = pushes.get(project_name(m))
        if seen is None:
            rows.append([code(m.name), m.team, "never"])
        elif (now - seen) / 86400 > stale_days:
            rows.append([code(m.name), m.team, f"{(now - seen) / 86400:.1f} days ago"])
    s.notable = bool(rows)
    if rows:
        _table(s, ["Host", "Team", "Last push"], rows)
    else:
        s.blocks.append(Para("None."))
    return s


# ---- state -----------------------------------------------------------------------------


def load_state(path: Path) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def save_state(path: Path, state: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(state, f, separators=(",", ":"))
    tmp.replace(path)


def error_section(title: str, message: str) -> Section:
    return Section(title, [Para(message)], notable=True, error=True)


# ---- output ----------------------------------------------------------------------------


def _title(kind: str, now: datetime) -> str:
    return f"vulnflow {kind} report, {now:%Y-%m-%d %H:%M} UTC"


def _md_cell(s: str) -> str:
    return s.replace("|", "\\|") or " "


def render_markdown(kind: str, sections: list[Section], now: datetime | None = None) -> str:
    now = now or datetime.now(UTC)
    out = [f"# {_title(kind, now)}", ""]
    for s in sections:
        out += [f"## {s.title}{' (ERROR)' if s.error else ''}", ""]
        for b in s.blocks:
            if isinstance(b, Para):
                out += [b.text, ""]
            elif isinstance(b, Items):
                out += [f"- {i}" for i in b.items] + [""]
            else:
                out.append("| " + " | ".join(b.header) + " |")
                out.append("|" + "|".join(" --- " for _ in b.header) + "|")
                out += ["| " + " | ".join(_md_cell(c) for c in r) + " |" for r in b.rows]
                out.append("")
    return "\n".join(out).rstrip() + "\n"


_CODE = re.compile(r"`([^`]+)`")
_BOLD = re.compile(r"\*\*(.+?)\*\*")
_TD = 'style="border:1px solid #ccc;padding:3px 8px;text-align:left;vertical-align:top"'
_CODE_STYLE = 'style="font-family:Menlo,Consolas,monospace;font-size:90%"'


def _inline(s: str) -> str:
    """Escape, then turn the two marks this module writes into tags."""
    t = html.escape(s, quote=False)
    t = _CODE.sub(lambda m: f"<code {_CODE_STYLE}>{m.group(1)}</code>", t)
    return _BOLD.sub(r"<strong>\1</strong>", t)


def render_html(kind: str, sections: list[Section], now: datetime | None = None) -> str:
    """The same report as HTML for mail clients: inline styles only (many clients drop
    <style>), no images, no links out."""
    now = now or datetime.now(UTC)
    out = [
        '<!doctype html><html><head><meta charset="utf-8">',
        f"<title>{html.escape(_title(kind, now))}</title></head>",
        '<body style="font-family:-apple-system,Segoe UI,Helvetica,Arial,sans-serif;'
        'font-size:14px;line-height:1.4;color:#222">',
        f'<h1 style="font-size:20px">{html.escape(_title(kind, now))}</h1>',
    ]
    for s in sections:
        color = "#b00020" if s.error else "#222"
        err = " (ERROR)" if s.error else ""
        out.append(
            f'<h2 style="font-size:16px;margin-top:20px;color:{color}">{html.escape(s.title)}{err}</h2>'
        )
        for b in s.blocks:
            if isinstance(b, Para):
                out.append(f"<p>{_inline(b.text)}</p>")
            elif isinstance(b, Items):
                out.append("<ul>" + "".join(f"<li>{_inline(i)}</li>" for i in b.items) + "</ul>")
            else:
                out.append('<table style="border-collapse:collapse">')
                out.append(
                    "<tr>" + "".join(f"<th {_TD}>{html.escape(h)}</th>" for h in b.header) + "</tr>"
                )
                for r in b.rows:
                    out.append("<tr>" + "".join(f"<td {_TD}>{_inline(c)}</td>" for c in r) + "</tr>")
                out.append("</table>")
    out.append("</body></html>")
    return "\n".join(out) + "\n"


def subject(kind: str, host: str, sections: list[Section]) -> str:
    s = f"vulnflow {kind} report ({host})"
    if any(x.error for x in sections):
        return s + ": errors"
    if any(x.notable for x in sections):
        return s + ": action needed"
    return s


def mime_message(
    kind: str, sections: list[Section], to: str, host: str, now: datetime | None = None
) -> EmailMessage:
    now = now or datetime.now(UTC)
    msg = EmailMessage()
    msg["To"] = to
    msg["Subject"] = subject(kind, host, sections)
    msg["Date"] = formatdate(now.timestamp(), localtime=True)
    msg["Message-ID"] = make_msgid("vulnflow")
    msg.set_content(render_markdown(kind, sections, now))
    msg.add_alternative(render_html(kind, sections, now), subtype="html")
    return msg
