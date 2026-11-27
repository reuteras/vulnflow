"""Per-team OSINT newsletter: `vulnflow newsletter weekly|daily|alert <id>` (issue #95).

Each team gets the security news that concerns what it runs, from

- vulnflow's own data (no new requests): its notified OpenCVE alerts, new KEV entries
  that hit it (kev-watch's log), accepted risks whose review date is near (the ignore
  ledger);
- OSINT feeds from `[news.feeds.<name>]` in machines.toml: RSS 2.0, RSS 1.0, Atom or JSON
  Feed, each **downloaded whole and filtered here**. Nothing is ever searched for per
  keyword or product, which would show each team's stack to the feed's host.

Matching, per team:

- a CVE or GHSA id in the item that is open in the team's Dependency-Track findings
  ("open on 3 of your projects") or was alerted to the team;
- a keyword: the team's OpenCVE subscriptions (vendors, products), the names of the
  vulnerable components in its Dependency-Track projects, and `[news.teams.<team>]
  keywords`, matched as whole words;
- a feed with `teams = [...]` goes to those teams whole (e.g. a vendor's PSIRT feed).

Items sharing a CVE are merged into one entry with all their links. Order: the team's
own systems first, then exploited (CISA or VulnCheck KEV) or a public exploit (an `exploit` feed),
then the rest, newest first. No summaries are generated: titles, links, sources and why
each item matched.

Modes:

- weekly: everything new (not sent in a weekly before) that matches the team, plus the
  vulnflow sections for the last 7 days;
- daily: only what is urgent (the team's own systems, exploited, or a public exploit),
  sent only when there is something;
- alert <id>: everything known about one CVE, GHSA or keyword, to the teams it concerns
  (or --team), now. Not scheduled; no seen-state.
"""

from __future__ import annotations

import html
import json
import re
import xml.etree.ElementTree as ET
from collections.abc import Callable, Collection, Iterable
from dataclasses import dataclass, field
from datetime import UTC, date, datetime, timedelta
from email.utils import parsedate_to_datetime
from pathlib import Path
from typing import Any

from .config import Inventory, Machines, NewsFeed
from .intel import kev_label
from .net import Http, Transport
from .receiver import NOTIFY_LABELS
from .report import Para, Section, Table, code

CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.IGNORECASE)
GHSA_RE = re.compile(r"\bGHSA(?:-[23456789cfghjmpqrvwx]{4}){3}\b", re.IGNORECASE)
TAG_RE = re.compile(r"<[^>]+>")
STATE_FILE = "news-seen.json"
SEEN_DAYS = 90
MAX_FEED_BYTES = 10 * 1024 * 1024
# words that would match almost every item: never keywords on their own
STOP = {
    "server", "servers", "linux", "office", "edge", "apps", "app", "enterprise", "platform",
    "management", "manager", "data", "center", "security", "gateway", "firmware", "web",
    "client", "core", "common", "utils", "util", "base", "tools", "python", "node", "java",
    "system", "systemd", "kernel", "library", "network", "cloud", "mobile", "desktop",
}  # fmt: skip
ATOM = "{http://www.w3.org/2005/Atom}"
RSS1 = "{http://purl.org/rss/1.0/}"
DC = "{http://purl.org/dc/elements/1.1/}"


# ---------------------------------------------------------------------------- items
@dataclass
class Item:
    key: str  # stable: the feed's id/guid, else the link
    title: str
    link: str
    summary: str
    published: str  # ISO 8601, "" if unknown
    source: str  # feed name
    kind: str  # the feed's kind
    ids: set[str] = field(default_factory=set)  # CVE/GHSA ids, upper-case

    @property
    def text(self) -> str:
        return f"{self.title} {self.summary}"


def _clean(s: str | None, limit: int = 600) -> str:
    t = html.unescape(TAG_RE.sub(" ", s or ""))
    t = " ".join(t.split())
    return t if len(t) <= limit else t[: limit - 3].rstrip() + "..."


def _iso(s: str | None) -> str:
    if not s:
        return ""
    s = s.strip()
    try:
        d = parsedate_to_datetime(s)  # RSS: RFC 822
    except (TypeError, ValueError, IndexError):
        try:
            d = datetime.fromisoformat(s.replace("Z", "+00:00"))  # Atom/JSON: ISO 8601
        except ValueError:
            return ""
    if d.tzinfo is None:
        d = d.replace(tzinfo=UTC)
    return d.astimezone(UTC).isoformat(timespec="seconds")


def ids_in(text: str) -> set[str]:
    return {m.upper() for m in CVE_RE.findall(text)} | {m.upper() for m in GHSA_RE.findall(text)}


def _item(feed: NewsFeed, key: str, title: str, link: str, summary: str, published: str) -> Item:
    title, summary = _clean(title, 300), _clean(summary)
    return Item(
        key=f"{feed.name}:{key or link or title}",
        title=title or "(no title)",
        link=link.strip(),
        summary=summary,
        published=_iso(published),
        source=feed.name,
        kind=feed.kind,
        ids=ids_in(f"{title} {summary} {link}"),
    )


def parse_feed(feed: NewsFeed, body: bytes) -> list[Item]:
    """RSS 2.0, RSS 1.0 (RDF), Atom or JSON Feed, by what the document is."""
    text = body.lstrip()
    if text.startswith(b"{"):
        data = json.loads(text)
        return [
            _item(
                feed,
                str(i.get("id") or ""),
                str(i.get("title") or ""),
                str(i.get("url") or i.get("external_url") or ""),
                str(i.get("summary") or i.get("content_text") or i.get("content_html") or ""),
                str(i.get("date_published") or i.get("date_modified") or ""),
            )
            for i in data.get("items") or []
            if isinstance(i, dict)
        ]
    root = ET.fromstring(text)  # noqa: S314 - expat limits entity expansion
    out = []
    if root.tag == "rss":
        for i in root.iter("item"):
            out.append(
                _item(
                    feed,
                    i.findtext("guid") or "",
                    i.findtext("title") or "",
                    i.findtext("link") or "",
                    i.findtext("description") or "",
                    i.findtext("pubDate") or i.findtext(f"{DC}date") or "",
                )
            )
    elif root.tag == f"{ATOM}feed":
        for e in root.iter(f"{ATOM}entry"):
            links = e.findall(f"{ATOM}link")
            href = next(
                (x.get("href", "") for x in links if x.get("rel", "alternate") == "alternate"), ""
            )
            out.append(
                _item(
                    feed,
                    e.findtext(f"{ATOM}id") or "",
                    e.findtext(f"{ATOM}title") or "",
                    href or (links[0].get("href", "") if links else ""),
                    e.findtext(f"{ATOM}summary") or e.findtext(f"{ATOM}content") or "",
                    e.findtext(f"{ATOM}published") or e.findtext(f"{ATOM}updated") or "",
                )
            )
    else:  # RSS 1.0 (rdf:RDF)
        for i in root.iter(f"{RSS1}item"):
            out.append(
                _item(
                    feed,
                    i.get("{http://www.w3.org/1999/02/22-rdf-syntax-ns#}about", ""),
                    i.findtext(f"{RSS1}title") or "",
                    i.findtext(f"{RSS1}link") or "",
                    i.findtext(f"{RSS1}description") or "",
                    i.findtext(f"{DC}date") or "",
                )
            )
    return out


def fetch_feeds(
    feeds: Iterable[NewsFeed], transport: Transport | None = None
) -> tuple[list[Item], list[str]]:
    """Every enabled feed, downloaded whole. Returns (items, errors)."""
    items: list[Item] = []
    errors: list[str] = []
    for f in feeds:
        if not f.enabled:
            continue
        try:
            body = Http(f.url, transport=transport, timeout=60).get("").body
            if len(body) > MAX_FEED_BYTES:
                raise ValueError(f"{len(body)} bytes, more than {MAX_FEED_BYTES}")
            items += parse_feed(f, body)
        except Exception as e:
            errors.append(f"feed {f.name}: {e}")
    return items, errors


# -------------------------------------------------------------------------- teams
@dataclass
class TeamProfile:
    team: str
    keywords: dict[str, str] = field(default_factory=dict)  # keyword -> why
    own_keywords: set[str] = field(default_factory=set)  # from the team's components
    open_ids: dict[str, set[str]] = field(default_factory=dict)  # id -> project labels
    alert_ids: set[str] = field(default_factory=set)

    def __post_init__(self) -> None:
        self._re: re.Pattern[str] | None = None

    def keyword_hits(self, text: str) -> list[str]:
        if not self.keywords:
            return []
        if self._re is None:
            words = sorted(self.keywords, key=len, reverse=True)
            self._re = re.compile(r"\b(" + "|".join(re.escape(w) for w in words) + r")\b", re.IGNORECASE)
        return sorted({m.lower() for m in self._re.findall(text)})


def _usable(word: str) -> bool:
    w = word.lower().strip()
    return len(w) >= 4 and w not in STOP and not w.replace(".", "").replace("-", "").isdigit()


def build_profiles(
    inv: Inventory,
    machines: Machines,
    findings: Iterable[tuple[str, str, str, str]],
    alerts: Iterable[dict[str, Any]],
) -> dict[str, TeamProfile]:
    """findings: (team, project label, component name, vuln id); alerts: alerts.jsonl rows."""
    out = {k: TeamProfile(k) for k in inv.teams}
    for key, t in inv.teams.items():
        prof = out[key]
        for vendor in t.vendors:
            if _usable(vendor.replace("_", " ")):
                prof.keywords[vendor.replace("_", " ").lower()] = f"vendor {vendor} (subscription)"
        for vendor, products in t.products.items():
            v = vendor.replace("_", " ")
            if _usable(v):
                prof.keywords.setdefault(v.lower(), f"vendor {vendor} (subscription)")
            for p in products:
                words = p.replace("_", " ").split()
                if _usable(" ".join(words)):
                    prof.keywords[" ".join(words).lower()] = f"{vendor} {p} (subscription)"
                if words and _usable(words[0]):
                    prof.keywords.setdefault(words[0].lower(), f"{vendor} {p} (subscription)")
        extra = machines.news_teams[key].keywords if key in machines.news_teams else []
        for kw in extra:
            if kw.strip():
                prof.keywords[kw.strip().lower()] = f"keyword {kw.strip()!r}"
    counts: dict[str, dict[str, set[str]]] = {}
    for team, project, component, vid in findings:
        if team not in out:
            continue
        out[team].open_ids.setdefault(vid.upper(), set()).add(project)
        counts.setdefault(team, {}).setdefault(component, set()).add(project)
    for team, comps in counts.items():
        top = sorted(comps, key=lambda c: (-len(comps[c]), c))[:40]
        for c in top:
            if _usable(c) and c.lower() not in out[team].keywords:
                out[team].keywords[c.lower()] = f"component {c} in your projects"
                out[team].own_keywords.add(c.lower())
    for a in alerts:
        team = str(a.get("team", ""))
        if team in out and a.get("notify", "x") != "":
            out[team].alert_ids.add(str(a.get("cve", "")).upper())
    return out


# ----------------------------------------------------------------------- matching
@dataclass
class Match:
    item: Item
    why: list[str]
    own: bool  # touches the team's own systems
    exploited: bool  # in KEV (CISA or VulnCheck), or a public exploit (exploit feed)
    links: list[tuple[str, str]] = field(default_factory=list)  # (source, link), merged items

    @property
    def urgent(self) -> bool:
        return self.own or self.exploited


def match_item(
    item: Item, prof: TeamProfile, feed_teams: list[str], kev: Collection[str]
) -> Match | None:
    why: list[str] = []
    own = False
    for i in sorted(item.ids):
        if i in prof.open_ids:
            n = len(prof.open_ids[i])
            why.append(f"{i} open on {n} of your project{'s' if n != 1 else ''}")
            own = True
        elif i in prof.alert_ids:
            why.append(f"{i} alerted to your team")
    if feed_teams:
        if prof.team not in feed_teams:
            return None
        if not why:
            why.append(f"from {item.source}, followed by your team")
    for kw in prof.keyword_hits(item.text):
        why.append(f"mentions {kw!r}: {prof.keywords.get(kw, 'keyword')}")
        own = own or kw in prof.own_keywords
    if not why:
        return None
    kev_ids = sorted(i for i in item.ids if i in kev)
    exploited = bool(kev_ids) or item.kind == "exploit"
    by_label: dict[str, list[str]] = {}
    for i in kev_ids:
        by_label.setdefault(kev_label(kev, i), []).append(i)
    for label, ids in sorted(by_label.items()):
        why.append(f"in {label}: {', '.join(ids)}")
    if item.kind == "exploit":
        why.append("public exploit or PoC")
    return Match(item, why, own, exploited, [(item.source, item.link)])


def _rank_key(m: Match) -> tuple[int, int, float]:
    try:
        ts = datetime.fromisoformat(m.item.published).timestamp() if m.item.published else 0.0
    except ValueError:
        ts = 0.0
    return (0 if m.own else 1, 0 if m.exploited else 1, -ts)


def merge(matches: list[Match]) -> list[Match]:
    """Items sharing a CVE/GHSA id become one entry (the best ranked), with all links."""
    out: list[Match] = []
    by_id: dict[str, Match] = {}
    for m in sorted(matches, key=_rank_key):
        same = next((by_id[i] for i in sorted(m.item.ids) if i in by_id), None)
        if same is None:
            out.append(m)
            for i in m.item.ids:
                by_id[i] = m
            continue
        for link in m.links:
            if link not in same.links:
                same.links.append(link)
        same.why += [w for w in m.why if w not in same.why]
        same.own, same.exploited = same.own or m.own, same.exploited or m.exploited
        for i in m.item.ids:
            by_id.setdefault(i, same)
    return sorted(out, key=_rank_key)


def team_matches(
    items: list[Item], prof: TeamProfile, feeds: dict[str, NewsFeed], kev: Collection[str]
) -> list[Match]:
    found = []
    for it in items:
        f = feeds.get(it.source)
        m = match_item(it, prof, f.teams if f else [], kev)
        if m is not None:
            found.append(m)
    return merge(found)


# -------------------------------------------------------------------------- state
def load_seen(path: Path) -> dict[str, dict[str, str]]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def save_seen(path: Path, seen: dict[str, dict[str, str]], now: datetime) -> None:
    cutoff = (now - timedelta(days=SEEN_DAYS)).isoformat(timespec="seconds")
    kept = {mode: {k: v for k, v in keys.items() if v >= cutoff} for mode, keys in seen.items()}
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(kept, sort_keys=True) + "\n", encoding="utf-8")
    tmp.replace(path)


# ------------------------------------------------------------------ vulnflow data
def jsonl(lines: Iterable[str]) -> list[dict[str, Any]]:
    out = []
    for raw in lines:
        try:
            d = json.loads(raw)
        except ValueError:
            continue
        if isinstance(d, dict):
            out.append(d)
    return out


REVIEW_RE = re.compile(r"review by (\d{4}-\d{2}-\d{2})")


def reviews_due(
    ledger: Iterable[dict[str, Any]], team: str, today: date, days: int = 14
) -> list[list[str]]:
    """Accepted risks (ignore with `review by <date>`) whose review is within `days`."""
    latest: dict[tuple[str, str, str], dict[str, Any]] = {}
    for e in ledger:
        k = (
            str(e.get("project_uuid", "")),
            str(e.get("component_uuid", "")),
            str(e.get("vuln_uuid", "")),
        )
        latest[k] = e
    rows = []
    for e in latest.values():
        m = REVIEW_RE.search(str(e.get("comment", "")))
        if e.get("op") != "ignore" or e.get("team") != team or not m:
            continue
        due = date.fromisoformat(m.group(1))
        if due <= today + timedelta(days=days):
            rows.append(
                [
                    m.group(1),
                    code(str(e.get("vuln_id", ""))),
                    f"{e.get('component', '')} in {e.get('project', '')}",
                ]
            )
    return sorted(rows)


def vulnflow_section(
    team: str,
    alerts: list[dict[str, Any]],
    kev_log: list[dict[str, Any]],
    ledger: list[dict[str, Any]],
    since: str,
    today: date,
) -> Section | None:
    s = Section("From vulnflow")
    al = [
        a
        for a in alerts
        if a.get("team") == team and str(a.get("received_at", "")) > since and a.get("notify", "x") != ""
    ]
    if al:
        s.blocks.append(Para("OpenCVE alerts for your team:"))
        rows = [
            [
                str(a.get("tier_name", "")),
                code(str(a.get("cve", ""))),
                str(a.get("title") or "")[:120],
                NOTIFY_LABELS.get(str(a.get("notify", "")), str(a.get("notify") or "")),
            ]
            for a in sorted(al, key=lambda a: (a.get("tier", 9), str(a.get("cve", ""))))
        ]
        s.blocks.append(Table(["Tier", "CVE", "What", "Why"], rows))
    kev = [
        e
        for e in kev_log
        if str(e.get("seen_at", "")) > since
        and (team in (e.get("findings") or {}) or team in (e.get("follows") or []))
    ]
    if kev:
        s.blocks.append(Para("New in KEV that hit your team:"))
        rows = [
            [
                code(str(e.get("cve", ""))) + f" ({e.get('source') or 'CISA'} KEV)",
                f"{e.get('vendor', '')} {e.get('product', '')}: {e.get('name', '')}",
                "open findings" if team in (e.get("findings") or {}) else "vendor you follow",
            ]
            for e in kev
        ]
        s.blocks.append(Table(["CVE", "Vulnerability", "Hits"], rows))
    due = reviews_due(ledger, team, today)
    if due:
        s.blocks.append(Para("Accepted risks to review within 14 days:"))
        s.blocks.append(Table(["Review by", "CVE", "Where"], due))
    if not s.blocks:
        return None
    s.notable = bool(al or kev)
    return s


# -------------------------------------------------------------------------- output
def items_section(title: str, matches: list[Match]) -> Section:
    s = Section(title)
    if not matches:
        s.blocks.append(Para("Nothing new."))
        return s
    rows = []
    for m in matches:
        flags = ("**your systems** " if m.own else "") + ("**exploited** " if m.exploited else "")
        links = "; ".join(f"{src}: {link}" for src, link in m.links if link)
        rows.append([flags.strip() or "-", m.item.title, "; ".join(m.why), links, m.item.published[:10]])
    s.blocks.append(Table(["", "Item", "Why", "Links", "Date"], rows))
    s.notable = any(m.urgent for m in matches)
    return s


@dataclass
class TeamLetter:
    team: str
    sections: list[Section]
    sent_keys: list[str]

    @property
    def empty(self) -> bool:
        return not any(s.notable or any(isinstance(b, Table) for b in s.blocks) for s in self.sections)


def newsletter(
    mode: str,
    inv: Inventory,
    machines: Machines,
    profiles: dict[str, TeamProfile],
    items: list[Item],
    kev: Collection[str],
    seen: dict[str, dict[str, str]],
    *,
    alerts: list[dict[str, Any]] | None = None,
    kev_log: list[dict[str, Any]] | None = None,
    ledger: list[dict[str, Any]] | None = None,
    teams: list[str] | None = None,
    now: datetime | None = None,
) -> list[TeamLetter]:
    """weekly or daily: one letter per team with something to say."""
    now = now or datetime.now(UTC)
    already = seen.get(mode, {})
    letters = []
    for team in teams or sorted(inv.teams):
        found = [
            m
            for m in team_matches(items, profiles[team], machines.news_feeds, kev)
            if m.item.key not in already
        ]
        if mode == "daily":
            found = [m for m in found if m.urgent]
        sections = []
        if mode == "weekly":
            since = (now - timedelta(days=7)).isoformat(timespec="seconds")
            vs = vulnflow_section(team, alerts or [], kev_log or [], ledger or [], since, now.date())
            if vs is not None:
                sections.append(vs)
        if found or mode == "weekly":
            title = (
                "Urgent: your systems, exploited or public exploit"
                if mode == "daily"
                else "News for your team"
            )
            sections.append(items_section(title, found))
        keys = [m.item.key for m in found]
        letter = TeamLetter(team, sections, keys)
        if mode == "daily" and not found:
            continue
        if mode == "weekly" and letter.empty:
            continue
        letters.append(letter)
    return letters


def alert(
    ident: str,
    inv: Inventory,
    machines: Machines,
    profiles: dict[str, TeamProfile],
    items: list[Item],
    kev_index: dict[str, dict[str, Any]],
    findings: list[tuple[str, str, str, str]],
    *,
    teams: list[str] | None = None,
    followers: Callable[[str], list[str]] | None = None,
) -> list[TeamLetter]:
    """Everything known about one CVE, GHSA or keyword, to the teams it concerns."""
    ident = ident.strip()
    is_id = bool(CVE_RE.fullmatch(ident) or GHSA_RE.fullmatch(ident))
    key = ident.upper() if is_id else ident.lower()
    related = [
        it
        for it in items
        if (key in it.ids if is_id else re.search(rf"\b{re.escape(key)}\b", it.text, re.IGNORECASE))
    ]
    concerned: dict[str, list[str]] = {}
    for team, project, component, vid in findings:
        if (is_id and vid.upper() == key) or (not is_id and component.lower() == key):
            concerned.setdefault(team, []).append(f"{component} in {project}")
    for t, prof in profiles.items():
        if is_id and key in prof.alert_ids:
            concerned.setdefault(t, []).append("alerted to your team")
        if not is_id and prof.keyword_hits(ident):
            concerned.setdefault(t, []).append(f"matches {prof.keywords.get(key, 'a keyword')}")
    kev_entry = kev_index.get(key) if is_id else None
    if kev_entry and followers is not None:
        for t in followers(str(kev_entry.get("vendorProject", ""))):
            concerned.setdefault(t, []).append(f"vendor {kev_entry.get('vendorProject')} followed")
    letters = []
    for team in teams or sorted(concerned):
        s = Section(f"About {ident}")
        where = concerned.get(team, [])
        s.blocks.append(
            Para(
                "Concerns your team: "
                + (
                    "; ".join(sorted(set(where)))
                    if where
                    else "not found in your data (sent with --team)"
                )
            )
        )
        if kev_entry:
            s.blocks.append(
                Para(
                    f"**In {kev_entry.get('kevSource') or 'CISA'} KEV** since "
                    f"{kev_entry.get('dateAdded', '')}: "
                    f"{kev_entry.get('vendorProject', '')} {kev_entry.get('product', '')}: "
                    f"{kev_entry.get('vulnerabilityName', '')}"
                    + (
                        " (ransomware use)"
                        if str(kev_entry.get("knownRansomwareCampaignUse", "")).lower() == "known"
                        else ""
                    )
                )
            )
        s.notable = True
        sections = [s]
        if related:
            ms = [
                Match(
                    it,
                    [f"mentions {ident}"],
                    bool(where),
                    it.kind == "exploit" or bool(kev_entry),
                    [(it.source, it.link)],
                )
                for it in related
            ]
            sections.append(items_section("In the feeds", merge(ms)))
        letters.append(TeamLetter(team, sections, []))
    return letters
