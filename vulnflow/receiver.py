"""OpenCVE webhook receiver: enrich -> prioritize -> route to the owning team.

OpenCVE posts one JSON document per notification run, containing the organization,
project, notification name, period and a list of `changes` (each with `cve` and
`events`). See docs.opencve.io/concepts/notifications/.

Which changes notify (chat, SOC, OpenCVE write-back): the tier says how serious the CVE is,
`notify` why this change matters. A change notifies when the CVE is new to the project
(OpenCVE's `first_time` event), was just added to KEV, or became more serious (its tier
went up with this change's CVSS/EPSS update); and, for a CVE someone follows (an open
OpenCVE status: to_evaluate, pending_review, analysis_in_progress, remediation_in_progress),
any change that isn't only `quiet_event_types` (title, description, references,
weaknesses). Everything else (OpenCVE's titles come and go on old KEV entries) is logged
with notify "" and stays out of chat.

Configure the OpenCVE webhook notification with:
  URL:    http://<host>:8380/opencve
  Header: X-Vulnflow-Token: <VULNFLOW_WEBHOOK_TOKEN>
"""

from __future__ import annotations

import hmac
import json
import logging
import queue
import threading
import time
from collections.abc import Callable
from dataclasses import asdict, dataclass, field, replace
from datetime import UTC, datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from .clients import OpenCVE
from .config import ChatChannel, Inventory
from .intel import Enricher
from .net import Http
from .priority import assess

log = logging.getLogger(__name__)
MAX_BODY = 5 * 1024 * 1024


@dataclass
class Alert:
    received_at: str
    organization: str
    project: str
    team: str
    cve: str
    cvss31: float | None
    event_types: list[str]
    tier: int
    tier_name: str
    reasons: list[str]
    kev: bool
    epss: float | None
    epss_percentile: float | None
    sightings: dict[str, int]
    description: str
    enrichment_errors: list[str]
    title: str = ""  # KEV's name, OpenCVE's title, or the description's first sentence
    products: list[str] = field(default_factory=list)  # the subscriptions it matched
    subscribed: list[str] = field(default_factory=list)  # the same, raw (vendor, vendor$PRODUCT$p)
    # why this change notifies: new, kev, worse, followed; "" = log only
    notify: str = ""
    # a non-quiet change: notifies if the CVE turns out to be followed (Pipeline checks)
    followable: bool = False


FOLLOWED_STATUSES = ("to_evaluate", "pending_review", "analysis_in_progress", "remediation_in_progress")
NOTIFY_LABELS = {"new": "new", "kev": "added to KEV", "worse": "more serious", "followed": "followed"}


def _title(sig_name: str, events: list[dict[str, Any]], description: str) -> str:
    if sig_name:
        return sig_name
    for e in events:
        d = e.get("details") if e.get("type") == "title" else None
        if isinstance(d, dict) and d.get("new"):
            return str(d["new"])
    first = " ".join(description.split()).split(". ")[0]
    return first if len(first) <= 100 else first[:97].rstrip() + "..."


def _metric_old(events: list[dict[str, Any]], name: str, current: float | None) -> float | None:
    """The value of a metric before this change: the `old` of an update, None if the change
    added it, else unchanged."""
    for e in events:
        d = e.get("details") if e.get("type") == "metrics" else None
        if not isinstance(d, dict):
            continue
        if name in (d.get("added") or {}):
            return None
        upd = (d.get("updated") or {}).get(name)
        if isinstance(upd, dict):
            return _cvss((upd.get("old") or {}).get("score"))
    return current


def _cvss(v: Any) -> float | None:
    try:
        return None if v in (None, "") else float(v)
    except (TypeError, ValueError):
        return None


def chat_sender(url: str) -> Callable[[str], None]:
    """POST {"text": ...} to a Mattermost/Slack/Teams-style incoming webhook."""
    http = Http(url, timeout=15)

    def send(text: str) -> None:
        http.post("", json_body={"text": text})

    return send


def kev_added(events: list[dict[str, Any]]) -> str | None:
    """OpenCVE's own word that the change added the CVE to KEV: an event of type `metrics`
    with details.added.kev = {dateAdded, dueDate} (the `kev_added` trigger's test in v3.1.0;
    seen in opencve-kb on 2026-11-26). Returns dateAdded ("" if absent), or None."""
    for e in events:
        if not isinstance(e, dict) or e.get("type") != "metrics":
            continue
        details = e.get("details")
        added = details.get("added") if isinstance(details, dict) else None
        kev = added.get("kev") if isinstance(added, dict) else None
        if kev:
            return str(kev.get("dateAdded", "")) if isinstance(kev, dict) else ""
    return None


def process_payload(payload: dict[str, Any], inv: Inventory, enricher: Enricher) -> list[Alert]:
    project = str(payload.get("project", ""))
    team = inv.team_for_opencve_project(project)
    ignore = set(inv.rules.ignore_event_types)

    wanted: list[tuple[dict, list[str], str | None]] = []
    events_by_cve: dict[str, list[dict[str, Any]]] = {}
    for ch in payload.get("changes") or []:
        cve = ch.get("cve") or {}
        events = [e for e in ch.get("events") or [] if isinstance(e, dict)]
        types = [e.get("type", "") for e in events]
        relevant = [t for t in types if t not in ignore]
        if types and not relevant:
            continue  # only ignored event types (e.g. reference churn)
        if cve.get("cve_id"):
            wanted.append((cve, relevant or types, kev_added(events)))
            events_by_cve[str(cve["cve_id"]).upper()] = events

    signals = enricher.enrich(c["cve_id"] for c, _, _ in wanted)
    now = datetime.now(UTC).isoformat(timespec="seconds")
    alerts: list[Alert] = []
    for cve, types, kev_date in wanted:
        cid = cve["cve_id"].upper()
        sig = signals[cid]
        if kev_date is not None and not sig.kev:
            # OpenCVE saw the KEV addition before our cached copy of the catalog did
            sig.kev = True
            sig.kev_date_added = sig.kev_date_added or kev_date[:10]
        cvss = _cvss(cve.get("cvss31"))
        v = assess(cvss, sig, inv.rules)
        events = events_by_cve.get(cid, [])
        if "first_time" in types:
            notify = "new"
        elif kev_date is not None:
            notify = "kev"
        else:
            before = replace(sig, epss=_metric_old(events, "epss", sig.epss))
            old = assess(_metric_old(events, "cvssV3_1", cvss), before, inv.rules)
            notify = "worse" if v.tier < old.tier else ""
        quiet = set(inv.rules.quiet_event_types)
        subs = (cve.get("subscriptions") or {}).get("human") or []
        raw_subs = (cve.get("subscriptions") or {}).get("raw") or []
        alerts.append(
            Alert(
                received_at=now,
                organization=str(payload.get("organization", "")),
                project=project,
                team=team.key if team else "unrouted",
                cve=cid,
                cvss31=cvss,
                event_types=types,
                tier=v.tier,
                tier_name=v.name,
                reasons=v.reasons,
                kev=sig.kev,
                epss=sig.epss,
                epss_percentile=sig.epss_percentile,
                sightings=sig.sightings,
                description=(cve.get("description") or "")[:400],
                enrichment_errors=sig.errors,
                title=_title(sig.kev_name, events, str(cve.get("description") or "")),
                products=[str(x) for x in subs],
                subscribed=[str(x) for x in raw_subs],
                notify=notify,
                followable=any(t not in quiet for t in types),
            )
        )
    alerts.sort(key=lambda a: (a.tier, -(a.epss or 0), -(a.cvss31 or 0)))
    return alerts


def alert_line(
    a: Alert, opencve_url: str = "", team: bool = False, teams: list[str] | None = None
) -> str:
    """One chat line: what it is (title, products), why now, the scores and the reasons.
    team: name the alert's team; teams: name these instead (a noisy-product channel)."""
    epss = f"{a.epss:.3f}" if a.epss is not None else "n/a"
    cvss = a.cvss31 if a.cvss31 is not None else "n/a"
    link = f" {opencve_url.rstrip('/')}/cve/{a.cve}" if opencve_url else ""
    what = a.title + (f" ({', '.join(a.products)})" if a.products else "")
    why = NOTIFY_LABELS.get(a.notify, a.notify)
    changed = ", ".join(a.event_types) or "change"
    who = teams or ([a.team] if team else [])
    named = f", team{'s' if len(who) > 1 else ''} {', '.join(who)}" if who else ""
    return (
        f"- [{a.tier_name}] {a.cve}: {what}\n"
        f"  {why} ({changed}){named}, CVSS {cvss}, EPSS {epss}: "
        f"{'; '.join(a.reasons)}{link}"
    )


def format_chat(alerts: list[Alert], inv: Inventory, opencve_url: str = "") -> str | None:
    hot = [a for a in alerts if a.tier <= inv.rules.chat_min_tier and a.notify]
    if not hot:
        return None
    team = inv.teams.get(hot[0].team)
    head = (
        f"{team.chat_mention + ' ' if team and team.chat_mention else ''}"
        f"{len(hot)} CVE(s) to look at in project '{hot[0].project}'"
    )
    lines = [head, *(alert_line(a, opencve_url) for a in hot)]
    rest = len(alerts) - len(hot)
    if rest:
        lines.append(f"(+{rest} other change(s) in the log)")
    return "\n".join(lines)


def _vendor_product(raw: str) -> tuple[str, str]:
    """OpenCVE's raw subscription of a CVE: "vendor" or "vendor$PRODUCT$product" (v3.1.0
    `BaseNotifier.prepare_payload`: the project's subscriptions that are in the CVE's vendors;
    ":" is accepted too) -> (vendor, product or "")."""
    vendor, sep, product = raw.lower().replace("$product$", ":").partition(":")
    return vendor, product if sep else ""


def channel_matches(channel: ChatChannel, a: Alert) -> bool:
    """A "vendor" pattern matches any of that vendor's products, "vendor:product" only that one."""
    seen = {_vendor_product(r) for r in a.subscribed}
    for m in channel.match:
        vendor, _, product = m.partition(":")
        if any(v == vendor and (not product or p == product) for v, p in seen):
            return True
    return False


def route_channels(
    alerts: list[Alert], channels: list[ChatChannel]
) -> tuple[list[Alert], dict[str, list[Alert]]]:
    """Split off the alerts a noisy-product channel takes: (the rest, {channel: alerts}). An
    alert goes to the first channel (in machines.toml order) that matches it, and then not to
    the team's channel."""
    rest: list[Alert] = []
    routed: dict[str, list[Alert]] = {}
    for a in alerts:
        ch = next((c for c in channels if channel_matches(c, a)), None)
        if ch is None:
            rest.append(a)
        else:
            routed.setdefault(ch.name, []).append(a)
    return rest, routed


def teams_affected(a: Alert, inv: Inventory) -> list[str]:
    """The alert's team first, then every other team whose subscriptions cover one of the
    products the CVE matched: OpenCVE sends each team's project its own webhook, and a shared
    channel posts the CVE once for all of them."""
    seen = {_vendor_product(r) for r in a.subscribed}
    others = sorted(
        k
        for k, t in inv.teams.items()
        if k != a.team and any(v in t.vendors or (p and p in t.products.get(v, [])) for v, p in seen)
    )
    return ([a.team] if a.team != "unrouted" else []) + others


def format_channel(name: str, alerts: list[Alert], inv: Inventory, opencve_url: str = "") -> str | None:
    """A noisy-product channel's message: the alerts already filtered, every team affected
    named in each line, nobody mentioned."""
    if not alerts:
        return None
    lines = [f"#{name}: {len(alerts)} CVE(s) to look at"]
    lines += [alert_line(a, opencve_url, teams=teams_affected(a, inv)) for a in alerts]
    return "\n".join(lines)


class ChannelSeen:
    """What the noisy-product channels posted in the last `ttl` seconds, in a JSON file next to
    the alert log, so a CVE change that reaches several teams' projects (one webhook each) is
    posted once, also across a receiver restart. Used from the single worker thread only."""

    def __init__(self, path: Path, ttl: float = 24 * 3600):
        self.path, self.ttl = path, ttl
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            self._at = {str(k): float(v) for k, v in data.items()}
        except FileNotFoundError:
            self._at = {}
        except (OSError, ValueError, AttributeError) as e:
            log.warning("%s unreadable (%s), starting empty", path, e)
            self._at = {}

    @staticmethod
    def key(channel: str, a: Alert) -> str:
        return f"{channel}|{a.cve}|{a.notify}|{','.join(sorted(a.event_types))}"

    def has(self, key: str, now: float) -> bool:
        return now - self._at.get(key, -self.ttl - 1) <= self.ttl

    def add(self, keys: list[str], now: float) -> None:
        self._at = {k: t for k, t in self._at.items() if now - t <= self.ttl}
        self._at.update(dict.fromkeys(keys, now))
        tmp = self.path.with_name(self.path.name + ".tmp")
        try:
            tmp.write_text(json.dumps(self._at, sort_keys=True), encoding="utf-8")
            tmp.replace(self.path)
        except OSError as e:
            log.warning("could not save %s: %s", self.path, e)


def format_soc(alerts: list[Alert], min_tier: int, opencve_url: str = "") -> str | None:
    """The SOC channel's message: every alert at or above min_tier, whatever the team
    (unrouted included), with the team named in each line instead of mentioned."""
    hot = [a for a in alerts if a.tier <= min_tier and a.notify]
    if not hot:
        return None
    lines = [f"SOC: {len(hot)} CVE(s) to look at from OpenCVE project '{hot[0].project}'"]
    lines += [alert_line(a, opencve_url, team=True) for a in hot]
    return "\n".join(lines)


class Pipeline:
    """Background worker so the webhook returns 200 immediately."""

    def __init__(
        self,
        inv: Inventory,
        enricher: Enricher,
        log_path: Path,
        chat_webhook: str = "",
        opencve_url: str = "",
        chat_sender: Callable[[str], None] | None = None,
        opencve: OpenCVE | None = None,
        triage_max_tier: int = 0,
        soc_webhook: str = "",
        soc_sender: Callable[[str], None] | None = None,
        soc_min_tier: int = 1,
        channels: list[ChatChannel] | None = None,
        channel_senders: dict[str, Callable[[str], None]] | None = None,
    ):
        self.inv, self.enricher, self.log_path = inv, enricher, log_path
        # Noisy-product channels ([chat.*] in machines.toml): a channel takes its products'
        # alerts away from the team's channel, but only when its webhook is set; without one
        # the alerts stay where they were rather than going nowhere.
        # A channel is shared by all teams: a CVE change posted for one team's project isn't
        # posted again when the next team's webhook brings it (ChannelSeen, 24 h).
        senders = channel_senders or {}
        self.channels = [c for c in channels or [] if c.name in senders]
        self._channel_send = senders
        self._channel_seen = ChannelSeen(log_path.with_suffix(".channels-seen.json"))
        for c in channels or []:
            if c.name not in senders:
                log.warning(
                    "chat channel %s: %s is not set, its alerts stay in team chat", c.name, c.webhook_env
                )
        self.opencve_url = opencve_url
        # Write-back: mark P1..P(triage_max_tier) CVEs "to_evaluate" in OpenCVE so they
        # show up in the team's triage view. Never overwrites a status a human set.
        self.opencve, self.triage_max_tier = opencve, triage_max_tier
        self.q: queue.Queue[dict] = queue.Queue(maxsize=1000)
        self._send = chat_sender or (self._make_sender(chat_webhook) if chat_webhook else None)
        # SOC channel: every alert at or above soc_min_tier, across teams; independent of
        # the team channel, so one failing doesn't stop the other.
        self._soc_send = soc_sender or (self._make_sender(soc_webhook) if soc_webhook else None)
        self.soc_min_tier = soc_min_tier
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        threading.Thread(target=self._worker, daemon=True, name="vulnflow-worker").start()

    @staticmethod
    def _make_sender(url: str) -> Callable[[str], None]:
        return chat_sender(url)

    def handle(self, payload: dict) -> list[Alert]:
        alerts = process_payload(payload, self.inv, self.enricher)
        self._followed(alerts)
        with self.log_path.open("a", encoding="utf-8") as f:
            for a in alerts:
                f.write(json.dumps(asdict(a), ensure_ascii=False) + "\n")
        if self.opencve and self.triage_max_tier:
            self._triage(alerts)
        rest, routed = route_channels(alerts, self.channels)
        for name, chunk in routed.items():
            self._post_channel(name, chunk)
        msg = format_chat(rest, self.inv, self.opencve_url)
        if msg and self._send:
            try:
                self._send(msg)
            except Exception as e:
                log.error("chat delivery failed: %s", e)
        soc = format_soc(alerts, self.soc_min_tier, self.opencve_url)
        if soc and self._soc_send:
            try:
                self._soc_send(soc)
            except Exception as e:
                log.error("SOC chat delivery failed: %s", e)
        log.info(
            "project=%s changes=%d top=%s",
            payload.get("project"),
            len(alerts),
            alerts[0].tier_name if alerts else "-",
        )
        return alerts

    def _post_channel(self, name: str, chunk: list[Alert]) -> None:
        """Post a noisy-product channel's share of this payload, skipping CVE changes the
        channel already posted for another team. Recorded only once delivered, so after a
        failure the next team's webhook tries again."""
        ch = next(c for c in self.channels if c.name == name)
        tier = ch.min_tier or self.inv.rules.chat_min_tier
        now = time.time()
        hot = [a for a in chunk if a.tier <= tier and a.notify]
        keys = {a.cve: ChannelSeen.key(name, a) for a in hot}
        new = [a for a in hot if not self._channel_seen.has(keys[a.cve], now)]
        if len(new) < len(hot):
            log.info("chat channel %s: %d already posted for another team", name, len(hot) - len(new))
        text = format_channel(name, new, self.inv, self.opencve_url)
        if not text:
            return
        try:
            self._channel_send[name](text)
        except Exception as e:
            log.error("chat channel %s delivery failed: %s", name, e)
            return
        self._channel_seen.add([keys[a.cve] for a in new], now)

    def _followed(self, alerts: list[Alert]) -> None:
        """A non-quiet update to a CVE someone follows in OpenCVE (an open status) notifies.
        Asked only for changes that could reach chat and don't notify anyway."""
        if self.opencve is None:
            return
        limit = max(
            self.inv.rules.chat_min_tier,
            self.soc_min_tier if self._soc_send else 0,
            *(c.min_tier or 0 for c in self.channels),
        )
        for a in alerts:
            if a.notify or not a.followable or a.tier > limit or a.team == "unrouted":
                continue
            try:
                tracker = self.opencve.get_tracker(a.project, a.cve) or {}
            except Exception as e:
                log.warning("OpenCVE status lookup failed for %s: %s", a.cve, e)
                continue
            if tracker.get("status") in FOLLOWED_STATUSES:
                a.notify = "followed"

    def _triage(self, alerts: list[Alert]) -> None:
        if self.opencve is None:
            return
        for a in alerts:
            if a.tier > self.triage_max_tier or a.team == "unrouted" or not a.notify:
                continue
            try:
                tracker = self.opencve.get_tracker(a.project, a.cve) or {}
                if tracker.get("status"):
                    continue  # a human already triaged it
                self.opencve.set_status(a.project, a.cve, "to_evaluate")
                log.info("OpenCVE %s/%s -> to_evaluate (%s)", a.project, a.cve, a.tier_name)
            except Exception as e:
                log.warning("OpenCVE triage write-back failed for %s: %s", a.cve, e)

    def _worker(self) -> None:
        while True:
            payload = self.q.get()
            try:
                self.handle(payload)
            except Exception:
                log.exception("failed to process payload")
            finally:
                self.q.task_done()


def make_handler(pipeline: Pipeline, token: str) -> type[BaseHTTPRequestHandler]:
    if not token or len(token) < 16:
        raise SystemExit("VULNFLOW_WEBHOOK_TOKEN must be set (>= 16 chars)")

    class Handler(BaseHTTPRequestHandler):
        server_version = "vulnflow"

        def _reply(self, code: int, body: dict) -> None:
            data = json.dumps(body).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self) -> None:
            if self.path == "/healthz":
                self._reply(200, {"status": "ok", "queued": pipeline.q.qsize()})
            else:
                self._reply(404, {"error": "not found"})

        def do_POST(self) -> None:
            if self.path != "/opencve":
                return self._reply(404, {"error": "not found"})
            given = self.headers.get("X-Vulnflow-Token", "")
            if not hmac.compare_digest(given.encode(), token.encode()):
                return self._reply(401, {"error": "bad token"})
            length = int(self.headers.get("Content-Length") or 0)
            if length <= 0 or length > MAX_BODY:
                return self._reply(413 if length > MAX_BODY else 400, {"error": "bad length"})
            try:
                payload = json.loads(self.rfile.read(length))
                if not isinstance(payload, dict):
                    raise ValueError("payload is not an object")
            except ValueError as e:
                return self._reply(400, {"error": f"invalid json: {e}"})
            try:
                pipeline.q.put_nowait(payload)
            except queue.Full:
                return self._reply(503, {"error": "queue full"})
            self._reply(202, {"accepted": len(payload.get("changes") or [])})

        def log_message(self, fmt: str, *args: Any) -> None:
            log.debug("http: " + fmt, *args)

    return Handler


def serve(pipeline: Pipeline, token: str, host: str, port: int) -> None:
    httpd = ThreadingHTTPServer((host, port), make_handler(pipeline, token))
    log.info("listening on http://%s:%d/opencve", host, port)
    httpd.serve_forever()
