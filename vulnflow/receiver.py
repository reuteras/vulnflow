"""OpenCVE webhook receiver: enrich -> prioritize -> route to the owning team.

OpenCVE posts one JSON document per notification run, containing the organization,
project, notification name, period and a list of `changes` (each with `cve` and
`events`). See docs.opencve.io/concepts/notifications/.

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
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Callable

from .clients import OpenCVE
from .config import Inventory
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


def _cvss(v: Any) -> float | None:
    try:
        return None if v in (None, "") else float(v)
    except (TypeError, ValueError):
        return None


def process_payload(payload: dict[str, Any], inv: Inventory, enricher: Enricher) -> list[Alert]:
    project = str(payload.get("project", ""))
    team = inv.team_for_opencve_project(project)
    ignore = set(inv.rules.ignore_event_types)

    wanted: list[tuple[dict, list[str]]] = []
    for ch in payload.get("changes") or []:
        cve = ch.get("cve") or {}
        types = [e.get("type", "") for e in ch.get("events") or []]
        relevant = [t for t in types if t not in ignore]
        if types and not relevant:
            continue  # only ignored event types (e.g. reference churn)
        if cve.get("cve_id"):
            wanted.append((cve, relevant or types))

    signals = enricher.enrich(c["cve_id"] for c, _ in wanted)
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    alerts: list[Alert] = []
    for cve, types in wanted:
        cid = cve["cve_id"].upper()
        sig = signals[cid]
        cvss = _cvss(cve.get("cvss31"))
        v = assess(cvss, sig, inv.rules)
        alerts.append(Alert(
            received_at=now, organization=str(payload.get("organization", "")),
            project=project, team=team.key if team else "unrouted", cve=cid, cvss31=cvss,
            event_types=types, tier=v.tier, tier_name=v.name, reasons=v.reasons,
            kev=sig.kev, epss=sig.epss, epss_percentile=sig.epss_percentile,
            sightings=sig.sightings, description=(cve.get("description") or "")[:400],
            enrichment_errors=sig.errors))
    alerts.sort(key=lambda a: (a.tier, -(a.epss or 0), -(a.cvss31 or 0)))
    return alerts


def format_chat(alerts: list[Alert], inv: Inventory, opencve_url: str = "") -> str | None:
    hot = [a for a in alerts if a.tier <= inv.rules.chat_min_tier]
    if not hot:
        return None
    team = inv.teams.get(hot[0].team)
    head = f"{team.chat_mention + ' ' if team and team.chat_mention else ''}" \
           f"{len(hot)} prioritised CVE change(s) for project '{hot[0].project}'"
    lines = [head]
    for a in hot:
        epss = f"{a.epss:.3f}" if a.epss is not None else "n/a"
        link = f" {opencve_url.rstrip('/')}/cve/{a.cve}" if opencve_url else ""
        lines.append(f"- [{a.tier_name}] {a.cve} CVSS {a.cvss31 if a.cvss31 is not None else 'n/a'}"
                     f" EPSS {epss} ({', '.join(a.event_types) or 'change'}): "
                     f"{'; '.join(a.reasons)}{link}")
    rest = len(alerts) - len(hot)
    if rest:
        lines.append(f"(+{rest} lower-tier change(s) in the log)")
    return "\n".join(lines)


class Pipeline:
    """Background worker so the webhook returns 200 immediately."""

    def __init__(self, inv: Inventory, enricher: Enricher, log_path: Path,
                 chat_webhook: str = "", opencve_url: str = "",
                 chat_sender: Callable[[str], None] | None = None,
                 opencve: OpenCVE | None = None, triage_max_tier: int = 0):
        self.inv, self.enricher, self.log_path = inv, enricher, log_path
        self.opencve_url = opencve_url
        # Write-back: mark P1..P(triage_max_tier) CVEs "to_evaluate" in OpenCVE so they
        # show up in the team's triage view. Never overwrites a status a human set.
        self.opencve, self.triage_max_tier = opencve, triage_max_tier
        self.q: queue.Queue[dict] = queue.Queue(maxsize=1000)
        self._send = chat_sender or (self._make_sender(chat_webhook) if chat_webhook else None)
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        threading.Thread(target=self._worker, daemon=True, name="vulnflow-worker").start()

    @staticmethod
    def _make_sender(url: str) -> Callable[[str], None]:
        http = Http(url, timeout=15)
        return lambda text: http.post("", json_body={"text": text})

    def handle(self, payload: dict) -> list[Alert]:
        alerts = process_payload(payload, self.inv, self.enricher)
        with self.log_path.open("a", encoding="utf-8") as f:
            for a in alerts:
                f.write(json.dumps(asdict(a), ensure_ascii=False) + "\n")
        if self.opencve and self.triage_max_tier:
            self._triage(alerts)
        msg = format_chat(alerts, self.inv, self.opencve_url)
        if msg and self._send:
            try:
                self._send(msg)
            except Exception as e:
                log.error("chat delivery failed: %s", e)
        log.info("project=%s changes=%d top=%s", payload.get("project"), len(alerts),
                 alerts[0].tier_name if alerts else "-")
        return alerts

    def _triage(self, alerts: list[Alert]) -> None:
        assert self.opencve
        for a in alerts:
            if a.tier > self.triage_max_tier or a.team == "unrouted":
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

        def do_GET(self) -> None:  # noqa: N802
            if self.path == "/healthz":
                self._reply(200, {"status": "ok", "queued": pipeline.q.qsize()})
            else:
                self._reply(404, {"error": "not found"})

        def do_POST(self) -> None:  # noqa: N802
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
