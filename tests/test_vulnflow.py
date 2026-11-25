"""Offline tests: all HTTP goes through a fake transport."""

from __future__ import annotations

import base64
import json
import os
import pwd
import secrets
import threading
import time
import urllib.request
from dataclasses import asdict
from pathlib import Path
from typing import Any

import pytest

from vulnflow.clients import DefectDojo, DependencyTrack, OpenCVE
from vulnflow.config import PriorityRules, load_inventory, load_machines
from vulnflow.intel import Enricher, Signals
from vulnflow.jobs import dt_to_dojo, sync_inventory
from vulnflow.net import Response
from vulnflow.priority import assess
from vulnflow.receiver import Pipeline, format_chat, make_handler, process_payload

ROOT = Path(__file__).resolve().parents[1]
INV = ROOT / "inventory" / "inventory.toml"

KEV_DOC = {
    "vulnerabilities": [
        {"cveID": "CVE-2024-3400", "dateAdded": "2024-04-12", "knownRansomwareCampaignUse": "Unknown"},
        {"cveID": "CVE-2023-4966", "dateAdded": "2023-10-18", "knownRansomwareCampaignUse": "Known"},
    ]
}


class FakeTransport:
    """Routes requests by substring match; records every call."""

    def __init__(self, routes: dict[str, object]):
        self.routes = routes
        # body typed Any: tests json.loads()/decode() it directly
        self.calls: list[tuple[str, str, dict, Any]] = []

    def __call__(self, method, url, headers, body, timeout):
        self.calls.append((method, url, dict(headers), body))
        for key, val in self.routes.items():
            m, _, frag = key.partition(" ")
            if m == method and frag in url:
                if callable(val):
                    return val(method, url, headers, body)
                if isinstance(val, Response):
                    return val
                return Response(200, json.dumps(val).encode(), {})
        return Response(404, b'{"detail":"not found"}', {})


def intel_routes(
    epss: dict[str, float] | None = None, sightings: dict[str, list[str]] | None = None
) -> dict[str, object]:
    epss = epss or {}
    sightings = sightings or {}

    def epss_route(m, url, h, b):
        ids = url.split("cve=")[1].split(",")
        rows = [{"cve": c, "epss": str(epss[c]), "percentile": "0.9"} for c in ids if c in epss]
        return Response(200, json.dumps({"data": rows}).encode(), {})

    def circl_route(m, url, h, b):
        q = dict(p.split("=", 1) for p in url.split("?", 1)[1].split("&"))
        assert q["per_page"] == "1"
        n = sightings.get(q["vuln_id"], []).count(q["type"])
        return Response(200, json.dumps({"metadata": {"count": n}, "data": []}).encode(), {})

    return {
        "GET known_exploited_vulnerabilities.json": KEV_DOC,
        "GET api.first.org/data/v1/epss": epss_route,
        "GET /api/sighting/": circl_route,
    }


@pytest.fixture
def inv():
    return load_inventory(INV)


def make_enricher(tmp_path, **kw) -> tuple[Enricher, FakeTransport]:
    t = FakeTransport(intel_routes(**kw))
    return Enricher(cache_dir=tmp_path, transport=t), t


# ----------------------------------------------------------------------- inventory
def test_inventory_loads_teams_and_rules(inv):
    assert set(inv.teams) == {"sysadm", "users", "dev", "network", "virt", "platform"}
    assert inv.teams["network"].products["citrix"] == [
        "netscaler_application_delivery_controller",
        "netscaler_gateway",
    ]
    assert inv.teams["virt"].dtrack_tag == "team-virt"
    s = inv.teams["sysadm"]
    assert s.opencve_project == "sysadm" and s.dtrack_tag == "team-sysadm"
    assert s.products["debian"] == ["debian_linux"] and s.products["linux"] == ["linux_kernel"]
    assert inv.teams["users"].products["apple"] == ["macos"]
    assert inv.rules.chat_min_tier == 2 and inv.rules.ignore_event_types == ["references"]
    assert inv.team_for_opencve_project("dev").key == "dev"


# ------------------------------------------------------------------------ priority
@pytest.mark.parametrize(
    "cvss,sig,tier",
    [
        (5.0, Signals("C", kev=True), 1),
        (None, Signals("C", sightings={"exploited": 2}), 1),
        (6.0, Signals("C", epss=0.4), 2),
        (9.8, Signals("C", epss=0.02), 2),
        (9.8, Signals("C", epss=0.001), 3),
        (7.5, Signals("C"), 3),
        (5.0, Signals("C", epss=0.001), 4),
        (None, Signals("C"), 4),
    ],
)
def test_assess_tiers(cvss, sig, tier):
    assert assess(cvss, sig, PriorityRules()).tier == tier


def test_assess_explains_missing_cvss():
    v = assess(None, Signals("C"), PriorityRules())
    assert any("unenriched" in r for r in v.reasons)


# --------------------------------------------------------------------- enrichment
def test_enricher_combines_sources_and_caches_kev(tmp_path):
    e, t = make_enricher(
        tmp_path,
        epss={"CVE-2024-3400": 0.94},
        sightings={"CVE-2024-1111": ["seen", "exploited", "seen"]},
    )
    out = e.enrich(["cve-2024-3400", "CVE-2023-4966", "CVE-2024-1111", "CVE-2024-3400"])
    assert set(out) == {"CVE-2024-3400", "CVE-2023-4966", "CVE-2024-1111"}
    assert out["CVE-2024-3400"].kev and out["CVE-2024-3400"].epss == pytest.approx(0.94)
    assert out["CVE-2023-4966"].kev_ransomware
    assert out["CVE-2024-1111"].sightings == {"seen": 2, "exploited": 1}
    assert (tmp_path / "kev.json").is_file()
    # KEV URL must not get a trailing slash
    kev_urls = [u for m, u, *_ in t.calls if "known_exploited" in u]
    assert kev_urls == [
        "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    ]
    # second call: KEV from memory, no new download
    e.enrich(["CVE-2024-3400"])
    assert len([u for m, u, *_ in t.calls if "known_exploited" in u]) == 1


def test_enricher_survives_source_failure(tmp_path):
    t = FakeTransport(
        {
            "GET known_exploited": Response(500, b"boom", {}),
            **{k: v for k, v in intel_routes(epss={"CVE-1": 0.5}).items() if "known" not in k},
        }
    )
    e = Enricher(cache_dir=tmp_path, transport=t)
    e.kev.http.retries = 0
    out = e.enrich(["CVE-1"])
    assert out["CVE-1"].epss == 0.5 and not out["CVE-1"].kev
    assert any(err.startswith("kev:") for err in out["CVE-1"].errors)


def test_enricher_respects_disabled_sources(tmp_path):
    t = FakeTransport({})
    e = Enricher(cache_dir=tmp_path, use_kev=False, use_epss=False, use_circl=False, transport=t)
    e.enrich(["CVE-2024-3400"])
    assert t.calls == []  # nothing leaves the box


# ---------------------------------------------------------------------- receiver
PAYLOAD = {
    "organization": "polisen-poc",
    "project": "sysadm",
    "notification": "webhook",
    "period": {"start": "2026-11-19T05:00:00Z", "end": "2026-11-19T06:00:00Z"},
    "changes": [
        {
            "cve": {"cve_id": "CVE-2024-3400", "description": "PAN-OS cmd injection", "cvss31": 10.0},
            "events": [{"type": "metrics", "details": {}}],
        },
        {
            "cve": {"cve_id": "CVE-2026-0001", "description": "minor", "cvss31": 4.3},
            "events": [{"type": "new_cve", "details": {}}],
        },
        {
            "cve": {"cve_id": "CVE-2026-0002", "description": "refs only", "cvss31": 9.1},
            "events": [{"type": "references", "details": {}}],
        },
        {
            "cve": {"cve_id": "CVE-2026-0003", "description": "no score yet", "cvss31": None},
            "events": [{"type": "new_cve", "details": {}}],
        },
    ],
}


def test_process_payload_routes_ranks_and_filters(inv, tmp_path):
    e, _ = make_enricher(tmp_path, epss={"CVE-2024-3400": 0.94, "CVE-2026-0001": 0.0004})
    alerts = process_payload(PAYLOAD, inv, e)
    ids = [a.cve for a in alerts]
    assert "CVE-2026-0002" not in ids  # references-only change ignored
    assert ids[0] == "CVE-2024-3400" and alerts[0].tier == 1 and alerts[0].team == "sysadm"
    by = {a.cve: a for a in alerts}
    assert by["CVE-2026-0001"].tier == 4
    assert by["CVE-2026-0003"].cvss31 is None and by["CVE-2026-0003"].tier == 4


def test_unknown_project_is_unrouted(inv, tmp_path):
    e, _ = make_enricher(tmp_path)
    alerts = process_payload({**PAYLOAD, "project": "nope"}, inv, e)
    assert {a.team for a in alerts} == {"unrouted"}


def test_format_chat_only_hot_tiers(inv, tmp_path):
    e, _ = make_enricher(tmp_path, epss={"CVE-2024-3400": 0.94})
    msg = format_chat(process_payload(PAYLOAD, inv, e), inv, "http://opencve.local")
    assert msg is not None and msg.startswith("@sysadm")
    assert "CVE-2024-3400" in msg and "http://opencve.local/cve/CVE-2024-3400" in msg
    assert "CVE-2026-0001" not in msg and "lower-tier" in msg


def test_http_receiver_auth_and_pipeline(inv, tmp_path):
    from http.server import ThreadingHTTPServer

    e, _ = make_enricher(tmp_path, epss={"CVE-2024-3400": 0.94})
    sent: list[str] = []
    pipe = Pipeline(inv, e, tmp_path / "alerts.jsonl", chat_sender=sent.append)
    token = "x" * 32
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(pipe, token))
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    url = f"http://127.0.0.1:{httpd.server_address[1]}"
    try:

        def post(tok, body):
            req = urllib.request.Request(
                f"{url}/opencve",
                data=body,
                method="POST",
                headers={"X-Vulnflow-Token": tok, "Content-Type": "application/json"},
            )
            try:
                with urllib.request.urlopen(req) as r:
                    return r.status
            except urllib.error.HTTPError as err:
                return err.code

        assert post("wrong", b"{}") == 401
        assert post(token, b"not json") == 400
        assert post(token, json.dumps(PAYLOAD).encode()) == 202
        for _ in range(50):
            if sent:
                break
            time.sleep(0.05)
        pipe.q.join()
        lines = (tmp_path / "alerts.jsonl").read_text().splitlines()
        assert len(lines) == 3 and json.loads(lines[0])["cve"] == "CVE-2024-3400"
        assert sent and "CVE-2024-3400" in sent[0]
        with urllib.request.urlopen(f"{url}/healthz") as r:
            assert json.loads(r.read())["status"] == "ok"
    finally:
        httpd.shutdown()


def test_handler_rejects_weak_token(inv, tmp_path):
    e, _ = make_enricher(tmp_path)
    pipe = Pipeline(inv, e, tmp_path / "a.jsonl")
    with pytest.raises(SystemExit):
        make_handler(pipe, "short")


# --------------------------------------------------------------------- API clients
def test_opencve_put_subscriptions_payload():
    t = FakeTransport({"PUT /subscriptions": {}})
    oc = OpenCVE("http://oc", "polisen poc", "opc_org.a.b", transport=t)
    oc.put_subscriptions("sysadm", ["fortinet"], {"apache": ["http_server"]})
    _, url, h, body = t.calls[0]
    assert url == ("http://oc/api/v2/organizations/polisen%20poc/projects/sysadm/subscriptions")
    assert h["Authorization"] == "Bearer opc_org.a.b"
    assert json.loads(body) == {"vendors": ["fortinet"], "products": {"apache": ["http_server"]}}


def test_dtrack_upload_and_paging():
    pages = {
        1: [
            {
                "uuid": f"u{i}",
                "name": f"p{i}",
                "version": "1",
                "active": True,
                "tags": [{"name": "team-dev"}],
            }
            for i in range(100)
        ],
        2: [{"uuid": "u100", "name": "p100", "version": "1", "active": False}],
    }

    def tag_route(m, url, h, b):
        page = int(url.split("pageNumber=")[1])
        return Response(200, json.dumps(pages[page]).encode(), {"X-Total-Count": "101"})

    t = FakeTransport(
        {"GET /api/v1/project/tag/team-dev": tag_route, "PUT /api/v1/bom": {"token": "tok-1"}}
    )
    dt = DependencyTrack("http://dt:8180", "odt_key", transport=t)
    projs = dt.projects_by_tag("team-dev")
    assert len(projs) == 101 and projs[-1].active is False
    assert dt.upload_bom("app", "1.0", b'{"bomFormat":"CycloneDX"}', ["team-dev"]) == "tok-1"
    body = json.loads(t.calls[-1][3])
    assert body["autoCreate"] is True and body["projectTags"] == [{"name": "team-dev"}]
    assert base64.b64decode(body["bom"]) == b'{"bomFormat":"CycloneDX"}'
    assert t.calls[-1][2]["X-Api-Key"] == "odt_key"


def test_dojo_reimport_multipart_and_product_type():
    t = FakeTransport(
        {
            "GET /product_types/": {"results": []},
            "POST /product_types/": {"id": 7},
            "POST /reimport-scan/": {"statistics": {"after": {"total": {"active": 3}}}},
        }
    )
    dd = DefectDojo("http://dd:8280", "k", transport=t)
    assert dd.ensure_product_type("Sysadmin") == 7
    dd.reimport(
        scan_type=DefectDojo.FPF_SCAN_TYPE,
        report=b"{}",
        filename="x.json",
        product_name="app",
        product_type="Sysadmin",
        engagement="Dependency-Track",
        tags=["team-sysadm", "source-dtrack"],
    )
    _, url, h, body = t.calls[-1]
    assert url == "http://dd:8280/api/v2/reimport-scan/"
    assert h["Authorization"] == "Token k" and h["Content-Type"].startswith("multipart/form-data")
    text = body.decode()
    assert "Dependency Track Finding Packaging Format (FPF) Export" in text
    assert text.count('name="tags"') == 2 and 'name="auto_create_context"' in text


# ---------------------------------------------------------------------------- jobs
def test_sync_inventory_dry_run_and_missing_project(inv):
    t = FakeTransport({"GET /projects/sysadm": {"name": "sysadm"}, "GET /api/v1/project/tag/": []})
    rep = sync_inventory(
        inv,
        opencve=OpenCVE("http://oc", "org", "t", transport=t),
        dtrack=DependencyTrack("http://dt", "k", transport=t),
        dojo=None,
        dry_run=True,
    )
    assert any("[dry-run] OpenCVE 'sysadm'" in d for d in rep.done)
    assert any("project 'dev' missing" in w for w in rep.warnings)
    assert not [c for c in t.calls if c[0] != "GET"]  # dry run writes nothing


def test_dt_to_dojo_routes_by_tag(inv):
    def tag_route(m, url, h, b):
        tag = url.split("/tag/")[1].split("?")[0]
        rows = [
            {
                "uuid": f"{tag}-1",
                "name": f"{tag}-app",
                "version": "2",
                "active": True,
                "tags": [
                    {"name": tag},
                    {"name": "host-h1"},
                    {"name": "kind-container"},
                    {"name": "x-y"},
                ],
            },
            # retired by prune: not exported, counted in one line instead of a WARN each
            {"uuid": f"{tag}-0", "name": f"{tag}-app", "version": "1", "active": False, "tags": []},
        ]
        return Response(200, json.dumps(rows).encode(), {"X-Total-Count": "2"})

    t = FakeTransport(
        {
            "GET /api/v1/project/tag/": tag_route,
            "GET /export": {"version": "1.2", "findings": []},
            "POST /reimport-scan/": {},
        }
    )
    rep = dt_to_dojo(
        inv, DependencyTrack("http://dt", "k", transport=t), DefectDojo("http://dd", "k", transport=t)
    )
    n = len(inv.teams)  # one active and one retired project per team tag
    assert not rep.errors and not rep.warnings and len(rep.done) == n + 1
    assert rep.done[-1] == f"{n} inactive project(s) skipped (retired versions)"
    posts = [c for c in t.calls if c[0] == "POST"]
    assert len(posts) == n
    sysadm = next(p for p in posts if b"team-sysadm-app" in p[3])
    assert b"Sysadmin" in sysadm[3]
    fields = _multipart_fields(sysadm[3])
    assert fields["tags"] == ["team-sysadm", "source-dtrack", "host-h1", "kind-container"]  # not x-y
    assert fields["version"] == ["2"] and fields["apply_tags_to_findings"] == ["true"]
    assert fields["test_title"] == ["Dependency-Track 2"]


def _multipart_fields(body: bytes) -> dict[str, list[str]]:
    """name -> values of the plain (non-file) fields of a multipart body."""
    import re

    out: dict[str, list[str]] = {}
    for name, value in re.findall(rb'name="([^"]+)"\r\n\r\n(.*?)\r\n--', body, re.S):
        out.setdefault(name.decode(), []).append(value.decode())
    return out


def test_opencve_paths_match_schema():
    t = FakeTransport(
        {"GET /projects/sysadm": {"name": "sysadm"}, "POST /organizations/org/projects": {}}
    )
    oc = OpenCVE("http://oc", "org", "t", transport=t)
    assert oc.project_exists("sysadm")
    oc.create_project("dev", "Utveckling")
    assert t.calls[0][1] == "http://oc/api/v2/organizations/org/projects/sysadm"
    assert t.calls[1][1] == "http://oc/api/v2/organizations/org/projects"
    with pytest.raises(ValueError):
        oc.set_status("dev", "CVE-1", "fixed")


def test_triage_writeback_never_overwrites_human_status(inv, tmp_path):
    trackers = {"CVE-2024-3400": None, "CVE-2023-4966": {"status": "risk_accepted"}}

    def get_cve(m, url, h, b):
        cid = url.rsplit("/", 1)[1]
        return Response(200, json.dumps({"cve_id": cid, "tracker": trackers.get(cid)}).encode(), {})

    t = FakeTransport({"GET /projects/sysadm/cves/": get_cve, "PATCH /projects/sysadm/cves/": {}})
    e, _ = make_enricher(tmp_path)
    pipe = Pipeline(
        inv,
        e,
        tmp_path / "a.jsonl",
        opencve=OpenCVE("http://oc", "org", "t", transport=t),
        triage_max_tier=2,
    )
    payload = {
        "project": "sysadm",
        "changes": [
            {"cve": {"cve_id": c, "cvss31": 9.8}, "events": [{"type": "new_cve"}]}
            for c in ("CVE-2024-3400", "CVE-2023-4966")
        ],
    }
    pipe.handle(payload)
    patches = [c for c in t.calls if c[0] == "PATCH"]
    assert len(patches) == 1 and patches[0][1].endswith("/CVE-2024-3400")
    assert json.loads(patches[0][3]) == {"status": "to_evaluate"}


# ------------------------------------------------------------ Dependency-Track bootstrap
# Dummy credentials for the fake servers, random per run (no literals for secret scanners)
TEST_PW = secrets.token_hex(8)
WRONG_PW = TEST_PW + "-wrong"


class FakeDT:
    """Stateful fake of the DT 5.x v1 auth/team endpoints used by bootstrap."""

    def __init__(self, password: str = "admin", force_change: bool = True):
        from urllib.parse import parse_qs

        self.parse_qs = parse_qs
        self.password, self.force = password, force_change
        self.teams: dict[str, dict] = {}
        self.keys: dict[str, str] = {}
        self.issued = 0  # key counter (keys of deleted teams must not come back)
        self.calls: list[tuple[str, str]] = []
        # DT 5.2.2 stores the factory default on startup; None = nothing stored (404)
        self.osv: dict | None = {
            "enabled": False,
            "aliasSyncEnabled": False,
            "incrementalMirroringEnabled": True,
            "dataUrl": "https://storage.googleapis.com/osv-vulnerabilities",
            "ecosystems": ["Go", "Maven", "npm", "NuGet", "PyPI"],
        }

    def form(self, body):
        return {k: v[0] for k, v in self.parse_qs(body.decode()).items()}

    def __call__(self, method, url, headers, body, timeout):
        path = url.split("://", 1)[1].split("/", 1)[1].split("?")[0]
        self.calls.append((method, path))

        def ok(obj, status=200):
            return Response(status, json.dumps(obj).encode(), {})

        if path == "api/version":
            return ok({"version": "5.2.1"})
        if path in ("api/v1/user/login", "api/v1/user/forceChangePassword"):
            # JAX-RS @Produces(TEXT_PLAIN): an Accept that excludes text/plain gets 406
            accept = headers.get("Accept", "*/*")
            if not any(
                a.strip().split(";")[0] in ("text/plain", "text/*", "*/*") for a in accept.split(",")
            ):
                return Response(406, b"", {})
        if path == "api/v1/user/login":
            f = self.form(body)
            if f["password"] != self.password:
                return Response(401, b"INVALID_CREDENTIALS", {})
            if self.force:
                return Response(401, b"FORCE_PASSWORD_CHANGE", {})
            return Response(200, b"jwt-token", {})
        if path == "api/v1/user/forceChangePassword":
            f = self.form(body)
            if f["password"] != self.password or not self.force:
                return Response(401, b"INVALID_CREDENTIALS", {})
            self.password, self.force = f["newPassword"], False
            return Response(200, b"", {})
        if path == "api/v1/team/self":
            key_team = self.keys.get(headers.get("X-Api-Key", ""))
            return ok(self.teams[key_team]) if key_team else Response(401, b"", {})
        assert headers.get("Authorization") == "Bearer jwt-token", path
        if path == "api/v1/team" and method == "GET":
            return ok(list(self.teams.values()))
        if path == "api/v1/team" and method == "DELETE":
            uuid = json.loads(body)["uuid"]
            name = next((n for n, t in self.teams.items() if t["uuid"] == uuid), None)
            if name is None:
                return Response(404, b"", {})
            del self.teams[name]
            self.keys = {k: v for k, v in self.keys.items() if v != name}
            return Response(204, b"", {})
        if path == "api/v1/team" and method == "PUT":
            name = json.loads(body)["name"]
            self.teams[name] = {"uuid": f"uuid-{name}", "name": name, "permissions": []}
            return ok(self.teams[name], 201)
        if path.startswith("api/v1/permission/"):
            _, _, _, perm, _, uuid = path.split("/")
            team = next(t for t in self.teams.values() if t["uuid"] == uuid)
            if {"name": perm} in team["permissions"]:
                return Response(304, b"", {})
            team["permissions"].append({"name": perm})
            return ok(team)
        if path.endswith("/key") and method == "PUT":
            uuid = path.split("/")[3]
            name = next(n for n, t in self.teams.items() if t["uuid"] == uuid)
            self.issued += 1
            key = f"odt_{self.issued:08d}_secret"
            self.keys[key] = name
            return ok({"key": key, "publicId": key[4:12]}, 201)
        if path == "api/v2/extension-points/vuln-data-source/extensions/osv/config":
            if method == "GET":
                return ok({"config": self.osv}) if self.osv is not None else Response(404, b"", {})
            if method == "PUT":
                # 5.2.2 answers this PUT only as application/problem+json (seen live): an
                # Accept of just application/json gets 406 before anything is stored
                accept = headers.get("Accept", "*/*")
                if not any(a in accept for a in ("application/problem+json", "*/*")):
                    return Response(406, b'{"title":"Not Acceptable","status":406}', {})
                cfg = json.loads(body)["config"]
                if cfg == self.osv:
                    return Response(304, b"", {})
                self.osv = cfg
                return Response(204, b"", {})
        return Response(404, b"", {})


def test_dt_bootstrap_fresh_install_then_idempotent():
    from vulnflow.bootstrap import DT_TEAM_PERMISSIONS, bootstrap_dtrack

    dt = FakeDT()
    r1 = bootstrap_dtrack("http://dt:8180", admin_password=TEST_PW, transport=dt)
    assert r1.changed_admin_password and r1.created_team and r1.api_key.startswith("odt_")
    assert dt.password == TEST_PW
    assert {p["name"] for p in dt.teams["vulnflow"]["permissions"]} == set(DT_TEAM_PERMISSIONS)
    assert r1.osv.startswith("updated")
    assert dt.osv is not None and dt.osv["enabled"] is True
    assert dt.osv["ecosystems"] == ["Go", "Maven", "npm", "NuGet", "PyPI", "Debian"]
    assert dt.osv["dataUrl"] == "https://storage.googleapis.com/osv-vulnerabilities"

    r2 = bootstrap_dtrack(
        "http://dt:8180", admin_password=TEST_PW, existing_key=r1.api_key, transport=dt
    )
    assert not (r2.changed_admin_password or r2.created_team) and r2.api_key == ""
    assert len(dt.keys) == 1  # no new key minted when the old one still works
    assert r2.osv == "unchanged"
    assert ("PUT", "api/v2/extension-points/vuln-data-source/extensions/osv/config") not in (
        dt.calls[dt.calls.index(("GET", "api/version"), 1) :]
    )


def test_dt_enable_osv_keeps_operator_choices_and_never_raises():
    from vulnflow.bootstrap import dt_enable_osv
    from vulnflow.net import Http

    dt = FakeDT(password=TEST_PW, force_change=False)
    http = Http("http://dt", headers={"Authorization": "Bearer jwt-token"}, transport=dt)
    dt.osv = {"enabled": True, "ecosystems": ["Debian", "Alpine"], "dataUrl": "https://mirror/osv"}
    assert dt_enable_osv(http, ["Debian", "PyPI"]).startswith("updated")
    assert dt.osv == {
        "enabled": True,
        "ecosystems": ["Debian", "Alpine", "PyPI"],  # added, nothing removed
        "dataUrl": "https://mirror/osv",  # operator's mirror kept
    }
    assert dt_enable_osv(http, []) == "skipped"
    dt.osv = None  # nothing stored yet: start from DT's defaults
    assert dt_enable_osv(http, ["Debian"]).startswith("updated")
    assert dt.osv is not None and dt.osv["ecosystems"][-1] == "Debian"

    def broken(method, url, headers, body, timeout):
        return Response(403, b"forbidden", {})

    denied = Http("http://dt", transport=broken, retries=0)
    assert dt_enable_osv(denied, ["Debian"]).startswith("failed: GET OSV config HTTP 403")


def test_dt_bootstrap_replaces_dead_key_and_reports_wrong_password():
    from vulnflow.bootstrap import BootstrapError, bootstrap_dtrack

    dt = FakeDT(password=TEST_PW, force_change=False)
    r = bootstrap_dtrack("http://dt", admin_password=TEST_PW, existing_key="odt_stale", transport=dt)
    assert r.api_key and r.api_key != "odt_stale"
    with pytest.raises(BootstrapError, match="DT_ADMIN_PASSWORD"):
        bootstrap_dtrack("http://dt", admin_password=WRONG_PW, transport=dt)


def test_set_env_values_keeps_layout(tmp_path):
    from vulnflow.bootstrap import set_env_values

    p = tmp_path / ".env"
    p.write_text("# c\nDT_API_KEY=\nDT_URL=http://x\n# DT_API_KEY=commented\n")
    set_env_values(p, {"DT_API_KEY": "odt_k", "DT_ADMIN_PASSWORD": "pw"})
    assert p.read_text() == (
        "# c\nDT_API_KEY=odt_k\nDT_URL=http://x\n# DT_API_KEY=commented\nDT_ADMIN_PASSWORD=pw\n"
    )
    assert p.stat().st_mode & 0o777 == 0o600
    with pytest.raises(ValueError):
        set_env_values(p, {"X": "a\nEVIL=1"})


def test_dd_bootstrap_waits_for_admin_then_returns_token():
    from vulnflow.bootstrap import bootstrap_defectdojo

    attempts = {"n": 0}

    def token_route(m, url, h, b):
        attempts["n"] += 1
        body = json.loads(b)
        if attempts["n"] < 3:  # initializer hasn't created the admin yet
            return Response(400, b'{"non_field_errors":["Unable to log in"]}', {})
        assert body == {"username": "admin", "password": "pw"}
        return Response(200, b'{"token": "dd-tok"}', {})

    def types_route(m, url, h, b):
        ok = h.get("Authorization") == "Token dd-tok"
        return Response(200 if ok else 401, b'{"results": []}', {})

    t = FakeTransport(
        {
            "GET /login": Response(200, b"", {}),
            "POST /api/v2/api-token-auth/": token_route,
            "GET /api/v2/product_types/": types_route,
        }
    )
    key = bootstrap_defectdojo(
        "http://dd:8280",
        admin_user="admin",
        admin_password="pw",
        existing_key="stale",
        transport=t,
        interval=0,
    )
    assert key == "dd-tok" and attempts["n"] == 3
    assert (
        bootstrap_defectdojo(
            "http://dd:8280",
            admin_user="admin",
            admin_password="pw",
            existing_key="dd-tok",
            transport=t,
            interval=0,
        )
        == ""
    )


def test_dd_bootstrap_gives_up_with_hint():
    from vulnflow.bootstrap import BootstrapError, bootstrap_defectdojo

    t = FakeTransport(
        {"GET /login": Response(200, b"", {}), "POST /api/v2/api-token-auth/": Response(400, b"{}", {})}
    )
    with pytest.raises(BootstrapError, match="DD_ADMIN_PASSWORD"):
        bootstrap_defectdojo(
            "http://dd", admin_user="admin", admin_password="x", transport=t, wait_timeout=0, interval=0
        )


def test_opencve_webhook_input_is_a_python_assignment(inv):
    from vulnflow.__main__ import opencve_webhook_input

    token = secrets.token_hex(16)
    line = opencve_webhook_input(inv, "http://vulnflow-receiver:8380/opencve", token, "org")
    assert line.startswith("VF = ") and "\n" not in line
    ns: dict[str, Any] = {}
    exec(line, ns)  # noqa: S102 - our own line, run as manage.py shell would
    vf = ns["VF"]
    assert vf["org"] == "org" and vf["name"] == "vulnflow"
    assert vf["projects"] == sorted({t.opencve_project for t in inv.teams.values()})
    assert vf["url"] == "http://vulnflow-receiver:8380/opencve"
    assert vf["headers"] == {"X-Vulnflow-Token": token}


def _run_bootstrap_webhooks(monkeypatch, vf, store):
    """Execute stacks/opencve/bootstrap_webhooks.py against minimal fake Django models."""
    import contextlib
    import sys
    import types
    import uuid

    class Obj:
        def __init__(self, **kw):
            self.id = uuid.uuid4()
            self.__dict__.update(kw)

        def save(self):
            store["saved"].append(self)

    class Manager:
        def __init__(self, kind):
            self.kind = kind

        def _match(self, kw):
            return [o for o in store[self.kind] if all(getattr(o, k) == v for k, v in kw.items())]

        def get(self, **kw):
            (o,) = self._match(kw)
            return o

        def filter(self, **kw):
            found = self._match(kw)
            return types.SimpleNamespace(first=lambda: found[0] if found else None)

        def get_or_create(self, defaults=None, **kw):
            found = self._match(kw)
            if found:
                return found[0], False
            o = Obj(**kw, **(defaults or {}))
            store[self.kind].append(o)
            return o, True

    def model(kind, **attrs):
        return type(kind, (), {"objects": Manager(kind), **attrs})

    db = types.ModuleType("django.db")
    db.transaction = types.SimpleNamespace(atomic=contextlib.nullcontext)  # type: ignore[attr-defined]
    orgs = types.ModuleType("organizations.models")
    orgs.Organization = model("org")  # type: ignore[attr-defined]
    projects = types.ModuleType("projects.models")
    projects.Project = model("project")  # type: ignore[attr-defined]
    projects.Notification = model("notification")  # type: ignore[attr-defined]
    projects.Automation = model("automation", TRIGGER_ALERT="alert")  # type: ignore[attr-defined]
    for name, mod in {
        "django": types.ModuleType("django"),
        "django.db": db,
        "organizations": types.ModuleType("organizations"),
        "organizations.models": orgs,
        "projects": types.ModuleType("projects"),
        "projects.models": projects,
    }.items():
        monkeypatch.setitem(sys.modules, name, mod)

    import io
    from contextlib import redirect_stdout

    script = (ROOT / "stacks" / "opencve" / "bootstrap_webhooks.py").read_text()
    out = io.StringIO()
    with redirect_stdout(out):
        exec(compile(script, "bootstrap_webhooks.py", "exec"), {"VF": vf})  # noqa: S102 - our own script
    return out.getvalue().split()


def test_opencve_bootstrap_webhooks_script_creates_then_updates(monkeypatch):
    import types

    org = types.SimpleNamespace(name="org")
    dev = types.SimpleNamespace(organization=org, name="dev")
    store: dict[str, list] = {
        "org": [org],
        "project": [dev],
        "notification": [],
        "automation": [],
        "saved": [],
    }
    vf = {
        "org": "org",
        "projects": ["dev", "gone"],
        "name": "vulnflow",
        "url": "http://r:8380/opencve",
        "headers": {"X-Vulnflow-Token": "a"},
    }

    out = _run_bootstrap_webhooks(monkeypatch, vf, store)
    assert out == ["WEBHOOK", "dev", "created", "MISSING", "gone"]
    (n,), (a,) = store["notification"], store["automation"]
    assert (n.project, n.name, n.type, n.is_enabled) == (dev, "vulnflow", "webhook", True)
    assert n.configuration == {
        "extras": {"url": "http://r:8380/opencve", "headers": {"X-Vulnflow-Token": "a"}}
    }
    assert (a.project, a.name, a.trigger_type, a.is_enabled) == (dev, "vulnflow", "alert", True)
    assert a.configuration["conditions"] == {"operator": "AND", "children": []}
    assert a.configuration["actions"] == [{"type": "send_notification", "value": str(n.id)}]
    assert "cve_enters_project" in a.configuration["triggers"]
    assert len(a.configuration["triggers"]) == 12

    # Rerun with a rotated token: same objects, updated in place
    vf["headers"] = {"X-Vulnflow-Token": "b"}
    out = _run_bootstrap_webhooks(monkeypatch, vf, store)
    assert out == ["WEBHOOK", "dev", "updated", "MISSING", "gone"]
    assert len(store["notification"]) == 1 and len(store["automation"]) == 1
    assert store["notification"][0].configuration["extras"]["headers"] == {"X-Vulnflow-Token": "b"}
    assert store["automation"][0].configuration["actions"][0]["value"] == str(n.id)


def test_env_set_cli_reads_stdin(tmp_path, monkeypatch):
    import io

    from vulnflow.__main__ import main

    env_file = tmp_path / ".env"
    env_file.write_text("A=1\nOPENCVE_TOKEN=\n")
    monkeypatch.setattr("sys.stdin", io.StringIO("OPENCVE_TOKEN=opc_org.a.b=c\n"))
    assert main(["--env-file", str(env_file), "env-set"]) == 0
    assert env_file.read_text() == "A=1\nOPENCVE_TOKEN=opc_org.a.b=c\n"


# ------------------------------------------------------- own machines (push agents)
TEAMS_TOML = """
[teams.sysadm]
dtrack_tag = "team-sysadm"
[teams.users]
dtrack_tag = "team-users"
[teams.dev]
dtrack_tag = "team-dev"
"""

MACHINES_TOML = """
[groups.servers]
team = "sysadm"
scans = ["system", "containers"]
hosts = ["web1", "db1"]

[groups.laptops]
team = "users"
kind = "macos"
hosts = ["mbp"]

[hosts.db1]
scans = ["system"]
version = "pinned-1"

[hosts.lone]
team = "dev"
kind = "linux"

[code.myapp]
host = "web1"
path = "/srv/myapp"

[cpe_map]
ripgrep = "burntsushi:ripgrep"
"""


def load_estate(tmp_path, text: str = MACHINES_TOML):
    inv_file = tmp_path / "inv.toml"
    inv_file.write_text(TEAMS_TOML, encoding="utf-8")
    inv = load_inventory(inv_file)
    f = tmp_path / "machines.toml"
    f.write_text(text, encoding="utf-8")
    return inv, load_machines(f, inv.teams)


def test_machines_subscriptions_merge_into_teams(tmp_path):
    from vulnflow.config import add_subscriptions

    text = (
        MACHINES_TOML
        + """
[subscriptions.sysadm]
vendors = ["nginx"]
[subscriptions.sysadm.products]
openbsd = ["openssh"]
linux = ["linux_kernel"]
"""
    )
    inv_file = tmp_path / "inv.toml"
    inv_file.write_text(TEAMS_TOML + '[teams.sysadm.opencve.products]\nlinux = ["linux_kernel"]\n')
    inv = load_inventory(inv_file)
    (tmp_path / "m.toml").write_text(text, encoding="utf-8")
    add_subscriptions(inv, load_machines(tmp_path / "m.toml", inv.teams))
    assert inv.teams["sysadm"].vendors == ["nginx"]
    assert inv.teams["sysadm"].products == {"linux": ["linux_kernel"], "openbsd": ["openssh"]}
    assert inv.teams["dev"].vendors == []

    for bad in ('[subscriptions.nope]\nvendors = ["x"]', '[subscriptions.dev]\nvendors = ["Bad Name"]'):
        (tmp_path / "m.toml").write_text(MACHINES_TOML + bad, encoding="utf-8")
        with pytest.raises(SystemExit):
            load_machines(tmp_path / "m.toml", inv.teams)


def test_patched_findings_lists_only_recorded_fixes(inv):
    from vulnflow.patches import patched_findings

    def finding(vid, src="GITHUB", suppressed=False):
        return {
            "component": {"name": "requests", "version": "2.0.0"},
            "vulnerability": {"source": src, "vulnId": vid, "severity": "HIGH"},
            "analysis": {"isSuppressed": suppressed},
        }

    vulns = {
        "GHSA-fixed": {"patchedVersions": "2.31.0"},
        "CVE-2024-1": {"patchedVersions": ""},
        "GHSA-supp": {"patchedVersions": "9.9"},
    }

    def route(m, url, h, b):
        if "/project/tag/team-dev" in url:
            return Response(
                200, json.dumps([{"uuid": "p1", "name": "app", "active": True}]).encode(), {}
            )
        if "/project/tag/" in url:
            return Response(200, b"[]", {})
        if "/finding/project/p1" in url:
            body = [
                finding("GHSA-fixed"),
                finding("CVE-2024-1", "NVD"),
                finding("GHSA-supp", suppressed=True),
            ]
            return Response(200, json.dumps(body).encode(), {})
        vid = url.split("/vuln/")[1]
        return Response(200, json.dumps(vulns[vid]).encode(), {})

    t = FakeTransport({"GET /api/v1/": route})
    dt = DependencyTrack("http://dt", "k", transport=t)
    rows, unknown, _, _, _, errors = patched_findings(inv, dt)
    assert errors == []
    assert [(r.team, r.project, r.vuln_id, r.patched) for r in rows] == [
        ("dev", "app", "GHSA-fixed", "2.31.0")
    ]
    assert unknown == 1  # the NVD one; the suppressed finding is skipped entirely
    urls = [c[1] for c in t.calls]
    assert "http://dt/api/v1/finding/project/p1?pageSize=100&pageNumber=1" in urls
    assert "http://dt/api/v1/vulnerability/source/GITHUB/vuln/GHSA-fixed" in urls
    assert not any("GHSA-supp" in u for u in urls)


def test_patched_findings_osv_fallback_is_opt_in(inv):
    from vulnflow.clients import OSV
    from vulnflow.patches import patched_findings

    purl = "pkg:pypi/requests@2.0.0?distro=x"
    finding = {
        "component": {"name": "requests", "version": "2.0.0", "purl": purl},
        "vulnerability": {"source": "NVD", "vulnId": "CVE-2024-1", "severity": "HIGH"},
        "analysis": {},
    }
    osv_vulns = [
        {"id": "GHSA-other", "aliases": ["CVE-2099-9"], "affected": []},
        {
            "id": "GHSA-xxxx",
            "aliases": ["CVE-2024-1"],
            "affected": [
                {
                    "package": {"name": "other", "ecosystem": "PyPI"},
                    "ranges": [{"events": [{"introduced": "0"}, {"fixed": "9.9"}]}],
                },
                {
                    "package": {"name": "requests", "ecosystem": "PyPI"},
                    "ranges": [{"events": [{"introduced": "0"}, {"fixed": "2.31.0"}]}],
                },
            ],
        },
    ]

    def dt_route(m, url, h, b):
        if "/project/tag/team-dev" in url:
            proj = [{"uuid": "p1", "name": "app", "active": True}]
            return Response(200, json.dumps(proj).encode(), {})
        if "/project/tag/" in url:
            return Response(200, b"[]", {})
        if "/finding/project/p1" in url:
            return Response(200, json.dumps([finding]).encode(), {})
        return Response(200, json.dumps({"patchedVersions": ""}).encode(), {})

    dt = DependencyTrack("http://dt", "k", transport=FakeTransport({"GET /api/v1/": dt_route}))

    rows, unknown, _, _, _, _ = patched_findings(inv, dt)  # default: nothing leaves the machine
    assert rows == [] and unknown == 1

    osv_t = FakeTransport({"POST /v1/query": {"vulns": osv_vulns}})
    rows, unknown, _, _, _, errors = patched_findings(
        inv, dt, osv=OSV("https://osv.test", transport=osv_t)
    )
    assert errors == [] and unknown == 0
    assert [(r.vuln_id, r.patched, r.via) for r in rows] == [("CVE-2024-1", "2.31.0", "osv")]
    method, url, _, body = osv_t.calls[0]
    assert (method, url) == ("POST", "https://osv.test/v1/query")
    assert json.loads(body) == {"package": {"purl": "pkg:pypi/requests@2.0.0"}}  # qualifiers dropped


def test_debian_tracker_matches_on_cve_source_package_and_release(inv, tmp_path):
    from vulnflow.debian import DebianTracker, debian_findings, parse_deb_purl

    assert parse_deb_purl("pkg:pypi/requests@1") is None
    assert parse_deb_purl("pkg:deb/ubuntu/curl@1") is None
    assert parse_deb_purl(
        "pkg:deb/debian/libssl3t64@3.5.4?arch=amd64&upstream=openssl%403.5.4&distro=debian-13"
    ) == ({"libssl3t64", "openssl"}, "trixie")
    assert parse_deb_purl("pkg:deb/debian/acl@2.3") == ({"acl"}, "")

    def finding(name, purl, cve):
        return {
            "component": {"name": name, "version": "1", "purl": purl, "uuid": f"c-{name}"},
            "vulnerability": {"source": "NVD", "vulnId": cve, "severity": "HIGH", "uuid": f"v-{cve}"},
            "analysis": {},
        }

    ssl = "pkg:deb/debian/libssl3t64@3.5.4?upstream=openssl%403.5.4&distro=debian-13"
    findings = [
        finding("libssl3t64", ssl, "CVE-2024-1"),  # tracker: unimportant
        finding("libssl3t64", ssl, "CVE-2024-2"),  # tracker: open/high
        finding("libssl3t64", ssl, "CVE-2024-3"),  # not in tracker
        finding("libssl3t64", ssl, "DEBIAN-CVE-2024-2"),  # DT's OSV id for the same CVE
        finding("acl", "pkg:deb/debian/acl@2.3", "CVE-2024-1"),  # no distro: release unknown
        finding("requests", "pkg:pypi/requests@2", "CVE-2024-1"),  # not Debian: ignored
    ]
    tracker_doc = {
        "openssl": {
            "CVE-2024-1": {"releases": {"trixie": {"status": "open", "urgency": "unimportant"}}},
            "CVE-2024-2": {
                "releases": {
                    "trixie": {"status": "resolved", "urgency": "high", "fixed_version": "3.5.5-1"},
                    "bookworm": {"status": "open", "urgency": "low"},
                }
            },
        }
    }

    def dt_route(m, url, h, b):
        if "/project/tag/team-dev" in url:
            proj = [{"uuid": "p1", "name": "app", "active": True}]
            return Response(200, json.dumps(proj).encode(), {})
        if "/project/tag/" in url:
            return Response(200, b"[]", {})
        return Response(200, json.dumps(findings).encode(), {})

    dt = DependencyTrack("http://dt", "k", transport=FakeTransport({"GET /api/v1/": dt_route}))
    tt = FakeTransport({"GET /tracker/data/json": tracker_doc})
    tracker = DebianTracker(tmp_path, transport=tt)

    rows, unmatched, errors = debian_findings(inv, dt, tracker)
    assert errors == []
    assert [(r.vuln_id, r.urgency, r.status, r.fixed, r.package, r.release) for r in rows] == [
        ("CVE-2024-2", "high", "resolved", "3.5.5-1", "openssl", "trixie"),
        ("DEBIAN-CVE-2024-2", "high", "resolved", "3.5.5-1", "openssl", "trixie"),
        ("CVE-2024-1", "unimportant", "open", "", "openssl", "trixie"),
    ]
    assert (rows[0].project_uuid, rows[0].component_uuid, rows[0].vuln_uuid) == (
        "p1",
        "c-libssl3t64",
        "v-CVE-2024-2",
    )
    assert unmatched == 2  # CVE-2024-3 (not listed) and the acl finding (release unknown)
    assert [c[1] for c in tt.calls] == ["https://security-tracker.debian.org/tracker/data/json"]

    only, _, _ = debian_findings(inv, dt, tracker, ignorable_only=True)
    assert [r.vuln_id for r in only] == ["CVE-2024-1"]
    forced, _, _ = debian_findings(inv, dt, tracker, release="bookworm")
    assert [(r.vuln_id, r.urgency) for r in forced] == [
        ("CVE-2024-2", "low"),
        ("DEBIAN-CVE-2024-2", "low"),
    ]
    assert len(tt.calls) == 1  # one download, then the in-memory index


def test_ignore_writes_reviewed_findings_to_dt_once(tmp_path):
    from datetime import date

    from vulnflow.net import Http
    from vulnflow.triage import ReviewFileError, apply_ignores, load_review

    row = {
        "team": "dev",
        "project": "app",
        "project_uuid": "P1",
        "component": "libssl3t64",
        "version": "3.5.4",
        "component_uuid": "C1",
        "vuln_id": "CVE-2024-1",
        "vuln_uuid": "V1",
        "urgency": "unimportant",
        "status": "open",
        "release": "trixie",
        "package": "openssl",
    }
    other = {**row, "component_uuid": "C2", "component": "libcrypto3", "vuln_uuid": "V2"}
    f = tmp_path / "review.json"
    f.write_text(json.dumps([row, row, other]), encoding="utf-8")  # row twice: deduplicated

    items = load_review(f, today=date(2026, 11, 23))
    assert [(i.component_uuid, i.vuln_uuid) for i in items] == [("C1", "V1"), ("C2", "V2")]
    assert items[0].comment == (
        "Debian tracker: unimportant (open) in trixie, source package openssl; "
        "reviewed 2026-11-23 via vulnflow"
    )

    state = {"C2": {"analysisState": "NOT_AFFECTED", "isSuppressed": True}}  # already done

    def get_route(m, url, h, b):
        for comp, cur in state.items():
            if f"component={comp}&" in url:
                return Response(200, json.dumps(cur).encode(), {})
        return Response(404, b'{"detail":"none"}', {})

    t = FakeTransport({"GET /api/v1/analysis": get_route, "PUT /api/v1/analysis": {}})
    http = Http("http://dt", transport=t)
    written, skipped, _, errors = apply_ignores(http, items, "NOT_AFFECTED", "REQUIRES_ENVIRONMENT")
    assert errors == []
    assert [i.component_uuid for i in written] == ["C1"]
    assert [i.component_uuid for i in skipped] == ["C2"]
    puts = [c for c in t.calls if c[0] == "PUT"]
    assert len(puts) == 1 and puts[0][1] == "http://dt/api/v1/analysis"
    assert json.loads(puts[0][3]) == {
        "project": "P1",
        "component": "C1",
        "vulnerability": "V1",
        "analysisState": "NOT_AFFECTED",
        "comment": items[0].comment,
        "isSuppressed": True,
        "analysisJustification": "REQUIRES_ENVIRONMENT",
    }

    # a bad row rejects the whole file, nothing is half-applied
    f.write_text(json.dumps([row, {**row, "vuln_uuid": ""}]), encoding="utf-8")
    with pytest.raises(ReviewFileError, match=r"row 1.*vuln_uuid"):
        load_review(f)
    f.write_text('{"not": "a list"}', encoding="utf-8")
    with pytest.raises(ReviewFileError):
        load_review(f)


def test_ignore_overwrite_corrects_justification_of_a_suppressed_finding(tmp_path):
    from vulnflow.net import Http
    from vulnflow.triage import IgnoreItem, apply_ignores

    it = IgnoreItem("dev", "app", "P1", "stdlib", "go1.24.4", "C1", "CVE-2025-47906", "V1", "c")
    cur = {
        "analysisState": "NOT_AFFECTED",
        "analysisJustification": "CODE_NOT_REACHABLE",
        "isSuppressed": True,
    }

    def run(justification, overwrite):
        t = FakeTransport(
            {
                "GET /api/v1/analysis": lambda m, u, h, b: Response(200, json.dumps(cur).encode(), {}),
                "PUT /api/v1/analysis": {},
            }
        )
        ledger = tmp_path / "ledger.jsonl"
        res = apply_ignores(
            Http("http://dt", transport=t),
            [it],
            "NOT_AFFECTED",
            justification,
            overwrite=overwrite,
            ledger=ledger,
        )
        return res, [json.loads(c[3]) for c in t.calls if c[0] == "PUT"], ledger

    # without --overwrite a suppressed finding in that state counts as done, as before
    (written, skipped, _, errs), puts, _ = run("REQUIRES_ENVIRONMENT", False)
    assert (written, [i.vuln_id for i in skipped], puts, errs) == ([], ["CVE-2025-47906"], [], [])
    # the same justification is a no-op even with --overwrite (no duplicate comment)
    (written, skipped, _, _), puts, _ = run("CODE_NOT_REACHABLE", True)
    assert (written, len(skipped), puts) == ([], 1, [])
    # --overwrite with a different justification rewrites it and records the old one
    (written, skipped, _, errs), puts, ledger = run("REQUIRES_ENVIRONMENT", True)
    assert (len(written), skipped, errs) == (1, [], [])
    assert puts[0]["analysisJustification"] == "REQUIRES_ENVIRONMENT" and puts[0]["isSuppressed"] is True
    entry = json.loads(ledger.read_text(encoding="utf-8").splitlines()[-1])
    assert (entry["previous_state"], entry["previous_justification"]) == (
        "NOT_AFFECTED",
        "CODE_NOT_REACHABLE",
    )


def test_disputed_marker_must_lead_the_description():
    from vulnflow.disputed import disputed_marker

    assert disputed_marker("** DISPUTED ** A flaw in foo. Vendor says no.") == (
        "DISPUTED",
        "A flaw in foo. Vendor says no.",
    )
    assert disputed_marker("  ** reject ** DO NOT USE THIS CANDIDATE NUMBER.") == (
        "REJECT",
        "DO NOT USE THIS CANDIDATE NUMBER.",
    )
    assert disputed_marker("** REJECTED ** withdrawn") == ("REJECT", "withdrawn")
    assert disputed_marker("A flaw in foo. ** DISPUTED ** appears later") is None
    assert disputed_marker("") is None and disputed_marker("plain description") is None


def test_disputed_findings_and_ignore_roundtrip(inv, tmp_path):
    from datetime import date

    from vulnflow.disputed import disputed_findings
    from vulnflow.net import Http
    from vulnflow.triage import apply_ignores, load_review

    def finding(vid, desc, comp="foo"):
        return {
            "component": {"name": comp, "version": "1", "uuid": f"c-{comp}"},
            "vulnerability": {
                "source": "NVD",
                "vulnId": vid,
                "severity": "HIGH",
                "uuid": f"v-{vid}",
                "description": desc,
            },
            "analysis": {},
        }

    findings = [
        finding("CVE-2020-1", "** DISPUTED ** Foo allows X. " + "pad " * 80),
        finding("CVE-2020-2", "** REJECT ** DO NOT USE THIS CANDIDATE NUMBER."),
        finding("CVE-2020-3", "A normal vulnerability in foo."),
        finding("CVE-2020-4", ""),  # no description on the finding: looked up on the record
    ]

    def dt_route(m, url, h, b):
        if "/project/tag/team-dev" in url:
            proj = [{"uuid": "p1", "name": "app", "active": True}]
            return Response(200, json.dumps(proj).encode(), {})
        if "/project/tag/" in url:
            return Response(200, b"[]", {})
        if "/finding/project/p1" in url:
            return Response(200, json.dumps(findings).encode(), {})
        assert url.endswith("/vulnerability/source/NVD/vuln/CVE-2020-4")
        return Response(200, json.dumps({"description": "** DISPUTED ** from the record"}).encode(), {})

    dt = DependencyTrack("http://dt", "k", transport=FakeTransport({"GET /api/v1/": dt_route}))
    res = disputed_findings(inv, dt)  # no NVD feeds: only the description prefix
    rows, checked, errors = res.rows, res.checked, res.errors
    assert errors == [] and checked == 4 and res.unchecked == 0
    assert [(r.vuln_id, r.marker) for r in rows] == [
        ("CVE-2020-2", "REJECT"),  # withdrawn first
        ("CVE-2020-1", "DISPUTED"),
        ("CVE-2020-4", "DISPUTED"),
    ]
    assert rows[1].reason.startswith('CVE-2020-1 is marked DISPUTED in its CVE record: "Foo allows X.')
    assert rows[1].reason.endswith('…"') and len(rows[1].reason) < 260
    assert (rows[1].project_uuid, rows[1].component_uuid, rows[1].vuln_uuid) == (
        "p1",
        "c-foo",
        "v-CVE-2020-1",
    )

    # the same JSON `disputed --json` prints is what `ignore` reads
    review = tmp_path / "review.json"
    review.write_text(json.dumps([asdict(r) for r in rows[:1]]), encoding="utf-8")
    items = load_review(review, today=date(2026, 11, 23))
    assert items[0].comment == (
        "CVE-2020-2 is marked REJECT in its CVE record: "
        '"DO NOT USE THIS CANDIDATE NUMBER."; reviewed 2026-11-23 via vulnflow'
    )
    t = FakeTransport({"GET /api/v1/analysis": Response(404, b"{}", {}), "PUT /api/v1/analysis": {}})
    written, _, _, errs = apply_ignores(Http("http://dt", transport=t), items, "NOT_AFFECTED")
    assert errs == [] and len(written) == 1
    put = next(c for c in t.calls if c[0] == "PUT")
    assert json.loads(put[3])["comment"] == items[0].comment


def _nvd_feed(records: list[dict]) -> tuple[bytes, bytes]:
    """(feed .json.gz body, .meta body) in NVD's JSON 2.0 feed layout."""
    import gzip
    import hashlib

    raw = json.dumps(
        {"resultsPerPage": len(records), "format": "NVD_CVE", "vulnerabilities": records}
    ).encode()
    meta = (
        f"lastModifiedDate:2026-11-21T03:04:08-05:00\nsha256:{hashlib.sha256(raw).hexdigest().upper()}\n"
    )
    return gzip.compress(raw), meta.encode()


def _nvd_cve(
    cid: str,
    desc: str,
    status: str = "Modified",
    tags: list[str] | None = None,
    matches: list[dict] | None = None,
    published: str = "2010-04-05T16:30:00.000",
) -> dict:
    cve: dict[str, Any] = {
        "id": cid,
        "published": published,
        "vulnStatus": status,
        "descriptions": [{"lang": "es", "value": "otro"}, {"lang": "en", "value": desc}],
    }
    if tags:
        cve["cveTags"] = [{"sourceIdentifier": "cve@mitre.org", "tags": tags}]
    if matches:
        cve["configurations"] = [{"nodes": [{"operator": "OR", "negate": False, "cpeMatch": matches}]}]
    return {"cve": cve}


def _cpe(product: str, version: str = "*", vulnerable: bool = True, **bounds: str) -> dict:
    vendor, name = product.split(":")
    return {
        "vulnerable": vulnerable,
        "criteria": f"cpe:2.3:a:{vendor}:{name}:{version}:*:*:*:*:*:*:*",
        **bounds,
    }


def test_nvd_feed_is_read_record_by_record_and_checksummed():
    from vulnflow.disputed import scan_feed

    records = [
        _nvd_cve(
            "CVE-2018-20225", "pip installs the highest version. NOTE: intended.", tags=["disputed"]
        ),
        _nvd_cve("CVE-2018-1", "Rejected reason: duplicate of CVE-2018-2.", status="Rejected"),
        _nvd_cve("CVE-2018-2", "Plain flaw, café", tags=["exclusively-hosted-service"]),
        _nvd_cve("CVE-2018-3", "** DISPUTED ** old style", status="Analyzed"),
        _nvd_cve("CVE-2018-4", "Assigned to an EOL product.", tags=["unsupported-when-assigned"]),
    ]
    body, meta = _nvd_feed(records)
    want = meta.decode().split("sha256:")[1].strip()
    for chunk in (7, 1 << 20):  # 7 bytes: records, keys and the "é" span reads
        ids, flags, sha, anyver = scan_feed(body, chunk=chunk)
        assert anyver == {}  # none of these list a product
        assert sha == want
        assert ids == ["CVE-2018-20225", "CVE-2018-1", "CVE-2018-2", "CVE-2018-3", "CVE-2018-4"]
        assert flags == {
            "CVE-2018-20225": ["DISPUTED", "NOTE: intended."],
            "CVE-2018-1": ["REJECT", "Rejected reason: duplicate of CVE-2018-2."],
            "CVE-2018-3": ["DISPUTED", "old style"],
            "CVE-2018-4": ["UNSUPPORTED", "Assigned to an EOL product."],
        }
    import gzip

    with pytest.raises(ValueError, match="ends inside"):
        scan_feed(gzip.compress(b'{"vulnerabilities": [{"cve": {"id": "CVE-2018-1"}},'))


def test_nvd_feeds_download_once_per_year_and_recheck_the_meta(tmp_path):
    import os

    from vulnflow.disputed import NvdFeeds

    body18, meta18 = _nvd_feed([_nvd_cve("CVE-2018-20225", "x NOTE: intended.", tags=["disputed"])])
    body02, meta02 = _nvd_feed([_nvd_cve("CVE-1999-0001", "old")])
    routes: dict[str, object] = {
        "GET /nvdcve-2.0-2018.meta": Response(200, meta18, {}),
        "GET /nvdcve-2.0-2018.json.gz": Response(200, body18, {}),
        "GET /nvdcve-2.0-2002.meta": Response(200, meta02, {}),
        "GET /nvdcve-2.0-2002.json.gz": Response(200, body02, {}),
    }
    t = FakeTransport(routes)
    notes: list[str] = []
    nvd = NvdFeeds(tmp_path, transport=t, url="https://nvd.test/feeds", notify=notes.append)
    assert nvd.flag("CVE-2018-20225") == ("DISPUTED", "NOTE: intended.")
    assert nvd.knows("CVE-2018-20225") and not nvd.knows("CVE-2018-9")  # not in the feed (yet)
    assert nvd.knows("CVE-1999-0001") and nvd.flag("CVE-1999-0001") is None  # 1999-2001: 2002 feed
    assert not nvd.knows("CVE-2019-1") and nvd.errors == [
        "NVD feed 2019: GET https://nvd.test/feeds/nvdcve-2.0-2019.meta -> HTTP 404: "
        '{"detail":"not found"}'
    ]
    assert notes == ["downloading NVD feed 2018", "downloading NVD feed 2002"]
    assert [c[1].rsplit("/", 1)[1] for c in t.calls] == [
        "nvdcve-2.0-2018.meta",
        "nvdcve-2.0-2018.json.gz",
        "nvdcve-2.0-2002.meta",
        "nvdcve-2.0-2002.json.gz",
        "nvdcve-2.0-2019.meta",
    ]
    assert not (tmp_path / "nvd" / "nvdcve-2.0-2018.json.gz").exists()  # only the small index

    t.calls.clear()  # within a day: the index on disk, nothing fetched
    assert NvdFeeds(tmp_path, transport=t, url="https://nvd.test/feeds").flag("CVE-2018-20225")
    assert t.calls == []

    index = tmp_path / "nvd" / "nvdcve-2.0-2018.flags.json"
    os.utime(index, (0, 0))  # a day later, same sha256: only the .meta
    assert NvdFeeds(tmp_path, transport=t, url="https://nvd.test/feeds").flag("CVE-2018-20225")
    assert [c[1].rsplit("/", 1)[1] for c in t.calls] == ["nvdcve-2.0-2018.meta"]

    t.calls.clear()  # changed upstream, but the download does not match the new .meta
    os.utime(index, (0, 0))
    routes["GET /nvdcve-2.0-2018.meta"] = Response(200, b"sha256:" + b"0" * 64 + b"\n", {})
    stale = NvdFeeds(tmp_path, transport=t, url="https://nvd.test/feeds")
    assert stale.flag("CVE-2018-20225") == ("DISPUTED", "NOTE: intended.")  # stale beats nothing
    assert len(stale.errors) == 1 and "does not match the .meta file" in stale.errors[0]


def test_nvd_any_version_rules_and_the_index_format_upgrade(tmp_path):
    from vulnflow.disputed import INDEX_FORMAT, NvdFeeds, scan_feed, unbounded_products

    safari_any = _nvd_cve(
        "CVE-2010-1179",
        "Safari on iPhone OS 3.1.3 ...",
        matches=[
            _cpe("apple:safari"),  # every version: NVD's data error
            {"vulnerable": False, "criteria": "cpe:2.3:o:apple:iphone_os:3.1.3:*:*:*:*:*:*:*"},
        ],
    )
    assert unbounded_products(safari_any["cve"]) == ["apple:safari"]
    bounded = [
        _cpe("apple:safari", versionEndExcluding="4.0.5"),  # a range
        _cpe("haxx:curl", "7.1.0"),  # an exact version
        _cpe("gnu:wget", "-"),  # "not applicable", not "every version"
        _cpe("vim:vim", vulnerable=False),  # not the vulnerable part
    ]
    assert unbounded_products(_nvd_cve("CVE-2010-2", "x", matches=bounded)["cve"]) == []

    body, meta = _nvd_feed([safari_any, _nvd_cve("CVE-2010-2", "x", matches=bounded)])
    _, _, _, anyver = scan_feed(body)
    assert anyver == {"CVE-2010-1179": ["2010-04-05", ["apple:safari"]]}

    # an index written before ANY-VERSION existed is rebuilt although the feed is unchanged
    index = tmp_path / "nvd" / "nvdcve-2.0-2010.flags.json"
    index.parent.mkdir(parents=True)
    sha = meta.decode().split("sha256:")[1].strip()
    index.write_text(json.dumps({"sha256": sha, "ids": ["CVE-2010-1179"], "flags": {}}))
    t = FakeTransport(
        {
            "GET /nvdcve-2.0-2010.meta": Response(200, meta, {}),
            "GET /nvdcve-2.0-2010.json.gz": Response(200, body, {}),
        }
    )
    nvd = NvdFeeds(tmp_path, transport=t, url="https://nvd.test/feeds")
    assert nvd.any_version("CVE-2010-1179") == ("2010-04-05", {"apple:safari"})
    assert nvd.any_version("CVE-2010-2") is None
    assert [c[1].rsplit("/", 1)[1] for c in t.calls] == [
        "nvdcve-2.0-2010.meta",
        "nvdcve-2.0-2010.json.gz",
    ]
    assert json.loads(index.read_text())["format"] == INDEX_FORMAT


def test_disputed_flags_old_cves_nvd_lists_for_every_version(inv, tmp_path):
    from datetime import date

    from vulnflow.disputed import NvdFeeds, disputed_findings

    def finding(vid, cpe, version="27.2", comp="Safari"):
        return {
            "component": {"name": comp, "version": version, "uuid": f"c-{comp}", "cpe": cpe},
            "vulnerability": {
                "source": "NVD",
                "vulnId": vid,
                "severity": "HIGH",
                "uuid": f"v-{vid}",
                "description": "x",
            },
            "analysis": {},
        }

    safari = "cpe:2.3:a:apple:safari:27.2:*:*:*:*:*:*:*"
    findings = [
        finding("CVE-2010-1179", safari),  # every version, 2010: flagged
        finding("CVE-2010-2", safari),  # Safari with a version range: not flagged
        finding(
            "CVE-2010-3", "cpe:2.3:a:gnu:wget:1.25:*:*:*:*:*:*:*", "1.25", "wget"
        ),  # wget not listed
        finding("CVE-2026-4", safari),  # every version, but recent: not flagged
    ]

    def dt_route(m, url, h, b):
        if "/project/tag/team-dev" in url:
            return Response(
                200,
                json.dumps(
                    [{"uuid": "p1", "name": "host:mbp", "version": "macos-27", "active": True}]
                ).encode(),
                {},
            )
        if "/project/tag/" in url:
            return Response(200, b"[]", {})
        return Response(200, json.dumps(findings).encode(), {})

    b10, m10 = _nvd_feed(
        [
            _nvd_cve("CVE-2010-1179", "x", matches=[_cpe("apple:safari")]),
            _nvd_cve("CVE-2010-2", "x", matches=[_cpe("apple:safari", versionEndExcluding="5.0")]),
            _nvd_cve("CVE-2010-3", "x", matches=[_cpe("apple:safari")]),
        ]
    )
    b26, m26 = _nvd_feed(
        [
            _nvd_cve(
                "CVE-2026-4", "x", matches=[_cpe("apple:safari")], published="2026-11-01T00:00:00.000"
            )
        ]
    )
    t = FakeTransport(
        {
            "GET /nvdcve-2.0-2010.meta": Response(200, m10, {}),
            "GET /nvdcve-2.0-2010.json.gz": Response(200, b10, {}),
            "GET /nvdcve-2.0-2026.meta": Response(200, m26, {}),
            "GET /nvdcve-2.0-2026.json.gz": Response(200, b26, {}),
        }
    )
    nvd = NvdFeeds(tmp_path, transport=t, url="https://nvd.test/feeds")
    dt = DependencyTrack("http://dt", "k", transport=FakeTransport({"GET /api/v1/": dt_route}))
    res = disputed_findings(inv, dt, nvd=nvd, today=date(2026, 11, 24))
    assert res.errors == [] and [(r.vuln_id, r.marker) for r in res.rows] == [
        ("CVE-2010-1179", "ANY-VERSION")
    ]
    assert res.rows[0].reason == (
        'CVE-2010-1179 is marked ANY-VERSION in NVD: "NVD lists apple:safari as vulnerable in '
        'every version (no version range); published 2010-04-05, installed 27.2"'
    )
    off = disputed_findings(inv, dt, nvd=nvd, any_version_years=0, today=date(2026, 11, 24))
    assert off.rows == []


def test_disputed_uses_nvd_tags_and_counts_what_nvd_cannot_answer(inv, tmp_path):
    from vulnflow.disputed import NvdFeeds, disputed_findings

    def finding(vid, desc=""):
        return {
            "component": {"name": "pip", "version": "24.0", "uuid": "c-pip"},
            "vulnerability": {"source": "NVD", "vulnId": vid, "severity": "HIGH", "uuid": f"v-{vid}"}
            | ({"description": desc} if desc else {"description": "plain text from DT"}),
            "analysis": {},
        }

    findings = [
        finding("CVE-2018-20225"),  # disputed only in NVD's cveTags, not in DT's description
        finding("CVE-2018-1"),  # rejected
        finding("DEBIAN-CVE-2018-1"),  # DT's OSV id for the same CVE: looked up as CVE-2018-1
        finding("CVE-2026-99999"),  # newer than the feed
        finding("GHSA-xxxx-yyyy-zzzz"),  # not a CVE: not counted as unchecked
        finding("CVE-2018-5", "** DISPUTED ** old prefix still counts"),
    ]

    def dt_route(m, url, h, b):
        if "/project/tag/team-dev" in url:
            proj = [{"uuid": "p1", "name": "container:app", "version": "1.2", "active": True}]
            return Response(200, json.dumps(proj).encode(), {})
        if "/project/tag/" in url:
            return Response(200, b"[]", {})
        return Response(200, json.dumps(findings).encode(), {})

    body18, meta18 = _nvd_feed(
        [
            _nvd_cve("CVE-2018-20225", "pip installs it. NOTE: intended.", tags=["disputed"]),
            _nvd_cve("CVE-2018-1", "Rejected reason: not a vulnerability.", status="Rejected"),
            _nvd_cve("CVE-2018-5", "** DISPUTED ** old prefix still counts"),
        ]
    )
    body26, meta26 = _nvd_feed([])
    nvd = NvdFeeds(
        tmp_path,
        url="https://nvd.test/feeds",
        transport=FakeTransport(
            {
                "GET /nvdcve-2.0-2018.meta": Response(200, meta18, {}),
                "GET /nvdcve-2.0-2018.json.gz": Response(200, body18, {}),
                "GET /nvdcve-2.0-2026.meta": Response(200, meta26, {}),
                "GET /nvdcve-2.0-2026.json.gz": Response(200, body26, {}),
            }
        ),
    )
    dt = DependencyTrack("http://dt", "k", transport=FakeTransport({"GET /api/v1/": dt_route}))
    res = disputed_findings(inv, dt, nvd=nvd)
    assert res.errors == [] and res.checked == 6 and res.unchecked == 1
    assert [(r.vuln_id, r.marker, r.project_version) for r in res.rows] == [
        ("CVE-2018-1", "REJECT", "1.2"),
        ("DEBIAN-CVE-2018-1", "REJECT", "1.2"),
        ("CVE-2018-20225", "DISPUTED", "1.2"),
        ("CVE-2018-5", "DISPUTED", "1.2"),
    ]
    assert res.rows[2].reason == 'CVE-2018-20225 is marked DISPUTED in NVD: "NOTE: intended."'


def test_debian_cli_shows_project_version_and_why_debian_has_no_fix(inv, tmp_path, monkeypatch, capsys):
    import secrets

    from vulnflow.__main__ import main
    from vulnflow.triage import load_review

    monkeypatch.setenv("DT_URL", "http://dt.test")
    monkeypatch.setenv("DT_API_KEY", secrets.token_hex(8))
    env_file = tmp_path / ".env"
    env_file.write_text("")
    purl = "pkg:deb/debian/gnupg@2.4.7-21?distro=debian-13"

    def finding(proj):
        return {
            "component": {"name": "gnupg", "version": "2.4.7-21", "purl": purl, "uuid": f"c-{proj}"},
            "vulnerability": {
                "source": "NVD",
                "vulnId": "CVE-2025-1",
                "severity": "MEDIUM",
                "uuid": "v1",
            },
            "analysis": {},
        }

    def route(m, url, h, b):
        if "/project/tag/team-dev" in url:  # one image name, two hosts, two tags
            proj = [
                {"uuid": "p1", "name": "container:nginx", "version": "1.31.8", "active": True},
                {"uuid": "p2", "name": "container:nginx", "version": "trixie", "active": True},
            ]
            return Response(200, json.dumps(proj).encode(), {})
        if "/project/tag/" in url:
            return Response(200, b"[]", {})
        if "/finding/project/" in url:
            return Response(
                200, json.dumps([finding(url.split("/finding/project/")[1][:2])]).encode(), {}
            )
        assert "/tracker/data/json" in url
        rel = {
            "status": "open",
            "urgency": "not yet assigned",
            "nodsa": "Minor issue",
            "nodsa_reason": "postponed",
            "next_point_update": True,
        }
        return Response(
            200, json.dumps({"gnupg": {"CVE-2025-1": {"releases": {"trixie": rel}}}}).encode(), {}
        )

    monkeypatch.setattr("vulnflow.net.urllib_transport", FakeTransport({"GET ": route}))
    args = ["--env-file", str(env_file), "--inventory", str(INV), "--data-dir", str(tmp_path)]
    assert main([*args, "debian"]) == 0
    out = capsys.readouterr().out.splitlines()
    note = "(fix queued for the next point release; no DSA: Minor issue [postponed])"
    assert out == [
        f"not yet assigned no-fix   dev/container:nginx@1.31.8: gnupg 2.4.7-21 CVE-2025-1 "
        f"(gnupg, trixie) fix: - {note}",
        f"not yet assigned no-fix   dev/container:nginx@trixie: gnupg 2.4.7-21 CVE-2025-1 "
        f"(gnupg, trixie) fix: - {note}",
    ]

    assert main([*args, "debian", "--json"]) == 0
    rows = json.loads(capsys.readouterr().out)
    assert [(r["project_version"], r["note"]) for r in rows] == [
        ("1.31.8", note[1:-1]),
        ("trixie", note[1:-1]),
    ]
    review = tmp_path / "review.json"
    review.write_text(json.dumps(rows[:1]))
    assert [it.label for it in load_review(review)] == ["dev/container:nginx@1.31.8"]


def test_where_lists_the_file_paths_syft_recorded(tmp_path, monkeypatch, capsys):
    import secrets

    from vulnflow.__main__ import main

    monkeypatch.setenv("DT_URL", "http://dt.test")
    monkeypatch.setenv("DT_API_KEY", secrets.token_hex(8))
    env_file = tmp_path / ".env"
    env_file.write_text("")
    projects = {
        "team-sysadm": [
            {"uuid": "h1", "name": "host:second", "version": "debian-13", "active": True},
            {"uuid": "h0", "name": "host:gone", "version": "debian-12", "active": False},
        ],
    }
    comps = {
        "h1": [
            {"uuid": "c1", "name": "stdlib", "version": "go1.23.3", "purl": "pkg:golang/stdlib@1.23.3"},
            {"uuid": "c2", "name": "stdlib", "version": "go1.24.4", "purl": "pkg:golang/stdlib@1.24.4"},
            {"uuid": "c3", "name": "curl", "version": "8", "purl": "pkg:deb/debian/curl@8"},
        ],
    }

    def prop(n, v, group="syft"):
        return {"groupName": group, "propertyName": f"location:{n}:path", "propertyValue": v}

    props = {
        "c1": [
            prop(1, "usr/local/bin/tool"),
            prop(0, "usr/bin/geoipupdate"),
            {"groupName": "syft", "propertyName": "location:0:layerID", "propertyValue": "x"},
            {"groupName": "syft", "propertyName": "package:language", "propertyValue": "go"},
        ],
        "c2": [],
    }

    def route(m, url, h, b):
        path = url.split("http://dt.test/")[1].split("?")[0]
        if path.startswith("api/v1/project/tag/"):
            return Response(200, json.dumps(projects.get(path.rsplit("/", 1)[1], [])).encode(), {})
        if path.startswith("api/v1/component/project/"):
            return Response(200, json.dumps(comps[path.rsplit("/", 1)[1]]).encode(), {})
        if path.endswith("/property"):
            return Response(200, json.dumps(props[path.split("/")[-2]]).encode(), {})
        raise AssertionError(f"unexpected {m} {url}")

    t = FakeTransport({"GET ": route})
    monkeypatch.setattr("vulnflow.net.urllib_transport", t)
    args = ["--env-file", str(env_file), "--inventory", str(INV), "--data-dir", str(tmp_path)]
    assert main([*args, "where", "STDLIB"]) == 0
    assert capsys.readouterr().out.splitlines() == [
        "sysadm/host:second@debian-13: stdlib go1.23.3  /usr/bin/geoipupdate, /usr/local/bin/tool",
        "sysadm/host:second@debian-13: stdlib go1.24.4  (no path recorded)",
    ]
    assert not any("/component/project/h0" in c[1] for c in t.calls)  # inactive: not read

    assert main([*args, "where", "stdlib", "--version", "go1.23.3", "--json"]) == 0
    (row,) = json.loads(capsys.readouterr().out)
    assert row["paths"] == ["/usr/bin/geoipupdate", "/usr/local/bin/tool"]
    assert row["project"] == "host:second" and row["purl"] == "pkg:golang/stdlib@1.23.3"
    assert main([*args, "where", "stdlib", "--project", "nomatch", "--json"]) == 0
    assert json.loads(capsys.readouterr().out) == []


class FakePortfolio:
    """Stateful fake of the DT endpoints `prune` uses: projects by tag, findings (with and
    without suppressed), analysis GET/PUT, project PATCH and the FPF export."""

    def __init__(self, projects: list[dict], findings: dict[str, list[dict]]):
        self.projects = {p["uuid"]: p for p in projects}
        self.findings = findings  # project uuid -> findings (analysis in "analysis")
        self.analyses: dict[tuple[str, str, str], dict] = {}
        self.calls: list[tuple[str, str]] = []

    def __call__(self, method, url, headers, body, timeout):
        from urllib.parse import parse_qs, urlsplit

        u = urlsplit(url)
        path, q = u.path.removeprefix("/"), {k: v[0] for k, v in parse_qs(u.query).items()}
        self.calls.append((method, path))

        def ok(obj):
            return Response(200, json.dumps(obj).encode(), {})

        if path.startswith("api/v1/project/tag/"):
            tag = path.rsplit("/", 1)[1]
            return ok([p for p in self.projects.values() if any(t["name"] == tag for t in p["tags"])])
        if method == "PATCH" and path.startswith("api/v1/project/"):
            self.projects[path.rsplit("/", 1)[1]].update(json.loads(body))
            return ok({})
        if path.endswith("/export"):
            uuid = path.split("/")[-2]
            return ok({"version": "1.2", "project": {"uuid": uuid}, "findings": self.findings[uuid]})
        if path.startswith("api/v1/finding/project/"):
            fs = self.findings[path.rsplit("/", 1)[1]]
            if q.get("suppressed") != "true":
                fs = [f for f in fs if not f["analysis"].get("isSuppressed")]
            return ok(fs)
        if path == "api/v1/analysis" and method == "GET":
            k = (q["project"], q["component"], q["vulnerability"])
            return ok(self.analyses[k]) if k in self.analyses else Response(404, b"", {})
        if path == "api/v1/analysis" and method == "PUT":
            b = json.loads(body)
            k = (b["project"], b["component"], b["vulnerability"])
            self.analyses[k] = {
                "analysisState": b["analysisState"],
                "analysisJustification": b.get("analysisJustification"),
                "analysisResponse": b.get("analysisResponse"),
                "isSuppressed": b["isSuppressed"],
                "analysisComments": [{"comment": b["comment"]}],
            }
            for f in self.findings[b["project"]]:
                if (f["component"]["uuid"], f["vulnerability"]["uuid"]) == k[1:]:
                    f["analysis"] = {"state": b["analysisState"], "isSuppressed": b["isSuppressed"]}
            return ok(self.analyses[k])
        raise AssertionError(f"unexpected {method} {url}")


def test_prune_carries_decisions_deactivates_stale_and_reactivates_rollbacks(inv):
    from vulnflow.prune import prune

    now = 1_800_000_000.0
    hours = 3600 * 1000  # lastBomImport is epoch milliseconds

    def proj(uuid, name, version, tags, age_h, active=True, inactive_h=None):
        return {
            "uuid": uuid,
            "name": name,
            "version": version,
            "active": active,
            "tags": [{"name": t} for t in tags],
            "lastBomImport": None if age_h is None else int(now * 1000 - age_h * hours),
            # DT sets inactiveSince when a project is deactivated
            "inactiveSince": None if inactive_h is None else int(now * 1000 - inactive_h * hours),
        }

    box = "pkg:generic/busybox@1.34.1"

    def f(proj_uuid, comp, purl, cve, state="", suppressed=False):
        return {
            "component": {"uuid": f"{proj_uuid}-{comp}", "name": comp, "version": "x", "purl": purl},
            "vulnerability": {"uuid": f"V-{cve}", "vulnId": cve},
            "analysis": {"state": state, "isSuppressed": suppressed} if state else {},
        }

    c = ["kind-container", "team-dev", "host-h1"]
    projects = [
        proj("old", "container:searxng", "v1", c, 72),  # superseded for 3 days
        proj("new", "container:searxng", "v2", c, 1),
        proj("ng1", "container:nginx", "1.30", c, 1, active=False, inactive_h=48),  # rolled back to
        proj("ng2", "container:nginx", "1.31", c, 24),  # newer tag, seen yesterday: kept
        # runs next to 1.30, deactivated while the host was offline, uploaded again: back
        proj("ng0", "container:nginx", "1.29", c, 2, active=False, inactive_h=30),
        # retired early (by hand) an hour ago and not uploaded since: stays retired
        proj("ng9", "container:nginx", "1.28", c, 6, active=False, inactive_h=1),
        # no inactiveSince (older DT): only the newest of a group comes back
        proj("rd0", "container:redis", "7", c, 1, active=False),
        proj("rd1", "container:redis", "8", c, 0.5),
        proj("h2", "host:h2", "debian-13", ["kind-host", "team-sysadm"], 8 * 24),  # gone a week
        proj("man", "manual", "1", ["team-dev"], 500),  # not an agent project: untouched
        proj("nev", "container:never", "1", c, None),  # never uploaded: untouched
    ]
    findings = {
        "old": [
            f("old", "busybox", box, "CVE-1", "NOT_AFFECTED", True),
            f("old", "busybox", box, "CVE-2", "IN_TRIAGE"),  # not a decision to carry
        ],
        "new": [
            f("new", "busybox", box, "CVE-1"),  # same build, untriaged: gets the decision
            f("new", "busybox", box, "CVE-2"),
            f("new", "busybox2", "pkg:generic/busybox@1.37.0", "CVE-1"),  # other build: no
        ],
        "ng0": [],
        "ng9": [],
        "rd0": [],
        "rd1": [],
        "ng1": [],
        "ng2": [],
        "h2": [],
        "man": [],
        "nev": [],
    }
    fake = FakePortfolio(projects, findings)
    fake.analyses[("old", "old-busybox", "V-CVE-1")] = {
        "analysisState": "NOT_AFFECTED",
        "analysisJustification": "CODE_NOT_PRESENT",
        "isSuppressed": True,
        "analysisComments": [
            {"comment": "Analysis: NOT_SET → NOT_AFFECTED"},
            {"comment": "Void patches it (0001, 0002); reviewed 2026-11-24 via vulnflow"},
            {"comment": "Suppressed"},
        ],
    }
    dt = DependencyTrack("http://dt", "k", transport=fake)

    dry = prune(inv, dt, now=now)
    assert [c for c in fake.calls if c[0] != "GET"] == []  # a dry run writes nothing
    assert dry.reactivated == ["dev/container:nginx@1.29", "dev/container:nginx@1.30"]
    assert dry.deactivated == [
        "dev/container:searxng@v1 (newer version uploaded; last 3.0 days ago)",
        "sysadm/host:h2@debian-13 (no upload; last 8.0 days ago)",
    ]
    assert dry.carried == [
        f"dev/container:searxng@v2: {box} CVE-1 <- NOT_AFFECTED from container:searxng@v1"
    ]

    dojo_t = FakeTransport({"POST /api/v2/reimport-scan/": {"statistics": {}}})
    dojo = DefectDojo("http://dd", "t", transport=dojo_t)
    for p in projects:  # the dry run only changed its own copies
        fake.projects[p["uuid"]]["active"] = p["active"]
    fake.projects["ng1"]["active"] = False
    rep = prune(inv, dt, dojo, apply=True, now=now)
    assert rep.errors == [] and rep.carried == dry.carried
    keys = ("old", "new", "ng0", "ng9", "rd0", "rd1", "ng1", "ng2", "h2", "man", "nev")
    assert {u: fake.projects[u]["active"] for u in keys} == {
        "old": False,
        "new": True,
        "ng0": True,
        "ng9": False,
        "rd0": False,
        "rd1": True,
        "ng1": True,
        "ng2": True,
        "h2": False,
        "man": True,
        "nev": True,
    }
    carried = fake.analyses[("new", "new-busybox", "V-CVE-1")]
    assert carried["analysisState"] == "NOT_AFFECTED" and carried["isSuppressed"] is True
    assert carried["analysisJustification"] == "CODE_NOT_PRESENT"
    assert carried["analysisComments"][0]["comment"] == (
        "Carried forward from container:searxng@v1: Void patches it (0001, 0002); "
        "reviewed 2026-11-24; via vulnflow"
    )
    assert ("new", "new-busybox2", "V-CVE-1") not in fake.analyses  # a different build
    assert ("new", "new-busybox", "V-CVE-2") not in fake.analyses  # In Triage is no decision

    # the deactivated ones were closed in DefectDojo first: same product/test, no findings
    posts = [c for c in dojo_t.calls if c[0] == "POST"]
    assert len(posts) == 2
    first = next(c[3] for c in posts if b'name="product_name"\r\n\r\ncontainer:searxng\r\n' in c[3])
    assert b'name="test_title"\r\n\r\nDependency-Track v1\r\n' in first
    assert b'"findings": []' in first and b'name="close_old_findings"\r\n\r\ntrue' in first

    again = prune(inv, dt, dojo, apply=True, now=now)  # idempotent: nothing left to do
    assert not again.changed and again.errors == []


def test_prune_retires_what_the_hosts_last_scan_did_not_upload(inv):
    from vulnflow.prune import prune

    now = 1_800_000_000.0
    hour = 3600 * 1000  # lastBomImport is epoch milliseconds

    def proj(uuid, name, version, tags, age_h, active=True, inactive_h=None):
        return {
            "uuid": uuid,
            "name": name,
            "version": version,
            "active": active,
            "tags": [{"name": t} for t in tags],
            "lastBomImport": int(now * 1000 - age_h * hour),
            "inactiveSince": None if inactive_h is None else int(now * 1000 - inactive_h * hour),
        }

    on_h1 = ["kind-container", "team-dev", "host-h1"]
    projects = [
        proj("h1", "host:h1", "debian-13", ["kind-host", "team-sysadm"], 2),  # agent ran 2 h ago
        proj("same", "container:nginx", "1.31", on_h1, 2.05),  # same run, minutes apart: kept
        proj("gone", "container:airflow", "latest", on_h1, 26),  # not in the last run: retired
        # back in the last run after being retired by an earlier one
        proj("back", "container:redis", "8", on_h1, 2, active=False, inactive_h=20),
        # a host whose own project is older than its containers (host scan failed): kept
        proj("h2", "host:h2", "debian-13", ["kind-host", "team-sysadm"], 30),
        proj("c2", "container:app", "1", ["kind-container", "team-dev", "host-h2"], 3),
        # no host project at all: only the old 7-day rule
        proj("c3", "container:app", "1", ["kind-container", "team-dev", "host-h3"], 50),
    ]
    fake = FakePortfolio(projects, {p["uuid"]: [] for p in projects})
    dt = DependencyTrack("http://dt", "k", transport=fake)

    dry = prune(inv, dt, now=now)
    assert dry.deactivated == [
        "dev/container:airflow@latest (not in the host's last scan, 2.0 h ago; last 1.1 days ago)"
    ]
    assert dry.reactivated == ["dev/container:redis@8"]

    dojo_t = FakeTransport({"POST /api/v2/reimport-scan/": {"statistics": {}}})
    rep = prune(inv, dt, DefectDojo("http://dd", "t", transport=dojo_t), apply=True, now=now)
    assert rep.errors == []
    assert {u: fake.projects[u]["active"] for u in ("same", "gone", "back", "c2", "c3")} == {
        "same": True,
        "gone": False,
        "back": True,
        "c2": True,
        "c3": True,
    }
    posts = [c for c in dojo_t.calls if c[0] == "POST"]
    assert len(posts) == 1 and b"container:airflow" in posts[0][3]  # closed in DefectDojo first


def test_set_active_accepts_dt_304_only_when_the_project_changed():
    from vulnflow.net import HttpError

    state = {"active": True}

    def route(applied):
        def patch(m, url, h, b):
            if applied:
                state.update(json.loads(b))
            return Response(304, b"", {})  # what DT 5.2.2 answered, applied or not

        return patch

    def get(m, url, h, b):
        return Response(200, json.dumps({"uuid": "p1", **state}).encode(), {})

    t = FakeTransport({"PATCH /api/v1/project/p1": route(True), "GET /api/v1/project/p1": get})
    DependencyTrack("http://dt", "k", transport=t).set_active("p1", False)
    assert state["active"] is False
    assert [(c[0], c[1]) for c in t.calls] == [
        ("PATCH", "http://dt/api/v1/project/p1"),
        ("GET", "http://dt/api/v1/project/p1"),
    ]

    state["active"] = True
    t = FakeTransport({"PATCH /api/v1/project/p1": route(False), "GET /api/v1/project/p1": get})
    with pytest.raises(HttpError):
        DependencyTrack("http://dt", "k", transport=t).set_active("p1", False)


def test_prune_carries_accepted_risks_and_lifts_them_after_the_review_date(inv):
    from vulnflow.prune import prune

    now = 1_800_000_000.0  # 2027-01-15
    c = [{"name": t} for t in ("kind-container", "team-dev", "host-h1")]
    projects = [
        {
            "uuid": u,
            "name": "container:app",
            "version": v,
            "active": True,
            "tags": c,
            "lastBomImport": int(now * 1000 - h * 3600 * 1000),
        }
        for u, v, h in (("v1", "1", 2), ("v2", "2", 1))
    ]

    def f(p, cve, state="", suppressed=False):
        return {
            "component": {
                "uuid": f"{p}-lib",
                "name": "lib",
                "version": "1",
                "purl": "pkg:generic/lib@1",
            },
            "vulnerability": {"uuid": f"V-{cve}", "vulnId": cve},
            "analysis": {"state": state, "isSuppressed": suppressed} if state else {},
        }

    fake = FakePortfolio(
        projects,
        {
            "v1": [
                f("v1", "CVE-A", "EXPLOITABLE", True),  # accepted risk, review in 2099: carried
                f("v1", "CVE-B", "EXPLOITABLE", True),  # exploitable, response UPDATE: no
                f("v1", "CVE-C", "NOT_AFFECTED", True),  # review date passed: shown again
            ],
            "v2": [f("v2", "CVE-A"), f("v2", "CVE-B"), f("v2", "CVE-C")],
        },
    )

    def analysis(state, response, comment):
        return {
            "analysisState": state,
            "analysisResponse": response,
            "analysisJustification": None,
            "isSuppressed": True,
            "analysisComments": [{"comment": "Analysis: NOT_SET → " + state}, {"comment": comment}],
        }

    fake.analyses[("v1", "v1-lib", "V-CVE-A")] = analysis(
        "EXPLOITABLE",
        "WILL_NOT_FIX",
        "No upstream fix; review by 2099-01-01; reviewed 2027-01-10 via vulnflow",
    )
    fake.analyses[("v1", "v1-lib", "V-CVE-B")] = analysis("EXPLOITABLE", "UPDATE", "update next week")
    fake.analyses[("v1", "v1-lib", "V-CVE-C")] = analysis(
        "NOT_AFFECTED", None, "Not used; review by 2026-12-31; reviewed 2026-06-01 via vulnflow"
    )
    dt = DependencyTrack("http://dt", "k", transport=fake)

    dry = prune(inv, dt, now=now)
    assert [m for m, _ in fake.calls if m != "GET"] == []
    assert dry.carried == [
        "dev/container:app@2: pkg:generic/lib@1 CVE-A <- EXPLOITABLE/WILL_NOT_FIX from container:app@1"
    ]
    assert dry.reopened == [
        "dev/container:app@1: pkg:generic/lib@1 CVE-C (NOT_AFFECTED, review by 2026-12-31)"
    ]

    rep = prune(inv, dt, apply=True, now=now)
    assert rep.errors == [] and rep.carried == dry.carried and rep.reopened == dry.reopened
    copy = fake.analyses[("v2", "v2-lib", "V-CVE-A")]
    assert (copy["analysisState"], copy["analysisResponse"], copy["isSuppressed"]) == (
        "EXPLOITABLE",
        "WILL_NOT_FIX",
        True,
    )
    assert copy["analysisComments"][0]["comment"] == (
        "Carried forward from container:app@1: No upstream fix; review by 2099-01-01; "
        "reviewed 2027-01-10; via vulnflow"
    )
    reopened = fake.analyses[("v1", "v1-lib", "V-CVE-C")]
    assert (reopened["analysisState"], reopened["isSuppressed"]) == ("NOT_AFFECTED", False)
    assert reopened["analysisComments"][-1]["comment"] == (
        "Review date 2026-12-31 passed: shown again; via vulnflow"
    )
    assert ("v2", "v2-lib", "V-CVE-B") not in fake.analyses
    assert ("v2", "v2-lib", "V-CVE-C") not in fake.analyses  # an expired decision is not carried
    assert not prune(inv, dt, apply=True, now=now).changed


def test_ignore_records_accepted_risks_with_a_review_date(tmp_path):
    from datetime import date

    from vulnflow.net import Http
    from vulnflow.triage import apply_ignores, load_review, review_date

    row = {
        "team": "dev",
        "project": "app",
        "project_uuid": "P1",
        "component": "lib",
        "component_uuid": "C1",
        "vuln_id": "CVE-1",
        "vuln_uuid": "V1",
        "reason": "No fix upstream, not reachable from outside",
    }
    f = tmp_path / "review.json"
    f.write_text(json.dumps([row]), encoding="utf-8")
    items = load_review(f, today=date(2026, 11, 24), review_by=date(2027, 3, 1))
    assert items[0].comment == (
        "No fix upstream, not reachable from outside; review by 2027-03-01; "
        "reviewed 2026-11-24 via vulnflow"
    )
    assert review_date(items[0].comment) == date(2027, 3, 1) and review_date("no date") is None

    t = FakeTransport({"GET /api/v1/analysis": Response(404, b"{}", {}), "PUT /api/v1/analysis": {}})
    http = Http("http://dt", transport=t)
    with pytest.raises(ValueError, match="accepted risk"):
        apply_ignores(http, items, "EXPLOITABLE")  # an accepted risk needs a response
    written, _, _, errs = apply_ignores(http, items, "EXPLOITABLE", response="WILL_NOT_FIX")
    assert errs == [] and len(written) == 1
    body = json.loads(next(c for c in t.calls if c[0] == "PUT")[3])
    assert (body["analysisState"], body["analysisResponse"], body["isSuppressed"]) == (
        "EXPLOITABLE",
        "WILL_NOT_FIX",
        True,
    )


def test_debian_version_order_matches_dpkg():
    from vulnflow.debver import compare

    older_first = [
        ("1.0~~", "1.0~"),
        ("1.0~", "1.0"),
        ("1.0~rc1", "1.0"),
        ("1.0", "1.0+b1"),
        ("1.0", "1.0a"),
        ("1.9", "1.10"),
        ("1.0", "1.0-1"),
        ("1.0-1~bpo12+1", "1.0-1"),
        ("1.0-1", "1.0-1+b1"),
        ("5.36.0-7+deb12u4", "5.36.0-7+deb12u5"),
        ("5.36.0-7+deb12u4", "5.36.0-7+deb12u10"),
        ("2.0", "1:1.0"),
    ]
    for a, b in older_first:
        assert compare(a, b) == -1 and compare(b, a) == 1, (a, b)
    assert compare("1.00", "1.0") == 0 and compare("0:1.0", "1.0") == 0


def test_debian_fix_actions_and_ignore_comment(inv, tmp_path):
    from datetime import date

    from vulnflow.debian import DebianTracker, debian_findings, fix_action, installed_version
    from vulnflow.triage import load_review

    assert (
        installed_version("pkg:deb/debian/libssl3t64@3.5.4-1?upstream=openssl%403.5.4-2", "3.5.4-1")
        == "3.5.4-2"
    )
    assert installed_version("pkg:deb/debian/acl@2.3", "2.3") == "2.3"
    assert fix_action("1.0-1", "resolved", "1.0-2") == "update"
    assert fix_action("1.0-2", "resolved", "1.0-2") == "fixed"
    assert fix_action("1.0-3", "resolved", "1.0-2") == "fixed"
    assert fix_action("1.0-1", "resolved", "0") == "fixed"  # never affected
    assert fix_action("1.0-1", "open", "") == "no-fix"
    assert fix_action("1.0-1", "resolved", "") == "unknown"
    assert fix_action("2.0-1", "resolved", "1:1.0-1") == "unknown"  # epoch on one side only
    assert fix_action("", "resolved", "1.0") == "unknown"

    def finding(cve, ver):
        purl = f"pkg:deb/debian/perl@{ver}?distro=debian-12"
        return {
            "component": {"name": "perl", "version": ver, "purl": purl, "uuid": "c-perl"},
            "vulnerability": {"source": "NVD", "vulnId": cve, "severity": "HIGH", "uuid": f"v-{cve}"},
            "analysis": {},
        }

    doc = {
        "perl": {
            "CVE-2024-1": {
                "releases": {
                    "bookworm": {
                        "status": "resolved",
                        "urgency": "medium",
                        "fixed_version": "5.36.0-7+deb12u5",
                    }
                }
            },
            "CVE-2024-2": {
                "releases": {
                    "bookworm": {
                        "status": "resolved",
                        "urgency": "low",
                        "fixed_version": "5.36.0-7+deb12u2",
                    }
                }
            },
            "CVE-2024-3": {"releases": {"bookworm": {"status": "open", "urgency": "unimportant"}}},
        }
    }
    findings = [finding(c, "5.36.0-7+deb12u4") for c in ("CVE-2024-1", "CVE-2024-2", "CVE-2024-3")]

    def dt_route(m, url, h, b):
        if "/project/tag/team-dev" in url:
            return Response(
                200, json.dumps([{"uuid": "p1", "name": "app", "active": True}]).encode(), {}
            )
        if "/project/tag/" in url:
            return Response(200, b"[]", {})
        return Response(200, json.dumps(findings).encode(), {})

    dt = DependencyTrack("http://dt", "k", transport=FakeTransport({"GET /api/v1/": dt_route}))
    tracker = DebianTracker(tmp_path, transport=FakeTransport({"GET /tracker/data/json": doc}))
    rows, _, errors = debian_findings(inv, dt, tracker)
    assert errors == []
    assert {r.vuln_id: (r.action, r.installed, r.fixed) for r in rows} == {
        "CVE-2024-1": ("update", "5.36.0-7+deb12u4", "5.36.0-7+deb12u5"),
        "CVE-2024-2": ("fixed", "5.36.0-7+deb12u4", "5.36.0-7+deb12u2"),
        "CVE-2024-3": ("no-fix", "5.36.0-7+deb12u4", ""),
    }

    # a row that is already fixed gets a comment that says why NVD is wrong here
    fixed_row = next(r for r in rows if r.action == "fixed")
    review = tmp_path / "review.json"
    review.write_text(json.dumps([asdict(fixed_row)]), encoding="utf-8")
    comment = load_review(review, today=date(2026, 11, 23))[0].comment
    assert comment == (
        "Debian tracker: fixed in 5.36.0-7+deb12u2, installed 5.36.0-7+deb12u4 is not older in "
        "bookworm, source package perl; reviewed 2026-11-23 via vulnflow"
    )


def test_recommend_picks_the_fix_for_the_installed_branch():
    from vulnflow.versions import recommend

    minimatch = ["10.2.1", "9.0.6", "8.0.5", "7.4.7", "6.2.1", "5.1.7", "4.2.4", "3.1.3"]
    assert recommend("9.0.3", minimatch) == "9.0.6"
    assert recommend("3.1.2", minimatch) == "3.1.3"
    assert recommend("go1.23.3", ["1.23.12", "1.24.6"]) == "1.23.12"
    assert recommend("go1.24.4", ["1.25.12", "1.26.5", "1.27.0-rc.2"]) == "1.25.12"  # branch gone
    assert recommend("8.3.2", ["11.1.1", "12.0.1", "13.0.1"]) == "11.1.1"  # no fix on 8.x
    assert recommend("v0.31.0", ["0.45.0", "0.52.0"]) == "0.45.0"
    assert recommend("1.0.0-rc1", ["1.0.0"]) == "1.0.0"  # pre-release is older than the release
    assert recommend("2.3.0", ["2.6.0", "2.8.0"]) == "2.6.0"
    assert recommend("2.7.0", ["2.6.0"]) == ""  # nothing newer
    assert recommend("UNKNOWN", ["1.0"]) == "" and recommend("1.0", ["abc"]) == ""


def test_patches_skips_osv_for_unknown_component_versions(inv):
    from vulnflow.clients import OSV
    from vulnflow.patches import is_go_pseudo_version, patched_findings

    for v in (
        "v0.0.0-20261105150651-e2e28adeee2c+dirty",
        "v1.5.1-0.20260910130453-bcfe9f230c1d",
        "v1.2.0-rc.1.0.20260101000000-abcdefabcdef",
        "v2.0.0-20200101000000-abcdefabcdef+incompatible",
    ):
        assert is_go_pseudo_version("pkg:golang/x@" + v, v), v
    for v in ("v1.2.0", "go1.24.6", "v1.2.3-rc.1", "v0.0.0-2026-abc"):
        assert not is_go_pseudo_version("pkg:golang/x@" + v, v), v
    assert not is_go_pseudo_version("pkg:npm/x", "v0.0.0-20261105150651-e2e28adeee2c")

    def finding(name, version, cve):
        return {
            "component": {"name": name, "version": version, "purl": f"pkg:golang/{name}@{version}"},
            "vulnerability": {"source": "NVD", "vulnId": cve, "severity": "MEDIUM"},
            "analysis": {},
        }

    findings = [
        finding("github.com/grafana/grafana", "UNKNOWN", "CVE-2018-1"),
        finding("github.com/grafana/grafana", "UNKNOWN", "CVE-2018-2"),
        finding("minimatch", "9.0.3", "CVE-2026-1"),
        # built from a commit: sorts before every release, so not sent to OSV either
        finding("github.com/prometheus/prometheus", "v0.0.0-20261105150651-e2e28adeee2c", "CVE-2026-2"),
    ]
    # a Debian package: left to `vulnflow debian`, neither looked up in DT nor sent to OSV
    findings.append(
        {
            "component": {
                "name": "curl",
                "version": "8.14.1-2+deb13u7",
                "purl": "pkg:deb/debian/curl@8.14.1-2%2Bdeb13u7?distro=debian-13",
            },
            "vulnerability": {"source": "OSV", "vulnId": "DEBIAN-CVE-2026-3", "severity": "HIGH"},
            "analysis": {},
        }
    )

    def dt_route(m, url, h, b):
        if "/project/tag/team-dev" in url:
            proj = [{"uuid": "p1", "name": "app", "active": True}]
            return Response(200, json.dumps(proj).encode(), {})
        if "/project/tag/" in url:
            return Response(200, b"[]", {})
        if "/finding/project/p1" in url:
            return Response(200, json.dumps(findings).encode(), {})
        return Response(200, json.dumps({"patchedVersions": ""}).encode(), {})

    osv_vulns = [
        {
            "id": "GHSA-m",
            "aliases": ["CVE-2026-1"],
            "affected": [
                {
                    "package": {"name": "minimatch"},
                    "ranges": [
                        {"events": [{"fixed": "10.2.1"}, {"fixed": "9.0.6"}, {"fixed": "3.1.3"}]}
                    ],
                }
            ],
        }
    ]
    dt = DependencyTrack("http://dt", "k", transport=FakeTransport({"GET /api/v1/": dt_route}))
    osv_t = FakeTransport({"POST /v1/query": {"vulns": osv_vulns}})
    rows, unknown, unversioned, pseudo, debian, errors = patched_findings(
        inv, dt, osv=OSV("https://osv.test", transport=osv_t)
    )
    assert errors == [] and unknown == 0 and unversioned == 2 and pseudo == 1 and debian == 1
    assert [(r.vuln_id, r.recommended, r.patched) for r in rows] == [
        ("CVE-2026-1", "9.0.6", "10.2.1, 9.0.6, 3.1.3")
    ]
    assert [json.loads(c[3])["package"]["purl"] for c in osv_t.calls] == ["pkg:golang/minimatch@9.0.3"]


def test_rpm_version_order_matches_rpmvercmp():
    from vulnflow.rpmver import compare, parse_nevr, vercmp

    older_first = [
        ("1.0", "1.1"),
        ("1.0", "1.0.1"),
        ("1.9", "1.10"),
        ("1.0a", "1.0b"),
        ("1.0~rc1", "1.0"),
        ("1.0~rc1", "1.0~rc2"),
        ("1.0", "1.0^git1"),
        ("1.0^git1", "1.0.1"),
        ("a", "1"),
        ("1.0", "1.0a"),
        ("0.074-2.el8", "0.074-10.el8"),
        ("2.el8", "2.el8_6.1"),
        ("2.el8_6.1", "2.el8_6.2"),
    ]
    for a, b in older_first:
        assert vercmp(a, b) == -1 and vercmp(b, a) == 1, (a, b)
    assert vercmp("1.01", "1.1") == 0 and vercmp("1_0", "1.0") == 0
    assert compare((0, "9.0", "1"), (1, "0.1", "1")) == -1  # epoch first
    assert parse_nevr("perl-HTTP-Tiny-0:0.074-2.el8") == ("perl-HTTP-Tiny", 0, "0.074", "2.el8")
    assert parse_nevr("not a nevr") is None


def test_vendor_purls():
    from vulnflow.vendors import parse_vendor_purl

    u = parse_vendor_purl(
        "pkg:deb/ubuntu/libperl5.34@5.34.0-3?upstream=perl%405.34.0-3ubuntu1.3&distro=ubuntu-22.04",
        "5.34.0-3",
    )
    assert u and (u.vendor, u.names, u.release, u.installed) == (
        "ubuntu",
        {"libperl5.34", "perl"},
        "jammy",
        "5.34.0-3ubuntu1.3",
    )
    j = parse_vendor_purl("pkg:deb/ubuntu/perl@5.34.0-3?distro=ubuntu-jammy", "")
    assert j and j.release == "jammy"
    r = parse_vendor_purl(
        "pkg:rpm/redhat/perl-HTTP-Tiny@0.074-2.el8?epoch=1&arch=noarch&distro=rhel-8.8", ""
    )
    assert r and (r.vendor, r.names, r.release, r.installed, r.epoch) == (
        "redhat",
        {"perl-http-tiny"},
        "8",
        "0.074-2.el8",
        1,
    )
    assert parse_vendor_purl("pkg:deb/debian/perl@5.36", "") is None
    assert parse_vendor_purl("pkg:rpm/fedora/bash@5", "") is None
    assert parse_vendor_purl("pkg:pypi/requests@2", "") is None
    nod = parse_vendor_purl("pkg:rpm/redhat/bash@5.1-1.el9", "")
    assert nod and nod.release == ""  # no distro qualifier: release unknown


def test_vendor_lookup_ubuntu_and_redhat(inv, tmp_path):
    from datetime import date

    from vulnflow.triage import load_review
    from vulnflow.vendors import VendorApi, VendorInfo, _reason, vendor_findings

    def st(codename, status, description="", pocket="security"):
        return {
            "release_codename": codename,
            "status": status,
            "description": description,
            "pocket": pocket,
            "component": None,
        }

    ubuntu_rec = {
        "id": "CVE-2024-10001",
        "priority": "medium",
        "packages": [
            {
                "name": "perl",
                "statuses": [
                    st("jammy", "released", "5.34.0-3ubuntu1.2"),
                    st("noble", "ignored", "see notes"),
                    st("focal", "DNE"),
                    st("bionic", "needed"),
                    st("upstream", "needed"),
                ],
            },
            {"name": "other", "statuses": [st("jammy", "released", "9.9")]},
        ],
    }
    cpe8, cpe9, cpe7 = (
        "cpe:/o:redhat:enterprise_linux:8",
        "cpe:/o:redhat:enterprise_linux:9",
        "cpe:/o:redhat:rhel_els:7",
    )
    redhat_rec = {
        "threat_severity": "Moderate",
        "affected_release": [
            {"cpe": cpe8, "advisory": "RHSA-2023:7174", "package": "perl-HTTP-Tiny-0:0.074-2.el8"},
            {
                "cpe": "cpe:/o:redhat:rhel_eus:8.6",
                "advisory": "RHSA-2024:0422",
                "package": "perl-HTTP-Tiny-0:0.074-1.el8_6.1",
            },
        ],
        "package_state": [
            {"cpe": cpe7, "fix_state": "Out of support scope", "package_name": "perl-HTTP-Tiny"},
            {"cpe": cpe9, "fix_state": "Will not fix", "package_name": "perl-HTTP-Tiny"},
            {"cpe": cpe8, "fix_state": "Affected", "package_name": "perl:5.30/perl-HTTP-Tiny"},
        ],
    }
    module_rec = {
        "threat_severity": "Low",
        "package_state": [
            {"cpe": cpe8, "fix_state": "Affected", "package_name": "perl:5.30/perl-HTTP-Tiny"}
        ],
    }

    def finding(name, purl, cve):
        version = purl.split("@", 1)[1].split("?", 1)[0] if "@" in purl else ""  # as in real DT data
        return {
            "component": {
                "name": name,
                "version": version,
                "purl": purl,
                "uuid": f"c-{name}-{purl[-8:]}",
            },
            "vulnerability": {"source": "NVD", "vulnId": cve, "severity": "HIGH", "uuid": f"v-{cve}"},
            "analysis": {},
        }

    ub = "pkg:deb/ubuntu/perl@%s?distro=ubuntu-%s"
    rh = "pkg:rpm/redhat/perl-HTTP-Tiny@%s?epoch=0&distro=rhel-%s"
    findings = [
        finding("perl", ub % ("5.34.0-3ubuntu1.1", "22.04"), "CVE-2024-10001"),  # jammy: older -> update
        finding(
            "libperl",
            "pkg:deb/ubuntu/libperl@5.34?upstream=perl%405.34.0-3ubuntu1.3&distro=ubuntu-22.04",
            "CVE-2024-10001",
        ),  # fixed
        finding("perl", ub % ("5.38.2-3", "24.04"), "CVE-2024-10001"),  # noble: ignored -> wontfix
        finding("perl", ub % ("5.30.0-9", "20.04"), "CVE-2024-10001"),  # focal: DNE -> not-affected
        finding("perl", ub % ("5.26.1-6", "18.04"), "CVE-2024-10001"),  # bionic: needed -> no-fix
        finding("perl", ub % ("5.40.0-1", "26.04"), "CVE-2024-10001"),  # release not mapped -> unmatched
        finding("perl-HTTP-Tiny", rh % ("0.074-1.el8", "8.8"), "CVE-2024-10002"),  # update
        finding("perl-HTTP-Tiny", rh % ("0.074-2.el8_6.1", "8.6"), "CVE-2024-10002"),  # fixed
        finding("perl-HTTP-Tiny", rh % ("0.076-1.el9", "9.4"), "CVE-2024-10002"),  # will not fix
        finding("perl-HTTP-Tiny", rh % ("0.070-1.el7", "7.9"), "CVE-2024-10002"),  # out of support scope
        finding(
            "perl-HTTP-Tiny", rh % ("0.074-1.el8", "8.8"), "CVE-2024-10003"
        ),  # module stream only: no-fix
        finding(
            "bash", "pkg:rpm/redhat/bash@5.1-1.el9?distro=rhel-9.4", "CVE-2024-10004"
        ),  # no record: unmatched
        finding(
            "perl", "pkg:deb/debian/perl@5.36?distro=debian-12", "CVE-2024-10001"
        ),  # not a vendor purl
        finding(
            "requests", "pkg:pypi/requests@2", "GHSA-xxxx-yyyy-zzzz"
        ),  # not a CVE, not a vendor purl
    ]

    def dt_route(m, url, h, b):
        if "/project/tag/team-dev" in url:
            return Response(
                200, json.dumps([{"uuid": "p1", "name": "app", "active": True}]).encode(), {}
            )
        if "/project/tag/" in url:
            return Response(200, b"[]", {})
        return Response(200, json.dumps(findings).encode(), {})

    dt = DependencyTrack("http://dt", "k", transport=FakeTransport({"GET /api/v1/": dt_route}))
    t = FakeTransport(
        {
            "GET /security/cves/CVE-2024-10001.json": ubuntu_rec,
            "GET /securitydata/cve/CVE-2024-10002.json": redhat_rec,
            "GET /securitydata/cve/CVE-2024-10003.json": module_rec,
        }  # CVE-2024-10004: the fake answers 404
    )
    told: list[tuple[str, int]] = []
    res = vendor_findings(
        inv, dt, tmp_path, ubuntu=True, redhat=True, transport=t, notify=lambda v, n: told.append((v, n))
    )
    assert res.errors == []
    by = {(r.vendor, r.version, r.vuln_id): r for r in res.rows}
    got = {k: (r.action, r.release, r.fixed) for k, r in by.items()}
    assert got == {
        ("ubuntu", "5.34.0-3ubuntu1.1", "CVE-2024-10001"): ("update", "jammy", "5.34.0-3ubuntu1.2"),
        ("ubuntu", "5.34.0-3ubuntu1.3", "CVE-2024-10001"): ("fixed", "jammy", "5.34.0-3ubuntu1.2"),
        ("ubuntu", "5.38.2-3", "CVE-2024-10001"): ("wontfix", "noble", ""),
        ("ubuntu", "5.30.0-9", "CVE-2024-10001"): ("not-affected", "focal", ""),
        ("ubuntu", "5.26.1-6", "CVE-2024-10001"): ("no-fix", "bionic", ""),
        ("redhat", "0.074-1.el8", "CVE-2024-10002"): ("update", "rhel8", "0.074-2.el8"),
        ("redhat", "0.074-2.el8_6.1", "CVE-2024-10002"): ("fixed", "rhel8", "0.074-2.el8"),
        ("redhat", "0.076-1.el9", "CVE-2024-10002"): ("wontfix", "rhel9", ""),
        ("redhat", "0.070-1.el7", "CVE-2024-10002"): ("wontfix", "rhel7", ""),
        ("redhat", "0.074-1.el8", "CVE-2024-10003"): ("no-fix", "rhel8", ""),  # module stream only
    }
    assert by[("redhat", "0.074-1.el8", "CVE-2024-10002")].note == "RHSA-2023:7174"
    assert res.unmatched == 2  # Ubuntu 26.04 (release not mapped) and bash (no record)
    assert res.considered == {"ubuntu": 6, "redhat": 6}
    assert res.contacted == {"ubuntu": 1, "redhat": 3}
    assert sorted(told) == [("redhat", 3), ("ubuntu", 1)]
    urls = sorted(c[1] for c in t.calls)
    assert urls == [
        "https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2024-10002.json",
        "https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2024-10003.json",
        "https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2024-10004.json",
        "https://ubuntu.com/security/cves/CVE-2024-10001.json",
    ]

    # a second run answers from the cache (404s too): nothing is requested or announced
    t2 = FakeTransport({})
    again = vendor_findings(
        inv,
        dt,
        tmp_path,
        ubuntu=True,
        redhat=True,
        transport=t2,
        notify=lambda v, n: told.append((v, n)),
    )
    assert (
        t2.calls == []
        and again.contacted == {"ubuntu": 0, "redhat": 0}
        and len(again.rows) == len(res.rows)
    )

    # a vendor that was not asked for is not contacted at all
    t3 = FakeTransport({"GET /securitydata/cve/": redhat_rec})
    only = vendor_findings(inv, dt, tmp_path / "fresh", redhat=True, transport=t3)
    assert only.considered == {"redhat": 6} and all("ubuntu.com" not in c[1] for c in t3.calls)

    # the reason text is what `ignore` writes, and a row goes through load_review unchanged
    fixed_row = by[("ubuntu", "5.34.0-3ubuntu1.3", "CVE-2024-10001")]
    assert (
        fixed_row.reason
        == "Ubuntu: fixed in 5.34.0-3ubuntu1.2 (jammy), installed 5.34.0-3ubuntu1.3 is not older"
    )
    review = tmp_path / "review.json"
    review.write_text(json.dumps([asdict(fixed_row)]), encoding="utf-8")
    assert (
        load_review(review, today=date(2026, 11, 23))[0].comment
        == fixed_row.reason + "; reviewed 2026-11-23 via vulnflow"
    )
    wontfix = by[("ubuntu", "5.38.2-3", "CVE-2024-10001")]
    assert wontfix.reason == "Ubuntu: ignored in noble: see notes"
    esm = VendorInfo(
        "ubuntu", "perl", "jammy", "released", "", "5.34.0-3ubuntu1.9", "", "esm-infra", "fixed"
    )
    assert (
        _reason("ubuntu", esm, "5.34.0-3ubuntu1.9")
        == "Ubuntu: fixed in 5.34.0-3ubuntu1.9 (jammy, esm-infra), installed 5.34.0-3ubuntu1.9 "
        "is not older"
    )

    # ids go into a URL, so anything that is not a CVE id is refused
    with pytest.raises(ValueError):
        VendorApi("ubuntu", "https://ubuntu.com", "security/cves/{cve}.json", tmp_path).record(
            "../../etc/passwd"
        )


class FakeAnalysisApi:
    """DT's /api/v1/analysis as a stateful fake: PUT replaces the analysis (and adds the comment),
    GET returns it, 404 if none. `analyses` is keyed by component uuid."""

    def __init__(self, analyses: dict[str, dict] | None = None, comments: bool = True):
        self.analyses = analyses or {}
        self.comments = comments
        self.puts: list[dict] = []

    def get(self, m, url, h, b):
        comp = url.split("component=")[1].split("&")[0]
        if comp not in self.analyses:
            return Response(404, b'{"detail":"none"}', {})
        return Response(200, json.dumps(self.analyses[comp]).encode(), {})

    def put(self, m, url, h, b):
        body = json.loads(b)
        self.puts.append(body)
        a = {"analysisState": body["analysisState"], "isSuppressed": body["isSuppressed"]}
        if self.comments:
            a["analysisComments"] = [{"comment": body["comment"]}]
        self.analyses[body["component"]] = a
        return Response(200, b"{}", {})

    def http(self):
        from vulnflow.net import Http

        routes: dict[str, object] = {"GET /api/v1/analysis": self.get, "PUT /api/v1/analysis": self.put}
        return Http("http://dt", transport=FakeTransport(routes))


def _review(tmp_path, comps):
    """A review file with one row per component uuid; returns the loaded items."""
    from vulnflow.triage import load_review

    rows = [
        {
            "team": "dev",
            "project": "app",
            "project_uuid": "P1",
            "component": f"pkg-{c}",
            "component_uuid": c,
            "vuln_id": "CVE-2024-10001",
            "vuln_uuid": "V1",
            "reason": "Debian tracker: fixed in 1.0",
        }
        for c in comps
    ]
    f = tmp_path / "review.json"
    f.write_text(json.dumps(rows), encoding="utf-8")
    return load_review(f)


def test_ignore_leaves_triaged_findings_alone_and_logs_what_it_replaced(tmp_path):
    from vulnflow.triage import apply_ignores, outstanding

    api = FakeAnalysisApi(
        {
            "C1": {"analysisState": "EXPLOITABLE", "isSuppressed": False},  # a human decided
            "C3": {"analysisState": "IN_TRIAGE", "isSuppressed": False},
        }
    )
    ledger = tmp_path / "data" / "ignored.jsonl"
    items = _review(tmp_path, ["C1", "C2", "C3"])

    written, _, kept, errors = apply_ignores(api.http(), items, "NOT_AFFECTED", ledger=ledger)
    assert errors == []
    assert [i.component_uuid for i in written] == ["C2"]  # nothing there before
    assert [(k.item.component_uuid, k.state) for k in kept] == [
        ("C1", "EXPLOITABLE"),
        ("C3", "IN_TRIAGE"),
    ]
    assert [p["component"] for p in api.puts] == ["C2"]  # the triaged ones were never written
    assert api.analyses["C1"]["analysisState"] == "EXPLOITABLE"

    # --overwrite replaces them, and the ledger remembers what was there
    written, _, kept, _ = apply_ignores(api.http(), items, "NOT_AFFECTED", overwrite=True, ledger=ledger)
    assert [i.component_uuid for i in written] == ["C1", "C3"] and kept == []  # C2 is already done
    prev = {r.component_uuid: (r.previous_state, r.previous_suppressed) for r in outstanding(ledger)}
    assert prev == {"C2": ("NOT_SET", False), "C1": ("EXPLOITABLE", False), "C3": ("IN_TRIAGE", False)}


def test_unignore_restores_the_previous_analysis_only_if_unchanged(tmp_path):
    from vulnflow.triage import apply_ignores, apply_reverts, outstanding, plan_reverts

    api = FakeAnalysisApi({"C1": {"analysisState": "IN_TRIAGE", "isSuppressed": True}})
    ledger = tmp_path / "ignored.jsonl"
    items = _review(tmp_path, ["C1", "C2", "C3"])
    apply_ignores(api.http(), items, "NOT_AFFECTED", overwrite=True, ledger=ledger)
    assert all(a["analysisState"] == "NOT_AFFECTED" and a["isSuppressed"] for a in api.analyses.values())

    # between ignore and undo, somebody changes C3 on their own
    api.analyses["C3"] = {"analysisState": "FALSE_POSITIVE", "isSuppressed": True}
    api.puts.clear()

    todo = plan_reverts(ledger)
    assert [(t.component_uuid, t.previous_state, t.previous_suppressed) for t in todo] == [
        ("C1", "IN_TRIAGE", True),
        ("C2", "NOT_SET", False),
        ("C3", "NOT_SET", False),
    ]
    reverted, skipped, errors = apply_reverts(api.http(), todo, ledger)
    assert errors == []
    assert [r.component_uuid for r in reverted] == ["C1", "C2"]
    assert [(i.component_uuid, why) for i, why in skipped] == [
        ("C3", "now FALSE_POSITIVE, suppressed: not as vulnflow left it (NOT_AFFECTED)")
    ]
    by_comp = {p["component"]: p for p in api.puts}
    assert by_comp["C1"] == {
        "project": "P1",
        "component": "C1",
        "vulnerability": "V1",
        "analysisState": "IN_TRIAGE",
        "comment": "Reverted via vulnflow: back to IN_TRIAGE (suppressed)",
        "isSuppressed": True,
    }
    assert (by_comp["C2"]["analysisState"], by_comp["C2"]["isSuppressed"]) == ("NOT_SET", False)
    assert "C3" not in by_comp and api.analyses["C3"]["analysisState"] == "FALSE_POSITIVE"
    assert [o.component_uuid for o in outstanding(ledger)] == ["C3"]  # only the untouched one is left

    # ignoring again after a revert counts once, with the latest previous state
    apply_ignores(api.http(), items[:1], "NOT_AFFECTED", overwrite=True, ledger=ledger)
    again = {o.component_uuid: o.previous_state for o in outstanding(ledger)}
    assert again == {"C3": "NOT_SET", "C1": "IN_TRIAGE"}

    # --forget-changed: C3's False Positive stands and it leaves the ledger; C1 is reverted
    api.puts.clear()
    todo = plan_reverts(ledger)
    reverted, skipped, errors = apply_reverts(api.http(), todo, ledger, forget_changed=True)
    assert errors == [] and [r.component_uuid for r in reverted] == ["C1"]
    assert [(i.component_uuid, why.endswith("; dropped from the ledger")) for i, why in skipped] == [
        ("C3", True)
    ]
    assert "C3" not in {p["component"] for p in api.puts}  # nothing written for it
    assert outstanding(ledger) == [] and plan_reverts(ledger) == []
    ops = [json.loads(line) for line in ledger.read_text().splitlines()]
    assert [(e["component_uuid"], e["found_state"]) for e in ops if e["op"] == "forget"] == [
        ("C3", "FALSE_POSITIVE")
    ]


def test_unignore_from_a_review_file_checks_the_vulnflow_comment(tmp_path):
    from vulnflow.triage import apply_ignores, apply_reverts, plan_reverts

    ledger = tmp_path / "none.jsonl"  # no ledger: these were ignored before it existed
    items = _review(tmp_path, ["C1", "C2"])
    api = FakeAnalysisApi()
    apply_ignores(
        api.http(), items[:1], "NOT_AFFECTED"
    )  # C1 written by vulnflow (comment has the marker)
    api.analyses["C2"] = {  # C2 set to the same state by a person
        "analysisState": "NOT_AFFECTED",
        "isSuppressed": True,
        "analysisComments": [{"comment": "not exposed, checked by hand"}],
    }
    api.puts.clear()
    todo = plan_reverts(ledger, items)
    assert [t.from_ledger for t in todo] == [False, False]
    reverted, skipped, _ = apply_reverts(api.http(), todo)
    assert [r.component_uuid for r in reverted] == ["C1"]
    assert [(i.component_uuid, why) for i, why in skipped] == [
        ("C2", "no comment ending 'via vulnflow': not written by vulnflow")
    ]

    # if DT returns no comment list at all the marker cannot be checked, so the state decides
    quiet = FakeAnalysisApi(
        {"C1": {"analysisState": "NOT_AFFECTED", "isSuppressed": True}}, comments=False
    )
    reverted, _, _ = apply_reverts(quiet.http(), plan_reverts(ledger, items[:1]))
    assert [r.component_uuid for r in reverted] == ["C1"]


def test_ledger_rejects_a_corrupt_line(tmp_path):
    from vulnflow.triage import ReviewFileError, outstanding

    ledger = tmp_path / "ignored.jsonl"
    ledger.write_text('{"op": "ignore", "project_uuid": "P1"}\n', encoding="utf-8")
    with pytest.raises(ReviewFileError, match="line 1"):
        outstanding(ledger)
    assert outstanding(tmp_path / "missing.jsonl") == []


def test_suggest_subscriptions_from_dt_components():
    from vulnflow.clients import DependencyTrack
    from vulnflow.subscriptions import suggest

    inv_text = TEAMS_TOML + '[teams.sysadm.opencve.products]\nlinux = ["linux_kernel"]\n'
    import tempfile

    with tempfile.TemporaryDirectory() as d:
        (Path(d) / "inv.toml").write_text(inv_text, encoding="utf-8")
        inv = load_inventory(Path(d) / "inv.toml")

    def comp(name, cpe, purl, classifier="LIBRARY"):
        return {"name": name, "cpe": cpe, "purl": purl, "classifier": classifier}

    cpe = "cpe:2.3:{}:*:*:*:*:*:*:*"
    projects = {
        "team-sysadm": [
            {"uuid": "h1", "name": "host:web1", "active": True},
            {"uuid": "h2", "name": "host:db1", "active": True},
            {"uuid": "old", "name": "host:gone", "active": False},
        ],
    }
    components = {
        "h1": [
            comp(
                "libssl3t64",
                cpe.format("a:libssl3t64:libssl3t64:3.5.4"),
                "pkg:deb/debian/libssl3t64@3.5.4",
            ),
            comp("nginx", cpe.format("a:nginx:nginx:1.27.4"), "pkg:deb/debian/nginx@1.27.4"),
            comp(
                "openssh-server",
                cpe.format("a:openssh:openssh:10.0"),
                "pkg:deb/debian/openssh-server@10.0",
            ),
            comp("linux_kernel", cpe.format("o:linux:linux_kernel:7.3.5"), "pkg:generic/linux@7.3.5"),
            comp("requests", cpe.format("a:psf:requests:2.32.3"), "pkg:pypi/requests@2.32.3"),
            comp("acl", "", "pkg:deb/debian/acl@2.3"),  # no CPE, not a known package
        ],
        "h2": [
            comp(
                "libssl3t64",
                cpe.format("a:libssl3t64:libssl3t64:3.5.4"),
                "pkg:deb/debian/libssl3t64@3.5.4",
            ),
            comp("libcrypto", cpe.format("a:openssl:libcrypto:3.5.4"), "", "APPLICATION"),
        ],
        "old": [comp("thing", cpe.format("a:ancient:thing:1"), "pkg:deb/debian/thing@1")],
    }

    def route(m, url, h, b):
        if "/project/tag/" in url:
            tag = url.split("/project/tag/")[1].split("?")[0]
            return Response(200, json.dumps(projects.get(tag, [])).encode(), {})
        uuid = url.split("/component/project/")[1].split("?")[0]
        return Response(200, json.dumps(components[uuid]).encode(), {})

    t = FakeTransport({"GET /api/v1/": route})
    dt = DependencyTrack("http://dt", "k", transport=t)
    out = suggest(inv, dt)
    assert any("/api/v1/component/project/h1?pageSize=100&pageNumber=1" in c[1] for c in t.calls)
    assert "not checked against OpenCVE (no OPENCVE_TOKEN): expect wrong names" in out
    # unchecked: syft's guesses and the known NVD names side by side; libssl3t64 is in both
    # projects, so its known name openssl:openssl comes first
    assert '# openssl = ["openssl", "libcrypto"]' in out
    for pair in ('# f5 = ["nginx"]', '# nginx = ["nginx"]', '# openbsd = ["openssh"]'):
        assert pair in out
    assert "requests" not in out and "linux_kernel" not in out and "ancient" not in out
    assert "# users: 0 projects tagged team-users, 0 candidates" in out
    assert "requests" in suggest(inv, dt, libraries=True)

    # with OpenCVE: ranked by projects, then CVEs; unknown names and ones without CVEs go
    from vulnflow.clients import OpenCVE

    counts = {
        ("openssl", "openssl"): 300,
        ("openssl", "libcrypto"): 0,
        ("f5", "nginx"): 40,
        ("nginx", "nginx"): 3,
        ("openbsd", "openssh"): 120,
    }

    def oc_route(m, url, h, b):
        vendor, product = url.split("/vendors/")[1].split("/cves")[0].split("/products/")
        n = counts.get((vendor, product))
        if n is None:
            return Response(404, b"{}", {})
        assert "page_size=1" in url
        return Response(200, json.dumps({"count": n, "results": []}).encode(), {})

    oc = OpenCVE("http://oc", "org", "tok", transport=FakeTransport({"GET /api/v2/vendors/": oc_route}))
    out = suggest(inv, dt, opencve=oc)
    lines = [ln for ln in out.splitlines() if ln.startswith("# ") and " = [" in ln]
    assert [ln.split(" = ")[0] for ln in lines] == ["# openssl", "# openbsd", "# f5", "# nginx"]
    assert lines[0].startswith(
        '# openssl = ["openssl"]   # openssl: 300 CVEs, 2 projects (host:db1, host:web1; deb)'
    )
    assert "left out: 2 names OpenCVE doesn't know, 1 with fewer than 1 CVEs (--list-skipped" in out
    listed = suggest(inv, dt, opencve=oc, list_skipped=True)
    assert "unknown: libssl3t64:libssl3t64, openssh:openssh" in listed
    assert "few CVEs: openssl:libcrypto (0)" in listed
    # --min-cves raises the bar
    assert "# nginx = " not in suggest(inv, dt, opencve=oc, min_cves=10)


def load_agent():
    import importlib.util

    spec = importlib.util.spec_from_file_location(
        "vulnflow_agent", ROOT / "scripts" / "vulnflow-agent.py"
    )
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def syft_doc(*pkgs: tuple[str, str], spec: str = "1.6") -> str:
    comps = [
        {
            "type": "library",
            "bom-ref": f"r-{n}",
            "name": n,
            "version": v,
            "purl": f"pkg:deb/debian/{n}@{v}",
        }
        for n, v in pkgs
    ]
    return json.dumps({"bomFormat": "CycloneDX", "specVersion": spec, "components": comps})


def test_machines_groups_overrides_and_defaults(tmp_path):
    _, m = load_estate(tmp_path)
    assert m.groups == {"servers": ["web1", "db1"], "laptops": ["mbp"]}
    web1, db1, mbp, lone = (m.hosts[h] for h in ("web1", "db1", "mbp", "lone"))
    assert (web1.group, web1.team, web1.kind, web1.scans) == (
        "servers",
        "sysadm",
        "linux",
        ["system", "containers"],
    )
    assert (db1.scans, db1.version, db1.group) == (["system"], "pinned-1", "servers")
    assert (mbp.kind, mbp.scans) == ("macos", ["brew", "languages", "apps"])
    assert (lone.group, lone.scans) == ("", ["system"])
    assert m.code["myapp"].host == "web1" and m.cpe_map == {"ripgrep": "burntsushi:ripgrep"}
    assert load_machines(tmp_path / "absent.toml", {}).hosts == {}


@pytest.mark.parametrize(
    "bad",
    [
        MACHINES_TOML.replace('hosts = ["mbp"]', 'hosts = ["mbp", "web1"]'),  # in two groups
        MACHINES_TOML.replace('team = "users"', 'team = "nope"'),
        MACHINES_TOML.replace('scans = ["system"]', 'scans = ["rm"]'),
        MACHINES_TOML.replace('version = "pinned-1"', 'ssh = "db1"'),  # pull-mode key is gone
        MACHINES_TOML.replace('host = "web1"', 'host = "ghost"'),
        MACHINES_TOML.replace('path = "/srv/myapp"', 'path = "srv/../x"'),
        MACHINES_TOML.replace("burntsushi:ripgrep", "no-colon"),
        MACHINES_TOML + '[hosts.x]\nteam = "dev"\nlanguage_paths = ["/etc"]\n',
        MACHINES_TOML + '[hosts.y]\ngroup = "nogroup"\nteam = "dev"\n',
        MACHINES_TOML + "[machines.old]\n",
    ],
)
def test_machines_validation(tmp_path, bad):
    with pytest.raises(SystemExit):
        load_estate(tmp_path, bad)


def test_agent_config_projects_and_tags(tmp_path):
    from vulnflow.machines import agent_config

    inv, m = load_estate(tmp_path)
    url = "https://vf.tail1.ts.net:8180"
    web1 = agent_config(m.hosts["web1"], m, inv, url)
    assert web1["vulnflow_agent_config"] == load_agent().CONFIG_FORMAT
    assert web1["host_project"] == {
        "name": "host:web1",
        "version": "",
        "tags": ["team-sysadm", "kind-host", "group-servers"],
        "scans": ["system"],
    }
    assert web1["containers"] == {"tags": ["team-dev", "kind-container", "host-web1"]}
    assert web1["code"] == [
        {
            "name": "code:myapp",
            "path": "/srv/myapp",
            "version": "",
            "tags": ["team-dev", "kind-app", "host-web1"],
        }
    ]
    assert web1["dt_url"] == url and web1["cpe_map"] == {"ripgrep": "burntsushi:ripgrep"}
    mbp = agent_config(m.hosts["mbp"], m, inv, url)
    assert mbp["host_project"]["tags"] == ["team-users", "kind-laptop", "group-laptops"]
    assert mbp["containers"] is None and mbp["code"] == []
    assert agent_config(m.hosts["lone"], m, inv, url)["host_project"]["tags"] == [
        "team-dev",
        "kind-host",
    ]


def test_agent_keys_per_host_team_keep_rotate_revoke():
    from vulnflow.bootstrap import DT_AGENT_PERMISSIONS, agent_key, dt_admin_http, revoke_agent

    dt = FakeDT(password=TEST_PW, force_change=False)
    admin = dt_admin_http("http://dt:8180", TEST_PW, transport=dt)
    k1, new1 = agent_key(admin, "web1")
    assert new1 and dt.keys[k1] == "agent-web1"
    assert {p["name"] for p in dt.teams["agent-web1"]["permissions"]} == set(DT_AGENT_PERMISSIONS)
    assert agent_key(admin, "web1", k1) == (k1, False)  # a working key is kept
    k2, new2 = agent_key(admin, "web1", k1, rotate=True)
    assert new2 and k2 != k1 and k1 not in dt.keys  # the old team and its keys are gone
    assert ("DELETE", "api/v1/team") in dt.calls
    k3, _ = agent_key(admin, "db1", k2)  # another host's key is not reused
    assert k3 != k2 and dt.keys[k3] == "agent-db1"
    assert revoke_agent(admin, "web1") and "agent-web1" not in dt.teams and k2 not in dt.keys
    assert not revoke_agent(admin, "web1")
    with pytest.raises(Exception, match="log in"):
        dt_admin_http("http://dt:8180", "wrong", transport=dt)


def test_maintenance_key_has_its_own_team_with_only_prune_permissions():
    from vulnflow.bootstrap import (
        DT_MAINTENANCE_PERMISSIONS,
        DT_MAINTENANCE_TEAM,
        dt_admin_http,
        maintenance_key,
    )

    dt = FakeDT(password=TEST_PW, force_change=False)
    admin = dt_admin_http("http://dt:8180", TEST_PW, transport=dt)
    k1, new1 = maintenance_key(admin)
    assert new1 and dt.keys[k1] == DT_MAINTENANCE_TEAM == "vulnflow-maintenance"
    assert (
        {p["name"] for p in dt.teams[DT_MAINTENANCE_TEAM]["permissions"]}
        == {
            "VIEW_PORTFOLIO",
            "VIEW_VULNERABILITY",
            "VULNERABILITY_ANALYSIS",
            "PORTFOLIO_MANAGEMENT",
        }
        == set(DT_MAINTENANCE_PERMISSIONS)
    )
    assert maintenance_key(admin, k1) == (k1, False)  # rerun of dt-bootstrap keeps it


def test_write_bundle_is_private(tmp_path):
    from vulnflow.machines import read_bundle_key, write_bundle

    d = write_bundle(tmp_path / "agents", "web1", {"host": "web1"}, "odt_k")
    assert json.loads((d / "config.json").read_text()) == {"host": "web1"}
    assert read_bundle_key(tmp_path / "agents", "web1") == "odt_k"
    assert read_bundle_key(tmp_path / "agents", "other") == ""
    assert (d.stat().st_mode & 0o777, (d / "key").stat().st_mode & 0o777) == (0o700, 0o600)
    assert (d / "config.json").stat().st_mode & 0o077 == 0


def test_last_pushes_and_stale_report(tmp_path, capsys):
    from vulnflow.machines import last_pushes, report

    _, m = load_estate(tmp_path)
    now = 1_800_000_000.0
    hosts = [
        {
            "uuid": "1",
            "name": "host:web1",
            "version": "debian-12",
            "lastBomImport": (now - 9 * 86400) * 1000,
        },
        {"uuid": "2", "name": "host:web1", "version": "debian-13", "lastBomImport": (now - 3600) * 1000},
        {
            "uuid": "3",
            "name": "host:db1",
            "version": "pinned-1",
            "lastBomImport": "2020-01-01T00:00:00Z",
        },
    ]
    t = FakeTransport(
        {"GET /api/v1/project/tag/kind-host": hosts, "GET /api/v1/project/tag/kind-laptop": []}
    )
    pushes = last_pushes(DependencyTrack("http://dt:8180", "odt_key", transport=t))
    assert pushes["host:web1"] == pytest.approx(now - 3600)  # newest version wins
    assert report(m, pushes, stale_days=2, now=now) == 3  # db1 old, mbp and lone never
    out = capsys.readouterr().out
    assert "[servers]" in out and "[no group]" in out
    assert "web1" in out and "ok last push 0.0 days ago" in out
    assert "STALE never pushed" in out
    assert report(m, None, stale_days=2) == 0  # DT not asked: list only


def test_agent_merge_keeps_every_file_location():
    a = load_agent()

    def stdlib(*paths):
        props = [{"name": "syft:package:foundBy", "value": "go-module-binary-cataloger"}]
        for i, p in enumerate(paths):
            props += [
                {"name": f"syft:location:{i}:path", "value": p},
                {"name": f"syft:location:{i}:layerID", "value": f"sha256:{i}"},
            ]
        return {"type": "library", "name": "stdlib", "version": "go1.24.4", "properties": props}

    docs = [
        {"specVersion": "1.6", "components": [stdlib("/usr/bin/podman")]},
        {"specVersion": "1.6", "components": [stdlib("/usr/bin/buildah", "/usr/bin/podman")]},
        {"specVersion": "1.6", "components": [stdlib("/usr/bin/skopeo")]},
    ]
    (c,) = a.merge_boms(docs)["components"]
    locs = {p["name"]: p["value"] for p in c["properties"] if p["name"].startswith("syft:location:")}
    assert locs == {
        "syft:location:0:path": "/usr/bin/podman",
        "syft:location:0:layerID": "sha256:0",
        "syft:location:1:path": "/usr/bin/buildah",  # renumbered after the kept one
        "syft:location:1:layerID": "sha256:0",
        "syft:location:2:path": "/usr/bin/skopeo",  # podman again was not repeated
        "syft:location:2:layerID": "sha256:0",
    }
    assert len(docs[0]["components"][0]["properties"]) == 3  # the input was not changed

    many = [{"specVersion": "1.6", "components": [stdlib(f"/bin/b{i}")]} for i in range(40)]
    (c,) = a.merge_boms(many)["components"]
    paths = [p for p in c["properties"] if p["name"].endswith(":path")]
    assert len(paths) == a.MAX_LOCATIONS


def test_agent_merge_brew_apps_and_images():
    a = load_agent()
    raw = (
        syft_doc(("curl", "8"), ("bash", "5")) + "\n" + syft_doc(("curl", "8"), ("git", "2"), spec="1.5")
    )
    docs = a.parse_docs(raw)
    merged = a.merge_boms(docs)
    assert merged["specVersion"] == "1.6"
    assert [c["name"] for c in merged["components"]] == ["curl", "bash", "git"]
    assert len({c["bom-ref"] for c in merged["components"]}) == 3
    with pytest.raises(a.ScanError):
        a.parse_docs("{} not json")

    info = {
        "formulae": [
            {"name": "python@3.12", "installed": [{"version": "3.12.7_1"}]},
            {"name": "ripgrep", "installed": [{"version": "14.1.1"}]},
            {"name": "curl", "installed": [{"version": "8.10.1"}]},
            {"name": "orphan", "installed": []},
        ],
        "casks": [{"token": "firefox", "installed": "131.0", "version": "132.0"}, {"token": "nover"}],
    }
    by = {
        (c["name"], c["version"]): c
        for c in a.brew_bom(info, {"ripgrep": "burntsushi:ripgrep"})["components"]
    }
    assert set(by) == {
        ("python@3.12", "3.12.7"),
        ("ripgrep", "14.1.1"),
        ("curl", "8.10.1"),
        ("firefox", "131.0"),
    }
    assert by[("python@3.12", "3.12.7")]["cpe"] == "cpe:2.3:a:python:python:3.12.7:*:*:*:*:*:*:*"
    assert by[("python@3.12", "3.12.7")]["purl"] == "pkg:generic/python%403.12@3.12.7"
    assert by[("ripgrep", "14.1.1")]["cpe"].startswith("cpe:2.3:a:burntsushi:ripgrep:14.1.1:")
    assert by[("curl", "8.10.1")]["cpe"].startswith("cpe:2.3:a:haxx:curl:")

    app = a.app_entry(
        {
            "CFBundleIdentifier": "com.google.Chrome",
            "CFBundleName": "Google Chrome",
            "CFBundleShortVersionString": "130.0.1",
        },
        {},
    )
    assert app["purl"] == "pkg:generic/com.google.Chrome@130.0.1"
    assert app["cpe"].startswith("cpe:2.3:a:google:chrome:130.0.1:")
    assert a.app_entry({"CFBundleIdentifier": "com.x.y", "CFBundleName": "Y"}, {}) is None
    docker = a.app_entry(
        {
            "CFBundleIdentifier": "com.docker.docker",
            "CFBundleName": "Docker",
            "CFBundleShortVersionString": "4.100.0",
        },
        {},
    )
    assert docker["cpe"].startswith("cpe:2.3:a:docker:desktop:4.100.0:")  # not docker:docker (Engine)

    assert a.split_image("ghcr.io/o/app:1.2") == ("ghcr.io/o/app", "1.2")
    assert a.split_image("localhost:5000/app") == ("localhost:5000/app", "latest")
    assert a.split_image("nginx@sha256:" + "a" * 64) == ("nginx", "sha256aaaaaaaaaaaa")


class FakeTools:
    """Stands in for the agent's run(): answers by tool and argument, records argv."""

    def __init__(self, answers: dict[str, tuple[int, str, str]]):
        self.answers = answers
        self.calls: list[list[str]] = []
        self.envs: list[dict[str, str] | None] = []

    def __call__(self, argv, timeout=1800, **kw):
        self.calls.append(list(argv))
        self.envs.append(kw.get("env"))
        tool = Path(argv[0]).name
        key = tool
        if tool == "syft":
            key = f"syft {argv[2]}"
        elif tool in ("docker", "podman"):
            key = f"{tool} {argv[1]}" + (f" as {kw['user']}" if "user" in kw else "")
        if key not in self.answers:
            raise AssertionError(f"unexpected command {argv}")
        return self.answers[key]


class FakeResponse:
    def __init__(self, body: bytes):
        self.body = body

    def __enter__(self) -> FakeResponse:
        return self

    def __exit__(self, *exc: object) -> None:
        return None

    def read(self) -> bytes:
        return self.body


class FakeUrlopen:
    def __init__(self):
        self.requests: list[Any] = []

    def __call__(self, req, timeout=None):
        self.requests.append(req)
        return FakeResponse(b'{"token": "tok-1"}')


def agent_files(tmp_path, cfg: dict) -> Path:
    d = tmp_path / "agent"
    d.mkdir()
    (d / "config.json").write_text(json.dumps(cfg), encoding="utf-8")
    (d / "key").write_text("odt_agentkey\n", encoding="utf-8")
    (d / "key").chmod(0o600)
    return d / "config.json"


def test_agent_pushes_host_containers_and_code(tmp_path, monkeypatch, capsys):
    from vulnflow.machines import agent_config

    a = load_agent()
    inv, m = load_estate(tmp_path)
    cfg_file = agent_files(tmp_path, agent_config(m.hosts["web1"], m, inv, "https://vf.ts.net:8180"))
    good = syft_doc(("openssl", "3.0.15"))
    tools = FakeTools(
        {
            "syft dir:/": (0, syft_doc(("libc6", "2.41")), ""),
            "docker --version": (0, "Docker version 29.1.0, build 1234567\n", ""),
            "docker ps": (0, "nginx:1.27\nbroken:1\nnginx:1.27\n", ""),
            "podman ps": (0, "docker.io/library/redis:7.4\nnginx:1.27\n", ""),
            "syft docker:nginx:1.27": (0, good, ""),
            "syft docker:broken:1": (1, "", "cannot pull"),
            "syft podman:docker.io/library/redis:7.4": (0, syft_doc(("redis", "7.4.2")), ""),
            "syft dir:/srv/myapp": (0, syft_doc(("django", "5.1")), ""),
            "git": (0, "v1.4.0\n", ""),
        }
    )
    monkeypatch.setattr(a, "run", tools)
    monkeypatch.setattr(a, "which", lambda tool: f"/usr/bin/{tool}")
    monkeypatch.setattr(a, "os_version", lambda: "debian-13")
    monkeypatch.setattr(a.sys, "platform", "linux")
    uname = os.uname_result(("Linux", "web1", "6.12.117+deb13-cloud-amd64", "#1", "x86_64"))
    monkeypatch.setattr(a.os, "uname", lambda: uname)
    opener = FakeUrlopen()
    monkeypatch.setattr(a.urllib.request, "urlopen", opener)

    assert a.main(["--config", str(cfg_file)]) == 1  # the broken image fails the run ...
    assert "FAIL  container:broken" in capsys.readouterr().out
    got = {}
    for req in opener.requests:
        assert (req.get_method(), req.full_url) == ("PUT", "https://vf.ts.net:8180/api/v1/bom")
        assert req.get_header("X-api-key") == "odt_agentkey"
        body = json.loads(req.data)
        assert body["autoCreate"] is True
        names = [c["name"] for c in json.loads(base64.b64decode(body["bom"]))["components"]]
        got[body["projectName"]] = (
            body["projectVersion"],
            [t["name"] for t in body["projectTags"]],
            names,
        )
    # ... but the host, the good image (scanned once) and the code were each uploaded to their owner
    assert got == {
        "host:web1": (
            "debian-13",
            ["team-sysadm", "kind-host", "group-servers"],
            ["libc6", "linux_kernel"],  # the running kernel isn't a package in this SBOM
        ),
        "container:nginx": ("1.27", ["team-dev", "kind-container", "host-web1"], ["openssl"]),
        "container:docker.io/library/redis": (
            "7.4",
            ["team-dev", "kind-container", "host-web1"],
            ["redis"],
        ),
        "code:myapp": ("v1.4.0", ["team-dev", "kind-app", "host-web1"], ["django"]),
    }
    # nginx runs under both runtimes: scanned once, from docker
    assert sum(c[2].endswith("nginx:1.27") for c in tools.calls if c[0].endswith("syft")) == 1
    calls = zip(tools.calls, tools.envs, strict=True)
    syft_env = [e for c, e in calls if c[0].endswith("syft")]
    assert syft_env and all(e and e["SYFT_FILE_METADATA_SELECTION"] == "none" for e in syft_env)
    system = next(c for c in tools.calls if c[:3] == ["/usr/bin/syft", "scan", "dir:/"])
    for x in ("./var/lib/containers/**", "./var/cache/**", "./root/.cache/**", "./usr/lib/modules/**"):
        assert x in system
    git = next(c for c in tools.calls if c[0].endswith("git"))
    assert git[1:3] == ["-c", "safe.directory=/srv/myapp"]


def test_agent_reports_syft_errors(monkeypatch):
    a = load_agent()
    # real stderr of syft 1.57.2 without -q (with -q it is empty)
    err = (
        "[0001]  WARN \x1b[33mslow registry\x1b[0m\n"
        "[0003] ERROR \x1b[31mcould not determine source: unable to load image: "
        "write /var/tmp/x/layer.tar: no space left on device\x1b[0m\n"
    )
    tools = FakeTools({"syft docker:big:1": (1, "", err)})
    monkeypatch.setattr(a, "run", tools)
    monkeypatch.setattr(a, "which", lambda tool: f"/usr/bin/{tool}")
    with pytest.raises(a.ScanError) as exc:
        a.syft("docker:big:1")
    assert str(exc.value) == (
        "syft docker:big:1 failed (1): could not determine source: unable to load image: "
        "write /var/tmp/x/layer.tar: no space left on device"
    )
    assert "-q" not in tools.calls[0]

    assert a.syft_error("") == "no error output"
    assert a.syft_error("panic: boom\ngoroutine 1\n") == "goroutine 1"
    long = a.syft_error("[0001] ERROR " + "x" * 500 + " no space left on device")
    assert len(long) == 400 and long.startswith("…") and long.endswith("no space left on device")


def test_agent_drops_files_and_handles_podman(monkeypatch):
    a = load_agent()
    doc = json.loads(syft_doc(("libc6", "2.41")))
    doc["components"].append({"type": "file", "name": "/usr/bin/ls", "bom-ref": "f1"})
    assert [c["name"] for c in a.merge_boms([doc])["components"]] == ["libc6"]

    # podman-docker's `docker` is podman: list podman once, not a docker daemon that isn't there
    tools = FakeTools(
        {
            "docker --version": (0, "podman version 5.4.2\n", ""),
            "podman ps": (0, "quay.io/x/app:2\n", ""),
            "syft podman:quay.io/x/app:2": (1, "", "cannot connect to podman socket"),
        }
    )
    monkeypatch.setattr(a, "run", tools)
    monkeypatch.setattr(a, "which", lambda tool: f"/usr/bin/{tool}")
    results, errors = a.collect_containers({"host": "h1", "containers": {"tags": []}})
    assert results == []
    assert errors == [
        "container:quay.io/x/app: syft podman:quay.io/x/app:2 failed (1): cannot connect to "
        "podman socket; " + a.PODMAN_SOCKET_HINT
    ]
    assert not any(c[:2] == ["/usr/bin/docker", "ps"] for c in tools.calls)

    # one runtime that can't be listed is reported; the other is still scanned
    tools = FakeTools(
        {
            "podman ps": (125, "", "permission denied"),
            "docker --version": (0, "Docker version 29.1.0\n", ""),
            "docker ps": (0, "nginx:1.27\n", ""),
            "syft docker:nginx:1.27": (0, syft_doc(("openssl", "3.0.15")), ""),
        }
    )
    monkeypatch.setattr(a, "run", tools)
    results, errors = a.collect_containers({"host": "h1", "containers": {"tags": []}})
    assert [r.project for r in results] == ["container:nginx"]
    assert errors == ["containers on h1: podman ps failed (125): permission denied"]

    monkeypatch.setattr(a, "which", lambda tool: None)
    with pytest.raises(a.ScanError, match="neither docker nor podman"):
        a.collect_containers({"host": "h1", "containers": {"tags": []}})


def test_agent_skips_every_forgejo_runner_container():
    a = load_agent()
    h = "ab" * 32
    runner = [
        f"FORGEJO-ACTIONS-TASK-7_WORKFLOW-{h}_JOB-build",  # job
        f"FORGEJO-ACTIONS-TASK-7-WORKFLOW-{h}-JOB-megalinter_STEP-lint",  # docker action step
        "FORGEJO-ACTIONS-TASK-7-WORKFLOW-abababababababababababababababababababa-" + h,  # service
        "GITEA-ACTIONS-TASK-3_WORKFLOW-x",
        f"WORKFLOW-{h}_JOB-test",  # plain act, no prefix
    ]
    kept = ["searxng", "paperless-db-dumper", "my-WORKFLOW-app", f"x{h}", "forgejo-runner"]
    assert [n for n in runner if not a.RUNNER_JOB_RE.search(n)] == []
    assert [n for n in kept if a.RUNNER_JOB_RE.search(n)] == []


def test_agent_rootless_podman_and_runner_jobs(tmp_path, monkeypatch):
    a = load_agent()
    pw = pwd.struct_passwd(("alice", "x", 1000, 1000, "", "/home/alice", "/bin/bash"))
    job = "FORGEJO-ACTIONS-TASK-7_WORKFLOW-" + "ab" * 32 + "_JOB-build"
    saved: list[Path] = []

    class Tools(FakeTools):
        def __call__(self, argv, timeout=1800, **kw):
            if argv[1:3] == ["image", "save"]:
                assert "-o" not in argv  # podman can't see the unit's private /var/tmp
                kw["stdout_file"].write(b"oci")
                saved.append(Path(kw["stdout_file"].name))
            return super().__call__(argv, timeout, **kw)

    tools = Tools(
        {
            "docker --version": (0, "Docker version 29.1.0\n", ""),
            "docker ps": (0, f"{job}\tnode:22\nweb\tnginx:1.27\n", ""),
            "podman ps": (0, "", ""),
            "podman ps as 1000": (0, "grafana\tdocker.io/grafana/grafana:12.3\nweb2\tnginx:1.27\n", ""),
            "podman image as 1000": (0, "", ""),
            "syft docker:nginx:1.27": (0, syft_doc(("openssl", "3.0.15")), ""),
        }
    )
    monkeypatch.setattr(a, "run", tools)
    monkeypatch.setattr(a, "which", lambda tool: f"/usr/bin/{tool}")
    monkeypatch.setattr(a, "rootless_podman_users", lambda: [pw])
    monkeypatch.setattr(a.pwd, "getpwnam", lambda name: pw)
    monkeypatch.setattr(a, "ARCHIVE_DIR", str(tmp_path))
    real_syft = a.syft

    def syft(target, extra=()):
        if target.startswith("oci-archive:"):
            assert Path(target.split(":", 1)[1]).read_text(encoding="utf-8") == "oci"
            return a.parse_docs(syft_doc(("grafana", "12.3.0")))
        return real_syft(target, extra)

    monkeypatch.setattr(a, "syft", syft)
    results, errors = a.collect_containers({"host": "h1", "containers": {"tags": []}})
    assert errors == []
    # the runner's job container is skipped; nginx (docker and alice) is scanned once, from docker
    got = {r.project: [c["name"] for c in r.sbom["components"]] for r in results}
    assert got == {"container:nginx": ["openssl"], "container:docker.io/grafana/grafana": ["grafana"]}
    save = next(c for c in tools.calls if c[1:3] == ["image", "save"])
    assert save[-1] == "docker.io/grafana/grafana:12.3"
    as_alice = [
        (c[1], e) for c, e in zip(tools.calls, tools.envs, strict=True) if e and e.get("USER") == "alice"
    ]
    assert [what for what, _ in as_alice] == ["ps", "image"]
    for _, env in as_alice:
        assert env["XDG_RUNTIME_DIR"] == "/run/user/1000" and env["HOME"] == "/home/alice"
    assert saved and not saved[0].parent.exists()  # the archive dir is removed afterwards
    # syft unpacks images under ARCHIVE_DIR (on disk), not a tmpfs /tmp, and cleans up
    calls = zip(tools.calls, tools.envs, strict=True)
    syft_tmp = [Path(e["TMPDIR"]) for c, e in calls if c[0].endswith("syft") and e]
    assert syft_tmp and all(d.parent == tmp_path and not d.exists() for d in syft_tmp)


def deb(name: str, version: str, upstream: str = "") -> dict:
    q = f"&upstream={upstream}" if upstream else ""
    purl = f"pkg:deb/debian/{name.replace('+', '%2B')}@{version}?arch=amd64&distro=debian-13{q}"
    return {"type": "library", "name": name, "version": version, "purl": purl}


def test_agent_gives_the_images_own_go_binary_the_image_tag_as_version():
    a = load_agent()

    def comp(
        name, version="UNKNOWN", main=None, purl=None, cpe="cpe:2.3:a:grafana:grafana:*:*:*:*:*:*:*:*"
    ):
        props = [{"name": "syft:package:type", "value": "go-module"}]
        if main:
            props.append({"name": "syft:metadata:mainModule", "value": main})
        return {
            "type": "library",
            "name": name,
            "version": version,
            "cpe": cpe,
            "purl": purl or f"pkg:golang/{name}",
            "properties": props,
        }

    grafana = "github.com/grafana/grafana"
    doc = {
        "components": [
            comp(grafana, main=grafana),  # the image's own binary: gets the tag
            comp(f"{grafana}/apps/advisor", main=grafana),  # a sub-module, not the main one
            comp("github.com/other/tool", main="github.com/other/tool"),  # another binary
            comp(grafana, version="v1.0.0", main=grafana),  # already has a version
            {"type": "library", "name": "grafana", "version": "UNKNOWN", "purl": "pkg:npm/grafana"},
        ]
    }
    out = a.version_from_tag([doc], "docker.io/grafana/grafana", "13.3.1")[0]["components"]
    assert (out[0]["version"], out[0]["purl"], out[0]["cpe"]) == (
        "13.3.1",
        "pkg:golang/github.com/grafana/grafana@13.3.1",
        "cpe:2.3:a:grafana:grafana:13.3.1:*:*:*:*:*:*:*",
    )
    assert {"name": "vulnflow:version-from", "value": "image-tag"} in out[0]["properties"]
    assert out[1:] == doc["components"][1:]  # nothing else touched
    assert doc["components"][0]["version"] == "UNKNOWN"  # the input is not modified
    for tag in ("latest", "trixie", "13.3", "v2.4.1"):  # only release tags count
        changed = a.version_from_tag([doc], "docker.io/grafana/grafana", tag)[0]["components"][0]
        assert (changed["version"] != "UNKNOWN") == (tag in ("13.3", "v2.4.1")), tag
    # qualifiers stay after the version
    q = comp(grafana, main=grafana, purl=f"pkg:golang/{grafana}?type=module", cpe="")
    out = a.version_from_tag([{"components": [q]}], "ghcr.io/grafana/grafana", "13.3.1")[0]
    assert out["components"][0]["purl"] == f"pkg:golang/{grafana}@13.3.1?type=module"
    assert out["components"][0]["cpe"] == ""


def test_agent_reports_a_container_whose_image_was_removed(monkeypatch):
    a = load_agent()

    def no_syft(*args, **kw):
        raise AssertionError("syft must not be asked to pull an image ID")

    monkeypatch.setattr(a, "syft", no_syft)
    for ref in (
        "05c8f9d91118",
        "sha256:" + "05c8f9d9111801716fd2237471586256d8ae62d6c159b756701669f3fcc4d716",
    ):
        with pytest.raises(a.ScanError, match="recreate the container"):
            a.scan_image("docker", ref)
    seen: list[str] = []

    def fake_syft(target, *extra):
        seen.append(target)
        return []

    monkeypatch.setattr(a, "syft", fake_syft)
    a.scan_image("docker", "opencve-airflow-worker:latest")  # a name, even an odd one: scanned
    a.scan_image("docker", "deadbeefcafe/app:1")
    assert seen == ["docker:opencve-airflow-worker:latest", "docker:deadbeefcafe/app:1"]


def test_agent_drops_pypi_copies_of_apt_python_packages():
    a = load_agent()

    def comp(purl, *paths):
        props = [{"name": f"syft:location:{i}:path", "value": p} for i, p in enumerate(paths)]
        return {
            "type": "library",
            "name": purl.split("/")[-1].split("@")[0],
            "purl": purl,
            "properties": props,
        }

    apt = "/usr/lib/python3/dist-packages/urllib3-2.3.0.dist-info/METADATA"
    doc = {
        "components": [
            comp("pkg:pypi/urllib3@2.3.0", apt),  # apt's python3-urllib3, seen as PyPI: dropped
            comp(
                "pkg:deb/debian/python3-urllib3@2.3.0-3%2Bdeb13u2?distro=debian-13",
                "/var/lib/dpkg/status",
            ),
            comp(
                "pkg:pypi/requests@2.32.5",
                "/usr/local/lib/python3.13/dist-packages/requests-2.32.5.dist-info/METADATA",
            ),
            comp(
                "pkg:pypi/rich@14.0.0",
                "/opt/app/.venv/lib/python3.13/site-packages/rich-14.0.0.dist-info/METADATA",
            ),
            comp(
                "pkg:pypi/idna@3.10",
                apt.replace("urllib3-2.3.0", "idna-3.10"),
                "/opt/app/vendor/idna/METADATA",
            ),
            comp("pkg:pypi/nolocation@1.0"),  # no path: kept
            # syft 1.57.2 on `dir:/` writes root-relative paths: still apt's copy, dropped
            comp("pkg:pypi/pyjwt@2.10.1", apt.replace("urllib3-2.3.0", "pyjwt-2.10.1")[1:]),
            comp(
                "pkg:pypi/pillow@11.1.0",
                "./usr/lib/python3/dist-packages/pillow-11.1.0.egg-info/PKG-INFO",
            ),
            # relative, but not apt's directory: kept
            comp(
                "pkg:pypi/rich@13.0.0",
                "opt/app/.venv/lib/python3.13/site-packages/rich-13.0.0.dist-info/METADATA",
            ),
        ]
    }
    kept = [c["purl"] for c in a.no_apt_python_copies([doc])[0]["components"]]
    assert kept == [
        "pkg:deb/debian/python3-urllib3@2.3.0-3%2Bdeb13u2?distro=debian-13",
        "pkg:pypi/requests@2.32.5",  # pip as root on Debian
        "pkg:pypi/rich@14.0.0",  # a venv
        "pkg:pypi/idna@3.10",  # also found outside apt's directory
        "pkg:pypi/nolocation@1.0",
        "pkg:pypi/rich@13.0.0",
    ]
    assert len(doc["components"]) == 9  # the input is not modified


def test_agent_tracks_only_the_running_kernel():
    a = load_agent()
    pkgs = [
        deb("libc6", "2.41-12"),
        deb("linux-base", "4.12.1"),  # not from the kernel source: kept
        deb("linux-image-6.12.116+deb13-cloud-amd64", "6.12.116-1", "linux-signed-amd64%406.12.116%2B1"),
        deb("linux-image-6.12.117+deb13-cloud-amd64", "6.12.117-1", "linux-signed-amd64%406.12.117%2B1"),
        deb("linux-headers-6.12.117+deb13-cloud-amd64", "6.12.117-1", "linux"),
        deb("linux-image-cloud-amd64", "6.12.117-1", "linux-signed-amd64%406.12.117%2B1"),
        deb("linux-libc-dev", "6.12.117-1", "linux"),
        # syft's entries from /boot/vmlinuz-*: dropped whatever runs
        {
            "name": "linux-kernel",
            "version": "6.12.117+deb13-cloud-amd64",
            "purl": "pkg:generic/linux-kernel@6.12.117%2Bdeb13-cloud-amd64",
        },
        {"name": "linux-kernel", "version": "7.3.5", "purl": "pkg:generic/linux-kernel@7.3.5"},
    ]

    def names(docs):
        return [c["name"] for d in docs for c in d["components"]]

    # booted the Debian kernel: only its image and headers stay
    got = a.running_kernel_only([a.bom(list(pkgs))], "6.12.117+deb13-cloud-amd64")
    assert names(got) == [
        "libc6",
        "linux-base",
        "linux-image-6.12.117+deb13-cloud-amd64",
        "linux-headers-6.12.117+deb13-cloud-amd64",
    ]
    # booted a self-built kernel: every Debian kernel goes, the running one is added by CPE
    got = a.running_kernel_only([a.bom(list(pkgs))], "7.3.5-hardened1")
    assert names(got) == ["libc6", "linux-base", "linux_kernel"]
    kernel = got[-1]["components"][0]
    assert kernel["version"] == "7.3.5"
    assert kernel["cpe"] == "cpe:2.3:o:linux:linux_kernel:7.3.5:*:*:*:*:*:*:*"
    # a container has no kernel: linux-libc-dev and friends are dropped
    assert names(a.no_kernel_packages([a.bom(list(pkgs))])) == ["libc6", "linux-base"]


def test_agent_host_project_is_all_or_nothing(tmp_path, monkeypatch, capsys):
    a = load_agent()
    cfg = {
        "vulnflow_agent_config": 1,
        "host": "mbp",
        "dt_url": "https://vf.ts.net:8180",
        "host_project": {
            "name": "host:mbp",
            "version": "",
            "tags": ["team-users"],
            "scans": ["brew", "languages"],
        },
        "containers": None,
        "code": [],
        "language_paths": ["tools"],
        "cpe_map": {},
    }
    cfg_file = agent_files(tmp_path, cfg)
    monkeypatch.setattr(a.Path, "home", staticmethod(lambda: tmp_path))
    (tmp_path / "tools").mkdir()
    opener = FakeUrlopen()
    monkeypatch.setattr(a.urllib.request, "urlopen", opener)
    monkeypatch.setattr(a, "os_version", lambda: "macos-27.2")
    which = {"syft": "/opt/homebrew/bin/syft"}
    monkeypatch.setattr(a, "which", which.get)  # no brew, no npm

    # no Homebrew is "nothing to scan" for brew; languages still worked -> upload
    monkeypatch.setattr(
        a,
        "run",
        FakeTools({"syft dir:" + str(tmp_path / "tools"): (0, syft_doc(("black", "25.1")), "")}),
    )
    assert a.main(["--config", str(cfg_file)]) == 0
    assert "skipped brew (Homebrew not found)" in capsys.readouterr().out
    assert len(opener.requests) == 1

    # a failing scan means no upload at all for the host project
    monkeypatch.setattr(a, "run", FakeTools({"syft dir:" + str(tmp_path / "tools"): (1, "", "boom")}))
    assert a.main(["--config", str(cfg_file)]) == 1
    assert "FAIL  host:mbp" in capsys.readouterr().out and len(opener.requests) == 1

    # --dry-run scans but neither reads the key nor uploads
    (tmp_path / "agent" / "key").unlink()
    monkeypatch.setattr(
        a,
        "run",
        FakeTools({"syft dir:" + str(tmp_path / "tools"): (0, syft_doc(("black", "25.1")), "")}),
    )
    assert a.main(["--config", str(cfg_file), "--dry-run"]) == 0
    assert "plan  host:mbp@macos-27.2" in capsys.readouterr().out and len(opener.requests) == 1


def test_agent_rejects_bad_config(tmp_path):
    a = load_agent()
    f = tmp_path / "c.json"
    for bad in ({"host": "x"}, {"vulnflow_agent_config": 1, "dt_url": "file:///etc/passwd"}):
        f.write_text(json.dumps(bad), encoding="utf-8")
        with pytest.raises(SystemExit):
            a.load_config(f)


# --- check-updates (vulnflow/upstreams.py) ---------------------------------------------


def _rel(tag: str, day: str, *, pre: bool = False, draft: bool = False) -> dict[str, Any]:
    return {"tag_name": tag, "published_at": f"{day}T12:00:00Z", "prerelease": pre, "draft": draft}


UPSTREAM_ROUTES: dict[str, object] = {
    "GET DefectDojo/django-DefectDojo/releases": [
        _rel("3.5.300", "2026-11-24"),
        _rel("nightly-dev", "2025-05-24", pre=True),
        _rel("3.5.202", "2026-11-12"),
        _rel("3.5.201", "2026-11-10"),
        _rel("3.5.200", "2026-11-08"),
    ],
    "GET opencve/opencve/releases": [_rel("v3.1.0", "2026-08-14"), _rel("v3.0.0", "2026-06-24")],
    "GET DependencyTrack/dependency-track/releases": [
        _rel("4.14.9", "2026-11-01"),
        _rel("5.2.3", "2026-11-22"),
        _rel("5.2.2", "2026-11-10"),
        _rel("5.3.0-rc.1", "2026-11-01", pre=True),
    ],
    "GET valkey-io/valkey/releases": [
        _rel("9.2.0", "2026-11-19"),
        _rel("9.1.4", "2026-11-18"),
        _rel("9.0.8", "2026-11-18"),
        _rel("8.1.12", "2026-11-18"),
        _rel("9.1.3", "2026-10-26"),
    ],
}


def _upstream_root(tmp_path: Path, running_dd: str) -> tuple[Path, Path]:
    (tmp_path / "stacks/dependency-track").mkdir(parents=True)
    (tmp_path / "stacks/dependency-track/docker-compose.yml").write_text(
        "services:\n  apiserver:\n    image: ghcr.io/dependencytrack/apiserver:5.2.2\n"
    )
    (tmp_path / ".env.example").write_text("DD_REF=3.5.201\nOPENCVE_REF=v3.1.0\n")
    (tmp_path / "stacks/defectdojo").mkdir(parents=True)
    (tmp_path / "stacks/defectdojo/override.yml").write_text(
        "services:\n  valkey:\n    <<: *restart\n"
        "    image: valkey/valkey:9.1.4-alpine@sha256:" + "a" * 64 + "\n"
    )
    env_file = tmp_path / ".env"
    env_file.write_text(f"DD_REF='{running_dd}'\nOPENCVE_REF=v3.1.0\n")
    return tmp_path, env_file


def test_image_tag_and_version() -> None:
    from vulnflow.upstreams import image_tag, image_version

    digest = "@sha256:" + "b" * 64
    assert image_tag("valkey/valkey:9.1.2-alpine" + digest) == "9.1.2-alpine"
    assert image_tag("localhost:5000/redis") == ""  # a registry port is not a tag
    assert image_tag("ghcr.io/dependencytrack/apiserver:5.2.2") == "5.2.2"
    assert (image_version("9.1.4-alpine"), image_version("v1.2"), image_version("latest")) == (
        "9.1.4",
        "v1.2",
        "",
    )


def test_upstream_releases_skip_prereleases_drafts_and_odd_tags() -> None:
    from vulnflow.upstreams import releases

    t = FakeTransport(
        {
            "GET x/y/releases": [
                _rel("1.2.0", "2026-01-02"),
                _rel("1.3.0", "2026-01-03", draft=True),
                _rel("1.4.0-rc1", "2026-01-04", pre=True),
                _rel("latest", "2026-01-05"),
                _rel("1.10.0", "2026-01-06"),
            ]
        }
    )
    assert [r.tag for r in releases("x/y", transport=t)] == ["1.10.0", "1.2.0"]
    assert t.calls[0][1] == "https://api.github.com/repos/x/y/releases?per_page=50"


def test_check_updates_cooldown_ready_and_major_line(tmp_path: Path) -> None:
    from datetime import UTC, datetime

    from vulnflow.upstreams import check, report

    root, env_file = _upstream_root(tmp_path, running_dd="3.5.200")
    now = datetime(2026, 11, 24, 18, 0, tzinfo=UTC)
    running_valkey = "9.1.2-alpine"
    statuses = check(root, env_file, FakeTransport(UPSTREAM_ROUTES), now, "5.2.2", running_valkey)
    st = {s.component.name: s for s in statuses}

    dojo = st["dojo"]
    assert (dojo.running, dojo.pinned) == ("3.5.200", "3.5.201")
    assert dojo.upstream and dojo.upstream.tag == "3.5.202"  # 3.5.300 is 0 days old
    assert dojo.waiting and dojo.waiting.tag == "3.5.300"
    text = "\n".join(dojo.lines())
    assert "UPDATE 3.5.202" in text and "bump DD_REF in .env.example" in text
    assert "READY  3.5.201 is pinned: ./poc.sh upgrade dojo" in text
    assert "3.5.300 (cooldown until 2026-12-01)" in text

    assert not st["opencve"].actionable  # v3.1.0 everywhere
    assert st["opencve"].lines() == ["OpenCVE: running v3.1.0, pinned v3.1.0"]

    dt = st["dtrack"]  # 4.x line ignored; 5.2.3 still in the cooldown
    assert dt.pinned == "5.2.2" and dt.upstream and dt.upstream.tag == "5.2.2"
    assert dt.waiting and dt.waiting.tag == "5.2.3"
    assert not dt.actionable

    vk = st["valkey"]  # variant and digest stripped; 9.1.4 and 9.2.0 still in the cooldown
    assert (vk.running, vk.pinned) == ("9.1.2", "9.1.4")
    assert vk.upstream and vk.upstream.tag == "9.1.3"
    assert vk.waiting and vk.waiting.tag == "9.2.0"  # same major; 8.1.12 ignored
    assert vk.lines() == [
        "Valkey (DefectDojo): running 9.1.2, pinned 9.1.4",
        "  READY  9.1.4 is pinned: ./poc.sh dojo-up",
        "  new    9.2.0 (cooldown until 2026-11-26)",
    ]
    assert "Nothing to do." not in report(list(st.values()))


def test_check_updates_nothing_to_do_and_errors(tmp_path: Path) -> None:
    from datetime import UTC, datetime

    from vulnflow.upstreams import check, report

    root, env_file = _upstream_root(tmp_path, running_dd="3.5.201")
    (root / ".env.example").write_text("DD_REF=3.5.202\nOPENCVE_REF=v3.1.0\n")
    env_file.write_text("DD_REF=3.5.202\nOPENCVE_REF=v3.1.0\n")
    now = datetime(2026, 11, 20, tzinfo=UTC)  # 3.5.202 and 5.2.3 not out of cooldown / released
    routes = dict(UPSTREAM_ROUTES)
    vk = "9.1.4-alpine@sha256:" + "a" * 64
    out = report(check(root, env_file, FakeTransport(routes), now, "5.2.2", vk))
    assert out.endswith("Nothing to do."), out

    routes["GET valkey-io/valkey/releases"] = [_rel("9.1.5", "2026-11-01")]  # ready: bump it
    out = report(check(root, env_file, FakeTransport(routes), now, "5.2.2", vk))
    assert "  UPDATE 9.1.5 released 2026-11-01: bump the valkey image (tag and digest) in " in out
    routes["GET valkey-io/valkey/releases"] = UPSTREAM_ROUTES["GET valkey-io/valkey/releases"]

    routes["GET opencve/opencve/releases"] = Response(500, b"boom", {})
    out = report(check(root, env_file, FakeTransport(routes), now, "5.2.2", vk))
    assert "OpenCVE: running v3.1.0, pinned v3.1.0\n  ERROR  release check failed:" in out
    assert "Nothing to do." not in out


# ---- report ------------------------------------------------------------------------------


def _dt_finding(comp: str, version: str, vuln: str, severity: str, suppressed: bool = False) -> dict:
    return {
        "component": {"uuid": f"c-{comp}", "name": comp, "version": version},
        "vulnerability": {"uuid": f"v-{vuln}", "vulnId": vuln, "source": "NVD", "severity": severity},
        "analysis": {"isSuppressed": suppressed},
    }


def _report_portfolio() -> FakePortfolio:
    def proj(uuid, name, version, tag, active=True):
        return {
            "uuid": uuid,
            "name": name,
            "version": version,
            "active": active,
            "tags": [{"name": tag}, {"name": "kind-host"}],
            "lastBomImport": 1_800_000_000_000,
        }

    return FakePortfolio(
        [
            proj("p1", "host:web01", "debian-13", "team-sysadm"),
            proj("p2", "container:grafana", "13.3.1", "team-dev"),
            proj("p3", "container:grafana", "13.3.0", "team-dev", active=False),
        ],
        {
            "p1": [
                _dt_finding("openssl", "3.5.1", "CVE-2026-0001", "HIGH"),
                _dt_finding("curl", "8.14.1", "CVE-2026-0002", "LOW"),
                _dt_finding("perl", "5.40", "CVE-2026-0003", "CRITICAL", suppressed=True),
            ],
            "p2": [_dt_finding("grafana", "13.3.1", "CVE-2026-0004", "MEDIUM")],
            "p3": [_dt_finding("grafana", "13.3.0", "CVE-2026-0009", "CRITICAL")],
        },
    )


def test_report_findings_baseline_then_new_resolved_and_kev(inv):
    from vulnflow import report as rp

    fake = _report_portfolio()
    dt = DependencyTrack("http://dt", "k", transport=fake)
    errors: list[str] = []
    first = rp.collect_findings(inv, dt, errors)
    assert errors == []
    # suppressed findings and inactive project versions are left out; keys carry no versions
    assert sorted(first) == [
        "dev|container:grafana|grafana|CVE-2026-0004",
        "sysadm|host:web01|curl|CVE-2026-0002",
        "sysadm|host:web01|openssl|CVE-2026-0001",
    ]
    base = rp.findings_section(None, first, set(), weekly=False)
    assert "baseline of 3 open findings" in base.text() and not base.notable

    saved = json.loads(json.dumps({k: f.to_json() for k, f in first.items()}))
    # a new package version with the same CVE is not new; curl fixed; two new ones
    fake.findings["p1"] = [
        _dt_finding("openssl", "3.5.2", "CVE-2026-0001", "HIGH"),
        _dt_finding("zlib", "1.3", "CVE-2026-0005", "LOW"),
        _dt_finding("sudo", "1.9", "CVE-2026-0006", "CRITICAL"),
    ]
    fake.findings["p2"].append(_dt_finding("grafana", "13.3.1", "CVE-2026-0007", "MEDIUM"))
    now = rp.collect_findings(inv, dt, errors)
    daily = rp.findings_section(saved, now, {"CVE-2026-0007"}, weekly=False)
    assert daily.notable
    para, table = daily.blocks
    assert isinstance(para, rp.Para) and isinstance(table, rp.Table)
    assert para.text == (
        "**3** new, **1** resolved or suppressed since the last daily report; "
        "**2** new critical/high/KEV."
    )
    # KEV first, then by severity; the LOW one is only counted (weekly)
    assert table.rows == [
        ["medium", "`CVE-2026-0007`", "**KEV**", "`grafana` 13.3.1", "`container:grafana@13.3.1`"],
        ["critical", "`CVE-2026-0006`", "", "`sudo` 1.9", "`host:web01@debian-13`"],
    ]

    weekly = rp.findings_section(saved, now, set(), weekly=True)
    per_team = weekly.blocks[-1]
    assert isinstance(per_team, rp.Table)
    assert per_team.header == [
        "Team",
        "Open",
        "critical",
        "high",
        "medium",
        "low",
        "Other new",
        "Resolved",
    ]
    assert per_team.rows == [
        ["dev", "2", "0", "0", "2", "0", "1", "0"],
        ["sysadm", "3", "1", "1", "0", "1", "1", "1"],
    ]


def test_report_alerts_since_last_run_best_tier_per_team_and_cve():
    from vulnflow.report import Para, Table, alerts_section

    def line(at, cve, tier, team="sysadm", **kw):
        return json.dumps(
            {"received_at": at, "cve": cve, "team": team, "tier": tier, "tier_name": f"P{tier}", **kw}
        )

    log_lines = [
        line("2026-11-24T10:00:00Z", "CVE-2021-44228", 1, cvss31=10.0, kev=True, epss=0.97),
        line("2026-11-25T08:00:00Z", "CVE-2026-1111", 2, cvss31=8.1),
        line("2026-11-25T09:00:00Z", "CVE-2026-1111", 1, cvss31=8.1, kev=True, epss=0.5),
        line("2026-11-25T09:30:00Z", "CVE-2026-2222", 3, cvss31=5.0),
        "not json",
        "",
    ]
    sec, newest = alerts_section(log_lines, "2026-11-24T12:00:00Z")
    assert newest == "2026-11-25T09:30:00Z"
    assert sec.notable
    (table,) = sec.blocks
    assert isinstance(table, Table)
    assert table.rows == [["**P1**", "`CVE-2026-1111`", "sysadm", "8.1", "**KEV**", "0.500"]]
    quiet, newest2 = alerts_section(log_lines, newest)
    assert (quiet.notable, quiet.blocks, newest2) == (False, [Para("None.")], newest)


def test_report_machines_and_updates_sections(tmp_path, inv):
    from vulnflow.report import Items, Para, Table, machines_section, updates_section
    from vulnflow.upstreams import COMPONENTS, Release, Status

    mf = tmp_path / "machines.toml"
    mf.write_text(
        '[groups.servers]\nhosts = ["web01", "db01", "new01"]\n'
        '[hosts.web01]\nteam = "sysadm"\nscans = ["system"]\n'
        '[hosts.db01]\nteam = "sysadm"\nscans = ["system"]\n'
        '[hosts.new01]\nteam = "sysadm"\nscans = ["system"]\n'
    )
    machines = load_machines(mf, inv.teams)
    now = 1_800_000_000.0
    pushes = {"host:web01": now - 3600, "host:db01": now - 5 * 86400}
    sec = machines_section(machines, pushes, 2, now=now)
    assert sec.notable
    assert sec.blocks == [
        Table(
            ["Host", "Team", "Last push"],
            [["`db01`", "sysadm", "5.0 days ago"], ["`new01`", "sysadm", "never"]],
        )
    ]

    from datetime import UTC, datetime

    dojo, opencve = COMPONENTS[0], COMPONENTS[1]
    rel = Release("3.5.300", datetime(2026, 11, 24, tzinfo=UTC))
    statuses = [
        Status(dojo, "3.5.201", "3.5.201", rel, None),
        Status(opencve, "v3.1.0", "v3.1.0", None, None),
    ]
    daily = updates_section(statuses, everything=False)
    assert daily.notable
    assert daily.blocks[0] == Para("**DefectDojo**: running 3.5.201, pinned 3.5.201")
    assert isinstance(daily.blocks[1], Items) and daily.blocks[1].items[0].startswith(
        "UPDATE 3.5.300 released"
    )
    assert "OpenCVE" not in daily.text()
    weekly = updates_section(statuses, everything=True)
    assert Para("**OpenCVE**: running v3.1.0, pinned v3.1.0") in weekly.blocks
    calm = updates_section(statuses[1:], everything=False)
    assert (calm.notable, calm.blocks) == (False, [Para("Nothing to do.")])


def test_report_markdown_html_and_mime_render_the_same_sections():
    from datetime import UTC, datetime
    from email import message_from_string, policy

    from vulnflow.report import (
        Items,
        Para,
        Section,
        Table,
        error_section,
        mime_message,
        render_html,
        render_markdown,
    )

    now = datetime(2026, 11, 25, 6, 30, tzinfo=UTC)
    sections = [
        Section(
            "Findings <new>",
            [
                Para("**2** new"),
                Table(["CVE", "Component"], [["`CVE-1`", "a|b <script>"], ["`CVE-2`", ""]]),
                Items(["READY 3.5.300 is pinned"]),
            ],
            notable=True,
        ),
        error_section("Hosts", "Dependency-Track: refused"),
    ]
    md = render_markdown("daily", sections, now)
    assert md.startswith(
        "# vulnflow daily report, 2026-11-25 06:30 UTC\n\n## Findings <new>\n\n**2** new\n"
    )
    assert "| CVE | Component |\n| --- | --- |\n| `CVE-1` | a\\|b <script> |\n| `CVE-2` |   |" in md
    assert "- READY 3.5.300 is pinned" in md and "## Hosts (ERROR)" in md

    page = render_html("daily", sections, now)
    assert "<script>" not in page and "&lt;script&gt;" in page
    assert "Findings &lt;new&gt;" in page and "<strong>2</strong> new" in page
    assert ">CVE-1</code>" in page and "<li>READY 3.5.300 is pinned</li>" in page

    msg = mime_message("daily", sections, "ops@example.org", "vulnflow", now)
    parsed = message_from_string(msg.as_string(), policy=policy.default)
    assert parsed["To"] == "ops@example.org"
    assert parsed["Subject"] == "vulnflow daily report (vulnflow): errors"
    assert parsed.get_content_type() == "multipart/alternative"
    plain = parsed.get_body(preferencelist=("plain",))
    rich = parsed.get_body(preferencelist=("html",))
    assert plain is not None and rich is not None
    assert plain.get_content() == md
    assert rich.get_content() == page


def test_report_command_saves_state_and_daily_is_quiet_without_news(tmp_path, monkeypatch, capsys):
    import vulnflow.__main__ as vf
    import vulnflow.upstreams as up

    fake = _report_portfolio()
    monkeypatch.setattr(
        vf, "DependencyTrack", lambda url, key: DependencyTrack(url, key, transport=fake)
    )
    monkeypatch.setattr(up, "check", lambda root, env_file: [])
    env_file = tmp_path / ".env"
    env_file.write_text(f"DT_API_KEY={secrets.token_hex(8)}\nDT_URL=http://dt\nVULNFLOW_ENRICH_KEV=0\n")
    alerts = tmp_path / "alerts.jsonl"
    alerts.write_text("")
    args = [
        "--env-file", str(env_file),
        "--inventory", str(INV),
        "--machines", str(tmp_path / "none.toml"),
        "--data-dir", str(tmp_path / "data"),
        "report",
    ]  # fmt: skip
    assert vf.main([*args, "daily", "--alerts", str(alerts), "--quiet"]) == 0
    assert capsys.readouterr().out == ""  # first run: baseline only
    state_file = tmp_path / "data" / "report-state.json"
    assert oct(state_file.stat().st_mode & 0o777) == "0o600"
    state = json.loads(state_file.read_text())
    assert len(state["daily"]["findings"]) == 3 and "weekly" not in state

    assert vf.main([*args, "daily", "--alerts", str(alerts), "--quiet"]) == 0
    assert capsys.readouterr().out == ""  # nothing new

    fake.findings["p1"].append(_dt_finding("sudo", "1.9", "CVE-2026-0006", "CRITICAL"))
    assert vf.main([*args, "daily", "--alerts", str(alerts), "--quiet", "--no-save"]) == 0
    out = capsys.readouterr().out
    assert out.startswith("# vulnflow daily report, ")
    assert "## Dependency-Track findings\n\n**1** new, **0** resolved" in out
    assert "`CVE-2026-0006`" in out
    assert len(json.loads(state_file.read_text())["daily"]["findings"]) == 3  # --no-save

    # --mime: a whole message for sendmail -t, subject says action is needed
    assert vf.main([*args, "daily", "--alerts", str(alerts), "--no-save", "--mime"]) == 2
    capsys.readouterr()
    assert (
        vf.main([*args, "daily", "--alerts", str(alerts), "--quiet", "--mime", "--to", "a@example.org"])
        == 0
    )
    mail = capsys.readouterr().out
    assert "To: a@example.org\n" in mail and "Subject: vulnflow daily report (" in mail
    assert ": action needed" in mail and "multipart/alternative" in mail

    # a missing alert log (receiver down) is an error in the report, exit 1
    assert vf.main([*args, "weekly", "--alerts", str(tmp_path / "gone.jsonl")]) == 1
    out = capsys.readouterr().out
    assert "## OpenCVE alerts (ERROR)" in out and "baseline of 4 open findings" in out


# ---- local chat (Mattermost) ---------------------------------------------------------------


class FakeMattermost:
    """Stateful fake of the Mattermost v4 endpoints bootstrap_mattermost uses (v12.1.0:
    first signup allowed while open signup is off, later ones 403; Token header on login)."""

    def __init__(self) -> None:
        self.users: dict[str, dict] = {}
        self.teams: dict[str, dict] = {}
        self.channels: dict[str, dict] = {}
        self.hooks: dict[str, dict] = {}
        self.calls: list[tuple[str, str]] = []
        self.n = 0

    def _id(self) -> str:
        self.n += 1
        return f"id{self.n:024d}"

    def __call__(self, method, url, headers, body, timeout):
        from urllib.parse import parse_qs, urlsplit

        u = urlsplit(url)
        assert u.netloc == "localhost:8065", url
        path, q = u.path.removeprefix("/api/v4/"), {k: v[0] for k, v in parse_qs(u.query).items()}
        self.calls.append((method, path))
        data = json.loads(body) if body else {}

        def ok(obj, status=200, hdrs=None):
            return Response(status, json.dumps(obj).encode(), hdrs or {})

        if path == "system/ping":
            return ok({"status": "OK"})
        if path == "users/login":
            user = self.users.get(data["login_id"])
            if not user or user["password"] != data["password"]:
                return ok({"id": "api.user.login.invalid_credentials"}, 401)
            return ok({"id": user["id"]}, hdrs={"Token": f"session-{user['id']}"})
        if path == "users" and method == "POST":
            if self.users:
                return ok({"id": "api.user.create_user.no_open_server"}, 403)
            assert data["email"] == data["email"].lower() and "@" in data["email"]
            self.users[data["username"]] = {
                **data,
                "id": self._id(),
                "roles": "system_admin system_user",
            }
            return ok({"id": self.users[data["username"]]["id"]}, 201)
        session = headers.get("Authorization", "").removeprefix("Bearer ")
        assert any(session == f"session-{x['id']}" for x in self.users.values()), path
        if path.startswith("teams/name/"):
            t = next((t for t in self.teams.values() if t["name"] == path.rsplit("/", 1)[1]), None)
            return ok(t) if t else ok({}, 404)
        if path == "teams" and method == "POST":
            tid = self._id()
            self.teams[tid] = {**data, "id": tid}
            return ok(self.teams[tid], 201)
        if "/channels/name/" in path:
            tid, name = path.split("/")[1], path.rsplit("/", 1)[1]
            c = next(
                (c for c in self.channels.values() if (c["team_id"], c["name"]) == (tid, name)), None
            )
            return ok(c) if c else ok({}, 404)
        if path == "channels" and method == "POST":
            cid = self._id()
            self.channels[cid] = {**data, "id": cid}
            return ok(self.channels[cid], 201)
        if path == "hooks/incoming" and method == "GET":
            return ok(
                [
                    h
                    for h in self.hooks.values()
                    if self.channels[h["channel_id"]]["team_id"] == q["team_id"]
                ]
            )
        if path == "hooks/incoming" and method == "POST":
            hid = self._id()
            self.hooks[hid] = {**data, "id": hid}
            return ok(self.hooks[hid], 201)
        raise AssertionError(f"unexpected {method} {url}")


def test_bootstrap_mattermost_creates_admin_team_channel_hook_and_reruns_cleanly():
    from vulnflow.bootstrap import BootstrapError, bootstrap_mattermost

    mm = FakeMattermost()
    pw = secrets.token_hex(12)
    url = bootstrap_mattermost(
        "http://localhost:8065", admin_user="admin", admin_password=pw, transport=mm
    )
    (hook_id,) = mm.hooks
    assert url == f"http://mattermost:8065/hooks/{hook_id}"
    assert mm.users["admin"]["email"] == "admin@vulnflow.invalid"
    (team,) = mm.teams.values()
    assert (team["name"], team["type"]) == ("vulnflow", "I")
    (chan,) = mm.channels.values()
    assert (chan["name"], chan["type"], chan["team_id"]) == ("alerts", "O", team["id"])
    assert mm.hooks[hook_id]["display_name"] == "vulnflow"

    # rerun: logs in, finds everything, creates nothing, same URL
    mm.calls.clear()
    assert (
        bootstrap_mattermost(
            "http://localhost:8065", admin_user="admin", admin_password=pw, transport=mm
        )
        == url
    )
    assert [c for c in mm.calls if c[0] == "POST"] == [("POST", "users/login")]

    # someone else's install: the admin exists with another password, signup is closed
    with pytest.raises(BootstrapError, match=r"put the real password in \.env"):
        bootstrap_mattermost(
            "http://localhost:8065",
            admin_user="admin",
            admin_password=secrets.token_hex(12),
            transport=mm,
        )


# ---- tui ------------------------------------------------------------------------------------


class FakeScreen:
    """Enough of a curses window for vulnflow.tui: records what is drawn, plays keys."""

    def __init__(self, keys: list[int | str], size: tuple[int, int] = (20, 120)):
        self.keys = [ord(k) if isinstance(k, str) else k for k in keys]
        self.size = size
        self.lines: dict[int, str] = {}

    def addnstr(self, y, x, s, n, attr=0):
        self.lines[y] = s[:n]

    def getmaxyx(self):
        return self.size

    def erase(self):
        self.lines = {}

    def refresh(self):
        pass

    def getch(self):
        assert self.keys, "the UI asked for more keys than the test gave"
        return self.keys.pop(0)

    def text(self) -> str:
        return "\n".join(self.lines[k] for k in sorted(self.lines))


def _typed(s: str) -> list[int | str]:
    return [*s, 10]


def test_tui_filters_and_decision_rules(inv):
    from datetime import date

    from vulnflow import tui

    dt = DependencyTrack("http://dt", "k", transport=_report_portfolio())
    rows = tui.load_findings(inv, dt, {"CVE-2026-0004"}, [])
    # KEV first, then severity
    assert [r.vuln_id for r in rows] == ["CVE-2026-0004", "CVE-2026-0001", "CVE-2026-0002"]
    assert (
        rows[0].kev and rows[0].component_uuid == "c-grafana" and rows[0].vuln_uuid == "v-CVE-2026-0004"
    )
    assert [r.vuln_id for r in tui.filter_rows(rows, team="sysadm")] == [
        "CVE-2026-0001",
        "CVE-2026-0002",
    ]
    assert [r.vuln_id for r in tui.filter_rows(rows, min_sev="HIGH")] == ["CVE-2026-0001"]
    assert [r.vuln_id for r in tui.filter_rows(rows, text="CURL")] == ["CVE-2026-0002"]
    assert tui.finding_line(rows[0], 200).startswith("  MEDI KEV CVE-2026-0004")

    today = date(2026, 11, 25)
    ok = tui.Decision(
        "EXPLOITABLE", "no fix upstream", response="WILL_NOT_FIX", review_by=date(2027, 3, 1)
    )
    assert ok.problems(today) == []
    assert tui.Decision("EXPLOITABLE", "x", response="WILL_NOT_FIX").problems(today) == [
        "an accepted risk needs a review date"
    ]
    assert tui.Decision("FALSE_POSITIVE", " ").problems(today) == ["a reason is required"]
    assert (
        "must be in the future" in tui.Decision("NOT_AFFECTED", "x", review_by=today).problems(today)[0]
    )
    item = tui.ignore_item(rows[1], ok, today)
    assert item.comment == "no fix upstream; review by 2027-03-01; reviewed 2026-11-25 via vulnflow tui"


def test_tui_marks_a_finding_false_positive_with_confirmation(inv, tmp_path):
    from datetime import date

    from vulnflow import tui
    from vulnflow.net import Http

    fake = _report_portfolio()
    dt = DependencyTrack("http://dt", "k", transport=fake)
    ledger = tmp_path / "ignored.jsonl"
    writer = tui.make_writer(
        lambda: Http("http://dt", transport=fake), ledger, lambda: date(2026, 11, 25)
    )
    app = tui.App(
        tui.Sources(
            findings=lambda: (tui.load_findings(inv, dt, set(), []), []),
            alerts=lambda: [],
            hosts=lambda w: [],
            updates=lambda: [],
            details=lambda r: tui.finding_details(r, None),
            write=writer,
        ),
        today=date(2026, 11, 25),
    )
    app.reload()
    assert app.status == "3 open findings"

    # filter to curl, cancel once at the confirmation, then mark it False Positive
    scr = FakeScreen(["/", *_typed("curl"), "m", "2", *_typed("other curl"), 10, "n"])
    for _ in range(2):
        app.draw(scr)
        assert app.handle(scr, scr.getch())
    assert app.status == "cancelled, nothing written" and not ledger.exists()

    scr = FakeScreen(["m", "2", *_typed("libcurl is not linked"), 10, "y"])
    app.draw(scr)
    assert app.handle(scr, scr.getch())
    assert app.status == "1 written, 0 already FALSE_POSITIVE"
    ((key, analysis),) = fake.analyses.items()
    assert key == ("p1", "c-curl", "v-CVE-2026-0002")
    assert analysis["analysisState"] == "FALSE_POSITIVE" and analysis["isSuppressed"] is True
    assert analysis["analysisComments"][0]["comment"] == (
        "libcurl is not linked; reviewed 2026-11-25 via vulnflow tui"
    )
    assert json.loads(ledger.read_text())["vuln_id"] == "CVE-2026-0002"  # unignore can undo it
    assert [r.vuln_id for r in app.rows] == ["CVE-2026-0001", "CVE-2026-0004"]

    # an accepted risk without a review date is refused before anything is asked to confirm
    app.text = ""
    scr = FakeScreen(["m", "3", *_typed("later"), 10])
    app.draw(scr)
    app.handle(scr, scr.getch())
    assert app.status == "not written: an accepted risk needs a review date"
    assert len(fake.analyses) == 1

    # read-only without DT_ADMIN_PASSWORD
    app.src.write = None
    scr = FakeScreen(["m"])
    app.handle(scr, scr.getch())
    assert app.status.startswith("read-only")


def test_tui_details_step_with_J_and_K(inv):
    from datetime import date

    from vulnflow import tui

    dt = DependencyTrack("http://dt", "k", transport=_report_portfolio())
    shown: list[str] = []

    def details(r):
        shown.append(r.vuln_id)
        return tui.finding_details(r, None)

    app = tui.App(
        tui.Sources(
            findings=lambda: (tui.load_findings(inv, dt, {"CVE-2026-0004"}, []), []),
            alerts=lambda: [],
            hosts=lambda w: [],
            updates=lambda: [],
            details=details,
            write=None,
        ),
        today=date(2026, 11, 25),
    )
    app.reload()
    # open the first finding, J twice (the last J is the end of the list: stays), K back, close
    scr = FakeScreen([10, "J", "J", "J", "K", "q"])
    app.draw(scr)
    assert app.handle(scr, scr.getch())
    assert shown == [
        "CVE-2026-0004",
        "CVE-2026-0001",
        "CVE-2026-0002",
        "CVE-2026-0002",
        "CVE-2026-0001",
    ]
    assert app.pos == 1  # the list cursor follows, so closing leaves it on the last viewed one


def test_tui_tabs_alerts_hosts_and_quit(inv, tmp_path):
    from vulnflow import tui

    first = {
        "received_at": "2026-11-24T10:00:00Z",
        "cve": "CVE-1",
        "tier_name": "P2 Attend",
        "team": "dev",
    }
    second: dict[str, Any] = {
        "received_at": "2026-11-25T10:00:00Z",
        "cve": "CVE-2",
        "tier_name": "P1 Act",
    }
    second |= {"team": "sysadm", "kev": True, "epss": 0.9}
    log_lines = [json.dumps(first), json.dumps(second), "garbage"]
    lines = tui.alert_lines(log_lines, 100)
    assert lines[0].startswith("2026-11-25T10:00 P1 Act     KEV CVE-2") and "EPSS 0.900" in lines[0]
    assert lines[1].startswith("2026-11-24T10:00 P2 Attend")
    assert tui.alert_lines(tui.read_alerts(tmp_path / "gone.jsonl"), 100)[0].startswith("(cannot read")

    mf = tmp_path / "machines.toml"
    mf.write_text('[hosts.web01]\nteam = "sysadm"\nscans = ["system"]\n')
    machines = load_machines(mf, inv.teams)
    assert tui.host_lines(machines, {}, 100, 0)[0].endswith("never pushed")

    asked: list[str] = []

    def updates() -> list[str]:
        asked.append("updates")
        return ["Nothing to do."]

    app = tui.App(
        tui.Sources(
            findings=lambda: ([], ["DT down"]),
            alerts=lambda: log_lines,
            hosts=lambda w: ["host line"],
            updates=updates,
            details=lambda r: [],
            write=None,
        )
    )
    app.reload()
    assert app.status == "0 open findings; 1 error(s): DT down"
    scr = FakeScreen(["2", "4", "4", "q"])
    for want in ("CVE-2", "Nothing to do."):
        assert app.handle(scr, scr.getch())
        app.draw(scr)
        assert want in scr.text()
    assert app.handle(scr, scr.getch())
    assert asked == ["updates"]  # GitHub is asked once, when the tab is first opened
    assert app.handle(scr, scr.getch()) is False
