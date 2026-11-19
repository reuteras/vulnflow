"""Offline tests: all HTTP goes through a fake transport."""

from __future__ import annotations

import base64
import json
import secrets
import threading
import time
import urllib.request
from pathlib import Path
from typing import Any

import pytest

from vulnflow.clients import DefectDojo, DependencyTrack, OpenCVE
from vulnflow.config import PriorityRules, load_inventory
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
    assert set(inv.teams) == {"sysadm", "dev"}
    s = inv.teams["sysadm"]
    assert s.opencve_project == "sysadm" and s.dtrack_tag == "team-sysadm"
    assert "fortinet" in s.vendors
    assert s.products["microsoft"] == sorted(
        ["windows_server_2022", "windows_server_2025", "exchange_server"]
    )
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
    assert msg is not None and msg.startswith("@drift-oncall")
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
        rows = [{"uuid": f"{tag}-1", "name": f"{tag}-app", "version": "2", "active": True}]
        return Response(200, json.dumps(rows).encode(), {"X-Total-Count": "1"})

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
    assert not rep.errors and len(rep.done) == 2
    posts = [c for c in t.calls if c[0] == "POST"]
    sysadm = next(p for p in posts if b"team-sysadm-app" in p[3])
    assert b"Sysadmin" in sysadm[3]


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
        self.calls: list[tuple[str, str]] = []

    def form(self, body):
        return {k: v[0] for k, v in self.parse_qs(body.decode()).items()}

    def __call__(self, method, url, headers, body, timeout):
        path = url.split("://", 1)[1].split("/", 1)[1].split("?")[0]
        self.calls.append((method, path))

        def ok(obj, status=200):
            return Response(status, json.dumps(obj).encode(), {})

        if path == "api/version":
            return ok({"version": "5.2.1"})
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
            key = f"odt_{len(self.keys):08d}_secret"
            self.keys[key] = name
            return ok({"key": key, "publicId": key[4:12]}, 201)
        return Response(404, b"", {})


def test_dt_bootstrap_fresh_install_then_idempotent():
    from vulnflow.bootstrap import DT_TEAM_PERMISSIONS, bootstrap_dtrack

    dt = FakeDT()
    r1 = bootstrap_dtrack("http://dt:8180", admin_password=TEST_PW, transport=dt)
    assert r1.changed_admin_password and r1.created_team and r1.api_key.startswith("odt_")
    assert dt.password == TEST_PW
    assert {p["name"] for p in dt.teams["vulnflow"]["permissions"]} == set(DT_TEAM_PERMISSIONS)

    r2 = bootstrap_dtrack(
        "http://dt:8180", admin_password=TEST_PW, existing_key=r1.api_key, transport=dt
    )
    assert not (r2.changed_admin_password or r2.created_team) and r2.api_key == ""
    assert len(dt.keys) == 1  # no new key minted when the old one still works


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


def test_opencve_ensure_webhook_creates_then_patches():
    state: dict[str, object] = {}

    def get_route(m, url, h, b):
        return Response(200, b"{}", {}) if state else Response(404, b"", {})

    def post_route(m, url, h, b):
        state.update(json.loads(b))
        return Response(201, b"{}", {})

    t = FakeTransport(
        {
            "GET /notifications/vulnflow": get_route,
            "POST /notifications": post_route,
            "PATCH /notifications/vulnflow": {},
        }
    )
    oc = OpenCVE("http://oc", "org", "t", transport=t)
    hdrs = {"X-Vulnflow-Token": "s"}
    assert oc.ensure_webhook("dev", "vulnflow", "http://r:8380/opencve", hdrs) is True
    assert state == {
        "name": "vulnflow",
        "type": "webhook",
        "configuration": {"url": "http://r:8380/opencve", "headers": hdrs},
    }
    assert t.calls[-1][1].endswith("/api/v2/organizations/org/projects/dev/notifications")
    assert oc.ensure_webhook("dev", "vulnflow", "http://r:8380/opencve", hdrs) is False
    m, _, _, body = t.calls[-1]
    assert m == "PATCH" and json.loads(body)["configuration"]["headers"] == hdrs


def test_env_set_cli_reads_stdin(tmp_path, monkeypatch):
    import io

    from vulnflow.__main__ import main

    env_file = tmp_path / ".env"
    env_file.write_text("A=1\nOPENCVE_TOKEN=\n")
    monkeypatch.setattr("sys.stdin", io.StringIO("OPENCVE_TOKEN=opc_org.a.b=c\n"))
    assert main(["--env-file", str(env_file), "env-set"]) == 0
    assert env_file.read_text() == "A=1\nOPENCVE_TOKEN=opc_org.a.b=c\n"
