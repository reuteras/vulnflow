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
    assert set(inv.teams) == {"sysadm", "users", "dev"}
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
    assert not rep.errors and len(rep.done) == 3
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
    rows, unknown, errors = patched_findings(inv, dt)
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

    rows, unknown, _ = patched_findings(inv, dt)  # default: nothing leaves the machine
    assert rows == [] and unknown == 1

    osv_t = FakeTransport({"POST /v1/query": {"vulns": osv_vulns}})
    rows, unknown, errors = patched_findings(inv, dt, osv=OSV("https://osv.test", transport=osv_t))
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
            "component": {"name": name, "version": "1", "purl": purl},
            "vulnerability": {"source": "NVD", "vulnId": cve, "severity": "HIGH"},
            "analysis": {},
        }

    ssl = "pkg:deb/debian/libssl3t64@3.5.4?upstream=openssl%403.5.4&distro=debian-13"
    findings = [
        finding("libssl3t64", ssl, "CVE-2024-1"),  # tracker: unimportant
        finding("libssl3t64", ssl, "CVE-2024-2"),  # tracker: open/high
        finding("libssl3t64", ssl, "CVE-2024-3"),  # not in tracker
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
        ("CVE-2024-1", "unimportant", "open", "", "openssl", "trixie"),
    ]
    assert unmatched == 2  # CVE-2024-3 (not listed) and the acl finding (release unknown)
    assert [c[1] for c in tt.calls] == ["https://security-tracker.debian.org/tracker/data/json"]

    only, _, _ = debian_findings(inv, dt, tracker, ignorable_only=True)
    assert [r.vuln_id for r in only] == ["CVE-2024-1"]
    forced, _, _ = debian_findings(inv, dt, tracker, release="bookworm")
    assert [(r.vuln_id, r.urgency) for r in forced] == [("CVE-2024-2", "low")]
    assert len(tt.calls) == 1  # one download, then the in-memory index


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
