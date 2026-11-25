"""First-run automation for the upstream tools (no clicking through UIs).

Dependency-Track (verified against the v1 API of DT 5.x (5.2.1 docs, main source), which v5 uses for
login and access management):
  POST /api/v1/user/forceChangePassword   form: username,password,newPassword,confirmPassword
  POST /api/v1/user/login                 form: username,password -> JWT (text/plain)
  GET  /api/v1/team                       list teams
  PUT  /api/v1/team                       {"name": ...} -> 201 team (409 if it exists)
  POST /api/v1/permission/{perm}/team/{uuid}  -> 200, or 304 if already granted
  PUT  /api/v1/team/{uuid}/key            -> 201 {"key": "odt_...", ...}  (plaintext only now)
  GET  /api/v1/team/self                  with X-Api-Key -> the key's team {"uuid","name",...}
  DELETE /api/v1/team                     {"uuid": ...} -> 204 (its API keys go with it)
Per-host agent teams (agent_key/revoke_agent) use the same calls, checked against the DT
5.2.2 tag (TeamResource, DeleteTeamRequest). PUT /api/v1/bom with autoCreate needs
BOM_UPLOAD plus PROJECT_CREATION_UPLOAD and applies projectTags to the project it creates;
changing tags later needs PORTFOLIO_MANAGEMENT(_UPDATE), else DT only logs a warning
(BomResource.maybeBindTags).
OSV source config, admin JWT. Not in the hyades-apiserver v5.2.2 tag (no ExtensionsResource
there), so checked against a running 5.2.2 instead (2026-11-24):
  GET  /api/v2/extension-points/vuln-data-source/extensions/osv/config  -> {"config": {...}}
  PUT  same path  {"config": {...}}  -> 204, or 304 if unchanged. It answers only as
       application/problem+json: with Accept: application/json it is a 406.
  OSV ships disabled, ecosystems PyPI/npm/Go/Maven/NuGet (no Debian); only NVD is on.

DefectDojo (checked against 3.5.300): the initializer creates the admin with DD_ADMIN_PASSWORD
(passed in by stacks/defectdojo/override.yml) and
  POST /api/v2/api-token-auth/   {"username","password"} -> {"token": ...}
returns that user's (stable) API v2 token. It is enabled by default
(DD_API_TOKEN_AUTH_ENDPOINT_ENABLED).

OpenCVE (checked against the v3.1.0 tag): organizations and org tokens have no API, so
stacks/opencve/bootstrap_org.py runs inside the webserver container via manage.py shell.
Projects and subscriptions then go through API v2. Webhooks go through manage.py shell too
(stacks/opencve/bootstrap_webhooks.py): v3.1.0's API rejects every private webhook URL, and
a notification is only sent by an Automation with a send_notification action.
"""

from __future__ import annotations

import logging
import re
import secrets
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlencode

from .net import Http, Transport

log = logging.getLogger(__name__)

DT_DEFAULT_ADMIN = ("admin", "admin")
DT_TEAM_PERMISSIONS = ("BOM_UPLOAD", "PROJECT_CREATION_UPLOAD", "VIEW_PORTFOLIO", "VIEW_VULNERABILITY")
# A machine's agent can create projects and upload SBOMs, and read nothing back.
DT_AGENT_PERMISSIONS = ("BOM_UPLOAD", "PROJECT_CREATION_UPLOAD")
# `prune` (in the dt2dojo loop): copy analyses (PUT /api/v1/analysis needs
# VULNERABILITY_ANALYSIS) and (de)activate projects (PATCH /api/v1/project/{uuid} needs
# PORTFOLIO_MANAGEMENT, which in DT 5.2.2 also covers create/delete: there is no narrower
# one). Checked against the 5.2.2 tag (AnalysisResource, ProjectResource). Its own team, so
# the key the glue reads with stays read-only.
DT_MAINTENANCE_TEAM = "vulnflow-maintenance"
DT_MAINTENANCE_PERMISSIONS = (
    "VIEW_PORTFOLIO",
    "VIEW_VULNERABILITY",
    "VULNERABILITY_ANALYSIS",
    "PORTFOLIO_MANAGEMENT",
)
DT_AGENT_TEAM_PREFIX = "agent-"
# DT's login/forceChangePassword are @Produces(TEXT_PLAIN): Accept: application/json -> 406
FORM = {"Content-Type": "application/x-www-form-urlencoded", "Accept": "text/plain"}


class BootstrapError(RuntimeError):
    pass


@dataclass
class DTBootstrapResult:
    api_key: str  # "" when the existing key was kept
    team_uuid: str
    created_team: bool
    changed_admin_password: bool
    osv: str = "skipped"  # "updated: ...", "unchanged", "skipped", or "failed: ..."


DT_OSV_PATH = "api/v2/extension-points/vuln-data-source/extensions/osv/config"
# OsvVulnDataSourceFactory defaults in DT 5.2.2, used if no config is stored yet
DT_OSV_DEFAULTS: dict[str, Any] = {
    "enabled": False,
    "aliasSyncEnabled": False,
    "incrementalMirroringEnabled": True,
    "dataUrl": "https://storage.googleapis.com/osv-vulnerabilities",
    "ecosystems": ["Go", "Maven", "npm", "NuGet", "PyPI"],
}


def dt_enable_osv(http: Http, ecosystems: list[str]) -> str:
    """Enable DT's OSV source with at least these ecosystems. Keeps everything else as it
    is (ecosystems are only added, never removed). Never raises: DT works without OSV, so
    the caller reports a failure instead of aborting the bootstrap."""
    if not ecosystems:
        return "skipped"
    try:
        r = http.get(DT_OSV_PATH, expect_ok=False)
        if r.status == 404:
            current = dict(DT_OSV_DEFAULTS)
        elif r.ok:
            current = dict((r.json() or {}).get("config") or DT_OSV_DEFAULTS)
        else:
            return f"failed: GET OSV config HTTP {r.status}"
        have = list(current.get("ecosystems") or [])
        added = [e for e in ecosystems if e not in have]
        wanted = {**current, "enabled": True, "ecosystems": have + added}
        if wanted == current:
            return "unchanged"
        # The v2 API answers this PUT only as application/problem+json; with the client's
        # usual Accept: application/json, DT 5.2.2 rejects it with 406 (seen live 2026-11-24)
        r = http.put(
            DT_OSV_PATH,
            json_body={"config": wanted},
            headers={"Accept": "application/json, application/problem+json"},
            expect_ok=False,
        )
        if r.status == 304:
            return "unchanged"
        if not r.ok:
            body = r.body[:200].decode("utf-8", "replace")
            return f"failed: PUT OSV config HTTP {r.status} {body}"
        return "updated: enabled, ecosystems " + ", ".join(wanted["ecosystems"])
    except OSError as e:
        return f"failed: {e}"


def new_secret(nbytes: int = 24) -> str:
    return secrets.token_urlsafe(nbytes)


def wait_for(http: Http, path: str, timeout: float, interval: float = 5.0) -> None:
    deadline = time.monotonic() + timeout
    while True:
        try:
            if http.get(path, expect_ok=False).ok:
                return
        except OSError as e:
            log.debug("waiting for %s: %s", http.url(path), e)
        if time.monotonic() >= deadline:
            raise BootstrapError(f"{http.url(path)} not ready after {timeout:.0f}s")
        time.sleep(interval)


def _form(**fields: str) -> bytes:
    return urlencode(fields).encode()


def _dt_login(http: Http, user: str, password: str) -> tuple[str | None, str]:
    """Return (token, failure_cause)."""
    r = http.post(
        "api/v1/user/login", body=_form(username=user, password=password), headers=FORM, expect_ok=False
    )
    text = r.body.decode("utf-8", "replace").strip()
    return (text, "") if r.ok and text else (None, text or f"HTTP {r.status}")


def dt_key_works(base_url: str, api_key: str, transport: Transport | None = None) -> bool:
    if not api_key:
        return False
    http = Http(
        base_url,
        headers={"X-Api-Key": api_key, "Accept": "application/json"},
        transport=transport,
        retries=0,
    )
    return http.get("api/v1/team/self", expect_ok=False).ok


def bootstrap_dtrack(
    base_url: str,
    *,
    admin_password: str,
    team_name: str = "vulnflow",
    existing_key: str = "",
    osv_ecosystems: tuple[str, ...] = ("Debian", "PyPI"),
    transport: Transport | None = None,
    wait_timeout: float = 600.0,
) -> DTBootstrapResult:
    """Idempotently get Dependency-Track to: admin password set, team with the vulnflow
    permissions, a working API key for it, and the OSV source enabled for osv_ecosystems
    (empty = leave OSV alone)."""
    if not admin_password:
        raise BootstrapError("admin password must not be empty")
    anon = Http(base_url, headers={"Accept": "application/json"}, transport=transport)
    wait_for(anon, "api/version", wait_timeout)

    user, default_pw = DT_DEFAULT_ADMIN
    changed = False
    token, cause = _dt_login(anon, user, admin_password)
    if token is None:
        # Fresh install: admin/admin with FORCE_PASSWORD_CHANGE. Swap to ours.
        r = anon.post(
            "api/v1/user/forceChangePassword",
            body=_form(
                username=user,
                password=default_pw,
                newPassword=admin_password,
                confirmPassword=admin_password,
            ),
            headers=FORM,
            expect_ok=False,
        )
        if not r.ok:
            raise BootstrapError(
                f"cannot log in as {user} (login: {cause}; forced change: HTTP {r.status} "
                f"{r.body[:200].decode('utf-8', 'replace')}). If you changed the admin "
                f"password in the UI, put it in .env as DT_ADMIN_PASSWORD."
            )
        changed = True
        token, cause = _dt_login(anon, user, admin_password)
        if token is None:
            raise BootstrapError(f"login failed after password change: {cause}")

    http = Http(
        base_url,
        headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
        transport=transport,
    )

    team = _find_team(http, team_name)
    created = team is None
    if team is None:
        team = http.put("api/v1/team", json_body={"name": team_name}).json()
    uuid = team["uuid"]

    have = {p.get("name") for p in team.get("permissions") or []}
    for perm in DT_TEAM_PERMISSIONS:
        if perm in have:
            continue
        r = http.post(f"api/v1/permission/{perm}/team/{uuid}", expect_ok=False)
        if not (r.ok or r.status == 304):
            raise BootstrapError(f"granting {perm} to team {team_name}: HTTP {r.status}")

    osv = dt_enable_osv(http, list(osv_ecosystems))

    if dt_key_works(base_url, existing_key, transport):
        return DTBootstrapResult("", uuid, created, changed, osv)

    key = (http.put(f"api/v1/team/{uuid}/key").json() or {}).get("key", "")
    if not key or not dt_key_works(base_url, key, transport):
        raise BootstrapError("generated API key did not validate against /api/v1/team/self")
    return DTBootstrapResult(key, uuid, created, changed, osv)


def dt_admin_http(base_url: str, admin_password: str, transport: Transport | None = None) -> Http:
    """Http with an admin JWT (access management needs a user, not the vulnflow team key)."""
    anon = Http(base_url, headers={"Accept": "application/json"}, transport=transport)
    token, cause = _dt_login(anon, DT_DEFAULT_ADMIN[0], admin_password)
    if token is None:
        raise BootstrapError(f"cannot log in to Dependency-Track as admin: {cause}")
    return Http(
        base_url,
        headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
        transport=transport,
    )


def _grant(http: Http, team: dict[str, Any], perms: tuple[str, ...]) -> None:
    have = {p.get("name") for p in team.get("permissions") or []}
    for perm in perms:
        if perm in have:
            continue
        r = http.post(f"api/v1/permission/{perm}/team/{team['uuid']}", expect_ok=False)
        if not (r.ok or r.status == 304):
            raise BootstrapError(f"granting {perm} to team {team.get('name')}: HTTP {r.status}")


def agent_key_team(base_url: str, api_key: str, transport: Transport | None = None) -> str:
    """Name of the team an API key belongs to ("" if the key doesn't work)."""
    if not api_key:
        return ""
    http = Http(
        base_url,
        headers={"X-Api-Key": api_key, "Accept": "application/json"},
        transport=transport,
        retries=0,
    )
    r = http.get("api/v1/team/self", expect_ok=False)
    return str((r.json() or {}).get("name", "")) if r.ok else ""


def team_key(
    admin: Http, name: str, perms: tuple[str, ...], existing_key: str = "", *, rotate: bool = False
) -> tuple[str, bool]:
    """(API key, new?) for a team that holds exactly one key. A working key of that team is
    kept unless rotate; otherwise the team is deleted (taking every old key with it) and
    created again with one new key."""
    team = _find_team(admin, name)
    if (
        team is not None
        and not rotate
        and agent_key_team(admin.base_url, existing_key, admin.transport) == name
    ):
        _grant(admin, team, perms)
        return existing_key, False
    if team is not None:
        admin.request("DELETE", "api/v1/team", json_body={"uuid": team["uuid"]})
    team = admin.put("api/v1/team", json_body={"name": name}).json()
    _grant(admin, team, perms)
    key = str((admin.put(f"api/v1/team/{team['uuid']}/key").json() or {}).get("key", ""))
    if agent_key_team(admin.base_url, key, admin.transport) != name:
        raise BootstrapError(f"the new key for {name} did not validate against /api/v1/team/self")
    return key, True


def agent_key(
    admin: Http, host: str, existing_key: str = "", *, rotate: bool = False
) -> tuple[str, bool]:
    """(API key, new?) for host's agent: its own team agent-<host> with only
    DT_AGENT_PERMISSIONS."""
    return team_key(
        admin, DT_AGENT_TEAM_PREFIX + host, DT_AGENT_PERMISSIONS, existing_key, rotate=rotate
    )


def maintenance_key(admin: Http, existing_key: str = "") -> tuple[str, bool]:
    """(API key, new?) of team vulnflow-maintenance, for `prune`."""
    return team_key(admin, DT_MAINTENANCE_TEAM, DT_MAINTENANCE_PERMISSIONS, existing_key)


def revoke_agent(admin: Http, host: str) -> bool:
    """Delete team agent-<host> and with it every API key of that host. False if absent."""
    team = _find_team(admin, DT_AGENT_TEAM_PREFIX + host)
    if team is None:
        return False
    admin.request("DELETE", "api/v1/team", json_body={"uuid": team["uuid"]})
    return True


def agent_teams(admin: Http) -> list[str]:
    """Host names that have an agent team in Dependency-Track."""
    out: list[str] = []
    page = 1
    while True:
        items: list[dict[str, Any]] = (
            admin.get(f"api/v1/team?pageSize=100&pageNumber={page}").json() or []
        )
        out += [
            str(t["name"])[len(DT_AGENT_TEAM_PREFIX) :]
            for t in items
            if str(t.get("name", "")).startswith(DT_AGENT_TEAM_PREFIX)
        ]
        if len(items) < 100:
            return sorted(out)
        page += 1


def _find_team(http: Http, name: str) -> dict[str, Any] | None:
    page = 1
    while True:
        r = http.get(f"api/v1/team?pageSize=100&pageNumber={page}")
        items: list[dict[str, Any]] = r.json() or []
        for t in items:
            if t.get("name") == name:
                return t
        if len(items) < 100:
            return None
        page += 1


def dd_key_works(base_url: str, api_key: str, transport: Transport | None = None) -> bool:
    if not api_key:
        return False
    http = Http(
        f"{base_url.rstrip('/')}/api/v2",
        headers={"Authorization": f"Token {api_key}", "Accept": "application/json"},
        transport=transport,
        retries=0,
    )
    return http.get("product_types/?limit=1", expect_ok=False).ok


def bootstrap_defectdojo(
    base_url: str,
    *,
    admin_user: str,
    admin_password: str,
    existing_key: str = "",
    transport: Transport | None = None,
    wait_timeout: float = 900.0,
    interval: float = 10.0,
) -> str:
    """Return a working API v2 key ("" if existing_key already works).

    Retries the token call until wait_timeout: the web UI answers well before the
    initializer has created the admin user."""
    http = Http(
        f"{base_url.rstrip('/')}/api/v2", headers={"Accept": "application/json"}, transport=transport
    )
    wait_for(http, f"{base_url.rstrip('/')}/login", wait_timeout, interval)
    if dd_key_works(base_url, existing_key, transport):
        return ""
    deadline = time.monotonic() + wait_timeout
    while True:
        r = http.post(
            "api-token-auth/",
            expect_ok=False,
            json_body={"username": admin_user, "password": admin_password},
        )
        token = (r.json() or {}).get("token", "") if r.ok else ""
        if token:
            if not dd_key_works(base_url, token, transport):
                raise BootstrapError("DefectDojo token did not validate")
            return str(token)
        if time.monotonic() >= deadline:
            raise BootstrapError(
                f"DefectDojo token auth for {admin_user!r} failed (HTTP {r.status}: "
                f"{r.body[:200].decode('utf-8', 'replace')}). If the admin was created "
                f"before DD_ADMIN_PASSWORD was set, put the real password in .env."
            )
        log.info("DefectDojo admin not ready yet (HTTP %s), retrying", r.status)
        time.sleep(interval)


_KEY_RE = re.compile(r"^[A-Z][A-Z0-9_]*$")


def set_env_values(path: str | Path, values: dict[str, str]) -> None:
    """Replace KEY=... lines in a .env file (appending missing keys), keeping
    comments and order. The file is (re)written with mode 600."""
    p = Path(path)
    for key, val in values.items():
        if not _KEY_RE.match(key) or "\n" in val:
            raise ValueError(f"refusing to write {key!r} to {p}")
    lines = p.read_text(encoding="utf-8").splitlines() if p.exists() else []
    todo = dict(values)
    out: list[str] = []
    for line in lines:
        key = line.partition("=")[0].strip()
        if "=" in line and not line.lstrip().startswith("#") and key in todo:
            out.append(f"{key}={todo.pop(key)}")
        else:
            out.append(line)
    for key, val in todo.items():
        out.append(f"{key}={val}")
    p.touch(mode=0o600, exist_ok=True)
    p.chmod(0o600)
    p.write_text("\n".join(out) + "\n", encoding="utf-8")
