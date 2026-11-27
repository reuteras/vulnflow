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
  aliasSyncEnabled (default false) keeps each OSV record's `aliases`. OSV's PyPI data holds
  both the PYSEC and the GHSA record of one issue, and DT files GHSA-* ids under source
  GITHUB (ModelConverter.SOURCE_NAME_BY_PREFIX); without the aliases every such issue is two
  findings. Aliases are only stored when a record is mirrored, and incremental mirroring
  (a watermark per ecosystem) skips records already seen, so turning it on needs one run
  with incrementalMirroringEnabled false (5.2.2 source, vuln-data-source/osv; seen live
  2026-11-27: a full run of 7 ecosystems took under 4 minutes and the open findings went
  from 3194 to 2451 issues).
OSV mirror runs (OpenAPI in the 5.2.2 tag, VulnDataSourcesResource; SYSTEM_CONFIGURATION):
  POST /api/v2/vuln-data-sources/osv/mirror-runs         -> 202 (seen live)
  GET  /api/v2/vuln-data-sources/osv/mirror-runs/latest  -> {"status": PENDING|RUNNING|
       COMPLETED|FAILED, "started_at", "completed_at"} (seen live)

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

Mattermost Team Edition, the optional local chat (checked against the v12.1.0 tag,
server/channels/api4 and app/user.go): with open signup off, the first account may still
sign up (CreateUserFromSignup, IsFirstUserAccount) and becomes system admin
(app/users/users.go); every later one is refused with 403.
  GET  /api/v4/system/ping
  POST /api/v4/users/login            {"login_id","password"} -> 200, session in the Token header
  POST /api/v4/users                  {"username","email","password"} -> 201
  GET  /api/v4/teams/name/{name}      -> 200 team, 404 if missing
  POST /api/v4/teams                  {"name","display_name","type":"I"} -> 201 (creator joins)
  GET  /api/v4/teams/{id}/channels/name/{name}  -> 200 channel, 404 if missing
  POST /api/v4/channels               {"team_id","name","display_name","type":"O"} -> 201
  GET  /api/v4/hooks/incoming?team_id=  -> [hook]
  POST /api/v4/hooks/incoming         {"channel_id","display_name","description"} -> 201
An incoming webhook takes the Slack-style {"text": ...} the receiver posts, at
<server>/hooks/{id}.
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
# A CI pipeline (one repository) uploads with the same two permissions as an agent, in its own
# team ci-<name>, so one leaked CI secret can be revoked without touching the others.
DT_CI_TEAM_PREFIX = "ci-"
CI_NAME_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,62}")
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
DT_OSV_RUNS = "api/v2/vuln-data-sources/osv/mirror-runs"
# The v2 API answers only as application/problem+json; with the client's usual
# Accept: application/json, DT 5.2.2 rejects a PUT with 406 (seen live 2026-11-24)
DT_V2_ACCEPT = {"Accept": "application/json, application/problem+json"}
# OsvVulnDataSourceFactory defaults in DT 5.2.2, used if no config is stored yet
DT_OSV_DEFAULTS: dict[str, Any] = {
    "enabled": False,
    "aliasSyncEnabled": False,
    "incrementalMirroringEnabled": True,
    "dataUrl": "https://storage.googleapis.com/osv-vulnerabilities",
    "ecosystems": ["Go", "Maven", "npm", "NuGet", "PyPI"],
}


class _OsvConfigError(Exception):
    pass


def _put_osv_config(http: Http, config: dict[str, Any]) -> bool:
    """Store the OSV config; False when DT says it was already so (304)."""
    r = http.put(DT_OSV_PATH, json_body={"config": config}, headers=DT_V2_ACCEPT, expect_ok=False)
    if r.status == 304:
        return False
    if not r.ok:
        raise _OsvConfigError(
            f"PUT OSV config HTTP {r.status} {r.body[:200].decode('utf-8', 'replace')}"
        )
    return True


def dt_osv_full_mirror(
    http: Http,
    config: dict[str, Any],
    *,
    timeout: float = 900.0,
    interval: float = 10.0,
    sleep: Any = time.sleep,
) -> str:
    """Run one OSV mirror with incremental mirroring off, so every record is read again
    (and gets its aliases), then put `config`'s own incremental setting back. Never
    raises; says how it went."""
    try:
        _put_osv_config(http, {**config, "incrementalMirroringEnabled": False})
        status = "not started"
        try:
            r = http.post(DT_OSV_RUNS, headers=DT_V2_ACCEPT, expect_ok=False)
            if r.status != 202:
                return f"failed: start OSV mirror run HTTP {r.status}"
            waited = 0.0
            while waited <= timeout:
                sleep(interval)
                waited += interval
                r = http.get(f"{DT_OSV_RUNS}/latest", headers=DT_V2_ACCEPT, expect_ok=False)
                status = str((r.json() or {}).get("status") or "") if r.ok else f"HTTP {r.status}"
                if status in ("COMPLETED", "FAILED"):
                    break
        finally:
            # back to incremental even if the run is still going: it read its config at start
            _put_osv_config(http, config)
        if status == "COMPLETED":
            return "full mirror completed"
        return f"full mirror {status.lower() or 'unknown'} after {waited:.0f}s"
    except (OSError, _OsvConfigError) as e:
        return f"failed: {e}"


def dt_enable_osv(http: Http, ecosystems: list[str], *, sleep: Any = time.sleep) -> str:
    """Enable DT's OSV source with at least these ecosystems and with alias sync. Keeps
    everything else as it is (ecosystems are only added, never removed). When alias sync
    is turned on for an OSV source that has already mirrored, runs one full mirror so the
    records seen before get their aliases too. Never raises: DT works without OSV, so the
    caller reports a failure instead of aborting the bootstrap."""
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
        wanted = {**current, "enabled": True, "aliasSyncEnabled": True, "ecosystems": have + added}
        if wanted == current or not _put_osv_config(http, wanted):
            return "unchanged"
        msg = "updated: enabled, alias sync, ecosystems " + ", ".join(wanted["ecosystems"])
        if current.get("enabled") and not current.get("aliasSyncEnabled"):
            msg += "; " + dt_osv_full_mirror(http, wanted, sleep=sleep)
        return msg
    except (OSError, _OsvConfigError) as e:
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


def ci_key(admin: Http, name: str, existing_key: str = "", *, rotate: bool = False) -> tuple[str, bool]:
    """(API key, new?) for a CI pipeline: its own team ci-<name> with only
    DT_AGENT_PERMISSIONS (upload an SBOM, create its project; read nothing back)."""
    if not CI_NAME_RE.fullmatch(name):
        raise BootstrapError(f"CI name {name!r}: use letters, digits, '.', '_' and '-'")
    return team_key(admin, DT_CI_TEAM_PREFIX + name, DT_AGENT_PERMISSIONS, existing_key, rotate=rotate)


def revoke_team(admin: Http, name: str) -> bool:
    """Delete a team and with it every API key it holds. False if absent."""
    team = _find_team(admin, name)
    if team is None:
        return False
    admin.request("DELETE", "api/v1/team", json_body={"uuid": team["uuid"]})
    return True


def revoke_agent(admin: Http, host: str) -> bool:
    """Delete team agent-<host> and with it every API key of that host. False if absent."""
    return revoke_team(admin, DT_AGENT_TEAM_PREFIX + host)


def revoke_ci(admin: Http, name: str) -> bool:
    """Delete team ci-<name> and its keys. False if absent."""
    return revoke_team(admin, DT_CI_TEAM_PREFIX + name)


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


MM_HOOK_NAME = "vulnflow"


def _mm_login(http: Http, user: str, password: str) -> str:
    r = http.post("users/login", expect_ok=False, json_body={"login_id": user, "password": password})
    if not r.ok:
        return ""
    return next((v for k, v in r.headers.items() if k.lower() == "token"), "")


def bootstrap_mattermost(
    base_url: str,
    *,
    admin_user: str,
    admin_password: str,
    team: str = "vulnflow",
    channels: tuple[str, ...] = ("alerts",),
    hook_base: str = "http://mattermost:8065",
    transport: Transport | None = None,
    wait_timeout: float = 300.0,
    interval: float = 5.0,
) -> dict[str, str]:
    """Admin, team, and per channel an incoming webhook; returns {channel: webhook URL as
    the receiver reaches it} (hook_base: the server's name on the chat network). Safe to
    rerun: finds what exists and only creates what is missing; the URLs stay the same."""
    root = base_url.rstrip("/")
    http = Http(f"{root}/api/v4", headers={"Accept": "application/json"}, transport=transport)
    wait_for(http, "system/ping", wait_timeout, interval)
    token = _mm_login(http, admin_user, admin_password)
    if not token:
        email = f"{admin_user.lower()}@vulnflow.invalid"
        r = http.post(
            "users",
            expect_ok=False,
            json_body={"username": admin_user, "email": email, "password": admin_password},
        )
        if r.status == 403:
            raise BootstrapError(
                f"Mattermost already has users and {admin_user!r} cannot log in with "
                "MM_ADMIN_PASSWORD; put the real password in .env"
            )
        if not r.ok:
            raise BootstrapError(
                f"Mattermost: creating {admin_user!r} failed (HTTP {r.status}: "
                f"{r.body[:200].decode('utf-8', 'replace')})"
            )
        token = _mm_login(http, admin_user, admin_password)
        if not token:
            raise BootstrapError(f"Mattermost: {admin_user!r} was created but cannot log in")
    http.headers["Authorization"] = f"Bearer {token}"

    r = http.get(f"teams/name/{team}", expect_ok=False)
    if r.status == 404:
        r = http.post("teams", json_body={"name": team, "display_name": team.title(), "type": "I"})
    elif not r.ok:
        raise BootstrapError(f"Mattermost: team lookup failed (HTTP {r.status})")
    team_id = str((r.json() or {})["id"])
    return {c: _mm_channel_hook(http, team_id, c, hook_base) for c in channels}


MM_HOOK_DESCRIPTIONS = {
    "alerts": "P1/P2 alerts from the vulnflow receiver",
    "soc": "P1 alerts of every team from the vulnflow receiver",
}


def _mm_channel_hook(http: Http, team_id: str, channel: str, hook_base: str) -> str:
    """The channel (created if missing) and its incoming webhook named MM_HOOK_NAME."""
    r = http.get(f"teams/{team_id}/channels/name/{channel}", expect_ok=False)
    if r.status == 404:
        r = http.post(
            "channels",
            json_body={
                "team_id": team_id,
                "name": channel,
                "display_name": channel.upper() if channel == "soc" else channel.title(),
                "type": "O",
            },
        )
    elif not r.ok:
        raise BootstrapError(f"Mattermost: channel lookup failed (HTTP {r.status})")
    channel_id = str((r.json() or {})["id"])

    hooks = http.get(f"hooks/incoming?team_id={team_id}&per_page=200").json() or []
    hook = next(
        (
            h
            for h in hooks
            if h.get("channel_id") == channel_id and h.get("display_name") == MM_HOOK_NAME
        ),
        None,
    )
    if hook is None:
        hook = http.post(
            "hooks/incoming",
            json_body={
                "channel_id": channel_id,
                "display_name": MM_HOOK_NAME,
                "description": MM_HOOK_DESCRIPTIONS.get(channel, "vulnflow receiver"),
            },
        ).json()
    return f"{hook_base.rstrip('/')}/hooks/{hook['id']}"


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
