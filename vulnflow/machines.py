"""Own machines, server side: agent bundles, and which hosts have stopped pushing.

The machines push. scripts/vulnflow-agent.py runs on each of them from a timer and uploads
its SBOMs to Dependency-Track over the tailnet; nothing connects to the machines. On the
vulnflow server this module turns machines.toml (not in git, like .env) into one
bundle per host for Ansible to copy:

    <out>/<host>/config.json   what to scan, project names and tags, DT URL, cpe_map
    <out>/<host>/key           that host's own Dependency-Track API key (mode 600)

Each host gets its own Dependency-Track team agent-<host> with only BOM_UPLOAD and
PROJECT_CREATION_UPLOAD: a stolen key can't read the portfolio, and revoking one machine
(`vulnflow agent-revoke <host>`) deletes that team and its keys.

Project names and tags (the owner is the team tag; DT applies tags when it creates the
project, so a later group/team change needs the tag fixed in the DT UI):
  host:<host>        team-<team>, kind-host or kind-laptop, group-<group>
  container:<image>  team-<containers_team>, kind-container, host-<host>
  code:<name>        team-<team>, kind-app, host-<host>
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from .clients import DependencyTrack
from .config import Inventory, Machine, Machines

AGENT_CONFIG_FORMAT = 1  # must match CONFIG_FORMAT in scripts/vulnflow-agent.py
HOST_KINDS = {"linux": "host", "macos": "laptop"}


def project_name(m: Machine) -> str:
    return f"host:{m.name}"


def host_scans(m: Machine) -> list[str]:
    return [s for s in m.scans if s != "containers"]


def agent_config(m: Machine, machines: Machines, inv: Inventory, dt_url: str) -> dict[str, Any]:
    """The agent config for one host (the JSON scripts/vulnflow-agent.py reads)."""

    def tag(team: str) -> str:
        return inv.teams[team].dtrack_tag

    host_project = None
    if host_scans(m):
        tags = [tag(m.team), f"kind-{HOST_KINDS[m.kind]}"] + ([f"group-{m.group}"] if m.group else [])
        host_project = {
            "name": project_name(m),
            "version": m.version,
            "tags": tags,
            "scans": host_scans(m),
        }
    containers = None
    if "containers" in m.scans:
        containers = {"tags": [tag(m.containers_team), "kind-container", f"host-{m.name}"]}
    code = [
        {
            "name": f"code:{c.name}",
            "path": c.path,
            "version": c.version,
            "tags": [tag(c.team), "kind-app", f"host-{m.name}"],
        }
        for c in machines.code.values()
        if c.host == m.name
    ]
    return {
        "vulnflow_agent_config": AGENT_CONFIG_FORMAT,
        "host": m.name,
        "dt_url": dt_url,
        "host_project": host_project,
        "containers": containers,
        "code": code,
        "language_paths": m.language_paths,
        "cpe_map": machines.cpe_map,
    }


def bundle_dir(out: Path, host: str) -> Path:
    return out / host


def read_bundle_key(out: Path, host: str) -> str:
    f = bundle_dir(out, host) / "key"
    return f.read_text(encoding="utf-8").strip() if f.is_file() else ""


def write_bundle(out: Path, host: str, config: dict[str, Any], key: str) -> Path:
    """Write config.json and key; the directory and both files are private (700/600)."""
    d = bundle_dir(out, host)
    d.mkdir(parents=True, exist_ok=True, mode=0o700)
    d.chmod(0o700)
    for name, text in (("config.json", json.dumps(config, indent=2) + "\n"), ("key", key + "\n")):
        f = d / name
        f.touch(mode=0o600, exist_ok=True)
        f.chmod(0o600)
        f.write_text(text, encoding="utf-8")
    return d


def last_pushes(dt: DependencyTrack) -> dict[str, float]:
    """host project name -> newest lastBomImport (epoch s) over all its versions."""
    out: dict[str, float] = {}
    for kind in HOST_KINDS.values():
        for p in dt.projects_by_tag(f"kind-{kind}"):
            if p.last_bom_import is not None:
                out[p.name] = max(out.get(p.name, 0.0), p.last_bom_import)
    return out


def report(
    machines: Machines,
    pushes: dict[str, float] | None,
    *,
    stale_days: float,
    now: float | None = None,
) -> int:
    """Print hosts by group with their last push; returns how many are stale or never pushed
    (0 when pushes is None, i.e. Dependency-Track was not asked)."""
    now = time.time() if now is None else now
    stale = 0
    order = [*machines.groups, ""]
    for g in order:
        members = [m for m in machines.hosts.values() if m.group == g]
        if not members:
            continue
        print(f"[{g or 'no group'}]")
        for m in members:
            what = ", ".join(m.scans) or "-"
            line = f"  {m.name:<20} {m.team:<8} {m.kind:<6} {what}"
            if pushes is None or not host_scans(m):
                print(line)
                continue
            seen = pushes.get(project_name(m))
            if seen is None:
                stale += 1
                print(f"{line}  STALE never pushed")
                continue
            age = (now - seen) / 86400
            flag = "STALE" if age > stale_days else "ok"
            stale += flag == "STALE"
            print(f"{line}  {flag} last push {age:.1f} days ago")
    for c in machines.code.values():
        print(f"  code:{c.name:<15} {c.team:<8} on {c.host}: {c.path}")
    return stale
