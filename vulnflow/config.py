"""Configuration: .env file + environment variables + inventory.toml."""

from __future__ import annotations

import os
import re
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


def load_dotenv(path: str | Path = ".env") -> None:
    """Load KEY=VALUE lines into os.environ without overriding existing vars."""
    p = Path(path)
    if not p.is_file():
        return
    for raw in p.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        value = value.strip().strip('"').strip("'")
        os.environ.setdefault(key.strip(), value)


def env(name: str, default: str | None = None, *, required: bool = False) -> str:
    val = os.environ.get(name, default)
    if required and not val:
        raise SystemExit(f"Missing required setting {name} (set it in .env)")
    return val or ""


def env_flag(name: str, default: bool = True) -> bool:
    val = os.environ.get(name)
    if val is None or val == "":
        return default
    return val.strip().lower() in {"1", "true", "yes", "on"}


@dataclass
class Team:
    key: str
    display_name: str
    opencve_project: str
    defectdojo_product_type: str
    dtrack_tag: str
    chat_mention: str = ""
    vendors: list[str] = field(default_factory=list)
    products: dict[str, list[str]] = field(default_factory=dict)


@dataclass
class PriorityRules:
    epss_attend: float = 0.10
    epss_floor: float = 0.01
    cvss_critical: float = 9.0
    cvss_high: float = 7.0
    chat_min_tier: int = 2
    ignore_event_types: list[str] = field(default_factory=list)


MACHINE_KINDS = ("linux", "macos")
SCANS = ("system", "brew", "languages", "apps", "containers")
DEFAULT_SCANS = {"linux": ("system", "brew"), "macos": ("brew", "languages", "apps")}
_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
_CPE_PAIR_RE = re.compile(r"^[a-z0-9._-]+:[a-z0-9._-]+$")


@dataclass
class Machine:
    """A machine `vulnflow collect` inventories (servers, laptops)."""

    name: str
    team: str
    kind: str  # "linux" or "macos"
    ssh: str = ""  # ssh destination (alias or user@host); empty = this machine
    scans: list[str] = field(default_factory=list)
    sudo: bool = False  # run the system scan through `sudo -n`
    language_paths: list[str] = field(default_factory=list)  # relative to $HOME
    version: str = ""  # DT project version; empty = probe the OS
    containers_team: str = "dev"  # owner of the container-image projects of the `containers` scan


@dataclass
class CodeTarget:
    """A directory with application code (and its installed dependencies) on a machine."""

    name: str
    machine: str
    path: str  # absolute, on that machine
    team: str = "dev"
    version: str = ""  # empty = `git describe` in the directory, else "unknown"


@dataclass
class Inventory:
    teams: dict[str, Team]
    rules: PriorityRules
    machines: dict[str, Machine] = field(default_factory=dict)
    code: dict[str, CodeTarget] = field(default_factory=dict)
    # "vendor:product" overrides for the CPE of Homebrew formulae/casks and Mac apps
    cpe_map: dict[str, str] = field(default_factory=dict)

    def team_for_opencve_project(self, project: str) -> Team | None:
        for t in self.teams.values():
            if t.opencve_project == project:
                return t
        return None


def _load_machine(name: str, m: dict[str, Any], teams: dict[str, Team], path: str | Path) -> Machine:
    where = f"[machines.{name}] in {path}"
    if not _NAME_RE.match(name):
        raise SystemExit(f"{where}: name must match {_NAME_RE.pattern}")
    kind = m.get("kind", "linux")
    if kind not in MACHINE_KINDS:
        raise SystemExit(f"{where}: kind must be one of {MACHINE_KINDS}, got {kind!r}")
    team = m.get("team", "")
    if team not in teams:
        raise SystemExit(f"{where}: team {team!r} is not one of {sorted(teams)}")
    ssh = str(m.get("ssh", ""))
    if ssh.startswith("-") or any(c.isspace() for c in ssh):
        raise SystemExit(f"{where}: ssh must be a host or user@host, got {ssh!r}")
    scans = list(m.get("scans") or DEFAULT_SCANS[kind])
    bad = [x for x in scans if x not in SCANS]
    if bad:
        raise SystemExit(f"{where}: unknown scans {bad}, choose from {SCANS}")
    paths = [str(x) for x in m.get("language_paths") or []]
    for p in paths:
        if p.startswith("/") or ".." in Path(p).parts:
            raise SystemExit(f"{where}: language_paths must be relative to $HOME, got {p!r}")
    containers_team = str(m.get("containers_team", "dev"))
    if containers_team not in teams:
        raise SystemExit(f"{where}: containers_team {containers_team!r} is not one of {sorted(teams)}")
    return Machine(
        name=name,
        team=team,
        kind=kind,
        ssh=ssh,
        scans=scans,
        sudo=bool(m.get("sudo", False)),
        language_paths=paths,
        version=str(m.get("version", "")),
        containers_team=containers_team,
    )


def _load_code(
    name: str, c: dict[str, Any], teams: dict[str, Team], machines: dict[str, Machine], path: str | Path
) -> CodeTarget:
    where = f"[code.{name}] in {path}"
    if not _NAME_RE.match(name):
        raise SystemExit(f"{where}: name must match {_NAME_RE.pattern}")
    machine = str(c.get("machine", ""))
    if machine not in machines:
        raise SystemExit(f"{where}: machine {machine!r} is not one of {sorted(machines)}")
    where_path = str(c.get("path", ""))
    if not where_path.startswith("/") or ".." in Path(where_path).parts or "\n" in where_path:
        raise SystemExit(f"{where}: path must be absolute and without '..', got {where_path!r}")
    team = str(c.get("team", "dev"))
    if team not in teams:
        raise SystemExit(f"{where}: team {team!r} is not one of {sorted(teams)}")
    return CodeTarget(name, machine, where_path, team, str(c.get("version", "")))


def load_inventory(path: str | Path) -> Inventory:
    data: dict[str, Any] = tomllib.loads(Path(path).read_text(encoding="utf-8"))
    teams: dict[str, Team] = {}
    for key, t in (data.get("teams") or {}).items():
        oc = t.get("opencve") or {}
        teams[key] = Team(
            key=key,
            display_name=t.get("display_name", key),
            opencve_project=t.get("opencve_project", key),
            defectdojo_product_type=t.get("defectdojo_product_type", key),
            dtrack_tag=t.get("dtrack_tag", f"team-{key}"),
            chat_mention=t.get("chat_mention", ""),
            vendors=sorted(set(oc.get("vendors") or [])),
            products={v: sorted(set(ps)) for v, ps in (oc.get("products") or {}).items()},
        )
    pr = data.get("priority") or {}
    rules = PriorityRules(**{k: v for k, v in pr.items() if k in PriorityRules.__dataclass_fields__})
    if not teams:
        raise SystemExit(f"No [teams.*] defined in {path}")
    machines = {
        name: _load_machine(name, m, teams, path) for name, m in (data.get("machines") or {}).items()
    }
    code = {
        name: _load_code(name, c, teams, machines, path) for name, c in (data.get("code") or {}).items()
    }
    cpe_map = {str(k): str(v) for k, v in (data.get("cpe_map") or {}).items()}
    for k, v in cpe_map.items():
        if not _CPE_PAIR_RE.match(v):
            raise SystemExit(f"[cpe_map] {k!r} in {path}: expected 'vendor:product', got {v!r}")
    return Inventory(teams=teams, rules=rules, machines=machines, code=code, cpe_map=cpe_map)
