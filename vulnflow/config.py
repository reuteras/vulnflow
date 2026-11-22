"""Configuration: .env file + environment variables + inventory.toml + machines.toml."""

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
DEFAULT_SCANS = {"linux": ("system",), "macos": ("brew", "languages", "apps")}
_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
_CPE_PAIR_RE = re.compile(r"^[a-z0-9._-]+:[a-z0-9._-]+$")
_CPE_PART_RE = re.compile(r"^[a-z0-9][a-z0-9._~+-]*$")  # an OpenCVE/NVD vendor or product
# settings a [groups.*] entry gives its hosts and a [hosts.*] entry can override
_MACHINE_KEYS = {"team", "kind", "scans", "language_paths", "containers_team"}


@dataclass
class Machine:
    """A machine that pushes its own SBOMs with scripts/vulnflow-agent.py."""

    name: str
    team: str
    kind: str  # "linux" or "macos"
    group: str = ""  # the [groups.*] entry it belongs to, if any
    scans: list[str] = field(default_factory=list)
    language_paths: list[str] = field(default_factory=list)  # relative to $HOME
    version: str = ""  # DT project version; empty = the agent probes the OS
    containers_team: str = "dev"  # owner of the container-image projects of the `containers` scan


@dataclass
class CodeTarget:
    """A directory with application code (and its installed dependencies) on a machine."""

    name: str
    host: str
    path: str  # absolute, on that machine
    team: str = "dev"
    version: str = ""  # empty = `git describe` in the directory, else "unknown"


@dataclass
class Machines:
    """machines.toml: the operator's own hosts. Not in git (like .env)."""

    hosts: dict[str, Machine] = field(default_factory=dict)
    groups: dict[str, list[str]] = field(default_factory=dict)  # group -> host names
    code: dict[str, CodeTarget] = field(default_factory=dict)
    # "vendor:product" overrides for the CPE of Homebrew formulae/casks and Mac apps
    cpe_map: dict[str, str] = field(default_factory=dict)
    # extra OpenCVE subscriptions per team: (vendors, {vendor: [products]}); kept here, out of
    # git, because a detailed list shows the software stack
    subscriptions: dict[str, tuple[list[str], dict[str, list[str]]]] = field(default_factory=dict)


@dataclass
class Inventory:
    teams: dict[str, Team]
    rules: PriorityRules

    def team_for_opencve_project(self, project: str) -> Team | None:
        for t in self.teams.values():
            if t.opencve_project == project:
                return t
        return None


def _check_name(kind: str, name: str, path: str | Path) -> None:
    if not _NAME_RE.match(name):
        raise SystemExit(f"[{kind}.{name}] in {path}: name must match {_NAME_RE.pattern}")


def _machine(
    name: str, group: str, settings: dict[str, Any], teams: dict[str, Team], where: str
) -> Machine:
    kind = settings.get("kind", "linux")
    if kind not in MACHINE_KINDS:
        raise SystemExit(f"{where}: kind must be one of {MACHINE_KINDS}, got {kind!r}")
    team = settings.get("team", "")
    if team not in teams:
        raise SystemExit(f"{where}: team {team!r} is not one of {sorted(teams)}")
    scans = list(settings.get("scans") or DEFAULT_SCANS[kind])
    bad = [x for x in scans if x not in SCANS]
    if bad:
        raise SystemExit(f"{where}: unknown scans {bad}, choose from {SCANS}")
    paths = [str(x) for x in settings.get("language_paths") or []]
    for p in paths:
        if p.startswith("/") or ".." in Path(p).parts:
            raise SystemExit(f"{where}: language_paths must be relative to $HOME, got {p!r}")
    containers_team = str(settings.get("containers_team", "dev"))
    if containers_team not in teams:
        raise SystemExit(f"{where}: containers_team {containers_team!r} is not one of {sorted(teams)}")
    return Machine(
        name=name,
        team=team,
        kind=kind,
        group=group,
        scans=scans,
        language_paths=paths,
        version=str(settings.get("version", "")),
        containers_team=containers_team,
    )


def load_machines(path: str | Path, teams: dict[str, Team]) -> Machines:
    """Parse machines.toml: [groups.*] with shared settings and a `hosts` list, optional
    [hosts.*] overrides (or stand-alone hosts), [code.*] and [cpe_map]. A missing file is an
    empty estate; the example lives in machines.example.toml."""
    p = Path(path)
    if not p.is_file():
        return Machines()
    data: dict[str, Any] = tomllib.loads(p.read_text(encoding="utf-8"))
    unknown = sorted(set(data) - {"groups", "hosts", "code", "cpe_map", "subscriptions"})
    if unknown:
        raise SystemExit(f"{path}: unknown sections {unknown}")

    groups: dict[str, list[str]] = {}
    member_of: dict[str, str] = {}
    group_settings: dict[str, dict[str, Any]] = {}
    for g, gs in (data.get("groups") or {}).items():
        _check_name("groups", g, path)
        bad = sorted(set(gs) - _MACHINE_KEYS - {"hosts"})
        if bad:
            raise SystemExit(f"[groups.{g}] in {path}: unknown keys {bad}")
        names = [str(h) for h in gs.get("hosts") or []]
        for h in names:
            _check_name("hosts", h, path)
            if h in member_of:
                raise SystemExit(f"{path}: host {h!r} is in groups {member_of[h]!r} and {g!r}")
            member_of[h] = g
        groups[g] = names
        group_settings[g] = {k: v for k, v in gs.items() if k != "hosts"}

    overrides: dict[str, dict[str, Any]] = data.get("hosts") or {}
    hosts: dict[str, Machine] = {}
    for h in [*member_of, *(x for x in overrides if x not in member_of)]:
        _check_name("hosts", h, path)
        o = overrides.get(h) or {}
        bad = sorted(set(o) - _MACHINE_KEYS - {"group", "version"})
        if bad:
            raise SystemExit(f"[hosts.{h}] in {path}: unknown keys {bad}")
        g = member_of.get(h) or str(o.get("group", ""))
        if "group" in o and member_of.get(h) not in (None, o["group"]):
            raise SystemExit(
                f"[hosts.{h}] in {path}: group {o['group']!r} but listed in {member_of[h]!r}"
            )
        if g and g not in groups:
            raise SystemExit(f"[hosts.{h}] in {path}: group {g!r} is not one of {sorted(groups)}")
        if g and h not in groups[g]:
            groups[g].append(h)
        settings = {**group_settings.get(g, {}), **o}
        hosts[h] = _machine(h, g, settings, teams, f"host {h!r} in {path}")

    code: dict[str, CodeTarget] = {}
    for name, c in (data.get("code") or {}).items():
        _check_name("code", name, path)
        where = f"[code.{name}] in {path}"
        host = str(c.get("host", ""))
        if host not in hosts:
            raise SystemExit(f"{where}: host {host!r} is not one of {sorted(hosts)}")
        cpath = str(c.get("path", ""))
        if not cpath.startswith("/") or ".." in Path(cpath).parts or "\n" in cpath:
            raise SystemExit(f"{where}: path must be absolute and without '..', got {cpath!r}")
        team = str(c.get("team", "dev"))
        if team not in teams:
            raise SystemExit(f"{where}: team {team!r} is not one of {sorted(teams)}")
        code[name] = CodeTarget(name, host, cpath, team, str(c.get("version", "")))

    cpe_map = {str(k): str(v) for k, v in (data.get("cpe_map") or {}).items()}
    for k, v in cpe_map.items():
        if not _CPE_PAIR_RE.match(v):
            raise SystemExit(f"[cpe_map] {k!r} in {path}: expected 'vendor:product', got {v!r}")
    subscriptions: dict[str, tuple[list[str], dict[str, list[str]]]] = {}
    for team, sub in (data.get("subscriptions") or {}).items():
        where = f"[subscriptions.{team}] in {path}"
        if team not in teams:
            raise SystemExit(f"{where}: team {team!r} is not one of {sorted(teams)}")
        bad = sorted(set(sub) - {"vendors", "products"})
        if bad:
            raise SystemExit(f"{where}: unknown keys {bad}")
        vendors = [str(v) for v in sub.get("vendors") or []]
        products = {str(v): [str(p) for p in ps] for v, ps in (sub.get("products") or {}).items()}
        for name in [*vendors, *products, *(p for ps in products.values() for p in ps)]:
            if not _CPE_PART_RE.match(name):
                raise SystemExit(f"{where}: {name!r} is not an NVD vendor/product name")
        subscriptions[team] = (vendors, products)
    return Machines(hosts=hosts, groups=groups, code=code, cpe_map=cpe_map, subscriptions=subscriptions)


def add_subscriptions(inv: Inventory, machines: Machines) -> None:
    """Merge machines.toml [subscriptions.<team>] into the teams' OpenCVE subscriptions."""
    for key, (vendors, products) in machines.subscriptions.items():
        team = inv.teams[key]
        team.vendors = sorted({*team.vendors, *vendors})
        for vendor, ps in products.items():
            team.products[vendor] = sorted({*team.products.get(vendor, []), *ps})


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
    return Inventory(teams=teams, rules=rules)
