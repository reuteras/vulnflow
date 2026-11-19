"""Configuration: .env file + environment variables + inventory.toml."""

from __future__ import annotations

import os
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


@dataclass
class Inventory:
    teams: dict[str, Team]
    rules: PriorityRules

    def team_for_opencve_project(self, project: str) -> Team | None:
        for t in self.teams.values():
            if t.opencve_project == project:
                return t
        return None


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
