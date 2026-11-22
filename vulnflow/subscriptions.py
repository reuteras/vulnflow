"""Suggest OpenCVE subscriptions from what Dependency-Track has seen on the machines.

    python3 -m vulnflow suggest-subscriptions [--top 40] [--libraries]

For each team: every active project tagged with the team's DT tag, every component with a
CPE, counted by NVD vendor:product over the projects it appears in. What the team already
follows (inventory.toml + machines.toml) is left out. Libraries from language ecosystems
(pypi, npm, golang, maven, ...) are left out too unless --libraries: Dependency-Track
matches those by package URL (OSV/GHSA), which is better than OpenCVE's CPE subscriptions.
The output is a [subscriptions.<team>] block for machines.toml (not in git) to review and
paste; nothing is changed. `vulnflow sync` then pushes it to OpenCVE.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field

from .clients import DependencyTrack, OpenCVE
from .config import Inventory, Team

LIBRARY_PURL_TYPES = {
    "pypi",
    "npm",
    "golang",
    "maven",
    "gem",
    "cargo",
    "nuget",
    "composer",
    "hex",
    "pub",
    "swift",
    "cocoapods",
    "conan",
    "hackage",
    "cran",
}


@dataclass
class Seen:
    projects: set[str] = field(default_factory=set)
    kinds: set[str] = field(default_factory=set)  # purl types, or the DT classifier


def cpe_vendor_product(cpe: str) -> tuple[str, str] | None:
    """cpe:2.3:a:openssl:openssl:3.5.4:... -> ("openssl", "openssl"); None for a wildcard."""
    parts = cpe.replace("\\:", "\x00").split(":")
    if len(parts) < 6 or parts[0] != "cpe" or parts[1] != "2.3" or parts[2] not in ("a", "o"):
        return None
    vendor, product = (p.replace("\x00", ":").replace("\\", "") for p in parts[3:5])
    if vendor in ("*", "-", "") or product in ("*", "-", ""):
        return None
    return vendor.lower(), product.lower()


def follows(team: Team, vendor: str, product: str) -> bool:
    return vendor in team.vendors or product in team.products.get(vendor, [])


def gather(
    team: Team, dt: DependencyTrack, *, libraries: bool
) -> tuple[dict[tuple[str, str], Seen], int]:
    seen: dict[tuple[str, str], Seen] = defaultdict(Seen)
    projects = [p for p in dt.projects_by_tag(team.dtrack_tag) if p.active]
    for p in projects:
        for c in dt.components(p.uuid):
            vp = cpe_vendor_product(str(c.get("cpe") or ""))
            if vp is None or follows(team, *vp):
                continue
            purl = str(c.get("purl") or "")
            kind = purl[4:].split("/", 1)[0] if purl.startswith("pkg:") else ""
            if kind in LIBRARY_PURL_TYPES and not libraries:
                continue
            s = seen[vp]
            s.projects.add(p.name)
            s.kinds.add(kind or str(c.get("classifier") or "?").lower())
    return seen, len(projects)


def toml_key(s: str) -> str:
    return s if all(ch.isalnum() or ch in "_-" for ch in s) else f'"{s}"'


def render(
    team: Team,
    seen: dict[tuple[str, str], Seen],
    n_projects: int,
    top: int,
    opencve: OpenCVE | None = None,
) -> str:
    """The top pairs by number of projects, one commented-out line per vendor. With an
    OpenCVE client, names OpenCVE doesn't know are listed apart (a subscription to one fails)."""
    rows = sorted(seen.items(), key=lambda kv: (-len(kv[1].projects), kv[0]))
    unknown: list[str] = []
    if opencve is not None:
        known: list[tuple[tuple[str, str], Seen]] = []
        for row in rows:
            if len(known) >= top:
                break
            (vendor, product), _ = row
            if opencve.product_exists(vendor, product):
                known.append(row)
            else:
                unknown.append(f"{vendor}:{product}")
        rows = known
    rows = rows[:top]
    head = f"# {team.key}: {n_projects} projects tagged {team.dtrack_tag}"
    if not rows:
        return f"{head}; nothing new to suggest\n"
    by_vendor: dict[str, list[tuple[str, Seen]]] = {}
    for (vendor, product), sn in rows:
        by_vendor.setdefault(vendor, []).append((product, sn))
    lines = [
        head,
        f"#   {len(seen)} candidates, top {len(rows)} by number of projects",
        f"[subscriptions.{team.key}.products]",
    ]
    for vendor, items in by_vendor.items():
        products = ", ".join(f'"{p}"' for p, _ in items)
        notes = "; ".join(
            f"{p}: {len(sn.projects)} ({', '.join(sorted(sn.projects)[:3])}"
            f"{', ...' if len(sn.projects) > 3 else ''}; {', '.join(sorted(sn.kinds))})"
            for p, sn in items
        )
        lines.append(f"# {toml_key(vendor)} = [{products}]   # {notes}")
    if unknown:
        lines.append(f"#   not in OpenCVE (syft's CPE guesses), skipped: {', '.join(unknown)}")
    elif opencve is None:
        lines.append("#   names not checked against OpenCVE (no OPENCVE_TOKEN)")
    return "\n".join(lines) + "\n"


def suggest(
    inv: Inventory,
    dt: DependencyTrack,
    *,
    opencve: OpenCVE | None = None,
    top: int = 40,
    libraries: bool = False,
) -> str:
    out = [
        "# Suggested OpenCVE subscriptions. Uncomment what you want to follow, paste into",
        "# machines.toml (not in git) and run `python3 -m vulnflow sync`. Remove the products",
        "# you don't want from a vendor's list.",
        "",
    ]
    for team in inv.teams.values():
        seen, n = gather(team, dt, libraries=libraries)
        out.append(render(team, seen, n, top, opencve))
    return "\n".join(out)
