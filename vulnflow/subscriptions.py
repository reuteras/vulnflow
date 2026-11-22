"""Suggest OpenCVE subscriptions from what Dependency-Track has seen on the machines.

    python3 -m vulnflow suggest-subscriptions [--top 40] [--min-cves 1] [--libraries]
                                              [--list-skipped]

For each team: every active project tagged with the team's DT tag, every component, turned
into NVD vendor:product candidates: the component's CPE (often syft's guess, vendor =
product) plus KNOWN_PRODUCTS, the NVD names of common packages whose vendor can't be
guessed (openssh is openbsd:openssh, curl is haxx:curl, ...). What the team already follows
(inventory.toml + machines.toml) is left out, and so are language libraries (pypi, npm,
golang, maven, ...) unless --libraries: Dependency-Track matches those by package URL
(OSV/GHSA), better than CPE subscriptions.

Each candidate is looked up in OpenCVE: a name it doesn't know (most of syft's guesses) or
one with fewer than --min-cves CVEs is dropped, which also weeds out wrong vendors that
happen to exist. The rest is ranked by the number of projects it appears in, then by its
CVE count, and printed as commented-out [subscriptions.<team>] lines for machines.toml (not
in git). Nothing is changed. Without an OpenCVE token nothing is checked or ranked by CVEs.
"""

from __future__ import annotations

import sys
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


# Package name (as DT shows it) -> its NVD vendor:product, for common software whose NVD
# vendor isn't the package name. Wrong or missing entries only cost a suggestion: every
# candidate is checked against OpenCVE before it is shown.
_GNU = (
    "bash",
    "binutils",
    "coreutils",
    "cpio",
    "gzip",
    "grep",
    "less",
    "readline",
    "sed",
    "tar",
    "wget",
)
KNOWN_PRODUCTS: dict[str, tuple[str, str]] = {
    **{n: ("gnu", n) for n in _GNU},
    **{n: ("gnu", "glibc") for n in ("glibc", "libc6", "libc-bin", "musl-libc")},
    **{n: ("gnu", "ncurses") for n in ("ncurses", "ncurses-base", "ncurses-bin", "libncursesw6")},
    **{n: ("openbsd", "openssh") for n in ("openssh", "openssh-client", "openssh-server")},
    **{n: ("haxx", "curl") for n in ("curl", "libcurl", "libcurl4t64", "libcurl3t64-gnutls")},
    **{n: ("openssl", "openssl") for n in ("libssl3", "libssl3t64", "libcrypto3", "libssl-dev")},
    **{n: ("isc", "bind") for n in ("bind9-libs", "bind9-host", "bind9-dnsutils")},
    **{n: ("postgresql", "postgresql") for n in ("libpq5", "postgresql-18", "postgresql-17")},
    **{n: ("python", "python") for n in ("python3.13", "python3.12", "python3.11", "libpython3.13")},
    **{n: ("libexpat_project", "libexpat") for n in ("expat", "libexpat1")},
    **{n: ("gnupg", "gnupg") for n in ("gnupg", "gpg", "gpg-agent", "dirmngr")},
    **{n: ("netfilter", n) for n in ("iptables", "nftables")},
    "git": ("git-scm", "git"),
    "go": ("golang", "go"),
    "nginx": ("f5", "nginx"),
    "sudo": ("sudo_project", "sudo"),
    "tmux": ("tmux_project", "tmux"),
    "systemd": ("systemd_project", "systemd"),
    "rsync": ("samba", "rsync"),
    "libsqlite3-0": ("sqlite", "sqlite"),
    "libxml2": ("xmlsoft", "libxml2"),
    "zlib1g": ("zlib", "zlib"),
    "libgcrypt20": ("gnupg", "libgcrypt"),
    "libgnutls30t64": ("gnu", "gnutls"),
    "jq": ("jqlang", "jq"),
    "util-linux": ("kernel", "util-linux"),
    "e2fsprogs": ("e2fsprogs_project", "e2fsprogs"),
    "nodejs": ("nodejs", "node.js"),
    "certbot": ("eff", "certbot"),
    "perl-base": ("perl", "perl"),
    "podman": ("podman_project", "podman"),
    "htop": ("htop-dev", "htop"),
}


@dataclass
class Seen:
    projects: set[str] = field(default_factory=set)
    kinds: set[str] = field(default_factory=set)  # purl types, or the DT classifier
    cves: int | None = None  # OpenCVE's count; None = not checked


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
            purl = str(c.get("purl") or "")
            kind = purl[4:].split("/", 1)[0] if purl.startswith("pkg:") else ""
            if kind in LIBRARY_PURL_TYPES and not libraries:
                continue
            candidates = {cpe_vendor_product(str(c.get("cpe") or ""))}
            for name in (str(c.get("name") or ""), *(vp[1] for vp in candidates if vp)):
                candidates.add(KNOWN_PRODUCTS.get(name))
            for vp in candidates:
                if vp is None or follows(team, *vp):
                    continue
                sn = seen[vp]
                sn.projects.add(p.name)
                sn.kinds.add(kind or str(c.get("classifier") or "?").lower())
    return seen, len(projects)


def toml_key(s: str) -> str:
    return s if all(ch.isalnum() or ch in "_-" for ch in s) else f'"{s}"'


def check(
    seen: dict[tuple[str, str], Seen], opencve: OpenCVE, cache: dict[tuple[str, str], int | None]
) -> None:
    """Fill in each candidate's CVE count from OpenCVE (None = OpenCVE doesn't know it)."""
    todo = [vp for vp in seen if vp not in cache]
    for i, (vendor, product) in enumerate(todo, 1):
        if i % 100 == 0:
            print(f"  checked {i}/{len(todo)} names in OpenCVE", file=sys.stderr)
        cache[(vendor, product)] = opencve.cve_count(vendor, product)
    for vp, sn in seen.items():
        sn.cves = cache[vp]


def render(
    team: Team,
    seen: dict[tuple[str, str], Seen],
    n_projects: int,
    *,
    top: int,
    min_cves: int,
    checked: bool,
    list_skipped: bool,
) -> str:
    """The top candidates, one commented-out line per vendor."""
    head = f"# {team.key}: {n_projects} projects tagged {team.dtrack_tag}, {len(seen)} candidates"
    unknown = sorted(f"{v}:{p}" for (v, p), sn in seen.items() if checked and sn.cves is None)
    few = sorted(
        f"{v}:{p} ({sn.cves})"
        for (v, p), sn in seen.items()
        if checked and sn.cves is not None and sn.cves < min_cves
    )
    good = [
        kv for kv in seen.items() if not checked or (kv[1].cves is not None and kv[1].cves >= min_cves)
    ]
    rows = sorted(good, key=lambda kv: (-len(kv[1].projects), -(kv[1].cves or 0), kv[0]))[:top]
    lines = [head]
    if rows:
        lines.append(f"[subscriptions.{team.key}.products]")
    by_vendor: dict[str, list[tuple[str, Seen]]] = {}
    for (vendor, product), sn in rows:
        by_vendor.setdefault(vendor, []).append((product, sn))
    for vendor, items in by_vendor.items():
        products = ", ".join(f'"{p}"' for p, _ in items)
        notes = "; ".join(
            f"{p}: {'' if sn.cves is None else f'{sn.cves} CVEs, '}{len(sn.projects)} projects"
            f" ({', '.join(sorted(sn.projects)[:2])}{', ...' if len(sn.projects) > 2 else ''}"
            f"; {', '.join(sorted(sn.kinds))})"
            for p, sn in items
        )
        lines.append(f"# {toml_key(vendor)} = [{products}]   # {notes}")
    if not rows:
        lines.append("#   nothing new to suggest")
    if not checked:
        lines.append("#   not checked against OpenCVE (no OPENCVE_TOKEN): expect wrong names")
    elif unknown or few:
        lines.append(
            f"#   left out: {len(unknown)} names OpenCVE doesn't know, {len(few)} with fewer "
            f"than {min_cves} CVEs" + ("" if list_skipped else " (--list-skipped shows them)")
        )
        if list_skipped:
            lines += [f"#     unknown: {', '.join(unknown)}", f"#     few CVEs: {', '.join(few)}"]
    return "\n".join(lines) + "\n"


def suggest(
    inv: Inventory,
    dt: DependencyTrack,
    *,
    opencve: OpenCVE | None = None,
    top: int = 40,
    min_cves: int = 1,
    libraries: bool = False,
    list_skipped: bool = False,
) -> str:
    out = [
        "# Suggested OpenCVE subscriptions. Uncomment what you want to follow, paste into",
        "# machines.toml (not in git) and run `python3 -m vulnflow sync`. Remove the products",
        "# you don't want from a vendor's list.",
        "",
    ]
    cache: dict[tuple[str, str], int | None] = {}
    for team in inv.teams.values():
        seen, n = gather(team, dt, libraries=libraries)
        if opencve is not None:
            check(seen, opencve, cache)
        out.append(
            render(
                team,
                seen,
                n,
                top=top,
                min_cves=min_cves,
                checked=opencve is not None,
                list_skipped=list_skipped,
            )
        )
    return "\n".join(out)
