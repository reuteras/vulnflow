"""`vulnflow collect`: build one SBOM per machine over ssh and upload it to Dependency-Track.

Meant for a Dependency-Track that is not always up (a small VM you start when you want to
look). Nothing runs on a schedule and nothing on the machines needs to reach the VM: run this
on your own computer with the VM's Dependency-Track port tunnelled to localhost, and it pulls
from every machine in `[machines.*]`, then uploads.

Per machine, scans run one after another and their SBOMs are merged into a single
Dependency-Track project `host:<name>`. An upload replaces the project's components, so a
machine is only uploaded when *all* its scans worked; otherwise it is skipped and the
previous SBOM stays in place.

Scans (see config.SCANS):
  system     syft on `/` (Linux; dpkg/rpm/apk packages, ...)
  brew       Homebrew formulae and casks (scripts/sbom-extras.py)
  languages  syft on pip/uv/pipx/npm/cargo locations under $HOME
  apps       macOS app bundles (scripts/sbom-extras.py)

Upstream behaviour relied on (not yet run live): `syft scan ... -o cyclonedx-json` with no
file writes the SBOM to stdout; `GET /api/version` on Dependency-Track is unauthenticated.
"""

from __future__ import annotations

import json
import re
import shlex
import subprocess  # noqa: S404 - fixed argv; ssh/sh with operator-supplied inventory values
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .clients import DependencyTrack
from .config import Inventory, Machine
from .net import HttpError

EXTRAS_SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "sbom-extras.py"

# non-interactive ssh has a minimal PATH: add where syft/brew/npm usually live
PATH_PREFIX = (
    'PATH="$HOME/.local/bin:/opt/homebrew/bin:/usr/local/bin:/home/linuxbrew/.linuxbrew/bin:$PATH"; '
    "export PATH; "
)
NEED_SYFT = 'command -v syft >/dev/null 2>&1 || { echo "syft not installed" >&2; exit 127; }; '
SYSTEM_EXCLUDES = (
    "./proc/**",
    "./sys/**",
    "./dev/**",
    "./run/**",
    "./home/**",
    "./tmp/**",
    "./var/lib/docker/**",
)
# relative to $HOME; plus `npm root -g` when npm exists
DEFAULT_LANGUAGE_PATHS = (
    ".local/share/uv/tools",
    ".local/pipx/venvs",
    ".local/share/pipx/venvs",
    ".cargo/bin",
)
VERSION_PROBE = (
    'if [ -r /etc/os-release ]; then . /etc/os-release; echo "${ID}-${VERSION_ID}"; '
    'elif command -v sw_vers >/dev/null 2>&1; then echo "macos-$(sw_vers -productVersion)"; '
    "else uname -sr; fi"
)
NOTHING_TO_SCAN = 3  # exit code of sbom-extras.py


class CollectError(RuntimeError):
    pass


@dataclass
class RunResult:
    returncode: int
    stdout: str
    stderr: str


# runner(machine, remote shell command, stdin) -> result; replaced in tests
Runner = Callable[[Machine, str, bytes | None], RunResult]


def run_command(machine: Machine, command: str, stdin: bytes | None = None, timeout: float = 900) -> RunResult:
    """Run a shell command on the machine: through ssh, or locally when `ssh` is empty."""
    if machine.ssh:
        argv = ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10", "--", machine.ssh, command]
    else:
        argv = ["sh", "-c", command]
    try:
        r = subprocess.run(  # noqa: S603 - argv list, no shell; ssh host validated in config
            argv, input=stdin or b"", capture_output=True, timeout=timeout, check=False
        )
    except subprocess.TimeoutExpired as e:
        raise CollectError(f"timed out after {timeout:.0f}s") from e
    except OSError as e:
        raise CollectError(f"cannot run {argv[0]}: {e}") from e
    return RunResult(r.returncode, r.stdout.decode("utf-8", "replace"), r.stderr.decode("utf-8", "replace"))


# ------------------------------------------------------------------ commands per scan
def system_command(m: Machine) -> str:
    excludes = " ".join(f"--exclude {shlex.quote(x)}" for x in SYSTEM_EXCLUDES)
    sudo = "sudo -n " if m.sudo else ""
    return f"{PATH_PREFIX}{NEED_SYFT}{sudo}syft scan dir:/ {excludes} -o cyclonedx-json -q"


def languages_command(m: Machine) -> str:
    paths = m.language_paths or list(DEFAULT_LANGUAGE_PATHS)
    items = " ".join(f'"$HOME"/{shlex.quote(p)}' for p in paths)
    return (
        f"{PATH_PREFIX}{NEED_SYFT}rc=0; "
        f"if command -v npm >/dev/null 2>&1; then npmroot=$(npm root -g 2>/dev/null); fi; "
        f'for p in {items} "$npmroot"; do '
        f'if [ -n "$p" ] && [ -d "$p" ]; then syft scan "dir:$p" -o cyclonedx-json -q || rc=1; fi; '
        "done; exit $rc"
    )


def extras_command(mode: str, cpe_map: dict[str, str]) -> str:
    args = f" --cpe-map {shlex.quote(json.dumps(cpe_map))}" if cpe_map else ""
    return f"{PATH_PREFIX}python3 - {mode}{args}"


# --------------------------------------------------------------------------- merging
def parse_docs(raw: str) -> list[dict[str, Any]]:
    """Zero or more concatenated JSON documents (one per syft run)."""
    dec = json.JSONDecoder()
    docs: list[dict[str, Any]] = []
    i, n = 0, len(raw)
    while True:
        while i < n and raw[i].isspace():
            i += 1
        if i >= n:
            return docs
        obj, i = dec.raw_decode(raw, i)
        if not isinstance(obj, dict):
            raise ValueError("expected a JSON object")
        docs.append(obj)


def _spec_key(doc: dict[str, Any]) -> tuple[int, ...]:
    return tuple(int(x) for x in re.findall(r"\d+", str(doc.get("specVersion", "1.5"))))


def merge_boms(docs: Sequence[dict[str, Any]]) -> dict[str, Any]:
    """One CycloneDX document: the union of all components, duplicates dropped.

    Only components survive (metadata and the dependency graph are not needed for matching).
    specVersion is the highest of the inputs so newer syft fields stay valid."""
    spec = max((_spec_key(d) for d in docs), default=(1, 5))
    seen: set[tuple[str, str, str, str]] = set()
    comps: list[dict[str, Any]] = []
    for n, d in enumerate(docs):
        for c in d.get("components") or []:
            key = (c.get("purl", ""), c.get("name", ""), c.get("version", ""), c.get("type", ""))
            if key in seen:
                continue
            seen.add(key)
            comps.append({**c, "bom-ref": f"s{n}:{c.get('bom-ref') or len(comps)}"})
    return {
        "bomFormat": "CycloneDX",
        "specVersion": ".".join(str(x) for x in spec),
        "version": 1,
        "components": comps,
    }


# ----------------------------------------------------------------------- collecting
@dataclass
class Collected:
    machine: Machine
    version: str
    sbom: bytes
    components: int
    scans: list[str]
    skipped: list[str] = field(default_factory=list)


def _clean_version(raw: str) -> str:
    v = re.sub(r"[^A-Za-z0-9._-]", "", raw.strip().splitlines()[0] if raw.strip() else "")
    return v or "unknown"


def collect_machine(
    m: Machine, inv: Inventory, run: Runner = run_command, extras: Path = EXTRAS_SCRIPT
) -> Collected:
    """All scans of one machine, merged. Raises CollectError if any requested scan fails."""
    docs: list[dict[str, Any]] = []
    done: list[str] = []
    skipped: list[str] = []
    for scan in m.scans:
        stdin: bytes | None = None
        if scan == "system":
            cmd = system_command(m)
        elif scan == "languages":
            cmd = languages_command(m)
        else:  # brew, apps
            if not extras.is_file():
                raise CollectError(f"{extras} not found")
            cmd, stdin = extras_command(scan, inv.cpe_map), extras.read_bytes()
        r = run(m, cmd, stdin)
        if scan in ("brew", "apps") and r.returncode == NOTHING_TO_SCAN:
            skipped.append(f"{scan} ({r.stderr.strip() or 'nothing to scan'})")
            continue
        if r.returncode != 0:
            raise CollectError(f"{scan} scan failed ({r.returncode}): {r.stderr.strip()[:300]}")
        try:
            docs.extend(parse_docs(r.stdout))
        except ValueError as e:
            raise CollectError(f"{scan} scan printed invalid JSON: {e}") from e
        done.append(scan)
    if not done:
        raise CollectError("no scan produced anything: " + "; ".join(skipped))
    merged = merge_boms(docs)
    version = m.version
    if not version:
        v = run(m, VERSION_PROBE, None)
        version = _clean_version(v.stdout) if v.returncode == 0 else "unknown"
    return Collected(
        m, version, json.dumps(merged).encode(), len(merged["components"]), done, skipped
    )


def project_name(m: Machine) -> str:
    return f"host:{m.name}"


def collect_all(
    inv: Inventory,
    dt: DependencyTrack | None,
    names: Sequence[str] = (),
    *,
    dry_run: bool = False,
    run: Runner = run_command,
    extras: Path = EXTRAS_SCRIPT,
) -> int:
    """Collect and upload; returns the process exit code (1 if any machine failed)."""
    if not inv.machines:
        print("  error no [machines.*] in the inventory", flush=True)
        return 1
    unknown = [n for n in names if n not in inv.machines]
    if unknown:
        print(f"  error unknown machine(s) {unknown}; choose from {sorted(inv.machines)}")
        return 2
    chosen = [inv.machines[n] for n in names] if names else list(inv.machines.values())

    if dry_run:
        for m in chosen:
            where = m.ssh or "this machine"
            print(f"  plan  {project_name(m)} [{m.team}] via {where}: {', '.join(m.scans)}")
        return 0

    if dt is None:
        print("  error Dependency-Track is not configured (DT_API_KEY)")
        return 2
    r = dt.http.get("api/version", expect_ok=False)
    if not r.ok:
        print(f"  error Dependency-Track answered HTTP {r.status} on /api/version; is it up?")
        return 1

    failed = 0
    for m in chosen:
        name = project_name(m)
        try:
            got = collect_machine(m, inv, run, extras)
            tags = [inv.teams[m.team].dtrack_tag, "kind-host" if m.kind == "linux" else "kind-laptop"]
            token = dt.upload_bom(name, got.version, got.sbom, tags)
        except (CollectError, HttpError, OSError) as e:
            failed += 1
            print(f"  FAIL  {name}: {e}")
            continue
        extra = f"; skipped {', '.join(got.skipped)}" if got.skipped else ""
        print(
            f"  ok    {name}@{got.version}: {got.components} components from "
            f"{', '.join(got.scans)}{extra} (token {token or '-'})"
        )
    return 1 if failed else 0
