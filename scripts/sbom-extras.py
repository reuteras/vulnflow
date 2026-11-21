#!/usr/bin/env python3
"""CycloneDX SBOMs for things syft doesn't catalogue: Homebrew and macOS apps.

    python3 sbom-extras.py brew [--cpe-map JSON]    # formulae + casks from `brew info`
    python3 sbom-extras.py apps [--cpe-map JSON]    # /Applications/*.app bundles (macOS)

The SBOM goes to stdout. `python -m vulnflow collect` pipes this file to the machine over
ssh (`python3 - brew ...`), so it must stay self-contained, standard library only, and run
on the Python 3 that ships with macOS (3.9) as well as on Linux.

Exit codes: 0 ok, 2 bad usage, 3 nothing to scan (no Homebrew / not macOS), 1 other error.

Matching is best effort. Homebrew has no package-URL type and no OSV ecosystem, so
Dependency-Track can only match these components through their CPE. NVD vendor names are
not derivable from Homebrew metadata: the default guess is vendor = product, a few
well-known exceptions are built in (CPE_VENDORS), and `[cpe_map]` in
inventory/inventory.toml overrides both. Anything that stays unmatched is better covered
by OpenCVE product subscriptions.
"""

from __future__ import annotations

import json
import os
import plistlib
import re
import shutil
import subprocess
import sys
from pathlib import Path
from urllib.parse import quote

# formula/cask/bundle name -> "vendor:product" as NVD spells it. Only entries where the
# name differs from the NVD product and the NVD name is well known.
CPE_VENDORS = {
    "bash": "gnu:bash",
    "coreutils": "gnu:coreutils",
    "curl": "haxx:curl",
    "git": "git-scm:git",
    "gnupg": "gnupg:gnupg",
    "node": "nodejs:node.js",
    "openssl": "openssl:openssl",
    "python": "python:python",
    "sqlite": "sqlite:sqlite",
    "vim": "vim:vim",
    "wget": "gnu:wget",
}

BREW_CANDIDATES = (
    "/opt/homebrew/bin/brew",  # macOS, Apple silicon
    "/usr/local/bin/brew",  # macOS, Intel
    "/home/linuxbrew/.linuxbrew/bin/brew",  # Linux
)
APP_DIRS = ("/Applications", "~/Applications")


def _cpe_part(s: str) -> str:
    return re.sub(r"[^a-z0-9._]", "_", s.lower())


def make_cpe(vendor: str, product: str, version: str) -> str:
    return f"cpe:2.3:a:{_cpe_part(vendor)}:{_cpe_part(product)}:{_cpe_part(version)}:*:*:*:*:*:*:*"


def clean_version(v: str) -> str:
    """Homebrew appends the bottle revision as `_N` (3.12.7_1); NVD versions don't have it."""
    return re.sub(r"_\d+$", "", str(v).strip())


def resolve_cpe(
    keys: list[str], vendor_product: tuple[str, str], cpe_map: dict[str, str]
) -> tuple[str, str]:
    """vendor, product: first hit in the operator's map, then the built-in table, then the guess."""
    for table in (cpe_map, CPE_VENDORS):
        for k in keys:
            if k in table:
                vendor, _, product = table[k].partition(":")
                return vendor, product
    return vendor_product


def _component(
    *, name: str, version: str, kind: str, source: str, vendor: str, product: str, ident: str = ""
) -> dict[str, object]:
    comp: dict[str, object] = {
        "type": kind,
        "bom-ref": f"{source}:{ident or name}@{version}",
        "name": name,
        "version": version,
        # No package-URL type exists for Homebrew or app bundles; `generic` is the honest one.
        "purl": f"pkg:generic/{quote(ident or name, safe='')}@{quote(version, safe='')}",
        "cpe": make_cpe(vendor, product, version),
        "properties": [{"name": "vulnflow:source", "value": source}],
    }
    return comp


def bom(components: list[dict[str, object]]) -> dict[str, object]:
    return {"bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1, "components": components}


def brew_bom(info: dict[str, object], cpe_map: dict[str, str]) -> dict[str, object]:
    """SBOM from `brew info --json=v2 --installed`.

    Shape assumed from Homebrew's formula/cask JSON API (not yet run against a real brew):
    formulae[].name + installed[].version; casks[].token + installed (a version string)."""
    comps: list[dict[str, object]] = []
    for f in info.get("formulae") or []:  # type: ignore[attr-defined]
        name = str(f["name"])
        product = name.split("@")[0]  # python@3.12 -> python
        for inst in f.get("installed") or []:
            ver = clean_version(inst.get("version", ""))
            if not ver:
                continue
            vendor, prod = resolve_cpe([name, product], (product, product), cpe_map)
            comps.append(
                _component(
                    name=name,
                    version=ver,
                    kind="application",
                    source="homebrew",
                    vendor=vendor,
                    product=prod,
                )
            )
    for c in info.get("casks") or []:  # type: ignore[attr-defined]
        token = str(c["token"])
        inst = c.get("installed")
        ver = clean_version(inst if isinstance(inst, str) else c.get("version", ""))
        if not ver:
            continue
        vendor, prod = resolve_cpe([token], (token, token), cpe_map)
        comps.append(
            _component(
                name=token,
                version=ver,
                kind="application",
                source="homebrew-cask",
                vendor=vendor,
                product=prod,
            )
        )
    return bom(comps)


def app_entry(plist: dict[str, object], cpe_map: dict[str, str]) -> dict[str, object] | None:
    bundle_id = str(plist.get("CFBundleIdentifier") or "")
    name = str(plist.get("CFBundleDisplayName") or plist.get("CFBundleName") or "")
    ver = str(plist.get("CFBundleShortVersionString") or plist.get("CFBundleVersion") or "").strip()
    if not (bundle_id and name and ver):
        return None
    # com.google.Chrome -> google:chrome; org.mozilla.firefox -> mozilla:firefox
    parts = bundle_id.lower().split(".")
    guess = (parts[1], parts[-1]) if len(parts) >= 3 else (parts[-1], parts[-1])
    vendor, prod = resolve_cpe([bundle_id, name], guess, cpe_map)
    return _component(
        name=name,
        version=ver,
        kind="application",
        source="macos-app",
        vendor=vendor,
        product=prod,
        ident=bundle_id,
    )


def apps_bom(plists: list[dict[str, object]], cpe_map: dict[str, str]) -> dict[str, object]:
    comps = [c for p in plists if (c := app_entry(p, cpe_map)) is not None]
    return bom(comps)


def find_brew() -> str | None:
    found = shutil.which("brew")
    if found:
        return found
    return next((p for p in BREW_CANDIDATES if os.access(p, os.X_OK)), None)


def read_app_plists() -> list[dict[str, object]]:
    out: list[dict[str, object]] = []
    for d in APP_DIRS:
        root = Path(d).expanduser()
        if not root.is_dir():
            continue
        for app in sorted(root.glob("*.app")):
            try:
                with (app / "Contents" / "Info.plist").open("rb") as fh:
                    out.append(plistlib.load(fh))
            except (OSError, plistlib.InvalidFileException, ValueError) as e:
                print(f"skip {app}: {e}", file=sys.stderr)
    return out


def main(argv: list[str]) -> int:
    if not argv or argv[0] not in ("brew", "apps"):
        print(__doc__, file=sys.stderr)
        return 2
    mode, rest = argv[0], argv[1:]
    cpe_map: dict[str, str] = {}
    if rest[:1] == ["--cpe-map"] and len(rest) == 2:
        cpe_map = {str(k): str(v) for k, v in json.loads(rest[1]).items()}
    elif rest:
        print("usage: sbom-extras.py {brew|apps} [--cpe-map JSON]", file=sys.stderr)
        return 2

    if mode == "apps":
        if sys.platform != "darwin":
            print("apps: not macOS, nothing to scan", file=sys.stderr)
            return 3
        json.dump(apps_bom(read_app_plists(), cpe_map), sys.stdout)
        return 0

    brew = find_brew()
    if brew is None:
        print("brew: Homebrew not found, nothing to scan", file=sys.stderr)
        return 3
    env = {**os.environ, "HOMEBREW_NO_AUTO_UPDATE": "1", "HOMEBREW_NO_ANALYTICS": "1"}
    res = subprocess.run(  # noqa: S603 - fixed argv, brew path from PATH or a fixed list
        [brew, "info", "--json=v2", "--installed"],
        capture_output=True,
        text=True,
        env=env,
        check=False,
        timeout=600,
    )
    if res.returncode != 0:
        print(f"brew info failed ({res.returncode}): {res.stderr.strip()[:500]}", file=sys.stderr)
        return 1
    json.dump(brew_bom(json.loads(res.stdout), cpe_map), sys.stdout)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
