"""Devices from a list into Dependency-Track (`vulnflow device-sboms`; docs/sboms.md).

Network and appliance devices (firewalls, switches, hypervisors) run firmware whose version
changes too often to keep in machines.toml by hand, and they have no agent. Their versions
come from a system that already has them (NetBox, Ansible facts, the vendor's management
system, the CMDB), exported to a device list: `devices.csv` in the repository root (or
$VULNFLOW_DEVICES; `.json` for a JSON list), parsed by config.load_devices. Like
machines.toml it names your devices, so it is in .gitignore and .dockerignore.

Each device becomes a one-component CycloneDX SBOM, uploaded as project `net:<name>`,
version = the device's version, tags team-<team>, kind-net and source-devices. The
component carries the device's NVD CPE (`cpe:2.3:o:fortinet:fortios:7.4.3:...`), so
Dependency-Track matches it against NVD's version ranges and the ranking, DefectDojo tiers,
finding-watch and the reports apply as for any project. The context columns of the list
(exposure, criticality, eol, ...) are the asset context of `net:<name>` (context.py), and a
`[projects."net:<name>"]` in machines.toml still overrides them.

- Uploaded when the device's CPE or team changed, and again about once a day otherwise:
  `prune` deactivates a `kind-*` project after 7 days without an upload. A device dropped
  from the list is therefore retired by prune a week later; a new version is a new project
  version, and prune retires the old one.
- Dependency-Track applies tags only when it creates a project version, so a device moved
  to another team keeps its old team tag until its next version (or move it in DT).
- CPE matching depends on NVD adding CPEs to new CVEs, which is often late; the OpenCVE
  product subscriptions stay the early warning.

Uses DT_API_KEY (team vulnflow: BOM_UPLOAD + PROJECT_CREATION_UPLOAD), like github-sboms.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .clients import DependencyTrack
from .config import DEVICE_PARTS, Device, Inventory, Machines

STATE_FILE = "device-sboms.json"
REFRESH_SECONDS = 20 * 3600  # upload unchanged devices again about once a day (prune: 7 days)
TAGS = ("kind-net", "source-devices")


def device_bom(d: Device) -> bytes:
    """A CycloneDX 1.5 SBOM with the device as its one component."""
    component = {
        "type": DEVICE_PARTS[d.part],
        "bom-ref": d.project,
        "name": d.product,
        "version": d.version,
        "publisher": d.vendor,
        "cpe": d.cpe,
        "purl": f"pkg:generic/{d.vendor}/{d.product}@{d.version}",
    }
    bom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "metadata": {"component": {"type": "device", "name": d.project}},
        "components": [component],
    }
    return json.dumps(bom, sort_keys=True).encode()


@dataclass
class ImportResult:
    uploaded: list[str] = field(default_factory=list)
    unchanged: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


def _load_state(path: Path) -> dict[str, dict[str, Any]]:
    """Last upload per device; an unreadable file uploads everything again (harmless)."""
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return {k: v for k, v in data.items() if isinstance(v, dict)} if isinstance(data, dict) else {}


def import_devices(
    machines: Machines,
    inv: Inventory,
    dt: DependencyTrack,
    state_path: Path,
    *,
    now: float | None = None,
    dry_run: bool = False,
    force: bool = False,
) -> ImportResult:
    res = ImportResult()
    now = time.time() if now is None else now
    state = _load_state(state_path)
    for name, d in sorted(machines.devices.items()):
        label = f"{d.project}@{d.version} ({d.cpe})"
        sig = f"{d.cpe}|{d.team}"
        last = state.get(name) or {}
        due = (
            force
            or last.get("sig") != sig
            or now - float(last.get("uploaded", 0) or 0) >= REFRESH_SECONDS
        )
        if not due:
            res.unchanged.append(name)
            continue
        if dry_run:
            res.uploaded.append(f"{label} [dry run]")
            continue
        try:
            team = inv.teams[d.team]
            dt.upload_bom(d.project, d.version, device_bom(d), [team.dtrack_tag, *TAGS])
        except Exception as e:
            res.errors.append(f"{d.project}: {e}")
            continue
        state[name] = {"sig": sig, "uploaded": now}
        res.uploaded.append(label)
    if not dry_run and res.uploaded:
        state_path.parent.mkdir(parents=True, exist_ok=True)
        tmp = state_path.with_suffix(".tmp")
        tmp.write_text(json.dumps(state, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        tmp.replace(state_path)
    return res
