"""CLI: python -m vulnflow {sync,dt2dojo,serve,enrich,upload-sbom,dt-bootstrap}"""

from __future__ import annotations

import argparse
import json
import logging
import sys
import time
from dataclasses import asdict
from pathlib import Path

from .clients import DefectDojo, DependencyTrack, OpenCVE
from .config import env, env_flag, load_dotenv, load_inventory
from .intel import Enricher
from .jobs import dt_to_dojo, sync_inventory
from .priority import assess


def _enricher(data_dir: Path) -> Enricher:
    return Enricher(cache_dir=data_dir, use_kev=env_flag("VULNFLOW_ENRICH_KEV"),
                    use_epss=env_flag("VULNFLOW_ENRICH_EPSS"),
                    use_circl=env_flag("VULNFLOW_ENRICH_CIRCL"),
                    circl_url=env("CIRCL_URL", "https://vulnerability.circl.lu"))


def _opencve() -> OpenCVE | None:
    if not env("OPENCVE_TOKEN"):
        print("  skip  OpenCVE (OPENCVE_TOKEN not set)")
        return None
    return OpenCVE(env("OPENCVE_URL", "http://localhost"), env("OPENCVE_ORG", required=True),
                   env("OPENCVE_TOKEN"))


def _dtrack(required: bool = False) -> DependencyTrack | None:
    if not env("DT_API_KEY", required=required):
        print("  skip  Dependency-Track (DT_API_KEY not set)")
        return None
    return DependencyTrack(env("DT_URL", "http://localhost:8180"), env("DT_API_KEY"))


def _dojo(required: bool = False) -> DefectDojo | None:
    if not env("DD_API_KEY", required=required):
        print("  skip  DefectDojo (DD_API_KEY not set)")
        return None
    return DefectDojo(env("DD_URL", "http://localhost:8280"), env("DD_API_KEY"))


def _dt_bootstrap(env_file: str, team_name: str, wait: float) -> int:
    from .bootstrap import BootstrapError, bootstrap_dtrack, new_secret, set_env_values
    admin_pw = env("DT_ADMIN_PASSWORD")
    if not admin_pw:
        # Persist before use so a crash mid-way can't lose the new admin password
        admin_pw = new_secret()
        set_env_values(env_file, {"DT_ADMIN_PASSWORD": admin_pw})
        print(f"  gen   DT_ADMIN_PASSWORD written to {env_file}")
    try:
        res = bootstrap_dtrack(env("DT_URL", "http://localhost:8180"),
                               admin_password=admin_pw, team_name=team_name,
                               existing_key=env("DT_API_KEY"), wait_timeout=wait)
    except BootstrapError as e:
        print(f"  error {e}", file=sys.stderr)
        return 1
    print(f"  {'set ' if res.changed_admin_password else 'ok  '}  admin password "
          f"(DT_ADMIN_PASSWORD in {env_file})")
    print(f"  {'new ' if res.created_team else 'ok  '}  team '{team_name}' {res.team_uuid}")
    if res.api_key:
        set_env_values(env_file, {"DT_API_KEY": res.api_key})
        print(f"  new   API key written to {env_file} as DT_API_KEY")
    else:
        print("  ok    existing DT_API_KEY still valid")
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="vulnflow", description=__doc__)
    ap.add_argument("--env-file", default=".env")
    ap.add_argument("--inventory", default="inventory/inventory.toml")
    ap.add_argument("--data-dir", default="data")
    ap.add_argument("-v", "--verbose", action="store_true")
    sub = ap.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("sync", help="push inventory to OpenCVE/DefectDojo, report DT coverage")
    s.add_argument("--dry-run", action="store_true")
    s.add_argument("--create-projects", action="store_true",
                   help="try to create missing OpenCVE projects via API (verify endpoint first)")

    d = sub.add_parser("dt2dojo", help="copy Dependency-Track findings into DefectDojo")
    d.add_argument("--dry-run", action="store_true")
    d.add_argument("--loop", type=int, default=0, metavar="SECONDS",
                   help="repeat every N seconds (for running as a service)")

    sv = sub.add_parser("serve", help="run the OpenCVE webhook receiver")
    sv.add_argument("--host", default="0.0.0.0")
    sv.add_argument("--port", type=int, default=None)

    e = sub.add_parser("enrich", help="show KEV/EPSS/sightings + tier for CVE IDs")
    e.add_argument("cves", nargs="+")
    e.add_argument("--cvss", type=float, default=None)
    e.add_argument("--json", action="store_true")

    u = sub.add_parser("upload-sbom", help="upload a CycloneDX SBOM to DT, tagged by team")
    u.add_argument("--team", required=True)
    u.add_argument("--name", required=True)
    u.add_argument("--version", default="")
    u.add_argument("--file", required=True, type=Path)
    u.add_argument("--tag", action="append", default=[], help="extra tags")

    b = sub.add_parser("dt-bootstrap",
                       help="first-run Dependency-Track setup: admin password, team, API key")
    b.add_argument("--team-name", default="vulnflow")
    b.add_argument("--wait", type=float, default=600, metavar="SECONDS",
                   help="how long to wait for the API server to come up")

    a = ap.parse_args(argv)
    logging.basicConfig(level=logging.DEBUG if a.verbose else logging.INFO,
                        format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    load_dotenv(a.env_file)
    inv = load_inventory(a.inventory)
    data_dir = Path(a.data_dir)

    if a.cmd == "sync":
        rep = sync_inventory(inv, opencve=_opencve(), dtrack=_dtrack(), dojo=_dojo(),
                             create_projects=a.create_projects, dry_run=a.dry_run)
        rep.print()
        return 1 if rep.errors else 0

    if a.cmd == "dt2dojo":
        dt, dd = _dtrack(required=True), _dojo(required=True)
        assert dt and dd
        while True:
            rep = dt_to_dojo(inv, dt, dd, dry_run=a.dry_run)
            rep.print()
            if not a.loop:
                return 1 if rep.errors else 0
            time.sleep(a.loop)

    if a.cmd == "serve":
        from .receiver import Pipeline, serve
        triage = int(env("VULNFLOW_OPENCVE_TRIAGE_MAX_TIER", "0") or 0)
        pipe = Pipeline(inv, _enricher(data_dir), data_dir / "alerts.jsonl",
                        chat_webhook=env("VULNFLOW_CHAT_WEBHOOK"),
                        opencve_url=env("OPENCVE_URL"),
                        opencve=_opencve() if triage else None,
                        triage_max_tier=triage)
        serve(pipe, env("VULNFLOW_WEBHOOK_TOKEN", required=True), a.host,
              a.port or int(env("VULNFLOW_PORT", "8380")))
        return 0

    if a.cmd == "enrich":
        sigs = _enricher(data_dir).enrich(a.cves)
        for cid, sig in sigs.items():
            v = assess(a.cvss, sig, inv.rules)
            if a.json:
                print(json.dumps({**asdict(sig), "tier": v.tier, "reasons": v.reasons}))
            else:
                epss = f"{sig.epss:.4f} (p{(sig.epss_percentile or 0) * 100:.0f})" \
                    if sig.epss is not None else "n/a"
                print(f"{cid}: {v.name} | KEV={'yes' if sig.kev else 'no'} EPSS={epss} "
                      f"sightings={sig.sightings or '-'} | {'; '.join(v.reasons)}")
        return 0

    if a.cmd == "dt-bootstrap":
        return _dt_bootstrap(a.env_file, a.team_name, a.wait)

    if a.cmd == "upload-sbom":
        team = inv.teams.get(a.team)
        if not team:
            print(f"unknown team '{a.team}', choose from {sorted(inv.teams)}", file=sys.stderr)
            return 2
        dt = _dtrack(required=True)
        assert dt
        token = dt.upload_bom(a.name, a.version, a.file.read_bytes(),
                              [team.dtrack_tag, *a.tag])
        print(f"uploaded {a.file} -> {a.name}@{a.version or '-'} "
              f"[{team.dtrack_tag}] token={token}")
        return 0
    return 2


if __name__ == "__main__":
    sys.exit(main())
