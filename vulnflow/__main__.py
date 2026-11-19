"""CLI: python -m vulnflow {sync,dt2dojo,serve,enrich,upload-sbom,
dt-bootstrap,dd-bootstrap,opencve-bootstrap,env-set}"""

from __future__ import annotations

import argparse
import json
import logging
import sys
import time
from dataclasses import asdict
from pathlib import Path

from .clients import DefectDojo, DependencyTrack, OpenCVE
from .config import Inventory, env, env_flag, load_dotenv, load_inventory
from .intel import Enricher
from .jobs import dt_to_dojo, sync_inventory
from .priority import assess


def _enricher(data_dir: Path) -> Enricher:
    return Enricher(
        cache_dir=data_dir,
        use_kev=env_flag("VULNFLOW_ENRICH_KEV"),
        use_epss=env_flag("VULNFLOW_ENRICH_EPSS"),
        use_circl=env_flag("VULNFLOW_ENRICH_CIRCL"),
        circl_url=env("CIRCL_URL", "https://vulnerability.circl.lu"),
    )


def _opencve() -> OpenCVE | None:
    if not env("OPENCVE_TOKEN"):
        print("  skip  OpenCVE (OPENCVE_TOKEN not set)")
        return None
    # OPENCVE_API_URL: how *this process* reaches OpenCVE (the receiver container uses the
    # OpenCVE docker network); OPENCVE_URL stays the browser-facing URL used in chat links.
    base = env("OPENCVE_API_URL") or env("OPENCVE_URL", "http://localhost")
    return OpenCVE(base, env("OPENCVE_ORG", required=True), env("OPENCVE_TOKEN"))


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
        res = bootstrap_dtrack(
            env("DT_URL", "http://localhost:8180"),
            admin_password=admin_pw,
            team_name=team_name,
            existing_key=env("DT_API_KEY"),
            wait_timeout=wait,
        )
    except BootstrapError as e:
        print(f"  error {e}", file=sys.stderr)
        return 1
    print(
        f"  {'set ' if res.changed_admin_password else 'ok  '}  admin password "
        f"(DT_ADMIN_PASSWORD in {env_file})"
    )
    print(f"  {'new ' if res.created_team else 'ok  '}  team '{team_name}' {res.team_uuid}")
    if res.api_key:
        set_env_values(env_file, {"DT_API_KEY": res.api_key})
        print(f"  new   API key written to {env_file} as DT_API_KEY")
    else:
        print("  ok    existing DT_API_KEY still valid")
    return 0


def _dd_bootstrap(env_file: str, wait: float) -> int:
    from .bootstrap import BootstrapError, bootstrap_defectdojo, set_env_values

    try:
        key = bootstrap_defectdojo(
            env("DD_URL", "http://localhost:8280"),
            admin_user=env("DD_ADMIN_USER", "admin"),
            admin_password=env("DD_ADMIN_PASSWORD", required=True),
            existing_key=env("DD_API_KEY"),
            wait_timeout=wait,
        )
    except BootstrapError as e:
        print(f"  error {e}", file=sys.stderr)
        return 1
    if key:
        set_env_values(env_file, {"DD_API_KEY": key})
        print(f"  new   API v2 key written to {env_file} as DD_API_KEY")
    else:
        print("  ok    existing DD_API_KEY still valid")
    return 0


def _opencve_bootstrap(inv: Inventory, webhook_url: str) -> int:
    oc = _opencve()
    if oc is None:
        print("  error OPENCVE_TOKEN missing; run ./poc.sh opencve-bootstrap", file=sys.stderr)
        return 1
    rep = sync_inventory(inv, opencve=oc, dtrack=None, dojo=None, create_projects=True)
    rep.print()
    if rep.errors:
        return 1
    token = env("VULNFLOW_WEBHOOK_TOKEN", required=True)
    for team in inv.teams.values():
        created = oc.ensure_webhook(
            team.opencve_project, "vulnflow", webhook_url, {"X-Vulnflow-Token": token}
        )
        print(f"  {'new ' if created else 'ok  '}  webhook {team.opencve_project} -> {webhook_url}")
    return 0


def _env_set(env_file: str) -> int:
    """KEY=VALUE lines on stdin -> .env (keeps secrets off the command line)."""
    from .bootstrap import set_env_values

    values = {}
    for line in sys.stdin.read().splitlines():
        if line.strip():
            k, sep, v = line.partition("=")
            if not sep:
                print(f"  error expected KEY=VALUE, got {k!r}", file=sys.stderr)
                return 2
            values[k.strip()] = v
    set_env_values(env_file, values)
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
    s.add_argument(
        "--create-projects",
        action="store_true",
        help="try to create missing OpenCVE projects via API (verify endpoint first)",
    )

    d = sub.add_parser("dt2dojo", help="copy Dependency-Track findings into DefectDojo")
    d.add_argument("--dry-run", action="store_true")
    d.add_argument(
        "--loop",
        type=int,
        default=0,
        metavar="SECONDS",
        help="repeat every N seconds (for running as a service)",
    )

    sv = sub.add_parser("serve", help="run the OpenCVE webhook receiver")
    sv.add_argument("--host", default="0.0.0.0")  # noqa: S104 - runs in a container
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

    b = sub.add_parser(
        "dt-bootstrap", help="first-run Dependency-Track setup: admin password, team, API key"
    )
    b.add_argument("--team-name", default="vulnflow")
    b.add_argument(
        "--wait",
        type=float,
        default=600,
        metavar="SECONDS",
        help="how long to wait for the API server to come up",
    )

    ddb = sub.add_parser("dd-bootstrap", help="first-run DefectDojo setup: API key for admin")
    ddb.add_argument("--wait", type=float, default=900, metavar="SECONDS")

    ob = sub.add_parser(
        "opencve-bootstrap",
        help="create OpenCVE projects/subscriptions + webhook notifications "
        "(org + token come from poc.sh opencve-bootstrap)",
    )
    ob.add_argument("--webhook-url", default=None, help="default: $VULNFLOW_WEBHOOK_URL")

    sub.add_parser("env-set", help="read KEY=VALUE lines from stdin into the .env file")

    a = ap.parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if a.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    load_dotenv(a.env_file)
    if a.cmd == "env-set":
        return _env_set(a.env_file)
    if a.cmd == "dd-bootstrap":
        return _dd_bootstrap(a.env_file, a.wait)
    inv = load_inventory(a.inventory)
    data_dir = Path(a.data_dir)

    if a.cmd == "sync":
        rep = sync_inventory(
            inv,
            opencve=_opencve(),
            dtrack=_dtrack(),
            dojo=_dojo(),
            create_projects=a.create_projects,
            dry_run=a.dry_run,
        )
        rep.print()
        return 1 if rep.errors else 0

    if a.cmd == "dt2dojo":
        dt, dd = _dtrack(required=True), _dojo(required=True)
        if dt is None or dd is None:  # unreachable: required=True exits first
            return 2
        while True:
            rep = dt_to_dojo(inv, dt, dd, dry_run=a.dry_run)
            rep.print()
            if not a.loop:
                return 1 if rep.errors else 0
            time.sleep(a.loop)

    if a.cmd == "serve":
        from .receiver import Pipeline, serve

        triage = int(env("VULNFLOW_OPENCVE_TRIAGE_MAX_TIER", "0") or 0)
        pipe = Pipeline(
            inv,
            _enricher(data_dir),
            data_dir / "alerts.jsonl",
            chat_webhook=env("VULNFLOW_CHAT_WEBHOOK"),
            opencve_url=env("OPENCVE_URL"),
            opencve=_opencve() if triage else None,
            triage_max_tier=triage,
        )
        serve(
            pipe,
            env("VULNFLOW_WEBHOOK_TOKEN", required=True),
            a.host,
            a.port or int(env("VULNFLOW_PORT", "8380")),
        )
        return 0

    if a.cmd == "enrich":
        sigs = _enricher(data_dir).enrich(a.cves)
        for cid, sig in sigs.items():
            v = assess(a.cvss, sig, inv.rules)
            if a.json:
                print(json.dumps({**asdict(sig), "tier": v.tier, "reasons": v.reasons}))
            else:
                epss = (
                    f"{sig.epss:.4f} (p{(sig.epss_percentile or 0) * 100:.0f})"
                    if sig.epss is not None
                    else "n/a"
                )
                print(
                    f"{cid}: {v.name} | KEV={'yes' if sig.kev else 'no'} EPSS={epss} "
                    f"sightings={sig.sightings or '-'} | {'; '.join(v.reasons)}"
                )
        return 0

    if a.cmd == "dt-bootstrap":
        return _dt_bootstrap(a.env_file, a.team_name, a.wait)

    if a.cmd == "opencve-bootstrap":
        return _opencve_bootstrap(
            inv, a.webhook_url or env("VULNFLOW_WEBHOOK_URL", "http://vulnflow-receiver:8380/opencve")
        )

    if a.cmd == "upload-sbom":
        team = inv.teams.get(a.team)
        if not team:
            print(f"unknown team '{a.team}', choose from {sorted(inv.teams)}", file=sys.stderr)
            return 2
        dt = _dtrack(required=True)
        if dt is None:  # unreachable: required=True exits first
            return 2
        token = dt.upload_bom(a.name, a.version, a.file.read_bytes(), [team.dtrack_tag, *a.tag])
        print(f"uploaded {a.file} -> {a.name}@{a.version or '-'} [{team.dtrack_tag}] token={token}")
        return 0
    return 2


if __name__ == "__main__":
    sys.exit(main())
