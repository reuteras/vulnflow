"""CLI: python -m vulnflow {sync,dt2dojo,serve,enrich,patches,debian,vendor,disputed,
ignore,unignore,upload-sbom,machines,agent-bundle,agent-revoke,dt-bootstrap,dd-bootstrap,opencve-bootstrap,
opencve-webhook-input,env-set,check-updates}"""

from __future__ import annotations

import argparse
import json
import logging
import sys
import time
from dataclasses import asdict
from pathlib import Path

from .clients import OSV, DefectDojo, DependencyTrack, OpenCVE
from .config import (
    Inventory,
    add_subscriptions,
    env,
    env_flag,
    load_dotenv,
    load_inventory,
    load_machines,
)
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
            osv_ecosystems=tuple(
                e.strip() for e in env("DT_OSV_ECOSYSTEMS", "Debian,PyPI").split(",") if e.strip()
            ),
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
    if res.osv.startswith("failed"):
        print(
            f"  warn  OSV source not configured ({res.osv}); enable it in the DT UI "
            "(see README 'After setup')",
            file=sys.stderr,
        )
    else:
        print(f"  {'set ' if res.osv.startswith('updated') else 'ok  '}  OSV source: {res.osv}")
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


def _opencve_bootstrap(inv: Inventory) -> int:
    oc = _opencve()
    if oc is None:
        print("  error OPENCVE_TOKEN missing; run ./poc.sh opencve-bootstrap", file=sys.stderr)
        return 1
    rep = sync_inventory(inv, opencve=oc, dtrack=None, dojo=None, create_projects=True)
    rep.print()
    return 1 if rep.errors else 0


def opencve_webhook_input(inv: Inventory, webhook_url: str, token: str, org: str) -> str:
    """First line for stacks/opencve/bootstrap_webhooks.py (a Python assignment, VF = {...}).

    The webhook is created through Django because OpenCVE v3.1.0's API rejects every
    private URL (see that script). json.dumps output is a valid Python literal here: only
    strings, a list and dicts, no true/false/null."""
    spec = {
        "org": org,
        "projects": sorted({t.opencve_project for t in inv.teams.values()}),
        "name": "vulnflow",
        "url": webhook_url,
        "headers": {"X-Vulnflow-Token": token},
    }
    return "VF = " + json.dumps(spec)


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


def _ignore(a: argparse.Namespace) -> int:
    from .bootstrap import BootstrapError, dt_admin_http
    from .triage import ReviewFileError, apply_ignores, load_review

    try:
        items = load_review(a.review)
    except ReviewFileError as e:
        print(f"  error {e}", file=sys.stderr)
        return 2
    for it in items:
        print(f"  {it.team}/{it.project}: {it.component} {it.version} {it.vuln_id} -> {a.state}")
        print(f"      comment: {it.comment}")
    if not a.apply:
        print(
            f"  dry run: {len(items)} finding(s) would be set to {a.state} and suppressed; add --apply"
        )
        return 0
    try:
        admin = dt_admin_http(
            env("DT_URL", "http://localhost:8180"), env("DT_ADMIN_PASSWORD", required=True)
        )
    except BootstrapError as e:
        print(f"  error {e}", file=sys.stderr)
        return 1
    written, skipped, kept, errors = apply_ignores(
        admin,
        items,
        a.state,
        a.justification,
        overwrite=a.overwrite,
        ledger=Path(a.data_dir) / "ignored.jsonl",
    )
    print(f"  {len(written)} written, {len(skipped)} already {a.state} and suppressed")
    for k in kept:
        print(
            f"  kept  {k.item.team}/{k.item.project}: {k.item.component} {k.item.vuln_id} "
            f"already triaged as {k.state}; --overwrite to replace it"
        )
    if written:
        print(f"  logged in {Path(a.data_dir) / 'ignored.jsonl'}; `vulnflow unignore` reverts")
    for msg in errors:
        print(f"  error {msg}", file=sys.stderr)
    return 1 if errors else 0


def _unignore(a: argparse.Namespace) -> int:
    from .bootstrap import BootstrapError, dt_admin_http
    from .triage import ReviewFileError, apply_reverts, load_review, plan_reverts

    ledger = Path(a.data_dir) / "ignored.jsonl"
    try:
        rows = load_review(a.review) if a.review else None
        todo = plan_reverts(ledger, rows, a.state)
    except ReviewFileError as e:
        print(f"  error {e}", file=sys.stderr)
        return 2
    if not todo:
        print(
            f"  nothing to undo: no outstanding entries in {ledger}"
            + (
                ""
                if a.review
                else "; for findings ignored before the ledger existed, pass --from review.json"
            )
        )
        return 0
    for it in todo:
        back = it.previous_state + (" (suppressed)" if it.previous_suppressed else "")
        src = "ledger" if it.from_ledger else "review file, previous state unknown"
        print(
            f"  {it.team}/{it.project}: {it.component} {it.vuln_id}: "
            f"{it.expected_state} -> {back} [{src}]"
        )
    if not a.apply:
        print(
            f"  dry run: {len(todo)} finding(s) would be reverted, each only if it is still as "
            "vulnflow left it; add --apply"
        )
        return 0
    try:
        admin = dt_admin_http(
            env("DT_URL", "http://localhost:8180"), env("DT_ADMIN_PASSWORD", required=True)
        )
    except BootstrapError as e:
        print(f"  error {e}", file=sys.stderr)
        return 1
    reverted, skipped, errors = apply_reverts(admin, todo, ledger)
    print(f"  {len(reverted)} reverted, {len(skipped)} left alone")
    for it, why in skipped:
        print(f"  left  {it.team}/{it.project}: {it.component} {it.vuln_id}: {why}")
    for msg in errors:
        print(f"  error {msg}", file=sys.stderr)
    return 1 if errors else 0


def _agent_dt_url() -> str:
    url = env("VULNFLOW_AGENT_DT_URL") or env("DT_PUBLIC_API_URL") or env("DT_URL")
    if "localhost" in url or "127.0.0.1" in url:
        print(
            f"  warn  agents would upload to {url}, which only works on this server; set "
            "VULNFLOW_TS_HOST (./poc.sh tailscale) or VULNFLOW_AGENT_DT_URL",
            file=sys.stderr,
        )
    return url


def _agent_bundle(a: argparse.Namespace, inv: Inventory) -> int:
    from .bootstrap import BootstrapError, agent_key, dt_admin_http
    from .machines import agent_config, read_bundle_key, write_bundle

    machines = load_machines(a.machines, inv.teams)
    names = sorted(machines.hosts) if a.all else a.hosts
    unknown = [h for h in names if h not in machines.hosts]
    if not names or unknown:
        print(f"  error unknown or no hosts {unknown}; choose from {sorted(machines.hosts)}")
        return 2
    url = _agent_dt_url()
    out = Path(a.out)
    try:
        admin = dt_admin_http(
            env("DT_URL", "http://localhost:8180"), env("DT_ADMIN_PASSWORD", required=True)
        )
        for h in names:
            key, new = agent_key(admin, h, read_bundle_key(out, h), rotate=a.rotate)
            d = write_bundle(out, h, agent_config(machines.hosts[h], machines, inv, url), key)
            print(f"  {'new ' if new else 'ok  '}  {d}/ (config.json, key{' (new)' if new else ''})")
    except BootstrapError as e:
        print(f"  error {e}", file=sys.stderr)
        return 1
    return 0


def _agent_revoke(a: argparse.Namespace) -> int:
    from .bootstrap import BootstrapError, dt_admin_http, revoke_agent

    try:
        admin = dt_admin_http(
            env("DT_URL", "http://localhost:8180"), env("DT_ADMIN_PASSWORD", required=True)
        )
        for h in a.hosts:
            gone = revoke_agent(admin, h)
            print(f"  {'del ' if gone else 'none'}  team agent-{h}{'' if gone else ' (not found)'}")
    except BootstrapError as e:
        print(f"  error {e}", file=sys.stderr)
        return 1
    return 0


def _machines(a: argparse.Namespace, inv: Inventory) -> int:
    from .machines import last_pushes, report

    machines = load_machines(a.machines, inv.teams)
    if not machines.hosts:
        print(f"  no hosts: copy machines.example.toml to {a.machines}")
        return 0
    dt = _dtrack()
    stale = report(machines, last_pushes(dt) if dt else None, stale_days=a.stale_days)
    return 1 if stale else 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="vulnflow", description=__doc__)
    ap.add_argument("--env-file", default=".env")
    ap.add_argument("--inventory", default="inventory/inventory.toml")
    ap.add_argument(
        "--machines",
        default=None,
        help="own hosts (not in git); default $VULNFLOW_MACHINES or machines.toml",
    )
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

    pt = sub.add_parser(
        "patches", help="open Dependency-Track findings whose vulnerability has a patched release"
    )
    pt.add_argument("--team", default=None, help="only this team (default: all)")
    pt.add_argument("--json", action="store_true")
    pt.add_argument(
        "--osv",
        action="store_true",
        help="also ask osv.dev (sends package URLs of findings DT has no fix for to api.osv.dev)",
    )

    db = sub.add_parser(
        "debian",
        help="what the Debian security tracker says (urgency, status, fixed version) about "
        "open findings on Debian components",
    )
    db.add_argument("--team", default=None, help="only this team (default: all)")
    db.add_argument("--json", action="store_true")
    db.add_argument("--release", default=None, help="codename (default: from each purl's distro=)")
    db.add_argument(
        "--ignorable",
        action="store_true",
        help="only entries Debian rates unimportant or end-of-life",
    )
    db.add_argument(
        "--action",
        choices=("update", "fixed", "no-fix", "unknown"),
        default=None,
        help="only update (a newer package fixes it), fixed (already fixed in the installed "
        "version: backport, candidates for `ignore`), no-fix or unknown",
    )

    vd = sub.add_parser(
        "vendor",
        help="what Ubuntu / Red Hat say about open findings on their packages (asks "
        "ubuntu.com / access.redhat.com per CVE id; needs --ubuntu and/or --redhat)",
    )
    vd.add_argument("--ubuntu", action="store_true", help="ask ubuntu.com about Ubuntu packages")
    vd.add_argument("--redhat", action="store_true", help="ask access.redhat.com about RPMs")
    vd.add_argument("--team", default=None, help="only this team (default: all)")
    vd.add_argument("--json", action="store_true")
    vd.add_argument(
        "--action",
        choices=("update", "fixed", "not-affected", "wontfix", "no-fix", "unknown"),
        default=None,
        help="only this verdict: update (a newer package fixes it), fixed (already fixed in "
        "the installed version), not-affected, wontfix (vendor will not fix it), no-fix, unknown",
    )

    dp = sub.add_parser(
        "disputed",
        help="open findings whose CVE record starts with ** DISPUTED ** or ** REJECT **",
    )
    dp.add_argument("--team", default=None, help="only this team (default: all)")
    dp.add_argument("--json", action="store_true")

    ig = sub.add_parser(
        "ignore",
        help="mark reviewed findings (a file edited down from `debian --json` or "
        "`disputed --json`) as not affected in Dependency-Track; dry run unless --apply",
    )
    ig.add_argument("--from", dest="review", required=True, type=Path, metavar="FILE")
    ig.add_argument("--apply", action="store_true", help="write to Dependency-Track")
    ig.add_argument("--state", choices=("NOT_AFFECTED", "FALSE_POSITIVE"), default="NOT_AFFECTED")
    ig.add_argument("--justification", default=None, help="DT analysisJustification, optional")
    ig.add_argument(
        "--overwrite",
        action="store_true",
        help="also replace a finding somebody already triaged (default: leave those alone)",
    )

    ui = sub.add_parser(
        "unignore",
        help="undo `ignore`: put back the analysis it replaced, only where a finding is still "
        "as vulnflow left it; dry run unless --apply",
    )
    ui.add_argument(
        "--from",
        dest="review",
        type=Path,
        default=None,
        metavar="FILE",
        help="only the findings in this review file (default: everything in the ledger "
        "that was not reverted; needed for findings ignored before the ledger existed)",
    )
    ui.add_argument("--apply", action="store_true", help="write to Dependency-Track")
    ui.add_argument(
        "--state",
        choices=("NOT_AFFECTED", "FALSE_POSITIVE"),
        default="NOT_AFFECTED",
        help="with --from and no ledger entry: the state `ignore` set",
    )

    u = sub.add_parser("upload-sbom", help="upload a CycloneDX SBOM to DT, tagged by team")
    u.add_argument("--team", required=True)
    u.add_argument("--name", required=True)
    u.add_argument("--version", default="")
    u.add_argument("--file", required=True, type=Path)
    u.add_argument("--tag", action="append", default=[], help="extra tags")

    mc = sub.add_parser(
        "machines", help="list own hosts by group and flag those that stopped pushing SBOMs"
    )
    mc.add_argument("--stale-days", type=float, default=2.0, metavar="DAYS")

    ab = sub.add_parser(
        "agent-bundle",
        help="per host: agent config.json + its own DT API key, for Ansible to copy (see README)",
    )
    ab.add_argument("hosts", nargs="*")
    ab.add_argument("--all", action="store_true", help="every host in machines.toml")
    ab.add_argument("--out", default="data/agents", help="directory for <host>/config.json + key")
    ab.add_argument("--rotate", action="store_true", help="new key even if the old one works")

    ss = sub.add_parser(
        "suggest-subscriptions",
        help="suggest OpenCVE subscriptions from what Dependency-Track has seen (prints TOML)",
    )
    ss.add_argument("--top", type=int, default=40, help="per team (default 40)")
    ss.add_argument("--libraries", action="store_true", help="include pypi/npm/golang/... libraries")
    ss.add_argument("--min-cves", type=int, default=1, help="leave out names with fewer CVEs")
    ss.add_argument(
        "--list-skipped", action="store_true", help="list the names left out, not just counts"
    )
    ar = sub.add_parser("agent-revoke", help="delete a host's DT team agent-<host> and its keys")
    ar.add_argument("hosts", nargs="+")

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

    sub.add_parser(
        "opencve-bootstrap",
        help="create OpenCVE projects/subscriptions from the inventory "
        "(org + token come from poc.sh opencve-bootstrap)",
    )
    owi = sub.add_parser(
        "opencve-webhook-input",
        help="print the input line for stacks/opencve/bootstrap_webhooks.py (contains the "
        "webhook token: pipe it, don't log it)",
    )
    owi.add_argument("--webhook-url", default=None, help="default: $VULNFLOW_WEBHOOK_URL")

    sub.add_parser("env-set", help="read KEY=VALUE lines from stdin into the .env file")

    sub.add_parser(
        "check-updates",
        help="newer DefectDojo/OpenCVE/Dependency-Track releases (7-day cooldown) and pinned "
        "versions not deployed yet",
    )

    a = ap.parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if a.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    load_dotenv(a.env_file)
    a.machines = a.machines or env("VULNFLOW_MACHINES") or "machines.toml"
    if a.cmd == "env-set":
        return _env_set(a.env_file)
    if a.cmd == "dd-bootstrap":
        return _dd_bootstrap(a.env_file, a.wait)
    if a.cmd == "check-updates":
        from .upstreams import check, report

        print(report(check(Path("."), Path(a.env_file))))
        return 0
    inv = load_inventory(a.inventory)
    data_dir = Path(a.data_dir)
    if a.cmd in ("sync", "opencve-bootstrap", "suggest-subscriptions"):
        # the detailed subscriptions live in machines.toml (not in git)
        add_subscriptions(inv, load_machines(a.machines, inv.teams))

    if a.cmd == "suggest-subscriptions":
        from .subscriptions import suggest

        dt = _dtrack(required=True)
        if dt is None:  # unreachable: required=True exits first
            return 2
        oc = None
        if env("OPENCVE_TOKEN"):  # quietly: stdout is the TOML to paste
            base = env("OPENCVE_API_URL") or env("OPENCVE_URL", "http://localhost")
            oc = OpenCVE(base, env("OPENCVE_ORG", required=True), env("OPENCVE_TOKEN"))
        print(
            suggest(
                inv,
                dt,
                opencve=oc,
                top=a.top,
                min_cves=a.min_cves,
                libraries=a.libraries,
                list_skipped=a.list_skipped,
            )
        )
        return 0

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

    if a.cmd == "patches":
        from .patches import patched_findings

        if a.team and a.team not in inv.teams:
            print(f"  error unknown team {a.team!r}; choose from {sorted(inv.teams)}", file=sys.stderr)
            return 2
        dt = _dtrack(required=True)
        if dt is None:  # unreachable: required=True exits first
            return 2
        rows, unknown, unversioned, errors = patched_findings(
            inv, dt, a.team, osv=OSV() if a.osv else None
        )
        if a.json:
            print(json.dumps([asdict(r) for r in rows], indent=2))
        else:
            for r in rows:
                print(
                    f"{r.severity or '-':8} {r.team}/{r.project}: {r.component} {r.version} "
                    f"{r.vuln_id} -> {r.recommended or r.patched}{' (osv)' if r.via == 'osv' else ''}"
                )
        print(
            f"  {len(rows)} finding(s) with a patched release; {unknown} without a recorded fix "
            "(unknown, not 'no fix')"
            + (
                f"; {unversioned} skipped: component version unknown (the SBOM tool could not "
                "resolve it, so every CVE of the package matches; fix the SBOM, not the package)"
                if unversioned
                else ""
            ),
            file=sys.stderr,
        )
        for msg in errors:
            print(f"  error {msg}", file=sys.stderr)
        return 1 if errors else 0

    if a.cmd == "ignore":
        return _ignore(a)

    if a.cmd == "unignore":
        return _unignore(a)

    if a.cmd == "vendor":
        from .vendors import ACTIONS as VENDOR_ACTIONS
        from .vendors import VENDOR_NAMES, vendor_findings

        if not (a.ubuntu or a.redhat):
            print(
                "  error choose --ubuntu and/or --redhat. This asks ubuntu.com / "
                "access.redhat.com about each CVE id found on their packages (nothing else is "
                "sent, but the list shows which CVEs affect you), so it is not done by default",
                file=sys.stderr,
            )
            return 2
        if a.team and a.team not in inv.teams:
            print(f"  error unknown team {a.team!r}; choose from {sorted(inv.teams)}", file=sys.stderr)
            return 2
        dt = _dtrack(required=True)
        if dt is None:  # unreachable: required=True exits first
            return 2

        def _notify(vendor: str, n: int) -> None:
            print(
                f"  asking {VENDOR_NAMES[vendor]} about {n} CVE id(s) (cached for 24 h)", file=sys.stderr
            )

        vres = vendor_findings(
            inv, dt, data_dir, ubuntu=a.ubuntu, redhat=a.redhat, team=a.team, notify=_notify
        )
        vshown = [x for x in vres.rows if not a.action or x.action == a.action]
        if a.json:
            print(json.dumps([asdict(x) for x in vshown], indent=2))
        else:
            for vrow in vshown:
                extra = (
                    f" [{vrow.pocket}]"
                    if vrow.pocket not in ("", "security", "updates", "release")
                    else ""
                )
                note = f" ({vrow.note})" if vrow.note and vrow.action == "wontfix" else ""
                print(
                    f"{vrow.vendor_severity or '-':10} {vrow.action:12} {vrow.team}/{vrow.project}: "
                    f"{vrow.component} {vrow.version} {vrow.vuln_id} "
                    f"({VENDOR_NAMES[vrow.vendor]} {vrow.package}, {vrow.release}) "
                    f"fix: {vrow.fixed or '-'}{extra}{note}"
                )
        counts = ", ".join(f"{sum(1 for x in vres.rows if x.action == k)} {k}" for k in VENDOR_ACTIONS)
        seen = ", ".join(f"{n} {VENDOR_NAMES[k]}" for k, n in vres.considered.items()) or "none"
        print(
            f"  findings on vendor packages: {seen}. {len(vres.rows)} with a vendor entry"
            f"{f', {len(vshown)} shown' if a.action else ''}: {counts}; {vres.unmatched} without "
            "a usable entry (unknown release, other package name or no record)",
            file=sys.stderr,
        )
        for msg in vres.errors:
            print(f"  error {msg}", file=sys.stderr)
        return 1 if vres.errors else 0

    if a.cmd == "disputed":
        from .disputed import disputed_findings

        if a.team and a.team not in inv.teams:
            print(f"  error unknown team {a.team!r}; choose from {sorted(inv.teams)}", file=sys.stderr)
            return 2
        dt = _dtrack(required=True)
        if dt is None:  # unreachable: required=True exits first
            return 2
        disp, checked, errors = disputed_findings(inv, dt, a.team)
        if a.json:
            print(json.dumps([asdict(x) for x in disp], indent=2))
        else:
            for x in disp:
                print(f"{x.marker:8} {x.team}/{x.project}: {x.component} {x.version} {x.reason}")
        print(
            f"  {len(disp)} of {checked} open finding(s) are marked disputed or rejected "
            "(a marker is a reason to review, not a verdict)",
            file=sys.stderr,
        )
        for msg in errors:
            print(f"  error {msg}", file=sys.stderr)
        return 1 if errors else 0

    if a.cmd == "debian":
        from .debian import ACTIONS, DebianTracker, debian_findings

        if a.team and a.team not in inv.teams:
            print(f"  error unknown team {a.team!r}; choose from {sorted(inv.teams)}", file=sys.stderr)
            return 2
        dt = _dtrack(required=True)
        if dt is None:  # unreachable: required=True exits first
            return 2
        drows, unmatched, errors = debian_findings(
            inv,
            dt,
            DebianTracker(data_dir),
            a.team,
            release=a.release,
            ignorable_only=a.ignorable,
        )
        shown = [r for r in drows if not a.action or r.action == a.action]
        if a.json:
            print(json.dumps([asdict(r) for r in shown], indent=2))
        else:
            for drow in shown:
                print(
                    f"{drow.urgency or '-':16} {drow.action:8} {drow.team}/{drow.project}: "
                    f"{drow.component} {drow.installed or drow.version} {drow.vuln_id} "
                    f"({drow.package}, {drow.release}) fix: {drow.fixed or '-'}"
                )
        by_action = {k: sum(1 for r in drows if r.action == k) for k in ACTIONS}
        print(
            f"  {len(drows)} finding(s) with a Debian tracker entry"
            f"{f', {len(shown)} shown' if a.action else ''}: "
            + ", ".join(f"{n} {k}" for k, n in by_action.items())
            + f"; {unmatched} CVE finding(s) on Debian components without an entry "
            "(no match, or release unknown: try --release)",
            file=sys.stderr,
        )
        for msg in errors:
            print(f"  error {msg}", file=sys.stderr)
        return 1 if errors else 0

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
        return _opencve_bootstrap(inv)

    if a.cmd == "opencve-webhook-input":
        print(
            opencve_webhook_input(
                inv,
                a.webhook_url or env("VULNFLOW_WEBHOOK_URL", "http://vulnflow-receiver:8380/opencve"),
                env("VULNFLOW_WEBHOOK_TOKEN", required=True),
                env("OPENCVE_ORG", required=True),
            )
        )
        return 0

    if a.cmd == "machines":
        return _machines(a, inv)

    if a.cmd == "agent-bundle":
        return _agent_bundle(a, inv)

    if a.cmd == "agent-revoke":
        return _agent_revoke(a)

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
