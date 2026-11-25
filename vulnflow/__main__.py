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
from datetime import date
from pathlib import Path

from .clients import OSV, DefectDojo, DependencyTrack, OpenCVE, project_label
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
            "(see docs/install.md 'After setup')",
            file=sys.stderr,
        )
    else:
        print(f"  {'set ' if res.osv.startswith('updated') else 'ok  '}  OSV source: {res.osv}")
    from .bootstrap import DT_MAINTENANCE_TEAM, dt_admin_http, maintenance_key

    try:
        admin = dt_admin_http(env("DT_URL", "http://localhost:8180"), admin_pw)
        key, new = maintenance_key(admin, env("DT_MAINTENANCE_API_KEY"))
    except BootstrapError as e:
        print(f"  error {DT_MAINTENANCE_TEAM}: {e}", file=sys.stderr)
        return 1
    if new:
        set_env_values(env_file, {"DT_MAINTENANCE_API_KEY": key})
        print(f"  new   {DT_MAINTENANCE_TEAM} key written to {env_file} as DT_MAINTENANCE_API_KEY")
    else:
        print(f"  ok    existing DT_MAINTENANCE_API_KEY still valid ({DT_MAINTENANCE_TEAM})")
    return 0


def _maintenance_dt() -> DependencyTrack | None:
    key = env("DT_MAINTENANCE_API_KEY")
    return DependencyTrack(env("DT_URL", "http://localhost:8180"), key) if key else None


def _mm_bootstrap(env_file: str, wait: float) -> int:
    from .bootstrap import BootstrapError, bootstrap_mattermost, set_env_values

    try:
        url = bootstrap_mattermost(
            env("MM_URL", f"http://localhost:{env('MM_PORT', '8065')}"),
            admin_user=env("MM_ADMIN_USER", "admin"),
            admin_password=env("MM_ADMIN_PASSWORD", required=True),
            wait_timeout=wait,
        )
    except BootstrapError as e:
        print(f"  error {e}", file=sys.stderr)
        return 1
    if env("VULNFLOW_CHAT_WEBHOOK") == url:
        print("  ok    VULNFLOW_CHAT_WEBHOOK already points at Mattermost's alerts channel")
    else:
        set_env_values(env_file, {"VULNFLOW_CHAT_WEBHOOK": url})
        print(f"  set   VULNFLOW_CHAT_WEBHOOK in {env_file} (Mattermost, channel alerts)")
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

    if a.state == "EXPLOITABLE" and not a.response:
        print(
            "  error --state EXPLOITABLE records an accepted risk: add --response WILL_NOT_FIX or "
            "CAN_NOT_FIX (and --review-by)",
            file=sys.stderr,
        )
        return 2
    if a.review_by is not None and a.review_by <= date.today():
        print(f"  error --review-by {a.review_by} is not in the future", file=sys.stderr)
        return 2
    try:
        items = load_review(a.review, review_by=a.review_by)
    except ReviewFileError as e:
        print(f"  error {e}", file=sys.stderr)
        return 2
    for it in items:
        print(f"  {it.label}: {it.component} {it.version} {it.vuln_id} -> {a.state}")
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
        response=a.response,
    )
    print(f"  {len(written)} written, {len(skipped)} already {a.state} and suppressed")
    for k in kept:
        print(
            f"  kept  {k.item.label}: {k.item.component} {k.item.vuln_id} "
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
        print(f"  {it.label}: {it.component} {it.vuln_id}: {it.expected_state} -> {back} [{src}]")
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
    reverted, skipped, errors = apply_reverts(admin, todo, ledger, forget_changed=a.forget_changed)
    print(f"  {len(reverted)} reverted, {len(skipped)} left alone")
    for it, why in skipped:
        print(f"  left  {it.label}: {it.component} {it.vuln_id}: {why}")
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


def _report(a: argparse.Namespace, inv: Inventory) -> int:
    """`report daily|weekly`: the digest poc.sh mails (see vulnflow/report.py)."""
    from . import report as rp
    from .intel import KevCache
    from .machines import last_pushes
    from .upstreams import check

    if a.mime and not a.to:
        print("report --mime needs --to", file=sys.stderr)
        return 2
    weekly = a.kind == "weekly"
    state_file = Path(a.data_dir) / "report-state.json"
    state = rp.load_state(state_file)
    mine: dict = dict(state.get(a.kind) or {})
    sections: list[rp.Section] = []

    try:
        sections.append(rp.updates_section(check(Path("."), Path(a.env_file)), everything=weekly))
    except Exception as e:  # a report must still go out
        sections.append(rp.error_section("Upstream updates", f"check failed: {e}"))

    if a.alerts is not None:
        try:
            text = a.alerts.read_text(encoding="utf-8", errors="replace")
        except OSError as e:
            sections.append(rp.error_section("OpenCVE alerts", f"cannot read {a.alerts}: {e}"))
        else:
            sec, newest = rp.alerts_section(text.splitlines(), str(mine.get("alerts_since", "")))
            if "alerts_since" not in mine:
                sec = rp.Section(
                    sec.title, [rp.Para("First report: alerts are listed from the next one.")]
                )
            sections.append(sec)
            mine["alerts_since"] = newest

    dt = None
    if env("DT_API_KEY"):
        dt = DependencyTrack(env("DT_URL", "http://localhost:8180"), env("DT_API_KEY"))
    else:
        sections.append(rp.error_section("Dependency-Track findings", "DT_API_KEY not set"))
    if dt is not None:
        errors: list[str] = []
        current = rp.collect_findings(inv, dt, errors)
        if errors:  # a partial list would report everything it missed as resolved
            sections.append(rp.error_section("Dependency-Track findings", "; ".join(errors)[:500]))
        else:
            kev: set[str] = set()
            if env_flag("VULNFLOW_ENRICH_KEV"):
                try:
                    kev = set(KevCache(Path(a.data_dir)).index())
                except Exception as e:
                    logging.getLogger(__name__).warning("KEV list unavailable: %s", e)
            sections.append(rp.findings_section(mine.get("findings"), current, kev, weekly=weekly))
            mine["findings"] = {k: f.to_json() for k, f in current.items()}

    machines = load_machines(a.machines, inv.teams)
    if machines.hosts and dt is not None:
        try:
            sections.append(rp.machines_section(machines, last_pushes(dt), a.stale_days))
        except Exception as e:
            sections.append(rp.error_section("Hosts", f"Dependency-Track: {e}"))

    if not a.no_save:
        state[a.kind] = mine
        rp.save_state(state_file, state)
    if a.quiet and not any(s.notable for s in sections):
        return 0
    if a.mime:
        import socket

        host = socket.gethostname().split(".")[0]
        sys.stdout.write(rp.mime_message(a.kind, sections, a.to, host).as_string())
    else:
        print(rp.render_markdown(a.kind, sections), end="")
    return 1 if any(s.error for s in sections) else 0


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
        "--no-prune",
        action="store_true",
        help="skip `prune` at the start of each round (it runs when DT_MAINTENANCE_API_KEY is set)",
    )
    pr = sub.add_parser(
        "prune",
        help="carry Not Affected/False Positive decisions to new project versions, deactivate "
        "versions no longer uploaded and close them in DefectDojo; dry run unless --apply "
        "(dt2dojo runs this every round)",
    )
    pr.add_argument("--apply", action="store_true", help="write to Dependency-Track / DefectDojo")
    pr.add_argument(
        "--superseded-days",
        type=float,
        default=2,
        help="deactivate a version not uploaded for this long once a newer one exists (2)",
    )
    pr.add_argument(
        "--gone-days",
        type=float,
        default=7,
        help="deactivate the newest version too when nothing uploaded it for this long (7)",
    )
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
        help="open findings NVD marks disputed, rejected or unsupported-when-assigned, or that "
        "match only because NVD lists every version (downloads NVD's yearly feeds for the "
        "years of your CVE ids, cached)",
    )
    dp.add_argument("--team", default=None, help="only this team (default: all)")
    dp.add_argument("--json", action="store_true")
    dp.add_argument(
        "--no-nvd",
        action="store_true",
        help="do not download NVD feeds; only the old ** DISPUTED ** description prefix is checked",
    )
    dp.add_argument(
        "--any-version-years",
        type=float,
        default=2,
        metavar="YEARS",
        help="flag ANY-VERSION: NVD lists the product for every version (no range) and the CVE "
        "is older than this (default 2; 0 = off)",
    )

    wh = sub.add_parser(
        "where",
        help="where a component is on disk: the file paths syft recorded, per project "
        "(e.g. which binaries carry `stdlib go1.23.3`)",
    )
    wh.add_argument("name", help="component name as in Dependency-Track (case-insensitive)")
    wh.add_argument("--version", default=None, help="only this exact version")
    wh.add_argument("--project", default=None, help="only projects whose name contains this")
    wh.add_argument("--team", default=None, help="only this team (default: all)")
    wh.add_argument("--json", action="store_true")

    ig = sub.add_parser(
        "ignore",
        help="mark reviewed findings (a file edited down from `debian --json` or "
        "`disputed --json`) as not affected in Dependency-Track; dry run unless --apply",
    )
    ig.add_argument("--from", dest="review", required=True, type=Path, metavar="FILE")
    ig.add_argument("--apply", action="store_true", help="write to Dependency-Track")
    ig.add_argument(
        "--state",
        choices=("NOT_AFFECTED", "FALSE_POSITIVE", "EXPLOITABLE"),
        default="NOT_AFFECTED",
        help="EXPLOITABLE = an accepted risk; needs --response",
    )
    ig.add_argument(
        "--response",
        choices=("WILL_NOT_FIX", "CAN_NOT_FIX"),
        default=None,
        help="DT analysisResponse, for --state EXPLOITABLE",
    )
    ig.add_argument(
        "--review-by",
        type=date.fromisoformat,
        default=None,
        metavar="YYYY-MM-DD",
        help="adds 'review by <date>' to the comment; after that day `prune` (dt2dojo) lifts the "
        "suppression, so the finding shows up again (also in DefectDojo)",
    )
    ig.add_argument("--justification", default=None, help="DT analysisJustification, optional")
    ig.add_argument(
        "--overwrite",
        action="store_true",
        help="also replace a finding somebody already triaged, or correct the justification/response "
        "of one already suppressed in this state (default: leave those alone)",
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
        choices=("NOT_AFFECTED", "FALSE_POSITIVE", "EXPLOITABLE"),
        default="NOT_AFFECTED",
        help="with --from and no ledger entry: the state `ignore` set",
    )
    ui.add_argument(
        "--forget-changed",
        action="store_true",
        help="with --apply: drop ledger entries of findings somebody changed since (their "
        "decision stands), so they stop showing up in every later unignore",
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
        help="per host: agent config.json + its own DT API key, for Ansible to copy (see docs/sboms.md)",
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

    mmb = sub.add_parser(
        "mm-bootstrap",
        help="local chat (Mattermost): admin, team, channel 'alerts', webhook -> VULNFLOW_CHAT_WEBHOOK",
    )
    mmb.add_argument("--wait", type=float, default=300, metavar="SECONDS")
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

    rpt = sub.add_parser(
        "report",
        help="daily/weekly digest: updates, new P1/P2 alerts, new and resolved findings, "
        "stale hosts (./poc.sh report mails it)",
    )
    rpt.add_argument("kind", choices=("daily", "weekly"))
    rpt.add_argument(
        "--alerts", type=Path, default=None, metavar="FILE", help="the receiver's alerts.jsonl"
    )
    rpt.add_argument("--stale-days", type=float, default=2.0, metavar="DAYS")
    rpt.add_argument(
        "--quiet", action="store_true", help="print nothing when there is nothing to act on"
    )
    rpt.add_argument("--no-save", action="store_true", help="do not record this run (a preview)")
    rpt.add_argument(
        "--mime",
        action="store_true",
        help="print a whole mail for `sendmail -t` (text/plain Markdown + text/html); needs --to",
    )
    rpt.add_argument("--to", default="", help="recipient(s) for --mime, comma-separated")

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
    if a.cmd == "mm-bootstrap":
        return _mm_bootstrap(a.env_file, a.wait)
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
        maint = None if a.no_prune else _maintenance_dt()
        if maint is None and not a.no_prune:
            print("  skip  prune (DT_MAINTENANCE_API_KEY not set; ./poc.sh dt-bootstrap creates it)")
        while True:
            rep = dt_to_dojo(inv, dt, dd, dry_run=a.dry_run, maintenance=maint)
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
        rows, unknown, unversioned, pseudo, debian, errors = patched_findings(
            inv, dt, a.team, osv=OSV() if a.osv else None
        )
        if a.json:
            print(json.dumps([asdict(r) for r in rows], indent=2))
        else:
            for r in rows:
                print(
                    f"{r.severity or '-':8} {r.team}/{project_label(r.project, r.project_version)}: "
                    f"{r.component} {r.version} "
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
            )
            + (
                f"; {pseudo} skipped: Go pseudo-version (built from a commit, so every advisory "
                "matches; check the commit date in the version instead)"
                if pseudo
                else ""
            )
            + (
                f"; {debian} on Debian packages left out: the fix depends on the release, "
                "see `vulnflow debian`"
                if debian
                else ""
            ),
            file=sys.stderr,
        )
        for msg in errors:
            print(f"  error {msg}", file=sys.stderr)
        return 1 if errors else 0

    if a.cmd == "prune":
        from .prune import prune

        maint = _maintenance_dt()
        if maint is None:
            print(
                "  error DT_MAINTENANCE_API_KEY not set; ./poc.sh dt-bootstrap creates team "
                "vulnflow-maintenance and its key",
                file=sys.stderr,
            )
            return 2
        prune_res = prune(
            inv,
            maint,
            _dojo() if a.apply else None,
            apply=a.apply,
            superseded_days=a.superseded_days,
            gone_days=a.gone_days,
        )
        for line in prune_res.reactivated:
            print(f"  reactivate  {line}")
        for line in prune_res.reopened:
            print(f"  reopen      {line}")
        for line in prune_res.deactivated:
            print(f"  deactivate  {line}")
        for line in prune_res.carried:
            print(f"  carry       {line}")
        print(
            f"  {len(prune_res.carried)} decision(s) carried forward, {len(prune_res.deactivated)} "
            f"project(s) deactivated, {len(prune_res.reactivated)} reactivated, "
            f"{len(prune_res.reopened)} past their review date"
            + ("" if a.apply else "; dry run, add --apply"),
            file=sys.stderr,
        )
        for msg in prune_res.errors:
            print(f"  error {msg}", file=sys.stderr)
        return 1 if prune_res.errors else 0

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
                    f"{vrow.vendor_severity or '-':10} {vrow.action:12} "
                    f"{vrow.team}/{project_label(vrow.project, vrow.project_version)}: "
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

    if a.cmd == "where":
        from .where import locate

        if a.team and a.team not in inv.teams:
            print(f"  error unknown team {a.team!r}; choose from {sorted(inv.teams)}", file=sys.stderr)
            return 2
        dt = _dtrack(required=True)
        if dt is None:  # unreachable: required=True exits first
            return 2
        located, errors = locate(inv, dt, a.name, a.version, a.project, a.team)
        if a.json:
            print(json.dumps([asdict(loc) for loc in located], indent=2))
        else:
            for loc in located:
                print(
                    f"{loc.team}/{project_label(loc.project, loc.project_version)}: {loc.component} "
                    f"{loc.version}  {', '.join(loc.paths) or '(no path recorded)'}"
                )
        print(f"  {len(located)} component(s) found", file=sys.stderr)
        for msg in errors:
            print(f"  error {msg}", file=sys.stderr)
        return 1 if errors else 0

    if a.cmd == "disputed":
        from .disputed import NvdFeeds, disputed_findings

        if a.team and a.team not in inv.teams:
            print(f"  error unknown team {a.team!r}; choose from {sorted(inv.teams)}", file=sys.stderr)
            return 2
        dt = _dtrack(required=True)
        if dt is None:  # unreachable: required=True exits first
            return 2
        nvd = None
        if not a.no_nvd:
            nvd = NvdFeeds(data_dir, notify=lambda msg: print(f"  {msg}", file=sys.stderr))
        res = disputed_findings(inv, dt, a.team, nvd=nvd, any_version_years=a.any_version_years)
        if a.json:
            print(json.dumps([asdict(x) for x in res.rows], indent=2))
        else:
            for x in res.rows:
                print(
                    f"{x.marker:11} {x.team}/{project_label(x.project, x.project_version)}: "
                    f"{x.component} {x.version} {x.reason}"
                )
        print(
            f"  {len(res.rows)} of {res.checked} open finding(s) are marked disputed, rejected, "
            "unsupported or any-version (a marker is a reason to review, not a verdict)"
            + (
                "; NVD feeds skipped (--no-nvd): only the old description prefix was checked, "
                "which current NVD records no longer carry"
                if nvd is None
                else f"; {res.unchecked} CVE finding(s) not in the NVD feeds (too new, or the "
                "feed could not be read)"
            ),
            file=sys.stderr,
        )
        for msg in res.errors:
            print(f"  error {msg}", file=sys.stderr)
        return 1 if res.errors else 0

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
                    f"{drow.urgency or '-':16} {drow.action:8} "
                    f"{drow.team}/{project_label(drow.project, drow.project_version)}: "
                    f"{drow.component} {drow.installed or drow.version} {drow.vuln_id} "
                    f"({drow.package}, {drow.release}) fix: {drow.fixed or '-'}"
                    + (f" ({drow.note})" if drow.note and drow.action != "fixed" else "")
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

    if a.cmd == "report":
        return _report(a, inv)

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
