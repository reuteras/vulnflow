# vulnflow PoC — CVE tracking for the dev and sysadmin teams

A proof of concept for three-layer vulnerability tracking:

| Layer | Tool | What it answers | Port |
| --- | --- | --- | --- |
| Watch | **OpenCVE** (self-hosted Community, BSL licence) | "A CVE changed for a vendor/product we use" — per-team projects, tags, status, assignee | 80 (web), 8080 (Airflow) |
| Match | **OWASP Dependency-Track 5.x** (Apache-2.0) | "Which of *our* apps/hosts contain the affected component?" — from SBOMs | 8181 (UI), 8180 (API) |
| Work | **DefectDojo** (BSD-3) | "Who owns this finding, what's its status, is the risk accepted until when?" | 8280 |
| Glue | **vulnflow** (this repo, stdlib Python) | Inventory sync, KEV/EPSS/CIRCL enrichment, priority tiers, routing to teams | 8380 |

```text
            inventory.toml (later: generated from CMDB)
                 │ python -m vulnflow sync
     ┌───────────┼─────────────────────────────┐
     ▼           ▼                             ▼
  OpenCVE     DefectDojo (product types)   Dependency-Track (team tags)
  projects ◄──── triage write-back            ▲  SBOMs from CI + hosts
  sysadm/dev  │ webhook                        │  (scripts/ci-sbom-upload.sh,
     │        │                                │   scripts/host-sbom.sh)
     ▼        │                                │
  vulnflow receiver ── KEV + EPSS + CIRCL ──► tier P1..P4 ──► chat (team mention) + alerts.jsonl
                                               │
  Dependency-Track ── FPF export ── vulnflow dt2dojo (every 30 min) ──► DefectDojo findings
```

## Quick start

Requires Docker 25+ with Compose v2, git, openssl, curl, Python 3.11+, ~12 GB RAM for
everything, Debian/Ubuntu host.

```bash
./poc.sh setup
```

That's the whole installation, unattended: it runs the steps below in order, then
`vulnflow sync --create-projects` (DefectDojo product types, DT coverage) and `status`, and
prints the three logins (passwords are in `.env`). The first run takes about an hour, mostly
OpenCVE's image build and CVE import. Every step is idempotent, so if something fails, fix
it and run `./poc.sh setup` again; it picks up where it stopped.

The individual steps, if you want to run or rerun one:

```bash
./poc.sh init               # .env with all secrets generated (chmod 600); rerun fills gaps
./poc.sh check              # tools, free ports, RAM

./poc.sh dtrack-up          # Dependency-Track: http://localhost:8181  (admin pw + API key -> .env)
./poc.sh dojo-up            # DefectDojo:       http://localhost:8280  (admin pw + API key -> .env)

./poc.sh opencve-prepare    # clone OpenCVE + generate config, upstream default passwords replaced
./poc.sh opencve-start      # upstream install steps without the interactive admin prompt
./poc.sh opencve-bootstrap  # admin, org, API token, projects, subscriptions, webhooks; starts the glue
```

No clicking through UIs is needed. Every bootstrap step is idempotent and can be rerun on
its own (`dt-bootstrap`, `dd-bootstrap`, `opencve-bootstrap`); keys/tokens are only
replaced when the one in `.env` no longer works. What they do:

1. **Dependency-Track** (`dtrack-up`): changes the forced `admin/admin` password to
   `DT_ADMIN_PASSWORD`, creates team `vulnflow` with `BOM_UPLOAD`,
   `PROJECT_CREATION_UPLOAD`, `VIEW_PORTFOLIO`, `VIEW_VULNERABILITY`, and writes its API
   key to `DT_API_KEY`.
2. **DefectDojo** (`dojo-up`): starts upstream's compose plus
   [`stacks/defectdojo/override.yml`](stacks/defectdojo/override.yml), so the admin gets
   `DD_ADMIN_PASSWORD`, the Django/AES keys come from `.env` instead of upstream's
   hard-coded defaults, and images match `DD_REF` instead of `:latest`. Then writes the
   admin's API v2 key to `DD_API_KEY`.
3. **OpenCVE** (`opencve-bootstrap`):
   - creates the admin `OPENCVE_ADMIN_USER` (superuser, email pre-verified, org owner) if
     that username doesn't exist yet. `opencve-start` runs upstream's `install.sh` steps one
     by one instead of `start`, which would stop at an interactive `createsuperuser` prompt;
   - creates a non-login service user `vulnflow`, organization `OPENCVE_ORG` and a
     read-write org token via `manage.py shell`
     ([`stacks/opencve/bootstrap_org.py`](stacks/opencve/bootstrap_org.py); OpenCVE has no
     API for these) and writes it to `OPENCVE_TOKEN`;
   - runs `glue-up`, which attaches the receiver to OpenCVE's network as
     `vulnflow-receiver`;
   - creates the projects and subscriptions from `inventory.toml` (API);
   - per project, creates a `vulnflow` webhook notification (`VULNFLOW_WEBHOOK_URL`, header
     `X-Vulnflow-Token`) and a `vulnflow` alert automation that sends it on every change
     ([`stacks/opencve/bootstrap_webhooks.py`](stacks/opencve/bootstrap_webhooks.py), via
     `manage.py shell`). In v3.1.0 a notification only fires through an automation, and the
     API refuses private webhook URLs, with no allow-list until after v3.1.0.

```bash
python3 -m vulnflow sync --dry-run              # what would change
python3 -m vulnflow sync --create-projects      # OpenCVE projects + subscriptions, Dojo product types
./poc.sh glue-up                                # receiver + dt2dojo loop in containers
```

Feed SBOMs:

```bash
# an application, from CI (GitLab/GitHub/Jenkins); needs syft + jq
DT_URL=... DT_API_KEY=... PROJECT_NAME=ärendesystem PROJECT_VERSION=2.4.1 \
  TEAM_TAG=team-dev ./scripts/ci-sbom-upload.sh

# a Linux server (installed packages), tagged for the sysadmin team
sudo ./scripts/host-sbom.sh sysadm

# or by hand
python3 -m vulnflow upload-sbom --team dev --name myapp --version 1.0 --file bom.cdx.json
```

Ad-hoc look-up of any CVE with the same priority logic:

```bash
$ python3 -m vulnflow enrich CVE-2021-44228 CVE-2025-0001
CVE-2021-44228: P1 Act | KEV=yes EPSS=1.0000 (p100) sightings={'exploited': 1424, ...} | in CISA KEV (ransomware use); ...
CVE-2025-0001: P4 Watch | KEV=no EPSS=0.0056 (p47) sightings={'published-proof-of-concept': 3, 'seen': 10} | no CVSS (likely unenriched in NVD ...)
```

(Real output from 2026-11-19.)

## How "dev vs sysadmin" works

Everything is keyed on the team entries in `inventory/inventory.toml`:

| | sysadm | dev |
| --- | --- | --- |
| OpenCVE project | `sysadm` (vendors/products subscribed) | `dev` |
| Dependency-Track tag | `team-sysadm` (host SBOMs) | `team-dev` (app SBOMs) |
| DefectDojo product type | `Sysadmin` | `Development` |
| Chat mention | `@drift-oncall` | `@dev-security` |

Products that both teams care about can be listed under both teams. Each team then gets its
own alert and its own status in OpenCVE.

## Priority tiers (vulnflow receiver)

| Tier | Rule (defaults, tune in `[priority]`) | Action |
| --- | --- | --- |
| **P1 Act** | in CISA KEV, or ≥1 `exploited` sighting in CIRCL Vulnerability-Lookup | chat + OpenCVE status `to_evaluate` |
| **P2 Attend** | EPSS ≥ 0.10, or CVSS ≥ 9.0 and EPSS ≥ 0.01 | chat + OpenCVE status `to_evaluate` |
| **P3 Track** | CVSS ≥ 7.0 | log only |
| **P4 Watch** | everything else, including CVEs with **no CVSS** (NVD no longer enriches most CVEs) | log only |

The write-back to OpenCVE (`VULNFLOW_OPENCVE_TRIAGE_MAX_TIER`) **only touches CVEs nobody
has triaged yet**. It never overwrites a status a person set (e.g. `risk_accepted`).
Everything lands in `data/alerts.jsonl`, which you can ship to the SIEM.

## Where status and comments live

- **CVE level** ("does Fortinet CVE-X matter to us?"): OpenCVE project status
  (`to_evaluate … risk_accepted`), assignee, tags, saved views per team.
- **Finding level** ("CVE-X in component Y in system Z"): DefectDojo. Notes, owner, SLA,
  risk acceptance with an expiry date, Jira link. `dt2dojo` re-imports with
  `close_old_findings`, so fixing the component in DT closes the finding in Dojo.
- VEX/analysis decisions made in Dependency-Track travel into DefectDojo inside the FPF export.

## Security and OPSEC notes

- **The inventory is sensitive.** The list of products you run, and especially what is
  unpatched, is targeting data. Keep all of this self-hosted, behind SSO and a TLS reverse
  proxy, on an admin network. Don't put the subscriptions in a SaaS.
- **Enrichment leaks interest, not exposure.** The receiver sends only CVE IDs to CISA (KEV
  file download), FIRST (EPSS) and CIRCL (sightings). You can turn each one off with
  `VULNFLOW_ENRICH_*=0`. For an isolated network, mirror the KEV and EPSS files internally and
  run your own Vulnerability-Lookup instance (`CIRCL_URL`).
- Compose files bind to `127.0.0.1` (for OpenCVE, `opencve-prepare` rewrites upstream's
  all-interfaces ports 80/8080 to `127.0.0.1:`), **except DefectDojo's upstream compose,
  which publishes 8280/8443 on all interfaces**. Firewall those ports.
- Webhook auth is a shared-secret header compared in constant time. The token must be ≥ 16
  chars, the body ≤ 5 MB, and processing runs on a bounded queue.
- The glue containers run read-only, with no capabilities, `no-new-privileges`, and a non-root
  UID.
- `./poc.sh init` generates every secret in `.env`; the bootstraps replace the DT
  `admin/admin` password, DefectDojo's hard-coded `DD_SECRET_KEY`/`DD_CREDENTIAL_AES_256_KEY`
  and OpenCVE's postgres/Airflow passwords plus Airflow's shared Fernet key and webserver
  `secret_key`. Bootstrap inputs and outputs travel via stdin and
  `.env` (mode 600), never on a command line.
- The receiver is published on `127.0.0.1` only; OpenCVE reaches it over OpenCVE's own
  docker network. OpenCVE v3.1.0's SSRF guard (API/UI only) rejects that private URL, so the
  webhook is written with the Django ORM; only this fixed, operator-set URL bypasses it.
  Editing that notification in the OpenCVE UI will fail validation; rerun
  `opencve-bootstrap` instead.
- The OpenCVE service user `vulnflow` has no usable password (API token only). Re-running
  `opencve-bootstrap` after losing `OPENCVE_TOKEN` revokes the old `vulnflow` token.

## Verified vs assumed

| Item | Status |
| --- | --- |
| OpenCVE API paths (subscriptions, project create, CVE tracker GET/PATCH, status enum) | Checked against the OpenCVE v3.1.0 tag's source; project create + subscriptions also run live |
| OpenCVE webhook payload (`organization`, `project`, `changes[].cve.cve_id/cvss31/description`, `events`) | Checked against v3.1.0 `WebhookNotifier.prepare_payload` |
| Dependency-Track `PUT /api/v1/bom` (JSON + `projectTags`), `/project/tag/{tag}`, FPF export | From DT docs. Paging header handling covers both v4 and v5 |
| DefectDojo `reimport-scan` with FPF scan type + `auto_create_context` | From DefectDojo docs |
| DT bootstrap (`forceChangePassword`, `login`, team, permissions, team key, `team/self`) | Checked against the DT 5.x apiserver source |
| DD bootstrap (`DD_ADMIN_PASSWORD` in `complete_initialization`, `api-token-auth`) | Checked against DefectDojo 3.5.201 source and compose file |
| OpenCVE org/token models | Checked against the v3.1.0 tag; run live |
| OpenCVE webhook notification + alert automation (models, triggers, action format) | Checked against the v3.1.0 tag; offline test with fake models. Delivery not yet seen live |
| KEV / EPSS / CIRCL sightings | Run live on 2026-11-19 (see `enrich` output above) |
| Full stack running together | **Not run here** (no Docker daemon in the build environment). Compose files validate with `docker compose config` |

## Tests

```bash
uvx pre-commit@4.7.0 install            # local checks: hygiene, ruff, secrets, markdownlint
uvx pre-commit@4.7.0 run --all-files
```

mypy, the offline pytest suite (fake HTTP transport), super-linter and OSV-Scanner run in
CI (`.github/workflows`); see [AGENTS.md](AGENTS.md). Dependabot (7-day cooldown) covers uv,
GitHub Actions, pre-commit, the Dockerfile base image and the Dependency-Track compose
images; `DD_REF`/`OPENCVE_REF` in `.env` are bumped by hand.

## Licences to be aware of

OpenCVE's self-hosted edition is under the **Business Source License**, which is not
OSI open source. Internal use by an authority is normally fine, but have the licence text
reviewed before you rely on it long term. Dependency-Track is Apache-2.0, DefectDojo BSD-3,
Vulnerability-Lookup AGPL-3.0, and vulnflow is yours.
