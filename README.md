# vulnflow PoC — CVE tracking for the dev and sysadmin teams

A proof of concept for three-layer vulnerability tracking:

| Layer | Tool | What it answers | Port |
|---|---|---|---|
| Watch | **OpenCVE** (self-hosted Community, BSL licence) | "A CVE changed for a vendor/product we use" — per-team projects, tags, status, assignee | 80 (web), 8080 (Airflow) |
| Match | **OWASP Dependency-Track 5.x** (Apache-2.0) | "Which of *our* apps/hosts contain the affected component?" — from SBOMs | 8181 (UI), 8180 (API) |
| Work | **DefectDojo** (BSD-3) | "Who owns this finding, what's its status, is the risk accepted until when?" | 8280 |
| Glue | **vulnflow** (this repo, stdlib Python) | Inventory sync, KEV/EPSS/CIRCL enrichment, priority tiers, routing to teams | 8380 |

```
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

Requires Docker 25+ with Compose v2, git, ~12 GB RAM for everything, Debian/Ubuntu host.

```bash
./poc.sh init               # .env with random DB password + webhook token (chmod 600)
./poc.sh check              # tools, free ports, RAM

./poc.sh dtrack-up          # Dependency-Track: http://localhost:8181  (admin/admin, forced change)
./poc.sh dojo-up            # DefectDojo:       http://localhost:8280  (admin password printed once)

./poc.sh opencve-prepare    # clone OpenCVE + generate config; edit passwords as instructed
./poc.sh opencve-start      # first build is slow (upstream: ~30-60 min)
```

Then, in the UIs:

1. **Dependency-Track** → Administration → Access Management → Teams: create team `vulnflow`
   with `BOM_UPLOAD`, `PROJECT_CREATION_UPLOAD`, `VIEW_PORTFOLIO`, `VIEW_VULNERABILITY`;
   copy its API key to `DT_API_KEY`.
2. **DefectDojo** → profile → API v2 key → `DD_API_KEY`.
3. **OpenCVE** → create organization (`OPENCVE_ORG`) and a read-write organization token →
   `OPENCVE_TOKEN`.

```bash
python3 -m vulnflow sync --dry-run              # what would change
python3 -m vulnflow sync --create-projects      # OpenCVE projects + subscriptions, Dojo product types
./poc.sh glue-up                                # receiver + dt2dojo loop in containers
```

4. **OpenCVE** → each project (`sysadm`, `dev`) → Notifications → add **Webhook**:
   URL `http://<docker-host-ip>:8380/opencve`, custom header
   `X-Vulnflow-Token: <VULNFLOW_WEBHOOK_TOKEN>`.
   (The notification `configuration` format isn't documented in OpenCVE's API schema, so this
   step is manual.)

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
|---|---|---|
| OpenCVE project | `sysadm` (vendors/products subscribed) | `dev` |
| Dependency-Track tag | `team-sysadm` (host SBOMs) | `team-dev` (app SBOMs) |
| DefectDojo product type | `Sysadmin` | `Development` |
| Chat mention | `@drift-oncall` | `@dev-security` |

Products that both teams care about can be listed under both teams. Each team then gets its
own alert and its own status in OpenCVE.

## Priority tiers (vulnflow receiver)

| Tier | Rule (defaults, tune in `[priority]`) | Action |
|---|---|---|
| **P1 Act** | in CISA KEV, or ≥1 `exploited` sighting in CIRCL Vulnerability-Lookup | chat + OpenCVE status `to_evaluate` |
| **P2 Attend** | EPSS ≥ 0.10, or CVSS ≥ 9.0 and EPSS ≥ 0.01 | chat + OpenCVE status `to_evaluate` |
| **P3 Track** | CVSS ≥ 7.0 | log only |
| **P4 Watch** | everything else, including CVEs with **no CVSS** (NVD no longer enriches most CVEs) | log only |

The write-back to OpenCVE (`VULNFLOW_OPENCVE_TRIAGE_MAX_TIER`) **only touches CVEs nobody
has triaged yet**. It never overwrites a status a person set (e.g. `risk_accepted`).
Everything lands in `data/alerts.jsonl`, which you can ship to the SIEM.

## Where status and comments live

* **CVE level** ("does Fortinet CVE-X matter to us?"): OpenCVE project status
  (`to_evaluate … risk_accepted`), assignee, tags, saved views per team.
* **Finding level** ("CVE-X in component Y in system Z"): DefectDojo. Notes, owner, SLA,
  risk acceptance with an expiry date, Jira link. `dt2dojo` re-imports with
  `close_old_findings`, so fixing the component in DT closes the finding in Dojo.
* VEX/analysis decisions made in Dependency-Track travel into DefectDojo inside the FPF export.

## Security and OPSEC notes

* **The inventory is sensitive.** The list of products you run, and especially what is
  unpatched, is targeting data. Keep all of this self-hosted, behind SSO and a TLS reverse
  proxy, on an admin network. Don't put the subscriptions in a SaaS.
* **Enrichment leaks interest, not exposure.** The receiver sends only CVE IDs to CISA (KEV
  file download), FIRST (EPSS) and CIRCL (sightings). You can turn each one off with
  `VULNFLOW_ENRICH_*=0`. For an isolated network, mirror the KEV and EPSS files internally and
  run your own Vulnerability-Lookup instance (`CIRCL_URL`).
* Compose files bind to `127.0.0.1`, **except DefectDojo's upstream compose, which publishes
  8280/8443 on all interfaces**. Firewall those ports.
* Webhook auth is a shared-secret header compared in constant time. The token must be ≥ 16
  chars, the body ≤ 5 MB, and processing runs on a bounded queue.
* The glue containers run read-only, with no capabilities, `no-new-privileges`, and a non-root
  UID.
* Change every default credential (DT `admin/admin`, OpenCVE `.env` files) before anyone else
  can reach the host.

## Verified vs assumed

| Item | Status |
|---|---|
| OpenCVE API paths (subscriptions, project create, CVE tracker GET/PATCH, status enum) | Checked against the OpenCVE Cloud OpenAPI schema (Nov 2026). Self-hosted releases may lag, so compare with `<opencve>/api/v2/docs/` |
| OpenCVE webhook payload (`organization`, `project`, `changes[].cve.cve_id/cvss31`, `events[].type`) | From OpenCVE docs |
| Dependency-Track `PUT /api/v1/bom` (JSON + `projectTags`), `/project/tag/{tag}`, FPF export | From DT docs. Paging header handling covers both v4 and v5 |
| DefectDojo `reimport-scan` with FPF scan type + `auto_create_context` | From DefectDojo docs |
| KEV / EPSS / CIRCL sightings | Run live on 2026-11-19 (see `enrich` output above) |
| Full stack running together | **Not run here** (no Docker daemon in the build environment). Compose files validate with `docker compose config` |

## Tests

```bash
python3 -m pytest -q        # 25 offline tests, fake HTTP transport, no network
```

## Licences to be aware of

OpenCVE's self-hosted edition is under the **Business Source License**, which is not
OSI open source. Internal use by an authority is normally fine, but have the licence text
reviewed before you rely on it long term. Dependency-Track is Apache-2.0, DefectDojo BSD-3,
Vulnerability-Lookup AGPL-3.0, and vulnflow is yours.
