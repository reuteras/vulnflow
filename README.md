# vulnflow PoC — CVE tracking for the sysadmin, users and dev teams

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
  per team    │ webhook                        │  (scripts/ci-sbom-upload.sh,
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

Stopping and starting later (data is kept in Docker volumes):

```bash
./poc.sh down    # stop all stacks
./poc.sh up      # start them again, e.g. after a reboot; no rebuild, no bootstrap
./poc.sh status  # containers and health endpoints
```

`up` uses the images and configuration from the last `setup`; after changing versions
(`DD_REF`, `OPENCVE_REF`, image tags) run `./poc.sh setup` instead.

To start over from scratch, `./poc.sh destroy` deletes all containers, data volumes,
`upstream/`, `data/` and `.env` (it lists what it will delete and asks you to type
`destroy`; `--yes` skips that). Docker images are kept, so the next `./poc.sh setup` is
faster.

The individual steps, if you want to run or rerun one:

```bash
./poc.sh init               # .env with all secrets generated (chmod 600); rerun fills gaps
./poc.sh check              # tools, free ports, RAM

./poc.sh dtrack-up          # Dependency-Track: http://localhost:8181  (admin pw + API key -> .env)
./poc.sh dojo-up            # DefectDojo:       http://localhost:8280  (admin pw + API key -> .env)

./poc.sh opencve-prepare    # clone OpenCVE + generate config, upstream default passwords replaced
./poc.sh opencve-start      # upstream install steps without the interactive admin prompt
./poc.sh opencve-bootstrap  # admin, org, API token, projects, subscriptions, webhooks; starts the glue
./poc.sh tailscale          # only with VULNFLOW_TS_HOST: tailnet URLs + tailscale serve
```

No clicking through UIs is needed. Every bootstrap step is idempotent and can be rerun on
its own (`dt-bootstrap`, `dd-bootstrap`, `opencve-bootstrap`); keys/tokens are only
replaced when the one in `.env` no longer works. What they do:

1. **Dependency-Track** (`dtrack-up`): changes the forced `admin/admin` password to
   `DT_ADMIN_PASSWORD`, creates team `vulnflow` with `BOM_UPLOAD`,
   `PROJECT_CREATION_UPLOAD`, `VIEW_PORTFOLIO`, `VIEW_VULNERABILITY`, writes its API
   key to `DT_API_KEY`, and enables the OSV vulnerability source for `DT_OSV_ECOSYSTEMS`
   (default `Debian,PyPI`; OSV is off by default in DT 5.2.2).
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

## After setup: first steps

A worked example for a typical small estate: a **Debian 13 (trixie)** server running
**nginx** in front of a **Python web app** (Django here, under `/srv/myapp` with a venv).
The sysadmin team owns the server and nginx, the dev team owns the app. Commands run on the
vulnflow host, in the repo directory, unless noted.

### 1. Reach the UIs

Everything listens on `127.0.0.1`. Users and passwords are printed at the end of `setup`
and `up` (passwords are in `.env`). There are two ways in.

**Over Tailscale (a server that is only reachable on the tailnet).** Set
`VULNFLOW_TS_HOST=auto` (or the node's full MagicDNS name) in `.env` before `setup`, or run
`./poc.sh tailscale` afterwards. `tailscale serve` then publishes, on the Tailscale
addresses only and with a MagicDNS HTTPS certificate:

| URL | Service (local port) |
| --- | --- |
| `https://<host>.<tailnet>.ts.net` | OpenCVE (80) |
| `https://<host>.<tailnet>.ts.net:8181` | Dependency-Track UI (8181) |
| `https://<host>.<tailnet>.ts.net:8180` | Dependency-Track API (8180): the DT UI calls it from the browser; SBOM uploads from other tailnet machines can use it too |
| `https://<host>.<tailnet>.ts.net:8280` | DefectDojo (8280) |

The Airflow UI (8080) and the webhook receiver (8380) are not served; use `ssh -L` for
Airflow. `poc.sh` also writes the matching browser-facing URLs to `.env`
(`DT_PUBLIC_API_URL`, `DD_SITE_URL`, `DD_CSRF_TRUSTED_ORIGINS`, `OPENCVE_URL`) and adds
the tailnet origin to OpenCVE's `CSRF_TRUSTED_ORIGINS`; without those the DT UI can't reach
its API and the DefectDojo/OpenCVE login forms fail Django's CSRF check. Empty
`VULNFLOW_TS_HOST` and rerun `./poc.sh tailscale` to remove the serve entries and go back
to localhost URLs.

What the host needs (e.g. from Ansible) before `./poc.sh setup`:

- Tailscale installed and logged in, MagicDNS on, **HTTPS certificates enabled** for the
  tailnet (admin console, DNS page), and the user that runs `poc.sh` allowed to configure
  serve: `sudo tailscale set --operator=<user>`.
- A firewall that drops inbound traffic on the public interface and allows `tailscale0`
  (ssh over the tailnet too, if you want nothing public at all). The stacks don't depend on
  it, since they bind to `127.0.0.1`, but it's the backstop if an upstream bump starts
  publishing on `0.0.0.0` again: Docker-published ports bypass ufw's input rules.
  `./poc.sh check` and `status` list every TCP listener that is not on loopback or a
  Tailscale address.
- Docker with the compose v2 plugin, git, curl, openssl and python3 ≥ 3.11.

**Over ssh.** From your workstation, tunnel the ports:

```bash
ssh -L 8000:127.0.0.1:80 -L 8181:127.0.0.1:8181 -L 8280:127.0.0.1:8280 user@vulnflow-host
```

Then open OpenCVE on <http://localhost:8000>, Dependency-Track on <http://localhost:8181>
and DefectDojo on <http://localhost:8280>.

### 2. OSV in Dependency-Track (done by setup; needed for Debian and PyPI)

Dependency-Track 5.2.2 ships with only the NVD source enabled. NVD matches by CPE, which
fits Debian packages and Python libraries poorly. The OSV source matches by package URL and
covers Debian security advisories and PyPI, but it is **off by default**, and Debian is not
in its default ecosystem list (`Go, Maven, npm, NuGet, PyPI`).

`dtrack-up`/`dt-bootstrap` therefore enables OSV and adds the ecosystems in
`DT_OSV_ECOSYSTEMS` (default `Debian,PyPI`; ecosystems already set are kept, and an empty
value leaves OSV alone). Its output shows `OSV source: ...`; if it prints a warning
instead, enable OSV by hand in the DT UI under Administration. The first OSV mirror takes a
while; findings show up after it finishes. Optional: an NVD API key (faster NVD mirroring)
and the GitHub Advisories source (needs a GitHub token).

### 3. Describe what you run in `inventory/inventory.toml`

OpenCVE watches **vendors/products** (CVE level, also for things you have no SBOM for);
Dependency-Track matches **exact package versions** from SBOMs. For this estate:

```toml
[teams.sysadm.opencve]
vendors  = []
[teams.sysadm.opencve.products]
debian = ["debian_linux"]
f5     = ["nginx"]            # nginx CVEs since F5's acquisition
nginx  = ["nginx"]            # older nginx CVEs

[teams.dev.opencve]
vendors  = []
[teams.dev.opencve.products]
python       = ["python"]
djangoproject = ["django"]
```

Names are OpenCVE's (derived from NVD CPEs, `cpe:2.3:a:<vendor>:<product>`), and OpenCVE
rejects names it doesn't know. Check one with the API (404 = no such name):

```bash
set -a; . ./.env; set +a
curl -s -o /dev/null -w '%{http_code}\n' -H @- http://localhost/api/v2/vendors/f5/products/nginx \
  <<<"Authorization: Bearer $OPENCVE_TOKEN"
```

`inventory.toml` is in git, and this repository is public. Keep the broad, team-level
subscriptions there and put the detailed list of what you actually run in `machines.toml`
(not in git), which `vulnflow sync` adds to each team:

```toml
[subscriptions.sysadm.products]
openbsd    = ["openssh"]
postgresql = ["postgresql"]
```

To see what's worth following, let the agents' SBOMs answer:

```bash
python3 -m vulnflow suggest-subscriptions   # --top N, --libraries
```

It turns every component in each team's Dependency-Track projects into NVD vendor:product
candidates (the component's CPE, often syft's guess, plus the right NVD names for common
packages: OpenSSH is `openbsd:openssh`, curl `haxx:curl`), leaves out what the team already
follows and language libraries (DT matches those by package URL), and asks OpenCVE how many
CVEs each one has. Names OpenCVE doesn't know and ones with fewer than `--min-cves` (1) are
dropped, which also removes wrong vendors that happen to exist; the rest is ranked by the
number of projects, then CVEs, and printed as commented-out `[subscriptions.<team>]` lines
(`--list-skipped` lists what was left out). Nothing is changed: uncomment what you want,
paste it into `machines.toml`, run `sync`.

Then push it, and restart the glue containers so they reload the inventory (it's a
mounted file, so `glue-up` alone doesn't recreate them):

```bash
python3 -m vulnflow sync --dry-run
python3 -m vulnflow sync --create-projects
./poc.sh opencve-bootstrap    # webhook + automation for any new OpenCVE project
docker restart vulnflow-glue-receiver-1 vulnflow-glue-dt2dojo-1
```

### 4. Install syft (SBOM generator)

On the vulnflow host and on every server you want to inventory. Pinned version, checksum
verified (use `linux_arm64` on ARM):

```bash
V=1.57.2
cd "$(mktemp -d)"
curl -fsSLO "https://github.com/anchore/syft/releases/download/v$V/syft_${V}_linux_amd64.deb"
curl -fsSLO "https://github.com/anchore/syft/releases/download/v$V/syft_${V}_checksums.txt"
sha256sum --ignore-missing -c "syft_${V}_checksums.txt"
sudo apt install "./syft_${V}_linux_amd64.deb"
```

### 5. SBOM of the server (sysadmin team)

On the vulnflow host itself:

```bash
sudo ./scripts/host-sbom.sh sysadm
```

For **another server**, keep the DT key off it: generate the SBOM there and copy only the
file over.

```bash
# on the app server (excludes as in scripts/host-sbom.sh)
sudo syft scan dir:/ --exclude './proc/**' --exclude './sys/**' --exclude './dev/**' \
  --exclude './run/**' --exclude './home/**' --exclude './tmp/**' \
  --exclude './var/lib/docker/**' -o cyclonedx-json=host.cdx.json -q

# on the vulnflow host
python3 -m vulnflow upload-sbom --team sysadm --name "host:app01.example.org" \
  --version debian-13 --file host.cdx.json --tag kind-host
```

nginx and the system `python3` are Debian packages, so they show up here as
`pkg:deb/debian/...` components and are matched against Debian's advisories, including
fixes Debian backported without changing the upstream version.

### 6. SBOM of the app (dev team)

Scan the deployed app directory *with its venv*, so the SBOM lists the exact installed
versions:

```bash
syft scan dir:/srv/myapp -o cyclonedx-json=myapp.cdx.json -q
python3 -m vulnflow upload-sbom --team dev --name myapp --version 1.4.0 \
  --file myapp.cdx.json --tag kind-app
```

Better: do it in CI on every release with [`scripts/ci-sbom-upload.sh`](scripts/ci-sbom-upload.sh)
(scans the checkout or image, uses a DT key with only upload permissions), so each released
version gets its own DT project version.

### 7. See the results

- **Dependency-Track:** projects `host:...` (tag `team-sysadm`) and `myapp` (tag
  `team-dev`) with their components and vulnerabilities, once analysis is done.
- **DefectDojo:** `dt2dojo` copies DT findings every 30 minutes into one product per DT
  project, under the team's product type. To run it now:
  `python3 -m vulnflow dt2dojo`.
- **OpenCVE:** projects `sysadm` and `dev` list the CVEs matching their subscriptions;
  new or changed ones are sent to the receiver by the `vulnflow` automation.
- **Coverage check:** `python3 -m vulnflow sync --dry-run` warns about teams with no SBOM
  in DT yet.

### 8. Smoke-test the alert path

Send the receiver a fake OpenCVE webhook (Log4Shell, which is in CISA KEV, so it should
come out as **P1**). The token goes in on stdin, not on the command line:

```bash
set -a; . ./.env; set +a
cat >/tmp/vf-test.json <<'EOF'
{"organization": "test", "project": "sysadm",
 "changes": [{"cve": {"cve_id": "CVE-2021-44228", "cvss31": 10.0,
                      "description": "smoke test"},
              "events": [{"type": "first_time"}]}]}
EOF
curl -s -H @- --json @/tmp/vf-test.json "http://127.0.0.1:${VULNFLOW_PORT:-8380}/opencve" \
  <<<"X-Vulnflow-Token: $VULNFLOW_WEBHOOK_TOKEN"
docker exec vulnflow-glue-receiver-1 tail -n 1 /app/data/alerts.jsonl
```

The reply is `{"accepted": 1}`, and the last line of `alerts.jsonl` shows the P1 alert. A
log warning that the OpenCVE write-back failed for this CVE is expected: Log4j isn't in
`sysadm`'s subscriptions. To get alerts in chat, set `VULNFLOW_CHAT_WEBHOOK` in `.env` and
run `./poc.sh glue-up`.

### 9. Day to day

- **Sysadmin:** triage new CVEs in OpenCVE project `sysadm` (status, assignee), then
  handle the Debian-package findings in DefectDojo. Rerun the host SBOM after upgrades
  (from cron or config management).
- **Dev:** upload an SBOM per release from CI; triage findings for `myapp` in DefectDojo
  (or with VEX/analysis in DT, which carries over).
- **Both:** P1/P2 alerts arrive in chat (when configured) and are marked `to_evaluate` in
  OpenCVE, but only if nobody has triaged them yet.

## Own machines (push agents)

The vulnflow server is always on and every machine **pushes** to it; nothing connects to
the machines. Each server and MacBook runs `scripts/vulnflow-agent.py` once a day (systemd
timer on Linux, launchd on macOS). The agent builds the machine's SBOMs locally with syft,
Homebrew and the app bundles and uploads them to Dependency-Track over the tailnet
(`https://<host>.<tailnet>.ts.net:8180`, see [Reach the UIs](#1-reach-the-uis)). Ownership is
split three ways: **sysadm** gets the servers, **users** the MacBooks, **dev** the code and
containers.

```text
 server1..3  ─┐  vulnflow-agent.py (timer)   ┌─► Dependency-Track ──► dt2dojo ──► DefectDojo
 laptop1..2  ─┼── HTTPS over the tailnet ────┤   (tailscale serve :8180, one API key per host)
 code dirs   ─┘  syft / brew / app bundles   └─► vulnflow machines: who stopped pushing?
```

### Your hosts: `machines.toml` (not in git)

Host names and what runs where are targeting data, and this repository is public. They live
in `machines.toml` next to `.env`, which is gitignored and dockerignored in the same way;
the committed [`machines.example.toml`](machines.example.toml) has placeholders only. Keep the
real file in a private place (your Ansible repo or vault) and copy it to the server
(`VULNFLOW_MACHINES` in `.env` if it lives elsewhere).

```toml
[groups.servers]                 # shared settings for the hosts in the group
team  = "sysadm"
kind  = "linux"
scans = ["system", "containers"]
hosts = ["server1", "server2", "server3"]

[groups.laptops]
team  = "users"
kind  = "macos"                  # default scans: brew, languages, apps
hosts = ["laptop1", "laptop2"]

[hosts.server1]                  # per-host override (or a host without a group)
scans = ["system", "brew", "containers"]

[code.myapp]                     # application code on one of the hosts, owned by dev
host = "server1"
path = "/srv/myapp"
```

`python3 -m vulnflow machines` lists the hosts by group. Once Dependency-Track is up it also
shows each host's last upload and marks hosts as `STALE` when they haven't pushed for
`--stale-days` (default 2) or never did; the exit code is 1 then. With push, a machine that
has gone quiet is the failure you would otherwise not notice. `./poc.sh status` runs it.

### Rolling out the agents (Ansible)

On the server, after a change to `machines.toml`:

```bash
python3 -m vulnflow agent-bundle --all          # or: agent-bundle server1 laptop2
```

This writes `data/agents/<host>/config.json` (what to scan, project names and tags,
`cpe_map`, the DT URL from `VULNFLOW_AGENT_DT_URL` or `DT_PUBLIC_API_URL`) and
`data/agents/<host>/key` (directory 700, files 600). Every host gets **its own**
Dependency-Track team `agent-<host>` with only `BOM_UPLOAD` and `PROJECT_CREATION_UPLOAD`:
a key taken from a laptop can upload SBOMs but can't read the portfolio. Rerunning keeps a
key that still works (`--rotate` forces a new one). `agent-revoke <host>` deletes that team
and every key of that host, for example when a laptop is lost.

Then Ansible copies, per host:

| | Linux server (runs as root) | MacBook (runs as the user) |
| --- | --- | --- |
| agent | `/usr/local/lib/vulnflow-agent/vulnflow-agent.py` | `~/.local/share/vulnflow-agent/vulnflow-agent.py` |
| bundle | `/etc/vulnflow-agent/config.json` + `key` (root, 600) | `~/.config/vulnflow-agent/config.json` + `key` (600) |
| timer | [`deploy/agent/vulnflow-agent.service`](deploy/agent/vulnflow-agent.service) + `.timer` to `/etc/systemd/system/`, `systemctl enable --now vulnflow-agent.timer` (e.g. from an Ansible role) | [`deploy/agent/install-macos.sh`](deploy/agent/install-macos.sh) `server:path/to/vulnflow` does all of it: fetches script, plist and bundle in one ssh, installs [`local.vulnflow.agent.plist`](deploy/agent/local.vulnflow.agent.plist) and loads it (`--uninstall` removes it) |
| tools | syft (pinned), python3; for `containers` docker, or podman with `systemctl enable --now podman.socket` | syft (`brew install syft`); macOS's own `/usr/bin/python3` (3.9) is enough |

The agent is one standard-library-only file and needs nothing else. On Linux it runs as
root: the system scan reads every package database, and the containers scan needs the
docker socket or root's podman socket (syft's `podman:` source talks to the API socket, so
enable `podman.socket`). Rootless podman containers are found through their `conmon`
processes: the agent lists them as their user and has that user export each image as an
OCI archive on stdout into a file under `/var/tmp` (deleted after the scan; needs room for
the largest image), which root then scans. Podman never gets a path: rootless podman runs in
the user's mount namespace, which can't see the unit's private `/var/tmp`. Forgejo runner
job containers (`…_WORKFLOW-<sha256>_JOB-…`) only live while a workflow runs and are
skipped. The system scan skips home directories, caches (`/var/cache`, `/root/.cache`),
container storage (docker, containerd, podman) and kernel modules (`ProtectKernelModules`
hides them from the unit anyway; the kernel itself comes from `/boot` and dpkg), and no SBOM carries
syft's per-file entries (`SYFT_FILE_METADATA_SELECTION=none`): on a Debian server those are
40,000+ files Dependency-Track can't match. For the Homebrew scan it switches to the user that owns `brew`, because
Homebrew refuses to run as root. Try it by hand first:

```bash
sudo python3 /usr/local/lib/vulnflow-agent/vulnflow-agent.py --dry-run   # scan, upload nothing
python3 ~/.local/share/vulnflow-agent/vulnflow-agent.py --out /tmp/sboms # write the SBOMs
```

Tailscale ACLs: the machines only need to reach the vulnflow server on TCP 8180.

### What the agents upload

| Project | From | Owner (tag) | Version |
| --- | --- | --- | --- |
| `host:<host>` (`kind-host` / `kind-laptop`, `group-<group>`) | the host scans, merged into one SBOM | the host's `team` (sysadm, users) | probed from the OS, e.g. `debian-13`, `macos-15.1` |
| `container:<image>` (`kind-container`, `host-<host>`) | the `containers` scan: every running image of docker, root's podman and users' rootless podman (once; runner jobs skipped) | `containers_team` (dev) | the image tag |
| `code:<name>` (`kind-app`, `host-<host>`) | `[code.<name>]`: a directory with the code and its installed dependencies | the entry's `team` (dev) | `git describe`, or `version` |

Kernels: a host project lists only the kernel that runs (`uname -r`). Kernel packages that
are installed but not booted (old ones Debian keeps, a new one waiting for a reboot),
`linux-libc-dev` and syft's `/boot/vmlinuz-*` entries are left out, because every kernel CVE
matches them. A packaged running kernel is tracked by its package; a self-built one is added
as `linux_kernel` with the NVD CPE `linux:linux_kernel:<version>`. Container projects carry no
kernel packages. Findings for the dropped ones close in DefectDojo with the next `dt2dojo`
re-import (`close_old_findings`).

Uploading replaces a project's components, so a project is uploaded only if everything that
makes it up worked; otherwise the agent reports `FAIL` and the previous SBOM stays. A failing
container or code project does not hold back the host project or the others; the exit code
is 1 if anything failed (visible in `systemctl status vulnflow-agent` /
`~/Library/Logs/vulnflow-agent.log`). Dependency-Track applies the tags when it creates a
project. An agent key can't change them later, so after moving a host to another group or
team, fix the tags in the DT UI (or delete the project and let the next push recreate it).

| Scan | Run on | What it lists | How it is matched |
| --- | --- | --- | --- |
| `system` | Linux | dpkg/rpm/apk packages (syft on `/`) | OSV (Debian; add `Ubuntu` to `DT_OSV_ECOSYSTEMS` if relevant) |
| `brew` | Linux, macOS | Homebrew formulae and casks (`brew info --json=v2 --installed`) | CPE only, see below |
| `languages` | any | uv tools, pipx venvs, `~/.cargo/bin`, `npm root -g` (syft) | OSV by purl (PyPI, npm) |
| `apps` | macOS | `/Applications` and `~/Applications` bundles (`Info.plist`) | CPE only, see below |
| `containers` | any with docker | running container images (syft on each image) | OSV by purl for language packages, OS packages by distro |

The server itself needs 4-8 GB of swap if it has less than 16 GB RAM, so the first imports
can't get OOM-killed (`./poc.sh check` warns):

```bash
sudo fallocate -l 8G /swapfile && sudo chmod 600 /swapfile
sudo mkswap /swapfile && sudo swapon /swapfile
echo '/swapfile none swap sw 0 0' | sudo tee -a /etc/fstab
```

### What to expect

- **Homebrew and apps have no package-URL type and no OSV data**, so Dependency-Track can only
  match them by CPE, and NVD's vendor name can't be derived from Homebrew metadata. The
  default guess is vendor = product, with a few built-in exceptions (curl, git, openssl,
  python, ...). Expect misses. Pin the ones you care about in `[cpe_map]` of `machines.toml`
  (`ripgrep = "burntsushi:ripgrep"`), and use OpenCVE product subscriptions for the rest:
  they work on vendor/product names and need no SBOM.
- A cask also shows up as an app (two entries for the same program). Harmless, a bit noisy.
- `~/.cargo/bin` only yields components for binaries built with `cargo auditable`; for others
  syft finds nothing.
- OSV has to cover the ecosystems you use: `DT_OSV_ECOSYSTEMS` in `.env` (default
  `Debian,PyPI`; npm is in DT's own default list, `crates.io` and `Ubuntu` are OSV names you
  can add) and rerun `./poc.sh dt-bootstrap`.
- Findings for a fresh upload take a while; the Dependency-Track UI shows the analysis queue.
- Dependency-Track's API server is capped at 2 GB in `stacks/dependency-track/docker-compose.yml`
  (its docs suggest more for a large portfolio); with this few projects that should do, but
  it is the first thing to raise if the JVM runs out of memory.

## How the teams work

Everything is keyed on the team entries in `inventory/inventory.toml`. The example estate has
three groups:

| | sysadm | users | dev |
| --- | --- | --- | --- |
| Owns | the servers | the MacBooks | code and containers |
| OpenCVE project | `sysadm` | `users` | `dev` |
| Dependency-Track tag | `team-sysadm` | `team-users` | `team-dev` |
| DefectDojo product type | `Sysadmin` | `Users` | `Development` |
| Chat mention | `@sysadm` | `@users` | `@dev` |
| DT projects | `host:<server>` | `host:<macbook>` | `container:<image>`, `code:<name>` |

Products that several teams care about can be listed under each. Each team then gets its
own alert and its own status in OpenCVE. A machine's `team` owns its `host:` project; the
containers running on it belong to `containers_team` (default `dev`) and `[code.*]` entries
to their own `team` (default `dev`).

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
- **Your host list stays out of git.** `machines.toml` (hosts, groups, code paths) is
  gitignored and dockerignored like `.env`, and isn't mounted into the glue containers.
  Agent bundles in `data/agents/` hold one upload-only DT key per host (files 600); revoke a
  host with `python3 -m vulnflow agent-revoke <host>`.
- **Enrichment leaks interest, not exposure.** The receiver sends only CVE IDs to CISA (KEV
  file download), FIRST (EPSS) and CIRCL (sightings). You can turn each one off with
  `VULNFLOW_ENRICH_*=0`. For an isolated network, mirror the KEV and EPSS files internally and
  run your own Vulnerability-Lookup instance (`CIRCL_URL`).
- Compose files bind to `127.0.0.1`: for OpenCVE, `opencve-prepare` rewrites upstream's
  all-interfaces ports 80/8080 to `127.0.0.1:`; for DefectDojo, `stacks/defectdojo/override.yml`
  replaces upstream's all-interfaces 8280/8443 with `127.0.0.1` (`ports: !override`).
  Docker-published ports bypass an input-only host firewall, so this matters even behind one.
  `./poc.sh check`/`status` warn about any TCP listener outside loopback and the tailnet.
- With `VULNFLOW_TS_HOST` set, browser access goes through `tailscale serve`: TLS ends in
  tailscaled, which listens only on the node's Tailscale addresses, so only tailnet members
  that your ACLs allow can reach the UIs. Nothing is published with `tailscale funnel`.
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
| DT bootstrap (`forceChangePassword`, `login`, team, permissions, team key, `team/self`) | Checked against the DT 5.x apiserver source; run live against 5.2.2 |
| DT OSV config (`/api/v2/extension-points/vuln-data-source/extensions/osv/config`, defaults) | Checked against the DT 5.2.2 tag's source; not yet run live |
| DD bootstrap (`DD_ADMIN_PASSWORD` in `complete_initialization`, `api-token-auth`) | Checked against DefectDojo 3.5.201 source and compose file |
| OpenCVE org/token models | Checked against the v3.1.0 tag; run live |
| OpenCVE webhook notification + alert automation (models, triggers, action format) | Checked against the v3.1.0 tag; offline test with fake models. Delivery not yet seen live |
| KEV / EPSS / CIRCL sightings | Run live on 2026-11-19 (see `enrich` output above) |
| Agent (`scripts/vulnflow-agent.py`): scans, merge, per-project upload | Offline tests with fake tools and a fake DT (exact path, header, body); `brew` + `apps` scans run for real on macOS with its Python 3.9.6; `--dry-run`/`--out` run on a MacBook and as root on a Debian 13 server (2026-11-22), which showed syft's per-file entries (41,925 of 44,988 components), now dropped. root's podman image scanned through `podman.socket`, and uploads to the live DT from the server, by hand and from the systemd timer. The first timer run found the user's 8 rootless containers (`NoNewPrivileges` does not stop `podman ps` as the user) but `podman image save -o /var/tmp/…` failed (the unit's private `/var/tmp`); now streamed through stdout, **not yet rerun** |
| Homebrew JSON shape (`formulae[].installed[].version`, `casks[].installed`) | Checked against a real `brew info --json=v2 --installed` on 2026-11-21; CPE vendors are still guesses (see "What to expect") |
| Per-host agent teams (`agent-bundle`/`agent-revoke`), BOM upload permissions and tags | Checked against the DT 5.2.2 tag (TeamResource, DeleteTeamRequest, BomResource); not yet run live |
| systemd unit / launchd plist (`deploy/agent/`) | plist passes `plutil -lint`; the systemd hardening (ProtectSystem=full, PrivateTmp) **not yet run** with syft's docker scan |
| Tailscale access: DefectDojo `DD_CSRF_TRUSTED_ORIGINS`/`DD_SITE_URL`, OpenCVE `ALLOWED_HOSTS = ["*"]` and nginx forwarding `Host` without the port | Checked against DefectDojo 3.5.201 and OpenCVE v3.1.0 source |
| Tailscale access: `tailscale serve` keeps the `Host` header; DT apiserver allows the cross-origin UI (it already does for `localhost:8181` → `:8180`) | Run on the tailnet 2026-11-22: logins to all three UIs work over `tailscale serve` |
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
