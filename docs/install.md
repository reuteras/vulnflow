# Installation

[Back to the README](../README.md). The short version is `./poc.sh setup`;
this page is what it does, and the first steps after it.

## The setup steps

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
   [`stacks/defectdojo/override.yml`](../stacks/defectdojo/override.yml), so the admin gets
   `DD_ADMIN_PASSWORD`, the Django/AES keys come from `.env` instead of upstream's
   hard-coded defaults, and images match `DD_REF` instead of `:latest`. Then writes the
   admin's API v2 key to `DD_API_KEY`.
3. **OpenCVE** (`opencve-bootstrap`):
   - creates the admin `OPENCVE_ADMIN_USER` (superuser, email pre-verified, org owner) if
     that username doesn't exist yet. `opencve-start` runs upstream's `install.sh` steps one
     by one instead of `start`, which would stop at an interactive `createsuperuser` prompt;
   - creates a non-login service user `vulnflow`, organization `OPENCVE_ORG` and a
     read-write org token via `manage.py shell`
     ([`stacks/opencve/bootstrap_org.py`](../stacks/opencve/bootstrap_org.py); OpenCVE has no
     API for these) and writes it to `OPENCVE_TOKEN`;
   - runs `glue-up`, which attaches the receiver to OpenCVE's network as
     `vulnflow-receiver`;
   - creates the projects and subscriptions from `inventory.toml` (API);
   - per project, creates a `vulnflow` webhook notification (`VULNFLOW_WEBHOOK_URL`, header
     `X-Vulnflow-Token`) and a `vulnflow` alert automation that sends it on every change
     ([`stacks/opencve/bootstrap_webhooks.py`](../stacks/opencve/bootstrap_webhooks.py), via
     `manage.py shell`). In v3.1.0 a notification only fires through an automation, and the
     API refuses private webhook URLs, with no allow-list until after v3.1.0.

```bash
python3 -m vulnflow sync --dry-run              # what would change
python3 -m vulnflow sync --create-projects      # OpenCVE projects + subscriptions, Dojo product types
./poc.sh glue-up                                # receiver + dt2dojo loop in containers
```

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

### 2. OSV in Dependency-Track

Done by `setup`; needed for Debian packages and PyPI.

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

OSV files Debian's records as `DEBIAN-CVE-YYYY-N`. `debian` and `disputed` look those up by
the CVE id inside; `patches` leaves Debian packages to `debian`, because osv.dev's fix list
for a Debian package mixes the releases (it offered unstable's curl to a trixie host for
CVEs trixie has no fix for).

### 3. Describe what you run

In `inventory/inventory.toml` (in git) and `machines.toml` (not in git).

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
python3 -m vulnflow patches                 # open DT findings with a patched release (--team, --json, --osv)
python3 -m vulnflow debian                  # Debian tracker: urgency, update available or already fixed (--action update|fixed, --release, --ignorable)
python3 -m vulnflow vendor --ubuntu --redhat  # Ubuntu / Red Hat verdicts; asks ubuntu.com / access.redhat.com per CVE id (--action update|fixed|wontfix, --json)
python3 -m vulnflow disputed                 # CVEs NVD tags disputed / unsupported-when-assigned, rejected, or lists for every version (--team, --json, --no-nvd, --any-version-years)
python3 -m vulnflow ignore --from review.json  # dry run; --apply writes NOT_AFFECTED to DT
python3 -m vulnflow unignore                    # undo `ignore` from the ledger (data/ignored.jsonl); dry run, --apply writes; --from review.json for older ones; --forget-changed drops findings somebody changed since
python3 -m vulnflow prune                       # what dt2dojo does every round: carry decisions to new versions, deactivate stale ones (dry run; --apply)
python3 -m vulnflow where stdlib --version go1.23.3  # which files (binaries, dist-info) carry a component, per project (--project, --team, --json)
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

### 4. Install syft

syft generates the SBOMs.

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

### 5. Check the alert path

Once setup has finished, check that the receiver works: send it a fake OpenCVE webhook (Log4Shell, which is in CISA KEV, so it should
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
run `./poc.sh glue-up`, or use the local chat below. How alerts flow in normal use: [Daily usage](operations.md#how-findings-and-alerts-reach-you).

### 6. Local chat (optional)

If you have no chat server for the alerts, the PoC can run its own: Mattermost Team
Edition, bound to 127.0.0.1 and served on the tailnet like the other UIs.

```bash
./poc.sh chat-up
```

It starts Mattermost and its Postgres (`stacks/mattermost`), creates the admin
`MM_ADMIN_USER` (password `MM_ADMIN_PASSWORD` in `.env`), team `vulnflow`, channels `alerts`
(the teams' P1/P2) and `soc` (every P1, for the SOC), each with an incoming webhook, writes
them to `VULNFLOW_CHAT_WEBHOOK` and `VULNFLOW_SOC_WEBHOOK`, and recreates the receiver on the
chat's network. Log in at `http://localhost:8065` (or
`https://<host>:8065` with `VULNFLOW_TS_HOST`), and rerun the check above: the P1 alert
appears in `alerts`. Invite the others from the System Console (Users) or with an invite
link; open signup is off. Mattermost's phone-home features are switched off
([Security](security.md#external-servers)). It needs about 1 GB of RAM more; `up`, `down`,
`status` and `destroy` include it once it is installed.

Next: get SBOMs into Dependency-Track, see [SBOMs](sboms.md).
