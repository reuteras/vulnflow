# Security, licences and external servers

[Back to the README](../README.md).

## Security and OPSEC notes

- **The inventory is sensitive.** The list of products you run, and especially what is
  unpatched, is targeting data. Keep all of this self-hosted, behind SSO and a TLS reverse
  proxy, on an admin network. Don't put the subscriptions in a SaaS.
- **Your host list stays out of git.** `machines.toml` (hosts, groups, code paths) is
  gitignored and dockerignored like `.env`, and isn't baked into the image. Only
  `dt2dojo` reads it, mounted read-only, for `github-sboms` and `kev-watch`; the receiver
  doesn't get it.
  Agent bundles in `data/agents/` hold one upload-only DT key per host (files 600); revoke a
  host with `python3 -m vulnflow agent-revoke <host>`. CI pipelines get the same kind of key
  per repository in `data/ci/` (`ci-key`; `ci-revoke <name>`).
- **Enrichment leaks interest, not exposure.** The receiver sends only CVE IDs to FIRST
  (EPSS) and CIRCL (sightings); the KEV catalogs (CISA, and VulnCheck with a token) are
  downloaded whole. You can turn each one off with
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

## Licences to be aware of

OpenCVE's self-hosted edition is under the **Business Source License**, which is not
OSI open source. Internal use by an authority is normally fine, but have the licence text
reviewed before you rely on it long term. Dependency-Track is Apache-2.0, DefectDojo BSD-3,
Vulnerability-Lookup AGPL-3.0, Mattermost Team Edition MIT (the compiled release; its
source is AGPL-3.0), and vulnflow is yours.

## External servers

Everything vulnflow and the three stacks contact outside your own network. Own machines
(push agents, CI) only talk to Dependency-Track over the tailnet; nothing on the internet
connects in.

### Installation and upgrades

| Server | What | When |
| --- | --- | --- |
| `github.com` | Clones of OpenCVE (`OPENCVE_REF`) and DefectDojo (`DD_REF`); syft releases (manual install, [Install syft](install.md#4-install-syft)) | `setup`, `upgrade` |
| `ghcr.io` | Dependency-Track `apiserver` and `frontend` images | `setup`, `upgrade` |
| `registry.defectdojo.com` | DefectDojo `django` and `nginx` images | `setup`, `upgrade` |
| Docker Hub | `postgres`, `valkey`, `nginx`, `redis/redis-stack`, the Airflow base image, `python` (glue and OpenCVE web images), `mattermost/mattermost-team-edition` (local chat) | `setup`, `upgrade`, `chat-up` |
| PyPI | Python packages for OpenCVE's locally built images (vulnflow itself has no runtime dependencies) | OpenCVE build |
| `api.github.com` | Newest releases of DefectDojo, OpenCVE, Dependency-Track and Valkey (anonymous, four requests per run; sends nothing about you) | `./poc.sh check-updates`, the email reports |

### Vulnerability data, while running

| Server | Who asks | What leaves the machine | Turn off |
| --- | --- | --- | --- |
| NVD (`nist.gov`) | Dependency-Track's NVD mirror (on by default) | nothing about you: it downloads the whole feed | DT UI, Administration |
| `storage.googleapis.com/osv-vulnerabilities` | Dependency-Track's OSV mirror, for `DT_OSV_ECOSYSTEMS` | nothing about you: it downloads per-ecosystem archives | `DT_OSV_ECOSYSTEMS=` empty before bootstrap, or DT UI |
| `metrics.dependencytrack.org` | Dependency-Track telemetry, **off** unless `DT_TELEMETRY=true` (`dt-bootstrap` sets it; the compose file keeps a new database from sending at first start) | once a day: a cluster id, the DT version, the database type and version | `DT_TELEMETRY=false` (the default), then `./poc.sh dt-bootstrap` |
| GitHub Advisories | Dependency-Track, only if you enable it with a GitHub token ([OSV in Dependency-Track](install.md#2-osv-in-dependency-track)) | the token | off by default |
| `github.com` | OpenCVE's Airflow DAG pulls `opencve/opencve-kb`, `opencve-nvd`, `opencve-redhat`, `CVEProject/cvelistV5`, `cisagov/vulnrichment` | nothing about you: full git repositories | stop the DAG |
| `www.cisa.gov` | receiver enrichment and the email reports: CISA KEV list (cached 6 h); `kev-watch` in each `dt2dojo` round (cached 1 h) | nothing about you: one file download | `VULNFLOW_ENRICH_KEV=0` |
| `api.vulncheck.com` | the same users, only with `VULNCHECK_API_TOKEN`: the whole VulnCheck KEV index (cached 6 h, also for `kev-watch`; about 5 requests) | the token, which identifies your VulnCheck account; never CVE ids or anything about your stack | leave `VULNCHECK_API_TOKEN` empty, or `VULNFLOW_ENRICH_KEV=0` |
| `api.github.com`, `github.com` (release downloads) | `github-sboms` in each `dt2dojo` round, only with `[github.*]` in `machines.toml` | the repository names; `VULNFLOW_GITHUB_TOKEN` to the API if set | remove the `[github.*]` entries, or `dt2dojo --no-github-sboms` |
| `tuf-repo-cdn.sigstore.dev` | `cosign verify-blob` in `github-sboms` fetches the Sigstore trust root (cached in `data/.sigstore`), only for entries with `verify` | nothing about your stack: a plain download of public metadata | drop `verify` (then the SBOM's origin is not checked) |

`github-sboms` accepts what a release publishes, so a compromised release would put a forged
SBOM into Dependency-Track (an SBOM without the vulnerable component closes its findings).
`verify` in a `[github.*]` entry requires a keyless cosign signature from the named workflow
identity; a missing, bad or foreign signature means no upload and an error. See
[SBOMs](sboms.md#verifying-the-signature-cosign).
| the feeds in `[news.feeds.*]` (`machines.toml`) | `newsletter` (daily, weekly, `alert`) | nothing about you: each feed is downloaded whole and filtered on the server, never searched per keyword or CVE | remove or `enabled = false` the feed, or point `url` at an internal mirror |
| `api.first.org` | receiver enrichment: EPSS score | the CVE ids it alerts on | `VULNFLOW_ENRICH_EPSS=0` |
| `vulnerability.circl.lu` (`CIRCL_URL`) | receiver enrichment: sightings | the CVE ids it alerts on | `VULNFLOW_ENRICH_CIRCL=0`, or your own instance |
| your chat server | receiver alerts, `kev-watch` and `finding-watch` (`VULNFLOW_CHAT_WEBHOOK`, `VULNFLOW_SOC_WEBHOOK`) | the message text: CVE, tier, team, links; findings also name the project (host, image), component and version | leave them empty, or use the local Mattermost |
| your pager (`VULNFLOW_PAGE_WEBHOOK`) | `finding-watch`: new P1 findings on critical assets | the same text as the chat messages, so host and component names. On public ntfy.sh anyone who knows the topic reads it: self-host ntfy, or use access control | leave it empty |
| Mattermost's own servers | the local chat, **switched off** in `stacks/mattermost/docker-compose.yml`: diagnostics, security-fix alerts, product notices, plugin marketplace, push notification proxy; link previews (the server fetching URLs in posts) off too | nothing while those stay off | — |
| Tailscale | `tailscaled` (coordination server and DERP relays) | node metadata, as for any tailnet member | — |

The `enrich` command uses the same three enrichment sources as the receiver.

### On-demand triage commands

These run only when you start them; the email reports do not run them. `ignore`/`unignore` only talk to
Dependency-Track.

| Command | Server | What leaves the machine |
| --- | --- | --- |
| `debian` | `security-tracker.debian.org` | nothing about you: one public JSON file, downloaded and cached |
| `vendor --ubuntu` | `ubuntu.com` (`/security/cves/<id>.json`) | the CVE ids of open findings on `pkg:deb/ubuntu/...` components, one request each, cached 24 h |
| `vendor --redhat` | `access.redhat.com` (`/hydra/rest/securitydata/cve/<id>.json`) | the CVE ids of open findings on `pkg:rpm/redhat/...` components, one request each, cached 24 h |
| `patches --osv` | `api.osv.dev` (`/v1/query`) | the package URL and version of each component with an open finding DT has no fix for |
| `disputed` | `nvd.nist.gov` (`/feeds/json/cve/2.0/`) | which years your CVE ids are from: one feed per year (8-50 MB), kept until its `.meta` changes; `--no-nvd` skips it |

`vendor` and `patches --osv` reveal which CVEs or packages you have, not only what you are
interested in: unlike the Debian file and the DT mirrors, the request itself is your
inventory. That's why they are opt-in flags. `vendor` says what it is about to send before it
sends it.
