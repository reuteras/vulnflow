# Teams, tiers and where things live

[Back to the README](../README.md).

## How the teams work

Everything is keyed on the team entries in `inventory/inventory.toml`. The example estate has
six groups:

| | sysadm | users | dev | network | virt | platform |
| --- | --- | --- | --- | --- | --- | --- |
| Owns | the servers | the MacBooks | code and containers | firewalls, VPN, load balancers, switches | vCenter, ESXi | OpenShift, Kubernetes |
| OpenCVE project | `sysadm` | `users` | `dev` | `network` | `virt` | `platform` |
| Dependency-Track tag | `team-sysadm` | `team-users` | `team-dev` | `team-network` | `team-virt` | `team-platform` |
| DefectDojo product type | `Sysadmin` | `Users` | `Development` | `Network` | `Virtualization` | `Platform` |
| Chat mention | `@sysadm` | `@users` | `@dev` | `@network` | `@virt` | `@platform` |
| DT projects | `host:<server>` | `host:<macbook>` | `container:<image>`, `code:<name>` | none | none | none |

network, virt and platform run appliances and platforms with no SBOM, so OpenCVE follows
their products (Fortinet, NetScaler, Cisco and Check Point product lines; vCenter and ESXi;
OpenShift and Kubernetes), with no version: every CVE for the product is an alert. The
products in `inventory.toml` are common examples; put the ones you run in
`[subscriptions.<team>]` in `machines.toml`.

Products that several teams care about can be listed under each. Each team then gets its
own alert and its own status in OpenCVE. A machine's `team` owns its `host:` project; the
containers running on it belong to `containers_team` (default `dev`) and `[code.*]` entries
to their own `team` (default `dev`).

## Priority tiers

The vulnflow receiver ranks every CVE change OpenCVE sends it:

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

Rule of thumb: **"is this a vulnerability here?" is answered in Dependency-Track; "what do
we do about it, who, and by when?" in DefectDojo.** CVEs for products without an SBOM are
followed in OpenCVE.

| Tool | Holds | Why there |
| --- | --- | --- |
| OpenCVE | CVE level ("does Fortinet CVE-X matter to us?"): project status (`to_evaluate … risk_accepted`), assignee, tags, saved views per team | Vendors/products you follow by subscription, appliances and SaaS that have no SBOM |
| Dependency-Track | What is installed where; matching against NVD, OSV, GitHub; **decisions that must survive updates**: Not Affected / False Positive with a justification, and accepted risks (Exploitable + Will Not Fix / Can Not Fix) with a review date (`ignore`, from `debian`, `disputed` or your own review) | `prune` carries these to new versions of the same build and brings a decision back after its review date; suppressed findings leave DefectDojo through the FPF export; they are VEX |
| DefectDojo | The work on what *is* a problem: owner, priority, SLA, notes, Jira link; reports and metrics per team/product; findings from other tools later (pentests, DAST). Filter by host or kind with the `host-*` / `kind-*` / `group-*` tags `dt2dojo` puts on each test and its findings | Built for workflow and reporting; `dt2dojo` re-imports with `close_old_findings`, so a component fixed in DT closes its finding here |

How it is laid out in DefectDojo: a **product type** per team, a **product** per DT project
name (`container:nginx`), one **engagement** `Dependency-Track` per product for the
continuous import, and a **test** per version (`Dependency-Track 1.31.8`). `prune` closes a
version's test once that version is no longer uploaded.

Things that follow from that layout:

- **Decisions in DefectDojo stay with one version.** A finding belongs to its version's
  test; the next image tag is a new test with new findings (checked 2026-11-24: no
  deduplication across the tests). Notes, an owner or a risk acceptance on
  `container:x@1.2` do not move to `@1.3`. Host projects are stable (their version is the OS
  release, e.g. `debian-13`), so a DefectDojo risk acceptance on a host finding lasts until
  the next release; on a container it lasts until the next update. Anything that should
  survive updates belongs in Dependency-Track: accepted risks too (`ignore --state
  EXPLOITABLE --response WILL_NOT_FIX --review-by <date>`, see "Clearing known-OK
  findings"). DefectDojo's importer only maps DT's False Positive; the other decisions
  reach it as suppressed (so: not exported, closed).
- **One test per image name and host would not fix that**: several versions of the same
  image often run side by side on one host (one postgres per application), and they would
  overwrite each other's findings on every import. DT has no project per container to key
  on.
- **The same CVE shows once per running version** (two postgres versions, two findings).
  That is right while both run; after an update the old version's findings close 2 days
  after its last upload.
- **Engagements:** keep the one `Dependency-Track` engagement for the continuous import;
  create your own engagement (with start and end date) for time-boxed work: a pentest, a
  quarterly review, a migration. Do not create one per version or per run; the tests do
  that.
- **Endpoints** are for network findings (host:port, URL) from tools such as ZAP or nuclei.
  Component findings have none, so they are not used; they become worth it once a network
  or web scanner feeds DefectDojo.
