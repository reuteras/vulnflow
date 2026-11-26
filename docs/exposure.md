# Exposure and criticality (design proposal)

[Back to the README](../README.md).

**Status: step 1 of [What it takes](#what-it-takes-in-vulnflow) is in place** (the asset
model and its tags, see [Step 1 in use](#step-1-in-use)); scoring with it (step 2) and the
rest are not. Today vulnflow ranks a CVE by threat alone (KEV,
CIRCL sightings, EPSS, CVSS; see [Priority tiers](concepts.md#priority-tiers)) and routes it
by team. The same CVE gets the same tier on a public web service and on a locked-down admin
workstation. This document describes how to add *asset context*, how exposed an asset is and
how much it matters, for large organisations such as government agencies and banks: many
users and teams, public digital services, mobile apps, identity, regulated critical
services and a fair amount of legacy.

The approach follows CISA's [SSVC](https://www.cisa.gov/ssvc) (exploitation, exposure,
automatable, impact) and the CVSS *environmental* metrics, so the scoring stays standard
and explainable.

## Exposure: who can reach it, and who controls the input

Exposure has two parts. Network reachability is the familiar one:

| Network class | Meaning |
| --- | --- |
| `internet` | Reachable by anyone on the internet, before login |
| `external-auth` | Reachable from outside, but only after login (customers, citizens, partners) |
| `internal` | Reachable from the internal network or user devices |
| `restricted` | Segmented, admin-only, allow-listed |
| `hostile-device` | Runs on devices the organisation does not control (public mobile apps) |

The second part is **who controls the input**. A system can be isolated on the network and
still parse attacker-controlled data:

- Systems that read documents, cards or chips (identity verification, card terminals)
  parse input that an attacker can craft.
- Self-service terminals in public places (kiosks, ATMs, gates) add the physical attack
  vector, which is normally ranked low.
- Public services accept files and documents from anonymous users.

| Input class | Meaning |
| --- | --- |
| `public` | Anyone can supply input |
| `partner` | Known external parties |
| `staff` | Employees only |

Rule: a CVE in a component that parses `public` input counts as exposed even on a
`restricted` network. The CVSS attack vector decides which part applies: Network bugs
depend on reachability, Adjacent and Physical bugs on where the device stands, and bugs
that need user interaction on what users open.

That last point matters for workstations. A locked-down managed desktop has no inbound
exposure, but its users browse the web and read mail, so client-side CVEs (browser, office
suite, PDF reader) stay relevant. Application control and no local admin rights do lower
the risk of local privilege escalation; record them as a compensating control.

## Criticality: what kind of damage, to how many

A single low-to-high scale is not enough. The *kind* of failure matters as much as its
size:

- **Integrity**: for identity, payments and records, silently accepting something false (a
  forged credential, a revoked certificate, a manipulated transaction) is often the worst
  case. Bugs in crypto libraries, certificate validation and signature checks rank high.
- **Availability**: when a critical public or financial service is down, that is itself the
  incident. Denial-of-service CVEs, normally ranked low, rank high here.
- **Confidentiality**: personal, financial and biometric data at scale.

Each asset therefore gets:

```toml
criticality  = "critical"                              # critical | high | normal | low
requirements = { C = "high", I = "high", A = "high" }  # CVSS environmental requirements
reach        = "large"                                 # how many people an outage or breach affects
```

| Criticality | Meaning |
| --- | --- |
| `critical` | Harm to the public, customers or society; usually a regulated or designated critical service |
| `high` | The organisation cannot do its core work (identity provider, PKI and HSM, core systems) |
| `normal` | Everything else |
| `low` | Test, sandbox, decommissioning |

The C/I/A requirements and the exposure feed the CVSS environmental metrics (security
requirements, modified attack vector) before the threat rules run. A DoS CVE on a
`critical` service rises; a local-only bug on a locked-down desktop drops.

## Systems you cannot just patch

Three flags describe how a fix can happen:

- **`vendor`**: an appliance or vendor system without an SBOM of our own. Followed as an
  OpenCVE product subscription, as the network team already does. Ask for SBOMs and VEX in
  contracts (the EU Cyber Resilience Act pushes in that direction) and track how long each
  vendor takes to ship a fix.
- **`certified`**: changes follow a certification or accreditation cycle. A P1 here starts
  compensating controls (segmentation, WAF rules, disabling the affected feature, manual
  fallback) and vendor escalation; the SLA measures time to mitigation, not time to patch.
- **`eol`**: no more patches. The outcome is an accepted risk with compensating controls
  and a review date, which vulnflow already supports
  (`ignore --state EXPLOITABLE --response CAN_NOT_FIX --review-by …`). Reported separately so
  legacy does not drown everything else.

## How common parts of an estate fit

| Part of the estate | Typical exposure | How it gets into vulnflow |
| --- | --- | --- |
| Public web and APIs | `internet`, `public` input | SBOMs from CI (`code:<app>`, `container:<image>`) |
| Customer or citizen services after login | `external-auth`, `public` input | SBOMs from CI |
| Public mobile apps | `hostile-device`, `public` input | SBOM at build time; app store metrics for OS versions in use |
| Self-service terminals, document or card readers | `restricted`, `public` input, physical | Usually `vendor`: OpenCVE subscriptions, vendor SBOM/VEX, SBOMs from the management system or image |
| Managed workstations | `internal` inbound, client-side exposed | Push agent or the endpoint management tool's inventory |
| Managed phones (MDM only) | `internal`, client-side exposed | OS version per device from the MDM; the mobile OS as an OpenCVE product subscription |
| Legacy systems | usually `internal` | `eol` flag, accepted risk with review date |

Two points for mobile:

- **Managed phones** need no SBOM. What matters is the share of the fleet below the fixed
  OS version, and the fix is an MDM minimum-OS policy, not a ticket per device.
- **Customers' and citizens' phones** cannot be managed. The levers are a minimum OS
  version enforced by the app and device attestation; the metric is the share of active
  users on an OS with a known exploited bug.

## Combining threat and context into a tier

Kept simple and explainable, as the current tiers are. Exposure first (after the attack
vector check above):

| Threat \ exposure | internet / public input | external-auth | internal | restricted, staff input |
| --- | --- | --- | --- | --- |
| **KEV or exploited** | P1 | P1 | P1 (P2 on locked-down desktops if local access is needed) | P2 |
| **High EPSS, or critical with some EPSS** | P1 | P2 | P2 | P3 |
| **CVSS high** | P2 | P3 | P3 | P4 |
| **Other** | P3 | P4 | P4 | P4 |

Then criticality: `critical` and `high` raise one step, `low` lowers one step. Any KEV or
exploited CVE on a `critical` asset is P1 regardless of exposure.

Every alert carries its reasons, as tiers do today, extended with the context, for example
"KEV; internet; critical; 3 hosts".

## Surfacing what matters

- **Only P1 interrupts people.** P1 goes to chat with the owning team mentioned and a short
  SLA. **P1 on a `critical` asset is an incident**: it pages on-call and starts the
  incident process, including any regulatory reporting (for example NIS2 or DORA in the
  EU).
- **P2 goes to DefectDojo with an SLA**; P3 and P4 only to dashboards and the weekly report.
- **Route by owner, not by tool.** In a large organisation owners come from the CMDB or
  application register, not from a handful of fixed teams.
- **Blast radius in every alert**: how many services, and how many of them `critical`,
  contain the component. `where` already answers where a component is.
- **A view per critical service chain** (for example identity, payments), including vendor
  and third-party parts, for the chain's owners.
- **Fleet metrics instead of per-device findings** for workstations and phones.
- **Exposure drift**: compare the declared exposure with an external attack-surface scan.
  An asset declared `internal` that is reachable from the internet is itself a finding.
- **Report order**: internet-facing and exploited first, then `critical`, then the rest;
  separate sections for vendors (open CVEs, days waiting for a fix) and `eol` systems.
- **Practise the fallback.** If the answer to an exploited critical system is a manual or
  degraded mode, that is part of the vulnerability process too.

## What it takes in vulnflow

1. **Asset model.** `exposure`, `input`, `criticality`, `requirements`, `reach` and the
   `vendor` / `certified` / `eol` flags on groups, hosts, `[code.*]` entries and
   subscription products in `machines.toml`. Carried as Dependency-Track project tags and
   DefectDojo tags (`exposure-internet`, `crit-critical`, …), as `dt2dojo` already does for
   host, kind and group.
2. **Scoring.** `priority.assess` takes the asset context and the CVSS vector, applies the
   environmental metrics, then the matrix above. Thresholds stay in `[priority]`.
3. **Tiers on Dependency-Track findings too**, not only on OpenCVE alerts. `dt2dojo` would
   set DefectDojo priority and SLA from the tier.
4. **Routing.** P1 on `critical` to paging and incident handling.
5. **Importers.** A CMDB or application register for owner, exposure and criticality
   (`machines.toml` becomes an override file on top; hand-maintaining a large estate does
   not scale), the MDM for OS versions per device, and an external attack-surface source
   for drift.
6. **Report.** The sections listed above.

Steps 1–3 fit the current design and can be built and tested offline. Steps 4–6 depend on
the paging, CMDB, MDM and attack-surface tools in use.

## Step 1 in use

`exposure`, `input`, `criticality`, `eol` and `certified` go in `machines.toml` on what
runs, never on a group: a group can run a public web service and an internal admin page,
so a group-wide exposure would be wrong for one of them. `machines.toml` refuses the keys
on a group.

| Dependency-Track project | Context from |
| --- | --- |
| any, by name | `[projects."<name>"]`, e.g. a project uploaded from CI (wins over the rest) |
| `host:<h>` | `[hosts.<h>]` |
| `container:<image>` | `[hosts.<h>.images]` of the host in its `host-<h>` tag: the image name, its last part (`nginx`), or a glob (`ghcr.io/acme/admin-*`); an exact name wins over a glob, a longer glob over a shorter one, so `"*"` catches the host's other containers |
| `code:<name>` | `[code.<name>]` |
| `<name>` from a GitHub release | `[github.<name>]` |

```toml
[hosts.web01]
exposure = "internal"            # the host itself
[hosts.web01.images]
"nginx" = { exposure = "internet", input = "public", criticality = "high" }
"ghcr.io/acme/admin-*" = { exposure = "restricted", input = "staff" }
"*" = { exposure = "internal" }  # the host's other containers (databases, workers, ...)
```

A catch-all is per host, on purpose: it says "everything else on this host is internal",
which you can check host by host, where a group-wide value could not be. An entry that sets
none of the keys counts as unknown.

They become tags on the Dependency-Track project (`exposure-internet`, `input-public`,
`crit-high`, `flag-eol`, `flag-certified`), which `dt2dojo` copies to DefectDojo. A project
without context gets none and stays unknown. The agents can't set them: Dependency-Track
applies tags only when it creates a project, and an upload-only key can't change them. So
every `dt2dojo` round sets them with the maintenance key (`DT_MAINTENANCE_API_KEY`),
replacing only the context tags and keeping the others; an edit to `machines.toml` takes
effect at the next round. `python3 -m vulnflow context --unknown` shows what would change
and which projects have no context yet; `--apply` writes it now.

`python3 -m vulnflow context --toml > unknown.toml` writes the `machines.toml` entries for
the projects without context: host and image names come from Dependency-Track, the values
are empty (empty is unknown, so the lines load as they are). Fill in what you know and move
the lines into `machines.toml`. A table that already exists there (`[hosts.web01]`,
`[hosts.web01.images]`) comes as a comment saying where its lines go, because TOML doesn't
allow the same table twice. Images that run in several versions get one line.

Editor help: `schemas/machines.schema.json` describes every key and allowed value of
`machines.toml`. With `#:schema ./schemas/machines.schema.json` as the first line (as in
`machines.example.toml`), a TOML language server completes keys and values, shows what each
value means and marks mistakes while you type: taplo, which LazyVim's TOML extra and
VS Code's Even Better TOML use. `taplo lint machines.toml` checks the file from the
command line. `python3 -m vulnflow schema` regenerates the schema (the teams come from
`inventory/inventory.toml`); a test fails when the committed file is out of date.
