# Exposure and criticality (design proposal)

[Back to the README](../README.md).

**Status: steps 1 to 3 of [What it takes](#what-it-takes-in-vulnflow) are in place**: the
asset model and its tags ([Step 1 in use](#step-1-in-use)), the scoring of
Dependency-Track findings with them ([Step 2 in use](#step-2-in-use)) and the tiers in
DefectDojo ([Step 3 in use](#step-3-in-use)); routing, importers and the report sections
(steps 4 to 6) are not. Before this, vulnflow ranked a CVE by threat alone
(KEV, CIRCL sightings, EPSS, CVSS; see [Priority tiers](concepts.md#priority-tiers)), so the
same CVE got the same tier on a public web service and on a locked-down admin workstation;
OpenCVE alerts still do, because they are per product, not per asset. This document describes how to add *asset context*, how exposed an asset is and
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

## Step 2 in use

Every open Dependency-Track finding gets a tier from the threat (KEV from the cached
catalog, EPSS and CVSS v3 as Dependency-Track reports them on the finding) and its
context, read from `machines.toml` as it is now (the project's tags only when
`machines.toml` has nothing for it, so an edit ranks at once, before the next `context`
run updates the tags), by the matrix in
[Combining threat and context](#combining-threat-and-context-into-a-tier):

- no context: the `internal` column, which is the threat-only tier vulnflow always had;
- `input = "public"` and `hostile-device`: the `internet` column;
- the CVSS v3 vector: a Local or Physical bug ranks in the `restricted` column, an Adjacent
  one at most as `internal`; on a laptop (`kind-laptop`) a network bug that needs user
  interaction (`UI:R`: browser, mail, PDF) ranks as `internet`, so laptops can be
  `internal` and their client-side CVEs still rank high;
- `critical` and `high` raise one step, but only a real threat (KEV or exploited, high EPSS,
  CVSS high): a finding with nothing behind it stays where the matrix puts it. `low` lowers
  one step. KEV or an exploited sighting on a `critical` asset is P1.
- No CVSS score (many GO-, GHSA- and DEBIAN- advisories): Dependency-Track's severity stands
  in, CRITICAL as 9.0 and HIGH as 7.5, and the reason says `severity HIGH (no CVSS score)`.

A host project holds every OS package and every module built into the host's binaries,
so one exposure for all of it is too coarse: on an internet-facing server, `acl`, `perl`
or the Docker CLI's Go modules would rank like the web server. `[hosts.<h>.packages]`
gives single packages their own context, by name or glob, overriding the host's field by
field when their findings are ranked (the project's tags stay the host's):

```toml
[hosts.web01]
exposure = "internal"                 # the OS as a whole
criticality = "high"
[hosts.web01.packages]
"nginx"          = { exposure = "internet", input = "public" }
"openssh-server" = { exposure = "internet" }
"openssl"        = { exposure = "internet", input = "public" }
```

Findings don't carry the vector, so vulnflow reads it per vulnerability from
Dependency-Track, only for projects with context, and caches it in `cvss-vectors.json` in
the data directory (refreshed after 30 days). Each tier has its reasons, e.g. `in CISA KEV;
internet; critical asset`.

Where it shows: `python3 -m vulnflow priorities [--team T] [--tier N] [--json]` lists the
findings by tier with the reasons; the TUI's Findings tab sorts by tier and filters with
`p`; the email reports list new P1/P2 findings (with critical, high and KEV ones as before),
with the tier and reasons, and a new P1 or P2 makes the daily report go out.

## Step 3 in use

After each re-import, `dt2dojo` ranks the project's findings (from the export it just
uploaded) and updates the DefectDojo findings of that test through the API, matched exactly
by Dependency-Track's finding id (`unique_id_from_tool`):

- tag `tier-p1` … `tier-p4` (the previous one replaced, other tags kept): filter on it, or
  build a dashboard on it;
- DefectDojo's own `known_exploited`, `ransomware_used` and `kev_date` from the CISA KEV
  catalog (its Dependency-Track parser already copies EPSS);
- **planned remediation date** = the finding's date plus `sla_days` for its tier, in
  `[priority]` of `inventory.toml` (default P1 7, P2 30, P3 90 days, P4 none). vulnflow only
  changes a date it set itself (empty, or what the previous tier gave); a date someone set
  by hand stays.

DefectDojo's own SLA date and its "SLA violated" views still follow severity. Making them
follow the tier would need code inside DefectDojo (its `FINDING_SLA_PERIOD_METHOD` hook),
which vulnflow leaves out on purpose: nothing to maintain inside another tool. Sort and
filter on the planned remediation date and the tier tag instead.
