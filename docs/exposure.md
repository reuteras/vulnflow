# Exposure and criticality (design proposal)

[Back to the README](../README.md).

**Status: proposal, not implemented.** Today vulnflow ranks a CVE by threat alone (KEV,
CIRCL sightings, EPSS, CVSS; see [Priority tiers](concepts.md#priority-tiers)) and routes it
by team. The same CVE gets the same tier on a public web server and on a locked-down admin
desktop. This document describes how to add *asset context* (how exposed an asset is and
how much it matters) for a large organisation: tens of thousands of users, more than a
thousand IT staff, mobile apps, web solutions, digital ID, border verification and services
used by millions of citizens, plus a lot of legacy.

The approach is close to CISA's [SSVC](https://www.cisa.gov/ssvc) (exploitation, exposure,
automatable, mission impact) and uses the CVSS *environmental* metrics so the scoring stays
standard and explainable.

## Exposure: who can reach it, and who controls the input

Exposure has two parts. Network reachability is the familiar one:

| Network class | Meaning | Examples |
| --- | --- | --- |
| `internet` | Reachable by anyone on the internet, before login | Public web and APIs, digital ID front ends, VPN and firewall edges, mail gateways |
| `external-auth` | Reachable from outside, but only after login (citizens, partners, B2B) | Self-service portals, partner integrations |
| `internal` | Reachable from the ordinary internal network or user devices | Intranet apps, file servers, most legacy systems |
| `restricted` | Segmented, admin-only, allow-listed | Admin workstations and enclaves, HSM and PKI, backup, border networks |
| `hostile-device` | Runs on devices the organisation does not control | The citizen wallet app, other public mobile apps |

The second part is **who controls the input**. A system can be isolated on the network and
still parse attacker-controlled data all day:

- **Document readers and eGates** read the passport or ID chip over NFC, the MRZ and
  photos. A forged document is a malicious input: a parser bug in the chip-reading stack
  (ASN.1, image decoding, signature verification) is exploitable at the counter without any
  network path.
- **Kiosks and eGates stand in public halls**, so the physical attack vector (USB,
  maintenance ports), normally ranked low, is real.
- **Citizen services** accept documents, images and files from millions of anonymous users.

| Input class | Meaning |
| --- | --- |
| `public` | Anyone can supply input (web forms, uploaded files, ID documents, NFC chips, public halls) |
| `partner` | Known external parties |
| `staff` | Employees only |

Rule: a CVE in a component that parses `public` input counts as exposed even on a
`restricted` network. The CVSS attack vector decides which part applies: Network bugs
depend on reachability, Adjacent (NFC) and Physical bugs on where the device stands, and
bugs that need user interaction on what users open.

That last point matters for desktops. A locked-down managed desktop has no inbound
exposure, but its users browse the web and read mail, so client-side CVEs (browser, office
suite, PDF reader) stay relevant. Application control and no local admin rights do lower
the risk of local privilege escalation; record them as a compensating control.

## Criticality: what kind of damage, to how many

A single low-to-high scale is not enough. For identity and border systems the *kind* of
failure matters as much as its size:

- **Integrity** is the worst case for border and identity systems. Accepting a forged
  document, a revoked certificate or a wrong face match does damage silently. Bugs in
  crypto libraries, certificate-chain checks and signature verification belong at the top.
- **Availability**: border control or a service for 10 million people being down is itself
  the incident. Denial-of-service CVEs, normally ranked low, rank high here.
- **Confidentiality**: biometrics and personal data at national scale.

Each asset therefore gets:

```toml
criticality  = "national"                          # national | mission | high | normal | low
requirements = { C = "high", I = "high", A = "high" }  # CVSS environmental requirements
population   = 10_000_000                          # people affected by an outage or breach
```

| Criticality | Meaning | Examples |
| --- | --- | --- |
| `national` | Harm to the public, citizens' rights or national security | Border verification, digital ID, citizen services at national scale |
| `mission` | The organisation cannot do its core work | Identity provider, PKI and HSM, payments, case management |
| `high` | Important internal systems | |
| `normal` | Everything else | |
| `low` | Test, sandbox, decommissioning | |

The C/I/A requirements and the exposure feed the CVSS environmental metrics (security
requirements, modified attack vector) before the threat rules run. So a DoS CVE on a
`national` asset rises, and a local-only bug on a locked-down desktop drops.

## Systems you cannot just patch

Three flags describe how a fix can happen:

- **`vendor`**: an appliance or vendor system without our own SBOM (eGates, document
  readers, network edges). Followed as an OpenCVE product subscription, as the network team
  already does. Ask for SBOMs and VEX in contracts (the EU Cyber Resilience Act pushes in
  that direction), and track how long each vendor takes to ship a fix.
- **`certified`**: changes follow a certification cycle (Common Criteria, ICAO conformance,
  national accreditation). A P1 here starts compensating controls (segmentation, WAF rules,
  disabling the affected feature, manual fallback at the border) and vendor escalation; the
  SLA measures time to mitigation, not time to patch.
- **`eol`**: no more patches. The outcome is an accepted risk with compensating controls
  and a review date, which vulnflow already supports
  (`ignore --state EXPLOITABLE --response CAN_NOT_FIX --review-by …`). Reported separately so
  legacy does not drown everything else.

## How the different parts of the estate fit

| Part of the estate | Exposure | Criticality | How it gets into vulnflow |
| --- | --- | --- | --- |
| Public web, APIs, digital ID front ends | `internet`, `public` | `national` or `mission` | SBOMs from CI (`code:<app>`, `container:<image>`) |
| Citizen services (10M+ users) | `internet` or `external-auth`, `public` | `national`, A and I high | SBOMs from CI |
| Border verification (eGates, readers, matching) | `restricted`, `public` input, physical | `national`, I and A high | `vendor` + `certified`: OpenCVE subscriptions, vendor SBOM/VEX, SBOMs from the central management system or golden image for offline posts |
| Citizen wallet app | `hostile-device`, `public` | `national` | SBOM at build time (SPM, CocoaPods, Gradle); store metrics for OS versions in use |
| Locked-down managed desktops | `internal` inbound, client-side exposed | `normal` | Push agent or the endpoint management tool's inventory |
| Staff iPhones (MDM only) | `internal`, client-side exposed | `normal` | OS version per device from the MDM; Apple iOS as an OpenCVE product subscription |
| Legacy systems | usually `internal` | varies | `eol` flag, accepted risk with review date |

Two points for mobile:

- **Staff iPhones** need no SBOM. What matters is the share of the fleet below the fixed
  iOS version, and the fix is an MDM minimum-OS policy, not a ticket per device. iOS is
  in KEV often, so expect a recurring P1 with a fleet-wide action.
- **Citizens' phones** cannot be managed. The levers are a minimum OS version enforced by
  the app and device attestation; the metric is the share of active wallet users on an OS
  with a known exploited bug.

## Combining threat and context into a tier

Kept simple and explainable, as the current tiers are. Exposure first (after the attack
vector check above):

| Threat \ exposure | internet / public input | external-auth | internal | restricted, staff input |
| --- | --- | --- | --- | --- |
| **KEV or exploited** | P1 | P1 | P1 (P2 on locked-down desktops if local access is needed) | P2 |
| **High EPSS, or critical with some EPSS** | P1 | P2 | P2 | P3 |
| **CVSS high** | P2 | P3 | P3 | P4 |
| **Other** | P3 | P4 | P4 | P4 |

Then criticality: `national` and `mission` raise one step, `low` lowers one step. Any KEV or
exploited CVE on a `national` asset is P1 regardless of exposure, and so is high EPSS.

Every alert carries its reasons, as tiers do today, extended with the context:
"KEV; internet; digital ID; 3 hosts; population 10M".

## Surfacing what matters

- **Only P1 interrupts people.** P1 goes to chat with the owning team mentioned and a short
  SLA. **P1 on a `national` asset is an incident**: it pages on-call and opens a security
  incident. Under NIS2, exploitation of such a system is likely also a reporting matter
  (24-hour early warning).
- **P2 goes to DefectDojo with an SLA**; P3 and P4 only to dashboards and the weekly report.
- **Route by owner, not by tool.** At this size there are probably 50–150 product and
  system teams; owners come from the CMDB or application register.
- **Blast radius in every alert**: "OpenSSL CVE-X: 4 citizen-facing services (10M users)
  and the document readers at 12 border posts". `where` already answers where a component
  is; alerts add service count and population.
- **A view per national chain**: digital ID (wallet, backend, PKI/HSM, certificate
  validation) and border (eGate, reader, matching, background lookups), each with its
  vendor and third-party parts, for the chain's owners.
- **Fleet metrics instead of per-device findings** for desktops and phones.
- **Exposure drift**: compare the declared exposure with an external attack-surface scan
  (your own scan of public ranges and DNS, or Shodan/Censys). An asset declared `internal`
  that is reachable from the internet is itself a finding.
- **Daily report order**: internet-facing and exploited, then `national` and `mission`,
  then the rest; separate sections for vendors (open CVEs, days waiting for a fix), `eol`
  systems and the wallet OS metric.
- **Practise the manual fallback.** If the answer to "reader exploited" is "switch to
  manual checks", that is part of the vulnerability process too.

## What it takes in vulnflow

1. **Asset model.** `exposure`, `input`, `criticality`, `requirements`, `population` and the
   `vendor` / `certified` / `eol` flags on groups, hosts, `[code.*]` entries and
   subscription products in `machines.toml`. Carried as Dependency-Track project tags and
   DefectDojo tags (`exposure-internet`, `crit-national`, …), as `dt2dojo` already does for
   host, kind and group.
2. **Scoring.** `priority.assess` takes the asset context and the CVSS vector, applies the
   environmental metrics, then the matrix above. Thresholds stay in `[priority]`.
3. **Tiers on Dependency-Track findings too**, not only on OpenCVE alerts. Today the TUI and
   DefectDojo sort by KEV and raw severity; `dt2dojo` would set DefectDojo priority and SLA
   from the tier.
4. **Routing.** P1 on `national` to paging and incident handling.
5. **Importers.** A CMDB or application register for owner, exposure and criticality
   (`machines.toml` becomes an override file on top: hand-maintaining tens of thousands of
   assets does not scale); the MDM for OS versions per device; an external attack-surface
   source for drift.
6. **Report.** The sections listed above.

Steps 1–3 fit the current design and can be built and tested offline. Steps 4–6 depend on
which paging, CMDB, MDM and attack-surface tools are in use.

## Open questions

- Which MDM, CMDB or application register, and paging system are in use?
- Can the border and wallet vendors deliver SBOMs and VEX today?
- Is there an external attack-surface source, or should vulnflow scan its own public
  ranges?
- Do the `national` systems fall under NIS2 or other reporting duties that the P1 path
  should feed directly?
