# Daily usage

[Back to the README](../README.md). How findings and alerts reach you, what each team does
with them, how to clear false positives, and keeping the stacks up to date. Commands run on
the vulnflow server, in the repository directory.

## How findings and alerts reach you

Two paths run side by side, and the email reports summarise both.

**Watch: a CVE changes for a product you follow (OpenCVE).** OpenCVE's Airflow DAG imports CVE
changes regularly from its own knowledge base, NVD, the CVE List, Red Hat and CISA
Vulnrichment. When a change touches a vendor or
product in a team's subscriptions (from `inventory.toml` and `machines.toml`), OpenCVE adds
it to that team's project (`sysadm`, `users`, `dev`, `network`, … see [the teams](concepts.md#how-the-teams-work)). Each project has an alert automation
named `vulnflow`, created by `opencve-bootstrap`, which fires on every change and sends a
webhook: an HTTP POST with the CVE, its CVSS score and the event types, from OpenCVE's
worker to `http://vulnflow-receiver:8380/opencve` on the Docker network the two share, with
the shared secret `VULNFLOW_WEBHOOK_TOKEN` in an `X-Vulnflow-Token` header. Nothing leaves
the server. The receiver then:

1. looks the CVE up in CISA KEV, FIRST EPSS and CIRCL sightings, and ranks it P1 to P4
   ([Priority tiers](concepts.md#priority-tiers));
2. decides whether the change is worth a message ([Which changes notify](concepts.md#which-changes-notify)):
   the CVE is new to the project, was just added to KEV, became more serious, or is one
   somebody follows in OpenCVE. A title, description or reference edit on an old CVE is
   not;
3. appends every change to `alerts.jsonl` in its data volume (for the SIEM and the
   reports), with `notify` saying why it notified (empty: logged only);
4. for P1 and P2 changes that notify: posts a message mentioning the team to chat (`VULNFLOW_CHAT_WEBHOOK`:
   your own Mattermost, Slack or Teams webhook, or the PoC's local Mattermost from
   `./poc.sh chat-up`, channel `alerts`), and sets the CVE's status in the OpenCVE project to `to_evaluate` if nobody has set one;
5. for P1 (`VULNFLOW_SOC_MIN_TIER`) changes that notify, whatever the team and also when no team owns the
   project: posts it to the SOC channel (`VULNFLOW_SOC_WEBHOOK`; the local Mattermost's
   `soc` channel), naming the team instead of mentioning it.
   The two deliveries are independent: one failing doesn't stop the other.
   Noisy products are the exception for step 4's channel: CVEs matching a `[chat.<name>]` in
   `machines.toml` (its `match` against the subscription that made OpenCVE notify) go to
   that channel (`VULNFLOW_CHAT_WEBHOOK_<NAME>`) instead, from `min_tier` up (default P2).
   The channel is shared by all teams: OpenCVE sends each team's project its own webhook,
   and the receiver posts a CVE change once (remembered for 24 h in
   `data/alerts.channels-seen.json`), naming every team whose subscriptions cover it.
   Without the webhook set, they stay in the team channel. A team subscribed to a whole
   vendor never matches a `vendor:product` channel; `serve` and `chat-up` warn about it.

**Match: a CVE is found in something you run (Dependency-Track).** The push agents (daily)
and CI (per release) upload SBOMs; Dependency-Track matches every component against NVD,
OSV and the GitHub advisories, also when a new CVE arrives later for an SBOM it already has.
Every 30 minutes `dt2dojo` copies the open findings into DefectDojo, one product per DT
project under the team's product type, and closes the ones that are gone.

**New in KEV: the catalog itself.** OpenCVE only reports a KEV addition for a product a team
follows, and only when its knowledge base records it (up to a day and a half later). So
every `dt2dojo` round (every 30 minutes) also runs `kev-watch`: it compares CISA's catalog
with the entries it has seen (`kev-seen.json` in the data directory) and, for each new one,
looks for open Dependency-Track findings with that CVE and for teams whose OpenCVE
subscriptions name the vendor. Entries that hit something go to chat
(`VULNFLOW_CHAT_WEBHOOK`), mentioning those teams:

```text
@dev @network New in CISA KEV (2):
- CVE-2026-0010 OpenSSL OpenSSL: OpenSSL bug (added 2026-11-25)
  open finding, team dev: code:web@2: openssl 3.0.1; container:app@1.0: openssl 3.0.1
- CVE-2026-0011 Citrix NetScaler: NetScaler bug (added 2026-11-25, ransomware use)
  vendor followed by: network
```

Every new entry, also those that match nothing of ours, goes to the SOC channel
(`VULNFLOW_SOC_WEBHOOK`) when it is set. The first run only records the catalog. An entry
counts as seen once its messages were delivered, so a chat outage is retried.
`python3 -m vulnflow kev-watch --dry-run` shows what is new without posting;
`dt2dojo --no-kev-watch` turns it off. The vendor match is by name only (KEV's "Palo Alto
Networks" against NVD's `paloaltonetworks`), not by product or version.

When OpenCVE does report the addition (its event `metrics` with `added.kev`), the receiver
counts the CVE as KEV even if its own copy of the catalog, cached for 6 hours, doesn't have
it yet, so the alert is P1.

**New P1/P2 findings: chat and paging.** The same round tells the team channel about new
P1/P2 findings, the SOC channel about new P1 findings, and pages (`VULNFLOW_PAGE_WEBHOOK`)
for new P1 findings on a `critical` asset, once per finding and channel. Findings on a
noisy product (`[chat.<name>]` in `machines.toml`, matched on the component's CPE) go to
that channel instead of the team's, like the OpenCVE alerts. See
[Step 4 in use](exposure.md#step-4-in-use).

**Email reports** (daily when something needs action, weekly always): new P1/P2 alerts,
new critical/high/KEV findings, hosts that stopped uploading, and versions to deploy. See
[Email reports](#email-reports).

## Where to look

| Question | Where |
| --- | --- |
| Which CVEs changed for the products my team follows? | OpenCVE, the team's project; `to_evaluate` = P1/P2 nobody has looked at yet |
| Which of our hosts, images and apps have a vulnerable component? | Dependency-Track, projects tagged `team-<team>`: `host:…`, `container:…`, `code:…`, apps from CI |
| What are we working on, who owns it, by when? | DefectDojo, the team's product type (Sysadmin, Network, Workplace, …); filter by the `tier-p1`/`tier-p2` tags and sort by planned remediation date ([Step 3](exposure.md#step-3-in-use)), or by the `host-*` / `kind-*` / `group-*` tags |
| Which hosts stopped uploading? | `python3 -m vulnflow machines`, or the email report |
| Does a team have no SBOM at all yet? | `python3 -m vulnflow sync --dry-run` |
| How serious is CVE-X right now? | `python3 -m vulnflow enrich CVE-X` ([Look up a CVE](#look-up-a-cve)) |
| Where on disk is component X? | `python3 -m vulnflow where <name> [--version V]` |
| Where do most findings come from? | `python3 -m vulnflow stats [--team T] [--top N] [--json]`: per project kind, project, component, ecosystem and advisory source; findings DT knows are aliases count once |
| Why is one vulnerability listed twice (GHSA and PYSEC)? | It isn't any more: each `dt2dojo` round keeps one finding per alias group open and suppresses the rest with a "Duplicate of …" comment (`python3 -m vulnflow duplicates` shows what it would do). Unsuppress a duplicate, or triage any finding of the group, and vulnflow leaves that group to you |

Dependency-Track analyses new SBOMs within minutes; DefectDojo follows at the next
`dt2dojo` round (`python3 -m vulnflow dt2dojo` runs one now).

## In the terminal: `./poc.sh tui`

The same data without a browser, on the server (over ssh):

| Key | Does |
| --- | --- |
| `1`-`4` | tabs: Findings, Alerts (the receiver's log, newest first), Hosts (last SBOM upload), Updates (`check-updates`) |
| `j`/`k`, arrows, PgUp/PgDn | move |
| `/`, `t`, `s`, `p` | filter findings by text (CVE, component, project), team, minimum severity, tier (P1, P1-P2, P1-P3, all; threat and asset context, [Step 2](exposure.md#step-2-in-use)) |
| Enter | the finding: project, component, purl, description, KEV, where on disk |
| `/`, `t`, `p`, `e` (Alerts) | filter alerts by text (CVE, title, project, description), team, tier (P1, P1-P2, P1-P3, all), KEV only |
| `n` (Alerts) | show all logged changes, not only those that notified ([Which changes notify](concepts.md#which-changes-notify)); each line says why: `new`, `kev`, `worse`, `fol` (followed) or `log` (logged only) |
| Enter (Alerts) | the alert: title, tier and reasons, why it notified, products it matched, team and OpenCVE project, events, CVSS, EPSS, KEV, sightings, description, OpenCVE link (`OPENCVE_URL`) |
| `J`/`K` (in a finding or alert) | the next/previous one in the list |
| `J`/`K` (in the finding) | the next / previous finding in the current list; the list cursor follows |
| space | select several findings |
| `m` | mark the selected (or current) findings: Not Affected with a justification, False Positive, or an accepted risk with a review date; asks for a reason and a `y` first |
| `r`, `q` | reload, quit |

Marking writes the same Dependency-Track analysis as `ignore` (and to the same ledger, so
`unignore` takes it back), so it needs `DT_ADMIN_PASSWORD` in `.env`; without it the TUI is
read-only. A finding somebody else already triaged is left alone and stays in the list.

## Sysadmin: common tasks

### A P1/P2 alert arrives

1. Open the CVE in OpenCVE (team project `sysadm`). It is `to_evaluate`.
2. Does it affect us? `python3 -m vulnflow where <component>` and Dependency-Track's
   component search show where it is installed; for a product without an SBOM (firewall,
   switch, SaaS) you know from your own inventory.
3. Set the OpenCVE status (`analysis_in_progress`, `remediation_in_progress`,
   `not_applicable`, `risk_accepted`, `resolved`, …) and an assignee. The receiver only
   sets `to_evaluate` on a CVE that has no status, so yours stays.
4. If it is installed somewhere it shows up as a DefectDojo finding too; do the work there.

### A new finding on a Debian package

Most Debian findings are already fixed by a Debian backport (NVD only knows upstream
versions). Check before you patch:

```bash
python3 -m vulnflow debian --team sysadm --action fixed   # fixed in the installed version
python3 -m vulnflow debian --team sysadm --action update  # an apt upgrade fixes it
python3 -m vulnflow debian --team sysadm --action no-fix  # no fix in this release yet
```

`fixed` rows are false positives: clear them ([Fixed by a Debian
backport](#1-fixed-by-a-debian-backport)). `update` rows are real: `apt upgrade` on the host,
and the next agent run closes them. `no-fix` rows wait for Debian; accept the risk with a
review date if the urgency is low ([Accepted risks](#4-accepted-risks)).

### A host stopped uploading

The report or `python3 -m vulnflow machines` says `STALE` or `never pushed`. On the host:

```bash
systemctl status vulnflow-agent.timer vulnflow-agent.service   # Linux
journalctl -u vulnflow-agent.service -n 50
tail -50 ~/Library/Logs/vulnflow-agent.log                       # macOS
```

Usual causes: the host was off, syft is missing or failed (out of memory or `/tmp` space on
a large image), or the key was revoked (`agent-bundle` makes a new one). See
[What to expect](sboms.md#what-to-expect).

### After upgrading a host or an image

Nothing to do. The next agent run uploads the new versions; Not Affected and False Positive
decisions carry over to the new image tag, and the old tag is retired (its findings closed
in DefectDojo) at the first `dt2dojo` round after that run. `python3 -m vulnflow prune`
shows what the next round will do.

### A product without an SBOM

Appliances, firmware and SaaS are followed only in OpenCVE: add the vendor or product to the
team's subscriptions (`[subscriptions.sysadm]` in `machines.toml`), then
`python3 -m vulnflow sync`. `suggest-subscriptions` proposes products from what
Dependency-Track has seen.

## Developer: common tasks

### An SBOM per release

Run [`scripts/ci-sbom-upload.sh`](../scripts/ci-sbom-upload.sh) in the release pipeline
(see [SBOM of an app](sboms.md#sbom-of-an-app)); for a Forgejo repository, copy the example
workflow ([From Forgejo Actions](sboms.md#from-forgejo-actions)). Each release becomes its own project version
in Dependency-Track and its own test in DefectDojo; `prune` retires a version two days after
a newer one is uploaded and the old one no longer is.

### What to fix first

```bash
python3 -m vulnflow priorities --tier 2              # P1 and P2 findings, every team, with reasons
python3 -m vulnflow priorities --team sysadm --json  # one team, for scripts
```

The tier combines the threat (KEV, EPSS, CVSS) with the project's exposure and criticality
from `machines.toml` ([Exposure and criticality](exposure.md#step-2-in-use)).

### A finding in a dependency

```bash
python3 -m vulnflow patches --team dev          # which findings have a fixed release (DT's data)
python3 -m vulnflow patches --team dev --osv    # also ask osv.dev (sends package URLs out)
python3 -m vulnflow where requests --version 2.31.0   # which images or apps carry it
```

`patches` gives the fix for the installed branch (`recommended`). Bump the dependency, and
the next release's SBOM closes the finding. With Renovate or Dependabot in the repository,
the weekly `patches --osv` is the list of what their next merges will fix.

### The vulnerable code is never reached

If the vulnerable function is not used (a CLI-only feature of a library, a platform you do
not run), record it as Not Affected with the justification `CODE_NOT_REACHABLE`; see
[Investigated by hand](#3-investigated-by-hand). It carries over to the next release as long
as the component and the CVE stay the same.

### Accepting a risk for now

Affected, no fix yet, and you decide to live with it until a date: [Accepted
risks](#4-accepted-risks). It comes back by itself after the review date.

## False positives and known-OK findings

| Case | How you recognise it | What to do |
| --- | --- | --- |
| Fixed by a Debian backport | `debian --action fixed` lists it | [1](#1-fixed-by-a-debian-backport): `ignore`, Not Affected, `CODE_NOT_PRESENT` |
| Disputed or rejected CVE | `disputed` lists it with a reason | [2](#2-disputed-rejected-or-every-version-in-nvd): `ignore`, False Positive |
| NVD lists every version (`ANY-VERSION`) | `disputed` lists it; an old CVE on a current version | [2](#2-disputed-rejected-or-every-version-in-nvd), after checking it is really fixed |
| Wrong product matched | CVE is about another project with the same name (e.g. CVE-2014-125070 on the Rust crate `console`) | [3](#3-investigated-by-hand): False Positive with the reason |
| Version range misread | NVD's range excludes the installed version, but DT matched (e.g. a `3.0.0b9` bound) | [3](#3-investigated-by-hand): False Positive with the reason |
| Version unknown (`UNKNOWN`, Go pseudo-version) | every historic CVE of the package matches | fix the SBOM, not the finding: see [What to expect](sboms.md#what-to-expect); these findings close when the version is right |
| Code not present or never reached | you checked the code or the build | [3](#3-investigated-by-hand): Not Affected, `CODE_NOT_PRESENT` / `CODE_NOT_REACHABLE` |
| Ubuntu or Red Hat package already patched | `vendor --ubuntu` / `--redhat` says `fixed` | [1](#1-fixed-by-a-debian-backport), with the `vendor --json` file |
| Affected, but accepted for now | your decision | [4](#4-accepted-risks): Exploitable + Will Not Fix / Can Not Fix with `--review-by` |

Record every such decision in **Dependency-Track**, not in DefectDojo: `prune` carries it to
later versions of the same build and DefectDojo closes the finding at the next round. A
decision made only in DefectDojo stays with that one version.

`ignore` reads a review file (the JSON from `debian --json`, `disputed --json` or
`vendor --json`, edited down to the rows you agree with) and writes one analysis per row.
It needs `DT_ADMIN_PASSWORD` (in `.env` on the server). It skips findings that are already
marked, so rerunning a step only adds what is new; it applies every row in the file, so
read the file first; `unignore` takes any of it back. Without `--apply` it is a dry run.

### 1. Fixed by a Debian backport

NVD compares upstream version numbers, and Debian fixes in its own package versions, so a
package with the fix backported still matches NVD's range:

```bash
python3 -m vulnflow debian --action fixed --json > fixed.json     # read it, drop rows you disagree with
python3 -m vulnflow ignore --from fixed.json --justification CODE_NOT_PRESENT            # dry run
python3 -m vulnflow ignore --from fixed.json --justification CODE_NOT_PRESENT --apply
```

Each analysis says which Debian version fixed it and which is installed. Ubuntu and Red Hat
packages work the same way with `vendor --ubuntu --action fixed --json` or
`vendor --redhat …` (they send the CVE ids to ubuntu.com or access.redhat.com).

### 2. Disputed, rejected, or "every version" in NVD

The supplier says it is not a vulnerability, the CVE was withdrawn, or (`ANY-VERSION`) NVD's
record lists the product with version `*` and no version range, so every version ever made
matches: an old CVE (more than 2 years, `--any-version-years`) on a current version is NVD's
data error. Seen: 72 Safari CVEs from 2005-2012 matching Safari 27.2 on every Mac, 144
findings on two laptops. Check each reason (the `NOTE:` text, or product and dates) before
agreeing.

`ANY-VERSION` is a list to review, not a verdict: an old CVE nobody ever fixed is real too
(2026-11-24: `rsa` 0.9.x and CVE-2023-49092, the Marvin attack, which RustCrypto has not
fixed). Delete those rows from the file before `ignore`. Safari's version changes with every
macOS update, so these come back as new findings on the new version; rerunning this step
marks them again:

```bash
python3 -m vulnflow disputed --json > disputed.json
python3 -m vulnflow ignore --from disputed.json --state FALSE_POSITIVE            # dry run, then --apply
```

### 3. Investigated by hand

A wrong product, a misread version range, code that is not in the build or never reached:
nothing generates these, you found them.

- **One or two findings:** in Dependency-Track's UI, open the project, Audit
  Vulnerabilities, the finding, and set the Analysis (state, justification, a comment saying
  why) and Suppress. `prune` carries it to later versions like any other decision.
- **Many:** take the rows for those findings from a `debian`, `disputed` or `vendor`
  `--json` file (they carry the UUIDs `ignore` needs), set `reason` on each, and run
  `ignore` with the matching state and justification:

```bash
python3 -m vulnflow ignore --from wrong-product.json --state FALSE_POSITIVE   # dry run, then --apply
python3 -m vulnflow ignore --from unused.json --justification CODE_NOT_REACHABLE
```

Justifications: `CODE_NOT_PRESENT` (the fix is in, or the vulnerable part is not compiled
in), `CODE_NOT_REACHABLE` (the code is there but never runs with outside input),
`REQUIRES_CONFIGURATION`, `REQUIRES_DEPENDENCY`, `REQUIRES_ENVIRONMENT`,
`PROTECTED_BY_COMPILER`, `PROTECTED_AT_RUNTIME`, `PROTECTED_AT_PERIMETER`,
`PROTECTED_BY_MITIGATING_CONTROL`. Examples seen on this estate (2026-11-24): CVE-2014-125070
on the Rust crate `console` (another project), CVE-2018-17175 on `marshmallow` 3.2x
(Dependency-Track misreads the `3.0.0b9` bound), CVE-2022-48833 on kernel 7.3.6 (only 5.x
ranges), ffmpeg CVE-2025-25468/25469 (the bound is a git date).

### 4. Accepted risks

It is affected, and you decide to live with it for now (e.g. a `debian --action no-fix` row
Debian calls minor). Record it in Dependency-Track with a review date, so it carries over to
new versions and comes back by itself:

```bash
python3 -m vulnflow ignore --from accept.json --state EXPLOITABLE --response WILL_NOT_FIX \
    --review-by 2027-03-01            # dry run, then --apply; CAN_NOT_FIX when there is no fix
```

The finding is suppressed (gone from the lists and DefectDojo) until the review date; the
first `dt2dojo` round after it lifts the suppression and it shows up again, with a comment
saying why. `--review-by` works with the other states too, for a Not Affected you want to
look at again. In the UI, writing `review by 2027-03-01` in the analysis comment does the
same.

Not for `ignore`: `debian --action update` and `patches --osv` list real fixes (update the
image or package instead).

### Undo

```bash
python3 -m vulnflow unignore                 # dry run: everything vulnflow marked
python3 -m vulnflow unignore --from fp.json --apply   # only these rows
```

`unignore` restores the analysis each finding had before, but only where the finding is still
as vulnflow left it: a decision somebody made since stays. One finding at a time is also fine
in Dependency-Track's UI (Audit Vulnerabilities, the finding, Analysis).

## Recommended routine

| When | What |
| --- | --- |
| Automatically | Agents upload daily; `dt2dojo` (every 30 min) runs `prune` first, then copies to DefectDojo; the [email reports](#email-reports) arrive daily (when something needs action) and every Monday |
| Weekly | [False positives](#false-positives-and-known-ok-findings) 1-2. `debian --action update` and `patches --osv`: what an image/package update would fix, input for the next Renovate merge. `python3 -m vulnflow machines`: hosts that stopped pushing (more than `--stale-days`, 2) |
| After an image update | Nothing: decisions carry over to the new tag, and the old tag is retired at the first `dt2dojo` round after the host's next agent run (2 days after its last upload if the host has no `host:` project). `python3 -m vulnflow prune` shows what the next round will do |
| Monthly | `python3 -m vulnflow unignore` (dry run): what vulnflow has marked, and what somebody changed since (`--apply --forget-changed` drops those from the ledger). `debian --action no-fix`: anything new to accept ([Accepted risks](#4-accepted-risks)) or that Debian has fixed since? `sync --dry-run`: teams without SBOMs |

## Email reports

Two digests, mailed by the server's own mail setup (`sendmail`: postfix, msmtp-mta,
nullmailer, whatever already delivers its cron mail). vulnflow holds no SMTP credentials.

Each mail has a Markdown text part and an HTML part with the same tables; mail clients
show the one they can.

| Report | When | Sent | Contents |
| --- | --- | --- | --- |
| daily | 06:30 | only when something needs action | upstream updates to deploy, new P1/P2 alerts from OpenCVE, new CISA KEV entries that hit a finding or a followed vendor, new critical/high/KEV findings in Dependency-Track, hosts that stopped pushing |
| weekly | Monday 06:45 | always | the same, plus all of the week's new and resolved findings, open findings per team and severity, accepted risks (`eol`/`certified` projects and their review dates), vendor systems (open findings and how long the oldest has waited), projects without asset context, every upstream version |

Set the recipient and install the timers once, as the user that runs `./poc.sh`:

```bash
python3 -m vulnflow env-set <<<'VULNFLOW_REPORT_TO=you@example.org'
./poc.sh schedule install    # systemd timers from deploy/timers/ (sudo); remove | status
./poc.sh report weekly       # send one now
./poc.sh report daily --always   # a daily even when there is nothing to act on
```

New findings are listed internet-facing or exploited first, then those on a `critical`
asset, then the rest, and each has a **Projects** column: how many projects have that
component version open with the same vulnerability, and how many are `critical`
([Step 6 in use](exposure.md#step-6-in-use)).

Each finding listed in a report has a **Where** column: up to three paths on disk (syft's
locations, as `vulnflow where` shows them) and links to the CVE in DefectDojo (its search,
`DD_SITE_URL`) and to the component in Dependency-Track (the UI on `DT_PUBLIC_API_URL`'s
host and `DT_UI_PORT`, or `DT_PUBLIC_UI_URL`). In the HTML part they are clickable; they
point only at your own servers.

The alerts and the new KEV entries carry the same information as the chat messages: the
CVE's title, the products it matched and why it notified (new, added to KEV, more serious,
followed), and for a KEV entry the findings and teams it hits. A KEV entry that hits nothing
of ours is listed but doesn't make a quiet daily go out. The mail has no links, so the
OpenCVE link from chat is not there; the CVE ID is.

"New" is since the last report of the same kind, so the weekly covers the whole week. The
first run of each kind records a baseline and lists no changes. A finding is the same finding
on a new image tag or package version, so an upgrade that keeps a CVE does not report it
again; findings that were suppressed (`ignore`) count as resolved. The state is in
`data/report-state.json`. `python3 -m vulnflow report daily --no-save` previews a report
without recording it, and without `VULNFLOW_REPORT_TO` `./poc.sh report` prints instead of
mailing. The daily report includes `check-updates`, so a separate nightly `check-updates` is
no longer needed.

## Newsletters

A per-team OSINT newsletter (`vulnflow/news.py`): security news that concerns what each team
runs, with links and why each item matched. No generated summaries.

| Mode | When | Content |
| --- | --- | --- |
| `weekly` | Monday 07:15 | everything new that matches the team, plus its notified alerts, new KEV entries that hit it and accepted risks to review within 14 days |
| `daily` | 07:00, only when there is something | only urgent items: the team's own systems, exploited (CISA KEV) or a public exploit |
| `alert <id>` | by hand | everything known about one CVE, GHSA id or keyword, now, to the teams it concerns |

```bash
./poc.sh newsletter weekly --dry-run         # print it, mark nothing as sent
./poc.sh newsletter alert CVE-2026-1001      # to the teams it concerns
./poc.sh newsletter alert fortios --team network
./poc.sh schedule install                    # the daily and weekly timers, with the reports
```

Feeds and addresses are in `machines.toml` (see `machines.example.toml`): `[news.feeds.<name>]`
with `url`, `kind` (`advisory`, `cert`, `exploit` or `news`) and optionally `teams` (a vendor's
PSIRT feed goes whole to the team that runs the product); `[news.teams.<team>]` with `to`
and extra `keywords`. A team without `to` goes into one mail to `VULNFLOW_REPORT_TO`.

An item matches a team when it names a CVE or GHSA id that is open in the team's
Dependency-Track findings or was alerted to it, or one of its keywords as a whole word: the
vendors and products it follows in OpenCVE, the names of the vulnerable components in its
projects, and its own keywords. Items about the same CVE become one entry with all links.
Order: the team's own systems first, then exploited or public exploit, then the rest.

Feeds are downloaded whole and filtered on the server: nothing is ever searched for per
keyword, product or CVE, so no feed host learns what a team runs. `alert <id>` only uses
what is already there (the feeds, Dependency-Track, the cached KEV catalog). What was sent
is recorded per mode in `data/news-seen.json` (90 days), so nothing is sent twice.

## Look up a CVE

Ad-hoc look-up of any CVE with the same priority logic:

```bash
$ python3 -m vulnflow enrich CVE-2021-44228 CVE-2025-0001
CVE-2021-44228: P1 Act | KEV=yes EPSS=1.0000 (p100) sightings={'exploited': 1424, ...} | in CISA KEV (ransomware use); ...
CVE-2025-0001: P4 Watch | KEV=no EPSS=0.0056 (p47) sightings={'published-proof-of-concept': 3, 'seen': 10} | no CVSS (likely unenriched in NVD ...)
```

(Real output from 2026-11-19.)

## Updates

`./poc.sh check-updates` (also part of the daily [email report](#email-reports)) compares, for
DefectDojo, OpenCVE, Dependency-Track and DefectDojo's Valkey, the newest upstream GitHub
release that is at least 7 days old, the version pinned in the repository
(`DD_REF`/`OPENCVE_REF` in `.env.example`, the image tags in
`stacks/dependency-track/docker-compose.yml`, the valkey image in
`stacks/defectdojo/override.yml`) and the running one:

```text
DefectDojo: running 3.5.200, pinned 3.5.201
  UPDATE 3.5.202 released 2026-11-20: bump DD_REF in .env.example after the AGENTS.md checks
  READY  3.5.201 is pinned: ./poc.sh upgrade dojo
  new    3.5.300 (cooldown until 2026-12-01)
```

- **UPDATE**: bump the pin in the repository (Dependency-Track: Dependabot opens the PR).
- **Valkey** is pinned in the DefectDojo overlay ahead of `DD_REF` and bumped by hand (tag
  and digest; Dependabot doesn't read that file). Its release notes say `Upgrade urgency
  SECURITY` when the cooldown is worth skipping. READY means `./poc.sh dojo-up`: Valkey
  only holds DefectDojo's Celery queue and cache.
- **READY**: on the server, `git pull` and `./poc.sh upgrade dojo|opencve|dtrack`. It dumps
  that stack's databases to `data/backups/` (newest 5 kept), sets the version in `.env` and
  reruns the stack's setup steps (clone/checkout, build, migrations on start, bootstrap).
  `./poc.sh upgrade dojo 3.5.202 --now` takes a version that is not the reviewed pin.
