# Daily usage

[Back to the README](../README.md). Where to look, how to clear known-OK findings, what
to run when, and keeping the stacks up to date.

## See the results

- **Dependency-Track:** projects `host:...` (tag `team-sysadm`) and `myapp` (tag
  `team-dev`) with their components and vulnerabilities, once analysis is done.
- **DefectDojo:** `dt2dojo` copies DT findings every 30 minutes into one product per DT
  project, under the team's product type. To run it now:
  `python3 -m vulnflow dt2dojo`.
- **OpenCVE:** projects `sysadm` and `dev` list the CVEs matching their subscriptions;
  new or changed ones are sent to the receiver by the `vulnflow` automation.
- **Coverage check:** `python3 -m vulnflow sync --dry-run` warns about teams with no SBOM
  in DT yet.

## Smoke-test the alert path

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

## Day to day

- **Sysadmin:** triage new CVEs in OpenCVE project `sysadm` (status, assignee), then
  handle the Debian-package findings in DefectDojo. Rerun the host SBOM after upgrades
  (from cron or config management).
- **Dev:** upload an SBOM per release from CI; triage findings for `myapp` in DefectDojo
  (or with VEX/analysis in DT, which carries over).
- **Both:** P1/P2 alerts arrive in chat (when configured) and are marked `to_evaluate` in
  OpenCVE, but only if nobody has triaged them yet.

### Clearing known-OK findings

Mark each one once: `prune` (every `dt2dojo` round) copies the decision to later versions of
the same build, and the next round closes the finding in DefectDojo. `ignore` skips findings
that are already marked, so rerunning a step only adds what is new. It applies every row in
the file, so read the file first; `unignore` takes any of it back.

1. **Already fixed by Debian.** NVD compares upstream version numbers, and Debian fixes in
   its own package versions:

   ```bash
   python3 -m vulnflow debian --action fixed --json > fixed.json     # read it, drop rows you disagree with
   python3 -m vulnflow ignore --from fixed.json --justification CODE_NOT_PRESENT            # dry run
   python3 -m vulnflow ignore --from fixed.json --justification CODE_NOT_PRESENT --apply
   ```

   Each analysis says which Debian version fixed it and which is installed.

2. **Disputed, rejected, or "every version" in NVD.** The supplier says it is not a
   vulnerability, the CVE was withdrawn, or (`ANY-VERSION`) NVD's record lists the product
   with version `*` and no version range, so every version ever made matches: an old CVE
   (more than 2 years, `--any-version-years`) on a current version is NVD's data error. Seen:
   72 Safari CVEs from 2005-2012 matching Safari 27.2 on every Mac, 144 findings on two
   laptops. Check each reason (the `NOTE:` text, or product and dates) before agreeing.
   `ANY-VERSION` is a list to review, not a verdict: an old CVE nobody ever fixed is real
   too (2026-11-24: `rsa` 0.9.x and CVE-2023-49092, the Marvin attack, which RustCrypto has
   not fixed). Delete those rows from the file before `ignore`.
   Safari's version changes with every macOS update, so these come back as new findings on
   the new version; rerunning this step marks them again:

   ```bash
   python3 -m vulnflow disputed --json > disputed.json
   python3 -m vulnflow ignore --from disputed.json --state FALSE_POSITIVE            # dry run, then --apply
   ```

3. **Anything else you investigated by hand** (e.g. a `pkg:generic/...` binary on a
   distribution none of the tools cover): write the rows with a `reason`, in the same JSON
   shape, and run `ignore` with the matching `--justification` (`CODE_NOT_PRESENT` when the
   fix is in, `CODE_NOT_REACHABLE` when the code is never run with outside input).

4. **Accepted risks** (it is affected, and you decide to live with it for now, e.g. a
   `debian --action no-fix` row Debian calls minor): record it in Dependency-Track with a
   review date, so it carries over to new versions and comes back by itself:

   ```bash
   python3 -m vulnflow ignore --from accept.json --state EXPLOITABLE --response WILL_NOT_FIX \
       --review-by 2027-03-01            # dry run, then --apply; CAN_NOT_FIX when there is no fix
   ```

   The finding is suppressed (gone from the lists and DefectDojo) until the review date; the
   first `dt2dojo` round after it lifts the suppression and it shows up again, with a
   comment saying why. `--review-by` works with the other states too, for a Not Affected
   you want to look at again.

Not for `ignore`: `debian --action update` and `patches --osv` list real fixes (update the
image or package instead).

### Recommended routine

| When | What |
| --- | --- |
| Automatically | Agents upload daily; `dt2dojo` (every 30 min) runs `prune` first, then copies to DefectDojo; the [email reports](#email-reports) arrive daily (when something needs action) and every Monday |
| Weekly | Steps 1-2 of [Clearing known-OK findings](#clearing-known-ok-findings). `debian --action update` and `patches --osv`: what an image/package update would fix, input for the next Renovate merge. `python3 -m vulnflow machines`: hosts that stopped pushing (more than `--stale-days`, 2) |
| After an image update | Nothing: decisions carry over to the new tag, and the old tag is retired at the first `dt2dojo` round after the host's next agent run (2 days after its last upload if the host has no `host:` project). `python3 -m vulnflow prune` shows what the next round will do |
| Monthly | `python3 -m vulnflow unignore` (dry run): what vulnflow has marked, and what somebody changed since (`--apply --forget-changed` drops those from the ledger). `debian --action no-fix`: anything new to accept (step 4) or that Debian has fixed since? `sync --dry-run`: teams without SBOMs |

## Email reports

Two digests, mailed by the server's own mail setup (`sendmail`: postfix, msmtp-mta,
nullmailer, whatever already delivers its cron mail). vulnflow holds no SMTP credentials.

| Report | When | Sent | Contents |
| --- | --- | --- | --- |
| daily | 06:30 | only when something needs action | upstream updates to deploy, new P1/P2 alerts from OpenCVE, new critical/high/KEV findings in Dependency-Track, hosts that stopped pushing |
| weekly | Monday 06:45 | always | the same, plus all of the week's new and resolved findings, open findings per team and severity, every upstream version |

Set the recipient and install the timers once, as the user that runs `./poc.sh`:

```bash
python3 -m vulnflow env-set <<<'VULNFLOW_REPORT_TO=you@example.org'
./poc.sh schedule install    # systemd timers from deploy/timers/ (sudo); remove | status
./poc.sh report weekly       # send one now
```

"New" is since the last report of the same kind, so the weekly covers the whole week. The
first run of each kind records a baseline and lists no changes. A finding is the same finding
on a new image tag or package version, so an upgrade that keeps a CVE does not report it
again; findings that were suppressed (`ignore`) count as resolved. The state is in
`data/report-state.json`. `python3 -m vulnflow report daily --no-save` previews a report
without recording it, and without `VULNFLOW_REPORT_TO` `./poc.sh report` prints instead of
mailing. The daily report includes `check-updates`, so a separate nightly `check-updates` is
no longer needed.

## Look up a CVE

Ad-hoc look-up of any CVE with the same priority logic:

```bash
$ python3 -m vulnflow enrich CVE-2021-44228 CVE-2025-0001
CVE-2021-44228: P1 Act | KEV=yes EPSS=1.0000 (p100) sightings={'exploited': 1424, ...} | in CISA KEV (ransomware use); ...
CVE-2025-0001: P4 Watch | KEV=no EPSS=0.0056 (p47) sightings={'published-proof-of-concept': 3, 'seen': 10} | no CVSS (likely unenriched in NVD ...)
```

(Real output from 2026-11-19.)

## Updates

`./poc.sh check-updates` (run nightly on the server, output in the cron mail) compares, for
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
