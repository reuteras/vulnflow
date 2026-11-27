"""New P1/P2 Dependency-Track findings -> chat, P1 on critical assets -> paging.

docs/exposure.md, step 4. Each `dt2dojo` round ranks every open finding for DefectDojo's
tiers (dojo_tiers.py); this takes those verdicts and tells people once per finding:

- **team channel** (VULNFLOW_CHAT_WEBHOOK): new findings at or above `[priority]
  chat_min_tier` (P2 by default), one message per team, mentioning it;
- **SOC channel** (VULNFLOW_SOC_WEBHOOK): new findings at or above VULNFLOW_SOC_MIN_TIER
  (P1 by default), every team, the team named in each line;
- **paging** (VULNFLOW_PAGE_WEBHOOK): new P1 findings on a `critical` asset
  (`criticality = "critical"` in machines.toml, or the `crit-critical` tag). JSON
  {"text": ...} by default; VULNFLOW_PAGE_FORMAT=text posts the message as a plain body
  with ntfy's Title/Priority headers.

Lines look like the receiver's alerts: tier, id and title, then why (new, or more
serious), where, CVSS, EPSS and the reasons. OpenCVE alerts are not paged: an alert is
about a product a team follows, not an asset, so it pages once Dependency-Track has the
finding on a critical asset.

"Once" is per finding and channel, kept in `findings-notified.json`: the key is project
name, component and vulnerability (not the project version, so a new release doesn't
notify again). A finding notifies again in a channel when its tier rises (P2 -> P1 pages).
A channel is marked only after its message was delivered, so a failed delivery is retried
next round without repeating the others. An entry not seen at P1/P2 for 30 days is
dropped, so a finding that comes back later is new again. The first run records what is
there without posting it, and so does a channel without a webhook, so setting one up later
posts only what is new from then on. An unreadable state file counts as a first run (logged),
so it can't stop dt2dojo's imports.

Noisy products ([chat.<name>] in machines.toml, as in the receiver): a finding whose
component CPE matches goes to that channel (VULNFLOW_CHAT_WEBHOOK_<NAME>) instead of the
team's, one line per vulnerability naming every host and team it is on. Without the
channel's webhook it stays in the team channel. The team and [chat.*] channels share their
record, so moving a product into a channel (or out of one) doesn't announce it again.
"""

from __future__ import annotations

import json
import logging
import time
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .config import ChatChannel, Inventory, cpe_vendor_product
from .net import Http
from .ranking import Ranked

STATE_FILE = "findings-notified.json"
EXPIRE_SECONDS = 30 * 86400
MAX_LINES = 20  # findings shown per message; the rest are counted
CHANNELS = ("team", "soc", "page")
CHAT_PREFIX = "chat:"  # a [chat.<name>] channel's key in the state: "chat:<name>"

log = logging.getLogger(__name__)

Sender = Callable[[str], None]


def page_sender(url: str, fmt: str = "json") -> Sender:
    """POST to the paging webhook: {"text": ...} (Mattermost/Slack style, or a paging tool's
    generic webhook), or the message as a plain body ("text": ntfy)."""
    http = Http(url, timeout=15)

    def send(text: str) -> None:
        if fmt == "text":
            headers = {
                "Content-Type": "text/plain; charset=utf-8",
                "Title": "vulnflow: P1 on a critical asset",
                "Priority": "urgent",
            }
            http.post("", body=text.encode(), headers=headers)
        else:
            http.post("", json_body={"text": text})

    return send


def key(r: Ranked) -> str:
    return f"{r.project}|{r.component}|{r.vuln_id}"


@dataclass
class Notice:
    finding: Ranked
    was: int | None  # the tier notified before in this channel, None = new

    @property
    def why(self) -> str:
        if self.was is None:
            return "new finding"
        return f"more serious (was P{self.was})"


@dataclass
class WatchResult:
    baseline: dict[str, int] = field(default_factory=dict)  # channel -> findings recorded
    sent: dict[str, list[Notice]] = field(default_factory=dict)  # channel -> notices posted
    errors: list[str] = field(default_factory=list)


def _line(n: Notice, opencve_url: str, team: bool, also: list[Notice] | None = None) -> str:
    """One finding; with `also`, the same vulnerability elsewhere, named in the same line."""
    r = n.finding
    group = [n, *(also or [])]
    where = ", ".join(sorted({x.finding.where for x in group}))
    teams = sorted({x.finding.team for x in group})
    epss = f"{r.epss:.3f}" if r.epss is not None else "n/a"
    cvss = r.cvss if r.cvss is not None else "n/a"
    link = ""
    if opencve_url and r.vuln_id.upper().startswith("CVE-"):
        link = f" {opencve_url.rstrip('/')}/cve/{r.vuln_id.upper()}"
    crit = f", {r.criticality} asset" if r.criticality else ""
    named = f", team{'s' if len(teams) > 1 else ''} {', '.join(teams)}" if team else ""
    return (
        f"- [{r.tier_name}] {r.vuln_id}: {r.title or r.severity}\n"
        f"  {n.why}: {r.component} {r.version} in {where}{crit}{named}, CVSS {cvss}, "
        f"EPSS {epss}: {'; '.join(r.reasons)}{link}"
    )


def _message(head: str, notices: list[Notice], opencve_url: str, team: bool) -> str:
    lines = [head, *(_line(n, opencve_url, team) for n in notices[:MAX_LINES])]
    if len(notices) > MAX_LINES:
        lines.append(f"(+{len(notices) - MAX_LINES} more; DefectDojo tags tier-p1/tier-p2)")
    return "\n".join(lines)


def _grouped_message(head: str, notices: list[Notice], opencve_url: str) -> str:
    """A [chat.*] channel's message: one line per vulnerability and component version,
    naming every host and team it is on."""
    groups: dict[tuple[str, str, str], list[Notice]] = {}
    for n in notices:
        r = n.finding
        groups.setdefault((r.vuln_id, r.component, r.version), []).append(n)
    lines = [f"{head}: {len(groups)} new finding(s) in Dependency-Track"]
    lines += [_line(g[0], opencve_url, True, g[1:]) for g in list(groups.values())[:MAX_LINES]]
    if len(groups) > MAX_LINES:
        lines.append(f"(+{len(groups) - MAX_LINES} more; DefectDojo tags tier-p1/tier-p2)")
    return "\n".join(lines)


def messages(
    channel: str, notices: list[Notice], inv: Inventory, opencve_url: str = ""
) -> list[tuple[str, list[Notice]]]:
    """(text, the notices it carries) for one channel."""
    if not notices:
        return []
    if channel == "team":
        out = []
        for t in sorted({n.finding.team for n in notices}):
            mine = [n for n in notices if n.finding.team == t]
            team = inv.teams.get(t)
            mention = f"{team.chat_mention} " if team and team.chat_mention else ""
            head = f"{mention}{len(mine)} new finding(s) to act on for team {t}"
            out.append((_message(head, mine, opencve_url, False), mine))
        return out
    if channel.startswith(CHAT_PREFIX):
        head = f"#{channel.removeprefix(CHAT_PREFIX)}"
        return [(_grouped_message(head, notices, opencve_url), notices)]
    if channel == "soc":
        head = f"SOC: {len(notices)} new finding(s) in Dependency-Track"
        return [(_message(head, notices, opencve_url, True), notices)]
    head = f"PAGE: {len(notices)} P1 finding(s) on critical assets"
    return [(_message(head, notices, opencve_url, True), notices)]


def chat_channel_for(r: Ranked, channels: list[ChatChannel]) -> ChatChannel | None:
    """The first [chat.*] channel (machines.toml order) whose match covers the finding's
    component CPE; None = the team channel."""
    vp = cpe_vendor_product(r.cpe)
    if vp is None:
        return None
    return next((c for c in channels if c.matches(*vp)), None)


def wanted(
    channel: str,
    r: Ranked,
    chat_min_tier: int,
    soc_min_tier: int,
    routed: ChatChannel | None = None,
) -> bool:
    """routed: the [chat.*] channel that takes this finding instead of the team's."""
    if channel == "team":
        return routed is None and r.tier <= chat_min_tier
    if channel.startswith(CHAT_PREFIX):
        if routed is None or channel != CHAT_PREFIX + routed.name:
            return False
        return r.tier <= (routed.min_tier or chat_min_tier)
    if channel == "soc":
        return r.tier <= soc_min_tier
    return r.tier == 1 and r.criticality == "critical"


def _chat_record(entry: dict[str, Any]) -> int | None:
    """The most serious tier announced in the team channel or any [chat.*] channel: they
    share it, so moving a product between them doesn't announce it again."""
    tiers = [int(t) for c, t in entry.items() if c == "team" or c.startswith(CHAT_PREFIX)]
    return min(tiers) if tiers else None


def load_state(path: Path) -> dict[str, dict[str, Any]] | None:
    """The record, or None for a first run: no file yet, or one that can't be read (logged;
    a broken record must not stop dt2dojo, and a first run posts nothing)."""
    if not path.is_file():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            raise ValueError("not a JSON object")
        return {
            str(k): {str(c): float(t) if c == "seen" else int(t) for c, t in v.items()}
            for k, v in data.items()
            if isinstance(v, dict)
        }
    except (OSError, ValueError, TypeError, AttributeError) as e:
        log.warning("%s unreadable (%s): recording what is open, posting nothing", path, e)
        return None


def save_state(path: Path, state: dict[str, dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(state, indent=1, sort_keys=True) + "\n", encoding="utf-8")
    tmp.replace(path)


def watch(
    inv: Inventory,
    ranked: Iterable[Ranked],
    state_path: Path,
    senders: dict[str, Sender | None],
    *,
    soc_min_tier: int = 1,
    opencve_url: str = "",
    now: float | None = None,
    dry_run: bool = False,
    channels: list[ChatChannel] | None = None,
) -> WatchResult:
    """One round: what is new per channel since the last one, posted and recorded.
    senders: "team", "soc", "page" and "chat:<name>" per [chat.*] channel; a [chat.*]
    channel without a sender leaves its findings in the team channel."""
    res = WatchResult()
    now = time.time() if now is None else now
    chat_min = inv.rules.chat_min_tier
    active = [c for c in channels or [] if senders.get(CHAT_PREFIX + c.name)]
    loaded = load_state(state_path)
    state = loaded or {}
    first_run = loaded is None
    # one entry per finding: the most serious if a project has it twice (two versions)
    best: dict[str, Ranked] = {}
    for r in ranked:
        k = key(r)
        if k not in best or r.tier < best[k].tier:
            best[k] = r
    routed = {k: chat_channel_for(r, active) for k, r in best.items()}
    limit = max(chat_min, soc_min_tier, 1, *(c.min_tier or 0 for c in active))
    for k, r in best.items():
        if r.tier <= limit:
            state.setdefault(k, {})["seen"] = now
    order = ["team", *(CHAT_PREFIX + c.name for c in active), "soc", "page"]
    for channel in order:
        send = senders.get(channel)
        shared = channel == "team" or channel.startswith(CHAT_PREFIX)
        notices = []
        for k, r in sorted(best.items(), key=lambda kv: (kv[1].tier, kv[1].team, kv[0])):
            if not wanted(channel, r, chat_min, soc_min_tier, routed[k]):
                continue
            entry = state.get(k, {})
            was = _chat_record(entry) if shared else entry.get(channel)
            if was is None or r.tier < int(was):
                notices.append(Notice(r, None if was is None else int(was)))
        if not notices:
            continue
        # nothing posted on the first run, or into a channel that has no webhook (setting
        # one up later must not post every open finding at once)
        if first_run or send is None:
            res.baseline[channel] = len(notices)
            for n in notices:
                state[key(n.finding)][channel] = n.finding.tier
            continue
        if dry_run:
            res.sent[channel] = notices
            continue
        for text, carried in messages(channel, notices, inv, opencve_url):
            try:
                send(text)
            except Exception as e:
                res.errors.append(f"{channel} delivery failed: {e}")
                continue
            res.sent.setdefault(channel, []).extend(carried)
            for n in carried:
                state[key(n.finding)][channel] = n.finding.tier
    for k in [k for k, v in state.items() if now - float(v.get("seen", 0)) > EXPIRE_SECONDS]:
        del state[k]
    if not dry_run:
        try:
            save_state(state_path, state)
        except OSError as e:  # posted but not recorded: may post again next round
            res.errors.append(f"could not save {state_path}: {e}")
    return res
