"""Configuration: .env file + environment variables + inventory.toml + machines.toml."""

from __future__ import annotations

import os
import re
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


def load_dotenv(path: str | Path = ".env") -> None:
    """Load KEY=VALUE lines into os.environ without overriding existing vars."""
    p = Path(path)
    if not p.is_file():
        return
    for raw in p.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        value = value.strip().strip('"').strip("'")
        os.environ.setdefault(key.strip(), value)


def env(name: str, default: str | None = None, *, required: bool = False) -> str:
    val = os.environ.get(name, default)
    if required and not val:
        raise SystemExit(f"Missing required setting {name} (set it in .env)")
    return val or ""


def env_flag(name: str, default: bool = True) -> bool:
    val = os.environ.get(name)
    if val is None or val == "":
        return default
    return val.strip().lower() in {"1", "true", "yes", "on"}


@dataclass
class Team:
    key: str
    display_name: str
    opencve_project: str
    defectdojo_product_type: str
    dtrack_tag: str
    chat_mention: str = ""
    vendors: list[str] = field(default_factory=list)
    products: dict[str, list[str]] = field(default_factory=dict)


@dataclass
class PriorityRules:
    epss_attend: float = 0.10
    epss_floor: float = 0.01
    cvss_critical: float = 9.0
    cvss_high: float = 7.0
    chat_min_tier: int = 2
    ignore_event_types: list[str] = field(default_factory=list)
    # Changes that never notify on their own, even for a followed CVE: OpenCVE's generated
    # titles come and go, descriptions and references get edited. Still logged.
    quiet_event_types: list[str] = field(
        default_factory=lambda: ["title", "description", "references", "weaknesses"]
    )
    # days from a finding's date to its planned remediation date in DefectDojo, per tier;
    # a tier left out (P4 by default) gets none
    sla_days: dict[str, int] = field(default_factory=lambda: {"p1": 7, "p2": 30, "p3": 90})


MACHINE_KINDS = ("linux", "macos")
SCANS = ("system", "brew", "languages", "apps", "containers")
DEFAULT_SCANS = {"linux": ("system",), "macos": ("brew", "languages", "apps")}
_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
_CPE_PAIR_RE = re.compile(r"^[a-z0-9._-]+:[a-z0-9._-]+$")
_CPE_PART_RE = re.compile(r"^[a-z0-9][a-z0-9._~+-]*$")  # an OpenCVE/NVD vendor or product
# settings a [groups.*] entry gives its hosts and a [hosts.*] entry can override
_MACHINE_KEYS = {"team", "kind", "scans", "language_paths", "containers_team"}

# Asset context (docs/exposure.md): set on what runs (a host, an image on a host, code, a
# GitHub repository, a named project), never on a group, because one group can run a
# public service and an internal admin page. Unset stays unknown: no default is guessed.
EXPOSURES = ("internet", "external-auth", "internal", "restricted", "hostile-device")
INPUTS = ("public", "partner", "staff")
CRITICALITIES = ("critical", "high", "normal", "low")
CONTEXT_KEYS = {"exposure", "input", "criticality", "eol", "certified"}


@dataclass(frozen=True)
class AssetContext:
    exposure: str = ""
    input: str = ""
    criticality: str = ""
    eol: bool = False
    certified: bool = False

    def __bool__(self) -> bool:
        """False when nothing is set: the asset's context is unknown."""
        return bool(self.exposure or self.input or self.criticality or self.eol or self.certified)

    def tags(self) -> list[str]:
        """Dependency-Track project tags; unknown values get none."""
        out = []
        if self.exposure:
            out.append(f"exposure-{self.exposure}")
        if self.input:
            out.append(f"input-{self.input}")
        if self.criticality:
            out.append(f"crit-{self.criticality}")
        out += ["flag-eol"] * self.eol + ["flag-certified"] * self.certified
        return out


def _context(settings: dict[str, Any], where: str) -> AssetContext:
    for key, allowed in (("exposure", EXPOSURES), ("input", INPUTS), ("criticality", CRITICALITIES)):
        v = settings.get(key, "")
        if v and v not in allowed:
            raise SystemExit(f"{where}: {key} must be one of {allowed}, got {v!r}")
    for key in ("eol", "certified"):
        if not isinstance(settings.get(key, False), bool):
            raise SystemExit(f"{where}: {key} must be true or false")
    return AssetContext(
        exposure=str(settings.get("exposure", "")),
        input=str(settings.get("input", "")),
        criticality=str(settings.get("criticality", "")),
        eol=bool(settings.get("eol", False)),
        certified=bool(settings.get("certified", False)),
    )


@dataclass
class Machine:
    """A machine that pushes its own SBOMs with scripts/vulnflow-agent.py."""

    name: str
    team: str
    kind: str  # "linux" or "macos"
    group: str = ""  # the [groups.*] entry it belongs to, if any
    scans: list[str] = field(default_factory=list)
    language_paths: list[str] = field(default_factory=list)  # relative to $HOME
    version: str = ""  # DT project version; empty = the agent probes the OS
    containers_team: str = "dev"  # owner of the container-image projects of the `containers` scan
    context: AssetContext = AssetContext()  # of the host project (host:<name>)
    # per image name (or glob) running on it: the container projects' context
    images: dict[str, AssetContext] = field(default_factory=dict)
    # per package name (or glob) in the host project: overrides the host's context when
    # ranking that package's findings (nginx and openssh face the internet, acl doesn't)
    packages: dict[str, AssetContext] = field(default_factory=dict)


@dataclass
class CodeTarget:
    """A directory with application code (and its installed dependencies) on a machine."""

    name: str
    host: str
    path: str  # absolute, on that machine
    team: str = "dev"
    version: str = ""  # empty = `git describe` in the directory, else "unknown"
    context: AssetContext = AssetContext()


GITHUB_OIDC_ISSUER = "https://token.actions.githubusercontent.com"


@dataclass(frozen=True)
class CosignVerify:
    """`verify = { identity = ..., issuer = ... }` of a [github.<name>] entry."""

    identity: str  # glob on the signing certificate's identity (`*` matches anything)
    issuer: str = GITHUB_OIDC_ISSUER


@dataclass
class GithubSource:
    """[github.<name>]: a GitHub repository whose releases carry a CycloneDX SBOM."""

    name: str  # the Dependency-Track project name
    repo: str  # owner/repo
    asset: str  # glob on the release asset names
    team: str
    context: AssetContext = AssetContext()
    verify: CosignVerify | None = None  # check the asset's cosign bundle before uploading


NEWS_KINDS = ("advisory", "cert", "exploit", "news")


@dataclass
class NewsFeed:
    """[news.feeds.<name>]: an RSS, Atom or JSON Feed URL, downloaded whole and filtered
    here (never a search query per keyword, which would show what each team runs)."""

    name: str
    url: str
    kind: str = "advisory"  # advisory | cert | exploit | news
    teams: list[str] = field(default_factory=list)  # empty: matched against every team
    enabled: bool = True


@dataclass
class NewsTeam:
    """[news.teams.<team>]: where the team's newsletter goes and extra keywords."""

    to: str = ""
    keywords: list[str] = field(default_factory=list)


@dataclass
class ChatChannel:
    """[chat.<name>]: a Mattermost channel for a noisy product (the Linux kernel, a vendor
    with a CVE a week). CVEs that match go there instead of the team's channel."""

    name: str
    match: list[str]  # "vendor" (all its products) or "vendor:product", NVD names
    min_tier: int | None = None  # None = rules.chat_min_tier

    @property
    def webhook_env(self) -> str:
        return chat_webhook_env(self.name)

    def matches(self, vendor: str, product: str) -> bool:
        """A "vendor" pattern matches any of that vendor's products, "vendor:product" only
        that one; product "" (a vendor-wide subscription) only matches a "vendor" pattern."""
        for m in self.match:
            v, _, p = m.partition(":")
            if v == vendor and (not p or p == product):
                return True
        return False


def cpe_vendor_product(cpe: str) -> tuple[str, str] | None:
    """cpe:2.3:o:linux:linux_kernel:7.3.6:... -> ("linux", "linux_kernel"); None if not a
    CPE 2.3 name."""
    parts = cpe.lower().split(":")
    if len(parts) < 5 or parts[:2] != ["cpe", "2.3"] or parts[3] in ("", "*"):
        return None
    return parts[3], parts[4] if parts[4] != "*" else ""


RESERVED_CHANNELS = ("alerts", "soc")
_CHANNEL_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,62}$")
_MATCH_RE = re.compile(r"^[a-z0-9][a-z0-9._~+-]*(:[a-z0-9][a-z0-9._~+-]*)?$")


def chat_webhook_env(channel: str) -> str:
    """A channel's webhook key in .env: linux-kernel -> VULNFLOW_CHAT_WEBHOOK_LINUX_KERNEL."""
    return "VULNFLOW_CHAT_WEBHOOK_" + channel.upper().replace("-", "_")


@dataclass
class Machines:
    """machines.toml: the operator's own hosts. Not in git (like .env)."""

    hosts: dict[str, Machine] = field(default_factory=dict)
    groups: dict[str, list[str]] = field(default_factory=dict)  # group -> host names
    code: dict[str, CodeTarget] = field(default_factory=dict)
    # "vendor:product" overrides for the CPE of Homebrew formulae/casks and Mac apps
    cpe_map: dict[str, str] = field(default_factory=dict)
    # extra OpenCVE subscriptions per team: (vendors, {vendor: [products]}); kept here, out of
    # git, because a detailed list shows the software stack
    subscriptions: dict[str, tuple[list[str], dict[str, list[str]]]] = field(default_factory=dict)
    github: dict[str, GithubSource] = field(default_factory=dict)
    # [projects."<DT project name>"]: context for projects that come from elsewhere (CI,
    # upload-sbom); wins over the context derived from hosts, images, code and github
    projects: dict[str, AssetContext] = field(default_factory=dict)
    news_feeds: dict[str, NewsFeed] = field(default_factory=dict)
    news_teams: dict[str, NewsTeam] = field(default_factory=dict)
    chat_channels: dict[str, ChatChannel] = field(default_factory=dict)


_REPO_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9-]{0,38}/[A-Za-z0-9._-]{1,100}$")


@dataclass
class Inventory:
    teams: dict[str, Team]
    rules: PriorityRules

    def team_for_opencve_project(self, project: str) -> Team | None:
        for t in self.teams.values():
            if t.opencve_project == project:
                return t
        return None


def _check_name(kind: str, name: str, path: str | Path) -> None:
    if not _NAME_RE.match(name):
        raise SystemExit(f"[{kind}.{name}] in {path}: name must match {_NAME_RE.pattern}")


def _machine(
    name: str, group: str, settings: dict[str, Any], teams: dict[str, Team], where: str
) -> Machine:
    kind = settings.get("kind", "linux")
    if kind not in MACHINE_KINDS:
        raise SystemExit(f"{where}: kind must be one of {MACHINE_KINDS}, got {kind!r}")
    team = settings.get("team", "")
    if team not in teams:
        raise SystemExit(f"{where}: team {team!r} is not one of {sorted(teams)}")
    scans = list(settings.get("scans") or DEFAULT_SCANS[kind])
    bad = [x for x in scans if x not in SCANS]
    if bad:
        raise SystemExit(f"{where}: unknown scans {bad}, choose from {SCANS}")
    paths = [str(x) for x in settings.get("language_paths") or []]
    for p in paths:
        if p.startswith("/") or ".." in Path(p).parts:
            raise SystemExit(f"{where}: language_paths must be relative to $HOME, got {p!r}")
    containers_team = str(settings.get("containers_team", "dev"))
    if containers_team not in teams:
        raise SystemExit(f"{where}: containers_team {containers_team!r} is not one of {sorted(teams)}")
    images: dict[str, AssetContext] = {}
    for image, ctx in (settings.get("images") or {}).items():
        if not isinstance(ctx, dict) or set(ctx) - CONTEXT_KEYS:
            raise SystemExit(f"{where}: images.{image!r} takes only {sorted(CONTEXT_KEYS)}")
        images[str(image)] = _context(ctx, f"{where}, image {image!r}")
    packages: dict[str, AssetContext] = {}
    for pkg, ctx in (settings.get("packages") or {}).items():
        if not isinstance(ctx, dict) or set(ctx) - CONTEXT_KEYS:
            raise SystemExit(f"{where}: packages.{pkg!r} takes only {sorted(CONTEXT_KEYS)}")
        packages[str(pkg)] = _context(ctx, f"{where}, package {pkg!r}")
    return Machine(
        name=name,
        team=team,
        kind=kind,
        group=group,
        scans=scans,
        language_paths=paths,
        version=str(settings.get("version", "")),
        containers_team=containers_team,
        context=_context(settings, where),
        images=images,
        packages=packages,
    )


def load_machines(path: str | Path, teams: dict[str, Team]) -> Machines:
    """Parse machines.toml: [groups.*] with shared settings and a `hosts` list, optional
    [hosts.*] overrides (or stand-alone hosts), [code.*] and [cpe_map]. A missing file is an
    empty estate; the example lives in machines.example.toml."""
    p = Path(path)
    if not p.is_file():
        return Machines()
    data: dict[str, Any] = tomllib.loads(p.read_text(encoding="utf-8"))
    sections = {
        "groups",
        "hosts",
        "code",
        "cpe_map",
        "subscriptions",
        "github",
        "projects",
        "news",
        "chat",
    }
    unknown = sorted(set(data) - sections)
    if unknown:
        raise SystemExit(f"{path}: unknown sections {unknown}")

    groups: dict[str, list[str]] = {}
    member_of: dict[str, str] = {}
    group_settings: dict[str, dict[str, Any]] = {}
    for g, gs in (data.get("groups") or {}).items():
        _check_name("groups", g, path)
        on_group = sorted(set(gs) & (CONTEXT_KEYS | {"images", "packages"}))
        if on_group:
            raise SystemExit(
                f"[groups.{g}] in {path}: {on_group} can't be set on a group (one group can run "
                "a public service and an internal admin page); set them on each host, image, "
                "[code.*], [github.*] or [projects.*]"
            )
        bad = sorted(set(gs) - _MACHINE_KEYS - {"hosts"})
        if bad:
            raise SystemExit(f"[groups.{g}] in {path}: unknown keys {bad}")
        names = [str(h) for h in gs.get("hosts") or []]
        for h in names:
            _check_name("hosts", h, path)
            if h in member_of:
                raise SystemExit(f"{path}: host {h!r} is in groups {member_of[h]!r} and {g!r}")
            member_of[h] = g
        groups[g] = names
        group_settings[g] = {k: v for k, v in gs.items() if k != "hosts"}

    overrides: dict[str, dict[str, Any]] = data.get("hosts") or {}
    hosts: dict[str, Machine] = {}
    for h in [*member_of, *(x for x in overrides if x not in member_of)]:
        _check_name("hosts", h, path)
        o = overrides.get(h) or {}
        bad = sorted(set(o) - _MACHINE_KEYS - CONTEXT_KEYS - {"group", "version", "images", "packages"})
        if bad:
            raise SystemExit(f"[hosts.{h}] in {path}: unknown keys {bad}")
        g = member_of.get(h) or str(o.get("group", ""))
        if "group" in o and member_of.get(h) not in (None, o["group"]):
            raise SystemExit(
                f"[hosts.{h}] in {path}: group {o['group']!r} but listed in {member_of[h]!r}"
            )
        if g and g not in groups:
            raise SystemExit(f"[hosts.{h}] in {path}: group {g!r} is not one of {sorted(groups)}")
        if g and h not in groups[g]:
            groups[g].append(h)
        settings = {**group_settings.get(g, {}), **o}
        hosts[h] = _machine(h, g, settings, teams, f"host {h!r} in {path}")

    code: dict[str, CodeTarget] = {}
    for name, c in (data.get("code") or {}).items():
        _check_name("code", name, path)
        where = f"[code.{name}] in {path}"
        host = str(c.get("host", ""))
        if host not in hosts:
            raise SystemExit(f"{where}: host {host!r} is not one of {sorted(hosts)}")
        cpath = str(c.get("path", ""))
        if not cpath.startswith("/") or ".." in Path(cpath).parts or "\n" in cpath:
            raise SystemExit(f"{where}: path must be absolute and without '..', got {cpath!r}")
        team = str(c.get("team", "dev"))
        if team not in teams:
            raise SystemExit(f"{where}: team {team!r} is not one of {sorted(teams)}")
        bad = sorted(set(c) - {"host", "path", "team", "version"} - CONTEXT_KEYS)
        if bad:
            raise SystemExit(f"{where}: unknown keys {bad}")
        code[name] = CodeTarget(name, host, cpath, team, str(c.get("version", "")), _context(c, where))

    cpe_map = {str(k): str(v) for k, v in (data.get("cpe_map") or {}).items()}
    for k, v in cpe_map.items():
        if not _CPE_PAIR_RE.match(v):
            raise SystemExit(f"[cpe_map] {k!r} in {path}: expected 'vendor:product', got {v!r}")
    subscriptions: dict[str, tuple[list[str], dict[str, list[str]]]] = {}
    for team, sub in (data.get("subscriptions") or {}).items():
        where = f"[subscriptions.{team}] in {path}"
        if team not in teams:
            raise SystemExit(f"{where}: team {team!r} is not one of {sorted(teams)}")
        bad = sorted(set(sub) - {"vendors", "products"})
        if bad:
            raise SystemExit(f"{where}: unknown keys {bad}")
        vendors = [str(v) for v in sub.get("vendors") or []]
        products = {str(v): [str(p) for p in ps] for v, ps in (sub.get("products") or {}).items()}
        for name in [*vendors, *products, *(p for ps in products.values() for p in ps)]:
            if not _CPE_PART_RE.match(name):
                raise SystemExit(f"{where}: {name!r} is not an NVD vendor/product name")
        subscriptions[team] = (vendors, products)
    github: dict[str, GithubSource] = {}
    for name, g in (data.get("github") or {}).items():
        _check_name("github", name, path)
        where = f"[github.{name}] in {path}"
        bad = sorted(set(g) - {"repo", "asset", "team", "verify"} - CONTEXT_KEYS)
        if bad:
            raise SystemExit(f"{where}: unknown keys {bad}")
        verify = None
        if "verify" in g:
            v = g["verify"]
            if not isinstance(v, dict) or set(v) - {"identity", "issuer"}:
                raise SystemExit(f"{where}: verify takes only identity and issuer")
            identity, issuer = str(v.get("identity", "")), str(v.get("issuer", GITHUB_OIDC_ISSUER))
            if not identity.strip():
                raise SystemExit(f"{where}: verify needs an identity (the signing workflow)")
            if not issuer.startswith("https://"):
                raise SystemExit(f"{where}: verify issuer must be an https URL, got {issuer!r}")
            verify = CosignVerify(identity, issuer)
        repo = str(g.get("repo", ""))
        if not _REPO_RE.match(repo) or ".." in repo:
            raise SystemExit(f"{where}: repo must be 'owner/repo', got {repo!r}")
        team = str(g.get("team", "dev"))
        if team not in teams:
            raise SystemExit(f"{where}: team {team!r} is not one of {sorted(teams)}")
        github[name] = GithubSource(
            name, repo, str(g.get("asset", "*.cdx.json")), team, _context(g, where), verify
        )
    projects: dict[str, AssetContext] = {}
    for name, pc in (data.get("projects") or {}).items():
        where = f"[projects.{name!r}] in {path}"
        if not isinstance(pc, dict) or set(pc) - CONTEXT_KEYS:
            raise SystemExit(f"{where}: takes only {sorted(CONTEXT_KEYS)}")
        projects[str(name)] = _context(pc, where)
    news_feeds, news_teams = _news(data.get("news") or {}, teams, path)
    chat_channels = _chat_channels(data.get("chat") or {}, path)
    return Machines(
        hosts=hosts,
        groups=groups,
        code=code,
        cpe_map=cpe_map,
        subscriptions=subscriptions,
        github=github,
        projects=projects,
        news_feeds=news_feeds,
        news_teams=news_teams,
        chat_channels=chat_channels,
    )


def _chat_channels(data: dict[str, Any], path: str | Path) -> dict[str, ChatChannel]:
    out: dict[str, ChatChannel] = {}
    for name, c in data.items():
        where = f"[chat.{name}] in {path}"
        if not _CHANNEL_RE.match(name) or name in RESERVED_CHANNELS:
            raise SystemExit(
                f"{where}: channel name must match {_CHANNEL_RE.pattern} and not be one of "
                f"{list(RESERVED_CHANNELS)}"
            )
        if not isinstance(c, dict) or set(c) - {"match", "min_tier"}:
            raise SystemExit(f"{where}: takes only 'match' and 'min_tier'")
        match = [str(m) for m in c.get("match") or []]
        if not match:
            raise SystemExit(f'{where}: match = [...] is required ("vendor" or "vendor:product")')
        for m in match:
            if not _MATCH_RE.match(m):
                raise SystemExit(f"{where}: {m!r} is not an NVD 'vendor' or 'vendor:product'")
        tier = c.get("min_tier")
        if tier is not None and (isinstance(tier, bool) or tier not in (1, 2, 3, 4)):
            raise SystemExit(f"{where}: min_tier must be 1..4 (P1..P4), got {tier!r}")
        out[name] = ChatChannel(name, match, tier)
    return out


def chat_channel_warnings(channels: dict[str, ChatChannel], teams: dict[str, Team]) -> list[str]:
    """Why a [chat.*] match can't catch anything. OpenCVE's webhook names only the project
    subscriptions a CVE matched (v3.1.0 `BaseNotifier.prepare_payload`), so a team that
    subscribes to the whole vendor reports "linux", never "linux$PRODUCT$linux_kernel".
    Pass the teams with machines.toml's [subscriptions.*] merged in (add_subscriptions)."""
    out: list[str] = []
    for ch in channels.values():
        for m in ch.match:
            vendor, _, product = m.partition(":")
            exact = [
                k
                for k, t in teams.items()
                if (product in t.products.get(vendor, []) if product else vendor in t.products)
            ]
            whole = [k for k, t in teams.items() if vendor in t.vendors and k not in exact]
            if product and whole:
                out.append(
                    f"[chat.{ch.name}] {m!r}: team(s) {sorted(whole)} subscribe to all of "
                    f"{vendor!r}, so OpenCVE reports their CVEs as {vendor!r} and they stay in "
                    f'team chat; use match = ["{vendor}"] or subscribe them to the product'
                )
            elif not exact and not whole:
                out.append(f"[chat.{ch.name}] {m!r}: no team subscribes to it, nothing will match")
    return out


def _news(
    data: dict[str, Any], teams: dict[str, Team], path: str | Path
) -> tuple[dict[str, NewsFeed], dict[str, NewsTeam]]:
    bad = sorted(set(data) - {"feeds", "teams"})
    if bad:
        raise SystemExit(f"[news] in {path}: unknown keys {bad}")
    feeds: dict[str, NewsFeed] = {}
    for name, f in (data.get("feeds") or {}).items():
        _check_name("news.feeds", name, path)
        where = f"[news.feeds.{name}] in {path}"
        bad = sorted(set(f) - {"url", "kind", "teams", "enabled"})
        if bad:
            raise SystemExit(f"{where}: unknown keys {bad}")
        url = str(f.get("url", ""))
        if not url.startswith(("https://", "http://")):
            raise SystemExit(f"{where}: url must be http(s), got {url!r}")
        kind = str(f.get("kind", "advisory"))
        if kind not in NEWS_KINDS:
            raise SystemExit(f"{where}: kind must be one of {NEWS_KINDS}, got {kind!r}")
        fteams = [str(t) for t in f.get("teams") or []]
        unknown = [t for t in fteams if t not in teams]
        if unknown:
            raise SystemExit(f"{where}: teams {unknown} are not in {sorted(teams)}")
        feeds[name] = NewsFeed(name, url, kind, fteams, bool(f.get("enabled", True)))
    nteams: dict[str, NewsTeam] = {}
    for team, t in (data.get("teams") or {}).items():
        where = f"[news.teams.{team}] in {path}"
        if team not in teams:
            raise SystemExit(f"{where}: team {team!r} is not one of {sorted(teams)}")
        bad = sorted(set(t) - {"to", "keywords"})
        if bad:
            raise SystemExit(f"{where}: unknown keys {bad}")
        to = str(t.get("to", ""))
        if to and ("@" not in to or any(c in to for c in "\r\n<>")):
            raise SystemExit(f"{where}: to must be an e-mail address, got {to!r}")
        nteams[team] = NewsTeam(to, [str(k) for k in t.get("keywords") or []])
    return feeds, nteams


def add_subscriptions(inv: Inventory, machines: Machines) -> None:
    """Merge machines.toml [subscriptions.<team>] into the teams' OpenCVE subscriptions."""
    for key, (vendors, products) in machines.subscriptions.items():
        team = inv.teams[key]
        team.vendors = sorted({*team.vendors, *vendors})
        for vendor, ps in products.items():
            team.products[vendor] = sorted({*team.products.get(vendor, []), *ps})


def load_inventory(path: str | Path) -> Inventory:
    data: dict[str, Any] = tomllib.loads(Path(path).read_text(encoding="utf-8"))
    teams: dict[str, Team] = {}
    for key, t in (data.get("teams") or {}).items():
        oc = t.get("opencve") or {}
        teams[key] = Team(
            key=key,
            display_name=t.get("display_name", key),
            opencve_project=t.get("opencve_project", key),
            defectdojo_product_type=t.get("defectdojo_product_type", key),
            dtrack_tag=t.get("dtrack_tag", f"team-{key}"),
            chat_mention=t.get("chat_mention", ""),
            vendors=sorted(set(oc.get("vendors") or [])),
            products={v: sorted(set(ps)) for v, ps in (oc.get("products") or {}).items()},
        )
    pr = data.get("priority") or {}
    rules = PriorityRules(**{k: v for k, v in pr.items() if k in PriorityRules.__dataclass_fields__})
    if not teams:
        raise SystemExit(f"No [teams.*] defined in {path}")
    return Inventory(teams=teams, rules=rules)
