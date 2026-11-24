"""What Ubuntu and Red Hat say about open findings on their own packages.

Like the Debian tracker lookup (debian.py), but both vendors only offer per-CVE records, so
this asks them one CVE id at a time and caches each answer on disk for 24 h:

    https://ubuntu.com/security/cves/CVE-YYYY-N.json
    https://access.redhat.com/hydra/rest/securitydata/cve/CVE-YYYY-N.json

What leaves the machine: the CVE ids of findings on Ubuntu (`pkg:deb/ubuntu/...`) or Red Hat
(`pkg:rpm/redhat/...`) components, and nothing else. That list does say which CVEs affect
you, so the command only runs with --ubuntu / --redhat, and says what it is about to send.

Record shapes (checked against real responses for CVE-2023-31486 on 2026-11-23; values not
seen there are marked ASSUMED):

Ubuntu  packages[] {name (source package), statuses[] {release_codename, status, description,
        pocket}}; priority. Status values seen: ignored, needed. ASSUMED from the vendor's
        documentation: released (description = fixed version), not-affected, DNE, pending,
        needs-triage, active, deferred.
Red Hat threat_severity; package_state[] {product_name, fix_state, package_name, cpe} (seen:
        Affected, Out of support scope; package_name can be "perl:5.30/perl-HTTP-Tiny");
        affected_release[] {advisory, cpe, package "name-epoch:version-release"}.

Every match gets the same kind of `action` as the Debian lookup, plus two vendor decisions:

    update        installed is older than the vendor's fix
    fixed         installed is the fix or newer (a backport NVD's range does not know)
    not-affected  the vendor says this release is not affected
    wontfix       the vendor will not fix it (Ubuntu `ignored`; Red Hat `Will not fix` or
                  `Out of support scope`)
    no-fix        open, no fix yet
    unknown       cannot decide safely (ambiguous module streams, unparsable versions)

`reason` carries the sentence `vulnflow ignore` writes as the analysis comment.
"""

from __future__ import annotations

import json
import logging
import re
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, unquote

from . import rpmver
from .clients import DependencyTrack, DTProject
from .config import Inventory
from .debian import fix_action, installed_version
from .net import Http, Transport
from .patches import open_findings

log = logging.getLogger(__name__)

ACTIONS = ("update", "fixed", "not-affected", "wontfix", "no-fix", "unknown")
VENDOR_NAMES = {"ubuntu": "Ubuntu", "redhat": "Red Hat"}
UBUNTU_CODENAMES = {
    "16.04": "xenial",
    "18.04": "bionic",
    "20.04": "focal",
    "22.04": "jammy",
    "24.04": "noble",
    "24.10": "oracular",
    "25.04": "plucky",
    "25.10": "questing",
}
_CVE = re.compile(r"CVE-\d{4}-\d{4,}")
_UBUNTU_RANK = {
    "released": 0,
    "not-affected": 1,
    "DNE": 2,
    "ignored": 3,
    "pending": 4,
    "needed": 5,
    "needs-triage": 6,
    "active": 7,
    "deferred": 8,
}
_RH_STATE = {
    "not affected": "not-affected",
    "will not fix": "wontfix",
    "out of support scope": "wontfix",
    "affected": "no-fix",
    "new": "no-fix",
    "under investigation": "no-fix",
    "fix deferred": "no-fix",
}
_RH_STATE_RANK = {"no-fix": 0, "wontfix": 1, "unknown": 2, "not-affected": 3}  # worst case wins
_RH_CPE = re.compile(r"cpe:/[oa]:redhat:(?:enterprise_linux|rhel_els):(\d+)")
_ROUTINE_POCKETS = ("", "security", "updates", "release")


@dataclass
class VendorComponent:
    vendor: str  # ubuntu | redhat
    names: set[str]
    release: str  # Ubuntu codename, or the RHEL major version
    installed: str  # deb version, or rpm version-release
    epoch: int = 0  # rpm only


@dataclass
class VendorInfo:
    vendor: str
    package: str
    release: str
    status: str
    severity: str
    fixed: str
    note: str
    pocket: str
    action: str


@dataclass
class VendorFinding:
    team: str
    project: str
    component: str
    version: str  # the installed version that was compared
    vuln_id: str
    severity: str  # Dependency-Track's
    vendor: str
    package: str
    release: str
    status: str
    vendor_severity: str
    fixed: str
    note: str
    pocket: str
    action: str
    reason: str
    project_uuid: str = ""
    component_uuid: str = ""
    vuln_uuid: str = ""
    project_version: str = ""


@dataclass
class _Item:
    team: str
    project: DTProject
    vuln: dict[str, Any]
    component: dict[str, Any]
    parsed: VendorComponent


@dataclass
class VendorResult:
    rows: list[VendorFinding] = field(default_factory=list)
    unmatched: int = 0  # CVE findings on this vendor's components with no usable record
    considered: dict[str, int] = field(default_factory=dict)  # findings per vendor
    contacted: dict[str, int] = field(default_factory=dict)  # CVE ids asked per vendor
    errors: list[str] = field(default_factory=list)


# --------------------------------------------------------------------------- purls
def parse_vendor_purl(purl: str, component_version: str = "") -> VendorComponent | None:
    """Classify a purl as an Ubuntu deb or a Red Hat rpm; None for anything else."""
    path, _, query = purl.partition("?")
    q = parse_qs(query)
    distro = (q.get("distro") or [""])[0].lower()
    if path.startswith("pkg:deb/ubuntu/"):
        name = unquote(path.split("/", 2)[2].split("@", 1)[0]).lower()
        names = {name}
        upstream = (q.get("upstream") or [""])[0]
        if upstream:
            names.add(unquote(upstream).split("@", 1)[0].lower())
        ver = distro.removeprefix("ubuntu-")
        release = UBUNTU_CODENAMES.get(ver, ver if ver in UBUNTU_CODENAMES.values() else "")
        return VendorComponent("ubuntu", names, release, installed_version(purl, component_version))
    if path.startswith(("pkg:rpm/redhat/", "pkg:rpm/rhel/")):
        rest = path.split("/", 2)[2]
        name, _, ver = rest.partition("@")
        major = ""
        for prefix in ("rhel-", "redhat-"):
            if distro.startswith(prefix):
                major = distro.removeprefix(prefix).split(".", 1)[0]
        epoch = (q.get("epoch") or ["0"])[0]
        return VendorComponent(
            "redhat",
            {unquote(name).lower()},
            major if major.isdigit() else "",
            unquote(ver) or component_version,
            int(epoch) if epoch.isdigit() else 0,
        )
    return None


# ------------------------------------------------------------------------- clients
class VendorApi:
    """One vendor's per-CVE JSON, cached on disk (negative answers too)."""

    def __init__(
        self,
        vendor: str,
        base_url: str,
        path: str,
        cache_dir: Path,
        transport: Transport | None = None,
        ttl_seconds: int = 24 * 3600,
    ):
        self.vendor = vendor
        self.path = path
        self.cache = cache_dir / "vendors" / vendor
        self.ttl = ttl_seconds
        self.http = Http(base_url, headers={"Accept": "application/json"}, transport=transport)
        self.requests = 0

    def record(self, cve: str) -> dict[str, Any] | None:
        if not _CVE.fullmatch(cve):
            raise ValueError(f"not a CVE id: {cve!r}")
        f = self.cache / f"{cve}.json"
        if f.is_file() and time.time() - f.stat().st_mtime < self.ttl:
            data = json.loads(f.read_bytes())
            return data if isinstance(data, dict) else None
        url = self.path.format(cve=cve)
        r = self.http.get(url, expect_ok=False)
        self.requests += 1
        if r.status == 404:
            data = None
        elif not r.ok:
            self.http.get(url)  # raise with details
            data = None
        else:
            data = r.json()
        self.cache.mkdir(parents=True, exist_ok=True)
        f.write_bytes(json.dumps(data).encode())
        return data if isinstance(data, dict) else None


def ubuntu_api(cache_dir: Path, transport: Transport | None = None) -> VendorApi:
    return VendorApi("ubuntu", "https://ubuntu.com", "security/cves/{cve}.json", cache_dir, transport)


def redhat_api(cache_dir: Path, transport: Transport | None = None) -> VendorApi:
    return VendorApi(
        "redhat",
        "https://access.redhat.com",
        "hydra/rest/securitydata/cve/{cve}.json",
        cache_dir,
        transport,
    )


# ------------------------------------------------------------------------- verdicts
def ubuntu_info(rec: dict[str, Any], comp: VendorComponent) -> VendorInfo | None:
    best: tuple[int, dict[str, Any], dict[str, Any]] | None = None
    for p in rec.get("packages") or []:
        if str(p.get("name", "")).lower() not in comp.names:
            continue
        for s in p.get("statuses") or []:
            if s.get("release_codename") != comp.release:
                continue
            rank = _UBUNTU_RANK.get(str(s.get("status")), 99)
            if best is None or rank < best[0]:
                best = (rank, p, s)
    if best is None:
        return None
    _, p, s = best
    status, desc = str(s.get("status") or ""), str(s.get("description") or "")
    fixed = ""
    if status == "released":
        fixed = desc
        action = fix_action(comp.installed, "resolved", fixed)
    elif status in ("not-affected", "DNE"):
        action = "not-affected"
    elif status == "ignored":
        action = "wontfix"
    elif status in ("needed", "needs-triage", "active", "pending", "deferred"):
        action = "no-fix"
    else:
        action = "unknown"
    return VendorInfo(
        "ubuntu",
        str(p.get("name") or ""),
        comp.release,
        status,
        str(rec.get("priority") or ""),
        fixed,
        "" if status == "released" else desc,
        str(s.get("pocket") or ""),
        action,
    )


def _rh_package_name(package_name: str) -> str:
    return package_name.rsplit("/", 1)[-1].lower()  # "perl:5.30/perl-HTTP-Tiny" -> name


def redhat_info(rec: dict[str, Any], comp: VendorComponent) -> VendorInfo | None:
    major = comp.release
    if not major:
        return None
    severity = str(rec.get("threat_severity") or "").lower()
    inst_ver, _, inst_rel = comp.installed.rpartition("-")
    if not inst_ver:  # no release part
        inst_ver, inst_rel = comp.installed, ""
    release = f"rhel{major}"

    fixes: dict[tuple[int, str, str], str] = {}  # (epoch, version, release) -> advisory
    for ar in rec.get("affected_release") or []:
        m = _RH_CPE.match(str(ar.get("cpe") or ""))
        nevr = rpmver.parse_nevr(str(ar.get("package") or ""))
        if m and m.group(1) == major and nevr and nevr[0].lower() in comp.names:
            fixes[(nevr[1], nevr[2], nevr[3])] = str(ar.get("advisory") or "")
    if fixes:
        cands = list(fixes)
        if len(cands) > 1:  # module streams: keep only the stream of the installed version
            cands = [c for c in cands if c[1] == inst_ver]
        fixed, advisory, action = "", "", "unknown"
        if len(cands) == 1:
            e, v, r = cands[0]
            fixed = f"{e}:{v}-{r}" if e else f"{v}-{r}"
            advisory = fixes[cands[0]]
            newer = rpmver.compare((comp.epoch, inst_ver, inst_rel), (e, v, r)) >= 0
            action = "fixed" if newer else "update"
        name = sorted(comp.names)[0]
        return VendorInfo("redhat", name, release, "fixed", severity, fixed, advisory, "", action)

    best: tuple[int, dict[str, Any]] | None = None
    for ps in rec.get("package_state") or []:
        m = _RH_CPE.match(str(ps.get("cpe") or ""))
        pkg = _rh_package_name(str(ps.get("package_name") or ""))
        if not (m and m.group(1) == major) or pkg not in comp.names:
            continue
        rank = _RH_STATE_RANK[_RH_STATE.get(str(ps.get("fix_state") or "").lower(), "unknown")]
        if best is None or rank < best[0]:
            best = (rank, ps)
    if best is None:
        return None
    state = str(best[1].get("fix_state") or "")
    return VendorInfo(
        "redhat",
        _rh_package_name(str(best[1].get("package_name") or "")),
        release,
        state,
        severity,
        "",
        "",
        "",
        _RH_STATE.get(state.lower(), "unknown"),
    )


def _reason(vendor: str, info: VendorInfo, installed: str) -> str:
    who = VENDOR_NAMES[vendor]
    where = f"{info.release}" + (f", {info.pocket}" if info.pocket not in _ROUTINE_POCKETS else "")
    if info.action == "fixed":
        return f"{who}: fixed in {info.fixed} ({where}), installed {installed} is not older"
    if info.action == "update":
        return f"{who}: fixed in {info.fixed} ({where}); installed {installed} is older"
    detail = f": {info.note}" if info.note else ""
    return f"{who}: {info.status or info.action} in {where}{detail}"


# ------------------------------------------------------------------------ findings
def vendor_findings(
    inv: Inventory,
    dt: DependencyTrack,
    cache_dir: Path,
    *,
    ubuntu: bool = False,
    redhat: bool = False,
    team: str | None = None,
    transport: Transport | None = None,
    notify: Callable[[str, int], None] | None = None,
) -> VendorResult:
    """Ubuntu / Red Hat verdicts for open CVE findings on their packages. `notify(vendor,
    n)` is called before the first request to a vendor, with the number of CVE ids that will
    be asked about (fewer if the cache already has them)."""
    res = VendorResult()
    enabled = {"ubuntu": ubuntu, "redhat": redhat}
    apis: dict[str, VendorApi] = {}
    if ubuntu:
        apis["ubuntu"] = ubuntu_api(cache_dir, transport)
    if redhat:
        apis["redhat"] = redhat_api(cache_dir, transport)

    todo: list[_Item] = []
    for key, proj, f in open_findings(inv, dt, team, res.errors):
        v: dict[str, Any] = f.get("vulnerability") or {}
        c: dict[str, Any] = f.get("component") or {}
        vid = str(v.get("vulnId") or "")
        comp = parse_vendor_purl(str(c.get("purl") or ""), str(c.get("version") or ""))
        if comp is None or not enabled[comp.vendor] or not _CVE.fullmatch(vid):
            continue
        res.considered[comp.vendor] = res.considered.get(comp.vendor, 0) + 1
        todo.append(_Item(key, proj, v, c, comp))

    for vendor, api in apis.items():
        ids = sorted({str(t.vuln.get("vulnId")) for t in todo if t.parsed.vendor == vendor})
        fresh = [i for i in ids if not (api.cache / f"{i}.json").is_file()]
        if fresh and notify:
            notify(vendor, len(fresh))
        res.contacted[vendor] = len(fresh)

    records: dict[tuple[str, str], dict[str, Any] | None] = {}
    for item in todo:
        key, proj, v, c, comp = item.team, item.project, item.vuln, item.component, item.parsed
        vid = str(v.get("vulnId"))
        api = apis[comp.vendor]
        if (comp.vendor, vid) not in records:
            try:
                records[(comp.vendor, vid)] = api.record(vid)
            except Exception as e:
                res.errors.append(f"{VENDOR_NAMES[comp.vendor]} {vid}: {e}")
                records[(comp.vendor, vid)] = None
        rec = records[(comp.vendor, vid)]
        info = None
        if rec:
            info = (ubuntu_info if comp.vendor == "ubuntu" else redhat_info)(rec, comp)
        if info is None:
            res.unmatched += 1
            continue
        res.rows.append(
            VendorFinding(
                team=key,
                project=proj.name,
                project_version=proj.version,
                component=str(c.get("name") or ""),
                version=comp.installed,
                vuln_id=vid,
                severity=str(v.get("severity") or ""),
                vendor=comp.vendor,
                package=info.package,
                release=info.release,
                status=info.status,
                vendor_severity=info.severity,
                fixed=info.fixed,
                note=info.note,
                pocket=info.pocket,
                action=info.action,
                reason=_reason(comp.vendor, info, comp.installed),
                project_uuid=proj.uuid,
                component_uuid=str(c.get("uuid") or ""),
                vuln_uuid=str(v.get("uuid") or ""),
            )
        )
    order = {a: i for i, a in enumerate(ACTIONS)}
    res.rows.sort(key=lambda r: (order.get(r.action, 99), r.team, r.project, r.component, r.vuln_id))
    return res
