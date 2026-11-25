"""Open findings whose CVE record says it is disputed, rejected or unsupported.

Where the marker is (checked against NVD and a real Dependency-Track, 2026-11-24): NVD keeps
it in the record's `cveTags` (`disputed`, `unsupported-when-assigned`) and `vulnStatus`
(`Rejected`), and no longer at the start of the description. Dependency-Track's copy of the
record has neither field, so the tags come from NVD's yearly JSON 2.0 feeds:

    https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-<year>.json.gz  (CVE-1999..2001 are in 2002)
    https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-<year>.meta     (sha256 of the JSON)

Only the feeds for the years of your CVE ids are downloaded; nothing else about you is sent.
Each feed is read one record at a time (a year is up to ~580 MB of JSON) and reduced to a
small index in data/nvd/, kept until the `.meta` sha256 changes (checked once a day).

The old description prefix is still recognised, for records that carry it:

    ** DISPUTED ** An issue was discovered in ...
    ** REJECT ** DO NOT USE THIS CANDIDATE NUMBER. ...

ANY-VERSION: NVD's configuration lists the finding's product (vendor:product of the
component's CPE) as vulnerable with version `*` and no version range, so every version ever
made matches; for a CVE older than `any_version_years` (2) that is almost always an NVD data
error (seen: cpe:2.3:a:apple:safari:* on 72 Safari CVEs from 2005-2012, matching Safari 27.2).
Recent ones are not flagged: "every version, no fix yet" can be true.

A marker is a signal for review, not a verdict. Who disputes it varies (sometimes the
maintainer says "working as intended", sometimes a vendor disputes a researcher). The rows
use the same shape as `vulnflow debian --json`, so after review `vulnflow ignore` can apply
them; the `reason` field becomes the analysis comment.
"""

from __future__ import annotations

import codecs
import gzip
import hashlib
import io
import json
import logging
import os
import re
import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import date, timedelta
from pathlib import Path
from typing import Any

from .clients import DependencyTrack
from .config import Inventory
from .net import Http, Transport
from .patches import cve_id, open_findings

log = logging.getLogger(__name__)

# The marker leads the description; anchoring avoids matching a CVE that merely mentions it.
MARKER = re.compile(r"\s*\*\*\s*(DISPUTED|REJECT(?:ED)?)\s*\*\*\s*(.*)", re.IGNORECASE | re.DOTALL)
SNIPPET = 160
FEED_URL = "https://nvd.nist.gov/feeds/json/cve/2.0"
# NVD cveTags worth a review; `exclusively-hosted-service` cannot be in an SBOM
NVD_TAGS = {"disputed": "DISPUTED", "unsupported-when-assigned": "UNSUPPORTED"}
_CVE = re.compile(r"CVE-(\d{4})-\d+$")
_ORDER = {"REJECT": 0, "DISPUTED": 1, "UNSUPPORTED": 2, "ANY-VERSION": 3}
INDEX_FORMAT = 2  # bump when the cached per-year index gains fields; old ones are rebuilt


@dataclass
class DisputedFinding:
    team: str
    project: str
    component: str
    version: str
    vuln_id: str
    severity: str
    marker: str
    reason: str
    project_uuid: str = ""
    component_uuid: str = ""
    vuln_uuid: str = ""
    project_version: str = ""


def disputed_marker(description: str) -> tuple[str, str] | None:
    """(DISPUTED|REJECT, text after the marker) if the description starts with one."""
    m = MARKER.match(description or "")
    if not m:
        return None
    return ("REJECT" if m.group(1).upper().startswith("REJECT") else "DISPUTED"), m.group(2).strip()


def record_flag(cve: dict[str, Any]) -> tuple[str, str] | None:
    """(REJECT|DISPUTED|UNSUPPORTED, explanation) for an NVD JSON 2.0 `cve` object."""
    desc = next(
        (str(d.get("value") or "") for d in cve.get("descriptions") or [] if d.get("lang") == "en"),
        "",
    )
    if str(cve.get("vulnStatus") or "") == "Rejected":
        return "REJECT", desc
    tags = {t for group in cve.get("cveTags") or [] for t in group.get("tags") or []}
    for tag, marker in NVD_TAGS.items():
        if tag in tags:
            # the dispute itself is usually a trailing "NOTE: ..." sentence
            note = desc.find("NOTE:")
            return marker, desc[note:] if note >= 0 else desc
    return disputed_marker(desc)


def unbounded_products(cve: dict[str, Any]) -> list[str]:
    """vendor:product of every vulnerable CPE match with version `*` and no version range."""
    out = set()
    for conf in cve.get("configurations") or []:
        for node in conf.get("nodes") or []:
            for m in node.get("cpeMatch") or []:
                parts = str(m.get("criteria", "")).split(":")
                if (
                    m.get("vulnerable")
                    and len(parts) > 5
                    and parts[5] == "*"
                    and not any(k.startswith("version") for k in m)
                ):
                    out.add(f"{parts[3]}:{parts[4]}")
    return sorted(out)


def scan_feed(
    gz_body: bytes, chunk: int = 1 << 20
) -> tuple[list[str], dict[str, list[str]], str, dict[str, list[Any]]]:
    """(every CVE id in the feed, {id: [marker, explanation]} for the flagged ones, sha256 of
    the uncompressed JSON, {id: [published, [vendor:product, ...]]} for the CVEs that list a
    product for every version). Reads one record at a time: json.load of a year needs
    gigabytes."""
    dec = json.JSONDecoder()
    text = codecs.getincrementaldecoder("utf-8")()
    digest = hashlib.sha256()
    ids: list[str] = []
    flags: dict[str, list[str]] = {}
    anyver: dict[str, list[Any]] = {}
    with gzip.GzipFile(fileobj=io.BytesIO(gz_body)) as gz:
        buf, pos, eof = "", 0, False

        def more() -> None:
            nonlocal buf, pos, eof
            data = gz.read(chunk)
            if data:
                digest.update(data)
                buf = buf[pos:] + text.decode(data)
            else:
                eof = True
                buf = buf[pos:] + text.decode(b"", final=True)
            pos = 0

        while True:  # find the start of the "vulnerabilities" array
            i = buf.find('"vulnerabilities"')
            j = buf.find("[", i) if i >= 0 else -1
            if j >= 0:
                pos = j + 1
                break
            if eof:
                raise ValueError("no 'vulnerabilities' array in the feed")
            more()
        while True:
            while pos < len(buf) and buf[pos] in " \t\r\n,":
                pos += 1
            if pos >= len(buf):
                if eof:
                    raise ValueError("feed ends inside the 'vulnerabilities' array")
                more()
                continue
            if buf[pos] == "]":
                break
            try:
                item, pos = dec.raw_decode(buf, pos)
            except json.JSONDecodeError:
                if eof:
                    raise
                more()  # the record runs past the buffer
                continue
            cve = (item or {}).get("cve") or {}
            cid = str(cve.get("id") or "")
            if cid:
                ids.append(cid)
                flag = record_flag(cve)
                if flag:
                    flags[cid] = [flag[0], flag[1][:600]]
                products = unbounded_products(cve)
                if products:
                    anyver[cid] = [str(cve.get("published") or "")[:10], products]
        while not eof:  # the rest only for the checksum
            more()
            buf, pos = "", 0
    return ids, flags, digest.hexdigest().upper(), anyver


def _meta_sha256(body: bytes) -> str:
    for line in body.decode("utf-8", "replace").splitlines():
        key, _, value = line.partition(":")
        if key.strip() == "sha256":
            return value.strip().upper()
    raise ValueError("no sha256 in the .meta file")


class NvdFeeds:
    """Disputed/rejected/unsupported flags from NVD's yearly feeds, cached per year."""

    def __init__(
        self,
        cache_dir: Path,
        transport: Transport | None = None,
        ttl_seconds: int = 24 * 3600,
        url: str = FEED_URL,
        notify: Callable[[str], None] | None = None,
    ):
        self.dir = cache_dir / "nvd"
        self.ttl = ttl_seconds
        self.http = Http(url, transport=transport, timeout=600)
        self.notify = notify or (lambda msg: None)
        self._years: dict[int, _YearIndex | None] = {}
        self.errors: list[str] = []

    @staticmethod
    def feed_year(cve_id: str) -> int | None:
        m = _CVE.match(cve_id.upper())
        return max(int(m.group(1)), 2002) if m else None

    def _year(self, year: int) -> _YearIndex | None:
        if year in self._years:
            return self._years[year]
        index = self.dir / f"nvdcve-2.0-{year}.flags.json"
        cached: dict[str, Any] | None = None
        if index.is_file():
            try:
                cached = json.loads(index.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                cached = None
        current = bool(cached) and (cached or {}).get("format") == INDEX_FORMAT
        loaded: _YearIndex | None = None
        try:
            if current and cached and time.time() - index.stat().st_mtime < self.ttl:
                loaded = _YearIndex.of(cached)
            else:
                want = _meta_sha256(self.http.get(f"nvdcve-2.0-{year}.meta").body)
                if current and cached and cached.get("sha256") == want:
                    os.utime(index)  # unchanged upstream: fresh for another day
                else:
                    self.notify(f"downloading NVD feed {year}")
                    ids, flags, got, anyver = scan_feed(self.http.get(f"nvdcve-2.0-{year}.json.gz").body)
                    if got != want:
                        raise ValueError(f"sha256 {got} does not match the .meta file ({want})")
                    cached = {
                        "format": INDEX_FORMAT,
                        "sha256": got,
                        "ids": ids,
                        "flags": flags,
                        "anyver": anyver,
                    }
                    self.dir.mkdir(parents=True, exist_ok=True)
                    tmp = index.with_suffix(".tmp")
                    tmp.write_text(json.dumps(cached), encoding="utf-8")
                    tmp.replace(index)
                loaded = _YearIndex.of(cached)
        except Exception as e:
            self.errors.append(f"NVD feed {year}: {e}")
            if cached:  # stale beats nothing; the error says it is stale
                loaded = _YearIndex.of(cached)
        self._years[year] = loaded
        return loaded

    def knows(self, cve_id: str) -> bool:
        """False when NVD could not answer: not a CVE id, feed unavailable, or too new."""
        year = self.feed_year(cve_id)
        data = self._year(year) if year else None
        return data is not None and cve_id.upper() in data.ids

    def flag(self, cve_id: str) -> tuple[str, str] | None:
        """(marker, explanation) when NVD flags the CVE."""
        year = self.feed_year(cve_id)
        data = self._year(year) if year else None
        got = data.flags.get(cve_id.upper()) if data else None
        return (got[0], got[1]) if got else None

    def any_version(self, cve_id: str) -> tuple[str, set[str]] | None:
        """(published YYYY-MM-DD, {vendor:product}) when NVD lists products for every version."""
        year = self.feed_year(cve_id)
        data = self._year(year) if year else None
        got = data.anyver.get(cve_id.upper()) if data else None
        return (str(got[0]), set(got[1])) if got else None


@dataclass
class _YearIndex:
    ids: set[str]
    flags: dict[str, list[str]]
    anyver: dict[str, list[Any]]

    @classmethod
    def of(cls, cached: dict[str, Any]) -> _YearIndex:
        return cls(set(cached["ids"]), cached["flags"], cached.get("anyver") or {})


def _reason(vuln_id: str, marker: str, text: str, where: str) -> str:
    snippet = " ".join(text.split())
    if len(snippet) > SNIPPET:
        snippet = snippet[: SNIPPET - 1].rstrip() + "…"
    return f"{vuln_id} is marked {marker} {where}" + (f': "{snippet}"' if snippet else "")


@dataclass
class DisputedResult:
    rows: list[DisputedFinding]
    checked: int  # open findings with a vulnerability id
    unchecked: int  # CVE findings the NVD feeds could not answer for (0 without feeds)
    errors: list[str]


def _cpe_product(cpe: str) -> str:
    parts = cpe.split(":")
    return f"{parts[3]}:{parts[4]}" if cpe.startswith("cpe:2.3:") and len(parts) > 5 else ""


def disputed_findings(
    inv: Inventory,
    dt: DependencyTrack,
    team: str | None = None,
    nvd: NvdFeeds | None = None,
    *,
    any_version_years: float = 2,
    today: date | None = None,
) -> DisputedResult:
    """Open findings with a marker. Without `nvd` only the description prefix is checked,
    which current NVD records no longer carry. any_version_years 0 turns ANY-VERSION off."""
    cutoff = (today or date.today()) - timedelta(days=round(any_version_years * 365.25))
    rows: list[DisputedFinding] = []
    errors: list[str] = []
    checked = unchecked = 0
    records: dict[tuple[str, str], str] = {}  # description lookups for findings without one
    for key, proj, f in open_findings(inv, dt, team, errors):
        v: dict[str, Any] = f.get("vulnerability") or {}
        src, vid = str(v.get("source") or ""), str(v.get("vulnId") or "")
        if not vid:
            continue
        checked += 1
        hit: tuple[str, str] | None = None
        where = "in its CVE record"
        cve = cve_id(vid)  # DT's OSV source names Debian's records DEBIAN-CVE-...
        if nvd is not None and cve:
            if not nvd.knows(cve):
                unchecked += 1
            hit, where = nvd.flag(cve), "in NVD"
        if hit is None:
            desc = str(v.get("description") or "")
            if not desc and src:
                if (src, vid) not in records:
                    try:
                        rec = dt.vulnerability(src, vid) or {}
                        records[(src, vid)] = str(rec.get("description") or "")
                    except Exception as e:
                        errors.append(f"{src}/{vid}: {e}")
                        records[(src, vid)] = ""
                desc = records[(src, vid)]
            hit = disputed_marker(desc)
            where = "in its CVE record"
        c: dict[str, Any] = f.get("component") or {}
        if hit is None and nvd is not None and any_version_years > 0 and vid.startswith("CVE-"):
            product = _cpe_product(str(c.get("cpe") or ""))
            av = nvd.any_version(vid) if product else None
            if av and product in av[1] and av[0] and av[0] < cutoff.isoformat():
                where = "in NVD"
                hit = (
                    "ANY-VERSION",
                    f"NVD lists {product} as vulnerable in every version (no version range); "
                    f"published {av[0]}, installed {c.get('version', '?')}",
                )
        if hit is None:
            continue
        marker, text = hit
        rows.append(
            DisputedFinding(
                team=key,
                project=proj.name,
                project_version=proj.version,
                component=c.get("name", ""),
                version=c.get("version", ""),
                vuln_id=vid,
                severity=v.get("severity", ""),
                marker=marker,
                reason=_reason(vid, marker, text, where),
                project_uuid=proj.uuid,
                component_uuid=str(c.get("uuid") or ""),
                vuln_uuid=str(v.get("uuid") or ""),
            )
        )
    # withdrawn candidates first: they are the clearest cases
    rows.sort(key=lambda r: (_ORDER.get(r.marker, 9), r.team, r.project, r.component, r.vuln_id))
    if nvd is not None:
        errors.extend(nvd.errors)
    return DisputedResult(rows, checked, unchecked, errors)
