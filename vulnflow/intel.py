"""Exploitation signals: CISA KEV (plus VulnCheck KEV with a token), FIRST EPSS, CIRCL
Vulnerability-Lookup sightings.

VulnCheck KEV (checked live 2026-11-27 with a community token): GET
https://api.vulncheck.com/v3/index/vulncheck-kev with `Authorization: Bearer <token>`,
cursor paging: `?start_cursor&limit=2000` first, then `?cursor=<_meta.next_cursor>` until a
page comes back without one (the last page is empty). 6164 records then, one CVE each in
`cve` (a list), 1808 with `cisa_date_added`; fields `vendorProject`, `product`,
`vulnerabilityName`, `shortDescription`, `required_action`, `knownRansomwareCampaignUse`
(Known/Unknown), `date_added` (RFC 3339). The whole index is downloaded, never searched by
CVE, so the request carries the token and nothing about our stack. Its licence asks for
prominent attribution: entries it adds carry `kevSource` "VulnCheck" and are labelled
"VulnCheck KEV" wherever vulnflow names the catalog.

OPSEC note: every lookup sends the CVE ID to a third party. CVE IDs alone reveal
*interest*, not exposure, but if that is unacceptable, disable the sources in .env
and mirror KEV/EPSS internally (both are plain downloadable files), and run your
own Vulnerability-Lookup instance.
"""

from __future__ import annotations

import json
import logging
import time
from collections.abc import Collection, Iterable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import quote

from .net import Http, Transport

log = logging.getLogger(__name__)

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
VULNCHECK_KEV_URL = "https://api.vulncheck.com/v3/index/vulncheck-kev"
CISA, VULNCHECK = "CISA", "VulnCheck"  # kevSource of a KEV index entry
EPSS_URL = "https://api.first.org/data/v1/epss"
SIGHTING_TYPES = ("exploited", "published-proof-of-concept", "seen")


@dataclass
class Signals:
    cve: str
    kev: bool = False
    kev_ransomware: bool = False
    kev_date_added: str = ""
    kev_source: str = CISA  # which catalog lists it (CISA when both do)
    kev_name: str = ""  # KEV's vulnerabilityName, e.g. "Apple macOS Improper Authentication ..."
    epss: float | None = None
    epss_percentile: float | None = None
    sightings: dict[str, int] = field(default_factory=dict)  # type -> count
    errors: list[str] = field(default_factory=list)

    @property
    def exploited_sightings(self) -> int:
        return self.sightings.get("exploited", 0)


def kev_source(kev: Collection[str], cve: str) -> str:
    """ "CISA" or "VulnCheck": the catalog that lists `cve` in a KEV index (CISA when both
    do, and for a bare set of ids)."""
    entry = kev.get(cve.upper()) if isinstance(kev, Mapping) else None
    return str((entry or {}).get("kevSource") or CISA)


def kev_label(kev: Collection[str], cve: str) -> str:
    """ "CISA KEV" or "VulnCheck KEV", for messages (VulnCheck asks for that attribution)."""
    return f"{kev_source(kev, cve)} KEV"


class VulnCheckKev:
    """The whole VulnCheck KEV index, cached on disk (default TTL 6 h; kev-watch's hourly
    runs reuse it, to go easy on the community rate limit). A failed download falls back
    to the copy on disk, however old."""

    PAGE = 2000
    # what index() reads; the rest (exploit links, citations) made the cache 12 MB
    FIELDS = (
        "cve",
        "vendorProject",
        "product",
        "vulnerabilityName",
        "shortDescription",
        "required_action",
        "knownRansomwareCampaignUse",
        "date_added",
    )
    MAX_PAGES = 50  # 6164 records were 4 pages of 2000 (2026-11-27)

    def __init__(
        self,
        cache_dir: Path,
        token: str,
        transport: Transport | None = None,
        ttl_seconds: int = 6 * 3600,
        url: str = VULNCHECK_KEV_URL,
    ):
        self.path = cache_dir / "vulncheck-kev.json"
        self.ttl = ttl_seconds
        self.http = Http(
            url,
            headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
            transport=transport,
            timeout=60,
        )

    def _download(self) -> list[dict[str, Any]]:
        records: list[dict[str, Any]] = []
        query = f"?start_cursor&limit={self.PAGE}"
        for _ in range(self.MAX_PAGES):
            body = self.http.get(query).json() or {}
            records += [
                {k: r[k] for k in self.FIELDS if k in r}
                for r in body.get("data") or []
                if isinstance(r, dict)
            ]
            cursor = (body.get("_meta") or {}).get("next_cursor")
            if not cursor:
                return records
            query = f"?cursor={quote(str(cursor), safe='')}&limit={self.PAGE}"
        raise RuntimeError(f"VulnCheck KEV: still more pages after {self.MAX_PAGES}")

    def records(self) -> list[dict[str, Any]]:
        fresh = self.path.is_file() and (time.time() - self.path.stat().st_mtime) < self.ttl
        if not fresh:
            try:
                records = self._download()
            except Exception as e:
                if not self.path.is_file():
                    raise
                log.warning("VulnCheck KEV download failed, using the cached copy: %s", e)
            else:
                self.path.parent.mkdir(parents=True, exist_ok=True)
                tmp = self.path.with_suffix(".tmp")
                tmp.write_text(json.dumps({"data": records}), encoding="utf-8")
                tmp.replace(self.path)
                return records
        return list(json.loads(self.path.read_bytes()).get("data") or [])

    def index(self) -> dict[str, dict[str, Any]]:
        """CVE id -> an entry shaped like CISA's (cveID, dateAdded, ...), kevSource VulnCheck."""
        out: dict[str, dict[str, Any]] = {}
        for r in self.records():
            for cve in r.get("cve") or []:
                cid = str(cve).strip().upper()
                if not cid:
                    continue
                out[cid] = {
                    "cveID": cid,
                    "vendorProject": str(r.get("vendorProject") or ""),
                    "product": str(r.get("product") or ""),
                    "vulnerabilityName": str(r.get("vulnerabilityName") or ""),
                    "shortDescription": str(r.get("shortDescription") or ""),
                    "requiredAction": str(r.get("required_action") or ""),
                    "knownRansomwareCampaignUse": str(r.get("knownRansomwareCampaignUse") or ""),
                    "dateAdded": str(r.get("date_added") or "")[:10],
                    "kevSource": VULNCHECK,
                }
        return out


class KevCache:
    """Downloads the CISA KEV JSON and caches it on disk (default TTL 6 h). With a
    VulnCheck KEV source, its index adds the CVEs CISA doesn't list (kevSource
    "VulnCheck"); if VulnCheck is unavailable it is CISA's alone, with a warning."""

    def __init__(
        self,
        cache_dir: Path,
        transport: Transport | None = None,
        ttl_seconds: int = 6 * 3600,
        url: str = KEV_URL,
        vulncheck: VulnCheckKev | None = None,
    ):
        self.path = cache_dir / "kev.json"
        self.ttl = ttl_seconds
        self.http = Http(url, transport=transport, timeout=60)
        self.vulncheck = vulncheck
        self._index: dict[str, dict] | None = None
        self._loaded_at = 0.0

    def _fresh_on_disk(self) -> bool:
        return self.path.is_file() and (time.time() - self.path.stat().st_mtime) < self.ttl

    def index(self) -> dict[str, dict]:
        if self._index is not None and time.time() - self._loaded_at < self.ttl:
            return self._index
        if not self._fresh_on_disk():
            r = self.http.get("")
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self.path.write_bytes(r.body)
        data = json.loads(self.path.read_bytes())
        index = {v["cveID"].upper(): {**v, "kevSource": CISA} for v in data.get("vulnerabilities", [])}
        cisa = len(index)
        if self.vulncheck is not None:
            try:
                for cid, entry in self.vulncheck.index().items():
                    index.setdefault(cid, entry)
            except Exception as e:
                log.warning("VulnCheck KEV unavailable, CISA KEV only: %s", e)
        self._index = index
        self._loaded_at = time.time()
        log.info("KEV loaded: %d entries (%d CISA)", len(index), cisa)
        return self._index


class Enricher:
    def __init__(
        self,
        *,
        cache_dir: Path,
        use_kev: bool = True,
        use_epss: bool = True,
        use_circl: bool = True,
        circl_url: str = "https://vulnerability.circl.lu",
        vulncheck_token: str = "",
        transport: Transport | None = None,
    ):
        self.use_kev, self.use_epss, self.use_circl = use_kev, use_epss, use_circl
        vulncheck = (
            VulnCheckKev(cache_dir, vulncheck_token, transport=transport)
            if vulncheck_token.strip()
            else None
        )
        self.kev = KevCache(cache_dir, transport=transport, vulncheck=vulncheck)
        self.epss_http = Http(EPSS_URL, transport=transport, timeout=30)
        self.circl_http = Http(
            circl_url, headers={"Accept": "application/json"}, transport=transport, timeout=30
        )

    def enrich(self, cves: Iterable[str]) -> dict[str, Signals]:
        ids = sorted({c.strip().upper() for c in cves if c and c.strip()})
        out = {c: Signals(cve=c) for c in ids}
        if not ids:
            return out
        if self.use_kev:
            try:
                idx = self.kev.index()
                for c in ids:
                    if c in idx:
                        out[c].kev = True
                        out[c].kev_source = str(idx[c].get("kevSource") or CISA)
                        out[c].kev_date_added = idx[c].get("dateAdded", "")
                        out[c].kev_name = str(idx[c].get("vulnerabilityName", ""))
                        out[c].kev_ransomware = (
                            str(idx[c].get("knownRansomwareCampaignUse", "")).lower() == "known"
                        )
            except Exception as e:  # keep going with the other sources
                log.warning("KEV lookup failed: %s", e)
                for s in out.values():
                    s.errors.append(f"kev: {e}")
        if self.use_epss:
            for chunk in _chunks(ids, 50):
                try:
                    r = self.epss_http.get(f"?cve={','.join(chunk)}")
                    for row in (r.json() or {}).get("data", []):
                        sig = out.get(row.get("cve", "").upper())
                        if sig:
                            sig.epss = float(row["epss"])
                            sig.epss_percentile = float(row.get("percentile", 0) or 0)
                except Exception as e:
                    log.warning("EPSS lookup failed: %s", e)
                    for c in chunk:
                        out[c].errors.append(f"epss: {e}")
        if self.use_circl:
            for c in ids:
                try:
                    # Ask for counts only (per_page=1 + metadata.count): popular CVEs
                    # have thousands of sightings and multi-MB responses otherwise.
                    counts: dict[str, int] = {}
                    for stype in SIGHTING_TYPES:
                        r = self.circl_http.get(
                            f"api/sighting/?vuln_id={quote(c)}&type={stype}&per_page=1"
                        )
                        n = int(((r.json() or {}).get("metadata") or {}).get("count") or 0)
                        if n:
                            counts[stype] = n
                    out[c].sightings = counts
                except Exception as e:
                    log.warning("CIRCL sightings lookup failed for %s: %s", c, e)
                    out[c].errors.append(f"circl: {e}")
        return out


def _chunks(seq: list[str], n: int) -> Iterable[list[str]]:
    for i in range(0, len(seq), n):
        yield seq[i : i + n]
