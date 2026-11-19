"""Exploitation signals: CISA KEV, FIRST EPSS, CIRCL Vulnerability-Lookup sightings.

OPSEC note: every lookup sends the CVE ID to a third party. CVE IDs alone reveal
*interest*, not exposure, but if that is unacceptable, disable the sources in .env
and mirror KEV/EPSS internally (both are plain downloadable files), and run your
own Vulnerability-Lookup instance.
"""

from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable
from urllib.parse import quote

from .net import Http, Transport

log = logging.getLogger(__name__)

KEV_URL = ("https://www.cisa.gov/sites/default/files/feeds/"
           "known_exploited_vulnerabilities.json")
EPSS_URL = "https://api.first.org/data/v1/epss"
SIGHTING_TYPES = ("exploited", "published-proof-of-concept", "seen")


@dataclass
class Signals:
    cve: str
    kev: bool = False
    kev_ransomware: bool = False
    kev_date_added: str = ""
    epss: float | None = None
    epss_percentile: float | None = None
    sightings: dict[str, int] = field(default_factory=dict)  # type -> count
    errors: list[str] = field(default_factory=list)

    @property
    def exploited_sightings(self) -> int:
        return self.sightings.get("exploited", 0)


class KevCache:
    """Downloads the CISA KEV JSON and caches it on disk (default TTL 6 h)."""

    def __init__(self, cache_dir: Path, transport: Transport | None = None,
                 ttl_seconds: int = 6 * 3600, url: str = KEV_URL):
        self.path = cache_dir / "kev.json"
        self.ttl = ttl_seconds
        self.http = Http(url, transport=transport, timeout=60)
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
        self._index = {v["cveID"].upper(): v for v in data.get("vulnerabilities", [])}
        self._loaded_at = time.time()
        log.info("KEV loaded: %d entries", len(self._index))
        return self._index


class Enricher:
    def __init__(self, *, cache_dir: Path, use_kev: bool = True, use_epss: bool = True,
                 use_circl: bool = True, circl_url: str = "https://vulnerability.circl.lu",
                 transport: Transport | None = None):
        self.use_kev, self.use_epss, self.use_circl = use_kev, use_epss, use_circl
        self.kev = KevCache(cache_dir, transport=transport)
        self.epss_http = Http(EPSS_URL, transport=transport, timeout=30)
        self.circl_http = Http(circl_url, headers={"Accept": "application/json"},
                               transport=transport, timeout=30)

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
                        out[c].kev_date_added = idx[c].get("dateAdded", "")
                        out[c].kev_ransomware = (
                            str(idx[c].get("knownRansomwareCampaignUse", "")).lower() == "known")
            except Exception as e:  # keep going with the other sources
                log.warning("KEV lookup failed: %s", e)
                for s in out.values():
                    s.errors.append(f"kev: {e}")
        if self.use_epss:
            for chunk in _chunks(ids, 50):
                try:
                    r = self.epss_http.get(f"?cve={','.join(chunk)}")
                    for row in (r.json() or {}).get("data", []):
                        s = out.get(row.get("cve", "").upper())
                        if s:
                            s.epss = float(row["epss"])
                            s.epss_percentile = float(row.get("percentile", 0) or 0)
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
                            f"api/sighting/?vuln_id={quote(c)}&type={stype}&per_page=1")
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
        yield seq[i:i + n]
