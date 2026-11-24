"""Thin API clients for OpenCVE (API v2), Dependency-Track (API v1) and DefectDojo (API v2).

Endpoints used, and how sure we are of them:

OpenCVE  (checked against the v3.1.0 tag's source: web/opencve/api/v2/)
  PUT   /api/v2/organizations/{org}/projects/{project}/subscriptions
  GET   /api/v2/organizations/{org}/projects/{name}
  GET   /api/v2/vendors/{vendor}/products/{product}/cves?page_size=1   {"count": N}; 404 =
        no such vendor/product (catalog.py ProductCveViewSet, DRF PageNumberPagination)
  POST  /api/v2/organizations/{org}/projects             {"name","description","active"}
  GET   /api/v2/organizations/{org}/projects/{project}/cves/{cve_id}   -> {"tracker": {...}|null}
  PATCH /api/v2/organizations/{org}/projects/{project}/cves/{cve_id}   {"status", "assignee"}
        status enum: to_evaluate, pending_review, analysis_in_progress,
        remediation_in_progress, evaluated, resolved, not_applicable, risk_accepted
  Webhook notifications are NOT created through the API: v3.1.0 rejects every private URL
  there. See stacks/opencve/bootstrap_webhooks.py (Django shell, run by poc.sh).
Dependency-Track
  PUT  /api/v1/bom  (JSON, base64 BOM, projectTags)                    documented
  GET  /api/v1/project/tag/{tag}                                        documented
       lastBomImport: a Date (Project.java in the 5.2.2 tag); epoch ms or ISO-8601 accepted
  GET  /api/v1/finding/project/{uuid}/export  (FPF)                    documented
  GET  /api/v1/component/project/{uuid}  paginated, VIEW_PORTFOLIO; cpe, purl, classifier
       (ComponentResource/Component.java in the 5.2.2 tag)
  GET  /api/v1/finding/project/{uuid}  paginated; component, vulnerability{source,vulnId,
       severity}, analysis{isSuppressed}. ASSUMED field names: not yet checked against a tag.
  GET  /api/v1/vulnerability/source/{source}/vuln/{vulnId}  patchedVersions (free text, only
       set by some sources, e.g. GITHUB/OSV; NVD has none). ASSUMED: check against the tag.
OSV (opt-in, see class OSV)
  POST https://api.osv.dev/v1/query                                     documented
DefectDojo
  GET/POST /api/v2/product_types/                                       documented
  POST /api/v2/reimport-scan/  scan_type "Dependency Track Finding
       Packaging Format (FPF) Export", auto_create_context=true          documented
"""

from __future__ import annotations

import base64
import logging
from dataclasses import dataclass
from datetime import datetime
from typing import Any
from urllib.parse import quote

from .net import Http, Transport, multipart

log = logging.getLogger(__name__)


# --------------------------------------------------------------------------- OpenCVE
class OpenCVE:
    def __init__(self, base_url: str, org: str, token: str, transport: Transport | None = None):
        self.org = org
        self.http = Http(
            f"{base_url.rstrip('/')}/api/v2",
            headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
            transport=transport,
        )

    def _proj(self, project: str) -> str:
        return f"organizations/{quote(self.org)}/projects/{quote(project)}"

    TRIAGE_STATUSES = (
        "to_evaluate",
        "pending_review",
        "analysis_in_progress",
        "remediation_in_progress",
        "evaluated",
        "resolved",
        "not_applicable",
        "risk_accepted",
    )

    def project_exists(self, project: str) -> bool:
        r = self.http.get(self._proj(project), expect_ok=False)
        if r.status == 404:
            return False
        if not r.ok:
            self.http.get(self._proj(project))  # raise with details
        return True

    def cve_count(self, vendor: str, product: str) -> int | None:
        """CVEs OpenCVE has for vendor/product; None if it doesn't know the name (a
        subscription to an unknown name fails)."""
        path = f"vendors/{quote(vendor, safe='')}/products/{quote(product, safe='')}/cves?page_size=1"
        r = self.http.get(path, expect_ok=False)
        if r.status == 404:
            return None
        if not r.ok:
            self.http.get(path)  # raise with details
        return int((r.json() or {}).get("count") or 0)

    def create_project(self, project: str, description: str) -> None:
        self.http.post(
            f"organizations/{quote(self.org)}/projects",
            json_body={"name": project, "description": description, "active": True},
        )

    def get_tracker(self, project: str, cve_id: str) -> dict[str, Any] | None:
        """Triage state of a CVE in a project, or None if untouched."""
        r = self.http.get(f"{self._proj(project)}/cves/{quote(cve_id)}")
        return (r.json() or {}).get("tracker")

    def set_status(self, project: str, cve_id: str, status: str, assignee: str | None = None) -> None:
        if status not in self.TRIAGE_STATUSES:
            raise ValueError(f"unknown OpenCVE status {status!r}")
        body: dict[str, Any] = {"status": status}
        if assignee:
            body["assignee"] = assignee
        self.http.request("PATCH", f"{self._proj(project)}/cves/{quote(cve_id)}", json_body=body)

    def put_subscriptions(
        self, project: str, vendors: list[str], products: dict[str, list[str]]
    ) -> None:
        """Replace the project's whole subscription set (documented PUT semantics)."""
        self.http.put(
            f"{self._proj(project)}/subscriptions", json_body={"vendors": vendors, "products": products}
        )


# --------------------------------------------------------------------- Dependency-Track
@dataclass
class DTProject:
    uuid: str
    name: str
    version: str
    active: bool
    tags: list[str]
    last_bom_import: float | None = None  # epoch seconds
    # when it was deactivated (epoch seconds); DT 5.2.2 sets inactiveSince on PATCH
    # active=false and clears it on reactivation (seen live 2026-11-24)
    inactive_since: float | None = None


def project_label(name: str, version: str = "") -> str:
    """How a project is shown: `container:nginx@1.31` — two hosts can run the same image name
    at different tags, which are separate projects that would otherwise look like one."""
    return f"{name}@{version}" if version else name


def _epoch(value: Any) -> float | None:
    """DT dates come as epoch milliseconds (Jackson default); accept ISO-8601 too."""
    if isinstance(value, int | float):
        return value / 1000
    if isinstance(value, str) and value:
        try:
            return datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()
        except ValueError:
            return None
    return None


class DependencyTrack:
    PAGE = 100

    def __init__(self, base_url: str, api_key: str, transport: Transport | None = None):
        self.http = Http(
            base_url,
            headers={"X-Api-Key": api_key, "Accept": "application/json"},
            transport=transport,
            timeout=120,
        )

    def projects_by_tag(self, tag: str) -> list[DTProject]:
        out: list[DTProject] = []
        page = 1
        while True:
            r = self.http.get(f"api/v1/project/tag/{quote(tag)}?pageSize={self.PAGE}&pageNumber={page}")
            items: list[dict[str, Any]] = r.json() or []
            for p in items:
                out.append(
                    DTProject(
                        uuid=p["uuid"],
                        name=p.get("name", ""),
                        version=p.get("version") or "",
                        # v4 uses "active"; some v5 builds expose "inactiveSince" instead
                        active=bool(p.get("active", p.get("inactiveSince") is None)),
                        tags=[t.get("name", "") for t in p.get("tags") or []],
                        last_bom_import=_epoch(p.get("lastBomImport")),
                        inactive_since=_epoch(p.get("inactiveSince")),
                    )
                )
            total = int(r.headers.get("X-Total-Count", len(out)) or len(out))
            if len(items) < self.PAGE or len(out) >= total:
                return out
            page += 1

    def components(self, project_uuid: str) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        page = 1
        while True:
            r = self.http.get(
                f"api/v1/component/project/{project_uuid}?pageSize={self.PAGE}&pageNumber={page}"
            )
            items: list[dict[str, Any]] = r.json() or []
            out.extend(items)
            total = int(r.headers.get("X-Total-Count", len(out)) or len(out))
            if len(items) < self.PAGE or len(out) >= total:
                return out
            page += 1

    def component_properties(self, component_uuid: str) -> list[dict[str, Any]]:
        """The component's properties (groupName, propertyName, propertyValue). A syft
        property `syft:location:0:path` arrives as group `syft`, name `location:0:path`
        (seen live on DT 5.2.2, 2026-11-24); the component list leaves properties out."""
        r = self.http.get(f"api/v1/component/{component_uuid}/property")
        return list(r.json() or [])

    def findings(self, project_uuid: str, suppressed: bool = False) -> list[dict[str, Any]]:
        """Findings of a project (component, vulnerability, analysis {state, isSuppressed}),
        paginated; suppressed ones only when asked."""
        out: list[dict[str, Any]] = []
        page = 1
        extra = "&suppressed=true" if suppressed else ""
        while True:
            r = self.http.get(
                f"api/v1/finding/project/{project_uuid}?pageSize={self.PAGE}&pageNumber={page}{extra}"
            )
            items: list[dict[str, Any]] = r.json() or []
            out.extend(items)
            total = int(r.headers.get("X-Total-Count", len(out)) or len(out))
            if len(items) < self.PAGE or len(out) >= total:
                return out
            page += 1

    def vulnerability(self, source: str, vuln_id: str) -> dict[str, Any] | None:
        """Full vulnerability record (has vulnerableVersions/patchedVersions); None if unknown."""
        r = self.http.get(
            f"api/v1/vulnerability/source/{quote(source, safe='')}/vuln/{quote(vuln_id, safe='')}",
            expect_ok=False,
        )
        if r.status == 404:
            return None
        if not r.ok:
            self.http.get(
                f"api/v1/vulnerability/source/{quote(source, safe='')}/vuln/{quote(vuln_id, safe='')}"
            )  # raise with details
        return r.json() or None

    def upload_bom(self, name: str, version: str, bom: bytes, tags: list[str]) -> str:
        body = {
            "projectName": name,
            "projectVersion": version,
            "autoCreate": True,
            "bom": base64.b64encode(bom).decode(),
            "projectTags": [{"name": t} for t in tags],
        }
        r = self.http.put("api/v1/bom", json_body=body)
        return (r.json() or {}).get("token", "")

    def set_active(self, project_uuid: str, active: bool) -> None:
        """PATCH /api/v1/project/{uuid} {"active": ...}; needs PORTFOLIO_MANAGEMENT
        (ProjectResource.patchProject, DT 5.2.2)."""
        self.http.request("PATCH", f"api/v1/project/{project_uuid}", json_body={"active": active})

    def export_fpf(self, project_uuid: str) -> bytes:
        return self.http.get(f"api/v1/finding/project/{project_uuid}/export").body


# ------------------------------------------------------------------------------- OSV
class OSV:
    """osv.dev query API (public, no key). Sends package URLs to an outside service, so it
    is only used when the operator asks for it (`patches --osv`).

    POST /v1/query {"package": {"purl": "pkg:...@version"}} -> {"vulns": [...],
    "next_page_token": "..."}; each vuln has id, aliases and affected[].ranges[].events[]
    with {"fixed": "<version>"}. Documented; the purl-with-version form is used because the
    version field must not be combined with a purl that already has one. ASSUMED: that
    OSV resolves deb/other purls the way DT's own ecosystems do (not checked)."""

    def __init__(self, base_url: str = "https://api.osv.dev", transport: Transport | None = None):
        self.http = Http(base_url, transport=transport, timeout=30)

    @staticmethod
    def clean_purl(purl: str) -> str:
        """Drop qualifiers/subpath (?distro=..., #...); keep name and @version."""
        return purl.split("?", 1)[0].split("#", 1)[0]

    def vulns_for(self, purl: str) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        body: dict[str, Any] = {"package": {"purl": self.clean_purl(purl)}}
        while True:
            data = self.http.post("v1/query", json_body=body).json() or {}
            out.extend(data.get("vulns") or [])
            token = data.get("next_page_token")
            if not token:
                return out
            body = {**body, "page_token": token}

    @staticmethod
    def fixed_in(vulns: list[dict[str, Any]], vuln_id: str, name: str) -> list[str]:
        """Fixed versions OSV lists for vuln_id (matched on id or alias). Entries for the
        component's own package name win; otherwise all entries of the matching vuln."""
        by_name: list[str] = []
        anywhere: list[str] = []
        for v in vulns:
            if vuln_id != v.get("id") and vuln_id not in (v.get("aliases") or []):
                continue
            for aff in v.get("affected") or []:
                fixed = [
                    str(ev["fixed"])
                    for rng in aff.get("ranges") or []
                    for ev in rng.get("events") or []
                    if ev.get("fixed")
                ]
                anywhere.extend(fixed)
                if str((aff.get("package") or {}).get("name", "")).lower() == name.lower():
                    by_name.extend(fixed)
        return list(dict.fromkeys(by_name or anywhere))


# ------------------------------------------------------------------------ DefectDojo
class DefectDojo:
    FPF_SCAN_TYPE = "Dependency Track Finding Packaging Format (FPF) Export"

    def __init__(self, base_url: str, api_key: str, transport: Transport | None = None):
        self.http = Http(
            f"{base_url.rstrip('/')}/api/v2",
            headers={"Authorization": f"Token {api_key}", "Accept": "application/json"},
            transport=transport,
            timeout=300,
        )

    def ensure_product_type(self, name: str, description: str = "") -> int:
        r = self.http.get(f"product_types/?name={quote(name)}")
        for pt in (r.json() or {}).get("results", []):
            if pt.get("name") == name:
                return int(pt["id"])
        r = self.http.post(
            "product_types/",
            json_body={"name": name, "description": description or f"Managed by vulnflow: {name}"},
        )
        return int(r.json()["id"])

    def reimport(
        self,
        *,
        scan_type: str,
        report: bytes,
        filename: str,
        product_name: str,
        product_type: str,
        engagement: str,
        tags: list[str],
        test_title: str = "",
        version: str = "",
        apply_tags_to_findings: bool = False,
    ) -> dict[str, Any]:
        """POST reimport-scan/. `tags` replace the test's tags (DefectDojo 3.5.201
        ReImportScanSerializer); with apply_tags_to_findings they go on its findings too.
        `version` is set on the test."""
        fields: dict[str, str | list[str]] = {
            "scan_type": scan_type,
            "product_name": product_name,
            "product_type_name": product_type,
            "engagement_name": engagement,
            "auto_create_context": "true",
            "deduplication_on_engagement": "true",
            "close_old_findings": "true",  # fixed in DT => closed in Dojo
            "do_not_reactivate": "false",
            "tags": tags,
        }
        if test_title:
            fields["test_title"] = test_title
        if version:
            fields["version"] = version
        if apply_tags_to_findings:
            fields["apply_tags_to_findings"] = "true"
        body, ctype = multipart(fields, {"file": (filename, report, "application/json")})
        r = self.http.post("reimport-scan/", body=body, headers={"Content-Type": ctype})
        return r.json() or {}
