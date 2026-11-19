"""Thin API clients for OpenCVE (API v2), Dependency-Track (API v1) and DefectDojo (API v2).

Endpoints used, and how sure we are of them:

OpenCVE  (checked against the OpenAPI schema at app.opencve.io/api/v2/schema/, Nov 2026;
          self-hosted Community releases may lag - compare with <your-opencve>/api/v2/docs/)
  PUT   /api/v2/organizations/{org}/projects/{project}/subscriptions
  GET   /api/v2/organizations/{org}/projects/{name}
  POST  /api/v2/organizations/{org}/projects             {"name","description","active"}
  GET   /api/v2/organizations/{org}/projects/{project}/cves/{cve_id}   -> {"tracker": {...}|null}
  PATCH /api/v2/organizations/{org}/projects/{project}/cves/{cve_id}   {"status", "assignee"}
        status enum: to_evaluate, pending_review, analysis_in_progress,
        remediation_in_progress, evaluated, resolved, not_applicable, risk_accepted
Dependency-Track
  PUT  /api/v1/bom  (JSON, base64 BOM, projectTags)                    documented
  GET  /api/v1/project/tag/{tag}                                        documented
  GET  /api/v1/finding/project/{uuid}/export  (FPF)                    documented
DefectDojo
  GET/POST /api/v2/product_types/                                       documented
  POST /api/v2/reimport-scan/  scan_type "Dependency Track Finding
       Packaging Format (FPF) Export", auto_create_context=true          documented
"""

from __future__ import annotations

import base64
import logging
from dataclasses import dataclass
from typing import Any
from urllib.parse import quote

from .net import Http, Transport, multipart

log = logging.getLogger(__name__)


# --------------------------------------------------------------------------- OpenCVE
class OpenCVE:
    def __init__(self, base_url: str, org: str, token: str,
                 transport: Transport | None = None):
        self.org = org
        self.http = Http(f"{base_url.rstrip('/')}/api/v2",
                         headers={"Authorization": f"Bearer {token}",
                                  "Accept": "application/json"},
                         transport=transport)

    def _proj(self, project: str) -> str:
        return f"organizations/{quote(self.org)}/projects/{quote(project)}"

    TRIAGE_STATUSES = ("to_evaluate", "pending_review", "analysis_in_progress",
                       "remediation_in_progress", "evaluated", "resolved",
                       "not_applicable", "risk_accepted")

    def project_exists(self, project: str) -> bool:
        r = self.http.get(self._proj(project), expect_ok=False)
        if r.status == 404:
            return False
        if not r.ok:
            self.http.get(self._proj(project))  # raise with details
        return True

    def create_project(self, project: str, description: str) -> None:
        self.http.post(f"organizations/{quote(self.org)}/projects",
                       json_body={"name": project, "description": description,
                                  "active": True})

    def get_tracker(self, project: str, cve_id: str) -> dict[str, Any] | None:
        """Triage state of a CVE in a project, or None if untouched."""
        r = self.http.get(f"{self._proj(project)}/cves/{quote(cve_id)}")
        return (r.json() or {}).get("tracker")

    def set_status(self, project: str, cve_id: str, status: str,
                   assignee: str | None = None) -> None:
        if status not in self.TRIAGE_STATUSES:
            raise ValueError(f"unknown OpenCVE status {status!r}")
        body: dict[str, Any] = {"status": status}
        if assignee:
            body["assignee"] = assignee
        self.http.request("PATCH", f"{self._proj(project)}/cves/{quote(cve_id)}",
                          json_body=body)

    def put_subscriptions(self, project: str, vendors: list[str],
                          products: dict[str, list[str]]) -> None:
        """Replace the project's whole subscription set (documented PUT semantics)."""
        self.http.put(f"{self._proj(project)}/subscriptions",
                      json_body={"vendors": vendors, "products": products})


# --------------------------------------------------------------------- Dependency-Track
@dataclass
class DTProject:
    uuid: str
    name: str
    version: str
    active: bool
    tags: list[str]


class DependencyTrack:
    PAGE = 100

    def __init__(self, base_url: str, api_key: str, transport: Transport | None = None):
        self.http = Http(base_url, headers={"X-Api-Key": api_key,
                                            "Accept": "application/json"},
                         transport=transport, timeout=120)

    def projects_by_tag(self, tag: str) -> list[DTProject]:
        out: list[DTProject] = []
        page = 1
        while True:
            r = self.http.get(f"api/v1/project/tag/{quote(tag)}"
                              f"?pageSize={self.PAGE}&pageNumber={page}")
            items: list[dict[str, Any]] = r.json() or []
            for p in items:
                out.append(DTProject(
                    uuid=p["uuid"], name=p.get("name", ""),
                    version=p.get("version") or "",
                    # v4 uses "active"; some v5 builds expose "inactiveSince" instead
                    active=bool(p.get("active", p.get("inactiveSince") is None)),
                    tags=[t.get("name", "") for t in p.get("tags") or []]))
            total = int(r.headers.get("X-Total-Count", len(out)) or len(out))
            if len(items) < self.PAGE or len(out) >= total:
                return out
            page += 1

    def upload_bom(self, name: str, version: str, bom: bytes, tags: list[str]) -> str:
        body = {"projectName": name, "projectVersion": version, "autoCreate": True,
                "bom": base64.b64encode(bom).decode(),
                "projectTags": [{"name": t} for t in tags]}
        r = self.http.put("api/v1/bom", json_body=body)
        return (r.json() or {}).get("token", "")

    def export_fpf(self, project_uuid: str) -> bytes:
        return self.http.get(f"api/v1/finding/project/{project_uuid}/export").body


# ------------------------------------------------------------------------ DefectDojo
class DefectDojo:
    FPF_SCAN_TYPE = "Dependency Track Finding Packaging Format (FPF) Export"

    def __init__(self, base_url: str, api_key: str, transport: Transport | None = None):
        self.http = Http(f"{base_url.rstrip('/')}/api/v2",
                         headers={"Authorization": f"Token {api_key}",
                                  "Accept": "application/json"},
                         transport=transport, timeout=300)

    def ensure_product_type(self, name: str, description: str = "") -> int:
        r = self.http.get(f"product_types/?name={quote(name)}")
        for pt in (r.json() or {}).get("results", []):
            if pt.get("name") == name:
                return int(pt["id"])
        r = self.http.post("product_types/", json_body={
            "name": name, "description": description or f"Managed by vulnflow: {name}"})
        return int(r.json()["id"])

    def reimport(self, *, scan_type: str, report: bytes, filename: str,
                 product_name: str, product_type: str, engagement: str,
                 tags: list[str], test_title: str = "") -> dict[str, Any]:
        fields: dict[str, str | list[str]] = {
            "scan_type": scan_type,
            "product_name": product_name,
            "product_type_name": product_type,
            "engagement_name": engagement,
            "auto_create_context": "true",
            "deduplication_on_engagement": "true",
            "close_old_findings": "true",   # fixed in DT => closed in Dojo
            "do_not_reactivate": "false",
            "tags": tags,
        }
        if test_title:
            fields["test_title"] = test_title
        body, ctype = multipart(fields, {"file": (filename, report, "application/json")})
        r = self.http.post("reimport-scan/", body=body, headers={"Content-Type": ctype})
        return r.json() or {}
