"""Batch jobs: inventory sync and Dependency-Track -> DefectDojo transfer."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field

from .clients import DefectDojo, DependencyTrack, OpenCVE
from .config import Inventory

log = logging.getLogger(__name__)


@dataclass
class Report:
    done: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    def print(self) -> None:
        for line in self.done:
            print(f"  ok    {line}")
        for line in self.warnings:
            print(f"  WARN  {line}")
        for line in self.errors:
            print(f"  ERROR {line}")


def sync_inventory(
    inv: Inventory,
    *,
    opencve: OpenCVE | None,
    dtrack: DependencyTrack | None,
    dojo: DefectDojo | None,
    create_projects: bool = False,
    dry_run: bool = False,
) -> Report:
    rep = Report()
    for team in inv.teams.values():
        n_products = sum(len(v) for v in team.products.values())
        # ---- OpenCVE: per-team project subscriptions
        if opencve:
            try:
                if not opencve.project_exists(team.opencve_project):
                    if create_projects and not dry_run:
                        opencve.create_project(team.opencve_project, team.display_name)
                        rep.done.append(f"OpenCVE: created project '{team.opencve_project}'")
                    else:
                        rep.warnings.append(
                            f"OpenCVE: project '{team.opencve_project}' missing - create it in "
                            f"the UI (or rerun with --create-projects)"
                        )
                        continue
                if dry_run:
                    rep.done.append(
                        f"[dry-run] OpenCVE '{team.opencve_project}': would set "
                        f"{len(team.vendors)} vendors, {n_products} products"
                    )
                else:
                    opencve.put_subscriptions(team.opencve_project, team.vendors, team.products)
                    rep.done.append(
                        f"OpenCVE '{team.opencve_project}': "
                        f"{len(team.vendors)} vendors, {n_products} products"
                    )
            except Exception as e:
                rep.errors.append(f"OpenCVE '{team.opencve_project}': {e}")
        # ---- DefectDojo: one product type per team
        if dojo:
            try:
                if dry_run:
                    rep.done.append(
                        f"[dry-run] DefectDojo: would ensure product type "
                        f"'{team.defectdojo_product_type}'"
                    )
                else:
                    pt = dojo.ensure_product_type(team.defectdojo_product_type, team.display_name)
                    rep.done.append(
                        f"DefectDojo product type '{team.defectdojo_product_type}' (id {pt})"
                    )
            except Exception as e:
                rep.errors.append(f"DefectDojo '{team.defectdojo_product_type}': {e}")
        # ---- Dependency-Track: report coverage per team tag
        if dtrack:
            try:
                projs = dtrack.projects_by_tag(team.dtrack_tag)
                if projs:
                    rep.done.append(f"Dependency-Track tag '{team.dtrack_tag}': {len(projs)} project(s)")
                else:
                    rep.warnings.append(
                        f"Dependency-Track: no projects tagged '{team.dtrack_tag}' yet - upload an SBOM"
                    )
            except Exception as e:
                rep.errors.append(f"Dependency-Track tag '{team.dtrack_tag}': {e}")
    return rep


def dt_to_dojo(
    inv: Inventory,
    dtrack: DependencyTrack,
    dojo: DefectDojo,
    *,
    engagement: str = "Dependency-Track",
    dry_run: bool = False,
) -> Report:
    """Copy findings per DT project into DefectDojo, routed to the owning team's product type.

    Re-import with close_old_findings means a component fixed in DT gets its finding
    closed in DefectDojo on the next run; triage notes/status live in DefectDojo.
    """
    rep = Report()
    for team in inv.teams.values():
        try:
            projects = dtrack.projects_by_tag(team.dtrack_tag)
        except Exception as e:
            rep.errors.append(f"list DT projects for '{team.dtrack_tag}': {e}")
            continue
        for p in projects:
            label = f"{p.name}@{p.version or '-'} -> {team.defectdojo_product_type}"
            if not p.active:
                rep.warnings.append(f"skip inactive {label}")
                continue
            if dry_run:
                rep.done.append(f"[dry-run] {label}")
                continue
            try:
                fpf = dtrack.export_fpf(p.uuid)
                res = dojo.reimport(
                    scan_type=DefectDojo.FPF_SCAN_TYPE,
                    report=fpf,
                    filename=f"{p.name}-{p.version or 'na'}.fpf.json",
                    product_name=p.name,
                    product_type=team.defectdojo_product_type,
                    engagement=engagement,
                    tags=[team.dtrack_tag, "source-dtrack"],
                    test_title=f"Dependency-Track {p.version}".strip(),
                )
                stats = res.get("statistics", {}).get("after", {}).get("total", {})
                rep.done.append(f"{label} (active findings: {stats.get('active', '?')})")
            except Exception as e:
                rep.errors.append(f"{label}: {e}")
    return rep
