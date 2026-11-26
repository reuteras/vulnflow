"""Batch jobs: inventory sync and Dependency-Track -> DefectDojo transfer."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

from .clients import DefectDojo, DependencyTrack, DTProject, OpenCVE
from .config import Inventory, Machines, Team
from .dojo_tiers import apply_tiers
from .ranking import Ranker

log = logging.getLogger(__name__)

# DT project tags copied to DefectDojo (the agent sets them; team-* is there already)
# carried to DefectDojo: where it runs, what it is, and its asset context (context.py)
DOJO_TAG_PREFIXES = ("host-", "kind-", "group-", "exposure-", "input-", "crit-", "flag-")


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


def reimport_project(
    dojo: DefectDojo, team: Team, p: DTProject, fpf: bytes, engagement: str
) -> dict[str, Any]:
    """One DT project's FPF into its DefectDojo product/test (one test per version). The
    project's host-/kind-/group- tags go on the test and its findings, so DefectDojo can
    filter by host or kind (a product such as container:nginx spans hosts)."""
    extra = sorted(t for t in p.tags if t.startswith(DOJO_TAG_PREFIXES))
    return dojo.reimport(
        scan_type=DefectDojo.FPF_SCAN_TYPE,
        report=fpf,
        filename=f"{p.name}-{p.version or 'na'}.fpf.json",
        product_name=p.name,
        product_type=team.defectdojo_product_type,
        engagement=engagement,
        tags=[team.dtrack_tag, "source-dtrack", *extra],
        test_title=f"Dependency-Track {p.version}".strip(),
        version=p.version,
        apply_tags_to_findings=True,
    )


def dt_to_dojo(
    inv: Inventory,
    dtrack: DependencyTrack,
    dojo: DefectDojo,
    *,
    engagement: str = "Dependency-Track",
    dry_run: bool = False,
    maintenance: DependencyTrack | None = None,
    machines: Machines | None = None,
    ranker: Ranker | None = None,
) -> Report:
    """Copy findings per DT project into DefectDojo, routed to the owning team's product type.

    Re-import with close_old_findings means a component fixed in DT gets its finding
    closed in DefectDojo on the next run; triage notes/status live in DefectDojo.
    With a `maintenance` client (DT_MAINTENANCE_API_KEY) each round starts with `prune`:
    decisions carried to new versions, stale versions deactivated and closed in DefectDojo.
    """
    rep = Report()
    if maintenance is not None:
        from .prune import prune

        pr = prune(inv, maintenance, dojo, apply=not dry_run, engagement=engagement)
        tag = "[dry-run] " if dry_run else ""
        rep.done += [f"{tag}prune: carried {line}" for line in pr.carried]
        rep.done += [f"{tag}prune: deactivated {line}" for line in pr.deactivated]
        rep.done += [f"{tag}prune: reactivated {line}" for line in pr.reactivated]
        rep.done += [f"{tag}prune: review date passed, shown again: {line}" for line in pr.reopened]
        rep.errors += [f"prune: {e}" for e in pr.errors]
        if machines is not None:
            from .context import apply_context

            cx = apply_context(inv, machines, maintenance, apply=not dry_run)
            rep.done += [f"{tag}context: {line}" for line in cx.changed]
            rep.errors += [f"context: {e}" for e in cx.errors]
    inactive = 0
    for team in inv.teams.values():
        try:
            projects = dtrack.projects_by_tag(team.dtrack_tag)
        except Exception as e:
            rep.errors.append(f"list DT projects for '{team.dtrack_tag}': {e}")
            continue
        for p in projects:
            label = f"{p.name}@{p.version or '-'} -> {team.defectdojo_product_type}"
            if not p.active:  # retired by prune (or by hand); its findings are closed
                inactive += 1
                continue
            if dry_run:
                rep.done.append(f"[dry-run] {label}")
                continue
            try:
                fpf = dtrack.export_fpf(p.uuid)
                res = reimport_project(dojo, team, p, fpf, engagement)
                stats = res.get("statistics", {}).get("after", {}).get("total", {})
                tiers = ""
                test_id = res.get("test_id") or res.get("test")
                if ranker is not None and test_id:
                    try:
                        updated, ranked = apply_tiers(dojo, int(test_id), p, fpf, ranker)
                        tiers = f", tiers: {updated} of {ranked} updated" if updated else ""
                    except Exception as e:  # the import itself worked
                        rep.errors.append(f"{label}: tiers in DefectDojo: {e}")
                rep.done.append(f"{label} (active findings: {stats.get('active', '?')}{tiers})")
            except Exception as e:
                rep.errors.append(f"{label}: {e}")
    if inactive:
        rep.done.append(f"{inactive} inactive project(s) skipped (retired versions)")
    return rep
