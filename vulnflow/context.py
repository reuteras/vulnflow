"""Asset context on Dependency-Track projects: exposure, input, criticality, eol/certified.

machines.toml says what each thing that runs is exposed to and how much it matters
(docs/exposure.md, step 1). This module turns that into project tags in Dependency-Track
(`exposure-internet`, `input-public`, `crit-high`, `flag-eol`, `flag-certified`), which
dt2dojo then carries to DefectDojo. Scoring doesn't use them yet (step 2).

Where a project's context comes from, first match wins:

1. [projects."<project name>"]: any project, e.g. one uploaded from CI;
2. host:<h>            -> [hosts.<h>] (the host project);
3. container:<image>   -> [hosts.<h>.images] of the host in its host-<h> tag, matched on
   the image name: the whole name, its last part (`nginx` for docker.io/library/nginx),
   or a glob (`ghcr.io/acme/*`); an exact name first, then the longest glob, so `"*"` is
   a catch-all for the host's other containers;
4. code:<name>         -> [code.<name>];
5. <name>              -> [github.<name>].

Never from a group: one group can run a public service and an internal admin page. A
project without context stays unknown (no tags), which step 2 will report.

The agents can't set these: Dependency-Track applies tags only when it creates a project,
and an upload-only key can't change them. So every dt2dojo round sets them with the
maintenance key (PORTFOLIO_MANAGEMENT), replacing only the context tags of a project and
keeping the rest; a change in machines.toml takes effect at the next round.
"""

from __future__ import annotations

import fnmatch
import json
from dataclasses import dataclass, field
from typing import Any

from .clients import DependencyTrack, DTProject, project_label
from .config import CRITICALITIES, EXPOSURES, INPUTS, AssetContext, Inventory, Machines

CONTEXT_PREFIXES = ("exposure-", "input-", "crit-", "flag-")


def _image_matches(pattern: str, image: str) -> bool:
    if any(c in pattern for c in "*?["):
        return fnmatch.fnmatchcase(image, pattern)
    return image == pattern or image.rsplit("/", 1)[-1] == pattern


def context_for(machines: Machines, p: DTProject) -> AssetContext | None:
    """The context machines.toml gives this project, or None (unknown: also an entry that
    exists but sets none of the keys)."""
    ctx = _context_for(machines, p)
    return ctx if ctx else None


def host_of(p: DTProject) -> str:
    return next((t.removeprefix("host-") for t in p.tags if t.startswith("host-")), "")


def _context_for(machines: Machines, p: DTProject) -> AssetContext | None:
    if p.name in machines.projects:
        return machines.projects[p.name]
    kind, _, rest = p.name.partition(":")
    host = host_of(p)
    if kind == "host" and rest in machines.hosts:
        return machines.hosts[rest].context
    if kind == "container" and host in machines.hosts:
        images = machines.hosts[host].images
        exact = [k for k in images if not any(c in k for c in "*?[")]
        # an exact name wins over a glob, a longer glob over a shorter one ("*" last)
        globs = sorted((k for k in images if k not in exact), key=len, reverse=True)
        for pattern in [*exact, *globs]:
            # an entry with no values (e.g. a `context --toml` stub not filled in yet) doesn't
            # hide a broader one that has them
            if _image_matches(pattern, rest) and images[pattern]:
                return images[pattern]
        return None
    if kind == "code" and rest in machines.code:
        return machines.code[rest].context
    if p.name in machines.github:
        return machines.github[p.name].context
    return None


def desired_tags(machines: Machines, p: DTProject) -> list[str]:
    """The project's tags with its context tags replaced by those machines.toml gives."""
    keep = [t for t in p.tags if not t.startswith(CONTEXT_PREFIXES)]
    ctx = context_for(machines, p)
    return sorted(set(keep) | set(ctx.tags() if ctx else []))


@dataclass
class ContextResult:
    changed: list[str] = field(default_factory=list)
    unknown: list[str] = field(default_factory=list)
    unknown_projects: list[DTProject] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


def apply_context(
    inv: Inventory, machines: Machines, dt: DependencyTrack, *, apply: bool = False
) -> ContextResult:
    """Set the context tags of the teams' active projects; a dry run unless apply."""
    res = ContextResult()
    seen: set[str] = set()
    for team in inv.teams.values():
        try:
            projects = dt.projects_by_tag(team.dtrack_tag)
        except Exception as e:
            res.errors.append(f"list DT projects for '{team.dtrack_tag}': {e}")
            continue
        for p in projects:
            if p.uuid in seen or not p.active:
                continue
            seen.add(p.uuid)
            label = project_label(p.name, p.version)
            if context_for(machines, p) is None:
                host = host_of(p)
                res.unknown.append(f"{label} (host {host})" if host else label)
                res.unknown_projects.append(p)
            want = desired_tags(machines, p)
            if want == sorted(set(p.tags)):
                continue
            old = sorted(t for t in p.tags if t.startswith(CONTEXT_PREFIXES))
            new = sorted(t for t in want if t.startswith(CONTEXT_PREFIXES))
            line = f"{label}: {', '.join(old) or '-'} -> {', '.join(new) or '-'}"
            if apply:
                try:
                    dt.set_tags(p.uuid, want)
                except Exception as e:
                    res.errors.append(f"{label}: {e}")
                    continue
            res.changed.append(line)
    return res


_EMPTY = 'exposure = "", input = "", criticality = ""'


def _key(name: str) -> str:
    """A TOML key: bare when it can be, else a quoted (JSON-escaped) string."""
    ok = name and all(c.isalnum() or c in "-_" for c in name)
    return name if ok else json.dumps(name)


def unknown_toml(machines: Machines, raw: dict[str, Any], projects: list[DTProject]) -> str:
    """machines.toml entries for the projects without context, with the host and image names
    filled in from Dependency-Track and the values left empty (empty = unknown, so the
    output loads as it is). `raw` is machines.toml as parsed TOML: a table that already
    exists there can't be written again, so its lines come under a comment instead."""
    raw_hosts = raw.get("hosts") or {}
    hosts: dict[str, dict[str, Any]] = {}  # host -> {"self": bool, "images": set}
    other: list[tuple[str, str]] = []  # (section header, comment)
    for p in projects:
        kind, _, rest = p.name.partition(":")
        host = host_of(p)
        if kind == "host" and rest in machines.hosts:
            hosts.setdefault(rest, {"self": False, "images": set()})["self"] = True
        elif kind == "container" and host in machines.hosts:
            hosts.setdefault(host, {"self": False, "images": set()})["images"].add(rest)
        elif kind == "code" and rest in machines.code:
            other.append((f"[code.{_key(rest)}]", "exists"))
        elif p.name in machines.github:
            other.append((f"[github.{_key(p.name)}]", "exists"))
        else:
            why = f"on host {host}, which isn't in machines.toml" if host else "from CI or upload-sbom"
            other.append((f"[projects.{json.dumps(p.name)}]", why))
    out = [
        "# Generated by `vulnflow context --toml`: the projects without exposure/criticality.",
        "# Fill in the values (empty = unknown), move the lines into machines.toml, delete the rest.",
        f"#   exposure:    {' | '.join(EXPOSURES)}",
        f"#   input:       {' | '.join(INPUTS)}",
        f"#   criticality: {' | '.join(CRITICALITIES)}",
        "#   eol, certified: true (leave out otherwise)",
    ]
    for h in sorted(hosts):
        entry = hosts[h]
        raw_h = raw_hosts.get(h) or {}
        if entry["self"]:
            out.append("")
            if h in raw_hosts:
                out.append(f"# add to your existing [hosts.{_key(h)}]:")
            else:
                out.append(f"[hosts.{_key(h)}]")
            out += ['exposure = ""', 'input = ""', 'criticality = ""']
        if entry["images"]:
            out.append("")
            if "images" in raw_h:
                out.append(f"# add to your existing [hosts.{_key(h)}.images]:")
            else:
                out.append(f"[hosts.{_key(h)}.images]")
            out += [f"{json.dumps(i)} = {{ {_EMPTY} }}" for i in sorted(entry["images"])]
    seen: set[str] = set()
    for header, why in sorted(other):
        if header in seen:
            continue
        seen.add(header)
        out.append("")
        if why == "exists":
            out.append(f"# add to your existing {header}:")
        else:
            out += [f"# {why}", header]
        out += ['exposure = ""', 'input = ""', 'criticality = ""']
    return "\n".join(out) + "\n"
