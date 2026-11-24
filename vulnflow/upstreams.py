"""Upstream versions of the stacks poc.sh installs: `python -m vulnflow check-updates`.

Each component has three versions:

    running   what this server runs: DD_REF / OPENCVE_REF in .env, the image tag of the
              running Dependency-Track apiserver container
    pinned    the reviewed version in the repository: DD_REF / OPENCVE_REF in .env.example,
              the image tag in stacks/dependency-track/docker-compose.yml
    upstream  the newest GitHub release (no drafts or prereleases) that is at least
              COOLDOWN_DAYS old, the same wait as Dependabot (AGENTS.md "Cooldown")

and two possible actions:

    upstream > pinned   bump the pin in the repository. DD_REF and OPENCVE_REF by hand after
                        the checks in AGENTS.md ("Bootstrap invariants"); the DT images come
                        as a Dependabot PR.
    pinned > running    ./poc.sh upgrade <component> (dump of its database, then deploy).

Releases younger than the cooldown are listed as information only. Upstream behaviour relied
on (checked 2026-11-24): GET https://api.github.com/repos/<repo>/releases returns
`tag_name`, `draft`, `prerelease`, `published_at` (ISO 8601, Z); DefectDojo tags `3.5.201`,
OpenCVE `v3.1.0`, Dependency-Track 5.x is released from DependencyTrack/dependency-track
next to a 4.x line (so only the pinned major is compared). Anonymous API use allows 60
requests an hour, three per run.
"""

from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

from .net import Http, HttpError, Transport
from .versions import version_key

COOLDOWN_DAYS = 7
DT_COMPOSE = "stacks/dependency-track/docker-compose.yml"
DT_PROJECT = "vulnflow-dtrack"


@dataclass(frozen=True)
class Component:
    name: str  # poc.sh upgrade <name>
    title: str
    repo: str  # GitHub owner/name
    same_major: bool  # compare only within the pinned major (parallel release lines)


COMPONENTS = (
    Component("dojo", "DefectDojo", "DefectDojo/django-DefectDojo", same_major=False),
    Component("opencve", "OpenCVE", "opencve/opencve", same_major=False),
    Component("dtrack", "Dependency-Track", "DependencyTrack/dependency-track", same_major=True),
)


@dataclass(frozen=True)
class Release:
    tag: str
    published: datetime


@dataclass
class Status:
    component: Component
    running: str
    pinned: str
    upstream: Release | None  # newest release past the cooldown
    waiting: Release | None  # newer release still in the cooldown
    error: str = ""

    def lines(self) -> list[str]:
        c = self.component
        out = [f"{c.title}: running {self.running or '?'}, pinned {self.pinned or '?'}"]
        if self.error:
            out.append(f"  ERROR  release check failed: {self.error}")
        if self.upstream and _newer(self.upstream.tag, self.pinned):
            how = (
                "Dependabot PR to stacks/dependency-track"
                if c.name == "dtrack"
                else f"bump {'DD_REF' if c.name == 'dojo' else 'OPENCVE_REF'} in .env.example "
                "after the AGENTS.md checks"
            )
            out.append(
                f"  UPDATE {self.upstream.tag} released {self.upstream.published:%Y-%m-%d}: {how}"
            )
        if self.pinned and _newer(self.pinned, self.running):
            out.append(f"  READY  {self.pinned} is pinned: ./poc.sh upgrade {c.name}")
        if self.waiting:
            until = self.waiting.published + timedelta(days=COOLDOWN_DAYS)
            out.append(f"  new    {self.waiting.tag} (cooldown until {until:%Y-%m-%d})")
        return out

    @property
    def actionable(self) -> bool:
        return bool(
            (self.upstream and _newer(self.upstream.tag, self.pinned))
            or (self.pinned and _newer(self.pinned, self.running))
        )


def _newer(a: str, b: str) -> bool:
    ka, kb = version_key(a), version_key(b)
    return ka is not None and kb is not None and ka > kb


def _major(v: str) -> int | None:
    k = version_key(v)
    return k[0][0] if k else None


def read_env_value(path: Path, key: str) -> str:
    """KEY's value in a dotenv file ("" when the file or key is missing); quotes stripped."""
    if not path.is_file():
        return ""
    for line in path.read_text().splitlines():
        m = re.fullmatch(rf"\s*{re.escape(key)}\s*=\s*(.*?)\s*", line)
        if m:
            return m.group(1).strip("'\"")
    return ""


def compose_image_tag(path: Path, image: str) -> str:
    """Tag of `image:` <image>:<tag> in a compose file ("" if not found)."""
    if not path.is_file():
        return ""
    m = re.search(rf"^\s*image:\s*{re.escape(image)}:(\S+)\s*$", path.read_text(), re.M)
    return m.group(1) if m else ""


def running_dt_tag() -> str:
    """Image tag of the running Dependency-Track apiserver container ("" when not running)."""
    try:
        out = subprocess.run(  # noqa: S603 - fixed argv, no shell
            [  # noqa: S607 - docker from PATH, as everywhere in poc.sh
                "docker",
                "ps",
                "--filter",
                f"label=com.docker.compose.project={DT_PROJECT}",
                "--filter",
                "label=com.docker.compose.service=apiserver",
                "--format",
                "{{.Image}}",
            ],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        ).stdout
    except (OSError, subprocess.TimeoutExpired):
        return ""
    image = out.strip().splitlines()[0] if out.strip() else ""
    return image.rsplit(":", 1)[1] if ":" in image.rsplit("/", 1)[-1] else ""


def releases(repo: str, transport: Transport | None = None) -> list[Release]:
    """Published, non-prerelease GitHub releases of owner/name, newest first."""
    http = Http(
        "https://api.github.com",
        headers={"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"},
        transport=transport,
    )
    rows = http.get(f"/repos/{repo}/releases?per_page=50").json() or []
    out = []
    for r in rows:
        if r.get("draft") or r.get("prerelease") or not r.get("published_at"):
            continue
        tag = str(r.get("tag_name") or "")
        if version_key(tag) is None:
            continue
        published = datetime.fromisoformat(str(r["published_at"]).replace("Z", "+00:00"))
        out.append(Release(tag, published))
    return sorted(out, key=lambda x: version_key(x.tag) or ((), 0, ""), reverse=True)


def pick(
    rels: list[Release], pinned: str, same_major: bool, now: datetime
) -> tuple[Release | None, Release | None]:
    """(newest release past the cooldown, newer one still waiting) among rels."""
    major = _major(pinned)
    if same_major and major is not None:
        rels = [r for r in rels if _major(r.tag) == major]
    cutoff = now - timedelta(days=COOLDOWN_DAYS)
    ready = next((r for r in rels if r.published <= cutoff), None)
    waiting = next((r for r in rels if r.published > cutoff), None)
    if waiting and ready and not _newer(waiting.tag, ready.tag):
        waiting = None
    if waiting and pinned and not _newer(waiting.tag, pinned):
        waiting = None
    return ready, waiting


def check(
    root: Path,
    env_file: Path,
    transport: Transport | None = None,
    now: datetime | None = None,
    dt_running: str | None = None,
) -> list[Status]:
    now = now or datetime.now(UTC)
    example = root / ".env.example"
    compose = root / DT_COMPOSE
    versions = {
        "dojo": (read_env_value(env_file, "DD_REF"), read_env_value(example, "DD_REF")),
        "opencve": (
            read_env_value(env_file, "OPENCVE_REF"),
            read_env_value(example, "OPENCVE_REF"),
        ),
        "dtrack": (
            running_dt_tag() if dt_running is None else dt_running,
            compose_image_tag(compose, "ghcr.io/dependencytrack/apiserver"),
        ),
    }
    out = []
    for c in COMPONENTS:
        running, pinned = versions[c.name]
        try:
            ready, waiting = pick(releases(c.repo, transport), pinned, c.same_major, now)
        except (HttpError, OSError, ValueError) as e:
            out.append(Status(c, running, pinned, None, None, error=str(e)[:200]))
            continue
        out.append(Status(c, running, pinned, ready, waiting))
    return out


def report(statuses: list[Status]) -> str:
    lines = []
    for s in statuses:
        lines += s.lines()
    if not any(s.actionable or s.error for s in statuses):
        lines.append("Nothing to do.")
    return "\n".join(lines)
