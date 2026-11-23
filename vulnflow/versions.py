"""Lenient version ordering for picking a fix from a list of fixed versions.

Not a full semver/PEP 440/Go implementation. It only has to answer "which of these fixed
versions should I upgrade to", for lists like

    installed minimatch 9.0.3, fixed in 10.2.1, 9.0.6, 8.0.5, 7.4.7  ->  9.0.6

Handles a leading `v` or `go`, dotted numbers, and a pre-release suffix (`-rc.2`, `rc1`, which
sorts before the release). Build metadata (`+incompatible`) is ignored. Anything that does not
start with a number cannot be ordered and gives no recommendation.
"""

from __future__ import annotations

import re

_START = re.compile(r"(?:v|go)?(\d+(?:\.\d+)*)(.*)", re.IGNORECASE)
_WIDTH = 6


def version_key(v: str) -> tuple[tuple[int, ...], int, str] | None:
    m = _START.fullmatch(v.strip())
    if not m:
        return None
    core = tuple(int(x) for x in m.group(1).split("."))[:_WIDTH]
    core += (0,) * (_WIDTH - len(core))
    rest = m.group(2)
    if rest.startswith("+"):  # build metadata only
        rest = ""
    return core, (0 if rest else 1), rest.split("+", 1)[0].lower()


def recommend(installed: str, fixed: list[str]) -> str:
    """The lowest fixed version newer than `installed`, preferring the same major version;
    "" when nothing can be ordered or nothing is newer."""
    cur = version_key(installed)
    if cur is None:
        return ""
    newer: list[tuple[tuple[tuple[int, ...], int, str], str]] = []
    for f in fixed:
        k = version_key(f)
        if k is not None and k > cur:
            newer.append((k, f))
    if not newer:
        return ""
    same_major = [x for x in newer if x[0][0][0] == cur[0][0]]
    return min(same_major or newer)[1]
