"""RPM version comparison: rpm's rpmvercmp(), then epoch:version-release ordering.

Segments are runs of digits or of letters; anything else is a separator and is skipped.
Numeric segments beat alphabetic ones, `~` sorts before everything (even the end of the
string), `^` sorts after the end of the string but before any other segment.
"""

from __future__ import annotations

import re

_NEVR = re.compile(r"(?P<name>.+)-(?P<epoch>\d+):(?P<version>[^-]+)-(?P<release>.+)")


def _alnum(c: str) -> bool:
    return c.isascii() and c.isalnum()


def vercmp(a: str, b: str) -> int:
    """-1, 0 or 1 as a is older than, the same as, or newer than b (rpmvercmp)."""
    if a == b:
        return 0
    i = j = 0
    while i < len(a) or j < len(b):
        while i < len(a) and not _alnum(a[i]) and a[i] not in "~^":
            i += 1
        while j < len(b) and not _alnum(b[j]) and b[j] not in "~^":
            j += 1
        ca = a[i] if i < len(a) else ""
        cb = b[j] if j < len(b) else ""
        if ca == "~" or cb == "~":
            if ca != "~":
                return 1
            if cb != "~":
                return -1
            i += 1
            j += 1
            continue
        if ca == "^" or cb == "^":
            if not ca:
                return -1
            if not cb:
                return 1
            if ca != "^":
                return 1
            if cb != "^":
                return -1
            i += 1
            j += 1
            continue
        if not (ca and cb):
            break
        end_a, end_b = i, j
        if ca.isdigit():
            while end_a < len(a) and a[end_a].isdigit():
                end_a += 1
            while end_b < len(b) and b[end_b].isdigit():
                end_b += 1
            numeric = True
        else:
            while end_a < len(a) and a[end_a].isascii() and a[end_a].isalpha():
                end_a += 1
            while end_b < len(b) and b[end_b].isascii() and b[end_b].isalpha():
                end_b += 1
            numeric = False
        seg_a, seg_b = a[i:end_a], b[j:end_b]
        if not seg_b:  # different segment types: numeric is newer than alphabetic
            return 1 if numeric else -1
        if numeric:
            seg_a, seg_b = seg_a.lstrip("0"), seg_b.lstrip("0")
            if len(seg_a) != len(seg_b):
                return 1 if len(seg_a) > len(seg_b) else -1
        if seg_a != seg_b:
            return 1 if seg_a > seg_b else -1
        i, j = end_a, end_b
    if i >= len(a) and j >= len(b):
        return 0
    return 1 if i < len(a) else -1


def compare(a: tuple[int, str, str], b: tuple[int, str, str]) -> int:
    """Compare (epoch, version, release) triples."""
    if a[0] != b[0]:
        return -1 if a[0] < b[0] else 1
    return vercmp(a[1], b[1]) or vercmp(a[2], b[2])


def parse_nevr(s: str) -> tuple[str, int, str, str] | None:
    """'perl-HTTP-Tiny-0:0.074-2.el8' -> (name, epoch, version, release); None if the
    string is not in name-epoch:version-release form."""
    m = _NEVR.fullmatch(s.strip())
    if not m:
        return None
    return m["name"], int(m["epoch"]), m["version"], m["release"]
