"""Debian version comparison (Debian Policy 5.6.12, the same algorithm as `dpkg
--compare-versions`): [epoch:]upstream[-revision].

Parts are compared as alternating runs of non-digits and digits. In a non-digit run letters
sort before everything else and `~` sorts before everything, even the end of the string, so
1.0~rc1 < 1.0 < 1.0+b1 < 1.0a.
"""

from __future__ import annotations

_DIGITS = "0123456789"


def _order(c: str) -> int:
    if not c or c in _DIGITS:
        return 0
    if c.isalpha():
        return ord(c)
    if c == "~":
        return -1
    return ord(c) + 256


def _verrevcmp(a: str, b: str) -> int:
    i = j = 0
    while i < len(a) or j < len(b):
        first_diff = 0
        while (i < len(a) and a[i] not in _DIGITS) or (j < len(b) and b[j] not in _DIGITS):
            ac = _order(a[i]) if i < len(a) else 0
            bc = _order(b[j]) if j < len(b) else 0
            if ac != bc:
                return ac - bc
            i += 1
            j += 1
        while i < len(a) and a[i] == "0":
            i += 1
        while j < len(b) and b[j] == "0":
            j += 1
        while i < len(a) and a[i] in _DIGITS and j < len(b) and b[j] in _DIGITS:
            if not first_diff:
                first_diff = ord(a[i]) - ord(b[j])
            i += 1
            j += 1
        if i < len(a) and a[i] in _DIGITS:
            return 1
        if j < len(b) and b[j] in _DIGITS:
            return -1
        if first_diff:
            return first_diff
    return 0


def _split(v: str) -> tuple[int, str, str]:
    epoch = 0
    if ":" in v:
        e, v = v.split(":", 1)
        epoch = int(e) if e.isdigit() else 0
    upstream, _, revision = v.rpartition("-") if "-" in v else (v, "", "")
    return epoch, upstream, revision


def has_epoch(v: str) -> bool:
    return ":" in v


def compare(a: str, b: str) -> int:
    """-1, 0 or 1 as a is older than, the same as, or newer than b."""
    ea, ua, ra = _split(a.strip())
    eb, ub, rb = _split(b.strip())
    if ea != eb:
        return -1 if ea < eb else 1
    for x, y in ((ua, ub), (ra, rb)):
        d = _verrevcmp(x, y)
        if d:
            return -1 if d < 0 else 1
    return 0
