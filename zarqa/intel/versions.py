"""Affected versions named in a report, compared with the versions installed on your hosts.

Reads plain statements in sentences that name the product:

* ``before 9.8``, ``prior to 9.8``, ``earlier than``, ``older than``, ``below``, ``< 9.8``: versions under 9.8;
* ``9.8 and earlier``, ``9.8 and older``, ``up to 9.8``, ``through 9.8``, ``<= 9.8``: versions up to 9.8;
* ``fixed in 9.8``, ``patched in``, ``resolved in``, ``addressed in``, ``upgrade to 9.8``, ``update to``:
  versions under 9.8;
* ``9.2 through 9.7``, ``from 9.2 to 9.7``, ``versions 9.2 - 9.7``: that range.

Installed versions are read as upstream versions: an epoch (``1:``) and a distribution revision (``-2+deb12u3``)
are dropped. Versions compare part by part, numbers as numbers (``9.10`` is after ``9.9``, ``9.2p1`` after
``9.2``). This is a reading of the text, not a vulnerability database: distributions often fix a flaw without
changing the upstream version (a backport), so "in range" means "check it", not "vulnerable".
"""

from __future__ import annotations

import re

_V = r"v?(\d+(?:\.\d+){0,3}(?:[a-z]+\d*)?)"
_WORDS = r"(?:[A-Za-z][\w+-]*\s+){0,2}"      # "fixed in OpenSSH 9.8p1": up to two words before the version
_SENT = re.compile(r"[^.!?\n]*(?:\.(?=\d)[^.!?\n]*)*[.!?\n]?")

_PATTERNS = [
    ("range", re.compile(r"(?:from\s+)?" + _V + r"\s*(?:through|thru|to|-|\u2013)\s*" + _V, re.I)),
    ("lt", re.compile(r"(?:before|prior to|earlier than|older than|below|lower than|<)\s*(?:version\s+)?" + _V, re.I)),
    ("le", re.compile(r"(?:up to(?: and including)?|through|<=|≤)\s*(?:version\s+)?" + _V, re.I)),
    ("le", re.compile(_V + r"\s+(?:and|or)\s+(?:earlier|older|below|prior|lower)", re.I)),
    ("lt", re.compile(r"(?:fixed|patched|resolved|addressed|corrected)\s+in\s+" + _WORDS + r"(?:version\s+)?" + _V, re.I)),
    ("lt", re.compile(r"(?:upgrade|update)\s+to\s+" + _WORDS + r"(?:version\s+)?" + _V, re.I)),
]


def upstream(version: str) -> str:
    """``1:9.2p1-2+deb12u3`` -> ``9.2p1``; ``3.0.11-1~deb12u2`` -> ``3.0.11``."""
    v = (version or "").strip()
    v = re.sub(r"^\d+:", "", v)
    if "-" in v:
        v = v.rsplit("-", 1)[0] if re.search(r"-[\w.~+]*$", v) else v
    v = re.split(r"[~+]", v)[0]
    return v


def key(version: str) -> tuple:
    parts = re.findall(r"\d+|[a-z]+", upstream(version).lower())
    out = []
    for p in parts:
        out.append((0, int(p), "") if p.isdigit() else (1, 0, p))
    return tuple(out)


def _cmp(a: str, b: str) -> int:
    ka, kb = key(a), key(b)
    n = max(len(ka), len(kb))
    pad = (0, 0, "")
    ka, kb = ka + (pad,) * (n - len(ka)), kb + (pad,) * (n - len(kb))
    return (ka > kb) - (ka < kb)


def _sentences_naming(text: str, names: list[str]) -> list[str]:
    low_names = [n.lower() for n in names if len(n) >= 3]
    out = []
    for m in _SENT.finditer(text or ""):
        s = m.group(0)
        sl = s.lower()
        if any(re.search(r"(?<![a-z0-9])" + re.escape(n) + r"(?![a-z0-9])", sl) for n in low_names):
            out.append(s)
    return out


def affected_ranges(text: str, names: list[str]) -> list[tuple]:
    """``(op, version[, version2])`` statements in sentences naming the product. ``op``: lt, le, range."""
    found = []
    for s in _sentences_naming(text, names):
        taken: list[tuple[int, int]] = []
        for op, rx in _PATTERNS:
            for m in rx.finditer(s):
                if any(a <= m.start() < b for a, b in taken):
                    continue
                taken.append((m.start(), m.end()))
                g = [x for x in m.groups() if x]
                if op == "range" and len(g) == 2 and "." in g[0] and "." in g[1] and _cmp(g[0], g[1]) < 0:
                    found.append(("range", g[0], g[1]))
                elif op != "range":
                    found.append((op, g[0]))
    return list(dict.fromkeys(found))


def in_range(installed: str, ranges: list[tuple]) -> bool | None:
    """True when the installed version falls in any stated range, False when it is outside all of them, None
    when there is nothing to compare (no ranges, or no installed version)."""
    if not ranges or not upstream(installed) or not re.match(r"\d", upstream(installed)):
        return None
    for r in ranges:
        if r[0] == "lt" and _cmp(installed, r[1]) < 0:
            return True
        if r[0] == "le" and _cmp(installed, r[1]) <= 0:
            return True
        if r[0] == "range" and _cmp(r[1], installed) <= 0 and _cmp(installed, r[2]) <= 0:
            return True
    return False


def describe(r: tuple) -> str:
    return {"lt": f"before {r[1]}", "le": f"up to {r[1]}"}.get(r[0], f"{r[1]} to {r[2]}" if len(r) > 2 else "")
