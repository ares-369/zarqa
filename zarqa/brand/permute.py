"""Lookalike domain names for a domain you own.

Techniques (each candidate keeps the first one that produced it):

  omission       exmple.com        letter left out
  repetition     exaample.com      letter doubled
  transposition  exmaple.com       two neighbours swapped
  replacement    exanple.com       a key next to it on the keyboard
  insertion      exasmple.com      a neighbouring key added
  homoglyph      examp1e.com       a look-alike character (including rn for m, vv for w)
  vowel          exomple.com       one vowel for another
  hyphen         exa-mple.com      a hyphen added
  bitsquat       dxample.com       one bit flipped in a letter
  tld            example.net       another top-level domain
  word           example-login.com a common phishing word added
  subdomain      exam.ple.com      a dot added (the registered part is the lookalike)

Only names that are valid hostnames are returned.
"""

from __future__ import annotations

import re

_KEYS = ["1234567890-", "qwertyuiop", "asdfghjkl", "zxcvbnm"]
_GLYPHS = {"a": ["4", "@"], "b": ["d", "lb", "6"], "c": ["e", "k"], "d": ["b", "cl"], "e": ["3", "c"], "g": ["q", "9"],
           "h": ["lh", "b"], "i": ["1", "l", "j", "!"], "k": ["lk", "ik"], "l": ["1", "i", "I"], "m": ["rn", "nn", "n"],
           "n": ["m", "r"], "o": ["0", "q"], "q": ["g", "9"], "s": ["5", "z"], "t": ["7"], "u": ["v"], "v": ["u"],
           "w": ["vv", "uu"], "y": ["v"], "z": ["2", "s"], "0": ["o"], "1": ["l", "i"]}
WORDS = ("login", "secure", "account", "support", "verify", "update", "mail", "portal", "online", "auth", "signin",
         "service", "help", "pay", "billing", "web", "my", "app", "id", "sso")
TLDS = ("com", "net", "org", "info", "biz", "co", "io", "app", "online", "site", "xyz", "top", "shop", "live", "click",
        "link", "support", "help", "cloud", "us", "uk", "de", "eu", "in")
_HOST = re.compile(r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}$")


def _neighbours() -> dict[str, set[str]]:
    out: dict[str, set[str]] = {}
    for r, row in enumerate(_KEYS):
        for i, ch in enumerate(row):
            n = set()
            for dr in (-1, 0, 1):
                rr = r + dr
                if 0 <= rr < len(_KEYS):
                    for di in (-1, 0, 1):
                        j = i + di
                        if 0 <= j < len(_KEYS[rr]) and (dr, di) != (0, 0):
                            n.add(_KEYS[rr][j])
            out[ch] = n
    return out


_NEAR = _neighbours()


def split(domain: str) -> tuple[str, str]:
    """('example', 'com') or ('example', 'co.uk'): the name and its suffix (simple rule: a two-letter
    country code after a short second level counts as one suffix)."""
    parts = domain.lower().strip(".").split(".")
    if len(parts) >= 3 and len(parts[-1]) == 2 and parts[-2] in ("co", "com", "net", "org", "gov", "ac", "edu"):
        return ".".join(parts[:-2]), ".".join(parts[-2:])
    return ".".join(parts[:-1]), parts[-1]


def permutations(domain: str, *, words: tuple[str, ...] = WORDS, tlds: tuple[str, ...] = TLDS,
                 limit: int = 5000) -> list[tuple[str, str]]:
    """[(candidate, technique)] for one domain, the domain itself excluded."""
    name, tld = split(domain)
    base = name.split(".")[-1]
    prefix = name[: -len(base)]          # keep any subdomain part as is
    out: dict[str, str] = {}

    def add(n: str, technique: str, t: str = tld) -> None:
        cand = f"{prefix}{n}.{t}".lower()
        if cand != domain.lower() and cand not in out and _HOST.match(cand) and "--" not in n:
            out[cand] = technique

    L = len(base)
    for i in range(L):
        add(base[:i] + base[i + 1:], "omission")
        add(base[:i] + base[i] + base[i:], "repetition")
        if i < L - 1:
            add(base[:i] + base[i + 1] + base[i] + base[i + 2:], "transposition")
        for k in sorted(_NEAR.get(base[i], ())):
            add(base[:i] + k + base[i + 1:], "replacement")
            add(base[:i] + k + base[i:], "insertion")
            add(base[:i + 1] + k + base[i + 1:], "insertion")
        for g in _GLYPHS.get(base[i], []):
            add(base[:i] + g.lower() + base[i + 1:], "homoglyph")
        if base[i] in "aeiou":
            for v in "aeiou":
                if v != base[i]:
                    add(base[:i] + v + base[i + 1:], "vowel")
        if 0 < i < L:
            add(base[:i] + "-" + base[i:], "hyphen")
            add(base[:i] + "." + base[i:], "subdomain")
        c = ord(base[i])
        for b in range(8):
            f = chr(c ^ (1 << b))
            if f.isascii() and (f.isalnum() or f == "-") and f.lower() == f:
                add(base[:i] + f + base[i + 1:], "bitsquat")
    for w in words:
        add(f"{base}-{w}", "word")
        add(f"{w}-{base}", "word")
        add(f"{base}{w}", "word")
        add(f"{w}{base}", "word")
    for t in tlds:
        if t != tld:
            add(base, "tld", t)
    return list(out.items())[:limit]


def registered_part(host: str) -> str:
    """The registrable name of a host (``a.b.example.com`` -> ``example.com``), by the same simple rule."""
    name, tld = split(host)
    return f"{name.split('.')[-1]}.{tld}"


def similarity(a: str, b: str) -> int:
    """0-100 by edit distance of the names without their suffixes."""
    x, y = split(a)[0].split(".")[-1], split(b)[0].split(".")[-1]
    if not x or not y:
        return 0
    prev = list(range(len(y) + 1))
    for i, cx in enumerate(x, 1):
        cur = [i]
        for j, cy in enumerate(y, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (cx != cy)))
        prev = cur
    return max(0, round(100 * (1 - prev[-1] / max(len(x), len(y)))))
