"""MITRE ATT&CK reference data: techniques, groups, software and campaigns, with aliases.

Built from the ATT&CK Enterprise STIX bundle by ``scripts/build_attack_data.py``. Used to name
techniques, map retired technique IDs to their replacements, and recognise group, software and
campaign names (and their aliases) in text.
"""

from __future__ import annotations

import json
import re
from functools import lru_cache
from pathlib import Path

_FILE = Path(__file__).with_name("attack_data.json")
KINDS = {"groups": "actor", "software": None, "campaigns": "campaign"}


@lru_cache(maxsize=1)
def data() -> dict:
    return json.loads(_FILE.read_text(encoding="utf-8"))


def version() -> str:
    return str(data().get("version", ""))


def technique(tid: str) -> dict | None:
    """``{"id", "name", "tactics", "replaced": old id or ""}`` for a live or retired technique ID."""
    tid = (tid or "").strip().upper()
    d = data()
    old = ""
    if tid in d["retired"]:
        old, tid = tid, d["retired"][tid].get("by") or ""
    t = d["techniques"].get(tid)
    if not t:
        return None
    return {"id": tid, "name": t["n"], "tactics": list(t["t"]), "replaced": old}


def norm(name: str) -> str:
    return re.sub(r"[^a-z0-9]+", " ", (name or "").lower()).strip()


@lru_cache(maxsize=1)
def _names() -> dict[str, tuple[str, str]]:
    """normalised name or alias -> (kind, ATT&CK id). Kind: actor, malware, tool, campaign."""
    out: dict[str, tuple[str, str]] = {}
    d = data()
    for table in ("groups", "campaigns", "software"):
        for eid, v in d[table].items():
            kind = v.get("k") if table == "software" else KINDS[table]
            for n in [v["n"], *v.get("a", [])]:
                out.setdefault(norm(n), (kind, eid))
    return out


_SUFFIXES = ("loader", "rat", "stealer", "ransomware", "malware", "backdoor", "botnet", "trojan", "group", "team",
             "gang", "apt", "family")


def _loose(name: str) -> str:
    """Spaces and hyphens removed, one generic suffix dropped: "JSS Loader", "JSSLoader" and "jss-loader" -> "jss"."""
    n = norm(name).replace(" ", "")
    for suf in _SUFFIXES:
        if n.endswith(suf) and len(n) - len(suf) >= 4:
            return n[: -len(suf)]
    return n


@lru_cache(maxsize=1)
def _loose_names() -> dict[str, tuple[str, str]]:
    """Loose key -> entry, only for keys that point at exactly one ATT&CK entry (ambiguous keys are dropped)."""
    seen: dict[str, set[tuple[str, str]]] = {}
    d = data()
    for table in ("groups", "campaigns", "software"):
        for eid, v in d[table].items():
            kind = v.get("k") if table == "software" else KINDS[table]
            for n in [v["n"], *v.get("a", [])]:
                key = _loose(n)
                if len(key) >= 4:
                    seen.setdefault(key, set()).add((kind, eid))
    return {k: next(iter(v)) for k, v in seen.items() if len(v) == 1}


def lookup(name: str) -> dict | None:
    """Resolve a group, software or campaign name or alias: ``{kind, id, name, aliases}``. Exact (normalised)
    first; then loose (spaces and one generic suffix ignored), only when that points at a single entry."""
    hit = _names().get(norm(name)) or _loose_names().get(_loose(name))
    if not hit:
        return None
    kind, eid = hit
    table = {"actor": "groups", "campaign": "campaigns"}.get(kind, "software")
    v = data()[table][eid]
    return {"kind": kind, "id": eid, "name": v["n"], "aliases": list(v.get("a", []))}


def known(eid: str) -> dict | None:
    d = data()
    for table in ("groups", "software", "campaigns"):
        if eid in d[table]:
            return {"table": table, **d[table][eid]}
    return None


# Names short or common enough to be ordinary words are not matched in free text.
_MIN_LEN = 5
_COMMON = {"group", "power", "agent", "cobalt", "mimic", "sharp", "ghost", "shell", "carbon", "comet", "shark",
           "phoenix", "orange", "volt", "sandworm team"}


# Software names that are ordinary English words: matched by the model only, never by word search.
_COMMON_SOFTWARE = frozenset(["agenda", "anchor", "andromeda", "apostle", "appleseed", "aurora", "avenger", "backspace", "biscuit", "bookworm", "bumblebee", "calendar", "cannon", "canopy", "carbon", "chaos", "chopstick", "covenant", "crimson", "crutch", "deadwood", "denis", "disco", "donut", "driftwood", "dustpan", "elise", "elmer", "embargo", "emissary", "empire", "expand", "explosive", "ferocious", "flame", "flamer", "gazer", "havoc", "james", "kevin", "lucifer", "lurid", "machete", "mango", "medusa", "meteor", "milan", "minibike", "minibus", "mosquito", "mythic", "nebulae", "nightclub", "ninja", "octopus", "pacemaker", "pandora", "peppy", "photo", "plead", "powerless", "prestige", "proton", "raindrop", "ramsay", "reptile", "route", "rover", "royal", "ruler", "samurai", "sardonic", "scorpion", "shark", "shipshape", "sliver", "snake", "solar", "soldier", "spaceship", "spark", "spica", "sunspot", "supernova", "teardrop", "trailblazer", "trinity", "uppercut", "vermin", "viper", "windshield", "wiper"])


@lru_cache(maxsize=1)
def _scan_re() -> re.Pattern | None:
    """Group, campaign and software names and aliases (case-sensitive, whole words) for scanning free text.
    Software names that are ordinary words ("Empire", "Royal", "Havoc") are left to the model."""
    d = data()
    names = set()
    for table in ("groups", "campaigns", "software"):
        for v in d[table].values():
            for n in [v["n"], *v.get("a", [])]:
                low = n.lower()
                if len(n) < _MIN_LEN or low in _COMMON or (table == "software" and low in _COMMON_SOFTWARE):
                    continue
                names.add(n)
    if not names:
        return None
    alt = "|".join(re.escape(n) for n in sorted(names, key=len, reverse=True))
    return re.compile(rf"(?<![\w-])(?:{alt})(?![\w-])")


def find_names(text: str) -> list[dict]:
    """Known group, campaign and software names in ``text``: [{kind, id, name, matched}] (each id once)."""
    rx = _scan_re()
    if rx is None:
        return []
    seen, out = set(), []
    for m in rx.finditer(text or ""):
        hit = lookup(m.group(0))
        if hit and hit["id"] not in seen:
            seen.add(hit["id"])
            out.append({**hit, "matched": m.group(0)})
    return out
