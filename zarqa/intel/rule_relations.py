"""Relations found by wording, with no model.

In one sentence, a subject named before a relation verb and an object named after it:

* actor, malware, tool or campaign + "exploited / weaponized / abused" + CVE      -> exploits
* actor or campaign + "used / deployed / delivered / installed" + malware or tool -> uses
* malware or tool + "contacted / connected to / beaconed to / sent data to" + IP, domain or URL
                                                                                  -> communicates_with
* malware or tool + "dropped / downloaded / installed / loaded" + malware or tool  -> drops
* campaign, malware or tool + "attributed to / linked to / operated by" + actor    -> attributed_to

The sentence is the quote, so every relation is grounded the same way as the model's, and it is "stated" (the
verb is in it). Only entities already found in the document (by rules, the dictionary or the model) are used, so
this adds links, never names. Negated sentences ("did not use", "no evidence that ... exploited") are skipped.
"""

from __future__ import annotations

import re

from .extract import refang

_SUBJ = {"actor", "malware", "tool", "campaign"}
_IOC = {"ipv4", "ipv6", "domain", "url"}

# relation, subject types, object types, verb pattern (between the two names)
RULES = [
    ("exploits", _SUBJ, {"cve"}, r"exploit\w*|weaponi[sz]\w*|abus\w*|leverag\w*|target\w*\s+(?:the\s+)?(?:flaw|vulnerabilit\w+)"),
    ("uses", {"actor", "campaign"}, {"malware", "tool"},
     r"us(?:e|es|ed|ing)|deploy\w*|deliver\w*|install\w*|drop\w*|distribut\w*|relied\s+on|rel(?:y|ies)\s+on|employ\w*"
     r"|leverag\w*|ran|run\w*|launch\w*"),
    ("communicates_with", {"malware", "tool"}, _IOC,
     r"contact\w*|connect\w*\s+(?:back\s+)?to|beacon\w*(?:\s+(?:out|back))?\s+to|communicat\w+\s+with|reach\w*\s+out\s+to"
     r"|sen(?:d|ds|t)\s+(?:\w+\s+){0,3}to|call\w*\s+(?:back|home|out)\s+to|exfiltrat\w+\s+(?:\w+\s+){0,3}to|resolv\w*"
     r"|download\w*\s+(?:\w+\s+){0,3}from|fetch\w*\s+(?:\w+\s+){0,3}from|retriev\w*\s+(?:\w+\s+){0,3}from"),
    ("drops", {"malware", "tool"}, {"malware", "tool"},
     r"drop\w*|download\w*|install\w*|load\w*|deploy\w*|fetch\w*|retriev\w*|execut\w*|launch\w*|side[\s-]?load\w*"),
    ("attributed_to", {"campaign", "malware", "tool"}, {"actor"},
     r"attribut\w*\s+to|link\w*\s+to|tied\s+to|associated\s+with|operated\s+by|used\s+(?:exclusively\s+)?by"
     r"|deployed\s+by|developed\s+by|belong\w*\s+to"),
]
_RULES = [(rel, s, o, re.compile(r"(?i)\b(?:" + v + r")\b")) for rel, s, o, v in RULES]
_NEG = re.compile(r"(?i)\b(?:not|never|no\s+evidence|no\s+indication|unlikely|unclear|cannot|can't|didn't|doesn't|"
                  r"isn't|wasn't|ruled\s+out)\b")
_SENT = re.compile(r"[^.!?\n]+(?:\.(?=\S)[^.!?\n]*)*[.!?]?")
MAX_GAP = 120          # characters between subject, verb and object: beyond that the sentence is about more


def _spans(sentence: str, surfaces: list[str]) -> list[tuple[int, int]]:
    out = []
    low = sentence.lower()
    for s in surfaces:
        s = s.strip().lower()
        if len(s) < 3:
            continue
        for m in re.finditer(r"(?<![\w.-])" + re.escape(s) + r"(?![\w-]|\.\w)", low):
            out.append(m.span())
    return out


def find_relations(text: str, entities: list[dict]) -> list[dict]:
    """``entities``: [{id, type, surfaces: [strings as written in the text]}].
    Returns [{src, rel, dst, quote}] (each triple once)."""
    found: dict[tuple[int, str, int], str] = {}
    by_type: dict[str, list[dict]] = {}
    for e in entities:
        by_type.setdefault(e["type"], []).append(e)
    t = refang(text or "")
    for m in _SENT.finditer(t):
        sent = m.group(0)
        if len(sent) > 600 or _NEG.search(sent):
            continue
        present = []
        for e in entities:
            for sp in _spans(sent, e["surfaces"]):
                present.append((sp, e))
        if len(present) < 2:
            continue
        for rel, stypes, otypes, verb in _RULES:
            for (s_sp, s_e) in present:
                if s_e["type"] not in stypes:
                    continue
                for (o_sp, o_e) in present:
                    if o_e["type"] not in otypes or o_e["id"] == s_e["id"] or o_sp[0] <= s_sp[1]:
                        continue
                    between = sent[s_sp[1]:o_sp[0]]
                    if len(between) > MAX_GAP or not verb.search(between):
                        continue
                    key = (s_e["id"], rel, o_e["id"])
                    if key not in found:
                        found[key] = sent.strip()
    return [{"src": k[0], "rel": k[1], "dst": k[2], "quote": q} for k, q in found.items()]
