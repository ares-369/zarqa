"""Scripted demo 'provider'. NOT an AI model.

Used only by ``zarqa demo`` so extraction and investigations can be seen with no model installed. It answers
from fixed rules about the sample data and labels every reply "[scripted demo, not AI]". Its output goes
through the same checks as a real model's.
"""

from __future__ import annotations

import json
import re

from .base import LLMProvider, LLMResult

TAG = "[scripted demo, not AI]"


def _sentences(text: str) -> list[str]:
    return [s.strip() for s in re.split(r"(?<=[.!?])\s+|\n+", text) if s.strip()]


def _extract(user: str) -> dict:
    from ..demo.data import BENIGN, NAMES, RELATIONS
    doc = user.split("<<UNTRUSTED-DATA document>>", 1)[-1].split("<<END-UNTRUSTED-DATA document>>", 1)[0]
    inds = user.split("by fixed rules:\n", 1)[-1].split("\n\n", 1)[0].splitlines()
    sents = _sentences(doc)

    def quote(*words):
        for s in sents:
            if all(w.lower() in s.lower() for w in words):
                return " ".join(s.split()[:25])
        return ""
    items = []
    for name, kind in NAMES.items():
        q = quote(name)
        if q:
            items.append({"type": kind, "name": name, "quote": q})
    for m in re.finditer(r"\((T\d{4}(?:\.\d{3})?)\)", doc):
        items.append({"type": "technique", "name": "technique", "id": m.group(1), "quote": quote(m.group(1))})
    for sector in ("energy utilities", "utilities"):
        if quote(sector):
            items.append({"type": "sector", "name": sector, "quote": quote(sector)})
            break
    labels = []
    for v in inds:
        v = v.strip()
        if not v or v == "(none)":
            continue
        role = BENIGN.get(v, "malicious")
        labels.append({"value": v, "role": role, "quote": ""})
    rels = [{"source": a, "type": r, "target": b, "quote": quote(a.split()[0], b.split()[0]) or quote(a)}
            for a, r, b in RELATIONS if quote(a) and (quote(b) or b in doc)]
    first = next((s for s in sents if "FICTIONAL" not in s and "invented" not in s), "")
    return {"summary": f"{TAG} {first[:200]}", "items": items, "relations": rels, "indicators": labels}


def _investigate(messages: list[dict]) -> dict:
    user = messages[1]["content"] if len(messages) > 1 else ""
    q = user.rsplit("Question:", 1)[-1].strip()
    results = [m["content"] for m in messages[2:] if m["role"] == "user" and re.match(r"E\d+ \(", m["content"])]
    if not results:
        from ..intel.extract import extract
        found = [v for vals in extract(q).values() for v in vals]
        names = [n for n in ("Glassbridge", "Quillspin", "Tin Heron") if n.lower() in q.lower()]
        value = (found or names or [q[:60]])[0]
        return {"action": "call", "connector": "zarqa", "tool": "lookup", "arguments": {"value": value},
                "thought": f"{TAG} look the value up first"}
    body = results[-1]
    try:
        data = json.loads(body.split(">>\n", 1)[1].rsplit("\n<<END", 1)[0])
    except (IndexError, ValueError):
        data = {}
    ents = data.get("entities") or []
    if not ents:
        return {"action": "assessment", "outcome": "not_enough_data", "confidence": 20,
                "answer": f"{TAG} Nothing about this is stored yet.", "findings": [], "gaps": ["no stored sightings"]}
    e = ents[0]
    findings = [{"claim": f"{e['value']} was seen in \"{s['title']}\": {s['sentence']}", "evidence": ["E1"]}
                for s in e.get("sightings", [])[:3] if s.get("sentence")]
    findings += [{"claim": r, "evidence": ["E1"]} for r in e.get("relations", [])[:3]]
    return {"action": "assessment", "outcome": "answered" if findings else "partial", "confidence": 60,
            "answer": f"{TAG} {e['value']} appears in {len(e.get('sightings', []))} stored document(s); the findings "
                      f"below quote them.", "findings": findings, "gaps": ["no enrichment in the demo"],
            "next_steps": ["look the value up in your own logs"]}


class DemoProvider(LLMProvider):
    name = "demo"

    def chat(self, messages, *, model=None, temperature=0.2, max_tokens=900) -> LLMResult:
        system = messages[0]["content"] if messages else ""
        user = messages[1]["content"] if len(messages) > 1 else ""
        if "You extract cyber threat intelligence" in system:
            out = _extract(user)
        elif "threat intelligence analyst answering one question" in system:
            out = _investigate(messages)
        elif "You rate how relevant" in system:
            out = {"score": 50, "why": f"{TAG} fixed score", "requirements": []}
        else:
            return LLMResult(text=json.dumps({"ok": True, "note": TAG}), model="scripted-demo")
        return LLMResult(text=json.dumps(out), model="scripted-demo")
