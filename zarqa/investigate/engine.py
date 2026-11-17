"""The investigation loop.

The analyst model gets the question, the organization profile and a catalogue of read-only tools (Zarqa's own,
plus every connector tool for the intel roles). Each turn it either calls one tool or gives its assessment.
Every tool result is stored as evidence ``E<n>``.

The assessment is checked before it is kept:

* a finding must cite at least one evidence id that exists and succeeded, otherwise it is moved to
  ``unsupported``;
* an indicator or CVE named in a finding must appear in the evidence it cites (or in the question),
  otherwise it is moved to ``unsupported`` too;
* with no supported finding, an "answered" outcome becomes ``not_enough_data`` and confidence is capped at 30;
* text that addresses an AI inside any result marks the investigation for review.

Outcomes: ``answered``, ``partial`` (some of it), ``not_enough_data`` (the sources do not say).
"""

from __future__ import annotations

import json
import re
import time
from typing import Any

from ..connectors.hub import ToolCallError
from ..connectors.untrusted import SYSTEM_RULE, wrap
from ..intel.extract import extract, refang
from ..intel.injection import scan
from ..jsonparse import first_object
from ..providers.base import FINAL_TOOLS
from . import tools as local
from .store import InvestigationStore

READ_ROLES = ("intel_platform", "enrichment", "search", "vuln", "malware", "analysis")
OUTCOMES = ("answered", "partial", "not_enough_data")
KEEP_FULL = 3
TRIM_TO = 900

FINAL_TOOLS["assessment"] = {
    "name": "submit_assessment",
    "description": "Give the final assessment. This ends the investigation.",
    "parameters": {"type": "object", "properties": {
        "outcome": {"type": "string", "enum": list(OUTCOMES)},
        "answer": {"type": "string", "description": "the answer in plain language, 2-6 sentences"},
        "confidence": {"type": "integer"},
        "findings": {"type": "array", "items": {"type": "object", "properties": {
            "claim": {"type": "string"}, "evidence": {"type": "array", "items": {"type": "string"}}}}},
        "gaps": {"type": "array", "items": {"type": "string"}},
        "next_steps": {"type": "array", "items": {"type": "string"}},
    }, "required": ["outcome", "answer", "confidence", "findings"]},
}

SYSTEM = """You are a threat intelligence analyst answering one question with evidence.
Work in turns. Each turn reply with ONE JSON object and nothing else, either a tool call:
{"action": "call", "connector": "<connector>", "tool": "<tool>", "arguments": {...}, "thought": "why"}
or, when you can answer (or the tools cannot), your assessment:
{"action": "assessment", "outcome": "answered|partial|not_enough_data", "answer": "2-6 sentences",
 "confidence": 0-100, "findings": [{"claim": "one fact", "evidence": ["E1", "E3"]}],
 "gaps": ["what is missing"], "next_steps": ["what a person could do next"]}

Rules:
- Every tool result is evidence with an id (E1, E2, ...). Each finding must cite the ids that show it. A claim
  you cannot cite is not a finding: put it in gaps instead.
- Use only what the evidence says. Do not add facts from memory. If the sources do not answer the question,
  say so with outcome not_enough_data; that is a correct and useful answer.
- Start with the zarqa tools (lookup, search_documents, read_document). Use other connectors to go further.
- Indicators may be written exactly as found; never invent or complete one.
- """ + SYSTEM_RULE


def catalogue(hub) -> tuple[list[dict], str]:
    tools = [{"connector": local.LOCAL, "name": t["name"], "description": t["description"], "inputSchema": t["inputSchema"]}
             for t in local.TOOLS]
    seen = {(local.LOCAL, t["name"]) for t in tools}
    if hub is not None:
        for role in READ_ROLES:
            for t in hub.tools_for_role(role):
                if (t["connector"], t["name"]) not in seen:
                    seen.add((t["connector"], t["name"]))
                    tools.append({"connector": t["connector"], "name": t["name"], "description": t["description"][:300],
                                  "inputSchema": t.get("inputSchema") or {}, "role": role})
    lines = []
    for t in tools:
        props = (t["inputSchema"] or {}).get("properties") or {}
        req = set((t["inputSchema"] or {}).get("required") or [])
        args = ", ".join(f"{k}{'' if k in req else '?'}: {(v or {}).get('type', 'any')}" for k, v in list(props.items())[:12])
        lines.append(f"- {t['connector']}.{t['name']}({args}): {t['description'][:240]}")
    return tools, "\n".join(lines)


def _trimmed(transcript: list[dict]) -> list[dict]:
    results = [i for i, m in enumerate(transcript) if m.get("_result")]
    old = set(results[: max(0, len(results) - KEEP_FULL)])
    out = []
    for i, m in enumerate(transcript):
        c = m["content"]
        if i in old and len(c) > TRIM_TO:
            c = c[:TRIM_TO] + "\n[older result trimmed; its evidence id stays valid]"
        out.append({"role": m["role"], "content": c})
    return out


_VALUE_TYPES = ("ipv4", "ipv6", "domain", "url", "email", "md5", "sha1", "sha256", "cve")


def check_assessment(a: dict, steps: list[dict], question: str) -> dict:
    ok_ids = {f"E{s['n']}" for s in steps if s["ok"]}
    # indicators are compared refanged on both sides: a claim may quote "hxxp://a[.]b" from the evidence
    texts = {f"E{s['n']}": refang(s.get("result") or "").lower() for s in steps}
    findings, unsupported = [], []
    for f in a.get("findings") or []:
        if not isinstance(f, dict):
            continue
        claim = str(f.get("claim", "")).strip()[:600]
        cited = [str(x).strip().upper() for x in f.get("evidence") or [] if str(x).strip()]
        valid = [c for c in cited if c in ok_ids]
        if not claim:
            continue
        if not valid:
            unsupported.append({"claim": claim, "why": "cites no evidence that exists and succeeded"})
            continue
        found = extract(claim)
        missing = [v for k in _VALUE_TYPES for v in found.get(k, [])
                   if v.lower() not in refang(question).lower() and not any(v.lower() in texts[c] for c in valid)]
        if missing:
            unsupported.append({"claim": claim, "why": f"{', '.join(missing[:3])} not in the cited evidence"})
            continue
        findings.append({"claim": claim, "evidence": valid})
    outcome = str(a.get("outcome", "")).lower()
    if outcome not in OUTCOMES:
        outcome = "partial" if findings else "not_enough_data"
    try:
        conf = max(0, min(100, int(a.get("confidence", 0))))
    except (TypeError, ValueError):
        conf = 0
    notes = []
    if not findings and outcome != "not_enough_data":
        outcome, conf = "not_enough_data", min(conf, 30)
        notes.append("no claim was backed by evidence, so the outcome was set to not_enough_data")
    if unsupported and findings:
        conf = min(conf, 70)
        notes.append(f"{len(unsupported)} claim(s) without evidence were set aside; confidence capped at 70")
    return {"outcome": outcome, "answer": str(a.get("answer", ""))[:3000], "confidence": conf, "findings": findings,
            "unsupported": unsupported, "gaps": [str(x)[:300] for x in a.get("gaps") or []][:10],
            "next_steps": [str(x)[:300] for x in a.get("next_steps") or []][:10], "checks": notes}


def run(cfg, question: str, *, inv_id: int, istore: InvestigationStore, kstore, llm, hub=None, actor: str = "",
        checkpoint=None, max_steps: int | None = None) -> dict[str, Any]:
    lim = cfg.limits
    steps_cap = int(max_steps or lim.max_steps)
    deadline = time.monotonic() + lim.max_runtime_sec
    tools, cat = catalogue(hub)
    index = {(t["connector"], t["name"]): t for t in tools}
    from ..intel.relevance import _context, has_profile, profile
    p = profile(cfg)
    org = _context(p) if has_profile(p) else "No organization profile given."
    user = f"{org}\n\nAvailable tools:\n{cat}\n\nQuestion: {question}"
    system = SYSTEM
    transcript: list[dict] = []
    steps: list[dict] = []
    review: list[str] = []
    calls = bad = 0
    final = None
    bound = llm.for_role("analyst")
    for _ in range(steps_cap + 8):
        if checkpoint is not None and not checkpoint():
            istore.finish(inv_id, status="stopped", assessment=None, review="; ".join(review))
            return {"status": "stopped"}
        used = int(sum(int(v.get("tokens_in", 0)) + int(v.get("tokens_out", 0))
                       for v in (getattr(llm, "usage", {}) or {}).values() if isinstance(v, dict)))
        last = calls >= steps_cap or time.monotonic() > deadline or (lim.max_tokens and used >= lim.max_tokens)
        if last:
            transcript.append({"role": "user", "content": "No more tool calls. Reply with the assessment JSON now."})
        res = bound.chat([{"role": "system", "content": system}, {"role": "user", "content": user}, *_trimmed(transcript)],
                         max_tokens=1600)
        if res.error:
            istore.finish(inv_id, status="error", assessment=None, error=res.error[:500])
            return {"status": "error", "error": res.error[:300]}
        act = first_object(res.text or "") or {}
        a = str(act.get("action", ""))
        if a in ("assessment", "submit_assessment"):
            final = act
            break
        if a in ("call", "call_tool") and not last:
            if isinstance(act.get("arguments"), dict) and "tool" in act["arguments"] and "tool" not in act:
                act = {**act, **act["arguments"]}
            conn, tool = str(act.get("connector", "")), str(act.get("tool", ""))
            if "." in tool and not conn:
                conn, tool = tool.split(".", 1)
            args = act.get("arguments") if isinstance(act.get("arguments"), dict) else {}
            calls += 1
            n = len(steps) + 1
            ok, text = True, ""
            if (conn, tool) not in index:
                ok, text = False, f"unknown tool {conn}.{tool}; use one from the list"
            else:
                try:
                    if conn == local.LOCAL:
                        out = local.call(tool, args, cfg=cfg, store=kstore, actor=actor)
                        text = wrap(local.LOCAL, tool, local.as_text(out), lim.max_result_bytes)["content"]
                    else:
                        r = hub.call(conn, tool, args, actor=actor or "investigation", ref=f"investigation:{inv_id}",
                                     deadline=deadline)
                        ok, text = not r.get("is_error"), r["content"]
                except (ToolCallError, ValueError, TypeError, KeyError) as exc:
                    ok, text = False, f"error: {str(exc)[:300]}"
            hits = scan(text) if ok else []
            if hits:
                review.append(f"E{n}: " + ", ".join(h["pattern"] for h in hits))
            elif ok and '"document_flagged"' in text:
                review.append(f"E{n}: cites a document flagged for possible prompt injection")
            step = {"n": n, "connector": conn, "tool": tool, "arguments": args, "ok": ok, "result": text,
                    "thought": str(act.get("thought", ""))[:300]}
            steps.append(step)
            istore.add_step(inv_id, step)
            transcript.append({"role": "assistant", "content": json.dumps({k: act.get(k) for k in
                                                                            ("action", "connector", "tool", "arguments")})})
            transcript.append({"role": "user", "content": f"E{n} ({'ok' if ok else 'failed'}):\n{text}", "_result": True})
            continue
        bad += 1
        if bad > 3:
            break
        transcript.append({"role": "assistant", "content": (res.text or "")[:1000]})
        transcript.append({"role": "user", "content": "Reply with ONE JSON object: a call or the assessment."})
    if final is None:
        final = {"outcome": "not_enough_data", "answer": "The model did not give an assessment.", "confidence": 0,
                 "findings": []}
    checked = check_assessment(final, steps, question)
    checked["model"] = getattr(bound, "model", "")
    if hasattr(llm, "usage_summary"):
        checked["usage"] = llm.usage_summary()
    istore.finish(inv_id, status="done", assessment=checked, review="; ".join(review))
    return {"status": "done", **checked}


def cites(text: str) -> list[str]:
    return re.findall(r"\bE\d+\b", text or "")
