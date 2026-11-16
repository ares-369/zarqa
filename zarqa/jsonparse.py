"""Get one JSON object out of a model reply (fenced, prefixed with prose, or bare)."""

from __future__ import annotations

import json
import re

_FENCE = re.compile(r"```(?:json)?\s*(\{.*?\})\s*```", re.S)


def first_object(text: str) -> dict | None:
    if not text:
        return None
    m = _FENCE.search(text)
    candidates = [m.group(1)] if m else []
    start = text.find("{")
    while start != -1 and len(candidates) < 6:
        depth, in_str, esc = 0, False, False
        for i in range(start, len(text)):
            ch = text[i]
            if in_str:
                if esc:
                    esc = False
                elif ch == "\\":
                    esc = True
                elif ch == '"':
                    in_str = False
            elif ch == '"':
                in_str = True
            elif ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    candidates.append(text[start:i + 1])
                    break
        start = text.find("{", start + 1)
    for c in candidates:
        try:
            obj = json.loads(c)
        except ValueError:
            continue
        if isinstance(obj, dict):
            return obj
    return None


def action_object(text: str) -> dict | None:
    """first_object, then normalize the native-tool shapes models copy into text replies:
    {"action": "submit_verdict", "arguments": {...}} -> {"action": "verdict", ...}
    {"action": "call_tool", "arguments": {"connector", "tool", "arguments"}} -> {"action": "call", ...}
    """
    obj = first_object(text)
    if not isinstance(obj, dict):
        return obj
    act = str(obj.get("action") or obj.get("name") or "")
    inner = obj.get("arguments") if isinstance(obj.get("arguments"), dict) else obj.get("args")
    if act == "submit_verdict":
        out = {k: v for k, v in obj.items() if k not in ("action", "name", "arguments", "args")}
        if isinstance(inner, dict):
            out.update(inner)
        return {"action": "verdict", **out}
    if act == "submit_case":
        out = {k: v for k, v in obj.items() if k not in ("action", "name", "arguments", "args")}
        if isinstance(inner, dict):
            out.update(inner)
        return {"action": "case", **out}
    if act == "call_tool":
        out = {k: v for k, v in obj.items() if k not in ("action", "name", "arguments", "args")}
        if isinstance(inner, dict) and ("tool" in inner or "connector" in inner):
            out.update(inner)
        elif isinstance(inner, dict):
            out["arguments"] = inner
        return {"action": "call", **out}
    return obj
