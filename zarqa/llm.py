"""The model client every module uses: the configured providers wrapped in the privacy layer."""

from __future__ import annotations


def privacy_llm(cfg, llm=None):
    from .privacy import PrivacyLLM
    from .providers import get_llm
    return PrivacyLLM(llm or get_llm(), (cfg.raw or {}).get("privacy") or {})


def test_models(cfg) -> list[dict]:
    """Send one tiny prompt to each role's model (with its fallbacks) and report."""
    import time as _t

    from .config import LLM_ROLES
    from .providers import get_llm
    llm = privacy_llm(cfg, get_llm(reload=True))
    out = []
    for role in LLM_ROLES:
        t0 = _t.monotonic()
        b = llm.for_role(role)
        res = b.chat([{"role": "system", "content": "You are a connectivity check."},
                      {"role": "user", "content": 'Reply with exactly {"ok": true}'}], max_tokens=50)
        out.append({"role": role, "provider": b.provider.name, "model": res.model or b.model, "ok": not res.error,
                    "ms": int((_t.monotonic() - t0) * 1000), "error": (res.error or "")[:400],
                    "reply": (res.text or "")[:80]})
    return out
