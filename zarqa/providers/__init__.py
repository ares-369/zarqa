"""Provider factory + role resolver.

``LLM.for_role("reporter")`` returns a (provider, model) bound pair the engine
can call without knowing or caring which backend serves it. Providers are
built lazily and cached; only the ones actually referenced get instantiated,
so an Ollama-only deployment never imports a cloud SDK.
"""

from __future__ import annotations

import re as _re
import threading
import time as _time
from dataclasses import dataclass
from typing import Any

from ..config import Config, get_config
from .base import LLMProvider, LLMResult, Message

# provider key in config -> (class path, env var holding its secret)
_SECRET_ENV = {
    "ollama": "",
    "anthropic": "ANTHROPIC_API_KEY",
    "gemini": "GEMINI_API_KEY",
    "openai": "OPENAI_API_KEY",
    "azure_openai": "AZURE_OPENAI_API_KEY",
    "openai_compatible": "OPENAI_COMPAT_API_KEY",
    "demo": "",
    "cli": "",
}


def _build(name: str, cfg: dict[str, Any], secret: str) -> LLMProvider:
    if name == "ollama":
        from .ollama import OllamaProvider
        return OllamaProvider(cfg, secret)
    if name == "anthropic":
        from .anthropic import AnthropicProvider
        return AnthropicProvider(cfg, secret)
    if name == "gemini":
        from .gemini import GeminiProvider
        return GeminiProvider(cfg, secret)
    if name in ("openai", "openai_compatible"):
        from .openai_compat import OpenAICompatProvider
        return OpenAICompatProvider(cfg, secret, name=name)
    if name == "azure_openai":
        from .openai_compat import OpenAICompatProvider
        return OpenAICompatProvider(cfg, secret, name="azure_openai", azure=True)
    if name == "cli":
        from .cli import CliProvider
        return CliProvider(cfg, secret)
    if name == "demo":
        from .demo import DemoProvider
        return DemoProvider(cfg, secret)
    raise ValueError(f"Unknown LLM provider: {name!r}")


_QUOTA = _re.compile(r"(?i)quota|rate.?limit|resource_exhausted|\b429\b|too many requests|resets in|overloaded|\b529\b")
# Used-up quota (daily/monthly limits, "resets in Xh"): skip the model for an hour.
_HARD_QUOTA = _re.compile(r"(?i)resets in|quota (exceeded|exhausted)|exceeded your (current )?quota|per.?day|daily|billing")
_COOLDOWN: dict[tuple[str, str], float] = {}   # (provider, model) -> skip until (monotonic)
COOLDOWN_SEC = 3600
SHORT_COOLDOWN_SEC = 60
# Short rate limits (shared-capacity 429s, overload) usually clear in seconds: retry with backoff first.
RETRY_DELAYS = (5.0, 15.0, 30.0, 60.0, 120.0)   # shared-capacity limits can last minutes


_LAST_CALL: dict[str, float] = {}


_PACE_LOCK = threading.Lock()


def _pace(provider: LLMProvider) -> None:
    """Optional ``min_interval_sec`` per provider: spaces requests to stay under per-minute limits.
    Thread-safe: parallel jobs reserve the next free slot in turn."""
    gap = float((provider.cfg or {}).get("min_interval_sec") or 0)
    if gap <= 0:
        return
    with _PACE_LOCK:
        now = _time.monotonic()
        slot = max(now, _LAST_CALL.get(provider.name, 0) + gap)
        _LAST_CALL[provider.name] = slot
    if slot > now:
        _time.sleep(slot - now)


@dataclass
class BoundModel:
    provider: LLMProvider
    model: str
    fallbacks: list = None   # list[BoundModel] tried in order when this one fails
    meter: dict = None       # shared usage totals: "provider/model" -> {calls, tokens_in, tokens_out}

    def _count(self, b, res) -> None:
        if self.meter is None:
            return
        m = self.meter.setdefault(f"{b.provider.name}/{b.model}",
                                  {"calls": 0, "tokens_in": 0, "tokens_out": 0, "tokens_cached": 0})
        m["calls"] += 1
        m["tokens_in"] += int(getattr(res, "tokens_in", 0) or 0)
        m["tokens_out"] += int(getattr(res, "tokens_out", 0) or 0)
        m["tokens_cached"] = m.get("tokens_cached", 0) + int(getattr(res, "tokens_cached", 0) or 0)

    def chat(self, messages: list[Message], **kw) -> LLMResult:
        chain = [self, *(self.fallbacks or [])]
        errors = []
        for b in chain:
            key = (b.provider.name, b.model)
            wait = _COOLDOWN.get(key, 0) - _time.monotonic()
            if 0 < wait <= SHORT_COOLDOWN_SEC and b is chain[-1]:
                _time.sleep(wait)   # last model in the chain on a short rate limit: wait it out
            elif wait > 0:
                errors.append(f"{b.provider.name}/{b.model}: skipped (quota cooldown)")
                continue
            _pace(b.provider)
            res = b.provider.chat(messages, model=b.model, **kw)
            self._count(b, res)
            for delay in RETRY_DELAYS:
                if not res.error or not _QUOTA.search(res.error) or _HARD_QUOTA.search(res.error):
                    break
                _time.sleep(delay)
                res = b.provider.chat(messages, model=b.model, **kw)
                self._count(b, res)
            if not res.error:
                if b is not self:
                    res.model = f"{b.model} (fallback)"
                return res
            errors.append(f"{b.provider.name}/{b.model}: {res.error[:300]}")
            if _QUOTA.search(res.error):
                hard = _HARD_QUOTA.search(res.error)
                _COOLDOWN[key] = _time.monotonic() + (COOLDOWN_SEC if hard else SHORT_COOLDOWN_SEC)
            elif len(chain) == 1:
                return res
        return LLMResult(text="", model=self.model, error=" | ".join(errors) or "no model available")


class LLM:
    def __init__(self, cfg: Config | None = None):
        self.cfg = cfg or get_config()
        self._cache: dict[str, LLMProvider] = {}
        self.usage: dict[str, dict] = {}   # totals for everything asked through this LLM

    def usage_summary(self, usage: dict | None = None) -> dict:
        """Model calls and tokens per model (input, of which cached by the provider's prompt cache, and
        output). ``usage``: a meter to summarise instead of this LLM's running total (each investigation keeps its own)."""
        usage = self.usage if usage is None else usage
        return {"models": {k: dict(v) for k, v in usage.items()},
                "calls": sum(u["calls"] for u in usage.values()),
                "tokens_in": sum(u["tokens_in"] for u in usage.values()),
                "tokens_out": sum(u["tokens_out"] for u in usage.values()),
                "tokens_cached": sum(int(u.get("tokens_cached", 0) or 0) for u in usage.values())}

    def provider(self, name: str) -> LLMProvider:
        if name not in self._cache:
            secret_env = _SECRET_ENV.get(name, "")
            secret = self.cfg.secret(secret_env) if secret_env else ""
            self._cache[name] = _build(name, self.cfg.provider_cfg(name), secret)
        return self._cache[name]

    def _bind(self, rc: dict) -> BoundModel:
        prov = self.provider(rc.get("provider", "ollama"))
        return BoundModel(provider=prov, model=rc.get("model") or prov.default_model, meter=self.usage)

    def for_role(self, role: str) -> BoundModel:
        """The role's model, with its optional ``fallback`` list (provider/model pairs) tried on errors."""
        rc = self.cfg.role_cfg(role)
        bound = self._bind(rc)
        bound.fallbacks = [self._bind(f) for f in rc.get("fallback") or [] if isinstance(f, dict)]
        return bound

    def configured_providers(self) -> list[str]:
        provs = (self.cfg.llm.get("providers") or {}).keys()
        return list(provs)

    def health(self) -> dict[str, bool]:
        out: dict[str, bool] = {}
        for name in self.configured_providers():
            try:
                out[name] = self.provider(name).health()
            except Exception:
                out[name] = False
        return out


_LLM: LLM | None = None


def get_llm(reload: bool = False) -> LLM:
    global _LLM
    if _LLM is None or reload:
        _LLM = LLM()
    return _LLM
