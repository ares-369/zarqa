"""Anthropic (Claude) provider. Needs ANTHROPIC_API_KEY. SDK imported lazily."""

from __future__ import annotations

from typing import Any

from .base import LLMProvider, LLMResult, Message, action_json, action_tools, is_tool_loop_system


def _split_system(messages: list[Message]) -> tuple[str, list[Message]]:
    system = "\n\n".join(m["content"] for m in messages if m["role"] == "system")
    convo = [m for m in messages if m["role"] != "system"]
    return system, convo


class AnthropicProvider(LLMProvider):
    name = "anthropic"

    def __init__(self, cfg: dict[str, Any], secret: str = ""):
        super().__init__(cfg, secret)
        self.default_model = cfg.get("default_model", "claude-sonnet-4-5")

    def _client(self):
        import anthropic  # lazy: only required if this provider is used
        return anthropic.Anthropic(api_key=self.secret)

    def chat(self, messages: list[Message], *, model=None, temperature=0.2, max_tokens=900) -> LLMResult:
        use_model = model or self.default_model
        if not self.secret:
            return LLMResult(text="", model=use_model, error="ANTHROPIC_API_KEY not set")
        try:
            system, convo = _split_system(messages)
            kw: dict[str, Any] = {
                "model": use_model,
                "system": system or None,
                "messages": [{"role": m["role"], "content": m["content"]} for m in convo],
                "temperature": temperature,
                "max_tokens": max_tokens,
            }
            native = is_tool_loop_system(system) and self.cfg.get("native_tools", True)
            if native:
                kw["tools"] = [{"name": t["name"], "description": t["description"], "input_schema": t["parameters"]}
                               for t in action_tools(system)]
            try:
                resp = self._client().messages.create(**kw)
            except Exception:
                if not native:
                    raise
                kw.pop("tools", None)  # model or gateway without tool support: fall back to the JSON protocol
                resp = self._client().messages.create(**kw)
            u = getattr(resp, "usage", None)
            cached = int(getattr(u, "cache_read_input_tokens", 0) or 0)
            # Anthropic reports cache reads apart from input_tokens; count them in tokens_in as other providers do
            tok = {"tokens_in": int(getattr(u, "input_tokens", 0) or 0) + cached,
                   "tokens_out": int(getattr(u, "output_tokens", 0) or 0), "tokens_cached": cached}
            for b in resp.content:
                if getattr(b, "type", "") == "tool_use":
                    return LLMResult(text=action_json(b.name, dict(getattr(b, "input", None) or {})), model=use_model, **tok)
            text = "".join(b.text for b in resp.content if getattr(b, "type", "") == "text")
            return LLMResult(text=text.strip(), model=use_model, **tok)
        except Exception as exc:
            return LLMResult(text="", model=use_model, error=f"Anthropic error: {exc}")

    def health(self) -> bool:
        return bool(self.secret)
