"""OpenAI and OpenAI-compatible providers.

One implementation covers:
  * openai            — api.openai.com (OPENAI_API_KEY)
  * azure_openai      — an Azure endpoint (AZURE_OPENAI_API_KEY + base_url)
  * openai_compatible — vLLM / LM Studio / OpenRouter / anything that speaks
                        the OpenAI Chat Completions API (OPENAI_COMPAT_API_KEY
                        + base_url)

The OpenAI Python SDK is imported lazily.
"""

from __future__ import annotations

import json
from typing import Any

from .base import LLMProvider, LLMResult, Message, action_json, action_tools, is_tool_loop_system


class OpenAICompatProvider(LLMProvider):
    name = "openai"

    def __init__(self, cfg: dict[str, Any], secret: str = "", *, name: str = "openai",
                 azure: bool = False):
        super().__init__(cfg, secret)
        self.name = name
        self.azure = azure
        self.base_url = cfg.get("base_url") or ""
        self.api_version = cfg.get("api_version", "2024-10-21")
        self.default_model = cfg.get("default_model", "gpt-4.1")

    def _client(self):
        if self.azure:
            from openai import AzureOpenAI  # lazy
            return AzureOpenAI(
                api_key=self.secret,
                azure_endpoint=self.base_url,
                api_version=self.api_version,
            )
        from openai import OpenAI  # lazy
        kwargs: dict[str, Any] = {"api_key": self.secret or "not-needed"}
        if self.base_url:
            kwargs["base_url"] = self.base_url
        return OpenAI(**kwargs)

    def chat(self, messages: list[Message], *, model=None, temperature=0.2, max_tokens=900) -> LLMResult:
        use_model = model or self.default_model
        try:
            system = "\n\n".join(m["content"] for m in messages if m["role"] == "system")
            kw: dict[str, Any] = {
                "model": use_model,
                "messages": [{"role": m["role"], "content": m["content"]} for m in messages],
                "temperature": temperature,
                "max_tokens": max_tokens,
            }
            native = is_tool_loop_system(system) and self.cfg.get("native_tools", True)
            if native:
                kw["tools"] = [{"type": "function", "function": t} for t in action_tools(system)]
            client = self._client()
            try:
                resp = client.chat.completions.create(**kw)
            except Exception:
                if not native:
                    raise
                kw.pop("tools", None)  # many local models reject tools: fall back to the JSON protocol
                resp = client.chat.completions.create(**kw)
            u = getattr(resp, "usage", None)
            det = getattr(u, "prompt_tokens_details", None)
            tok = {"tokens_in": int(getattr(u, "prompt_tokens", 0) or 0), "tokens_out": int(getattr(u, "completion_tokens", 0) or 0),
                   "tokens_cached": int(getattr(det, "cached_tokens", 0) or 0)}
            msg = resp.choices[0].message
            tcs = getattr(msg, "tool_calls", None) or []
            if tcs:
                fn = tcs[0].function
                try:
                    args = json.loads(fn.arguments) if isinstance(fn.arguments, str) else (fn.arguments or {})
                except ValueError:
                    args = {}
                return LLMResult(text=action_json(fn.name, args), model=use_model, **tok)
            return LLMResult(text=(msg.content or "").strip(), model=use_model, **tok)
        except Exception as exc:
            return LLMResult(text="", model=use_model, error=f"{self.name} error: {exc}")

    def health(self) -> bool:
        # Local OpenAI-compatible servers may need no key; clouds do.
        return bool(self.secret or self.base_url)
