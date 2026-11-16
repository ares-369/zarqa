"""Local Ollama provider (no API key, plain HTTP). The default.

Ollama's own default context window is small (2,048 to 4,096 tokens) and it drops the start of a longer
prompt without an error, so a long prompt would lose its instructions. The provider asks for
``num_ctx`` tokens (default 8192) instead; lower it on a small GPU, raise it if the model allows.
"""

from __future__ import annotations

import re
from typing import Any

import requests

from .base import LLMProvider, LLMResult, Message

_THINK_RE = re.compile(r"<think>.*?</think>", re.DOTALL)


class OllamaProvider(LLMProvider):
    name = "ollama"

    def __init__(self, cfg: dict[str, Any], secret: str = ""):
        super().__init__(cfg, secret)
        self.base_url = (cfg.get("base_url") or "http://localhost:11434").rstrip("/")
        self.num_ctx = int(cfg.get("num_ctx") or 8192)
        self.timeout = float(cfg.get("timeout_sec") or 300)
        self.think = cfg.get("think")      # None: the model's default; false turns off a reasoning model's thinking
        # Ollama counts a reasoning model's thinking against num_predict, so leave room for it. A cap only:
        # models that do not think stop when their answer is done.
        self.think_tokens = 0 if self.think is False else int(cfg.get("think_tokens", 6000) or 0)

    def chat(self, messages: list[Message], *, model=None, temperature=0.2, max_tokens=900) -> LLMResult:
        use_model = model or self.default_model
        try:
            body = {
                "model": use_model,
                "messages": messages,
                "stream": False,
                "options": {"temperature": temperature, "num_predict": max_tokens + self.think_tokens,
                            "num_ctx": self.num_ctx},
            }
            if self.think is not None:
                body["think"] = bool(self.think)
            r = requests.post(f"{self.base_url}/api/chat", json=body, timeout=self.timeout)
            r.raise_for_status()
            data = r.json()
            content = data.get("message", {}).get("content", "") or ""
            if not content.strip() and (data.get("message", {}).get("thinking") or ""):
                return LLMResult(text="", model=use_model, tokens_in=int(data.get("prompt_eval_count") or 0),
                                 tokens_out=int(data.get("eval_count") or 0),
                                 error="Ollama error: the model used its whole reply budget thinking and gave no answer; "
                                       "raise llm.providers.ollama.think_tokens")
            content = _THINK_RE.sub("", content).strip()
            tokens_in = int(data.get("prompt_eval_count") or 0)
            if tokens_in >= self.num_ctx - 16:
                return LLMResult(text="", model=use_model, tokens_in=tokens_in,
                                 error=f"Ollama error: the prompt filled the {self.num_ctx}-token context and was cut; "
                                       "raise llm.providers.ollama.num_ctx or use prompt_mode: compact")
            return LLMResult(text=content or "(empty response)", model=use_model,
                             tokens_in=tokens_in, tokens_out=int(data.get("eval_count") or 0))
        except Exception as exc:
            return LLMResult(text="", model=use_model, error=f"Ollama error: {exc}")

    def available_models(self) -> list[str]:
        try:
            r = requests.get(f"{self.base_url}/api/tags", timeout=4)
            if r.status_code == 200:
                return [m["name"] for m in r.json().get("models", []) if "embed" not in m["name"]]
        except Exception:
            pass
        return super().available_models()

    def health(self) -> bool:
        try:
            return requests.get(f"{self.base_url}/api/tags", timeout=3).status_code == 200
        except Exception:
            return False
