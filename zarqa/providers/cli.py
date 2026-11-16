"""Local CLI model provider: runs a command-line model client for each request.

For model tools you are signed in to on this machine (for example a vendor's
own CLI on a subscription). The command is a list; ``{prompt}``, ``{model}``
and ``{timeout}`` are filled in. The prompt is passed as one argument (no
shell). Messages are flattened to plain text with role headers.

    llm:
      providers:
        cli:
          command: ["/path/to/model-cli", "--model", "{model}", "-p={prompt}"]
          default_model: "some-model"
          timeout_sec: 180
          cwd: ""                  # default: an empty private scratch folder
          max_prompt_bytes: 120000 # argument size limit; older large results are trimmed to fit

The CLI may have its own tools (files, browser). Run it in its most restricted
mode in the command you configure; Zarqa gives it an empty working folder.
Output on a non-zero exit is reported as an error.
"""

from __future__ import annotations

import os
import subprocess
import tempfile

from .base import LLMProvider, LLMResult, Message


def flatten(messages: list[Message], max_bytes: int) -> str:
    parts = [f"### {m['role'].upper()}\n{m.get('content', '')}" for m in messages]
    text = "\n\n".join(parts)
    if len(text.encode()) <= max_bytes:
        return text
    # trim the largest messages, oldest first (never the system prompt or the last message)
    budget = max_bytes - 2000
    keep = [0, len(parts) - 1]
    order = sorted(range(1, len(parts) - 1), key=lambda i: (-len(parts[i]), i))
    for i in order:
        if len("\n\n".join(parts).encode()) <= budget:
            break
        if i in keep:
            continue
        p = parts[i]
        parts[i] = p[:1200] + "\n[trimmed to fit the prompt size limit]"
    text = "\n\n".join(parts)
    while len(text.encode()) > max_bytes and len(parts) > 3:
        parts.pop(1)
        text = "\n\n".join(parts)
    return text.encode()[:max_bytes].decode("utf-8", "ignore")


class CliProvider(LLMProvider):
    name = "cli"

    def __init__(self, cfg, secret=""):
        super().__init__(cfg, secret)
        self.command = [str(c) for c in self.cfg.get("command") or []]
        self.timeout = float(self.cfg.get("timeout_sec", 180))
        self.max_prompt = int(self.cfg.get("max_prompt_bytes", 120_000))
        self.cwd = self.cfg.get("cwd") or tempfile.mkdtemp(prefix="zarqa-cli-")

    def chat(self, messages, *, model=None, temperature=0.2, max_tokens=900) -> LLMResult:
        use = model or self.default_model
        if not self.command:
            return LLMResult(text="", model=use, error="cli provider: llm.providers.cli.command is not set")
        prompt = flatten(messages, self.max_prompt) + "\n\n### ASSISTANT\n"
        argv = [c.replace("{model}", use).replace("{timeout}", str(int(self.timeout))).replace("{prompt}", prompt)
                for c in self.command]
        env = {k: v for k, v in os.environ.items() if not k.startswith(("ZARQA_", "BRIDGE_"))}
        try:
            r = subprocess.run(argv, cwd=self.cwd, capture_output=True, text=True, timeout=self.timeout + 30,
                               stdin=subprocess.DEVNULL, env=env)
        except subprocess.TimeoutExpired:
            return LLMResult(text="", model=use, error=f"cli provider timed out after {self.timeout:.0f}s")
        except OSError as exc:
            return LLMResult(text="", model=use, error=f"cli provider could not start: {exc}")
        out = (r.stdout or "").strip()
        if r.returncode != 0:
            tail = (r.stderr or out or "")[-500:]
            return LLMResult(text="", model=use, error=f"cli provider exit {r.returncode}: {tail}")
        return LLMResult(text=out, model=use)

    def health(self) -> bool:
        return bool(self.command) and os.path.exists(self.command[0])
