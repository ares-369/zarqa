"""Minimal stdio MCP server used by the bridges (JSON-RPC 2.0, newline framed)."""

from __future__ import annotations

import json
import sys
import traceback
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any, TextIO

PROTOCOL_VERSION = "2025-06-18"


class ToolInputError(ValueError):
    """Bad arguments from the caller; reported as a tool error, not a crash."""


@dataclass
class Tool:
    name: str
    description: str
    input_schema: dict[str, Any]
    fn: Callable[[dict[str, Any]], Any]
    annotations: dict[str, Any] = field(default_factory=lambda: {"readOnlyHint": True, "openWorldHint": True})

    def describe(self) -> dict[str, Any]:
        return {"name": self.name, "description": self.description, "inputSchema": self.input_schema,
                "annotations": self.annotations}


class McpServer:
    def __init__(self, name: str, version: str = "0", instructions: str = ""):
        self.name, self.version, self.instructions = name, version, instructions
        self.tools: dict[str, Tool] = {}

    def tool(self, name: str, description: str, schema: dict[str, Any]):
        def deco(fn):
            self.tools[name] = Tool(name, description, schema, fn)
            return fn
        return deco

    def add(self, tool: Tool) -> None:
        self.tools[tool.name] = tool

    # ---- dispatch ----
    def handle(self, msg: dict[str, Any]) -> dict[str, Any] | None:
        rid = msg.get("id")
        method = msg.get("method")
        if rid is None:          # notification
            return None
        try:
            if method == "initialize":
                res = {"protocolVersion": PROTOCOL_VERSION, "capabilities": {"tools": {}},
                       "serverInfo": {"name": self.name, "version": self.version}}
                if self.instructions:
                    res["instructions"] = self.instructions
                return _ok(rid, res)
            if method == "ping":
                return _ok(rid, {})
            if method == "tools/list":
                return _ok(rid, {"tools": [t.describe() for t in self.tools.values()]})
            if method == "tools/call":
                p = msg.get("params") or {}
                tool = self.tools.get(str(p.get("name")))
                if not tool:
                    return _err(rid, -32602, f"unknown tool {p.get('name')!r}")
                return _ok(rid, self._call(tool, p.get("arguments") or {}))
            return _err(rid, -32601, f"method {method!r} not supported")
        except Exception as exc:  # pragma: no cover - last resort
            return _err(rid, -32603, f"internal error: {exc}")

    @staticmethod
    def _call(tool: Tool, args: dict[str, Any]) -> dict[str, Any]:
        try:
            out = tool.fn(args)
        except ToolInputError as exc:
            return {"isError": True, "content": [{"type": "text", "text": f"invalid input: {exc}"}]}
        except Exception as exc:
            tb = traceback.format_exc(limit=1).strip().splitlines()[-1]
            return {"isError": True, "content": [{"type": "text", "text": f"{type(exc).__name__}: {exc} ({tb})"[:1000]}]}
        text = out if isinstance(out, str) else json.dumps(out, default=str)
        res: dict[str, Any] = {"content": [{"type": "text", "text": text}]}
        if isinstance(out, dict):
            res["structuredContent"] = out
        return res

    def serve(self, stdin: TextIO = sys.stdin, stdout: TextIO = sys.stdout) -> None:
        for line in stdin:
            line = line.strip()
            if not line:
                continue
            try:
                msg = json.loads(line)
            except ValueError:
                reply = _err(None, -32700, "parse error")
            else:
                reply = self.handle(msg) if isinstance(msg, dict) else _err(None, -32600, "invalid request")
            if reply is not None:
                stdout.write(json.dumps(reply) + "\n")
                stdout.flush()


def _ok(rid, result):
    return {"jsonrpc": "2.0", "id": rid, "result": result}


def _err(rid, code, message):
    return {"jsonrpc": "2.0", "id": rid, "error": {"code": code, "message": message}}
