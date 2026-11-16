"""Minimal MCP client (JSON-RPC 2.0) for the stdio and streamable HTTP transports.

Only what Zarqa needs: ``initialize``, ``tools/list`` and
``tools/call``. Server-to-client requests (sampling, elicitation, roots) are
refused: a data source must never be able to drive the model or the user.
"""

from __future__ import annotations

import json
import os
import queue
import subprocess
import threading
import time
from typing import Any

import requests

from .spec import ConnectorSpec, expand_env

PROTOCOL_VERSION = "2025-06-18"
CLIENT_INFO = {"name": "zarqa", "version": "0"}


class McpError(RuntimeError):
    pass


def _secret(auth: dict, key: str) -> str:
    """Read ``key`` from ``<key>_env`` (env var name) or a ``${VAR}`` reference."""
    if auth.get(f"{key}_env"):
        return os.getenv(str(auth[f"{key}_env"]), "")
    return expand_env(auth.get(key, ""))


class _OAuthCC:
    """OAuth 2.0 client-credentials token cache."""

    def __init__(self, auth: dict, timeout: float, verify: bool):
        self.auth, self.timeout, self.verify = auth, timeout, verify
        self._tok, self._exp = "", 0.0

    def token(self) -> str:
        if self._tok and time.time() < self._exp - 30:
            return self._tok
        data = {"grant_type": "client_credentials", "client_id": str(self.auth.get("client_id", "")),
                "client_secret": _secret(self.auth, "client_secret")}
        if self.auth.get("scope"):
            data["scope"] = str(self.auth["scope"])
        if self.auth.get("audience"):
            data["audience"] = str(self.auth["audience"])
        r = requests.post(str(self.auth.get("token_url", "")), data=data, timeout=self.timeout, verify=self.verify)
        r.raise_for_status()
        j = r.json()
        self._tok = str(j["access_token"])
        self._exp = time.time() + float(j.get("expires_in", 300))
        return self._tok


class McpClient:
    def __init__(self, spec: ConnectorSpec):
        self.spec = spec
        self._id = 0
        self._lock = threading.Lock()
        # One request at a time per stdio process: replies share one stream, so a second caller
        # waiting at the same time could read (and drop) the first caller's reply.
        self._io_lock = threading.Lock()
        self._local = threading.local()   # per-thread call timeout override
        self.server_info: dict[str, Any] = {}
        self._initialized = False
        # stdio
        self._proc: subprocess.Popen | None = None
        self._lines: queue.Queue = queue.Queue()
        # http
        self._session_id = ""
        self._http = requests.Session()
        self._oauth = (_OAuthCC(spec.auth, spec.timeout_sec, spec.verify_tls)
                       if spec.auth.get("type") == "oauth_client_credentials" else None)
        self._oauth_user = None
        if spec.auth.get("type") == "oauth":
            from ..config import get_config
            from .oauth import TokenStore
            self._oauth_user = TokenStore(spec, get_config().data_dir)

    # ---- lifecycle ----
    def connect(self) -> dict[str, Any]:
        if self._initialized:
            return self.server_info
        if self.spec.transport == "stdio":
            self._start_stdio()
        res = self._request("initialize", {
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": {},          # no sampling / roots / elicitation
            "clientInfo": CLIENT_INFO,
        })
        self.server_info = res or {}
        self._notify("notifications/initialized")
        self._initialized = True
        return self.server_info

    def close(self) -> None:
        self._initialized = False
        if self._proc:
            try:
                self._proc.stdin.close()  # type: ignore[union-attr]
                self._proc.terminate()
                self._proc.wait(timeout=3)
            except Exception:
                self._proc.kill()
            self._proc = None
        if self.spec.transport == "http" and self._session_id:
            try:
                self._http.delete(self.spec.url, headers=self._headers(), timeout=5, verify=self.spec.verify_tls)
            except Exception:
                pass
            self._session_id = ""

    # ---- MCP methods ----
    def list_tools(self) -> list[dict[str, Any]]:
        self.connect()
        tools: list[dict[str, Any]] = []
        cursor = None
        for _ in range(50):
            res = self._request("tools/list", {"cursor": cursor} if cursor else {}) or {}
            tools.extend(res.get("tools") or [])
            cursor = res.get("nextCursor")
            if not cursor:
                break
        return tools

    def call_tool(self, name: str, arguments: dict[str, Any], *, timeout: float | None = None) -> dict[str, Any]:
        """``timeout``: seconds for this call, when shorter than the connector's own timeout_sec."""
        self.connect()
        self._local.timeout = timeout
        try:
            return self._request("tools/call", {"name": name, "arguments": arguments}) or {}
        finally:
            self._local.timeout = None

    def _timeout(self) -> float:
        t = getattr(self._local, "timeout", None)
        return min(self.spec.timeout_sec, t) if t else self.spec.timeout_sec

    # ---- JSON-RPC plumbing ----
    def _next_id(self) -> int:
        with self._lock:
            self._id += 1
            return self._id

    def _request(self, method: str, params: dict[str, Any]) -> Any:
        rid = self._next_id()
        msg = {"jsonrpc": "2.0", "id": rid, "method": method, "params": params}
        reply = self._stdio_roundtrip(msg) if self.spec.transport == "stdio" else self._http_roundtrip(msg)
        if "error" in reply:
            e = reply["error"] or {}
            raise McpError(f"{method}: {e.get('message', 'error')} (code {e.get('code')})")
        return reply.get("result")

    def _notify(self, method: str) -> None:
        msg = {"jsonrpc": "2.0", "method": method}
        if self.spec.transport == "stdio":
            self._write(msg)
        else:
            self._http.post(self.spec.url, json=msg, headers=self._headers(),
                            timeout=self._timeout(), verify=self.spec.verify_tls)

    @staticmethod
    def _refusal(msg: dict) -> dict:
        return {"jsonrpc": "2.0", "id": msg["id"],
                "error": {"code": -32601, "message": "not supported by this client"}}

    # ---- stdio ----
    def _start_stdio(self) -> None:
        env = {k: v for k, v in os.environ.items() if k in ("PATH", "HOME", "LANG", "TMPDIR", "SYSTEMROOT")}
        env.update({k: expand_env(v) for k, v in self.spec.env.items()})
        argv = [self.spec.command, *[expand_env(a) for a in self.spec.args]]
        if self.spec.command == "zarqa":   # built-in bridges: run with this interpreter
            import sys
            argv = [sys.executable, "-m", "zarqa", *argv[1:]]
            env["PYTHONSAFEPATH"] = "1"      # avoid shadowing by a repo folder named ./zarqa in cwd
        self._proc = subprocess.Popen(argv,
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            env=env, text=True, bufsize=1)
        out = self._proc.stdout

        def pump():
            for line in out:  # type: ignore[union-attr]
                self._lines.put(line)
            self._lines.put(None)
        threading.Thread(target=pump, daemon=True, name=f"mcp-{self.spec.name}").start()

    def _write(self, msg: dict) -> None:
        if not self._proc or self._proc.poll() is not None:
            raise McpError("connector process is not running")
        self._proc.stdin.write(json.dumps(msg) + "\n")  # type: ignore[union-attr]
        self._proc.stdin.flush()  # type: ignore[union-attr]

    def _stdio_roundtrip(self, msg: dict) -> dict:
        with self._io_lock:
            return self._stdio_roundtrip_locked(msg)

    def _stdio_roundtrip_locked(self, msg: dict) -> dict:
        self._write(msg)
        deadline = time.monotonic() + self._timeout()
        while True:
            left = deadline - time.monotonic()
            if left <= 0:
                raise McpError(f"timed out after {self._timeout()}s")
            try:
                line = self._lines.get(timeout=left)
            except queue.Empty:
                continue
            if line is None:
                raise McpError("connector process exited")
            try:
                reply = json.loads(line)
            except ValueError:
                continue  # stray log output on stdout
            if not isinstance(reply, dict):
                continue
            if "method" in reply:           # server -> client
                if "id" in reply:
                    self._write(self._refusal(reply) if reply["method"] != "ping"
                                else {"jsonrpc": "2.0", "id": reply["id"], "result": {}})
                continue
            if reply.get("id") == msg["id"]:
                return reply

    # ---- streamable HTTP ----
    def _headers(self) -> dict[str, str]:
        h = {"Accept": "application/json, text/event-stream", "Content-Type": "application/json",
             "MCP-Protocol-Version": PROTOCOL_VERSION}
        h.update({k: expand_env(v) for k, v in self.spec.headers.items()})
        a = self.spec.auth
        t = a.get("type", "none")
        if t == "bearer":
            h["Authorization"] = f"Bearer {_secret(a, 'token')}"
        elif t == "api_key":
            key = _secret(a, "api_key")
            hdr = str(a.get("header", "X-API-Key"))
            h[hdr] = f"{a.get('prefix', '')}{key}"
        elif t == "oauth_client_credentials" and self._oauth:
            h["Authorization"] = f"Bearer {self._oauth.token()}"
        elif t == "oauth" and self._oauth_user:
            h["Authorization"] = f"Bearer {self._oauth_user.token()}"
        if self._session_id:
            h["Mcp-Session-Id"] = self._session_id
        return h

    def _http_roundtrip(self, msg: dict) -> dict:
        r = self._http.post(self.spec.url, json=msg, headers=self._headers(), stream=True,
                            timeout=self._timeout(), verify=self.spec.verify_tls)
        if r.status_code in (401, 403):
            raise McpError(f"HTTP {r.status_code}: authentication failed")
        if r.status_code >= 400:
            raise McpError(f"HTTP {r.status_code}")
        sid = r.headers.get("Mcp-Session-Id")
        if sid:
            self._session_id = sid
        ctype = r.headers.get("Content-Type", "")
        if "text/event-stream" in ctype:
            return self._read_sse(r, msg["id"])
        reply = r.json()
        if isinstance(reply, list):
            reply = next((m for m in reply if m.get("id") == msg["id"]), {})
        return reply

    def _read_sse(self, r: requests.Response, rid: int) -> dict:
        data: list[str] = []
        deadline = time.monotonic() + self._timeout()
        for raw in r.iter_lines(decode_unicode=True):
            if time.monotonic() > deadline:
                break
            if raw is None:
                continue
            if raw.startswith("data:"):
                data.append(raw[5:].lstrip())
                continue
            if raw == "" and data:
                try:
                    m = json.loads("\n".join(data))
                except ValueError:
                    m = None
                data = []
                if isinstance(m, dict):
                    if m.get("id") == rid and "method" not in m:
                        r.close()
                        return m
                    if "method" in m and "id" in m:
                        self._http.post(self.spec.url, json=self._refusal(m), headers=self._headers(),
                                        timeout=self._timeout(), verify=self.spec.verify_tls)
        r.close()
        raise McpError("no response in event stream")
