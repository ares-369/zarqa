"""REST/OpenAPI bridge: turns the read operations of an OpenAPI 3 spec into MCP tools.

* Every ``GET`` operation becomes a tool (filtered by ``--include``/``--exclude``).
* ``POST`` operations are exposed ONLY when named with ``--allow-post <operationId>``,
  for APIs whose searches are POST requests. Name only operations that read.
* ``PUT``, ``PATCH`` and ``DELETE`` are never exposed.
"""

from __future__ import annotations

import argparse
import fnmatch
import json
import re
from pathlib import Path
from typing import Any
from urllib.parse import quote, urljoin

import yaml

from .common import check_status, session_from_env
from .server import McpServer, Tool, ToolInputError

MAX_TEXT = 500_000


def _name(op: dict, method: str, path: str) -> str:
    raw = op.get("operationId") or f"{method}_{path}"
    n = re.sub(r"[^A-Za-z0-9_-]+", "_", raw).strip("_")
    return n[:64] or "op"


class OpenApiBridge:
    def __init__(self, spec: dict, base_url: str = "", include: list[str] | None = None,
                 exclude: list[str] | None = None, allow_post: list[str] | None = None, max_tools: int = 150,
                 verify_tls: bool = True, ca_bundle: str = "", timeout: float = 30, session=None):
        self.spec = spec
        servers = spec.get("servers") or [{}]
        self.base = (base_url or servers[0].get("url", "")).rstrip("/") + "/"
        if not self.base.startswith(("http://", "https://")):
            raise ValueError("no usable base URL: pass --base-url")
        self.include, self.exclude = include or [], exclude or []
        self.allow_post = set(allow_post or [])
        self.max_tools, self.timeout = max_tools, timeout
        self.http = session or session_from_env("BRIDGE", verify_tls, ca_bundle)
        self.ops: dict[str, dict] = {}

    def _ref(self, obj: dict) -> dict:
        seen = 0
        while isinstance(obj, dict) and "$ref" in obj and seen < 10:
            node: Any = self.spec
            for part in str(obj["$ref"]).lstrip("#/").split("/"):
                node = (node or {}).get(part.replace("~1", "/").replace("~0", "~"), {})
            obj, seen = node, seen + 1
        return obj if isinstance(obj, dict) else {}

    def _wanted(self, name: str, path: str) -> bool:
        if self.include and not any(fnmatch.fnmatchcase(name, p) or fnmatch.fnmatchcase(path, p) for p in self.include):
            return False
        return not any(fnmatch.fnmatchcase(name, p) or fnmatch.fnmatchcase(path, p) for p in self.exclude)

    def collect(self) -> dict[str, dict]:
        for path, item in (self.spec.get("paths") or {}).items():
            item = self._ref(item)
            shared = item.get("parameters") or []
            for method in ("get", "post"):
                op = item.get(method)
                if not op:
                    continue
                name = _name(op, method, path)
                if method == "post" and name not in self.allow_post and op.get("operationId") not in self.allow_post:
                    continue
                if not self._wanted(name, path):
                    continue
                params = [self._ref(p) for p in shared + (op.get("parameters") or [])]
                params = [p for p in params if p.get("in") in ("path", "query") and p.get("name")]
                props, required = {}, []
                for p in params:
                    sch = dict(self._ref(p.get("schema") or {}))
                    sch = {k: v for k, v in sch.items() if k in ("type", "enum", "format", "items", "default")}
                    if p.get("description"):
                        sch["description"] = str(p["description"])[:300]
                    props[p["name"]] = sch or {"type": "string"}
                    if p.get("required") or p.get("in") == "path":
                        required.append(p["name"])
                if method == "post":
                    props["body"] = {"type": "object", "description": "JSON request body"}
                desc = str(op.get("summary") or op.get("description") or f"{method.upper()} {path}")[:400]
                self.ops[name] = {"method": method, "path": path, "params": params,
                                  "schema": {"type": "object", "properties": props, "required": required},
                                  "description": f"{desc} ({method.upper()} {path})"}
        if len(self.ops) > self.max_tools:
            raise ValueError(f"the spec gives {len(self.ops)} operations (limit {self.max_tools}); "
                             "narrow it with --include")
        return self.ops

    def call(self, name: str, args: dict) -> Any:
        op = self.ops[name]
        path = op["path"]
        query: dict[str, Any] = {}
        for p in op["params"]:
            v = args.get(p["name"])
            if v is None:
                if p.get("in") == "path":
                    raise ToolInputError(f"{p['name']} is required")
                continue
            if p["in"] == "path":
                path = path.replace("{" + p["name"] + "}", quote(str(v), safe=""))
            else:
                query[p["name"]] = v
        url = urljoin(self.base, path.lstrip("/"))
        if not url.startswith(self.base):
            raise ToolInputError("resolved URL left the API base")
        if op["method"] == "get":
            r = self.http.get(url, params=query, timeout=self.timeout)
        else:
            body = args.get("body") or {}
            if not isinstance(body, dict):
                raise ToolInputError("body must be a JSON object")
            r = self.http.post(url, params=query, json=body, timeout=self.timeout)
        check_status(r)
        try:
            data = r.json()
            text = json.dumps(data)
        except ValueError:
            text = r.text
        if len(text) > MAX_TEXT:
            return text[:MAX_TEXT] + "\n[truncated]"
        return text

    def build(self) -> McpServer:
        self.collect()
        title = (self.spec.get("info") or {}).get("title", "REST API")
        srv = McpServer("zarqa-openapi", instructions=f"Read-only REST bridge for {title}.")
        for name, op in self.ops.items():
            srv.add(Tool(name, op["description"], op["schema"], lambda a, n=name: self.call(n, a)))
        return srv


def load_spec(source: str, session=None) -> dict:
    if source.startswith(("http://", "https://")):
        import requests
        r = (session or requests).get(source, timeout=30)
        r.raise_for_status()
        text = r.text
    else:
        text = Path(source).expanduser().read_text()
    spec = yaml.safe_load(text)
    if not isinstance(spec, dict) or "paths" not in spec:
        raise ValueError("not an OpenAPI document (no paths)")
    return spec


def add_args(p: argparse.ArgumentParser) -> None:
    p.add_argument("--spec", required=True, help="OpenAPI 3 file path or URL (JSON or YAML)")
    p.add_argument("--base-url", default="")
    p.add_argument("--include", action="append", default=[], help="operationId or path glob to expose")
    p.add_argument("--exclude", action="append", default=[])
    p.add_argument("--allow-post", action="append", default=[], help="operationId of a read-only POST search")
    p.add_argument("--max-tools", type=int, default=150)
    p.add_argument("--insecure", action="store_true")
    p.add_argument("--ca-bundle", default="")


def run(a: argparse.Namespace) -> None:
    sess = session_from_env("BRIDGE", not a.insecure, a.ca_bundle)
    spec = load_spec(a.spec, sess)
    OpenApiBridge(spec, a.base_url, a.include, a.exclude, a.allow_post, a.max_tools,
                  session=sess, timeout=30).build().serve()
