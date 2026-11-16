"""Connector definitions from config.yaml ``connectors:``.

Example::

    connectors:
      - name: platform
        roles: [intel_platform]
        transport: http            # http | stdio
        url: https://mcp.example.internal/mcp
        auth: {type: bearer, token_env: PLATFORM_MCP_TOKEN}
        dialect: ""                # free text hint for the planner
        tools: {allow: [], deny: []}
        allow_write: false
        rate_per_min: 60
        timeout_sec: 30
      - name: reputation
        roles: [enrichment]
        transport: stdio
        command: python
        args: ["-m", "some_mcp_server"]
        env: {API_KEY: "${INTEL_API_KEY}"}

Secrets are never written in config.yaml: use ``*_env`` keys or ``${VAR}``.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from typing import Any

# Roles an investigation may read from.
#   intel_platform: another threat intel platform or sharing server (read side)
#   enrichment:     reputation, WHOIS/RDAP, DNS and passive DNS, certificates, geolocation, ASN
#   search:         web search and page fetch
#   vuln:           vulnerability and exploit data
#   malware:        file and sample lookups, sandboxes
#   brand:          domain registration and lookalike sources
#   analysis:       local helpers (decoding, parsing); not a data source
ROLES = ("intel_platform", "enrichment", "search", "vuln", "malware", "brand", "analysis")
# Roles that are never offered to a model: pushing intel out to other platforms and tickets (outputs only).
ACTION_ROLES = ("sharing", "ticketing")
DATA_ROLES = ("intel_platform", "enrichment", "search", "vuln", "malware", "brand")
AUTH_TYPES = ("none", "api_key", "bearer", "oauth_client_credentials", "oauth")
_NAME_RE = re.compile(r"[a-z0-9][a-z0-9_-]{0,39}")
_VAR_RE = re.compile(r"\$\{([A-Z0-9_]+)\}")


def expand_env(value: str) -> str:
    """Replace ``${VAR}`` with the environment value (empty if unset)."""
    return _VAR_RE.sub(lambda m: os.getenv(m.group(1), ""), str(value))


@dataclass
class ConnectorSpec:
    name: str
    roles: list[str]
    transport: str
    url: str = ""
    command: str = ""
    args: list[str] = field(default_factory=list)
    env: dict[str, str] = field(default_factory=dict)
    headers: dict[str, str] = field(default_factory=dict)
    auth: dict[str, Any] = field(default_factory=dict)
    dialect: str = ""
    description: str = ""
    query_notes: str = ""                     # how to write queries for this source (from config or a file)
    query_examples: list[dict] = field(default_factory=list)   # [{goal, query}]
    allow: list[str] = field(default_factory=list)
    deny: list[str] = field(default_factory=list)
    allow_write: bool = False
    rate_per_min: int = 60
    timeout_sec: float = 30.0
    enabled: bool = True
    verify_tls: bool = True
    access: list[str] = field(default_factory=list)   # who may use it: group, role:<r>, user:<u>; empty = all
    enrich: list[dict] = field(default_factory=list)   # [{types, tool, argument, arguments}] value lookups

    def public(self) -> dict[str, Any]:
        """Safe view for the UI/API (no secrets, no env values)."""
        return {
            "name": self.name, "roles": self.roles, "transport": self.transport,
            "url": self.url, "command": self.command, "dialect": self.dialect,
            "description": self.description, "auth_type": self.auth.get("type", "none"),
            "allow": self.allow, "deny": self.deny, "allow_write": self.allow_write, "access": self.access,
            "rate_per_min": self.rate_per_min, "enabled": self.enabled,
            "query_notes": bool(self.query_notes), "query_examples": len(self.query_examples),
            "enrich": [{"types": e["types"], "tool": e["tool"]} for e in self.enrich],
        }


def _notes(name: str, raw: dict[str, Any]) -> str:
    text = str(raw.get("query_notes", "") or "")
    path = raw.get("query_notes_file")
    if path:
        from pathlib import Path
        p = Path(str(path)).expanduser()
        if not p.is_file():
            raise ValueError(f"connector {name}: query_notes_file {p} does not exist")
        text = (text + "\n" + p.read_text(errors="replace")).strip()
    return text[:6000]


ENRICH_TYPES = ("ipv4", "ipv6", "domain", "url", "email", "md5", "sha1", "sha256", "cve")


def _enrich(name: str, items) -> list[dict]:
    """``enrich:`` maps value types to a lookup tool: which tool to call and which argument gets the value."""
    out = []
    for e in items or []:
        if not isinstance(e, dict) or not e.get("tool") or not e.get("argument"):
            raise ValueError(f"connector {name}: each enrich entry needs tool and argument")
        types = [str(t) for t in e.get("types") or []]
        bad = [t for t in types if t not in ENRICH_TYPES]
        if not types or bad:
            raise ValueError(f"connector {name}: enrich types must be some of {ENRICH_TYPES}")
        extra = e.get("arguments") or {}
        if not isinstance(extra, dict):
            raise ValueError(f"connector {name}: enrich arguments must be a mapping")
        out.append({"types": types, "tool": str(e["tool"]), "argument": str(e["argument"]), "arguments": extra})
    return out


def _spec(raw: dict[str, Any]) -> ConnectorSpec:
    name = str(raw.get("name", "")).strip()
    if not _NAME_RE.fullmatch(name):
        raise ValueError(f"connector name {name!r} must be lowercase letters, digits, _ or - (max 40)")
    roles = [str(r) for r in (raw.get("roles") or [])]
    if not roles:
        raise ValueError(f"connector {name}: at least one role is required ({', '.join(ROLES + ACTION_ROLES)})")
    bad = [r for r in roles if r not in ROLES + ACTION_ROLES]
    if bad:
        raise ValueError(f"connector {name}: unknown role(s) {bad}; expected {ROLES + ACTION_ROLES}")
    transport = str(raw.get("transport", "")).strip()
    if transport not in ("stdio", "http"):
        raise ValueError(f"connector {name}: transport must be 'stdio' or 'http'")
    if transport == "http" and not str(raw.get("url", "")).startswith(("http://", "https://")):
        raise ValueError(f"connector {name}: http transport needs an http(s) url")
    if transport == "stdio" and not raw.get("command"):
        raise ValueError(f"connector {name}: stdio transport needs a command")
    auth = dict(raw.get("auth") or {})
    auth.setdefault("type", "none")
    if auth["type"] not in AUTH_TYPES:
        raise ValueError(f"connector {name}: auth.type must be one of {AUTH_TYPES}")
    for k in ("token", "api_key", "client_secret"):
        if auth.get(k) and not _VAR_RE.fullmatch(str(auth[k])):
            raise ValueError(f"connector {name}: put auth.{k} in .env and reference it as {k}_env or ${{VAR}}")
    tools = raw.get("tools") or {}
    access = raw.get("access") or []
    if not isinstance(access, list) or not all(isinstance(a, str) and a.strip() for a in access):
        raise ValueError(f"connector {name}: access must be a list of group names, role:<role> or user:<name>")
    for a in access:
        if a.startswith("role:") and a[5:].strip().lower() not in ("viewer", "operator", "admin"):
            raise ValueError(f"connector {name}: access {a!r}: role must be viewer, operator or admin")
    return ConnectorSpec(
        name=name, roles=roles, transport=transport,
        url=str(raw.get("url", "")), command=str(raw.get("command", "")),
        args=[str(a) for a in raw.get("args") or []],
        env={str(k): str(v) for k, v in (raw.get("env") or {}).items()},
        headers={str(k): str(v) for k, v in (raw.get("headers") or {}).items()},
        auth=auth, dialect=str(raw.get("dialect", "")), description=str(raw.get("description", "")),
        query_notes=_notes(name, raw),
        query_examples=[{"goal": str(e.get("goal", ""))[:200], "query": str(e.get("query", ""))[:1000]}
                        for e in (raw.get("query_examples") or []) if isinstance(e, dict) and e.get("query")][:20],
        allow=[str(t) for t in tools.get("allow") or []],
        deny=[str(t) for t in tools.get("deny") or []],
        allow_write=bool(raw.get("allow_write", False)),
        rate_per_min=max(1, int(raw.get("rate_per_min", 60))),
        timeout_sec=float(raw.get("timeout_sec", 30)),
        enabled=bool(raw.get("enabled", True)),
        verify_tls=bool(raw.get("verify_tls", True)),
        access=[a.strip() for a in access],
        enrich=_enrich(name, raw.get("enrich")),
    )


def parse_connectors(items: list[dict[str, Any]]) -> list[ConnectorSpec]:
    specs = [_spec(i) for i in items or []]
    names = [s.name for s in specs]
    dupes = {n for n in names if names.count(n) > 1}
    if dupes:
        raise ValueError(f"duplicate connector names: {sorted(dupes)}")
    return specs
