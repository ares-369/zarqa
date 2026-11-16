"""Configuration loader for Zarqa.

``config.yaml`` holds the layout (server, auth, LLM roles, connectors, organization) and
``.env`` holds secrets. Nothing about a particular environment is hardcoded.

Config path resolution:
  1. ``ZARQA_CONFIG`` env var, if set
  2. ``./config.yaml`` in the current working directory
  3. ``<home>/config.yaml`` (the checkout root, or ``~/.zarqa``)
"""

from __future__ import annotations

import difflib
import logging
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml
from dotenv import load_dotenv

from .paths import home_dir

_log = logging.getLogger("zarqa")

# Model roles. Each maps to a provider + model:
#   extractor: turns reports and pages into structured intel (can be a small, cheap model)
#   analyst:   investigations, relevance and assessments (the strongest model you have)
#   reporter:  briefs and report text
LLM_ROLES = ("extractor", "analyst", "reporter")
PROVIDERS = ("ollama", "anthropic", "gemini", "openai", "azure_openai", "openai_compatible", "cli", "demo")


def _load_env() -> None:
    for candidate in (Path.cwd() / ".env", home_dir() / ".env"):
        if candidate.exists():
            load_dotenv(candidate)
            return


def config_path() -> Path:
    if os.getenv("ZARQA_CONFIG"):
        return Path(os.environ["ZARQA_CONFIG"]).expanduser()
    cwd_cfg = Path.cwd() / "config.yaml"
    if cwd_cfg.exists():
        return cwd_cfg
    return home_dir() / "config.yaml"


@dataclass
class AuthConfig:
    # none | basic | local | oidc | proxy
    mode: str = "none"
    username: str = "zarqa"
    password: str = ""          # from .env ZARQA_AUTH_PASSWORD
    password_hash: str = ""     # optional pbkdf2 hash (preferred over password)
    secret_key: str = ""        # session signing; from .env ZARQA_SECRET_KEY
    proxy_header: str = "X-Forwarded-User"
    proxy_trusted_ips: list = field(default_factory=list)
    allowed_users: list = field(default_factory=list)
    oidc: dict = field(default_factory=dict)
    default_role: str = "admin"               # admin | operator | viewer
    roles: dict[str, str] = field(default_factory=dict)
    users: dict[str, dict] = field(default_factory=dict)   # username -> {password_hash, role, name, groups}
    group_roles: dict[str, str] = field(default_factory=dict)   # IdP group -> role (highest match wins)
    require_group_role: bool = False         # with group_roles: refuse people in none of those groups
    proxy_groups_header: str = ""            # proxy mode: header with the user's groups (comma separated)

    @property
    def enabled(self) -> bool:
        return self.mode != "none"


@dataclass
class Limits:
    """Limits on one investigation (a model-driven tool loop)."""
    max_steps: int = 20            # tool calls
    max_runtime_sec: int = 600
    max_result_bytes: int = 8_000  # per tool result fed back to the model
    max_tokens: int = 0            # model tokens before an answer is forced (0 = no cap)
    max_query_sec: int = 60        # one tool call, retries included


@dataclass
class Config:
    raw: dict[str, Any]
    instance_name: str
    external_url: str
    bind_host: str
    bind_port: int
    auth: AuthConfig
    llm: dict[str, Any]
    connectors: list[dict[str, Any]]
    limits: Limits
    data_dir: Path
    path: Path
    allow_unauthenticated_network: bool = False

    def secret(self, name: str) -> str:
        return os.getenv(name, "") or ""

    def provider_cfg(self, name: str) -> dict[str, Any]:
        """Provider settings with ``${VAR}`` references filled from the environment."""
        from .connectors.spec import expand_env
        raw = (self.llm.get("providers") or {}).get(name, {}) or {}
        return {k: expand_env(v) if isinstance(v, str) else v for k, v in raw.items()}

    def role_cfg(self, role: str) -> dict[str, Any]:
        return (self.llm.get("roles") or {}).get(role, {}) or {}


def _truthy(v: Any) -> bool:
    return str(v).strip().lower() in ("1", "true", "yes")


def load_config() -> Config:
    _load_env()
    path = config_path()
    if not path.exists():
        raise FileNotFoundError(
            f"No config.yaml found at {path}. Run `zarqa init` (or copy "
            "config.example.yaml to config.yaml) and edit it for your environment.")
    data = yaml.safe_load(path.read_text()) or {}
    srv = data.get("zarqa", {}) or {}

    auth_raw = data.get("auth", {}) or {}
    oidc_raw = auth_raw.get("oidc", {}) or {}
    auth = AuthConfig(
        mode=str(auth_raw.get("mode", "none")),
        username=str(auth_raw.get("username", "zarqa")),
        password=os.getenv("ZARQA_AUTH_PASSWORD", auth_raw.get("password", "")) or "",
        password_hash=str(auth_raw.get("password_hash", "")),
        secret_key=os.getenv("ZARQA_SECRET_KEY", auth_raw.get("secret_key", "")) or "",
        proxy_header=str(auth_raw.get("proxy_header", "X-Forwarded-User")),
        proxy_trusted_ips=list(auth_raw.get("proxy_trusted_ips", []) or []),
        allowed_users=list(auth_raw.get("allowed_users", []) or []),
        oidc={
            "issuer": str(oidc_raw.get("issuer", "")),
            "client_id": str(oidc_raw.get("client_id", "")),
            "client_secret": os.getenv("OIDC_CLIENT_SECRET", oidc_raw.get("client_secret", "")) or "",
            "scopes": str(oidc_raw.get("scopes", "openid email profile")),
            "username_claim": str(oidc_raw.get("username_claim", "email")),
            "groups_claim": str(oidc_raw.get("groups_claim", "groups")),
        },
        default_role=str(auth_raw.get("default_role", "admin")).lower(),
        roles={str(k): str(v).lower() for k, v in (auth_raw.get("roles") or {}).items()},
        users={str(k): dict(v or {}) for k, v in (auth_raw.get("users") or {}).items()},
        group_roles={str(k): str(v).lower() for k, v in (auth_raw.get("group_roles") or {}).items()},
        require_group_role=bool(auth_raw.get("require_group_role", False)),
        proxy_groups_header=str(auth_raw.get("proxy_groups_header", "") or ""),
    )
    bad = {g: r for g, r in auth.group_roles.items() if r not in ("viewer", "operator", "admin")}
    if bad:
        raise ValueError(f"auth.group_roles: roles must be viewer, operator or admin, got {bad}")
    for un, u in auth.users.items():
        if u.get("password"):
            raise ValueError(f"auth.users.{un}: store a password_hash (zarqa users add), not a password")
    if auth.mode not in ("none", "basic", "local", "oidc", "proxy"):
        raise ValueError(f"auth.mode {auth.mode!r} is not one of none/basic/local/oidc/proxy")

    lim = data.get("limits", {}) or {}
    limits = Limits(
        max_steps=max(1, int(lim.get("max_steps", 20))),
        max_runtime_sec=max(10, int(lim.get("max_runtime_sec", 600))),
        max_result_bytes=max(1024, int(lim.get("max_result_bytes", 8_000))),
        max_tokens=max(0, int(lim.get("max_tokens", 0) or 0)),
        max_query_sec=max(0, int(lim.get("max_query_sec", 60) or 0)),
    )

    from .connectors.spec import parse_connectors
    parse_connectors(list(data.get("connectors", []) or []))  # fail fast on a bad connector
    from .privacy import validate as validate_privacy
    validate_privacy(data.get("privacy") or {})
    if str((data.get("jobs") or {}).get("mode", "local")) != "local":
        raise ValueError("jobs.mode: only 'local' is supported in this version")
    from .collect.collector import sources_from
    sources_from(type("C", (), {"raw": data})())            # fail fast on a bad source
    from .share.push import validate as validate_share
    validate_share(data)
    from .brand.watch import validate as validate_brand
    validate_brand(data)
    from .intel.relevance import validate as validate_relevance
    validate_relevance(data)
    from .intel.enrich import validate as validate_enrich
    validate_enrich(data.get("enrich") or {})
    for sec in ("collect", "extract", "intel", "web", "relevance", "mcp"):
        if not isinstance(data.get(sec) or {}, dict):
            raise ValueError(f"{sec}: must be a mapping")
    org = data.get("organization") or {}
    if not isinstance(org, dict):
        raise ValueError("organization: must be a mapping (name, sectors, regions, products, brands, domains)")

    data_dir = Path(str(srv.get("data_dir", "") or (home_dir() / "data"))).expanduser()
    dbc = data.get("database") or {}
    from . import db
    from .connectors.spec import expand_env
    db.configure(expand_env(str(dbc.get("url", "") or "")), str(dbc.get("schema", "zarqa") or "zarqa"))
    return Config(
        raw=data,
        instance_name=str(srv.get("instance_name", "Zarqa")),
        external_url=str(srv.get("external_url", "")).rstrip("/"),
        bind_host=str(os.getenv("ZARQA_BIND_HOST") or srv.get("bind_host", "127.0.0.1")),
        bind_port=int(os.getenv("ZARQA_BIND_PORT") or srv.get("bind_port", 8621)),
        auth=auth,
        llm=data.get("llm", {}) or {},
        connectors=list(data.get("connectors", []) or []),
        limits=limits,
        data_dir=data_dir,
        path=path,
        allow_unauthenticated_network=(
            _truthy(os.getenv("ZARQA_ALLOW_UNAUTHENTICATED_NETWORK", ""))
            or bool(srv.get("allow_unauthenticated_network", False))),
    )


_CONFIG: Config | None = None


def get_config(reload: bool = False) -> Config:
    global _CONFIG
    if _CONFIG is None or reload:
        _CONFIG = load_config()
    return _CONFIG


# --- Settings: model picker -------------------------------------------------

def _build_llm_update(roles: dict) -> tuple[Path, str, dict]:
    """Validate a model-picker update ``{role: {provider, model}}`` and return
    ``(path, old_text, new_data)`` without writing."""
    path = config_path()
    old_text = path.read_text()
    data = yaml.safe_load(old_text) or {}
    llm = data.setdefault("llm", {}) or {}
    data["llm"] = llm
    llm.setdefault("roles", {})
    for role, rc in (roles or {}).items():
        if role not in LLM_ROLES:
            raise ValueError(f"unknown model role {role!r}; expected one of {LLM_ROLES}")
        if not isinstance(rc, dict):
            raise ValueError(f"role {role!r} must be an object with provider and model")
        prov = str(rc.get("provider", "")).strip()
        if prov not in PROVIDERS:
            raise ValueError(f"unknown provider {prov!r}; expected one of {PROVIDERS}")
        model = str(rc.get("model", "")).strip()
        if model and not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:/@\-\[\]]{0,127}", model):
            raise ValueError(f"model name {model!r} has unexpected characters")
        entry = {"provider": prov, "model": model}
        fb = []
        for f in rc.get("fallback") or []:
            if not isinstance(f, dict) or str(f.get("provider", "")) not in PROVIDERS:
                raise ValueError(f"role {role!r}: each fallback needs a known provider")
            fm = str(f.get("model", "")).strip()
            if fm and not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:/@\-\[\]]{0,127}", fm):
                raise ValueError(f"fallback model name {fm!r} has unexpected characters")
            fb.append({"provider": str(f["provider"]), "model": fm})
        if fb:
            entry["fallback"] = fb[:5]
        llm["roles"][role] = entry
    return path, old_text, data


def _redact(text: str) -> str:
    return re.sub(r"(?im)^(\s*(?:api_key|secret|password|token|client_secret)\s*:\s*).+$", r"\1***", text)


def preview_llm_update(roles: dict) -> dict:
    _p, old_text, data = _build_llm_update(roles)
    old = yaml.safe_load(old_text) or {}

    def dump(d):
        return _redact(yaml.safe_dump(d, sort_keys=False))
    diff = "".join(difflib.unified_diff(dump(old).splitlines(True), dump(data).splitlines(True),
                                        "config.yaml (current)", "config.yaml (proposed)"))
    return {"changed": old != data, "diff": diff}


def apply_llm_update(roles: dict) -> Config:
    """Persist a model-picker change (writes config.yaml.bak first), then reload."""
    path, old_text, data = _build_llm_update(roles)
    path.with_name(path.name + ".bak").write_text(old_text)
    path.write_text(yaml.safe_dump(data, sort_keys=False))
    return get_config(reload=True)


def set_user(username: str, *, password_hash: str | None = None, role: str = "operator", name: str = "",
             remove: bool = False) -> None:
    """Add, update or remove a named account in config.yaml (writes config.yaml.bak first)."""
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._@-]{0,63}", username or ""):
        raise ValueError("username: letters, digits, . _ @ - (max 64)")
    if role not in ("viewer", "operator", "admin"):
        raise ValueError("role must be viewer, operator or admin")
    path = config_path()
    old = path.read_text()
    data = yaml.safe_load(old) or {}
    users = data.setdefault("auth", {}).setdefault("users", {}) or {}
    data["auth"]["users"] = users
    if remove:
        users.pop(username, None)
    else:
        entry = dict(users.get(username) or {})
        if password_hash:
            entry["password_hash"] = password_hash
        if not entry.get("password_hash"):
            raise ValueError("a password is required for a new user")
        entry["role"] = role
        if name:
            entry["name"] = name[:80]
        users[username] = entry
    path.with_name(path.name + ".bak").write_text(old)
    path.write_text(yaml.safe_dump(data, sort_keys=False))


def update_connectors(entry: dict | None = None, *, remove: str | None = None, preview: bool = False) -> dict:
    """Add/replace one connector (by name) or remove one, validating the whole list. Returns a diff."""
    from .connectors.spec import parse_connectors
    path = config_path()
    old_text = path.read_text()
    data = yaml.safe_load(old_text) or {}
    items = [c for c in data.get("connectors") or [] if isinstance(c, dict)]
    if remove:
        items = [c for c in items if c.get("name") != remove]
    if entry:
        clean = {k: v for k, v in entry.items() if v not in (None, "", [], {})}
        items = [c for c in items if c.get("name") != clean.get("name")] + [clean]
    parse_connectors(items)                      # raises ValueError with a clear message
    data["connectors"] = items
    old = yaml.safe_load(old_text) or {}

    def dump(d):
        return _redact(yaml.safe_dump(d.get("connectors") or [], sort_keys=False))
    diff = "".join(difflib.unified_diff(dump(old).splitlines(True), dump(data).splitlines(True),
                                        "connectors (current)", "connectors (proposed)"))
    if not preview and old != data:
        path.with_name(path.name + ".bak").write_text(old_text)
        path.write_text(yaml.safe_dump(data, sort_keys=False))
        get_config(reload=True)
    return {"changed": old != data, "diff": diff}
