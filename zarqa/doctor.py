"""``zarqa doctor``: check a deployment end to end and say what to fix.

Each check returns OK, WARN or FAIL with a hint. Model checks run only with ``models=True``
because they cost a model call per role.
"""

from __future__ import annotations

import importlib.util
import shutil


def _has(mod: str) -> bool:
    try:
        return importlib.util.find_spec(mod) is not None
    except (ImportError, ValueError):
        return False


def run(cfg=None, *, offline: bool = False, models: bool = False) -> list[dict]:
    out: list[dict] = []

    def add(level, area, msg, hint=""):
        out.append({"level": level, "area": area, "message": msg, "hint": hint})

    from .config import LLM_ROLES, get_config
    try:
        cfg = cfg or get_config(reload=True)
    except Exception as exc:
        add("FAIL", "config", f"config.yaml does not load: {exc}", "fix the file; see config.example.yaml")
        return out
    add("OK", "config", f"loaded {cfg.path}")

    try:
        cfg.data_dir.mkdir(parents=True, exist_ok=True)
        probe = cfg.data_dir / ".doctor"
        probe.write_text("x")
        probe.unlink()
        free = shutil.disk_usage(cfg.data_dir).free // (1024 * 1024)
        add("OK" if free > 500 else "WARN", "data", f"{cfg.data_dir} writable, {free} MB free",
            "" if free > 500 else "less than 500 MB free")
    except OSError as exc:
        add("FAIL", "data", f"{cfg.data_dir} is not writable: {exc}", "fix permissions or zarqa.data_dir")

    from . import db
    if db.is_pg():
        try:
            with db.connect(cfg.data_dir / "doctor.sqlite") as c:
                ver = c.execute("SHOW server_version").fetchone()[0]
            add("OK", "storage", f"PostgreSQL {ver}, schema {db._settings['schema']}")
        except Exception as exc:
            add("FAIL", "storage", f"PostgreSQL: {str(exc)[:200]}",
                "check ZARQA_DB_URL / database.url, and pip install 'zarqa[postgres]'")
    else:
        add("OK", "storage", "SQLite in the data folder")

    from .server import startup_security_check
    errors, warnings = startup_security_check(cfg)
    for e in errors:
        add("FAIL", "auth", e)
    for w in warnings:
        add("WARN", "auth", w)
    if cfg.auth.mode in ("local", "oidc") and not cfg.auth.secret_key:
        add("WARN", "auth", "ZARQA_SECRET_KEY is not set; sessions end on every restart", "set it in .env")
    if cfg.auth.mode == "none":
        add("WARN" if cfg.bind_host not in ("127.0.0.1", "localhost", "::1") else "OK", "auth",
            "no login (auth.mode none); fine for a single user on this machine only",
            "use oidc or proxy for a team")
    else:
        add("OK", "auth", f"auth.mode {cfg.auth.mode}, {len(cfg.auth.users)} named account(s)")
    if cfg.auth.mode == "oidc" and not _has("authlib"):
        add("FAIL", "auth", "auth.mode oidc needs the oidc extra", "pip install 'zarqa[oidc]'")

    roles = {r: cfg.role_cfg(r) for r in LLM_ROLES}
    used = {rc.get("provider", "ollama") for rc in roles.values()} | {
        f.get("provider") for rc in roles.values() for f in rc.get("fallback") or []}
    need = {"gemini": "google.genai", "anthropic": "anthropic", "openai": "openai", "azure_openai": "openai",
            "openai_compatible": "openai"}
    for p in sorted(x for x in used if x):
        mod = need.get(p)
        if mod and not _has(mod):
            extra = {"azure_openai": "openai", "openai_compatible": "openai"}.get(p, p)
            add("FAIL", "models", f"provider {p} is used but its SDK is not installed", f"pip install 'zarqa[{extra}]'")
    priv = (cfg.raw or {}).get("privacy") or {}
    mask_for = priv.get("mask_for", ["anthropic", "gemini", "openai", "azure_openai", "openai_compatible", "cli"])
    cloud = [p for p in used if p and p != "ollama"]
    unmasked = [p for p in cloud if p not in mask_for]
    if unmasked:
        add("WARN", "privacy", f"prompts to {', '.join(unmasked)} are not masked", "add them to privacy.mask_for")
    if cloud and not priv.get("terms"):
        add("WARN", "privacy", "no privacy.terms set; internal names in your organization profile would reach "
            "the cloud model", "list them under privacy.terms")
    if models:
        from .llm import test_models
        for r in test_models(cfg):
            add("OK" if r["ok"] else "FAIL", "models", f"{r['role']}: {r['provider']}/{r['model']} "
                + (f"answered in {r['ms']} ms" if r["ok"] else r["error"]))
    else:
        add("OK", "models", "model calls not tested (run with --models)")

    org = (cfg.raw or {}).get("organization") or {}
    if not any(org.get(k) for k in ("sectors", "regions", "products", "brands", "domains")):
        add("WARN", "organization", "no organization profile; intel cannot be ranked by relevance to you",
            "fill organization: in config.yaml (sectors, regions, products, brands, domains)")
    else:
        add("OK", "organization", "organization profile set")
    return out
