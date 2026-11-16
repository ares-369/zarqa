"""Command line entry point: ``zarqa [serve|init|doctor|version|models|users|connectors|bridge|hash-password]``."""

from __future__ import annotations

import argparse
import getpass
import secrets
import shutil
import sys
from pathlib import Path

from . import __version__
from .paths import PKG_DIR, REPO_ROOT, home_dir


def _example_config() -> Path:
    for p in (REPO_ROOT / "config.example.yaml", PKG_DIR / "config.example.yaml"):
        if p.is_file():
            return p
    raise FileNotFoundError("config.example.yaml is missing from this install")


def cmd_init(force: bool = False, database: str = "sqlite", db_url: str = "") -> int:
    home = home_dir()
    home.mkdir(parents=True, exist_ok=True)
    (home / "data").mkdir(exist_ok=True)
    cfg = home / "config.yaml"
    if cfg.exists() and not force:
        print(f"{cfg} already exists (use --force to overwrite)")
    else:
        shutil.copyfile(_example_config(), cfg)
        print(f"wrote {cfg}")
    env = home / ".env"
    if not env.exists():
        env.write_text(f"ZARQA_SECRET_KEY={secrets.token_hex(32)}\n")
        env.chmod(0o600)
        print(f"wrote {env}")
    if database == "postgres":
        return _init_postgres(env, db_url)
    print("storage: SQLite in the data folder (nothing else to install)")
    return 0


def _init_postgres(env: Path, db_url: str) -> int:
    """Store the PostgreSQL URL in .env (it holds the password) and check that it connects."""
    import os

    from . import db
    db_url = db_url or os.getenv("ZARQA_DB_URL", "")
    if not db_url:
        if not sys.stdin.isatty():
            print("--database postgres needs --db-url postgresql://user:password@host:5432/dbname")
            return 2
        db_url = getpass.getpass("PostgreSQL URL (postgresql://user:password@host:5432/dbname): ").strip()
    try:
        db.configure(db_url)
    except ValueError as exc:
        print(f"error: {exc}")
        return 2
    lines = [ln for ln in env.read_text().splitlines() if not ln.startswith("ZARQA_DB_URL=")]
    env.write_text("\n".join([*lines, f"ZARQA_DB_URL={db_url}"]) + "\n")
    env.chmod(0o600)
    print(f"storage: PostgreSQL (URL saved in {env})")
    try:
        with db.connect(home_dir() / "data" / "check.sqlite") as c:
            c.execute("SELECT 1")
        print("connected OK; tables are created on first start")
        return 0
    except Exception as exc:
        print(f"could not connect yet: {str(exc)[:300]}")
        print("fix the URL in .env (or install the extra: pip install 'zarqa[postgres]') and run zarqa doctor")
        return 1


def cmd_models() -> int:
    from .config import LLM_ROLES, get_config
    cfg = get_config()
    for role in LLM_ROLES:
        rc = cfg.role_cfg(role)
        print(f"{role:9} {rc.get('provider', 'ollama'):18} {rc.get('model') or '(provider default)'}")
    return 0


def cmd_login(name: str | None, manual: bool) -> int:
    from .config import get_config
    from .connectors.oauth import OAuthError, login
    from .connectors.spec import parse_connectors
    cfg = get_config()
    specs = {s.name: s for s in parse_connectors(list(cfg.connectors))}
    if not name or name not in specs:
        print("usage: zarqa connectors login <name> (an HTTP connector with auth: {type: oauth})")
        return 2
    if specs[name].auth.get("type") != "oauth":
        print(f"{name} does not use auth type oauth")
        return 2
    try:
        r = login(specs[name], cfg.data_dir, ask=input if manual else None)
    except OAuthError as exc:
        print(f"sign-in failed: {exc}")
        return 1
    print(f"signed in ({r.get('scope') or 'default scope'}); token saved under data/oauth/")
    return 0


def cmd_connectors(action: str, name: str | None) -> int:
    from .connectors import get_hub
    hub = get_hub()
    if action == "list":
        for s in hub.specs.values():
            state = "on " if s.enabled else "off"
            print(f"{state} {s.name:20} {s.transport:6} {','.join(s.roles)}")
        if not hub.specs:
            print("no connectors configured (see connectors: in config.yaml)")
        return 0
    names = [name] if name else list(hub.specs)
    rc = 0
    for n in names:
        if n not in hub.specs:
            print(f"unknown connector {n}")
            return 1
        if action == "test":
            r = hub.test(n)
            print(f"{n}: " + (f"ok, {r['allowed']}/{r['tools']} tools allowed, {r['ms']} ms" if r["ok"]
                              else f"FAILED: {r['error']}"))
            rc |= 0 if r["ok"] else 1
        else:
            for t in hub.tools(n):
                print(f"{n:16} {'allow' if t['allowed'] else 'BLOCK'} {t['name']:32} {t['reason']}")
    hub.close()
    return rc


def cmd_models_test() -> int:
    from .config import get_config
    from .llm import test_models
    rc = 0
    for r in test_models(get_config()):
        if r["ok"]:
            print(f"OK   {r['role']:9} {r['provider']}/{r['model']}  {r['ms']} ms  reply: {r['reply']}")
        else:
            rc = 1
            print(f"FAIL {r['role']:9} {r['provider']}/{r['model']}  {r['error']}")
    return rc



def cli_main(argv: list[str] | None = None) -> None:
    ap = argparse.ArgumentParser(prog="zarqa", description="Open-source, AI-powered threat intelligence tool.")
    sub = ap.add_subparsers(dest="cmd")
    sub.add_parser("serve", help="run the web UI and API (default)")
    p_init = sub.add_parser("init", help="create config.yaml and .env in the Zarqa home folder")
    p_init.add_argument("--force", action="store_true")
    p_init.add_argument("--database", choices=["sqlite", "postgres"], default="sqlite",
                        help="storage: sqlite (default, nothing to install) or postgres (needs zarqa[postgres])")
    p_init.add_argument("--db-url", default="", help="postgres: postgresql://user:password@host:5432/dbname")
    p_doc = sub.add_parser("doctor", help="check the whole setup and say what to fix")
    p_doc.add_argument("--offline", action="store_true", help="skip network probes")
    p_doc.add_argument("--models", action="store_true", help="also send one test prompt to each model role")
    sub.add_parser("version")
    p_models = sub.add_parser("models", help="show the model for each role; 'models test' checks each one answers")
    p_models.add_argument("action", nargs="?", choices=["show", "test"], default="show")
    sub.add_parser("hash-password", help="print a password hash for auth.password_hash")
    p_u = sub.add_parser("users", help="named accounts for basic/local login: users list | add NAME | remove NAME")
    p_u.add_argument("op", choices=["list", "add", "remove"])
    p_u.add_argument("name", nargs="?")
    p_u.add_argument("--role", default="operator", choices=["viewer", "operator", "admin"])
    p_u.add_argument("--full-name", default="")
    p_u.add_argument("--password-stdin", action="store_true", help="read the password from stdin")
    p_con = sub.add_parser("connectors", help="list, test or show tools of MCP connectors; login for OAuth")
    p_con.add_argument("action", choices=["list", "test", "tools", "login"], nargs="?", default="list")
    p_con.add_argument("name", nargs="?")
    p_con.add_argument("--manual", action="store_true", help="login: paste the redirect URL instead of a local listener")
    p_br = sub.add_parser("bridge", help="run a generic bridge as a stdio MCP server (used by connectors)")
    br = p_br.add_subparsers(dest="kind", required=True)
    from .bridges import openapi, taxii
    from .bridges import web as web_bridge
    bridges = {"taxii": taxii, "openapi": openapi, "web": web_bridge}
    for kind, mod in bridges.items():
        mod.add_args(br.add_parser(kind))
    a = ap.parse_args(argv)

    if a.cmd == "version":
        print(f"zarqa {__version__}")
        return
    if a.cmd == "init":
        sys.exit(cmd_init(a.force, a.database, a.db_url))
    if a.cmd == "doctor":
        from .doctor import run as run_doctor
        rows = run_doctor(offline=a.offline, models=a.models)
        for r in rows:
            print(f"{r['level']:4} {r['area']:10} {r['message']}" + (f"\n{'':16}-> {r['hint']}" if r["hint"] else ""))
        fails = sum(r["level"] == "FAIL" for r in rows)
        warns = sum(r["level"] == "WARN" for r in rows)
        print(f"\n{fails} problem(s), {warns} warning(s)")
        sys.exit(1 if fails else 0)
    if a.cmd == "models":
        sys.exit(cmd_models_test() if a.action == "test" else cmd_models())
    if a.cmd == "users":
        from .config import get_config, set_user
        cfg = get_config()
        if a.op == "list" or not a.name:
            for n, u in sorted(cfg.auth.users.items()):
                print(f"{n:24} {u.get('role', '?'):9} {u.get('name', '')}")
            if cfg.auth.mode in ("basic", "local"):
                print(f"{cfg.auth.username:24} {cfg.auth.default_role:9} (auth.username account)")
            return
        if a.op == "remove":
            set_user(a.name, remove=True)
            print(f"removed {a.name}")
            return
        from .auth import hash_password
        pw = sys.stdin.readline().rstrip("\n") if a.password_stdin else getpass.getpass(f"Password for {a.name}: ")
        if len(pw) < 10:
            print("use at least 10 characters")
            sys.exit(2)
        set_user(a.name, password_hash=hash_password(pw), role=a.role, name=a.full_name)
        print(f"saved {a.name} ({a.role}); restart the server to apply")
        return
    if a.cmd == "connectors":
        if a.action == "login":
            sys.exit(cmd_login(a.name, a.manual))
        sys.exit(cmd_connectors(a.action, a.name))
    if a.cmd == "bridge":
        bridges[a.kind].run(a)
        return
    if a.cmd == "hash-password":
        from .auth import hash_password
        print(hash_password(getpass.getpass("Password: ")))
        return
    from .server import main
    main()
