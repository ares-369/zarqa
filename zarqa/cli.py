"""Command line entry point: ``zarqa [serve|init|doctor|version|models|users|connectors|bridge|hash-password]``."""

from __future__ import annotations

import argparse
import getpass
import json
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


def _print_process(r: dict) -> None:
    m = r.get("model") or {}
    line = f"document {r['document_id']}: rules {r.get('rules', 0)}, dictionary {r.get('dictionary', 0)}"
    if m:
        line += f", model {m.get('items', 0)} items, {m.get('relations', 0)} relations"
        if m.get("errors"):
            line += f" (model errors: {'; '.join(m['errors'])[:200]})"
    print(line + (f", dropped {len(r.get('dropped') or [])}" if r.get("dropped") else ""))
    if r.get("review"):
        print(f"  review: {r['review']}")
    if r.get("error"):
        print(f"  error: {r['error']}")


def cmd_intel(a) -> int:
    from .config import get_config
    from .intel import service
    from .intel.store import store_for
    cfg = get_config()
    st = store_for(cfg)
    use_model = False if getattr(a, "no_model", False) else None
    if a.cmd == "sources":
        from .collect.collector import builtin_sources, default_settings, sources_from
        if a.action in ("enable", "disable"):
            from .config import set_default_sources, set_own_source_enabled
            on = a.action == "enable"
            if a.all:
                d = set_default_sources(enabled=on)
                print(f"built-in sources {'on' if d['enabled'] else 'off'}"
                      + (f" (still off by name: {', '.join(d['disable'])})" if on and d["disable"] else ""))
                return 0
            if not a.names:
                print(f"usage: zarqa sources {a.action} NAME [NAME...] | --all")
                return 2
            builtin = {s["name"] for s in builtin_sources()}
            own = {s.get("name") for s in (cfg.raw.get("sources") or [])}
            for n in a.names:
                if n in own:
                    set_own_source_enabled(n, on)
                elif n in builtin:
                    set_default_sources(**({"enable": [n]} if on else {"disable": [n]}))
                else:
                    print(f"no source named {n}")
                    return 1
                print(f"{n}: {'on' if on else 'off'}")
            return 0
        states = st.source_state()
        if a.action == "pull":
            names = a.names or [s["name"] for s in sources_from(cfg)]
            rc = 0
            for n in names:
                r = service.pull_source(cfg, n, actor="cli", use_model=use_model, store=st)
                print(f"{n}: {len(r['new_documents'])} new documents, {r['values']} values, {r['skipped']} skipped"
                      + (f", errors: {'; '.join(r['errors'])[:300]}" if r["errors"] else ""))
                for p in r.get("processed") or []:
                    _print_process(p)
                rc |= 1 if r["errors"] and not r["new_documents"] else 0
            return rc
        ds = default_settings(cfg.raw)
        rows = sources_from(cfg, include_disabled=True)
        print(f"built-in sources: {'on' if ds['enabled'] else 'OFF'}"
              + (f", off by name: {', '.join(ds['disable'])}" if ds["disable"] else ""))
        for s in rows:
            stt = states.get(s["name"], {})
            print(f"{'on ' if s['enabled'] else 'off'} {s['name']:22} {('built-in ' + s.get('category', '')) if s['builtin'] else 'yours':19} "
                  f"{s.get('kind', 'feed'):5} {s.get('reliability', '-')} every {s.get('interval_minutes', 0) or '-':>4} min  "
                  f"last {stt.get('last_pull', '-')[:16] or '-':16}  docs {stt.get('documents', 0)}"
                  + (f"  ERROR {stt['last_error'][:60]}" if stt.get("last_error") else ""))
        if not rows:
            print("no sources")
        return 0
    if a.cmd == "add":
        c = service.collector(cfg, st)
        tags = a.tag or []
        if a.url:
            r = c.add_url(a.url, actor="cli", tags=tags)
        elif a.file:
            r = c.add_file(a.file, actor="cli", tags=tags)
        else:
            text = sys.stdin.read()
            if a.values:
                r = c.add_values(text.split(), actor="cli", tags=tags)
                print(f"{r['values']} values added, {r['skipped']} skipped")
                return 0
            r = c.add_text(text, title=a.title or "", actor="cli", tags=tags)
        if r.get("stix"):
            x = r["stix"]
            print(f"STIX: {x['indicators']} indicators, {x['entities']} entities, {x['relations']} relations, "
                  f"{len(x['reports'])} reports")
            for p in service.process_documents(cfg, x["reports"], store=st, use_model=use_model):
                _print_process(p)
            return 0
        print(f"document {r['id']}" + ("" if r["new"] else " (already stored)"))
        if r["new"]:
            for p in service.process_documents(cfg, [r["id"]], store=st, use_model=use_model):
                _print_process(p)
        return 0
    if a.cmd == "process":
        ids = [int(x) for x in a.ids] or [d["id"] for d in st.documents(status="new", limit=200)]
        for p in service.process_documents(cfg, ids, store=st, use_model=use_model):
            _print_process(p)
        return 0
    if a.cmd == "entities":
        for e in st.entities(etype=a.type, q=a.q or "", order=a.order, limit=a.limit):
            print(f"{e['id']:6} {e['type']:10} {e['display'][:70]:70} seen {e['seen_count']:3}  last {e['last_seen'][:10]}")
        return 0
    if a.cmd == "lookup":
        hits = st.lookup(a.value)
        if not hits:
            print("not in the store")
            return 1
        for e in hits:
            print(f"{e['type']} {e['display']}  rating {e.get('rating') or 'F6'} (confidence {e['confidence']})  "
                  f"first {e['first_seen'][:10]}  last {e['last_seen'][:10]}  seen {e['seen_count']}  status {e['status']}")
            for m in st.mentions(entity_id=e["id"], limit=10):
                print(f"  [{m['method']}{'/' + m['context'] if m['context'] else ''}] {m['title'][:60]}: {m['snippet'][:160]}")
            for r in st.relations(entity_id=e["id"], limit=10):
                print(f"  {r['src_display']} {r['rel']} {r['dst_display']}  ({r['title'][:50]})")
        return 0
    if a.cmd == "enrich":
        from .intel.enrich import enrich
        hits = [st.entity(int(a.value))] if a.value.isdigit() else st.lookup(a.value)
        hits = [h for h in hits if h]
        if not hits:
            print("not in the store; add it first (zarqa add --values)")
            return 1
        rc = 0
        for e in hits:
            rows = enrich(cfg, st, e["id"], only=a.only, actor="cli", force=a.force)
            if not rows:
                print(f"{e['type']} {e['display']}: no enricher handles this type (enrich: on a connector, or enrich.builtin)")
            for r in rows:
                print(f"{e['display']}  {r['enricher']:24} {'ok  ' if r['ok'] else 'FAIL'} {r['summary']}")
                rc |= 0 if r["ok"] else 1
        return rc
    if a.cmd == "ask":
        from .investigate.service import run_investigation
        from .investigate.store import store_for as istore
        st_i = istore(cfg)
        inv_id = st_i.create(a.question, "cli")
        r = run_investigation(cfg, inv_id, actor="cli", max_steps=a.max_steps)
        inv = st_i.get(inv_id)
        for s in inv["steps"]:
            print(f"E{s['n']:<3} {'ok  ' if s['ok'] else 'FAIL'} {s['connector']}.{s['tool']} {json.dumps(s['arguments'])[:120]}")
        if r.get("status") != "done":
            print(f"investigation {inv_id}: {r.get('status')} {r.get('error', '')}")
            return 1
        print(f"\n[{r['outcome']}] confidence {r['confidence']}\n{r['answer']}\n")
        for f in r["findings"]:
            print(f"  - {f['claim']}  ({', '.join(f['evidence'])})")
        for u in r["unsupported"]:
            print(f"  set aside: {u['claim']}  ({u['why']})")
        for g in r["gaps"]:
            print(f"  gap: {g}")
        for c in r["checks"]:
            print(f"  check: {c}")
        if inv["review"]:
            print(f"  review: {inv['review']}")
        return 0
    if a.cmd in ("brief", "report"):
        from .reporting import brief_data, brief_markdown, document_markdown, to_html
        md = brief_markdown(brief_data(cfg, st, days=a.days)) if a.cmd == "brief" else document_markdown(st, a.id)
        text = to_html(md, "Zarqa") if a.html else md
        if a.out:
            Path(a.out).write_text(text, encoding="utf-8")
            print(f"wrote {a.out}")
        else:
            print(text)
        return 0
    if a.cmd == "export":
        from .share.push import build
        from .share.stix_out import export
        if a.format == "misp" and a.document is None and not a.entity:
            print("misp needs --document or --entity")
            return 2
        if a.document is None and not a.entity and a.format == "stix":
            body = export(st, producer_name=cfg.instance_name, since=a.since, types=a.type or None,
                          min_confidence=a.min_confidence)
        else:
            body = build(cfg, st, a.format, document_id=a.document, entity_ids=a.entity or None)
        text = json.dumps(body, indent=2, ensure_ascii=False)
        if a.out:
            Path(a.out).write_text(text, encoding="utf-8")
            n = len(body.get("objects") or (body.get("Event") or {}).get("Attribute") or [])
            print(f"wrote {a.out} ({n} objects)")
        else:
            print(text)
        return 0
    if a.cmd == "share":
        from .share.push import push
        r = push(cfg, st, a.target, actor="cli", document_id=a.document, entity_ids=a.entity or None)
        print(f"{a.target}: {'ok' if r['ok'] else 'FAILED'}, {r['items']} items; {r['text'][:200]}")
        return 0 if r["ok"] else 1
    if a.cmd == "brand":
        from .brand.watch import run as brand_run
        from .brand.watch import settings as bset
        from .brand.watch import store_for as bstore
        if a.action == "run":
            r = brand_run(cfg, kstore=st)
            print(f"{r['candidates']} candidates, {r['resolving']} resolve, {r['new']} new"
                  + (f"; errors: {'; '.join(r['errors'])}" if r["errors"] else ""))
            if r["errors"] and not bset(cfg)["watch"]:
                return 1
        for f in bstore(cfg).findings(limit=a.limit):
            ev = f["evidence"]
            page = ev.get("page") or {}
            extra = []
            if (ev.get("rdap") or {}).get("age_days") is not None:
                extra.append(f"registered {ev['rdap']['age_days']} days ago")
            if page.get("parked"):
                extra.append("parked or for sale")
            elif page.get("shows_brand"):
                extra.append("page shows the brand")
            if page.get("asks_password"):
                extra.append("asks for a password")
            if ev.get("mx"):
                extra.append("has mail servers")
            if ev.get("redirects_to_you"):
                extra = ["redirects to your own domain (likely yours)"]
            print(f"{f['score']:3} {f['domain']:40} {f['technique']:13} {f['status']:9} "
                  f"{'' if f['resolves'] else '(gone) '}{', '.join(extra)}")
        return 0
    if a.cmd == "rescore":
        from .intel.relevance import score_document
        from .llm import privacy_llm
        llm = privacy_llm(cfg)
        ids = [int(x) for x in a.ids] or [d["id"] for d in st.documents(status="extracted", limit=a.limit)]
        for i in ids:
            r = score_document(cfg, st, i, llm=llm)
            print(f"document {i}: {r['score'] if r['score'] is not None else '-'}  {'; '.join(r['reasons'])[:200]}")
        from .intel.credibility import refresh
        with st._conn() as c:
            all_ids = [r[0] for r in c.execute("SELECT id FROM entities").fetchall()]
        print(f"ratings and confidence recomputed for {refresh(st, all_ids)} entities")
        return 0
    if a.cmd == "stats":
        import json as _json
        print(_json.dumps(st.stats(), indent=2))
        return 0
    return 2


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
    p_src = sub.add_parser("sources", help="list sources (built-in and yours), pull now, or turn them on or off")
    p_src.add_argument("action", nargs="?", choices=["list", "pull", "enable", "disable"], default="list")
    p_src.add_argument("names", nargs="*")
    p_src.add_argument("--all", action="store_true", help="enable/disable: every built-in source at once")
    p_src.add_argument("--no-model", action="store_true", help="rules only, no extractor model")
    p_add = sub.add_parser("add", help="add a report: --url, --file (text, HTML, PDF, STIX JSON), or text on stdin")
    p_add.add_argument("--url")
    p_add.add_argument("--file")
    p_add.add_argument("--title")
    p_add.add_argument("--tag", action="append")
    p_add.add_argument("--values", action="store_true", help="stdin holds indicator values, not a report")
    p_add.add_argument("--no-model", action="store_true", help="rules only, no extractor model")
    p_pr = sub.add_parser("process", help="extract intel from documents (default: all new ones)")
    p_pr.add_argument("ids", nargs="*")
    p_pr.add_argument("--no-model", action="store_true", help="rules only, no extractor model")
    p_en = sub.add_parser("entities", help="list what is in the store")
    p_en.add_argument("--type", help="e.g. actor, malware, ipv4 or a comma list")
    p_en.add_argument("--q")
    p_en.add_argument("--order", default="last_seen", choices=["last_seen", "seen", "first_seen", "confidence"])
    p_en.add_argument("--limit", type=int, default=50)
    p_lk = sub.add_parser("lookup", help="everything known about a value (indicator, CVE, technique or name)")
    p_lk.add_argument("value")
    sub.add_parser("stats", help="counts in the store")
    p_ask = sub.add_parser("ask", help="investigate a question; the answer cites its evidence")
    p_ask.add_argument("question")
    p_ask.add_argument("--max-steps", type=int, default=None)
    p_bf = sub.add_parser("brief", help="what came in, most relevant first (markdown, or --html)")
    p_bf.add_argument("--days", type=float, default=1.0)
    p_bf.add_argument("--html", action="store_true")
    p_bf.add_argument("--out")
    p_rp = sub.add_parser("report", help="a report on one document (markdown, or --html)")
    p_rp.add_argument("id", type=int)
    p_rp.add_argument("--html", action="store_true")
    p_rp.add_argument("--out")
    p_ex = sub.add_parser("export", help="write a STIX 2.1 bundle or a MISP-format event")
    p_ex.add_argument("format", choices=["stix", "misp"])
    p_ex.add_argument("--document", type=int, help="one document and what was found in it")
    p_ex.add_argument("--entity", type=int, action="append", help="an entity id (repeatable)")
    p_ex.add_argument("--since", help="stix, whole store: entities last seen at or after this ISO time")
    p_ex.add_argument("--type", action="append", help="stix, whole store: entity types (repeatable)")
    p_ex.add_argument("--min-confidence", type=int, default=0)
    p_ex.add_argument("--out", help="file to write (default: print)")
    p_sh = sub.add_parser("share", help="push a document or entities to a share target (share.targets)")
    p_sh.add_argument("target")
    p_sh.add_argument("--document", type=int)
    p_sh.add_argument("--entity", type=int, action="append")
    sub.add_parser("mcp", help="serve Zarqa as an MCP server on stdio")
    p_demo = sub.add_parser("demo", help="a home folder with fictional sample data, processed offline by a scripted "
                                         "stand-in for the model (not AI)")
    p_demo.add_argument("--dir", default=str(Path.home() / ".zarqa-demo"))
    p_demo.add_argument("--run", action="store_true", help="also run a sample investigation and print it")
    p_br2 = sub.add_parser("brand", help="lookalike domains of your own: list findings, or run the watch now")
    p_br2.add_argument("action", nargs="?", choices=["list", "run"], default="list")
    p_br2.add_argument("--limit", type=int, default=50)
    p_rs = sub.add_parser("rescore", help="score documents again (relevance) and recompute every entity's rating "
                                          "and confidence")
    p_rs.add_argument("ids", nargs="*")
    p_rs.add_argument("--limit", type=int, default=200)
    p_enr = sub.add_parser("enrich", help="look a stored value (or entity id) up with the configured enrichers")
    p_enr.add_argument("value")
    p_enr.add_argument("--only", help="one enricher, e.g. rdap or reputation/lookup_ip")
    p_enr.add_argument("--force", action="store_true", help="ignore cached results")
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
    if a.cmd in ("sources", "add", "process", "entities", "lookup", "stats", "enrich", "rescore", "ask", "brand", "export", "share", "brief", "report"):
        sys.exit(cmd_intel(a))
    if a.cmd == "demo":
        from .demo.setup import build
        r = build(Path(a.dir), run=a.run)
        print(f"demo home: {r['home']} ({r['documents']} sample documents; all fictional)")
        for p in r["processed"]:
            _print_process(p)
            rel = p.get("relevance") or {}
            if rel.get("score") is not None:
                print(f"  relevance {rel['score']}: {'; '.join(rel['reasons'])[:160]}")
        inv = r["investigation"]
        if inv:
            print(f"\ninvestigation: [{inv.get('outcome')}] {inv.get('answer', '')}")
            for f in inv.get("findings", []):
                print(f"  - {f['claim'][:160]} ({', '.join(f['evidence'])})")
        print(f"\nserve it: ZARQA_HOME={r['home']} zarqa serve   ->  http://127.0.0.1:8631")
        return
    if a.cmd == "mcp":
        from .mcp_server import run as run_mcp
        run_mcp()
        return
    if a.cmd == "hash-password":
        from .auth import hash_password
        print(hash_password(getpass.getpass("Password: ")))
        return
    from .server import main
    main()
