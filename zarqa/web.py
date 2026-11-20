"""Flask app factory for the Zarqa web UI and JSON API."""

from __future__ import annotations

import re
from pathlib import Path

from flask import Flask, g, jsonify, render_template, request
from werkzeug.middleware.proxy_fix import ProxyFix

from . import __version__
from .auth import init_auth
from .config import LLM_ROLES, PROVIDERS, apply_llm_update, get_config, preview_llm_update
from .jobs import JobManager

CSP = ("default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; "
       "connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")


def create_app(cfg=None, *, start_scheduler: bool = False) -> Flask:
    cfg = cfg or get_config()
    app = Flask(__name__, static_folder="static", template_folder="templates")
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)  # type: ignore[method-assign]
    app.json.sort_keys = False                     # keep roles and settings in their config order
    app.config["MAX_CONTENT_LENGTH"] = 20 * 1024 * 1024    # pasted reports and STIX bundles
    init_auth(app, cfg)
    cfg.data_dir.mkdir(parents=True, exist_ok=True)
    jobs = JobManager.from_config(cfg)
    app.extensions["zarqa_jobs"] = jobs
    from .investigate.store import store_for as inv_store_for
    inv_store_for(cfg).mark_orphans()
    if start_scheduler:
        from .scheduler import Scheduler
        sched = Scheduler(get_config, jobs)
        sched.start()
        app.extensions["zarqa_scheduler"] = sched

    @app.after_request
    def _security_headers(resp):
        resp.headers.setdefault("Content-Security-Policy", CSP)
        resp.headers.setdefault("X-Content-Type-Options", "nosniff")
        resp.headers.setdefault("Referrer-Policy", "no-referrer")
        resp.headers.setdefault("X-Frame-Options", "DENY")
        return resp

    @app.route("/")
    def index():
        return render_template("index.html", name=cfg.instance_name, version=__version__,
                               demo=bool((cfg.raw.get("zarqa") or {}).get("demo")))

    @app.route("/api/status")
    def status():
        c = get_config()
        return jsonify({
            "version": __version__,
            "instance": c.instance_name,
            "auth_mode": c.auth.mode,
            "connectors": len(c.connectors),
            "roles": {r: c.role_cfg(r) for r in LLM_ROLES},
        })

    @app.route("/api/me")
    def me():
        c = get_config()
        u = str(getattr(g, "zarqa_user", "") or "")
        return jsonify({"user": u, "role": getattr(g, "zarqa_role", "viewer"), "auth_mode": c.auth.mode,
                        "name": (c.auth.users.get(u) or {}).get("name", ""),
                        "groups": list(getattr(g, "zarqa_groups", []) or [])})

    @app.route("/api/settings/llm", methods=["GET", "POST"])
    def settings_llm():
        if request.method == "GET":
            c = get_config()
            return jsonify({
                "roles": {r: c.role_cfg(r) for r in LLM_ROLES},
                "providers": list(PROVIDERS),
                "configured": list((c.llm.get("providers") or {}).keys()),
            })
        body = request.get_json(silent=True) or {}
        roles = body.get("roles") or {}
        try:
            if body.get("preview"):
                return jsonify(preview_llm_update(roles))
            c = apply_llm_update(roles)
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 400
        from .providers import get_llm
        get_llm(reload=True)
        return jsonify({"ok": True, "roles": {r: c.role_cfg(r) for r in LLM_ROLES}})

    @app.route("/api/settings/llm/test", methods=["POST"])
    def settings_llm_test():
        from .llm import test_models
        return jsonify(test_models(get_config()))

    def hub():
        from .connectors import get_hub
        return get_hub(get_config())

    @app.route("/api/connectors")
    def connectors():
        return jsonify([s.public() for s in hub().specs.values()])

    @app.route("/api/connectors/<name>/tools")
    def connector_tools(name):
        h = hub()
        if name not in h.specs:
            return jsonify({"error": "not found"}), 404
        try:
            return jsonify(h.tools(name, refresh=request.args.get("refresh") == "1"))
        except Exception as exc:
            return jsonify({"error": str(exc)[:300]}), 502

    @app.route("/api/connectors/<name>/test", methods=["POST"])
    def connector_test(name):
        h = hub()
        if name not in h.specs:
            return jsonify({"error": "not found"}), 404
        return jsonify(h.test(name))

    @app.route("/api/settings/connectors", methods=["POST"])
    def settings_connectors():
        from .config import update_connectors
        b = request.get_json(silent=True) or {}
        try:
            r = update_connectors(b.get("connector"), remove=b.get("remove"), preview=bool(b.get("preview")))
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 400
        if not b.get("preview") and r["changed"]:
            from .connectors import get_hub
            get_hub(get_config(), reload=True)
        return jsonify(r)

    @app.route("/api/audit")
    def audit():
        return jsonify(hub().audit.recent(limit=min(500, int(request.args.get("limit", 100))),
                                          ref=request.args.get("ref") or None))

    @app.route("/api/audit/verify")
    def audit_verify():
        return jsonify(hub().audit.verify())

    # ---- intel: sources, documents, entities ----
    def kstore():
        from .intel.store import store_for
        return store_for(get_config())

    def actor():
        return str(getattr(g, "zarqa_user", "") or "local")

    def _int(name, default, lo=0, hi=1000):
        try:
            return max(lo, min(hi, int(request.args.get(name, default))))
        except ValueError:
            return default

    def _process_job(ids, use_model=None):
        return jobs.submit("process", {"documents": ids[:20]}, None, task="process",
                           params={"document_ids": ids, "use_model": use_model}, deduplicate=False)

    @app.route("/api/intel/stats")
    def intel_stats():
        from .intel import attack
        return jsonify({**kstore().stats(), "attack_version": attack.version()})

    @app.route("/api/sources")
    def sources():
        from .collect.collector import default_settings, sources_from
        st = kstore().source_state()
        c = get_config()
        return jsonify({"defaults": default_settings(c.raw),
                        "sources": [{**{k: v for k, v in s.items() if k not in ("headers_env", "arguments")},
                                     "state": st.get(s["name"], {})} for s in sources_from(c, include_disabled=True)]})

    @app.route("/api/settings/sources", methods=["POST"])
    def settings_sources():
        from .collect.collector import builtin_sources
        from .config import set_default_sources, set_own_source_enabled
        b = request.get_json(silent=True) or {}
        try:
            if "all_builtin" in b:
                d = set_default_sources(enabled=bool(b["all_builtin"]))
            elif b.get("name"):
                name, on = str(b["name"]), bool(b.get("enabled"))
                if name in {s["name"] for s in builtin_sources()} and name not in {
                        s.get("name") for s in (get_config().raw.get("sources") or [])}:
                    d = set_default_sources(enable=[name]) if on else set_default_sources(disable=[name])
                else:
                    set_own_source_enabled(name, on)
                    d = {}
            else:
                return jsonify({"error": "send all_builtin or name and enabled"}), 400
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 400
        return jsonify({"ok": True, "defaults": d})

    @app.route("/api/sources/<name>/pull", methods=["POST"])
    def source_pull(name):
        from .collect.collector import sources_from
        if name not in {s["name"] for s in sources_from(get_config(), include_disabled=True)}:
            return jsonify({"error": "no such source"}), 404
        jid = jobs.submit("pull", {"source": name}, None, task="pull", params={"source": name, "actor": actor()})
        return jsonify({"job_id": jid})

    @app.route("/api/documents", methods=["GET", "POST"])
    def documents():
        st = kstore()
        if request.method == "GET":
            mr = request.args.get("min_relevance")
            docs = st.documents(status=request.args.get("status") or None,
                                source=request.args.get("source") or None, q=request.args.get("q", "")[:200],
                                limit=_int("limit", 50, 1, 200), offset=_int("offset", 0, 0, 10**7),
                                min_relevance=int(mr) if mr and mr.isdigit() else None,
                                order=request.args.get("order", "newest"), tag=request.args.get("tag") or None)
            if request.args.get("group") == "story":
                from .intel.correlate import group_stories
                docs = group_stories(st, docs)
            return jsonify(docs)
        from .collect.fetch import FetchError
        from .intel.service import collector
        b = request.get_json(silent=True) or {}
        tags = [str(t)[:40] for t in b.get("tags") or []][:10]
        try:
            if b.get("text"):
                r = collector(get_config(), st).add_text(str(b["text"]), title=str(b.get("title", ""))[:300],
                                                         url=str(b.get("url", ""))[:2000], actor=actor(), tags=tags)
            elif b.get("url"):
                r = collector(get_config(), st).add_url(str(b["url"])[:2000], actor=actor(), tags=tags)
            else:
                return jsonify({"error": "send text or url"}), 400
        except (FetchError, ValueError) as exc:
            return jsonify({"error": str(exc)[:300]}), 400
        job = _process_job([r["id"]], b.get("use_model")) if r["new"] else None
        return jsonify({**r, "job_id": job})

    @app.route("/api/documents/<int:doc_id>")
    def document(doc_id):
        st = kstore()
        d = st.document(doc_id)
        if not d:
            return jsonify({"error": "not found"}), 404
        return jsonify({**d, "mentions": st.mentions(document_id=doc_id, limit=500),
                        "relations": st.relations(document_id=doc_id)})

    @app.route("/api/documents/<int:doc_id>/process", methods=["POST"])
    def document_process(doc_id):
        if not kstore().document(doc_id, with_text=False):
            return jsonify({"error": "not found"}), 404
        b = request.get_json(silent=True) or {}
        return jsonify({"job_id": _process_job([doc_id], b.get("use_model"))})

    @app.route("/api/documents/<int:doc_id>/relevance", methods=["POST"])
    def document_relevance(doc_id):
        from .intel.relevance import score_document
        from .llm import privacy_llm
        if not kstore().document(doc_id, with_text=False):
            return jsonify({"error": "not found"}), 404
        return jsonify(score_document(get_config(), kstore(), doc_id, llm=privacy_llm(get_config())))

    @app.route("/api/profile")
    def org_profile():
        from .intel.relevance import has_profile, profile
        p = profile(get_config())
        return jsonify({**p, "set": has_profile(p)})

    @app.route("/api/settings/profile", methods=["POST"])
    def settings_profile():
        from .config import set_profile
        from .intel.relevance import clean_profile, has_profile, profile
        org, reqs = clean_profile(request.get_json(silent=True) or {})
        try:
            c = set_profile(org, reqs)
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 400
        jid = jobs.submit("rescore", {"rescore": "all"}, None, task="rescore", params={})
        p = profile(c)
        return jsonify({**p, "set": has_profile(p), "job_id": jid})

    @app.route("/api/inventory")
    def inventory_summary():
        from .intel import inventory as invmod
        from .intel.relevance import profile
        cfg = get_config()
        inv = invmod.Inventory(kstore())
        hp = inv.hosts_by_product()
        have = profile(cfg)["products"]
        return jsonify({"sources": inv.sources(), "rows": inv.count(),
                        "connector": bool(invmod.settings(cfg)["from"]),
                        "profile": [{"product": x, "hosts": invmod.matches(x, hp)} for x in have],
                        "suggestions": invmod.suggest(inv, have, limit=_int("limit", 60, 1, 500))})

    @app.route("/api/inventory/import", methods=["POST"])
    def inventory_import():
        """Replace one inventory source from a scheduled export: the inventory token, or an admin."""
        if g.get("zarqa_user") != "inventory-token" and g.get("zarqa_role") != "admin":
            return jsonify({"error": "needs the inventory token or the admin role"}), 403
        return settings_inventory()

    @app.route("/api/settings/inventory", methods=["POST"])
    def settings_inventory():
        """Import an inventory: a file upload (``file``) or a JSON body ``{"source", "rows" | "content"}``."""
        from .intel import inventory as invmod
        s = invmod.settings(get_config())
        try:
            if "file" in request.files:
                f = request.files["file"]
                rows = invmod.parse(f.read(), fields=s["fields"], rows=s["rows"])
                source = request.form.get("source") or Path(f.filename or "file").stem
            else:
                body = request.get_json(silent=True) or {}
                rows = invmod.parse(body.get("rows") if "rows" in body else str(body.get("content", "")),
                                    fields=s["fields"], rows=s["rows"])
                source = str(body.get("source") or "upload")
        except (ValueError, UnicodeDecodeError) as exc:
            return jsonify({"error": f"could not read the inventory: {exc}"[:300]}), 400
        if not rows:
            return jsonify({"error": "no rows with a host and a name"}), 400
        r = invmod.Inventory(kstore()).replace(re.sub(r"[^A-Za-z0-9_.-]+", "-", source)[:60] or "upload", rows)
        r["job_id"] = jobs.submit("rescore", {"rescore": "all"}, None, task="rescore", params={})
        return jsonify(r)

    @app.route("/api/settings/inventory/pull", methods=["POST"])
    def settings_inventory_pull():
        from .intel import inventory as invmod
        if not invmod.settings(get_config())["from"]:
            return jsonify({"error": "no inventory.from connector configured"}), 400
        return jsonify({"job_id": jobs.submit("inventory", {"inventory": "pull"}, None, task="inventory",
                                              params={"actor": actor()})})

    @app.route("/api/settings/inventory/clear", methods=["POST"])
    def settings_inventory_clear():
        from .intel import inventory as invmod
        body = request.get_json(silent=True) or {}
        n = invmod.Inventory(kstore()).clear(str(body.get("source") or "") or None)
        return jsonify({"removed": n, "job_id": jobs.submit("rescore", {"rescore": "all"}, None, task="rescore",
                                                             params={})})

    @app.route("/api/entities")
    def entities():
        return jsonify(kstore().entities(etype=request.args.get("type") or None, q=request.args.get("q", "")[:200],
                                         status=request.args.get("status", "active") or None,
                                         order=request.args.get("order", "last_seen"),
                                         limit=_int("limit", 100, 1, 500), offset=_int("offset", 0, 0, 10**7)))

    @app.route("/api/handoff")
    def handoff_info():
        from .share.handoff import settings
        h = settings(get_config())
        return jsonify({"hunt": h["name"] if h else None})

    @app.route("/api/entities/<int:eid>/hunt")
    def entity_hunt(eid):
        from .share.handoff import for_entity
        try:
            return jsonify(for_entity(get_config(), kstore(), eid))
        except LookupError as exc:
            return jsonify({"error": str(exc)}), 400
        except ValueError:
            return jsonify({"error": "not found"}), 404

    @app.route("/api/documents/<int:doc_id>/hunt")
    def document_hunt(doc_id):
        from .share.handoff import for_document
        try:
            return jsonify(for_document(get_config(), kstore(), doc_id))
        except LookupError as exc:
            return jsonify({"error": str(exc)}), 400
        except ValueError:
            return jsonify({"error": "not found"}), 404

    @app.route("/api/documents/<int:doc_id>/related")
    def document_related(doc_id):
        from .intel.correlate import related_documents
        try:
            return jsonify(related_documents(kstore(), doc_id, limit=_int("limit", 10, 1, 50)))
        except ValueError:
            return jsonify({"error": "not found"}), 404

    @app.route("/api/entities/<int:eid>/connections")
    def entity_connections(eid):
        from .intel.correlate import connections
        try:
            return jsonify(connections(kstore(), eid, limit=_int("limit", 20, 1, 100)))
        except ValueError:
            return jsonify({"error": "not found"}), 404

    @app.route("/api/entities/<int:eid>/timeline")
    def entity_timeline(eid):
        from .intel.timeline import timeline
        try:
            return jsonify(timeline(kstore(), eid, limit=_int("limit", 200, 1, 1000)))
        except ValueError:
            return jsonify({"error": "not found"}), 404

    @app.route("/api/entities/<int:eid>")
    def entity(eid):
        from .intel import attack
        st = kstore()
        e = st.entity(eid)
        if not e:
            return jsonify({"error": "not found"}), 404
        ref = attack.technique(e["ref"]) if e["type"] == "technique" else (attack.known(e["ref"]) if e["ref"] else None)
        if ref and "tech" in ref:
            ref = {**ref, "tech": [{"id": t, "name": (attack.technique(t) or {}).get("name", "")} for t in ref["tech"]]}
            ref["sw"] = [{"id": x, "name": (attack.known(x) or {}).get("n", "")} for x in ref.get("sw", [])]
        from .intel.enrich import Results, enrichers_for
        return jsonify({**e, "attack": ref, "mentions": st.mentions(entity_id=eid), "relations": st.relations(entity_id=eid),
                        "enrichments": Results(st).for_entity(eid),
                        "enrichers": [x["name"] for x in enrichers_for(get_config(), hub(), e["type"])]})

    @app.route("/api/entities/<int:eid>/enrich", methods=["POST"])
    def entity_enrich(eid):
        if not kstore().entity(eid):
            return jsonify({"error": "not found"}), 404
        b = request.get_json(silent=True) or {}
        jid = jobs.submit("enrich", {"entity": eid, "only": b.get("only")}, None, task="enrich",
                          params={"entity_id": eid, "only": b.get("only"), "actor": actor(), "force": bool(b.get("force"))})
        return jsonify({"job_id": jid})

    @app.route("/api/entities/<int:eid>/status", methods=["POST"])
    def entity_status(eid):
        b = request.get_json(silent=True) or {}
        try:
            kstore().set_status(eid, str(b.get("status", "")), str(b.get("note", ""))[:500])
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 400
        return jsonify({"ok": True})

    @app.route("/api/lookup")
    def lookup():
        v = request.args.get("value", "").strip()[:2048]
        if not v:
            return jsonify({"error": "value is required"}), 400
        st = kstore()
        return jsonify([{**e, "mentions": st.mentions(entity_id=e["id"], limit=20)} for e in st.lookup(v)])

    @app.route("/api/values", methods=["POST"])
    def add_values():
        from .intel.service import collector
        b = request.get_json(silent=True) or {}
        vals = [str(v)[:2048] for v in b.get("values") or []][:10_000]
        if not vals:
            return jsonify({"error": "values is a list of indicators"}), 400
        ctx = str(b.get("context", "malicious"))
        return jsonify(collector(get_config(), kstore()).add_values(vals, actor=actor(), context=ctx,
                                                                     tags=[str(t)[:40] for t in b.get("tags") or []][:10]))

    @app.route("/api/import/stix", methods=["POST"])
    def import_stix():
        from .collect.stix_in import import_bundle
        b = request.get_json(silent=True)
        if not isinstance(b, (dict, list)):
            return jsonify({"error": "send a STIX bundle as JSON"}), 400
        try:
            r = import_bundle(kstore(), b, source="manual", method="manual", added_by=actor())
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 400
        job = _process_job(r["reports"]) if r["reports"] else None
        return jsonify({**r, "job_id": job})

    # ---- reports ----
    def _report(md: str, fmt: str, name: str, title: str):
        from flask import Response

        from .reporting import to_html
        if fmt == "html":
            r = Response(to_html(md, title), mimetype="text/html")
            # the report carries its own small stylesheet and nothing else
            r.headers["Content-Security-Policy"] = "default-src 'none'; style-src 'unsafe-inline'; img-src 'none'"
        elif fmt == "md":
            r = Response(md, mimetype="text/markdown")
        else:
            return jsonify({"error": "format must be md or html"}), 400
        if request.args.get("download"):
            r.headers["Content-Disposition"] = f'attachment; filename="{name}.{fmt}"'
        return r

    @app.route("/api/brief")
    def brief():
        from .reporting import brief_data, brief_markdown
        try:
            days = max(0.1, min(90.0, float(request.args.get("days", 1))))
        except ValueError:
            days = 1.0
        b = brief_data(get_config(), kstore(), days=days)
        fmt = request.args.get("format", "json")
        if fmt == "json":
            return jsonify(b)
        return _report(brief_markdown(b), fmt, f"zarqa-brief-{b['generated'][:10]}", f"{b['instance']} brief")

    @app.route("/api/documents/<int:doc_id>/report.<fmt>")
    def document_report(doc_id, fmt):
        from .reporting import document_markdown
        try:
            md = document_markdown(kstore(), doc_id)
        except ValueError:
            return jsonify({"error": "not found"}), 404
        return _report(md, fmt, f"zarqa-document-{doc_id}", f"Document {doc_id}")

    # ---- sharing out ----
    from .share.taxii_server import blueprint as taxii_bp
    app.register_blueprint(taxii_bp(kstore, get_config))

    def _export_args():
        d = request.args.get("document")
        ids = [int(x) for x in request.args.get("entities", "").split(",") if x.strip().isdigit()]
        return (int(d) if d and d.isdigit() else None), ids

    @app.route("/api/export/<fmt>")
    def export_any(fmt):
        from .share.misp import event
        from .share.stix_out import export
        doc, ids = _export_args()
        try:
            if fmt == "stix":
                body = export(kstore(), producer_name=get_config().instance_name, document_id=doc, entity_ids=ids or None,
                              since=request.args.get("since") or None,
                              types=[t for t in request.args.get("types", "").split(",") if t] or None,
                              min_confidence=_int("min_confidence", 0, 0, 100), limit=_int("limit", 5000, 1, 50_000))
            elif fmt == "misp":
                if doc is None and not ids:
                    return jsonify({"error": "choose document= or entities="}), 400
                body = event(kstore(), info=request.args.get("info", ""), document_id=doc, entity_ids=ids or None,
                             producer=get_config().instance_name)
            else:
                return jsonify({"error": "format must be stix or misp"}), 400
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 404
        r = jsonify(body)
        name = f"zarqa-{'document-' + str(doc) if doc is not None else 'export'}.{fmt}.json"
        if request.args.get("download"):
            r.headers["Content-Disposition"] = f'attachment; filename="{name}"'
        return r

    @app.route("/api/share/targets")
    def share_targets():
        from .share.push import targets
        return jsonify([{"name": t["name"], "format": t.get("format", "stix"), "connector": t["connector"]}
                        for t in targets(get_config())])

    @app.route("/api/share", methods=["POST"])
    def share_push():
        from .connectors.hub import ToolCallError
        from .share.push import push
        b = request.get_json(silent=True) or {}
        doc = b.get("document_id")
        try:
            r = push(get_config(), kstore(), str(b.get("target", "")), actor=actor(),
                     document_id=int(doc) if doc is not None else None,
                     entity_ids=[int(x) for x in b.get("entity_ids") or []][:5000] or None, hub=hub())
        except (ValueError, ToolCallError) as exc:
            return jsonify({"error": str(exc)[:400]}), 400
        return jsonify(r)

    from .mcp_server import build as build_mcp

    def _role():
        return getattr(g, "zarqa_role", "viewer")
    mcp_srv = build_mcp(cfg, jobs, role_of=_role)

    @app.route("/mcp", methods=["POST", "GET", "DELETE"])
    def mcp_http():
        if request.method != "POST":
            return jsonify({"error": "use POST with a JSON-RPC message"}), 405
        msg = request.get_json(silent=True)
        if isinstance(msg, list):
            replies = [r for r in (mcp_srv.handle(m) for m in msg if isinstance(m, dict)) if r]
            return (jsonify(replies), 200) if replies else ("", 202)
        if not isinstance(msg, dict):
            return jsonify({"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "parse error"}}), 400
        reply = mcp_srv.handle(msg)
        return (jsonify(reply), 200) if reply else ("", 202)

    # ---- brand watch ----
    @app.route("/api/brand")
    def brand():
        from .brand.watch import settings as bset
        from .brand.watch import store_for as bstore
        st = bstore(get_config())
        mn = request.args.get("min_score", "0")
        return jsonify({"watch": bset(get_config())["watch"], "last_run": st.last_run(),
                        "findings": st.findings(status=request.args.get("status") or None,
                                                min_score=int(mn) if mn.isdigit() else 0, limit=_int("limit", 200, 1, 1000))})

    @app.route("/api/brand/run", methods=["POST"])
    def brand_run():
        return jsonify({"job_id": jobs.submit("brand", {"brand": "watch"}, None, task="brand", params={})})

    @app.route("/api/brand/<int:fid>/status", methods=["POST"])
    def brand_status(fid):
        from .brand.watch import store_for as bstore
        b = request.get_json(silent=True) or {}
        try:
            bstore(get_config()).set_status(fid, str(b.get("status", "")), str(b.get("note", "")), actor())
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 400
        return jsonify({"ok": True})

    # ---- investigations ----
    @app.route("/api/investigations", methods=["GET", "POST"])
    def investigations():
        from .investigate.service import start
        from .investigate.store import store_for as istore
        if request.method == "GET":
            return jsonify(istore(get_config()).list(limit=_int("limit", 50, 1, 200)))
        b = request.get_json(silent=True) or {}
        try:
            inv_id = start(jobs, get_config(), str(b.get("question", ""))[:2000], actor=actor())
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 400
        return jsonify({"id": inv_id})

    @app.route("/api/investigations/<int:inv_id>")
    def investigation(inv_id):
        from .investigate.store import store_for as istore
        d = istore(get_config()).get(inv_id)
        return (jsonify(d), 200) if d else (jsonify({"error": "not found"}), 404)

    @app.route("/api/investigations/<int:inv_id>/stop", methods=["POST"])
    def investigation_stop(inv_id):
        from .investigate.store import store_for as istore
        d = istore(get_config()).get(inv_id)
        if not d:
            return jsonify({"error": "not found"}), 404
        return jsonify({"ok": bool(d["job_id"]) and jobs.cancel(d["job_id"])})

    @app.route("/api/doctor")
    def doctor_api():
        from .doctor import run as run_doctor
        return jsonify(run_doctor(offline=request.args.get("offline") == "1"))

    @app.route("/api/jobs")
    def list_jobs():
        return jsonify(jobs.list(limit=50))

    @app.route("/api/jobs/<job_id>", methods=["GET"])
    def get_job(job_id):
        j = jobs.get(job_id)
        return (jsonify(j), 200) if j else (jsonify({"error": "not found"}), 404)

    @app.route("/api/jobs/<job_id>/<action>", methods=["POST"])
    def job_action(job_id, action):
        fn = {"cancel": jobs.cancel, "pause": jobs.pause, "resume": jobs.resume}.get(action)
        if not fn:
            return jsonify({"error": "unknown action"}), 400
        return jsonify({"ok": fn(job_id)})

    return app
