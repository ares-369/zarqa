"""Flask app factory for the Zarqa web UI and JSON API."""

from __future__ import annotations

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
        return render_template("index.html", name=cfg.instance_name, version=__version__)

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
        from .collect.collector import sources_from
        st = kstore().source_state()
        return jsonify([{**{k: v for k, v in s.items() if k not in ("headers_env", "arguments")},
                         "state": st.get(s["name"], {})} for s in sources_from(get_config())])

    @app.route("/api/sources/<name>/pull", methods=["POST"])
    def source_pull(name):
        from .collect.collector import sources_from
        if name not in {s["name"] for s in sources_from(get_config())}:
            return jsonify({"error": "no such source"}), 404
        jid = jobs.submit("pull", {"source": name}, None, task="pull", params={"source": name, "actor": actor()})
        return jsonify({"job_id": jid})

    @app.route("/api/documents", methods=["GET", "POST"])
    def documents():
        st = kstore()
        if request.method == "GET":
            mr = request.args.get("min_relevance")
            return jsonify(st.documents(status=request.args.get("status") or None,
                                        source=request.args.get("source") or None, q=request.args.get("q", "")[:200],
                                        limit=_int("limit", 50, 1, 200), offset=_int("offset", 0, 0, 10**7),
                                        min_relevance=int(mr) if mr and mr.isdigit() else None,
                                        order=request.args.get("order", "newest"), tag=request.args.get("tag") or None))
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

    @app.route("/api/entities")
    def entities():
        return jsonify(kstore().entities(etype=request.args.get("type") or None, q=request.args.get("q", "")[:200],
                                         status=request.args.get("status", "active") or None,
                                         order=request.args.get("order", "last_seen"),
                                         limit=_int("limit", 100, 1, 500), offset=_int("offset", 0, 0, 10**7)))

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
