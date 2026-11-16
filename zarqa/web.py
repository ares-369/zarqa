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
    init_auth(app, cfg)
    cfg.data_dir.mkdir(parents=True, exist_ok=True)
    jobs = JobManager.from_config(cfg)
    app.extensions["zarqa_jobs"] = jobs

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
