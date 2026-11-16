import base64
from pathlib import Path

import pytest

from tests.conftest import write_cfg
from zarqa import config
from zarqa.server import startup_security_check
from zarqa.web import create_app

ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture
def client(home):
    return create_app(config.get_config(reload=True)).test_client()


def _basic(user="zarqa", pw="pw"):
    return {"Authorization": "Basic " + base64.b64encode(f"{user}:{pw}".encode()).decode()}


def test_index_and_health(client):
    assert client.get("/healthz").json == {"ok": True}
    r = client.get("/")
    assert r.status_code == 200 and b"/static/img/logo.svg" in r.data
    csp = r.headers["Content-Security-Policy"]
    assert "script-src 'self'" in csp and "unsafe-inline" not in csp
    assert r.headers["X-Frame-Options"] == "DENY" and r.headers["X-Content-Type-Options"] == "nosniff"


def test_status_and_me(client):
    j = client.get("/api/status").json
    assert j["auth_mode"] == "none" and set(j["roles"]) == {"extractor", "analyst", "reporter"}
    assert client.get("/api/me").json["role"] == "admin"


def test_settings_llm_flow(client):
    assert "ollama" in client.get("/api/settings/llm").json["providers"]
    body = {"roles": {"reporter": {"provider": "gemini", "model": ""}}}
    assert client.post("/api/settings/llm", json={**body, "preview": True}).json["changed"]
    assert client.post("/api/settings/llm", json=body).json["roles"]["reporter"]["provider"] == "gemini"
    assert client.post("/api/settings/llm", json={"roles": {"planner": {}}}).status_code == 400
    bad = {"roles": {"analyst": {"provider": "ollama", "model": "x; rm -rf /"}}}
    assert client.post("/api/settings/llm", json=bad).status_code == 400


def test_jobs_api(client):
    assert client.get("/api/jobs").json == []
    assert client.get("/api/jobs/missing").status_code == 404
    assert client.post("/api/jobs/missing/explode").status_code == 400


def test_doctor_api(client):
    rows = client.get("/api/doctor?offline=1").json
    assert {r["area"] for r in rows} >= {"config", "data", "storage", "auth", "models", "organization"}


def test_basic_auth_required(home, monkeypatch):
    write_cfg(home, lambda d: d["auth"].update(mode="basic"))
    monkeypatch.setenv("ZARQA_AUTH_PASSWORD", "pw")
    c = create_app(config.load_config()).test_client()
    assert c.get("/api/status").status_code == 401
    assert c.get("/api/status", headers=_basic(pw="wrong")).status_code == 401
    assert c.get("/api/status", headers=_basic()).status_code == 200
    assert c.get("/healthz").status_code == 200


def test_roles_are_enforced(home, monkeypatch):
    write_cfg(home, lambda d: d["auth"].update(mode="basic", default_role="viewer"))
    monkeypatch.setenv("ZARQA_AUTH_PASSWORD", "pw")
    c = create_app(config.load_config()).test_client()
    assert c.post("/api/settings/llm", json={"roles": {}}, headers=_basic()).status_code == 403
    assert c.get("/api/doctor", headers=_basic()).status_code == 403      # admin-only read
    assert c.get("/api/status", headers=_basic()).status_code == 200


def test_refuses_open_network_bind(home):
    write_cfg(home, lambda d: d["zarqa"].update(bind_host="0.0.0.0"))
    errors, _ = startup_security_check(config.load_config())
    assert errors and "NO login" in errors[0]
    write_cfg(home, lambda d: d["auth"].update(mode="proxy"))
    errors, _ = startup_security_check(config.load_config())
    assert any("proxy_trusted_ips" in e for e in errors)


def test_ui_never_parses_html():
    js = (ROOT / "zarqa/static/app.js").read_text()
    for bad in ("innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval("):
        assert bad not in js, bad


def test_ui_loads_nothing_external():
    for p in [*(ROOT / "zarqa/templates").glob("*.html"), ROOT / "zarqa/static/app.css", ROOT / "zarqa/static/app.js"]:
        text = p.read_text()
        assert "http://" not in text and "https://" not in text, p.name
