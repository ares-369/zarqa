import json
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest

from zarqa.connectors import ConnectorHub, ToolCallError, parse_connectors
from zarqa.connectors.audit import AuditLog
from zarqa.connectors.policy import decide, looks_write
from zarqa.connectors.ratelimit import Pacer

FAKE = str(Path(__file__).parent / "fixtures" / "fake_mcp.py")
sys.path.insert(0, str(Path(__file__).parent / "fixtures"))
import fake_mcp  # noqa: E402


def stdio_spec(**kw):
    raw = {"name": "fake", "roles": ["enrichment"], "transport": "stdio", "command": sys.executable,
           "args": [FAKE], "timeout_sec": 5, "rate_per_min": 6000}
    raw.update(kw)
    return parse_connectors([raw])[0]


def make_hub(tmp_path, *specs):
    return ConnectorHub(list(specs), AuditLog(tmp_path / "audit.sqlite"), max_result_bytes=2000,
                        sleep=lambda s: None)


# ---- spec validation ----
@pytest.mark.parametrize("raw", [
    {"name": "Bad Name", "roles": ["enrichment"], "transport": "stdio", "command": "x"},
    {"name": "a", "roles": [], "transport": "stdio", "command": "x"},
    {"name": "a", "roles": ["siem"], "transport": "stdio", "command": "x"},
    {"name": "a", "roles": ["enrichment"], "transport": "ftp"},
    {"name": "a", "roles": ["enrichment"], "transport": "http", "url": "nope"},
    {"name": "a", "roles": ["enrichment"], "transport": "stdio"},
    {"name": "a", "roles": ["enrichment"], "transport": "http", "url": "https://x", "auth": {"type": "magic"}},
    {"name": "a", "roles": ["enrichment"], "transport": "http", "url": "https://x",
     "auth": {"type": "bearer", "token": "plaintext-secret"}},
])
def test_spec_rejects(raw):
    with pytest.raises(ValueError):
        parse_connectors([raw])


def test_duplicate_names():
    r = {"name": "a", "roles": ["enrichment"], "transport": "stdio", "command": "x"}
    with pytest.raises(ValueError):
        parse_connectors([r, r])


def test_public_view_has_no_secrets():
    s = parse_connectors([{"name": "a", "roles": ["enrichment"], "transport": "stdio", "command": "x",
                           "env": {"K": "${SECRET}"}}])[0]
    assert "env" not in s.public()


# ---- policy ----
@pytest.mark.parametrize("name,write", [
    ("search_events", False), ("get_host", False), ("isolateHost", True), ("delete-rule", True),
    ("run_query", True), ("list_alerts", False),
])
def test_looks_write(name, write):
    assert looks_write({"name": name}) is write


def test_write_name_wins_over_readonly_hint():
    assert looks_write({"name": "delete_all", "annotations": {"readOnlyHint": True}})


def test_policy_order():
    s = stdio_spec(tools={"deny": ["get_*"]})
    assert decide(s, {"name": "get_host"})[0] is False
    s = stdio_spec(tools={"allow": ["search_*"]})
    assert decide(s, {"name": "get_host"})[0] is False
    assert decide(s, {"name": "search_events"})[0] is True
    s = stdio_spec(allow_write=True, tools={"allow": ["create_*", "search_events"]})
    assert decide(s, {"name": "create_case"})[0] is False    # glob is not enough for writes
    s = stdio_spec(allow_write=True, tools={"allow": ["create_case"]})
    assert decide(s, {"name": "create_case"})[0] is True


def test_never_class_cannot_be_enabled():
    for name in ("isolate_host", "quarantineFile", "kill-process", "delete_user", "disable_account",
                 "revoke_sessions", "block_ip", "wipe_device", "reset_password"):
        s = stdio_spec(allow_write=True, tools={"allow": [name]})
        ok, why = decide(s, {"name": name})
        assert ok is False and "never" in why, name
    # A server-declared destructive tool is never allowed either, even with an innocent name.
    s = stdio_spec(allow_write=True, tools={"allow": ["create_case"]})
    assert decide(s, {"name": "create_case", "annotations": {"destructiveHint": True}})[0] is False
    # Read tools that only mention these words in a noun form stay allowed.
    s = stdio_spec()
    for name in ("search_blocked_connections", "list_quarantined_files", "decode_command", "get_deleted_items"):
        assert decide(s, {"name": name})[0] is True, name


def test_pacer_spacing():
    t = [0.0]
    slept = []
    p = Pacer(clock=lambda: t[0], sleep=slept.append)
    p.acquire("a", 60)
    p.acquire("a", 60)
    p.acquire("b", 60)
    assert slept == [1.0]


# ---- stdio end to end ----
def test_stdio_hub(tmp_path, monkeypatch):
    monkeypatch.setenv("MY_SECRET", "s3cret")
    hub = make_hub(tmp_path, stdio_spec(env={"FAKE_SECRET": "${MY_SECRET}"}))
    try:
        r = hub.test("fake")
        assert r["ok"] and r["tools"] == 7 and r["allowed"] == 5
        names = {t["name"] for t in hub.tools_for_role("enrichment")}
        assert names == {"search_events", "get_host", "flaky", "inject", "slow"}
        assert hub.tools_for_role("intel") == []
        out = hub.call("fake", "search_events", {"q": "x", "api_key": "k"}, ref="h1")
        assert "UNTRUSTED-DATA" in out["content"] and "s3cret" in out["content"]
        with pytest.raises(ToolCallError):
            hub.call("fake", "isolate_host", {})
        with pytest.raises(ToolCallError):
            hub.call("fake", "nope", {})
        rows = hub.audit.recent()
        assert [r["status"] for r in rows] == ["blocked", "blocked", "ok"]
        assert '"api_key": "***"' in rows[2]["arguments"] and rows[2]["ref"] == "h1"
    finally:
        hub.close()


def test_stdio_env_is_minimal(tmp_path, monkeypatch):
    monkeypatch.setenv("FAKE_SECRET", "leaked-from-parent")
    hub = make_hub(tmp_path, stdio_spec())
    try:
        assert "leaked-from-parent" not in hub.call("fake", "get_host", {})["content"]
    finally:
        hub.close()


def test_injection_marker_neutralised(tmp_path):
    hub = make_hub(tmp_path, stdio_spec())
    try:
        c = hub.call("fake", "inject", {})["content"]
        assert c.count("UNTRUSTED-DATA") == 2  # only our own open + close markers
    finally:
        hub.close()


def test_retry_then_error(tmp_path, monkeypatch):
    monkeypatch.setenv("FAKE_FLAKY_FAILS", "1")
    hub = make_hub(tmp_path, stdio_spec(env={"FAKE_FLAKY_FAILS": "${FAKE_FLAKY_FAILS}"}))
    try:
        # first attempt fails, the retry reconnects (fresh process, counter reset) -> fails again ...
        with pytest.raises(ToolCallError, match="3 attempts"):
            hub.call("fake", "flaky", {})
        assert hub.audit.recent()[0]["status"] == "error"
    finally:
        hub.close()


def test_audit_append_only(tmp_path):
    a = AuditLog(tmp_path / "a.sqlite")
    a.record(connector="c", tool="t", arguments={}, decision="allowed", status="ok")
    import sqlite3

    from zarqa import db
    with db.connect(tmp_path / "a.sqlite") as c, pytest.raises(sqlite3.DatabaseError):
        c.execute("DELETE FROM audit")


# ---- HTTP end to end ----
class _H(BaseHTTPRequestHandler):
    seen: list = []

    def log_message(self, *a):
        pass

    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        _H.seen.append(dict(self.headers))
        if self.headers.get("Authorization") != "Bearer tok123":
            self.send_response(401)
            self.end_headers()
            return
        out = fake_mcp.handle(body)
        if out is None:
            self.send_response(202)
            self.end_headers()
            return
        sse = body.get("method") == "tools/call"
        payload = (f"event: message\ndata: {json.dumps(out)}\n\n" if sse else json.dumps(out)).encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream" if sse else "application/json")
        self.send_header("Mcp-Session-Id", "sess-1")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_DELETE(self):
        self.send_response(204)
        self.end_headers()


@pytest.fixture
def http_url():
    srv = HTTPServer(("127.0.0.1", 0), _H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_port}/mcp"
    srv.shutdown()


def test_http_hub(tmp_path, http_url, monkeypatch):
    monkeypatch.setenv("TOK", "tok123")
    spec = parse_connectors([{"name": "remote", "roles": ["malware"], "transport": "http", "url": http_url,
                              "auth": {"type": "bearer", "token_env": "TOK"}, "timeout_sec": 5,
                              "rate_per_min": 6000}])[0]
    hub = make_hub(tmp_path, spec)
    try:
        assert hub.test("remote")["ok"]
        out = hub.call("remote", "get_host", {"id": 1})
        assert '"tool": "get_host"' in out["content"]
        assert _H.seen[-1].get("Mcp-Session-Id") == "sess-1"
    finally:
        hub.close()


def test_http_bad_token(tmp_path, http_url, monkeypatch):
    monkeypatch.setenv("TOK", "wrong")
    spec = parse_connectors([{"name": "remote", "roles": ["malware"], "transport": "http", "url": http_url,
                              "auth": {"type": "bearer", "token_env": "TOK"}}])[0]
    r = make_hub(tmp_path, spec).test("remote")
    assert not r["ok"] and "authentication" in r["error"]


def test_stdio_connector_is_safe_under_concurrent_calls(tmp_path):
    """Parallel investigations share one stdio process; every caller must get its own reply."""
    from concurrent.futures import ThreadPoolExecutor
    hub = make_hub(tmp_path, stdio_spec(rate_per_min=1_000_000, timeout_sec=5))   # no pacing: calls really overlap
    try:
        hub.test("fake")
        with ThreadPoolExecutor(max_workers=8) as ex:
            outs = list(ex.map(lambda i: hub.call("fake", "search_events", {"q": f"q{i}"}, ref=f"h{i}"), range(24)))
        assert len(outs) == 24 and all("UNTRUSTED-DATA" in o["content"] for o in outs)
    finally:
        hub.close()


# ---- sharing: pushing intel to another platform ----
def _share_spec(**kw):
    raw = {"name": "out", "roles": ["sharing"], "transport": "stdio", "command": "x", **kw}
    return parse_connectors([raw])[0]


def test_share_policy():
    from zarqa.connectors.policy import decide, decide_share
    push = {"name": "add_bundle"}
    assert not decide_share(_share_spec(), push)[0]                                     # read-only by default
    assert not decide_share(_share_spec(allow_write=True), push)[0]                     # not named
    s = _share_spec(allow_write=True, tools={"allow": ["add_bundle"]})
    assert decide_share(s, push) == (True, "allowed sharing tool")
    assert not decide(s, push)[0]                     # the read path (models) never gets the write tool
    assert not decide_share(_share_spec(allow_write=True, tools={"allow": ["delete_event"]}), {"name": "delete_event"})[0]
    enrich = parse_connectors([{"name": "e", "roles": ["enrichment"], "transport": "stdio", "command": "x",
                                "allow_write": True, "tools": {"allow": ["add_bundle"]}}])[0]
    assert not decide_share(enrich, push)[0]          # needs the sharing role


def test_share_call_is_audited_and_not_retried(tmp_path, monkeypatch):
    s = _share_spec(allow_write=True, tools={"allow": ["add_bundle"]})
    calls = []

    class C:
        def __init__(self, spec):
            pass

        def list_tools(self):
            return [{"name": "add_bundle"}, {"name": "list_events"}]

        def call_tool(self, name, args, timeout=None):
            calls.append(name)
            return {"content": [{"type": "text", "text": "stored 3 objects"}]}

        def close(self):
            pass
    hub = ConnectorHub([s], AuditLog(tmp_path / "a.sqlite"), sleep=lambda x: None, client_factory=C)
    with pytest.raises(ToolCallError):
        hub.share("out", "add_bundle", {}, actor="")                      # someone must own the push
    assert hub.share("out", "add_bundle", {"bundle": {}}, actor="alice", ref="share:1")["ok"]
    assert calls == ["add_bundle"]
    row = hub.audit.recent(limit=1)[0]
    assert row["status"] == "shared" and row["actor"] == "alice" and row["ref"] == "share:1"
    with pytest.raises(ToolCallError):
        hub.share("out", "list_events", {}, actor="alice")                # not on the allow list
    assert hub.tools_for_role("sharing") == [] or all(not t["name"].startswith("add") for t in hub.tools_for_role("sharing"))
