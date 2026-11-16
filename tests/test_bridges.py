import json
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse

import pytest

from zarqa.bridges.openapi import OpenApiBridge
from zarqa.bridges.server import McpServer, ToolInputError
from zarqa.bridges.taxii import TaxiiBridge
from zarqa.bridges.web import WebBridge, leak_check
from zarqa.collect.fetch import FetchError, _check_host, fetch_url
from zarqa.connectors import ConnectorHub, parse_connectors
from zarqa.connectors.audit import AuditLog


class Resp:
    def __init__(self, data, status=200):
        self.status_code, self._d = status, data
        self.text = json.dumps(data)
        self.content = self.text.encode()

    def json(self):
        return self._d


class FakeSession:
    def __init__(self, routes):
        self.routes, self.calls, self.headers = routes, [], {}

    def _hit(self, method, url, **kw):
        self.calls.append((method, url, kw))
        for key, val in self.routes.items():
            if key in url:
                return Resp(val(kw) if callable(val) else val)
        return Resp({"error": "nope"}, 404)

    def get(self, url, **kw):
        return self._hit("GET", url, **kw)

    def post(self, url, **kw):
        return self._hit("POST", url, **kw)


# ---- MCP server core ----
def test_server_core():
    s = McpServer("t")
    s.tool("echo", "e", {"type": "object"})(lambda a: {"got": a})

    def bad(a):
        raise ToolInputError("nope")
    s.tool("bad", "b", {"type": "object"})(bad)
    assert s.handle({"id": 1, "method": "initialize"})["result"]["serverInfo"]["name"] == "t"
    assert s.handle({"method": "notifications/initialized"}) is None
    assert [t["name"] for t in s.handle({"id": 2, "method": "tools/list"})["result"]["tools"]] == ["echo", "bad"]
    r = s.handle({"id": 3, "method": "tools/call", "params": {"name": "echo", "arguments": {"x": 1}}})["result"]
    assert r["structuredContent"] == {"got": {"x": 1}}
    assert s.handle({"id": 4, "method": "tools/call", "params": {"name": "bad"}})["result"]["isError"]
    assert "error" in s.handle({"id": 5, "method": "tools/call", "params": {"name": "zzz"}})
    assert "error" in s.handle({"id": 6, "method": "sampling/createMessage"})


# ---- TAXII ----
IND = {"type": "indicator", "id": "indicator--" + "0" * 8 + "-0000-0000-0000-" + "0" * 12, "name": "bad ip",
       "pattern": "[ipv4-addr:value = '203.0.113.9']", "valid_from": "2026-01-01T00:00:00Z"}


def test_taxii_flow():
    pages = {"n": 0}

    def objects(kw):
        pages["n"] += 1
        if pages["n"] == 1:
            return {"objects": [IND], "more": True, "next": "p2"}
        return {"objects": [{**IND, "pattern": "[domain-name:value = 'x.example']"}], "more": False}
    t = TaxiiBridge("https://taxii.example/api1", session=FakeSession({
        "/objects/": objects, "collections/": {"collections": [{"id": "c1", "title": "C", "can_read": True},
                                                              {"id": "c2", "can_read": False}]}}))
    assert [c["id"] for c in t.list_collections({})["collections"]] == ["c1"]
    r = t.find_indicator({"value": "203.0.113.9"})
    assert len(r["matches"]) == 1 and r["scanned"] == 2
    assert t.http.headers["Accept"].startswith("application/taxii+json")
    assert all(m == "GET" for m, _, _ in t.http.calls)


def test_taxii_guards():
    t = TaxiiBridge("https://t.example/", collections=["c1"], session=FakeSession({}))
    for args in ({"collection": "c9"}, {"collection": "c1", "type": "evil"}):
        with pytest.raises(ToolInputError):
            t.get_objects(args)
    with pytest.raises(ToolInputError):
        t.get_object({"collection": "c1", "id": "../../etc"})
    with pytest.raises(ToolInputError):
        t.find_indicator({"value": "a"})


# ---- OpenAPI ----
SPEC = {
    "openapi": "3.0.0", "info": {"title": "Demo"}, "servers": [{"url": "https://api.example/v1"}],
    "components": {"parameters": {"Lim": {"name": "limit", "in": "query", "schema": {"type": "integer"}}}},
    "paths": {
        "/hosts/{id}": {"get": {"operationId": "getHost", "parameters": [
            {"name": "id", "in": "path", "required": True, "schema": {"type": "string"}}]},
            "delete": {"operationId": "deleteHost"}},
        "/hosts": {"get": {"operationId": "listHosts", "parameters": [{"$ref": "#/components/parameters/Lim"}]},
                   "post": {"operationId": "createHost"}},
        "/search": {"post": {"operationId": "restSearch"}},
    },
}


def test_openapi_exposes_reads_only():
    b = OpenApiBridge(SPEC, allow_post=["restSearch"], session=FakeSession({"/hosts": {"ok": 1}, "/search": {"r": 1}}))
    assert set(b.collect()) == {"getHost", "listHosts", "restSearch"}
    assert b.ops["listHosts"]["schema"]["properties"]["limit"]["type"] == "integer"
    assert json.loads(b.call("getHost", {"id": "a/../../admin"})) == {"ok": 1}
    assert b.http.calls[0][1] == "https://api.example/v1/hosts/a%2F..%2F..%2Fadmin"
    b.call("restSearch", {"body": {"value": "x"}})
    assert b.http.calls[1][0] == "POST" and b.http.calls[1][2]["json"] == {"value": "x"}
    with pytest.raises(ToolInputError):
        b.call("getHost", {})


def test_openapi_include_and_limit():
    assert set(OpenApiBridge(SPEC, include=["list*"], session=FakeSession({})).collect()) == {"listHosts"}
    with pytest.raises(ValueError):
        OpenApiBridge(SPEC, max_tools=1, session=FakeSession({})).collect()
    with pytest.raises(ValueError):
        OpenApiBridge({"paths": {}}, session=FakeSession({}))


# ---- web bridge and safe fetching ----
@pytest.mark.parametrize("text", ["10.1.2.3 beacon", "user@corp.example", "host ws-1234 example corp", "WS-1234"])
def test_leak_check_refuses(text):
    import re
    with pytest.raises(ToolInputError):
        leak_check(text, ["example corp"], [re.compile(r"\bWS-\d{4}\b")])


def test_leak_check_allows_public():
    leak_check("8.8.8.8 CVE-2024-3400 beacon loader", ["example corp"])


def test_web_bridge():
    class S:
        def get(self, url, params=None, **kw):
            assert params["format"] == "json"

            class R:
                status_code = 200

                def json(self):
                    return {"results": [{"title": "T", "url": "https://x.example", "content": "snippet"}]}
            return R()
    b = WebBridge("https://search.example/search", ["corp"], session=S(),
                  fetch=lambda url, **kw: {"url": url, "title": "", "text": "page text", "content_type": "text/html"})
    assert set(b.build().tools) == {"fetch_page", "search_web"}
    assert b.search_web({"query": "CVE-2024-3400"})["results"][0]["url"] == "https://x.example"
    assert b.fetch_page({"url": "https://x.example"})["text"] == "page text"
    with pytest.raises(ToolInputError):
        b.search_web({"query": "corp vpn"})
    assert set(WebBridge("").build().tools) == {"fetch_page"}


def test_url_guard():
    for url in ("file:///etc/passwd", "http://127.0.0.1/x", "http://10.0.0.1/x", "http://[::1]/x",
                "http://169.254.169.254/latest/meta-data"):
        with pytest.raises(FetchError):
            _check_host(url, False)
    _check_host("http://10.0.0.1/x", True)


def test_redirect_to_private_is_refused(monkeypatch):
    import zarqa.collect.fetch as f
    monkeypatch.setattr(f, "_check_host", lambda url, allow: (_ for _ in ()).throw(FetchError("private"))
                        if "10.0.0.9" in url else None)

    class R:
        def __init__(self, status, loc=None):
            self.status_code, self.headers = status, ({"Location": loc} if loc else {})

        def close(self):
            pass

    class S:
        def get(self, url, **kw):
            return R(302, "http://10.0.0.9/internal")
    with pytest.raises(FetchError):
        fetch_url("https://public.example/adv", session=S())


def test_web_connector_only_when_enabled(home):
    from tests.conftest import write_cfg
    from zarqa import config
    from zarqa.connectors import get_hub
    assert "web" not in get_hub(config.get_config(reload=True), reload=True).specs
    write_cfg(home, lambda d: d.update(web={"tools": True}, privacy={**d["privacy"], "terms": ["examplecorp"]}))
    hub = get_hub(config.get_config(reload=True), reload=True)
    spec = hub.specs["web"]
    assert spec.roles == ["search"] and "--block-term" in spec.args and "examplecorp" in spec.args


# ---- end to end: hub -> stdio TAXII bridge -> local HTTP TAXII server ----
class _Taxii(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        assert self.headers.get("Authorization", "") == "Bearer tok"
        path = urlparse(self.path).path
        if path.endswith("/collections/"):
            data = {"collections": [{"id": "c1", "title": "Feed", "can_read": True}]}
        elif "/objects/" in path:
            data = {"objects": [IND], "more": False}
        else:
            data = {}
        b = json.dumps(data).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/taxii+json;version=2.1")
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)


def test_taxii_bridge_end_to_end(tmp_path, monkeypatch):
    srv = HTTPServer(("127.0.0.1", 0), _Taxii)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    monkeypatch.setenv("TX_URL", f"http://127.0.0.1:{srv.server_port}/api1/")
    monkeypatch.setenv("TX_TOKEN", "tok")
    spec = parse_connectors([{"name": "feeds", "roles": ["intel_platform"], "transport": "stdio", "command": "zarqa",
                              "args": ["bridge", "taxii", "--url", "${TX_URL}"], "env": {"BRIDGE_TOKEN": "${TX_TOKEN}"},
                              "timeout_sec": 10, "rate_per_min": 6000}])[0]
    hub = ConnectorHub([spec], AuditLog(tmp_path / "a.sqlite"), sleep=lambda s: None)
    try:
        r = hub.test("feeds")
        assert r["ok"] and r["probe"] == "list_collections", r
        assert {t["name"] for t in hub.tools_for_role("intel_platform")} >= {"list_collections", "find_indicator"}
        out = hub.call("feeds", "find_indicator", {"value": "203.0.113.9"})
        assert "203.0.113.9" in out["content"] and not out["is_error"]
        assert hub.audit.recent(limit=5)[0]["status"] == "ok"
    finally:
        hub.close()
        srv.shutdown()


def test_cli_has_bridges():
    import subprocess
    r = subprocess.run([sys.executable, "-m", "zarqa", "bridge", "--help"], capture_output=True, text=True)
    assert "taxii" in r.stdout and "openapi" in r.stdout and "web" in r.stdout


def test_connector_test_reports_source_errors(tmp_path):
    class Deny(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            self.send_response(401)
            self.end_headers()
    srv = HTTPServer(("127.0.0.1", 0), Deny)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    spec = parse_connectors([{"name": "feeds", "roles": ["intel_platform"], "transport": "stdio", "command": "zarqa",
                              "args": ["bridge", "taxii", "--url", f"http://127.0.0.1:{srv.server_port}/api1/"],
                              "timeout_sec": 10}])[0]
    hub = ConnectorHub([spec], AuditLog(tmp_path / "a.sqlite"), sleep=lambda s: None)
    try:
        r = hub.test("feeds")
        assert not r["ok"] and "401" in r["error"]
    finally:
        hub.close()
        srv.shutdown()


def test_fetch_assumes_utf8_without_a_charset(monkeypatch):
    import zarqa.collect.fetch as f
    monkeypatch.setattr(f, "_check_host", lambda url, allow: None)
    body = ("<html><title>Café " + chr(0x2013) + " login</title><body>ok</body></html>").encode()

    class R:
        status_code, headers, encoding = 200, {"Content-Type": "text/html"}, "ISO-8859-1"

        def iter_content(self, n):
            yield body

    class S:
        def get(self, url, **kw):
            return R()
    assert f.fetch_url("https://x.example/", session=S())["title"] == "Café " + chr(0x2013) + " login"
