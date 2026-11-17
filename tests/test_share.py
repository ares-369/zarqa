import base64
import json

import pytest

from tests.conftest import write_cfg
from tests.test_intel import MODEL_REPLY, REPORT, FakeLLM
from zarqa import config
from zarqa.collect.stix_in import import_bundle
from zarqa.connectors import parse_connectors
from zarqa.connectors.audit import AuditLog
from zarqa.connectors.hub import ConnectorHub
from zarqa.intel.pipeline import process
from zarqa.intel.store import KnowledgeStore, store_for
from zarqa.share import misp, push, stix_out


@pytest.fixture
def store(tmp_path):
    ks = KnowledgeStore(tmp_path / "k.sqlite")
    d = ks.add_document(source="lab", kind="url", text=REPORT, url="https://lab.example.org/post", title="Fancy Bear")
    process(ks, d["id"], llm=FakeLLM(MODEL_REPLY))
    return ks


def test_stix_document_export(store):
    b = stix_out.export(store, producer_name="Test", document_id=1)
    by = {}
    for o in b["objects"]:
        by.setdefault(o["type"], []).append(o)
    assert by["identity"][0]["name"] == "Test"
    pats = {o["pattern"] for o in by["indicator"]}
    assert "[ipv4-addr:value = '203.0.113.66']" in pats and "[domain-name:value = 'update-check.example-cdn.net']" in pats
    actor = by["intrusion-set"][0]
    assert actor["name"] == "APT28" and "Fancy Bear" in actor["aliases"]
    assert by["vulnerability"][0]["name"] == "CVE-2023-23397"
    assert by["attack-pattern"][0]["external_references"][0]["external_id"] == "T1566.001"
    rels = {(o["relationship_type"]) for o in by["relationship"]}
    assert {"uses", "communicates-with"} <= rels
    rep = by["report"][0]
    assert rep["external_references"][0]["url"] == "https://lab.example.org/post" and len(rep["object_refs"]) > 5
    ids = [o["id"] for o in b["objects"]]
    assert len(ids) == len(set(ids))
    again = stix_out.export(store, producer_name="Test", document_id=1)
    assert {o["id"] for o in again["objects"]} == set(ids)                      # stable ids
    # and Zarqa can read its own export back
    ks2 = KnowledgeStore(store.path.parent / "k2.sqlite")
    r = import_bundle(ks2, b, source="roundtrip")
    assert r["indicators"] >= 3 and r["relations"] >= 2 and ks2.find("actor", "APT28")


def test_store_export_skips_benign_everywhere(store):
    e = store.upsert_entity("domain", "good.example.org")
    d = store.add_document(source="m", kind="text", text="see good.example.org", title="t")
    store.add_mention(e["id"], d["id"], method="model", context="reference")
    b = stix_out.export(store)
    names = {o.get("name") for o in b["objects"]}
    assert "domain: good.example.org" not in names and "ipv4: 203.0.113.66" in names
    fp = store.find("ipv4", "203.0.113.66")
    store.set_status(fp["id"], "false_positive")
    assert "ipv4: 203.0.113.66" not in {o.get("name") for o in stix_out.export(store)["objects"]}


def test_misp_event(store):
    ev = misp.event(store, info="", document_id=1, producer="Test")["Event"]
    types = {(a["type"], a["value"]) for a in ev["Attribute"]}
    assert ("ip-dst", "203.0.113.66") in types and ("vulnerability", "CVE-2023-23397") in types
    assert ("link", "https://lab.example.org/post") in types
    assert next(a for a in ev["Attribute"] if a["type"] == "vulnerability")["to_ids"] is False
    tags = {t["name"] for t in ev["Tag"]}
    assert 'threat-actor:"APT28"' in tags and 'malware:"HeadLace"' in tags and ev["info"] == "Fancy Bear"


def test_push_through_sharing_connector(store):
    spec = parse_connectors([{"name": "out", "roles": ["sharing"], "transport": "stdio", "command": "x",
                              "allow_write": True, "tools": {"allow": ["add_bundle"]}}])[0]
    sent = []

    class C:
        def __init__(self, s):
            pass

        def list_tools(self):
            return [{"name": "add_bundle"}]

        def call_tool(self, name, args, timeout=None):
            sent.append(args)
            return {"content": [{"type": "text", "text": "accepted"}]}

        def close(self):
            pass
    hub = ConnectorHub([spec], AuditLog(store.path.parent / "a.sqlite"), sleep=lambda x: None, client_factory=C)
    cfg = type("C", (), {"raw": {"share": {"targets": [{"name": "plat", "connector": "out", "tool": "add_bundle",
                                                        "argument": "bundle", "arguments": {"collection": "c1"}}]}},
                         "instance_name": "Test"})()
    r = push.push(cfg, store, "plat", actor="alice", document_id=1, hub=hub)
    assert r["ok"] and r["items"] > 5 and sent[0]["collection"] == "c1" and sent[0]["bundle"]["type"] == "bundle"
    row = hub.audit.recent(limit=1)[0]
    assert row["status"] == "shared" and row["actor"] == "alice" and row["ref"] == "share:plat:document:1"
    with pytest.raises(ValueError):
        push.push(cfg, store, "plat", actor="", document_id=1, hub=hub)
    with pytest.raises(ValueError):
        push.push(cfg, store, "nope", actor="a", document_id=1, hub=hub)


def test_share_validation(home):
    write_cfg(home, lambda d: d.update(share={"targets": [{"name": "x", "connector": "c", "tool": "t"}]}))
    with pytest.raises(ValueError, match="argument"):
        config.load_config()


def _seed(home):
    cfg = config.get_config(reload=True)
    ks = store_for(cfg)
    d = ks.add_document(source="lab", kind="text", text=REPORT, title="r")
    process(ks, d["id"])
    return cfg


def test_taxii_server(home, monkeypatch):
    from zarqa.web import create_app
    write_cfg(home, lambda d: d.update(share={"taxii": False}))
    c = create_app(_seed(home)).test_client()
    assert c.get("/taxii2/").status_code == 404                                   # off by default
    write_cfg(home, lambda d: d.update(share={"taxii": True, "taxii_token_env": "TX"},
                                       auth={**d["auth"], "mode": "basic"}))
    monkeypatch.setenv("ZARQA_AUTH_PASSWORD", "pw")
    monkeypatch.setenv("TX", "secret-token")
    c = create_app(config.get_config(reload=True)).test_client()
    assert c.get("/taxii2/").status_code == 401
    h = {"Authorization": "Bearer secret-token"}
    assert c.get("/taxii2/", headers=h).headers["Content-Type"].startswith("application/taxii+json")
    cols = c.get("/taxii2/zarqa/collections/", headers=h).json["collections"]
    ind = next(x for x in cols if x["title"] == "Indicators")
    assert ind["can_write"] is False
    page = c.get(f"/taxii2/zarqa/collections/{ind['id']}/objects/?limit=2", headers=h).json
    assert page["more"] and len(page["objects"]) == 2
    rest = c.get(f"/taxii2/zarqa/collections/{ind['id']}/objects/?limit=500&next={page['next']}", headers=h).json
    assert not rest["more"] and all(o["type"] in ("indicator", "identity", "relationship") for o in rest["objects"])
    assert c.post(f"/taxii2/zarqa/collections/{ind['id']}/objects/", headers=h).status_code in (401, 405)
    assert c.get("/api/status", headers=h).status_code == 401                     # the token is for TAXII only


def test_export_api_and_mcp(home):
    from zarqa.web import create_app
    c = create_app(_seed(home)).test_client()
    b = c.get("/api/export/stix?document=1&download=1")
    assert b.status_code == 200 and "attachment" in b.headers["Content-Disposition"] and b.json["type"] == "bundle"
    assert c.get("/api/export/misp").status_code == 400
    assert c.get("/api/export/misp?document=1").json["Event"]["Attribute"]
    assert c.get("/api/export/stix?document=99").status_code == 404
    assert c.get("/api/share/targets").json == []
    rpc = lambda m, p=None: c.post("/mcp", json={"jsonrpc": "2.0", "id": 1, "method": m, "params": p or {}}).json  # noqa: E731
    names = {t["name"] for t in rpc("tools/list")["result"]["tools"]}
    assert {"lookup", "search_documents", "ask", "get_investigation", "export_stix", "brand_findings"} <= names
    assert "enrich" not in names
    r = rpc("tools/call", {"name": "lookup", "arguments": {"value": "203.0.113.66"}})["result"]
    assert "UNTRUSTED-DATA" in r["structuredContent"]["result"] and "203.0.113.66" in r["structuredContent"]["result"]


def test_mcp_token_is_viewer_by_default(home, monkeypatch):
    from zarqa.web import create_app
    write_cfg(home, lambda d: d.update(mcp={"token_env": "MT"}, auth={**d["auth"], "mode": "basic"}))
    monkeypatch.setenv("ZARQA_AUTH_PASSWORD", "pw")
    monkeypatch.setenv("MT", "t0ken")
    c = create_app(config.get_config(reload=True)).test_client()
    h = {"Authorization": "Bearer t0ken"}
    r = c.post("/mcp", headers=h, json={"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                                        "params": {"name": "ask", "arguments": {"question": "what about APT28?"}}}).json
    assert r["result"]["isError"] and "operator" in json.dumps(r)
    basic = {"Authorization": "Basic " + base64.b64encode(b"zarqa:pw").decode()}
    assert c.post("/mcp", headers=basic, json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"}).status_code == 200


def test_exports_carry_the_admiralty_rating(store):
    b = stix_out.export(store, producer_name="Test", document_id=1)
    ind = next(o for o in b["objects"] if o["type"] == "indicator")
    assert len(ind["x_zarqa_admiralty_rating"]) == 2 and isinstance(ind["confidence"], int)
    ev = misp.event(store, info="", document_id=1, producer="Test")["Event"]
    a = next(x for x in ev["Attribute"] if x["type"] == "ip-dst")
    names = {t["name"] for t in a["Tag"]}
    assert any(n.startswith("admiralty-scale:source-reliability=") for n in names)
    assert any(n.startswith("admiralty-scale:information-credibility=") for n in names)
