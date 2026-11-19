import base64
import json
import time

import pytest

from tests.conftest import write_cfg
from tests.test_intel import REPORT
from zarqa import config
from zarqa.intel import inventory as inv
from zarqa.intel.store import KnowledgeStore

CSV = """host,name,version,vendor
mail1,Microsoft Outlook (x64 en-us),16.0.1,Microsoft
mail2,Microsoft Outlook,16.0.2,Microsoft
web1,openssh-server,1:9.2p1-2,
web1,libssl3,3.0.11,
web1,less,590-2,
web1,python3-yaml,6.0,
web1,nginx-common,1.22,
"""

WAZUH_HITS = {"hits": {"total": {"value": 2}, "hits": [
    {"_source": {"agent": {"id": "001", "name": "pve1"}, "package": {"name": "pve-manager", "version": "9.2.1",
                                                                    "vendor": "Proxmox"}}},
    {"_source": {"agent": {"id": "002", "name": "pve2"}, "package": {"name": "pve-manager", "version": "9.2.0"}}}]}}


@pytest.fixture
def store(tmp_path):
    return KnowledgeStore(tmp_path / "k.sqlite")


def test_product_names():
    assert inv.product_name("openssh-server") == "OpenSSH"
    assert inv.product_name("libssl3") == "OpenSSL"
    assert inv.product_name("linux-image-6.1.0-18-amd64") == "Linux kernel"
    assert inv.product_name("postgresql-16") == "PostgreSQL"
    assert inv.product_name("Mozilla Firefox (x64 en-US)") == "Firefox"
    assert inv.product_name("Grafana Agent 0.39.1") == "Grafana Agent"
    assert inv.product_name("nginx-common") == "nginx"           # a noise suffix on a known product
    for noise in ("less", "python3-yaml", "libfoo1", "fonts-dejavu", "foo-doc", "tzdata", "KB5034441", ""):
        assert inv.product_name(noise) is None, noise


def test_parse_formats():
    rows = inv.parse(CSV)
    assert rows[0] == {"host": "mail1", "name": "Microsoft Outlook (x64 en-us)", "version": "16.0.1", "vendor": "Microsoft"}
    assert len(rows) == 7
    w = inv.parse(json.dumps(WAZUH_HITS))
    assert w[0] == {"host": "pve1", "name": "pve-manager", "version": "9.2.1", "vendor": "Proxmox"}
    api = inv.parse({"data": {"affected_items": [{"agent_id": "003", "name": "sudo", "version": "1.9"}]}})
    assert api == [{"host": "003", "name": "sudo", "version": "1.9", "vendor": ""}]
    mapped = inv.parse({"x": {"list": [{"m": {"h": "a"}, "sw": "Zoom"}]}}, fields={"host": "m.h", "name": "sw"},
                       rows="x.list")
    assert mapped == [{"host": "a", "name": "Zoom", "version": "", "vendor": ""}]
    assert inv.parse("host,name\n,nameless\nhostonly,\n") == []                     # incomplete rows skipped
    with pytest.raises(ValueError):
        inv.parse({"nothing": 1})


def test_snapshot_replaces_and_suggests(store):
    i = inv.Inventory(store)
    r = i.replace("cmdb", inv.parse(CSV))
    assert r == {"source": "cmdb", "rows": 7, "hosts": 3, "products": 4}
    prods = {p["product"]: p["hosts"] for p in i.products()}
    assert prods == {"Microsoft Outlook": ["mail1", "mail2"], "OpenSSH": ["web1"], "OpenSSL": ["web1"], "nginx": ["web1"]}
    i.replace("wazuh", inv.parse(WAZUH_HITS))
    i.replace("cmdb", inv.parse("host,name\nweb9,openssh-server\n"))               # a new snapshot replaces the old
    prods = {p["product"]: p["hosts"] for p in i.products()}
    assert prods == {"Proxmox VE": ["pve1", "pve2"], "OpenSSH": ["web9"]}
    hp = i.hosts_by_product()
    assert inv.matches("proxmox ve", hp) == ["pve1", "pve2"]
    assert inv.matches("Proxmox", hp) == ["pve1", "pve2"]                            # one is the other plus a word
    assert inv.matches("Outlook", hp) == []
    assert [s["product"] for s in inv.suggest(i, ["Proxmox"])] == ["OpenSSH"]
    assert i.clear("cmdb") == 1 and [s["source"] for s in i.sources()] == ["wazuh"]


def test_relevance_names_the_hosts(home):
    from zarqa.intel.relevance import score_document
    from zarqa.intel.service import process_documents
    from zarqa.intel.store import store_for
    write_cfg(home, lambda d: d.update(extract={"model": False}, default_sources={"enabled": False},
                                       organization={"products": ["Outlook"]}))
    cfg = config.get_config(reload=True)
    st = store_for(cfg)
    doc = st.add_document(source="m", kind="text", text=REPORT, title="r")["id"]
    process_documents(cfg, [doc], store=st)
    before = score_document(cfg, st, doc)
    assert not any(r.startswith("installed") for r in before["reasons"])
    inv.Inventory(st).replace("cmdb", inv.parse(CSV))
    after = score_document(cfg, st, doc)
    assert after["score"] == before["score"] + inv_weight()
    assert "installed: Outlook on 2 hosts (mail1, mail2)" in after["reasons"]


def inv_weight():
    from zarqa.intel.relevance import WEIGHTS
    return WEIGHTS["installed"]


class FakeHub:
    def __init__(self, payload, error=False):
        self.payload, self.error, self.calls = payload, error, []

    def call(self, name, tool, args, **kw):
        self.calls.append((name, tool, args))
        return {"content": f"<<UNTRUSTED-DATA {name}/{tool}>>\n{self.payload}\n<<END-UNTRUSTED-DATA {name}/{tool}>>",
                "is_error": self.error}


def test_pull_from_a_connector_and_schedule(home):
    from zarqa.intel.store import store_for
    write_cfg(home, lambda d: d.update(inventory={"from": {"connector": "siem", "tool": "search",
                                                           "arguments": {"index": "packages"}}, "source": "siem",
                                                  "every_hours": 24}))
    cfg = config.get_config(reload=True)
    st = store_for(cfg)
    assert inv.due(cfg, st)
    hub = FakeHub(json.dumps(WAZUH_HITS))
    r = inv.pull(cfg, st, hub=hub)
    assert r["hosts"] == 2 and hub.calls == [("siem", "search", {"index": "packages"})]
    assert not inv.due(cfg, st)
    with pytest.raises(ValueError):
        inv.pull(cfg, st, hub=FakeHub("denied", error=True))
    s = {x["source"]: x for x in inv.Inventory(st).sources()}["siem"]
    assert s["error"] and s["rows"] == 2                                             # the last good snapshot stays
    assert not inv.due(cfg, st)                                                      # a failure waits too


def test_inventory_config_is_checked(home):
    write_cfg(home, lambda d: d.update(inventory={"from": {"connector": "x"}}))
    with pytest.raises(ValueError, match=r"inventory\.from"):
        config.load_config()
    write_cfg(home, lambda d: d.update(inventory={"fields": {"owner": "a.b"}}))
    with pytest.raises(ValueError, match=r"inventory\.fields"):
        config.load_config()


def _wait(jobs, jid):
    end = time.time() + 10
    while time.time() < end and jobs.get(jid)["status"] in ("queued", "running"):
        time.sleep(0.05)
    return jobs.get(jid)


def test_inventory_api(home, monkeypatch):
    from zarqa.web import create_app
    write_cfg(home, lambda d: d.update(organization={"products": ["Outlook", "Fortinet"]}, default_sources={"enabled": False}))
    app = create_app(config.get_config(reload=True))
    c = app.test_client()
    assert c.post("/api/settings/inventory", json={"content": "nothing,here\n1,2\n"}).status_code == 400
    r = c.post("/api/settings/inventory", json={"source": "my cmdb!", "content": CSV}).json
    assert r["rows"] == 7 and r["source"] == "my-cmdb-"
    assert _wait(app.extensions["zarqa_jobs"], r["job_id"])["status"] == "done"
    j = c.get("/api/inventory").json
    assert j["profile"] == [{"product": "Outlook", "hosts": ["mail1", "mail2"]}, {"product": "Fortinet", "hosts": []}]
    assert {s["product"] for s in j["suggestions"]} == {"OpenSSH", "OpenSSL", "nginx"}
    assert c.post("/api/settings/inventory/pull").status_code == 400                # no connector configured
    assert c.post("/api/settings/inventory/clear", json={}).json["removed"] == 7


def test_only_admins_change_the_inventory(home, monkeypatch):
    from zarqa.web import create_app
    write_cfg(home, lambda d: d["auth"].update(mode="basic", default_role="operator"))
    monkeypatch.setenv("ZARQA_AUTH_PASSWORD", "pw")
    c = create_app(config.load_config()).test_client()
    h = {"Authorization": "Basic " + base64.b64encode(b"zarqa:pw").decode()}
    for path in ("/api/settings/inventory", "/api/settings/inventory/pull", "/api/settings/inventory/clear"):
        assert c.post(path, json={"content": CSV}, headers=h).status_code == 403, path
    assert c.get("/api/inventory", headers=h).status_code == 200


def test_suggestions_are_known_or_named_in_reports(store):
    i = inv.Inventory(store)
    i.replace("cmdb", inv.parse("host,name\na,openssh-server\na,acme-widgetd\na,obscure-thing\nb,obscure-thing\n"))
    assert [s["product"] for s in inv.suggest(i, [])] == ["OpenSSH"]                # well known, no report needed
    store.add_document(source="m", kind="text", text="Attackers abused acme-widgetd on exposed servers.", title="t")
    s = inv.suggest(i, [])
    assert [x["product"] for x in s] == ["acme-widgetd", "OpenSSH"] and s[0]["reports"] == 1
    assert {x["product"] for x in inv.suggest(i, [], everything=True)} == {"acme-widgetd", "OpenSSH", "obscure-thing"}
