import base64
import time

from tests.conftest import write_cfg
from tests.test_intel import REPORT
from zarqa import config
from zarqa.intel.relevance import clean_profile


def test_clean_profile_tidies_lists_and_names():
    org, reqs = clean_profile({"organization": {"name": "  Ex Org ", "products": "VPN Appliance\n\nvpn appliance\nMail",
                                                "domains": ["Example.COM.", "a.example, b.example"], "sectors": []},
                               "requirements": [{"name": "VPN Exploitation!", "question": "Is it?", "terms": ["vpn", " VPN "]},
                                                {"name": "", "terms": []}]})
    assert org == {"name": "Ex Org", "products": ["VPN Appliance", "Mail"],
                   "domains": ["example.com", "a.example", "b.example"]}
    assert reqs == [{"name": "vpn-exploitation", "question": "Is it?", "terms": ["vpn"]}]


def _wait(jobs, jid):
    end = time.time() + 10
    while time.time() < end and jobs.get(jid)["status"] in ("queued", "running"):
        time.sleep(0.05)
    return jobs.get(jid)


def test_save_profile_rescores_and_filters(home):
    from zarqa.intel.service import process_documents
    from zarqa.intel.store import store_for
    from zarqa.web import create_app
    write_cfg(home, lambda d: d.update(extract={"model": False}, default_sources={"enabled": False}))
    cfg = config.get_config(reload=True)
    st = store_for(cfg)
    hit = st.add_document(source="m", kind="text", text=REPORT, title="relevant")["id"]
    miss = st.add_document(source="m", kind="text", text="A football club changed its kit sponsor.", title="noise")["id"]
    process_documents(cfg, [hit, miss], store=st)
    assert st.document(hit)["relevance"] is None                                     # no profile yet
    app = create_app(cfg)
    c = app.test_client()
    assert c.get("/api/profile").json["set"] is False
    r = c.post("/api/settings/profile", json={"organization": {"sectors": ["energy"], "products": ["Outlook"]},
                                             "requirements": [{"name": "phishing", "question": "Who phishes us?",
                                                               "terms": ["spearphishing"]}]}).json
    assert r["set"] and r["products"] == ["Outlook"] and r["requirements"][0]["name"] == "phishing"
    assert _wait(app.extensions["zarqa_jobs"], r["job_id"])["status"] == "done"
    assert st.document(hit)["relevance"] >= 30 and st.document(miss)["relevance"] == 0
    shown = [d["id"] for d in c.get("/api/documents?min_relevance=30").json]
    assert shown == [hit]
    saved = config.load_config().raw
    assert saved["organization"]["sectors"] == ["energy"] and saved["requirements"][0]["terms"] == ["spearphishing"]
    bad = c.post("/api/settings/profile", json={"requirements": [{"name": "a", "terms": ["x"]}, {"name": "a", "terms": ["y"]}]})
    assert bad.status_code == 400 and "duplicate" in bad.json["error"]


def test_only_admins_save_the_profile(home, monkeypatch):
    from zarqa.web import create_app
    write_cfg(home, lambda d: d["auth"].update(mode="basic", default_role="operator"))
    monkeypatch.setenv("ZARQA_AUTH_PASSWORD", "pw")
    c = create_app(config.load_config()).test_client()
    h = {"Authorization": "Basic " + base64.b64encode(b"zarqa:pw").decode()}
    assert c.post("/api/settings/profile", json={"organization": {"products": ["x"]}}, headers=h).status_code == 403
    assert c.get("/api/profile", headers=h).status_code == 200
