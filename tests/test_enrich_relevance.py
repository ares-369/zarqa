import json

import pytest

from tests.conftest import write_cfg
from tests.test_intel import REPORT, FakeLLM
from zarqa import config
from zarqa.connectors import parse_connectors
from zarqa.intel import enrich as en
from zarqa.intel import relevance as rel
from zarqa.intel.pipeline import process
from zarqa.intel.store import KnowledgeStore


@pytest.fixture
def store(tmp_path):
    return KnowledgeStore(tmp_path / "intel.sqlite")


def cfg_with(**raw):
    return type("C", (), {"raw": raw, "data_dir": None})()


# ---- enrichment ----
def test_enrich_spec_validation():
    s = parse_connectors([{"name": "rep", "roles": ["enrichment"], "transport": "stdio", "command": "x",
                           "enrich": [{"types": ["ipv4"], "tool": "lookup_ip", "argument": "ip"}]}])[0]
    assert s.enrich[0]["tool"] == "lookup_ip" and s.public()["enrich"] == [{"types": ["ipv4"], "tool": "lookup_ip"}]
    for bad in ([{"types": ["planet"], "tool": "t", "argument": "a"}], [{"types": ["ipv4"], "tool": "t"}]):
        with pytest.raises(ValueError):
            parse_connectors([{"name": "rep", "roles": ["enrichment"], "transport": "stdio", "command": "x", "enrich": bad}])
    with pytest.raises(ValueError):
        en.validate({"builtin": {"shodan": True}})


class Hub:
    def __init__(self, specs, reply="ip 203.0.113.9: hosting provider, seen scanning"):
        self.specs = {s.name: s for s in specs}
        self.reply, self.calls = reply, []

    def call(self, name, tool, args, **kw):
        self.calls.append((name, tool, args, kw))
        return {"content": f"<<UNTRUSTED-DATA ab source={name}/{tool}>>\n{self.reply}\n<<END-UNTRUSTED-DATA ab>>",
                "is_error": False}


def test_connector_enrichment_and_cache(store):
    spec = parse_connectors([{"name": "rep", "roles": ["enrichment"], "transport": "stdio", "command": "x",
                              "enrich": [{"types": ["ipv4"], "tool": "lookup_ip", "argument": "ip",
                                          "arguments": {"days": 30}}]}])[0]
    hub = Hub([spec])
    e = store.upsert_entity("ipv4", "203.0.113.9")
    r = en.enrich(cfg_with(), store, e["id"], hub=hub, actor="alice")
    assert r == [{"enricher": "rep/lookup_ip", "ok": True, "summary": "ip 203.0.113.9: hosting provider, seen scanning"}]
    assert hub.calls[0][2] == {"days": 30, "ip": "203.0.113.9"} and hub.calls[0][3]["ref"] == f"entity:{e['id']}"
    assert en.enrich(cfg_with(), store, e["id"], hub=hub)[0]["cached"]                 # reused
    assert len(hub.calls) == 1
    en.enrich(cfg_with(), store, e["id"], hub=hub, force=True)
    assert len(hub.calls) == 2
    assert en.Results(store).for_entity(e["id"])[0]["actor"] == "enrich"
    d = store.upsert_entity("domain", "bad.example.net")
    assert en.enrich(cfg_with(), store, d["id"], hub=hub) == []                       # no enricher for domains


def test_builtin_epss_and_rdap(store):
    pages = {
        "https://api.first.org/data/v1/epss?cve=CVE-2023-23397":
            {"data": [{"cve": "CVE-2023-23397", "epss": "0.93", "percentile": "0.995", "date": "2026-11-15"}]},
        "https://rdap.org/domain/bad.example.net":
            {"handle": "D1", "ldhName": "bad.example.net", "events": [{"eventAction": "registration",
                                                                     "eventDate": "2026-11-01T00:00:00Z"}],
             "entities": [{"roles": ["registrar"], "vcardArray": ["vcard", [["fn", {}, "text", "Example Registrar"]]]}]},
    }
    asked = []

    def fetch(url, **kw):
        asked.append(url)
        return {"raw": json.dumps(pages[url]), "text": ""}
    cfg = cfg_with(enrich={"builtin": {"epss": True, "rdap": True}}, organization={"domains": ["example.org"]},
                   privacy={"terms": ["corp-internal"]})
    c = store.upsert_entity("cve", "CVE-2023-23397")
    r = en.enrich(cfg, store, c["id"], hub=Hub([]), fetch=fetch)
    assert r[0]["enricher"] == "epss" and "0.930" in r[0]["summary"]
    assert "epss-top10" in store.entity(c["id"])["tags"] and store.entity(c["id"])["seen_count"] == 1
    d = store.upsert_entity("domain", "bad.example.net")
    r = en.enrich(cfg, store, d["id"], hub=Hub([]), fetch=fetch)
    data = en.Results(store).for_entity(d["id"])[0]["data"]
    assert r[0]["ok"] and data["registrar"] == "Example Registrar" and data["age_days"] >= 0
    own = store.upsert_entity("domain", "mail.example.org")
    r = en.enrich(cfg, store, own["id"], hub=Hub([]), fetch=fetch)
    assert not r[0]["ok"] and "not sent" in r[0]["summary"] and len(asked) == 2      # never left the machine
    assert en.private_value(cfg, "10.1.2.3") and en.private_value(cfg, "vpn.corp-internal.example")


def test_failing_enricher_is_recorded(store):
    def fetch(url, **kw):
        raise ValueError("HTTP 500")
    c = store.upsert_entity("cve", "CVE-2023-23397")
    r = en.enrich(cfg_with(enrich={"builtin": {"epss": True}}), store, c["id"], hub=Hub([]), fetch=fetch)
    assert r == [{"enricher": "epss", "ok": False, "summary": "HTTP 500"}]


def test_auto_candidates_respect_switch_and_cap(store):
    d = store.add_document(source="s", kind="text", text="x 203.0.113.9", title="t")
    e = store.upsert_entity("ipv4", "203.0.113.9")
    store.add_mention(e["id"], d["id"], method="rules", context="malicious")
    assert en.auto_candidates(store, cfg_with(), d["id"]) == []
    cfg = cfg_with(enrich={"auto": True, "max_per_day": 1})
    assert en.auto_candidates(store, cfg, d["id"]) == [e["id"]]
    en.Results(store).add(e["id"], "x", ok=True, summary="s", data={}, actor="auto")
    assert en.auto_candidates(store, cfg, d["id"]) == []                              # done, and the cap is used


# ---- relevance ----
PROFILE = {"organization": {"name": "Example Utility", "sectors": ["energy"], "regions": ["Poland"],
                            "products": ["Outlook"], "brands": ["exampleutil"], "domains": ["exampleutil.com"]},
           "requirements": [{"name": "phishing", "question": "Who phishes us?", "terms": ["spearphishing"]}]}


def _doc(store, text=REPORT):
    d = store.add_document(source="manual", kind="text", text=text, title="r")
    process(store, d["id"])
    return d["id"]


def test_no_profile_means_no_score(store):
    r = rel.score_document(cfg_with(), store, _doc(store))
    assert r["score"] is None and store.document(1)["relevance"] is None


def test_rules_score_with_reasons(store):
    did = _doc(store)
    kev = store.find("cve", "CVE-2023-23397")
    store.add_tags(kev["id"], ["kev"])
    r = rel.score_document(cfg_with(**PROFILE), store, did)
    text = "; ".join(r["reasons"])
    assert "product Outlook" in text and "sector energy" in text and "region Poland" in text
    assert "known exploited: CVE-2023-23397" in text and "requirement phishing" in text
    assert r["requirements"] == ["phishing"] and r["score"] >= 70
    d = store.document(did)
    assert d["relevance"] == r["score"] and "pir:phishing" in d["tags"]
    other = _doc(store, "A football club changed its kit sponsor this week.")
    assert rel.score_document(cfg_with(**PROFILE), store, other)["score"] == 0
    assert store.documents(order="relevance")[0]["id"] == did
    assert [x["id"] for x in store.documents(tag="pir:phishing")] == [did]


def test_lists_are_not_scored(store):
    d = store.add_document(source="kev", kind="list", text="Indicator list kev\nCVE-2023-23397", title="kev")
    store.update_document(d["id"], relevance=20)
    assert rel.score_document(cfg_with(**PROFILE), store, d["id"])["score"] is None
    assert store.document(d["id"])["relevance"] is None                                # a stale score is cleared


def test_targeted_sector_counts_more(store):
    did = store.add_document(source="m", kind="text", text="Energy companies were attacked.", title="t")["id"]
    process(store, did, llm=FakeLLM({"items": [{"type": "sector", "name": "Energy",
                                                "quote": "Energy companies were attacked"}]}))
    r = rel.score_document(cfg_with(**PROFILE), store, did)
    assert any("targets your sector" in x for x in r["reasons"])


def test_model_relevance_only_when_rules_found_something(store):
    llm = FakeLLM({"score": 88, "why": "Phishing against Polish energy firms using Outlook flaws.",
                   "requirements": ["phishing", "made-up"]})
    cfg = cfg_with(**PROFILE, relevance={"model": True})
    r = rel.score_document(cfg, store, _doc(store), llm=llm)
    assert r["score"] == 88 and r["method"] == "rules+model" and r["reasons"][0].startswith("model:")
    assert r["requirements"] == ["phishing"] and llm.calls[0][0] == "analyst"
    n = len(llm.calls)
    rel.score_document(cfg, store, _doc(store, "Nothing about anyone here at all."), llm=llm)
    assert len(llm.calls) == n                                                         # nothing matched: no call


def test_requirements_validation(home):
    write_cfg(home, lambda d: d.update(requirements=[{"name": "Bad Name", "terms": ["x"]}]))
    with pytest.raises(ValueError, match="requirements"):
        config.load_config()
    write_cfg(home, lambda d: d.update(requirements=[{"name": "ok", "terms": []}]))
    with pytest.raises(ValueError, match="at least one term"):
        config.load_config()


def test_api(home):
    from zarqa.web import create_app
    write_cfg(home, lambda d: d.update(extract={"model": False}, **PROFILE))
    c = create_app(config.get_config(reload=True)).test_client()
    assert c.get("/api/profile").json["set"]
    from zarqa.intel.service import process_documents
    from zarqa.intel.store import store_for
    st = store_for(config.get_config())
    did = st.add_document(source="manual", kind="text", text=REPORT, title="r")["id"]
    out = process_documents(config.get_config(), [did], store=st)
    assert out[0]["relevance"]["score"] > 0                                            # scored after extraction
    assert c.get("/api/documents?order=relevance").json[0]["id"] == did
    assert c.post(f"/api/documents/{did}/relevance").json["score"] > 0
    eid = st.find("cve", "CVE-2023-23397")["id"]
    j = c.get(f"/api/entities/{eid}").json
    assert j["enrichers"] == [] and j["enrichments"] == []
    assert c.post(f"/api/entities/{eid}/enrich", json={}).json["job_id"]


def test_requirement_needs_more_than_a_passing_mention():
    from zarqa.intel.relevance import rules_score
    p = {"products": [], "brands": [], "domains": [], "sectors": [], "regions": [], "assets": {},
         "requirements": [{"name": "ransomware", "question": "", "terms": ["ransomware"]}]}
    body = "Vendor adds passkey support for Windows. " + "Details about the feature. " * 60
    once_deep = {"title": "Vendor adds passkeys", "text": body + " Menu: Ransomware (7)"}
    twice = {"title": "Weekly notes", "text": body + " ransomware here. And ransomware there."}
    in_title = {"title": "Ransomware gang arrested", "text": body}
    assert rules_score(p, once_deep, [], {})["requirements"] == []
    assert rules_score(p, twice, [], {})["requirements"] == ["ransomware"]
    assert rules_score(p, in_title, [], {})["requirements"] == ["ransomware"]
