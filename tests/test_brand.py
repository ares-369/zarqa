import json

import pytest

from tests.conftest import write_cfg
from zarqa import config
from zarqa.brand import watch
from zarqa.brand.permute import permutations, registered_part, similarity, split
from zarqa.intel.store import KnowledgeStore


def test_permutations_cover_the_techniques():
    p = dict(permutations("examplebank.com"))
    assert "examplebank.com" not in p
    for cand, tech in (("exampelbank.com", "transposition"), ("exmplebank.com", "omission"),
                       ("examp1ebank.com", "homoglyph"), ("exarnplebank.com", "homoglyph"),
                       ("examplebank-login.com", "word"), ("examplebank.net", "tld"), ("example-bank.com", "hyphen")):
        assert p.get(cand) == tech, cand
    assert all(c.count("--") == 0 and c == c.lower() for c in p)
    assert len(permutations("examplebank.com", limit=10)) == 10


def test_split_and_similarity():
    assert split("shop.example.co.uk") == ("shop.example", "co.uk") and split("example.com") == ("example", "com")
    assert registered_part("a.b.example.com") == "example.com"
    assert similarity("examp1e.com", "example.com") > 80 and similarity("totally.com", "example.com") < 40


def test_score_signals():
    base = watch.score("homoglyph", 90, {})
    hot = watch.score("homoglyph", 90, {"mx": ["mx.x"], "rdap": {"age_days": 3},
                                        "page": {"shows_brand": ["example"], "asks_password": True}})
    assert hot > base and hot == 100


def cfg_with(home, brand=None, org=None):
    write_cfg(home, lambda d: d.update(brand=brand or {}, organization=org or {}))
    return config.load_config()


def test_settings_default_to_organization(home):
    s = watch.settings(cfg_with(home, org={"domains": ["examplebank.com"], "brands": ["Example Bank"]}))
    assert s["watch"] == [{"domain": "examplebank.com", "names": ["Example Bank"]}]
    s = watch.settings(cfg_with(home, brand={"watch": [{"domain": "x.com"}]}, org={"domains": ["examplebank.com"]}))
    assert s["watch"] == [{"domain": "x.com", "names": ["x"]}]
    write_cfg(home, lambda d: d.update(brand={"watch": [{"names": ["x"]}]}))
    with pytest.raises(ValueError, match=r"brand\.watch"):
        config.load_config()


def test_run(home, tmp_path):
    cfg = cfg_with(home, brand={"watch": [{"domain": "examplebank.com", "names": ["examplebank", "Example Bank"]}],
                                "ignore": ["examplebank.net"]})
    live = {"examp1ebank.com": {"ips": ["203.0.113.80"], "mx": ["mx.examp1ebank.com"]},
            "examplebank-login.com": {"ips": ["203.0.113.81"], "mx": []},
            "examplebank.net": {"ips": ["203.0.113.82"], "mx": []}}

    def resolver(name):
        return live.get(name, {"ips": [], "mx": []})

    def fetch(url, **kw):
        if "examplebank-login.com" in url:
            return {"url": url, "title": "Example Bank sign in", "text": "Welcome to Example Bank. Password:"}
        raise ValueError("connection refused")
    ages = {"examp1ebank.com": 400, "examplebank-login.com": 2}
    bs = watch.BrandStore(tmp_path / "b.sqlite")
    ks = KnowledgeStore(tmp_path / "k.sqlite")
    r = watch.run(cfg, bstore=bs, kstore=ks, resolver=resolver, fetch=fetch,
                  rdap_fn=lambda d: {"age_days": ages[d], "registrar": "R"})
    assert r["resolving"] == 2 and r["new"] == 2 and not r["errors"]               # the ignored one is skipped
    f = {x["domain"]: x for x in bs.findings()}
    login = f["examplebank-login.com"]
    assert login["evidence"]["page"]["asks_password"] and login["evidence"]["page"]["shows_brand"] == ["Example Bank"]
    assert login["score"] > f["examp1ebank.com"]["score"] and bs.findings()[0]["domain"] == "examplebank-login.com"
    assert "error" in f["examp1ebank.com"]["evidence"]["page"]
    e = ks.find("domain", "examplebank-login.com")
    assert "lookalike:examplebank.com" in e["tags"]
    # second run: nothing new; a lookalike that stopped resolving is marked
    live.pop("examp1ebank.com")
    r2 = watch.run(cfg, bstore=bs, kstore=ks, resolver=resolver, fetch=fetch, rdap_fn=lambda d: {"age_days": 2})
    assert r2["new"] == 0
    assert not {x["domain"]: x for x in bs.findings()}["examp1ebank.com"]["resolves"]
    bs.set_status(login["id"], "takedown", "reported", "alice")
    assert bs.findings(status="takedown")[0]["updated_by"] == "alice"
    with pytest.raises(ValueError):
        bs.set_status(login["id"], "nuke", "", "x")


def test_redirect_to_own_domain_scores_low():
    assert watch.score("homoglyph", 95, {"redirects_to_you": True, "page": {"shows_brand": ["x"]}}) == 5


def test_parked_page_does_not_count_as_brand_use():
    def fetch(url, **kw):
        return {"url": url, "title": "paypa1-example.com for sale", "text": "paypa1-example.com is for sale. Make an offer."}
    p = watch.page_check("paypa1-example.com", ["paypa1-example"], fetch)
    assert p["parked"] and p["shows_brand"] == []
    assert watch.score("homoglyph", 90, {"page": p}) == watch.score("homoglyph", 90, {})


def test_ct_names():
    rows = [{"name_value": "*.examplebank-secure.com\nexamplebank-secure.com"}, {"name_value": "other.com"}]
    names = watch.ct_names("examplebank", lambda url, **kw: {"raw": json.dumps(rows), "text": ""})
    assert names == ["examplebank-secure.com"]


def test_nothing_to_watch(home):
    r = watch.run(cfg_with(home), resolver=lambda n: {"ips": [], "mx": []})
    assert r["errors"] and not watch.due(cfg_with(home), watch.store_for(cfg_with(home)))


def test_api(home):
    from zarqa.web import create_app
    c = create_app(cfg_with(home, org={"domains": ["examplebank.com"]})).test_client()
    j = c.get("/api/brand").json
    assert j["watch"][0]["domain"] == "examplebank.com" and j["findings"] == []
    assert c.post("/api/brand/1/status", json={"status": "bad"}).status_code == 400
