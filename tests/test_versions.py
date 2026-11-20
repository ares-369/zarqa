from zarqa.intel import inventory as inv
from zarqa.intel.relevance import rules_score
from zarqa.intel.store import KnowledgeStore
from zarqa.intel.versions import affected_ranges, in_range, key, upstream


def test_upstream_and_order():
    assert upstream("1:9.2p1-2+deb12u3") == "9.2p1" and upstream("3.0.11-1~deb12u2") == "3.0.11"
    assert upstream("16.0.1") == "16.0.1"
    assert key("9.10") > key("9.9") and key("9.2p1") > key("9.2") and key("10.0p1") > key("9.8")


def test_stated_ranges():
    t = ("OpenSSH before 9.8 is affected. The flaw was fixed in OpenSSH 9.8p1. nginx versions 1.25.0 through "
         "1.25.3 are vulnerable. Grafana 10.2.2 and earlier too. CVE-2023-23397 in Outlook was exploited.")
    assert ("lt", "9.8") in affected_ranges(t, ["OpenSSH"]) and ("lt", "9.8p1") in affected_ranges(t, ["OpenSSH"])
    assert affected_ranges(t, ["nginx"]) == [("range", "1.25.0", "1.25.3")]
    assert affected_ranges(t, ["Grafana"]) == [("le", "10.2.2")]
    assert affected_ranges(t, ["Outlook"]) == []                    # a CVE ID is not a version range
    r = affected_ranges(t, ["OpenSSH"])
    assert in_range("1:9.2p1-2+deb12u3", r) is True and in_range("1:10.0p1-7", r) is False
    assert in_range("", r) is None and in_range("9.0", []) is None
    assert in_range("1.25.2-1", affected_ranges(t, ["nginx"])) and not in_range("1.26.0", affected_ranges(t, ["nginx"]))


def _profile(store, products):
    i = inv.Inventory(store)
    return {"products": products, "brands": [], "domains": [], "sectors": [], "regions": [], "requirements": [],
            "assets": i.hosts_by_product(), "asset_versions": i.versions_by_product()}


def test_relevance_names_hosts_in_the_stated_range(tmp_path):
    st = KnowledgeStore(tmp_path / "k.sqlite")
    inv.Inventory(st).replace("cmdb", inv.parse("host,name,version\nweb1,openssh-server,1:9.2p1-2\n"
                                                "web2,openssh-server,1:10.0p1-7\n"))
    p = _profile(st, ["OpenSSH"])
    hit = rules_score(p, {"title": "t", "text": "OpenSSH before 9.8 lets attackers in."}, [], {})
    assert any("affected range" in r and "web1 1:9.2p1-2" in r and "web2" not in r for r in hit["reasons"])
    safe = rules_score(p, {"title": "t", "text": "OpenSSH before 8.0 lets attackers in."}, [], {})
    assert any("outside the affected range" in r for r in safe["reasons"])
    plain = rules_score(p, {"title": "t", "text": "OpenSSH is widely used."}, [], {})
    assert hit["score"] > plain["score"] > safe["score"]
