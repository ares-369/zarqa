from zarqa.intel.rule_relations import find_relations

E = [{"id": 1, "type": "actor", "surfaces": ["APT28", "Fancy Bear"]},
     {"id": 2, "type": "cve", "surfaces": ["CVE-2023-23397"]},
     {"id": 3, "type": "malware", "surfaces": ["HeadLace"]},
     {"id": 4, "type": "ipv4", "surfaces": ["203.0.113.66"]},
     {"id": 5, "type": "tool", "surfaces": ["Cobalt Strike"]}]


def rels(text):
    return {(r["src"], r["rel"], r["dst"]) for r in find_relations(text, E)}


def test_stated_relations():
    t = ("Fancy Bear exploited CVE-2023-23397 in Outlook. The group then deployed HeadLace. "
         "HeadLace beaconed to 203.0.113.66 every hour. HeadLace later dropped Cobalt Strike.")
    assert rels(t) == {(1, "exploits", 2), (3, "communicates_with", 4), (3, "drops", 5)}


def test_no_relation_without_a_verb_or_with_negation_or_wrong_types():
    assert rels("APT28 and CVE-2023-23397 were both in the news.") == set()
    assert rels("There is no evidence that APT28 exploited CVE-2023-23397.") == set()
    assert rels("203.0.113.66 contacted HeadLace.") == set()                # an address does not contact malware
    assert rels("APT28 deployed HeadLace.") == {(1, "uses", 3)}


def test_quote_is_the_sentence():
    r = find_relations("Intro. APT28 exploited CVE-2023-23397 widely. Outro.", E)
    assert r[0]["quote"] == "APT28 exploited CVE-2023-23397 widely."
