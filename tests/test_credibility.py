import pytest

from tests.conftest import write_cfg
from zarqa import config
from zarqa.intel.credibility import assess, rate, refresh
from zarqa.intel.store import KnowledgeStore


def test_rate_scale():
    assert rate("ipv4", [])["rating"] == "F6"
    one = rate("ipv4", [("feed-a", "C", "malicious")])
    assert one["rating"] == "C3" and one["confidence"] == 60
    three = rate("ipv4", [("a", "B", "malicious"), ("b", "D", ""), ("c", "F", "malicious"), ("a", "B", "")])
    assert three["rating"] == "B1" and three["confidence"] == 95 and three["sources"] == 3
    split = rate("domain", [("a", "B", "malicious"), ("b", "C", "reference")])
    assert split["rating"] == "B4" and split["contradicted"] and split["confidence"] == 50
    benign = rate("domain", [("a", "A", "benign"), ("b", "B", "reference")])
    assert benign["credibility"] == 5 and benign["confidence"] == 10
    unrated = rate("ipv4", [("a", "F", "")])
    assert unrated["rating"] == "F3" and unrated["confidence"] == 50
    named = rate("actor", [("a", "C", ""), ("b", "C", "")])      # names have no roles: sources only
    assert named["rating"] == "C2" and named["confidence"] == 70


def test_corroboration_raises_confidence_in_the_store(tmp_path):
    st = KnowledgeStore(tmp_path / "k.sqlite")
    e = st.upsert_entity("ipv4", "203.0.113.50")
    for i, (src, rel) in enumerate((("feed-a", "C"), ("feed-b", "B"), ("feed-c", "D"))):
        d = st.add_document(source=src, kind="feed", text=f"report {i} 203.0.113.50", title=src, reliability=rel)
        st.add_mention(e["id"], d["id"], method="rules", context="malicious")
        refresh(st, [e["id"]])
    got = st.entity(e["id"])
    assert got["rating"] == "B1" and got["confidence"] == 95
    assert assess(st, e["id"])["sources"] == 3


def test_source_reliability_is_validated_and_used(home):
    from zarqa.collect.collector import Collector
    write_cfg(home, lambda d: d.update(sources=[{"name": "x", "url": "https://x.example/f", "reliability": "Z"}]))
    with pytest.raises(ValueError, match="reliability"):
        config.load_config()
    write_cfg(home, lambda d: d.update(sources=[], collect={"manual_reliability": "B"}))
    cfg = config.load_config()
    from zarqa.intel.store import store_for
    st = store_for(cfg)
    r = Collector(cfg, st).add_values(["203.0.113.60"])
    assert r["values"] == 1
    e = st.find("ipv4", "203.0.113.60")
    assert e["rating"] == "B3" and e["confidence"] == 75
