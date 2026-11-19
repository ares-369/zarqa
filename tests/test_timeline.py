import sqlite3

import pytest

from tests.test_intel import MODEL_REPLY, REPORT, FakeLLM
from zarqa.intel.pipeline import process
from zarqa.intel.store import KnowledgeStore
from zarqa.intel.timeline import basis_of, date_in, observed_of, published_date, timeline


@pytest.fixture
def store(tmp_path):
    return KnowledgeStore(tmp_path / "k.sqlite")


def test_dates_in_text():
    assert date_in("The intrusion began on 2024-03-12 and lasted weeks.") == "2024-03-12"
    assert date_in("Seen on 12 March 2024 at two sites.") == "2024-03-12"
    assert date_in("Since March 12th, 2024 the group ...") == "2024-03-12"
    assert date_in("A wave in Sept. 2023 hit Poland.") == "2023-09"
    assert date_in("Active since 2019.") == "2019"
    assert date_in("They sent 2024 emails.") == ""                       # a bare number is not a date
    assert date_in("In March 2024, and again on 2024-06-01") == "2024-06-01"   # a full date beats a month
    assert date_in("on 2024-02-30") == "" and date_in("in 1850") == ""
    assert published_date("Tue, 05 Nov 2024 10:00:00 GMT") == "2024-11-05"
    assert published_date("2024-11-05T10:00:00Z") == "2024-11-05"
    assert published_date("someday") == ""
    assert observed_of("no date here", "2024-11-05") == ("2024-11-05", "published")
    assert observed_of("in May 2023", "2024-11-05") == ("2023-05", "text")
    assert observed_of("", "") == ("", "")


def test_stated_or_inferred():
    assert basis_of("exploits", "model", "The actor exploited CVE-2023-23397 in Outlook") == "stated"
    assert basis_of("uses", "model", "Fancy Bear and HeadLace appeared in the same campaign") == "inferred"
    assert basis_of("communicates_with", "model", "HeadLace contacted 203.0.113.66") == "stated"
    assert basis_of("related_to", "stix", "") == "stated"                 # a platform's relationship object
    assert basis_of("attributed_to", "model", "The group tracked as Fancy Bear") == "stated"


def test_relations_carry_basis_and_dates(store):
    d = store.add_document(source="lab", kind="text", text=REPORT, title="r", published="2024-11-05T08:00:00Z")
    process(store, d["id"], llm=FakeLLM(MODEL_REPLY))
    rels = store.relations(document_id=d["id"])
    assert rels and all(r["basis"] in ("stated", "inferred") for r in rels)
    assert all(r["observed"] == "2024-11-05" and r["observed_from"] == "published" for r in rels)
    assert all(r["created"] for r in rels)
    actor = store.find("actor", "APT28")
    t = timeline(store, actor["id"])
    assert t["entity"]["display"] == "APT28" and t["documents"] == 1
    assert t["first_reported"] == "2024-11-05" and t["stated"] + t["inferred"] == len([x for x in t["events"]
                                                                                     if x["kind"] == "relation"])
    other = store.add_document(source="news", kind="text", text="In May 2023 APT28 was named by a news site.",
                               title="news")
    process(store, other["id"])
    t = timeline(store, actor["id"])
    m = [x for x in t["events"] if x["kind"] == "mention"]
    assert m and m[0]["document_id"] == other["id"] and t["first_reported"] in ("2023-05", "2024-11-05")
    assert t["events"][0]["date"] >= t["events"][-1]["date"]               # newest first


@pytest.mark.skipif(bool(__import__("os").getenv("ZARQA_DB_URL")), reason="rewrites a SQLite file directly")
def test_old_databases_are_backfilled(tmp_path):
    path = tmp_path / "old.sqlite"
    st = KnowledgeStore(path)
    d = st.add_document(source="lab", kind="text", text=REPORT, title="r", published="2024-01-02")
    process(st, d["id"], llm=FakeLLM(MODEL_REPLY))
    with sqlite3.connect(path) as c:                                        # make it look like a 0.2 database
        rows = c.execute("SELECT id, src, rel, dst, document_id, snippet, method, created FROM relations").fetchall()
        c.execute("DROP TABLE relations")
        c.execute("CREATE TABLE relations (id INTEGER PRIMARY KEY AUTOINCREMENT, src INTEGER NOT NULL, rel TEXT NOT NULL, "
                  "dst INTEGER NOT NULL, document_id INTEGER NOT NULL, snippet TEXT DEFAULT '', method TEXT NOT NULL, "
                  "created TEXT NOT NULL, UNIQUE(src, rel, dst, document_id))")
        c.executemany("INSERT INTO relations VALUES (?,?,?,?,?,?,?,?)", rows)
    st2 = KnowledgeStore(path)
    rels = st2.relations()
    assert rels and all(r["basis"] and r["observed"] == "2024-01-02" for r in rels)


def test_api_and_export(home):
    from tests.conftest import write_cfg
    from zarqa import config
    from zarqa.intel.store import store_for
    from zarqa.share import stix_out
    from zarqa.web import create_app
    write_cfg(home, lambda d: d.update(default_sources={"enabled": False}))
    cfg = config.get_config(reload=True)
    st = store_for(cfg)
    d = st.add_document(source="lab", kind="text", text=REPORT, title="r", published="2024-11-05")
    process(st, d["id"], llm=FakeLLM(MODEL_REPLY))
    c = create_app(cfg).test_client()
    actor = st.find("actor", "APT28")
    j = c.get(f"/api/entities/{actor['id']}/timeline").json
    assert j["events"] and j["first_reported"] == "2024-11-05"
    assert c.get("/api/entities/99999/timeline").status_code == 404
    rel = next(o for o in stix_out.export(st, document_id=d["id"])["objects"] if o["type"] == "relationship")
    assert rel["x_zarqa_basis"] in ("stated", "inferred") and rel["x_zarqa_observed"] == "2024-11-05"
