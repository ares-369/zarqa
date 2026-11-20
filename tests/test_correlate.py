from zarqa.intel.correlate import connections, related_documents
from zarqa.intel.pipeline import process
from zarqa.intel.store import KnowledgeStore


def _store(tmp_path):
    st = KnowledgeStore(tmp_path / "k.sqlite")
    docs = {
        "a": ("Vendor A: QuillSpin loader exploits CVE-2026-31337", "2026-11-18",
              "The QuillSpin loader exploited CVE-2026-31337 and beaconed to 203.0.113.70. It used PowerShell."),
        "b": ("Outlet B on CVE-2026-31337 attacks by QuillSpin", "2026-11-19",
              "Attackers used CVE-2026-31337 to drop QuillSpin, which contacted 203.0.113.70."),
        "c": ("Unrelated admin tips", "2026-11-19", "Admins use PowerShell every day to manage servers."),
    }
    ids = {}
    for k, (title, pub, text) in docs.items():
        ids[k] = st.add_document(source=f"src-{k}", kind="text", text=f"{title}\n\n{text}", title=title,
                                 published=pub)["id"]
        process(st, ids[k])
    for i in range(6):                                    # background reports so PowerShell is common
        d = st.add_document(source="bg", kind="text", text=f"Weekly note {i}: PowerShell activity seen.", title=f"bg{i}")
        process(st, d["id"])
    st.upsert_entity("malware", "QuillSpin")
    return st, ids


def test_related_documents_finds_the_same_story(tmp_path):
    st, ids = _store(tmp_path)
    q = st.find("malware", "QuillSpin")
    for k in ("a", "b"):
        st.add_mention(q["id"], ids[k], method="model", snippet="QuillSpin")
    rel = related_documents(st, ids["a"])
    assert rel[0]["document_id"] == ids["b"] and rel[0]["same_story"]
    assert {"CVE-2026-31337", "203.0.113.70"} <= {x["display"] for x in rel[0]["shared"]}
    assert ids["c"] not in [r["document_id"] for r in rel if r["same_story"]]       # only a common word shared


def test_connections_rank_rare_co_mentions(tmp_path):
    st, ids = _store(tmp_path)
    cve = st.find("cve", "CVE-2026-31337")
    conn = connections(st, cve["id"])
    names = [x["display"] for x in conn]
    assert "203.0.113.70" in names
    ip = next(x for x in conn if x["display"] == "203.0.113.70")
    assert ip["documents"] == 2 and set(ip["document_ids"]) == {ids["a"], ids["b"]}


def test_api(home):
    from zarqa import config
    from zarqa.intel.store import store_for
    from zarqa.web import create_app
    cfg = config.get_config(reload=True)
    st = store_for(cfg)
    a = st.add_document(source="x", kind="text", text="CVE-2026-1111 exploited, beacon 203.0.113.71.", title="a")["id"]
    b = st.add_document(source="y", kind="text", text="More on CVE-2026-1111 and 203.0.113.71 today.", title="b")["id"]
    process(st, a)
    process(st, b)
    c = create_app(cfg).test_client()
    assert c.get(f"/api/documents/{a}/related").json[0]["document_id"] == b
    cve = st.find("cve", "CVE-2026-1111")
    assert c.get(f"/api/entities/{cve['id']}/connections").json[0]["display"] == "203.0.113.71"
    assert c.get("/api/documents/9999/related").status_code == 404


def test_group_stories_folds_the_same_event(tmp_path):
    from zarqa.intel.correlate import group_stories
    st, ids = _store(tmp_path)
    docs = [st.document(ids[k]) for k in ("a", "b", "c")]
    g = group_stories(st, docs)
    assert [d["id"] for d in g] == [ids["a"], ids["c"]]
    assert [o["id"] for o in g[0]["also"]] == [ids["b"]] and g[1]["also"] == []


def test_documents_api_groups_on_request(home):
    from zarqa import config
    from zarqa.intel.store import store_for
    from zarqa.web import create_app
    cfg = config.get_config(reload=True)
    st = store_for(cfg)
    for i, src in enumerate(("x", "y")):
        d = st.add_document(source=src, kind="text", published="2026-11-19", title=f"Report {i}",
                            text=f"Report {i}: CVE-2026-2222 exploited, beacon 203.0.113.72 and evil-{i}.example.")
        process(st, d["id"])
    c = create_app(cfg).test_client()
    assert len(c.get("/api/documents").json) == 2
    g = c.get("/api/documents?group=story").json
    assert len(g) == 1 and len(g[0]["also"]) == 1
