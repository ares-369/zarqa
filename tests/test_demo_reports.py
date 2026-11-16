from zarqa.demo.setup import build


def test_demo_runs_offline(tmp_path, monkeypatch):
    import socket

    def no_network(*a, **kw):
        raise AssertionError("the demo must not use the network")
    monkeypatch.setattr(socket, "getaddrinfo", no_network)
    for v in ("ZARQA_CONFIG", "ZARQA_HOME"):
        monkeypatch.delenv(v, raising=False)
    r = build(tmp_path / "demo", run=True)
    assert r["documents"] == 3
    p = {x["document_id"]: x for x in r["processed"]}
    assert p[1]["model"]["items"] >= 4 and p[1]["model"]["relations"] == 4
    assert p[2]["relevance"]["score"] > p[3]["relevance"]["score"] == 0
    inv = r["investigation"]
    assert inv["outcome"] == "answered" and len(inv["findings"]) == 3 and "[scripted demo, not AI]" in inv["answer"]
    from zarqa import config
    from zarqa.brand.watch import store_for as bstore
    from zarqa.intel.store import store_for
    cfg = config.get_config(reload=True)
    st = store_for(cfg)
    assert st.find("actor", "Tin Heron") and st.find("campaign", "Glassbridge")
    assert st.document(1)["summary"].startswith("[scripted demo, not AI]")
    victim = st.find("domain", "grid-ops.example")
    assert {m["context"] for m in st.mentions(entity_id=victim["id"])} == {"victim"}
    top = bstore(cfg).findings()[0]
    assert top["domain"] == "sampleutiIity.example" and top["evidence"]["sample"]
    from zarqa.web import create_app
    c = create_app(cfg).test_client()
    assert b"fictional sample data" in c.get("/").data


def test_brief_and_reports(tmp_path, monkeypatch):
    for v in ("ZARQA_CONFIG", "ZARQA_HOME"):
        monkeypatch.delenv(v, raising=False)
    build(tmp_path / "demo")
    from zarqa import config
    from zarqa.intel.store import store_for
    from zarqa.reporting import brief_data, brief_markdown, document_markdown, to_html
    cfg = config.get_config(reload=True)
    st = store_for(cfg)
    b = brief_data(cfg, st, days=1)
    md = brief_markdown(b)
    assert b["scored"] and md.index("SAMPLE: Advisory") < md.index("SAMPLE: Weekly roundup")
    assert "vpn-exploitation" in md and "New lookalike domains" in md and "Tin Heron" in md
    doc = document_markdown(st, 1)
    assert "203.0.113.45" in doc and "## Relations" in doc
    html = to_html("# T <script>alert(1)</script>\n- **bold** `code`")
    assert "<script>" not in html and "&lt;script&gt;" in html and "<b>bold</b>" in html
    from zarqa.web import create_app
    c = create_app(cfg).test_client()
    r = c.get("/api/brief?format=html&days=1")
    assert r.status_code == 200 and "default-src 'none'" in r.headers["Content-Security-Policy"]
    assert c.get("/api/brief?format=md&download=1").headers["Content-Disposition"].startswith("attachment")
    assert c.get("/api/brief").json["documents"] == 3
    assert c.get("/api/documents/1/report.md").status_code == 200
    assert c.get("/api/documents/9/report.md").status_code == 404
