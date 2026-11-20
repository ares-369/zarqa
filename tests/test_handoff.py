from urllib.parse import parse_qs, urlparse

import pytest

from tests.conftest import write_cfg
from tests.test_intel import MODEL_REPLY, REPORT, FakeLLM
from zarqa import config
from zarqa.intel.pipeline import process

URL = "https://hunt.example.org/#hunts?hypothesis={hypothesis}&context={context}&from={from}"


def _q(url):
    return {k: v[0] for k, v in parse_qs(urlparse(url).fragment.split("?", 1)[1]).items()}


def test_config_is_checked(home):
    write_cfg(home, lambda d: d.update(handoff={"hunt": {"url": "https://x.example/no-placeholder"}}))
    with pytest.raises(ValueError, match="hypothesis"):
        config.load_config()


def test_entity_and_document_handoff(home):
    from zarqa.intel.store import store_for
    from zarqa.web import create_app
    write_cfg(home, lambda d: d.update(default_sources={"enabled": False}))
    cfg = config.get_config(reload=True)
    st = store_for(cfg)
    d = st.add_document(source="lab", kind="text", text=REPORT, title="Fancy Bear phishing", url="https://lab.example/r")
    process(st, d["id"], llm=FakeLLM(MODEL_REPLY))
    c = create_app(cfg).test_client()
    actor = st.find("actor", "APT28")
    assert c.get(f"/api/entities/{actor['id']}/hunt").status_code == 400          # no tool configured
    assert c.get("/api/handoff").json == {"hunt": None}
    write_cfg(home, lambda x: x.update(handoff={"hunt": {"name": "Hunting", "url": URL}}))
    c = create_app(config.get_config(reload=True)).test_client()
    assert c.get("/api/handoff").json == {"hunt": "Hunting"}
    r = c.get(f"/api/entities/{actor['id']}/hunt").json
    q = _q(r["url"])
    assert q["from"] == "Zarqa" and "APT28" in q["hypothesis"] and q["hypothesis"] == r["hypothesis"]
    assert "203.0.113.66" in q["context"] and "a lead, not proof" in q["context"]
    rd = c.get(f"/api/documents/{d['id']}/hunt").json
    qd = _q(rd["url"])
    assert "Fancy Bear phishing" in qd["hypothesis"] and "CVE-2023-23397" in qd["context"]
    assert c.get("/api/documents/999/hunt").status_code == 404
