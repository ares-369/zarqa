import pytest

from tests.conftest import ROOT, write_cfg
from zarqa import config


def test_example_config_loads(home):
    c = config.load_config()
    assert c.instance_name == "Zarqa" and c.bind_host == "127.0.0.1" and c.bind_port == 8621
    assert c.auth.mode == "none" and c.limits.max_steps == 20 and c.connectors == []
    assert config.LLM_ROLES == ("extractor", "analyst", "reporter")


def test_packaged_example_matches_root():
    assert (ROOT / "config.example.yaml").read_text() == (ROOT / "zarqa/config.example.yaml").read_text()


def test_env_overrides(home, monkeypatch):
    monkeypatch.setenv("ZARQA_BIND_PORT", "9999")
    monkeypatch.setenv("ZARQA_SECRET_KEY", "k")
    c = config.load_config()
    assert c.bind_port == 9999 and c.auth.secret_key == "k"


@pytest.mark.parametrize("mutate, msg", [
    (lambda d: d["auth"].update(mode="magic"), "auth.mode"),
    (lambda d: d["auth"].update(group_roles={"g": "root"}), "group_roles"),
    (lambda d: d["auth"].update(users={"bob": {"password": "x"}}), "password_hash"),
    (lambda d: d.update(organization=["not", "a", "map"]), "organization"),
    (lambda d: d.update(connectors=[{"name": "x", "roles": ["log_search"], "transport": "http",
                                     "url": "https://e.example/mcp"}]), "role"),
    (lambda d: d.update(connectors=[{"name": "x", "roles": ["enrichment"], "transport": "http",
                                     "url": "https://e.example/mcp", "auth": {"type": "bearer", "token": "plain"}}]),
     ".env"),
])
def test_bad_config_fails_fast(home, mutate, msg):
    write_cfg(home, mutate)
    with pytest.raises(ValueError, match=msg):
        config.load_config()


def test_intel_connector_roles(home):
    write_cfg(home, lambda d: d.update(connectors=[
        {"name": "platform", "roles": ["intel_platform"], "transport": "http", "url": "https://p.example/mcp"},
        {"name": "rep", "roles": ["enrichment", "malware"], "transport": "stdio", "command": "python"},
        {"name": "out", "roles": ["sharing"], "transport": "http", "url": "https://s.example/mcp"},
    ]))
    assert len(config.load_config().connectors) == 3


def test_privacy_keeps_public_ips_by_default():
    from zarqa.privacy import PrivacyLLM
    m = PrivacyLLM(object(), {}).masker
    out = m.mask("callback to 8.8.8.8 from 10.1.2.3 by alice@example.org")
    assert "8.8.8.8" in out and "10.1.2.3" not in out and "alice@example.org" not in out


def test_ip_at_the_end_of_a_sentence_is_masked_and_refused():
    from zarqa.bridges.server import ToolInputError
    from zarqa.bridges.web import leak_check
    from zarqa.decode import _IP
    from zarqa.privacy import Masker
    assert "10.1.2.3" not in Masker().mask("login from 10.1.2.3. Then quiet.")
    with pytest.raises(ToolInputError):
        leak_check("scan of 10.1.2.3.", [])
    assert _IP.findall("beacon to 203.0.113.9.") == ["203.0.113.9"]
