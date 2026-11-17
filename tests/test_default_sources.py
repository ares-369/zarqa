import pytest

from tests.conftest import write_cfg
from zarqa import config
from zarqa.collect.collector import builtin_sources, sources_from


def test_catalogue_is_valid_and_on_by_default(home):
    cat = builtin_sources()
    names = [s["name"] for s in cat]
    assert len(cat) >= 25 and len(names) == len(set(names))
    assert {"government", "research", "news", "lists"} <= {s["category"] for s in cat}
    assert all(s.get("reliability") in "ABCDEF" and s["url"].startswith("https://") for s in cat)
    on = sources_from(config.load_config())
    assert {s["name"] for s in on} == set(names) and all(s["builtin"] and s["enabled"] for s in on)


def test_turn_all_off_or_some_off(home):
    write_cfg(home, lambda d: d.update(default_sources={"enabled": False}))
    cfg = config.load_config()
    assert sources_from(cfg) == []
    assert all(not s["enabled"] for s in sources_from(cfg, include_disabled=True))
    write_cfg(home, lambda d: d.update(default_sources={"enabled": True, "disable": ["talos", "cisa-kev"]}))
    names = {s["name"] for s in sources_from(config.load_config())}
    assert "talos" not in names and "cisa-kev" not in names and "sans-isc" in names


def test_own_source_replaces_builtin_and_can_be_switched_off(home):
    write_cfg(home, lambda d: d.update(sources=[
        {"name": "sans-isc", "url": "https://isc.example/feed.xml", "reliability": "A"},
        {"name": "mine", "url": "https://mine.example/feed.xml", "enabled": False}]))
    rows = {s["name"]: s for s in sources_from(config.load_config(), include_disabled=True)}
    assert rows["sans-isc"]["url"] == "https://isc.example/feed.xml" and not rows["sans-isc"]["builtin"]
    assert rows["mine"]["enabled"] is False
    assert "mine" not in {s["name"] for s in sources_from(config.load_config())}


def test_unknown_name_in_disable_is_refused_with_a_hint(home):
    write_cfg(home, lambda d: d.update(default_sources={"disable": ["tallos"]}))
    with pytest.raises(ValueError, match="did you mean talos"):
        config.load_config()


def test_cli_and_api_switches(home, capsys):
    from zarqa import cli
    from zarqa.web import create_app
    with pytest.raises(SystemExit) as e:
        cli.cli_main(["sources", "disable", "talos", "unit42"])
    assert e.value.code == 0
    assert config.load_config().raw["default_sources"]["disable"] == ["talos", "unit42"]
    with pytest.raises(SystemExit):
        cli.cli_main(["sources", "disable", "--all"])
    assert config.load_config().raw["default_sources"]["enabled"] is False
    with pytest.raises(SystemExit):
        cli.cli_main(["sources", "enable", "--all"])
    with pytest.raises(SystemExit):
        cli.cli_main(["sources", "enable", "talos"])
    d = config.load_config().raw["default_sources"]
    assert d["enabled"] is True and d["disable"] == ["unit42"]
    capsys.readouterr()
    with pytest.raises(SystemExit):
        cli.cli_main(["sources"])
    out = capsys.readouterr().out
    assert "built-in sources: on, off by name: unit42" in out and "off unit42" in out
    c = create_app(config.get_config(reload=True)).test_client()
    assert c.post("/api/settings/sources", json={"name": "unit42", "enabled": True}).json["ok"]
    assert c.post("/api/settings/sources", json={"all_builtin": False}).json["defaults"]["enabled"] is False
    assert c.post("/api/settings/sources", json={"name": "nope", "enabled": True}).status_code == 400
    j = c.get("/api/sources").json
    assert j["defaults"]["enabled"] is False and not any(s["enabled"] for s in j["sources"])


def test_viewer_cannot_switch_sources(home, monkeypatch):
    import base64

    from zarqa.web import create_app
    write_cfg(home, lambda d: d["auth"].update(mode="basic", default_role="operator"))
    monkeypatch.setenv("ZARQA_AUTH_PASSWORD", "pw")
    c = create_app(config.load_config()).test_client()
    h = {"Authorization": "Basic " + base64.b64encode(b"zarqa:pw").decode()}
    assert c.post("/api/settings/sources", json={"all_builtin": False}, headers=h).status_code == 403


def test_demo_has_no_builtin_sources(tmp_path, monkeypatch):
    for v in ("ZARQA_CONFIG", "ZARQA_HOME"):
        monkeypatch.delenv(v, raising=False)
    from zarqa.demo.setup import build
    build(tmp_path / "demo")
    assert sources_from(config.get_config(reload=True)) == []
