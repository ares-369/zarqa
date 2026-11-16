import pytest

from tests.conftest import write_cfg
from zarqa import config
from zarqa.providers import LLM, _build


def test_role_resolution_defaults_to_provider_model(home):
    llm = LLM(config.get_config(reload=True))
    bm = llm.for_role("extractor")
    assert bm.provider.__class__.__name__ == "OllamaProvider"
    assert bm.model == "qwen2.5:7b"


def test_role_model_override(home):
    write_cfg(home, lambda d: d["llm"]["roles"]["analyst"].update(model="other:3b"))
    assert LLM(config.get_config(reload=True)).for_role("analyst").model == "other:3b"


def test_unknown_provider():
    with pytest.raises(ValueError):
        _build("nope", {}, "")


def test_every_listed_provider_builds_without_sdk():
    # Providers import their SDK lazily, so construction must not need it.
    for name in config.PROVIDERS:
        try:
            _build(name, {"base_url": "http://localhost:1"}, "x")
        except ImportError:
            pass


def test_provider_cfg_expands_env(home, monkeypatch):
    monkeypatch.setenv("OLLAMA_URL", "http://model-host:11434")
    write_cfg(home, lambda d: d["llm"]["providers"]["ollama"].update(base_url="${OLLAMA_URL}"))
    assert config.load_config().provider_cfg("ollama")["base_url"] == "http://model-host:11434"


def test_fallback_on_quota(home, monkeypatch):
    import zarqa.providers as prov
    from zarqa.providers import _COOLDOWN, BoundModel
    monkeypatch.setattr(prov, "RETRY_DELAYS", (0, 0))
    from zarqa.providers.base import LLMProvider, LLMResult

    class P(LLMProvider):
        def __init__(self, name, err=None):
            super().__init__({})
            self.name, self.err, self.calls = name, err, 0

        def chat(self, messages, *, model=None, **kw):
            self.calls += 1
            return LLMResult(text="" if self.err else "hi", model=model, error=self.err)
    _COOLDOWN.clear()
    a, b = P("a", "RESOURCE_EXHAUSTED (code 429): quota reached. Resets in 54h"), P("b")
    bound = BoundModel(a, "big", [BoundModel(b, "small")])
    r = bound.chat([])
    assert r.text == "hi" and "fallback" in r.model
    bound.chat([])
    assert a.calls == 1 and b.calls == 2            # exhausted model skipped while cooling down
    c = P("c", "connection refused")
    assert BoundModel(c, "x").chat([]).error == "connection refused"
    both = BoundModel(P("d", "quota"), "1", [BoundModel(P("e", "quota"), "2")]).chat([])
    assert "d/1" in both.error and "e/2" in both.error
    _COOLDOWN.clear()


def test_transient_rate_limit_retried(home, monkeypatch):
    import zarqa.providers as prov
    from zarqa.providers import _COOLDOWN, BoundModel
    from zarqa.providers.base import LLMProvider, LLMResult
    monkeypatch.setattr(prov, "RETRY_DELAYS", (0, 0, 0))

    class Flaky(LLMProvider):
        name = "flaky"

        def __init__(self, fails):
            super().__init__({})
            self.fails, self.calls = fails, 0

        def chat(self, messages, *, model=None, **kw):
            self.calls += 1
            if self.calls <= self.fails:
                return LLMResult(text="", model=model, error="429 RESOURCE_EXHAUSTED. Resource exhausted. Try again later.")
            return LLMResult(text="ok", model=model)
    _COOLDOWN.clear()
    f = Flaky(2)
    assert BoundModel(f, "m").chat([]).text == "ok" and f.calls == 3
    # Still failing after every retry: a short cooldown only, not an hour.
    g = Flaky(99)
    assert BoundModel(g, "m").chat([]).error and g.calls == 4
    assert _COOLDOWN[("flaky", "m")] - prov._time.monotonic() <= prov.SHORT_COOLDOWN_SEC
    # A used-up quota is not retried.
    _COOLDOWN.clear()
    h = Flaky(99)
    h.chat = lambda messages, model=None, **kw: (setattr(h, "calls", h.calls + 1)
                                                 or LLMResult(text="", error="429 quota reached. Resets in 54h"))
    BoundModel(h, "m").chat([])
    assert h.calls == 1
    _COOLDOWN.clear()


def test_fallback_config(home):
    from zarqa.providers import LLM
    write_cfg(home, lambda d: d["llm"]["roles"]["analyst"].update(fallback=[{"provider": "ollama", "model": "m2"}]))
    b = LLM(config.get_config(reload=True)).for_role("analyst")
    assert [f.model for f in b.fallbacks] == ["m2"]
    import pytest
    with pytest.raises(ValueError):
        config.preview_llm_update({"analyst": {"provider": "ollama", "fallback": [{"provider": "zzz"}]}})


def test_usage_meter(home):
    from zarqa.providers import LLM
    from zarqa.providers.base import LLMProvider, LLMResult
    llm = LLM(config.get_config(reload=True))

    class P(LLMProvider):
        name = "p"

        def chat(self, messages, *, model=None, **kw):
            return LLMResult(text="ok", model=model, tokens_in=1000, tokens_out=500, tokens_cached=400)
    llm._cache["ollama"] = P({})
    b = llm.for_role("analyst")
    b.model = "m1"
    b.chat([])
    b.chat([])
    u = llm.usage_summary()
    assert u["calls"] == 2 and u["tokens_in"] == 2000 and u["tokens_out"] == 1000
    assert u["tokens_cached"] == 800 and "cost_usd" not in u


def test_each_privacy_wrapper_meters_its_own_hunt(home):
    from zarqa.privacy import PrivacyLLM
    from zarqa.providers import LLM
    from zarqa.providers.base import LLMProvider, LLMResult
    llm = LLM(config.get_config(reload=True))

    class P(LLMProvider):
        name = "p"

        def chat(self, messages, *, model=None, **kw):
            return LLMResult(text="ok", model=model, tokens_in=100, tokens_out=10)
    llm._cache["ollama"] = P({})
    a, b = PrivacyLLM(llm, {"mask_for": []}), PrivacyLLM(llm, {"mask_for": []})
    a.for_role("analyst").chat([])
    a.for_role("analyst").chat([])
    b.for_role("analyst").chat([])
    assert a.usage_summary()["calls"] == 2 and b.usage_summary()["calls"] == 1
