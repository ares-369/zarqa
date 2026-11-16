import sys
import types as pytypes

import pytest

from zarqa.providers.gemini import GeminiProvider


@pytest.fixture
def fake_sdk(monkeypatch):
    calls = {}

    class Resp:
        text = '{"ok": true}'

    class Models:
        def generate_content(self, **kw):
            calls["generate"] = kw
            return Resp()

    class Client:
        def __init__(self, **kw):
            calls["client"] = kw
            self.models = Models()

    def simple(**kw):
        return kw

    genai = pytypes.ModuleType("google.genai")
    genai.Client = Client
    t = pytypes.ModuleType("google.genai.types")
    t.HttpOptions = simple
    t.GenerateContentConfig = simple
    t.Content = simple
    t.Part = simple
    genai.types = t
    gauth = pytypes.ModuleType("google.auth")
    gauth.load_credentials_from_file = lambda path, scopes=None: (f"creds:{path}", "proj")
    google = pytypes.ModuleType("google")
    google.genai, google.auth = genai, gauth
    monkeypatch.setitem(sys.modules, "google", google)
    monkeypatch.setitem(sys.modules, "google.genai", genai)
    monkeypatch.setitem(sys.modules, "google.genai.types", t)
    monkeypatch.setitem(sys.modules, "google.auth", gauth)
    monkeypatch.delenv("GOOGLE_CLOUD_PROJECT", raising=False)
    monkeypatch.delenv("GOOGLE_API_KEY", raising=False)
    return calls


MSG = [{"role": "system", "content": "s"}, {"role": "user", "content": "u"}]


def test_api_key(fake_sdk):
    r = GeminiProvider({}, "key1").chat(MSG)
    assert r.text and fake_sdk["client"] == {"api_key": "key1"}
    assert fake_sdk["generate"]["config"]["max_output_tokens"] >= 2048


def test_auto_picks_vertex_when_project_set(fake_sdk):
    p = GeminiProvider({"project": "my-proj", "location": "europe-west4"}, "")
    assert p.mode() == "vertex"
    p.chat(MSG)
    c = fake_sdk["client"]
    assert c["vertexai"] and c["project"] == "my-proj" and c["location"] == "europe-west4" and c["credentials"] is None


def test_vertex_credentials_file_and_gateway(fake_sdk, monkeypatch):
    monkeypatch.setenv("GW_TOKEN", "t0k")
    p = GeminiProvider({"auth": "vertex", "project": "p", "credentials_file": "/etc/wif.json",
                        "base_url": "https://gateway.internal.example/", "headers": {"X-Gw": "${GW_TOKEN}"}}, "")
    p.chat(MSG)
    c = fake_sdk["client"]
    assert c["credentials"] == "creds:/etc/wif.json"
    assert c["http_options"] == {"base_url": "https://gateway.internal.example/", "headers": {"X-Gw": "t0k"}}


def test_vertex_project_from_env(fake_sdk, monkeypatch):
    monkeypatch.setenv("GOOGLE_CLOUD_PROJECT", "envproj")
    GeminiProvider({}, "").chat(MSG)
    assert fake_sdk["client"]["project"] == "envproj"


def test_vertex_express_key(fake_sdk):
    GeminiProvider({"auth": "vertex_api_key"}, "k").chat(MSG)
    assert fake_sdk["client"] == {"vertexai": True, "api_key": "k"}


def test_errors_are_clear(fake_sdk):
    assert "GEMINI_API_KEY" in GeminiProvider({"auth": "api_key"}, "").chat(MSG).error
    assert "project" in GeminiProvider({"auth": "vertex"}, "").chat(MSG).error
    assert "auth must be" in GeminiProvider({"auth": "magic"}, "k").chat(MSG).error


def test_models_test_command(home, monkeypatch):
    from zarqa import config, llm
    from zarqa.providers.base import LLMResult
    from zarqa.providers.ollama import OllamaProvider
    monkeypatch.setattr(OllamaProvider, "chat", lambda self, messages, **kw: LLMResult(text='{"ok": true}', model="m"))
    rows = llm.test_models(config.load_config())
    assert [r["role"] for r in rows] == ["extractor", "analyst", "reporter"] and all(r["ok"] for r in rows)
