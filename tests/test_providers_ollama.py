"""Ollama provider: asks for a real context window and reports a cut prompt instead of answering from it."""

from zarqa.providers.ollama import OllamaProvider


class _R:
    def __init__(self, data):
        self.data = data

    def raise_for_status(self):
        pass

    def json(self):
        return self.data


def test_num_ctx_sent_and_truncation_reported(monkeypatch):
    sent = {}

    def post(url, json, timeout):
        sent.update(json=json, timeout=timeout)
        return _R({"message": {"content": "ok"}, "prompt_eval_count": 100, "eval_count": 5})

    monkeypatch.setattr("zarqa.providers.ollama.requests.post", post)
    p = OllamaProvider({"num_ctx": 4096, "timeout_sec": 60, "default_model": "m"})
    r = p.chat([{"role": "user", "content": "hi"}])
    assert r.text == "ok" and not r.error
    assert sent["json"]["options"]["num_ctx"] == 4096 and sent["timeout"] == 60

    monkeypatch.setattr("zarqa.providers.ollama.requests.post",
                        lambda url, json, timeout: _R({"message": {"content": "x"}, "prompt_eval_count": 4096}))
    r = p.chat([{"role": "user", "content": "long"}])
    assert r.error and "context" in r.error and not r.text


def test_default_context_is_8192():
    assert OllamaProvider({}).num_ctx == 8192


def test_think_flag_only_sent_when_set(monkeypatch):
    sent = []
    monkeypatch.setattr("zarqa.providers.ollama.requests.post",
                        lambda url, json, timeout: sent.append(json) or _R({"message": {"content": "ok"}}))
    OllamaProvider({}).chat([{"role": "user", "content": "x"}])
    OllamaProvider({"think": False}).chat([{"role": "user", "content": "x"}])
    assert "think" not in sent[0] and sent[1]["think"] is False


def test_thinking_budget_and_empty_answer(monkeypatch):
    sent = []
    monkeypatch.setattr("zarqa.providers.ollama.requests.post",
                        lambda url, json, timeout: sent.append(json) or _R(
                            {"message": {"content": "", "thinking": "long thoughts"}, "eval_count": 3900}))
    r = OllamaProvider({}).chat([{"role": "user", "content": "x"}], max_tokens=900)
    assert sent[0]["options"]["num_predict"] == 6900 and r.error and "thinking" in r.error and not r.text
    OllamaProvider({"think": False}).chat([{"role": "user", "content": "x"}], max_tokens=900)
    assert sent[1]["options"]["num_predict"] == 900
