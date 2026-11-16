import base64
import hashlib
import json
import os
import time
from urllib.parse import parse_qs, urlparse

import pytest

from zarqa.connectors.oauth import OAuthError, TokenStore, discover, login, token_path
from zarqa.connectors.spec import parse_connectors


class R:
    def __init__(self, data, status=200):
        self._d, self.status_code = data, status

    def json(self):
        return self._d


class FakeAS:
    """Protected-resource + authorization-server metadata, registration, token endpoint."""

    def __init__(self, prm=True, pkce=True):
        self.prm, self.pkce = prm, pkce
        self.challenge = ""
        self.tokens_issued = 0
        self.posts = []

    def get(self, url, **kw):
        if self.prm and url == "https://mcp.example/.well-known/oauth-protected-resource/mcp":
            return R({"authorization_servers": ["https://login.example/tenant"]})
        if url == "https://login.example/.well-known/oauth-authorization-server/tenant" or (
                not self.prm and url == "https://mcp.example/.well-known/oauth-authorization-server"):
            return R({"authorization_endpoint": "https://login.example/authorize",
                      "token_endpoint": "https://login.example/token",
                      "registration_endpoint": "https://login.example/register",
                      "code_challenge_methods_supported": ["S256"] if self.pkce else ["plain"]})
        return R({}, 404)

    def post(self, url, data=None, json=None, **kw):
        self.posts.append((url, data or json))
        if url.endswith("/register"):
            return R({"client_id": "dyn-123"}, 201)
        if url.endswith("/token"):
            if data["grant_type"] == "authorization_code":
                v = data["code_verifier"]
                ok = base64.urlsafe_b64encode(hashlib.sha256(v.encode()).digest()).rstrip(b"=").decode() == self.challenge
                if not ok or data["code"] != "the-code":
                    return R({"error": "invalid_grant"}, 400)
            self.tokens_issued += 1
            return R({"access_token": f"at-{self.tokens_issued}", "refresh_token": "rt", "expires_in": 3600})
        return R({}, 404)


def spec(**auth):
    return parse_connectors([{"name": "remote", "roles": ["enrichment"], "transport": "http",
                              "url": "https://mcp.example/mcp", "auth": {"type": "oauth", **auth}}])[0]


def test_discovery_paths():
    assert discover("https://mcp.example/mcp", http=FakeAS())["token_endpoint"] == "https://login.example/token"
    assert discover("https://mcp.example/mcp", http=FakeAS(prm=False))["authorization_endpoint"]
    with pytest.raises(OAuthError):
        discover("https://mcp.example/mcp", http=FakeAS(pkce=False))


def test_login_with_pkce_and_refresh(tmp_path):
    fake = FakeAS()
    shown = []

    def fake_browser(port, state, timeout):
        url = shown[0].split("\n")[1]
        q = parse_qs(urlparse(url).query)
        assert q["client_id"] == ["dyn-123"] and q["code_challenge_method"] == ["S256"]
        assert q["resource"] == ["https://mcp.example/mcp"] and q["state"] == [state]
        fake.challenge = q["code_challenge"][0]
        return "the-code"

    s = spec()
    login(s, tmp_path, say=shown.append, http=fake, wait_for_code=fake_browser)
    p = token_path(tmp_path, "remote")
    assert oct(os.stat(p).st_mode & 0o777) == "0o600"
    rec = json.loads(p.read_text())
    assert rec["access_token"] == "at-1" and rec["client_id"] == "dyn-123"
    store = TokenStore(s, tmp_path, http=fake)
    assert store.token() == "at-1"
    rec["expires_at"] = time.time() - 10
    p.write_text(json.dumps(rec))
    assert store.token() == "at-2"                     # refreshed
    assert fake.posts[-1][1]["grant_type"] == "refresh_token"


def test_manual_paste_checks_state(tmp_path):
    fake = FakeAS()
    shown = []

    def ask(_prompt):
        q = parse_qs(urlparse(shown[0].split("\n")[1]).query)
        fake.challenge = q["code_challenge"][0]
        return f"http://127.0.0.1:8765/callback?code=the-code&state={q['state'][0]}"
    login(spec(client_id="fixed"), tmp_path, say=shown.append, ask=ask, http=fake)
    assert not any(u.endswith("/register") for u, _ in fake.posts)   # configured client_id: no registration
    with pytest.raises(OAuthError):
        login(spec(client_id="fixed"), tmp_path, say=shown.append,
              ask=lambda _p: "http://127.0.0.1:8765/callback?code=x&state=wrong", http=fake)


def test_not_signed_in(tmp_path):
    with pytest.raises(OAuthError, match="connectors login"):
        TokenStore(spec(), tmp_path, http=FakeAS()).token()
