"""Interactive OAuth 2.1 sign-in (authorization code + PKCE) for HTTP MCP connectors.

Follows the MCP authorization flow:
  1. protected-resource metadata on the MCP server names the authorization server
     (``/.well-known/oauth-protected-resource``); without it the server's origin is used
  2. authorization-server metadata gives the endpoints (``/.well-known/oauth-authorization-server``,
     then ``/.well-known/openid-configuration``)
  3. the client registers itself dynamically when no ``client_id`` is configured
  4. the user signs in in a browser; the code comes back to a one-shot listener on 127.0.0.1,
     or is pasted in (``--manual``, for headless servers)
  5. tokens are stored in ``data/oauth/<connector>.json`` (mode 600) and refreshed when they expire

``zarqa connectors login <name>`` runs steps 1-5. Connector config: ``auth: {type: oauth}``,
optional ``client_id``, ``client_secret_env``, ``scope``, ``redirect_port`` (default 8765).
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import secrets
import threading
import time
from collections.abc import Callable
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlencode, urlparse

import requests

from .spec import ConnectorSpec, expand_env


class OAuthError(RuntimeError):
    pass


def _origin(url: str) -> str:
    u = urlparse(url)
    return f"{u.scheme}://{u.netloc}"


def _get_json(http, url: str, timeout: float, verify: bool) -> dict | None:
    try:
        r = http.get(url, timeout=timeout, verify=verify, headers={"Accept": "application/json"})
    except requests.RequestException:
        return None
    if r.status_code != 200:
        return None
    try:
        return r.json()
    except ValueError:
        return None


def discover(server_url: str, *, http=None, timeout: float = 15, verify: bool = True) -> dict:
    """Authorization-server metadata for an MCP server URL."""
    http = http or requests.Session()
    origin = _origin(server_url)
    path = urlparse(server_url).path.rstrip("/")
    as_url = ""
    for u in ([f"{origin}/.well-known/oauth-protected-resource{path}"] if path else []) + \
             [f"{origin}/.well-known/oauth-protected-resource"]:
        prm = _get_json(http, u, timeout, verify)
        if prm and prm.get("authorization_servers"):
            as_url = str(prm["authorization_servers"][0]).rstrip("/")
            break
    as_url = as_url or origin
    a_origin, a_path = _origin(as_url), urlparse(as_url).path.rstrip("/")
    for u in (f"{a_origin}/.well-known/oauth-authorization-server{a_path}",
              f"{a_origin}/.well-known/openid-configuration{a_path}",
              f"{as_url}/.well-known/openid-configuration"):
        meta = _get_json(http, u, timeout, verify)
        if meta and meta.get("authorization_endpoint") and meta.get("token_endpoint"):
            if "S256" not in (meta.get("code_challenge_methods_supported") or ["S256"]):
                raise OAuthError("the authorization server does not support PKCE S256")
            return meta
    raise OAuthError(f"no OAuth authorization-server metadata found for {server_url}")


def token_path(data_dir: Path, name: str) -> Path:
    return Path(data_dir) / "oauth" / f"{name}.json"


def _save(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as fh:
        json.dump(data, fh)
    os.replace(tmp, path)


def _pkce() -> tuple[str, str]:
    verifier = base64.urlsafe_b64encode(secrets.token_bytes(48)).rstrip(b"=").decode()
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    return verifier, challenge


def _wait_for_code(port: int, state: str, timeout: float) -> str:
    got: dict[str, str] = {}

    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            q = parse_qs(urlparse(self.path).query)
            if urlparse(self.path).path != "/callback":
                self.send_error(404)
                return
            if q.get("state", [""])[0] != state:
                got["error"] = "state mismatch"
            elif q.get("error"):
                got["error"] = q["error"][0]
            else:
                got["code"] = q.get("code", [""])[0]
            body = b"Signed in. You can close this tab." if "code" in got else b"Sign-in failed. See the terminal."
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            threading.Thread(target=srv.shutdown, daemon=True).start()

    srv = HTTPServer(("127.0.0.1", port), H)
    timer = threading.Timer(timeout, srv.shutdown)
    timer.start()
    try:
        srv.serve_forever()
    finally:
        timer.cancel()
        srv.server_close()
    if got.get("code"):
        return got["code"]
    raise OAuthError(got.get("error") or "sign-in timed out")


def _code_from_pasted(url_or_code: str, state: str) -> str:
    s = url_or_code.strip()
    if "://" not in s and "?" not in s:
        return s
    q = parse_qs(urlparse(s).query)
    if q.get("state", [""])[0] != state:
        raise OAuthError("state mismatch in the pasted URL")
    if q.get("error"):
        raise OAuthError(q["error"][0])
    return q.get("code", [""])[0]


def login(spec: ConnectorSpec, data_dir: Path, *, say: Callable[[str], None] = print,
          ask: Callable[[str], str] | None = None, http=None, timeout: float = 300,
          wait_for_code: Callable[[int, str, float], str] = _wait_for_code) -> dict:
    """Run the sign-in. ``ask`` set = manual mode (the user pastes the redirect URL back)."""
    if spec.transport != "http":
        raise OAuthError("OAuth sign-in is only for HTTP connectors")
    http = http or requests.Session()
    a = spec.auth
    meta = discover(spec.url, http=http, timeout=spec.timeout_sec, verify=spec.verify_tls)
    port = int(a.get("redirect_port", 8765))
    redirect = f"http://127.0.0.1:{port}/callback"
    client_id = expand_env(str(a.get("client_id", "")))
    secret = os.getenv(str(a["client_secret_env"]), "") if a.get("client_secret_env") else ""
    if not client_id:
        reg = meta.get("registration_endpoint")
        if not reg:
            raise OAuthError("no client_id configured and the server does not support dynamic registration")
        r = http.post(reg, json={"client_name": "Zarqa", "redirect_uris": [redirect],
                                 "grant_types": ["authorization_code", "refresh_token"],
                                 "response_types": ["code"], "token_endpoint_auth_method": "none"},
                      timeout=spec.timeout_sec, verify=spec.verify_tls)
        if r.status_code not in (200, 201):
            raise OAuthError(f"dynamic client registration failed: HTTP {r.status_code}")
        client_id = str(r.json()["client_id"])
    verifier, challenge = _pkce()
    state = secrets.token_urlsafe(24)
    params = {"response_type": "code", "client_id": client_id, "redirect_uri": redirect, "state": state,
              "code_challenge": challenge, "code_challenge_method": "S256", "resource": spec.url}
    if a.get("scope"):
        params["scope"] = str(a["scope"])
    url = f"{meta['authorization_endpoint']}?{urlencode(params)}"
    say(f"Open this URL and sign in:\n{url}")
    if ask:
        code = _code_from_pasted(ask("After signing in, paste the full URL the browser ended on: "), state)
    else:
        say(f"Waiting for the sign-in to return to {redirect} ...")
        code = wait_for_code(port, state, timeout)
    data = {"grant_type": "authorization_code", "code": code, "redirect_uri": redirect, "client_id": client_id,
            "code_verifier": verifier, "resource": spec.url}
    if secret:
        data["client_secret"] = secret
    r = http.post(meta["token_endpoint"], data=data, timeout=spec.timeout_sec, verify=spec.verify_tls)
    if r.status_code != 200:
        raise OAuthError(f"token exchange failed: HTTP {r.status_code}")
    tok = r.json()
    rec = {"access_token": tok["access_token"], "refresh_token": tok.get("refresh_token", ""),
           "expires_at": time.time() + float(tok.get("expires_in", 3600)), "client_id": client_id,
           "token_endpoint": meta["token_endpoint"], "resource": spec.url, "scope": tok.get("scope", "")}
    _save(token_path(data_dir, spec.name), rec)
    return {k: rec[k] for k in ("client_id", "expires_at", "scope")}


class TokenStore:
    """Access token for an ``auth: {type: oauth}`` connector, refreshed when it expires."""

    def __init__(self, spec: ConnectorSpec, data_dir: Path, *, http=None):
        self.spec, self.path = spec, token_path(data_dir, spec.name)
        self.http = http or requests.Session()
        self._lock = threading.Lock()

    def token(self) -> str:
        with self._lock:
            if not self.path.exists():
                raise OAuthError(f"not signed in: run `zarqa connectors login {self.spec.name}`")
            rec: dict[str, Any] = json.loads(self.path.read_text())
            if time.time() < float(rec.get("expires_at", 0)) - 60:
                return rec["access_token"]
            if not rec.get("refresh_token"):
                raise OAuthError(f"token expired: run `zarqa connectors login {self.spec.name}` again")
            data = {"grant_type": "refresh_token", "refresh_token": rec["refresh_token"],
                    "client_id": rec["client_id"], "resource": rec.get("resource", self.spec.url)}
            sec = self.spec.auth.get("client_secret_env")
            if sec and os.getenv(str(sec)):
                data["client_secret"] = os.getenv(str(sec), "")
            r = self.http.post(rec["token_endpoint"], data=data, timeout=self.spec.timeout_sec,
                               verify=self.spec.verify_tls)
            if r.status_code != 200:
                raise OAuthError(f"token refresh failed (HTTP {r.status_code}): sign in again")
            tok = r.json()
            rec.update(access_token=tok["access_token"], expires_at=time.time() + float(tok.get("expires_in", 3600)))
            if tok.get("refresh_token"):
                rec["refresh_token"] = tok["refresh_token"]
            _save(self.path, rec)
            return rec["access_token"]
