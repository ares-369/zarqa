"""Authentication for Zarqa.

Modes (config.auth.mode):
  none   - no login (default; dev / behind a trusted network)
  basic  - HTTP Basic (simple single operator)
  local  - built-in login page + signed session cookie
  oidc   - SSO via any OpenID Connect provider. Requires the optional `authlib` extra.
  proxy  - trust a reverse-proxy forward-auth header (e.g. X-Forwarded-User). Zarqa must be reachable ONLY via that proxy.

Passwords: store a pbkdf2 hash (auth.password_hash) in preference to a plaintext
ZARQA_AUTH_PASSWORD. Sessions are signed with ZARQA_SECRET_KEY.
"""

from __future__ import annotations

import hashlib
import hmac
import html
import logging
import secrets
import time
from urllib.parse import urlparse

from flask import Response, g, redirect, render_template, request, session

log = logging.getLogger("zarqa.auth")

_PBKDF2_ITERS = 600_000
_OPEN_PATHS = {"/login", "/auth/callback", "/logout", "/healthz"}
_LOGIN_BUCKETS: dict[str, list[float]] = {}
_LOGIN_MAX_ATTEMPTS = 10
_LOGIN_WINDOW_SEC = 60.0
_VALID_ROLES = {"viewer", "operator", "admin"}
_ADMIN_ONLY_PATHS = {"/api/config", "/api/config/preview", "/api/settings/llm", "/api/settings/llm/test", "/api/retention",
                     "/api/settings/connectors", "/api/settings/sources", "/api/settings/profile",
                     "/api/settings/inventory", "/api/settings/inventory/pull", "/api/settings/inventory/clear"}
_ADMIN_ONLY_PREFIXES = ("/api/connectors/",)
# Reads that are NOT safe for every role (full database export) are admin-only.
_ADMIN_ONLY_READ_PATHS = {"/api/backup/download", "/api/audit", "/api/audit/verify", "/api/doctor"}


_RANK = {"viewer": 0, "operator": 1, "admin": 2}


def user_groups(cfg, user: str, extra=()) -> list[str]:
    """Groups from the identity provider (``extra``) plus any listed for a named account."""
    users = getattr(cfg.auth, "users", None) or {}
    own = (users.get(user) or {}).get("groups") or [] if user else []
    out = [str(g).strip() for g in [*(extra or []), *own] if str(g).strip()]
    return sorted(set(out))[:200]


def parse_groups(value) -> list[str]:
    """A claim or header value: a list, or a comma/semicolon separated string."""
    if isinstance(value, (list, tuple)):
        return [str(v) for v in value]
    if isinstance(value, str):
        return [v.strip() for v in value.replace(";", ",").split(",") if v.strip()]
    return []


def group_role(cfg, groups) -> str:
    """Highest role mapped from the user's groups by auth.group_roles, or ''."""
    gr = getattr(cfg.auth, "group_roles", None) or {}
    roles = [gr[g] for g in groups or () if gr.get(g) in _VALID_ROLES]
    return max(roles, key=lambda r: _RANK[r]) if roles else ""


def resolve_user_role(cfg, user: str, groups=()) -> str:
    """Resolve the effective RBAC role ('viewer', 'operator', or 'admin') for an
    authenticated user. Order: the named account's role, auth.roles, the highest role
    from auth.group_roles, the proxy role header, auth.default_role. Returns '' when
    auth.require_group_role is on and none of the user's groups has a role."""
    users = getattr(cfg.auth, "users", None) or {}
    if user and user in users and str(users[user].get("role", "")).lower() in _VALID_ROLES:
        return str(users[user]["role"]).lower()
    roles_map = getattr(cfg.auth, "roles", None) or {}
    if user and user in roles_map:
        r = str(roles_map[user]).lower()
        if r in _VALID_ROLES:
            return r
    gr = group_role(cfg, groups)
    if gr:
        return gr
    if getattr(cfg.auth, "group_roles", None) and getattr(cfg.auth, "require_group_role", False):
        return ""
    from flask import has_request_context
    hdr_role = (request.headers.get("X-ZARQA-Role") or "").strip().lower() if has_request_context() else ""
    if cfg.auth.mode == "proxy" and hdr_role in _VALID_ROLES:
        return hdr_role
    default_role = str(getattr(cfg.auth, "default_role", "admin") or "admin").lower()
    return default_role if default_role in _VALID_ROLES else "admin"


def check_rbac_permission(role: str, method: str, path: str, args=None) -> tuple[bool, str]:
    """Enforce 3-tier RBAC:
      - viewer: read-only GET/HEAD/OPTIONS + stateless PDF export (/api/report/pdf)
      - operator: can run investigations and jobs; cannot change settings or connectors
      - admin: full control
    """
    r = (role or "admin").lower()
    m = (method or "GET").upper()
    if path == "/mcp":
        return True, ""   # tool-level role checks happen in the MCP handler
    args = args or {}
    # Admin-only reads: checked BEFORE the general "GET is read-only" rule.
    sensitive_read = path in _ADMIN_ONLY_READ_PATHS or (
        path == "/api/doctor" and str(args.get("runner", "")).lower() in ("1", "true", "yes"))
    if sensitive_read and r != "admin":
        return False, f"Forbidden: {path} is restricted to the admin role."
    if m in ("GET", "HEAD", "OPTIONS") or path in _OPEN_PATHS or path == "/api/report/pdf":
        return True, ""
    if r == "viewer":
        return False, "Forbidden: role 'viewer' is read-only and cannot start investigations or modify state."
    if r == "operator" and (path in _ADMIN_ONLY_PATHS or (m == "POST" and path.startswith(_ADMIN_ONLY_PREFIXES))):
        return False, f"Forbidden: role 'operator' cannot modify administrative endpoint {path}."
    return True, ""


def _check_login_rate_limit(ip: str) -> bool:
    """Return True if the IP is within the login rate limit, False if throttled."""
    now = time.monotonic()
    bucket = [t for t in _LOGIN_BUCKETS.get(ip, []) if now - t < _LOGIN_WINDOW_SEC]
    if len(bucket) >= _LOGIN_MAX_ATTEMPTS:
        _LOGIN_BUCKETS[ip] = bucket
        return False
    bucket.append(now)
    _LOGIN_BUCKETS[ip] = bucket
    return True


def _origin_matches_request(cfg) -> bool:
    """Validate Origin/Referer header on state-changing cookie-authenticated requests."""
    origin = request.headers.get("Origin") or ""
    if not origin:
        return True
    try:
        o_host = urlparse(origin).netloc.lower()
    except Exception:
        return False
    allowed_hosts = {request.host.lower()}
    if cfg.external_url:
        try:
            allowed_hosts.add(urlparse(cfg.external_url).netloc.lower())
        except Exception:
            pass
    return bool(o_host and o_host in allowed_hosts)


# ---- password hashing ----
def hash_password(pw: str, iters: int = _PBKDF2_ITERS) -> str:
    salt = secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", pw.encode(), salt, iters)
    return f"pbkdf2_sha256${iters}${salt.hex()}${dk.hex()}"


def _check_hash(stored: str, pw: str) -> bool:
    try:
        algo, iters, salt_hex, hash_hex = stored.split("$", 3)
        if algo != "pbkdf2_sha256":
            return False
        dk = hashlib.pbkdf2_hmac("sha256", pw.encode(), bytes.fromhex(salt_hex), int(iters))
        return hmac.compare_digest(dk.hex(), hash_hex)
    except Exception:
        return False


_VERIFIED: dict[str, float] = {}     # digest(user, password, stored hash) -> expiry; avoids re-hashing per request
_VERIFIED_TTL = 300.0


def verify_user(cfg, user: str, pw: str) -> bool:
    """Named accounts in auth.users first, then the single auth.username account.

    Successful checks are remembered for 5 minutes as a digest of (user, password, stored hash), so
    HTTP Basic requests do not each pay for a full PBKDF2 run. Changing the password changes the digest.
    """
    users = getattr(cfg.auth, "users", None) or {}
    stored = str(users[user].get("password_hash", "")) if user in users else (cfg.auth.password_hash or "")
    key = hashlib.sha256(f"{user}\0{pw}\0{stored}".encode()).hexdigest()
    now = time.monotonic()
    if _VERIFIED.get(key, 0) > now:
        return True
    if user in users:
        ok = _check_hash(stored, pw)
    else:
        ok = hmac.compare_digest(user or "", cfg.auth.username) and _verify_password(cfg, pw)
    if ok:
        if len(_VERIFIED) > 1000:
            _VERIFIED.clear()
        _VERIFIED[key] = now + _VERIFIED_TTL
    return ok


def _verify_password(cfg, pw: str) -> bool:
    if cfg.auth.password_hash:
        return _check_hash(cfg.auth.password_hash, pw)
    if cfg.auth.password:
        return hmac.compare_digest(pw, cfg.auth.password)
    return False


def _user_allowed(cfg, user: str) -> bool:
    allow = cfg.auth.allowed_users
    return (not allow) or (user in allow)


def get_config_for_access(cfg):
    """The live config (connectors can change at runtime), falling back to the app's own."""
    try:
        from .config import get_config
        return get_config()
    except Exception:
        return cfg


def _local_user() -> str:
    import os
    return os.getenv("ZARQA_LOCAL_USER", "") or "local"


def init_auth(app, cfg) -> None:
    mode = cfg.auth.mode

    app.secret_key = cfg.auth.secret_key or secrets.token_hex(32)
    app.config.update(
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_NAME="zarqa_session",
    )
    if mode in ("local", "oidc") and not cfg.auth.secret_key:
        log.warning("auth.mode=%s but ZARQA_SECRET_KEY is unset; using an ephemeral "
                    "key (sessions drop on restart). Set ZARQA_SECRET_KEY.", mode)

    oauth = None
    if mode == "oidc":
        try:
            from authlib.integrations.flask_client import OAuth  # optional dep
        except ImportError as err:
            raise RuntimeError("auth.mode=oidc requires the 'oidc' extra: pip install 'zarqa[oidc]'") from err
        o = cfg.auth.oidc
        if not (o.get("issuer") and o.get("client_id")):
            raise RuntimeError("auth.mode=oidc requires auth.oidc.issuer and client_id")
        oauth = OAuth(app)
        oauth.register(
            name="zarqa_sso",
            client_id=o["client_id"],
            client_secret=o["client_secret"],
            server_metadata_url=o["issuer"].rstrip("/") + "/.well-known/openid-configuration",
            client_kwargs={"scope": o.get("scopes", "openid email profile")},
        )

    @app.before_request
    def _guard():
        p = request.path
        g.zarqa_role = "admin"
        g.zarqa_user = _local_user()
        g.zarqa_groups = []
        if p.startswith("/taxii2/") and request.method == "GET":
            from .share.taxii_server import token_ok
            if token_ok(cfg):
                g.zarqa_role, g.zarqa_user, g.zarqa_groups = "viewer", "taxii-token", []
                return None
        if p == "/api/inventory/import" and request.method == "POST":
            from .intel.inventory import token_ok as inventory_token_ok
            if inventory_token_ok(cfg, request.headers.get("Authorization", "")):
                g.zarqa_role, g.zarqa_user, g.zarqa_groups = "viewer", "inventory-token", []
                return None
        if p == "/mcp":
            import os
            mc = (cfg.raw or {}).get("mcp") or {}
            tok = os.getenv(str(mc.get("token_env", "")), "") if mc.get("token_env") else ""
            got = request.headers.get("Authorization", "")
            if tok and got.startswith("Bearer ") and hmac.compare_digest(got[7:].strip(), tok):
                role = str(mc.get("token_role", "viewer")).lower()
                g.zarqa_role = role if role in _VALID_ROLES else "viewer"
                g.zarqa_user = "mcp-token"
                g.zarqa_groups = parse_groups(mc.get("token_groups") or [])
                return None
        if mode == "none":
            return None
        if p.startswith("/static/") or p in _OPEN_PATHS:
            return None

        if mode == "basic":
            a = request.authorization
            if a and verify_user(cfg, a.username or "", a.password or ""):
                groups = user_groups(cfg, a.username or "")
                role = resolve_user_role(cfg, a.username or "", groups)
                if not role:
                    return Response("Forbidden: none of your groups has a role here.", 403)
                g.zarqa_role = role
                g.zarqa_user = a.username
                g.zarqa_groups = groups
                allowed, reason = check_rbac_permission(role, request.method, p, request.args)
                if not allowed:
                    return Response(reason, 403)
                return None
            return Response("Zarqa authentication required", 401,
                            {"WWW-Authenticate": 'Basic realm="Zarqa"'})

        if mode == "proxy":
            # Anti-forgery: only a trusted proxy IP may assert the identity header.
            # Fail CLOSED: with no trusted-proxy list, anyone could send the
            # header and log in as any user, so refuse every request instead.
            if not cfg.auth.proxy_trusted_ips:
                return Response("Forbidden: auth.mode=proxy requires auth.proxy_trusted_ips "
                                "(the reverse proxy's IP). Refusing to trust the identity header.", 403)
            # Check the REAL TCP peer, not request.remote_addr: ProxyFix rewrites
            # REMOTE_ADDR from the X-Forwarded-For header, which a direct client
            # can forge. ProxyFix preserves the true socket peer under
            # environ["werkzeug.proxy_fix.orig"]["REMOTE_ADDR"]; if ProxyFix did
            # not run, REMOTE_ADDR is still the real peer.
            _orig = request.environ.get("werkzeug.proxy_fix.orig") or {}
            real_peer = _orig.get("REMOTE_ADDR") or request.environ.get("REMOTE_ADDR")
            if real_peer not in cfg.auth.proxy_trusted_ips:
                return Response("Forbidden: request did not arrive via a trusted proxy.", 403)
            user = request.headers.get(cfg.auth.proxy_header, "")
            if user and _user_allowed(cfg, user):
                hdr = cfg.auth.proxy_groups_header
                groups = user_groups(cfg, user, parse_groups(request.headers.get(hdr, "")) if hdr else [])
                role = resolve_user_role(cfg, user, groups)
                if not role:
                    return Response("Forbidden: none of your groups has a role here.", 403)
                g.zarqa_role = role
                g.zarqa_user = user
                g.zarqa_groups = groups
                allowed, reason = check_rbac_permission(role, request.method, p, request.args)
                if not allowed:
                    return Response(reason, 403)
                return None
            return Response("Forbidden: missing or disallowed proxy auth header.", 403)

        # local / oidc -> session
        user = session.get("user")
        if user:
            if request.method in ("POST", "PUT", "DELETE", "PATCH") and not _origin_matches_request(cfg):
                return Response("Forbidden: cross-origin state-changing request blocked (CSRF guard).", 403)
            groups = user_groups(cfg, str(user), session.get("groups") or [])
            role = session.get("role") or resolve_user_role(cfg, str(user), groups)
            if not role:
                session.clear()
                return Response("Forbidden: none of your groups has a role here.", 403)
            g.zarqa_role = role
            g.zarqa_user = str(user)
            g.zarqa_groups = groups
            allowed, reason = check_rbac_permission(role, request.method, p, request.args)
            if not allowed:
                return Response(reason, 403)
            return None
        if p.startswith("/api/"):
            return Response("Authentication required.", 401)
        return redirect("/login")

    @app.before_request
    def _set_access():
        """Runs after _guard let the request through: hold who is asking for this request (zarqa/access.py)."""
        from .access import build, set_current
        from .connectors.spec import parse_connectors
        try:
            specs = parse_connectors(list(get_config_for_access(cfg).connectors))
        except Exception:
            specs = []
        a = build(specs, user=str(getattr(g, "zarqa_user", "") or ""), role=getattr(g, "zarqa_role", "viewer"),
                  groups=getattr(g, "zarqa_groups", []) or [])
        g.zarqa_access = a
        g.zarqa_access_token = set_current(a)

    @app.teardown_request
    def _reset_access(_exc=None):
        from .access import reset
        tok = g.pop("zarqa_access_token", None)
        if tok is not None:
            try:
                reset(tok)
            except ValueError:
                pass

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if mode == "none":
            return redirect("/")
        if mode == "oidc":
            base = (cfg.external_url or request.url_root).rstrip("/")
            redirect_uri = base + "/auth/callback"
            return oauth.zarqa_sso.authorize_redirect(redirect_uri)
        # local (and basic, though basic never redirects here)
        if request.method == "POST":
            client_ip = request.remote_addr or "unknown"
            if not _check_login_rate_limit(client_ip):
                return Response("Too many login attempts. Please wait 60 seconds.", 429)
            u = request.form.get("username", "")
            pw = request.form.get("password", "")
            if verify_user(cfg, u, pw):
                session["user"] = u
                return redirect("/")
            return render_template("login.html", error="Invalid credentials.",
                                   instance=cfg.instance_name), 401
        return render_template("login.html", error=None, instance=cfg.instance_name)

    @app.route("/auth/callback")
    def auth_callback():
        if mode != "oidc":
            return redirect("/")
        def _fail(msg: str):
            safe_msg = html.escape(str(msg or ""))
            return Response(
                f"<!doctype html><meta charset=utf-8><title>Zarqa sign-in</title>"
                f"<body style='background:#090b10;color:#f1f5f9;font-family:Inter,sans-serif;"
                f"display:flex;min-height:100vh;align-items:center;justify-content:center;text-align:center'>"
                f"<div><h2 style='color:#ef4444'>Sign-in failed</h2><p style='color:#94a3b8'>{safe_msg}</p>"
                f"<a href='/login' style='color:#ef4444'>Try again</a></div></body>", 400,
                {"Content-Type": "text/html; charset=utf-8"})

        err = request.args.get("error")
        if err:
            desc = request.args.get("error_description", err)
            log.warning("OIDC provider returned an error: %s (%s)", err, desc)
            return _fail(desc)
        try:
            token = oauth.zarqa_sso.authorize_access_token()
            info = token.get("userinfo") or {}
        except Exception as exc:
            log.warning("OIDC callback exchange failed: %s", exc)
            return _fail("Could not complete sign-in. Please try again.")
        claim = cfg.auth.oidc.get("username_claim", "email")
        user = info.get(claim) or info.get("email") or info.get("preferred_username") or info.get("sub")
        if not user or not _user_allowed(cfg, user):
            return Response("Forbidden: your account is not permitted.", 403)
        groups = parse_groups(info.get(cfg.auth.oidc.get("groups_claim", "groups")))
        if not resolve_user_role(cfg, str(user), user_groups(cfg, str(user), groups)):
            return Response("Forbidden: none of your groups has a role here.", 403)
        session["user"] = user
        session["groups"] = groups[:200]
        return redirect("/")

    @app.route("/logout")
    def logout():
        session.clear()
        return redirect("/login" if mode != "none" else "/")

    @app.route("/healthz")
    def healthz():
        return {"ok": True}
