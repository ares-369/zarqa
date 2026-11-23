"""The cross-origin guard holds in every auth mode, not only for session logins."""

from types import SimpleNamespace as N

import pytest
from flask import Flask

from zarqa.auth import init_auth


def client(mode):
    auth = N(mode=mode, secret_key="k" * 32, username="u", password="pw", password_hash="", allowed_users=[], users={}, roles={},
             group_roles={}, require_group_role=False, default_role="admin", proxy_header="X-User", proxy_groups_header="",
             proxy_trusted_ips=["127.0.0.1"], oidc={})
    cfg = N(auth=auth, external_url="https://app.example", raw={}, soc=None, instance_name="t", connectors=[])
    app = Flask(__name__)
    init_auth(app, cfg)
    app.add_url_rule("/api/x", "x", lambda: "done", methods=["GET", "POST"])
    return app.test_client()


@pytest.mark.parametrize("mode,headers", [("none", {}), ("proxy", {"X-User": "u"}),
                                          ("basic", {"Authorization": "Basic dTpwdw=="})])
def test_cross_origin_posts_are_refused(mode, headers):
    c = client(mode)
    for evil in ("https://evil.example", "null"):
        assert c.post("/api/x", headers={**headers, "Origin": evil}).status_code == 403
    for good in ("https://app.example", "http://localhost"):
        assert c.post("/api/x", headers={**headers, "Origin": good}).status_code == 200
    assert c.post("/api/x", headers=headers).status_code == 200            # no browser, no Origin
    assert c.get("/api/x", headers={**headers, "Origin": "https://evil.example"}).status_code == 200
