"""A read-only TAXII 2.1 server, so other platforms can pull from Zarqa.

    share:
      taxii: true
      taxii_token_env: ZARQA_TAXII_TOKEN     # optional bearer token, in .env, for platforms that pull

Endpoints (behind the normal login, or the bearer token):

    GET /taxii2/                                         discovery
    GET /taxii2/zarqa/                                   API root
    GET /taxii2/zarqa/collections/                       collections
    GET /taxii2/zarqa/collections/<id>/                  one collection
    GET /taxii2/zarqa/collections/<id>/objects/          objects (?added_after=, ?limit=, ?next=, ?match[type]=)

Collections: ``indicators`` (active indicators that are not labelled benign, victim or reference everywhere)
and ``intel`` (everything: indicators, actors, malware, tools, campaigns, CVEs, techniques, relations).
Nothing can be written.
"""

from __future__ import annotations

from flask import Blueprint, Response, jsonify, request

from ..intel.store import INDICATOR_TYPES
from .stix_out import export

MEDIA = "application/taxii+json;version=2.1"
COLLECTIONS = {
    "indicators": {"id": "a6a3c8f2-4a2e-5b1e-9f4e-1c9a6f2d0b11", "title": "Indicators",
                   "description": "Active indicators collected and extracted by Zarqa", "types": list(INDICATOR_TYPES)},
    "intel": {"id": "c1d47f0e-2b8a-5e5c-8a3d-7f0e6b9c2a44", "title": "Intel",
              "description": "Indicators, actors, malware, tools, campaigns, CVEs, techniques and relations",
              "types": None},
}
_BY_ID = {c["id"]: (k, c) for k, c in COLLECTIONS.items()}


def _out(data, status: int = 200) -> Response:
    r = jsonify(data)
    r.status_code = status
    r.headers["Content-Type"] = MEDIA
    return r


def blueprint(get_store, get_cfg) -> Blueprint:
    bp = Blueprint("taxii", __name__)

    def enabled():
        return bool(((get_cfg().raw or {}).get("share") or {}).get("taxii"))

    @bp.before_request
    def _check():
        if not enabled():
            return _out({"title": "TAXII is turned off", "description": "set share.taxii: true"}, 404)
        return None

    @bp.route("/taxii2/")
    def discovery():
        base = request.url_root.rstrip("/")
        return _out({"title": get_cfg().instance_name, "description": "Zarqa read-only TAXII 2.1",
                     "default": f"{base}/taxii2/zarqa/", "api_roots": [f"{base}/taxii2/zarqa/"]})

    @bp.route("/taxii2/zarqa/")
    def api_root():
        return _out({"title": get_cfg().instance_name, "versions": [MEDIA], "max_content_length": 0})

    def _coll(c):
        return {"id": c["id"], "title": c["title"], "description": c["description"], "can_read": True,
                "can_write": False, "media_types": ["application/stix+json;version=2.1"]}

    @bp.route("/taxii2/zarqa/collections/")
    def collections():
        return _out({"collections": [_coll(c) for c in COLLECTIONS.values()]})

    @bp.route("/taxii2/zarqa/collections/<cid>/")
    def collection(cid):
        if cid not in _BY_ID:
            return _out({"title": "unknown collection"}, 404)
        return _out(_coll(_BY_ID[cid][1]))

    @bp.route("/taxii2/zarqa/collections/<cid>/objects/")
    def objects(cid):
        if cid not in _BY_ID:
            return _out({"title": "unknown collection"}, 404)
        _, c = _BY_ID[cid]
        try:
            limit = max(1, min(1000, int(request.args.get("limit", 500))))
            start = max(0, int(request.args.get("next", 0) or 0))
        except ValueError:
            return _out({"title": "bad limit or next"}, 400)
        b = export(get_store(), producer_name=get_cfg().instance_name, types=c["types"],
                   since=request.args.get("added_after") or None, limit=start + limit + 1)
        objs = b["objects"]
        want = request.args.get("match[type]")
        if want:
            types = set(want.split(","))
            objs = [o for o in objs if o["type"] in types]
        page = objs[start:start + limit]
        more = len(objs) > start + limit
        body = {"more": more, "objects": page}
        if more:
            body["next"] = str(start + limit)
        return _out(body)

    return bp


def token_ok(cfg) -> bool:
    import hmac
    import os
    env = str(((cfg.raw or {}).get("share") or {}).get("taxii_token_env", "") or "")
    tok = os.getenv(env, "") if env else ""
    got = request.headers.get("Authorization", "")
    return bool(tok) and got.startswith("Bearer ") and hmac.compare_digest(got[7:].strip(), tok)

