"""STIX/TAXII 2.1 bridge: read-only access to a TAXII API root.

Calls only ``GET`` on ``collections/``, ``collections/<id>/objects/`` and
``collections/<id>/objects/<object-id>/``.
"""

from __future__ import annotations

import argparse
import json
import re
import sqlite3
import time
from typing import Any

from .common import cap, check_status, parse_time, session_from_env
from .server import McpServer, ToolInputError

ACCEPT = "application/taxii+json;version=2.1"
_ID_RE = re.compile(r"^[A-Za-z0-9._:-]{1,200}$")
_STIX_ID = re.compile(r"^[a-z0-9-]+--[0-9a-f-]{36}$")
_TYPES = {"indicator", "malware", "threat-actor", "attack-pattern", "campaign", "intrusion-set", "tool",
          "vulnerability", "report", "relationship", "sighting", "identity", "observed-data", "course-of-action",
          "infrastructure", "location", "note", "opinion", "grouping"}


def _slim(o: dict) -> dict:
    keep = ("type", "id", "name", "pattern", "pattern_type", "valid_from", "valid_until", "confidence", "labels",
            "indicator_types", "created", "modified", "kill_chain_phases", "external_references",
            "source_ref", "target_ref", "relationship_type", "object_refs", "revoked")
    out = {k: o[k] for k in keep if k in o}
    if o.get("description"):
        out["description"] = str(o["description"])[:500]
    if "external_references" in out:
        out["external_references"] = [{k: r.get(k) for k in ("source_name", "external_id", "url") if r.get(k)}
                                      for r in out["external_references"][:10]]
    return out


class TaxiiBridge:
    def __init__(self, api_root: str, collections: list[str] | None = None, max_pages: int = 20,
                 verify_tls: bool = True, ca_bundle: str = "", timeout: float = 30, session=None,
                 cache_ttl_sec: float = 300.0):
        self.root = api_root.rstrip("/") + "/"
        self.allowed = collections or []
        self.max_pages, self.timeout = max_pages, timeout
        self.cache_ttl_sec = cache_ttl_sec
        self.http = session or session_from_env("BRIDGE", verify_tls, ca_bundle)
        self.http.headers["Accept"] = ACCEPT
        self._db = sqlite3.connect(":memory:", check_same_thread=False)
        self._db.execute(
            "CREATE TABLE IF NOT EXISTS taxii_indicators "
            "(collection TEXT, id TEXT, name TEXT, pattern TEXT, slim_json TEXT)"
        )
        self._db.execute(
            "CREATE TABLE IF NOT EXISTS taxii_meta "
            "(collection TEXT PRIMARY KEY, fetched_at REAL, scanned INT, truncated INT)"
        )
        self._db.execute("CREATE INDEX IF NOT EXISTS idx_taxii_col ON taxii_indicators(collection)")

    def _get(self, path: str, params: dict | None = None) -> dict:
        r = self.http.get(self.root + path, params=params or {}, timeout=self.timeout)
        check_status(r)
        return r.json() if r.content else {}

    def _collection(self, value: Any) -> str:
        c = str(value or "")
        if not _ID_RE.match(c):
            raise ToolInputError("collection id is required")
        if self.allowed and c not in self.allowed:
            raise ToolInputError(f"collection {c!r} is not in the allowed list")
        return c

    def _collections(self) -> list[dict]:
        cols = self._get("collections/").get("collections") or []
        cols = [c for c in cols if c.get("can_read", True)]
        if self.allowed:
            cols = [c for c in cols if c.get("id") in self.allowed]
        return cols

    def list_collections(self, args: dict) -> dict:
        return {"collections": [{k: c.get(k) for k in ("id", "title", "description", "media_types")}
                                for c in self._collections()]}

    def _page(self, col: str, params: dict) -> tuple[list[dict], str | None]:
        res = self._get(f"collections/{col}/objects/", params)
        objs = res.get("objects") or []
        nxt = res.get("next") if res.get("more") else None
        return objs, nxt

    def get_objects(self, args: dict) -> dict:
        col = self._collection(args.get("collection"))
        params: dict[str, Any] = {"limit": cap(args.get("limit"), 100, 1000)}
        t = args.get("type")
        if t:
            if t not in _TYPES:
                raise ToolInputError("type must be a STIX type such as indicator, malware, attack-pattern")
            params["match[type]"] = t
        if args.get("added_after"):
            params["added_after"] = parse_time(str(args["added_after"]), default="now-7d").strftime(
                "%Y-%m-%dT%H:%M:%S.000Z")
        objs, nxt = self._page(col, params)
        return {"collection": col, "count": len(objs), "more": bool(nxt), "next": nxt,
                "objects": [_slim(o) for o in objs]}

    def get_object(self, args: dict) -> dict:
        col = self._collection(args.get("collection"))
        oid = str(args.get("id", ""))
        if not _STIX_ID.match(oid):
            raise ToolInputError("id must be a STIX id like indicator--<uuid>")
        objs = self._get(f"collections/{col}/objects/{oid}/").get("objects") or []
        return {"objects": [_slim(o) for o in objs]}

    def _ensure_indexed(self, col: str) -> tuple[int, bool]:
        row = self._db.execute("SELECT fetched_at, scanned, truncated FROM taxii_meta WHERE collection=?", (col,)).fetchone()
        now = time.monotonic()
        if row and (now - row[0]) < self.cache_ttl_sec:
            return int(row[1]), bool(row[2])
        params: dict[str, Any] = {"match[type]": "indicator", "limit": 1000}
        rows: list[tuple[str, str, str, str, str]] = []
        scanned, truncated = 0, False
        for page in range(self.max_pages):
            objs, nxt = self._page(col, params)
            scanned += len(objs)
            for o in objs:
                slim = _slim(o)
                rows.append((col, str(o.get("id", "")), str(o.get("name", "")).lower(),
                             str(o.get("pattern", "")).lower(), json.dumps({"collection": col, **slim})))
            if not nxt:
                break
            params["next"] = nxt
            if page == self.max_pages - 1:
                truncated = True
        with self._db:
            self._db.execute("DELETE FROM taxii_indicators WHERE collection=?", (col,))
            self._db.executemany("INSERT INTO taxii_indicators VALUES (?,?,?,?,?)", rows)
            self._db.execute("INSERT OR REPLACE INTO taxii_meta VALUES (?,?,?,?)",
                             (col, now, scanned, int(truncated)))
        return scanned, truncated

    def find_indicator(self, args: dict) -> dict:
        value = str(args.get("value", "")).strip()
        if len(value) < 3:
            raise ToolInputError("value must be at least 3 characters (an IP, domain, URL or hash)")
        cols = [self._collection(args["collection"])] if args.get("collection") else [c["id"] for c in self._collections()]
        needle = f"%{value.lower()}%"
        found, scanned, truncated = [], 0, False
        for col in cols:
            c_scanned, c_trunc = self._ensure_indexed(col)
            scanned += c_scanned
            truncated = truncated or c_trunc
            for (raw,) in self._db.execute(
                "SELECT slim_json FROM taxii_indicators WHERE collection=? AND (pattern LIKE ? OR name LIKE ?) LIMIT 200",
                (col, needle, needle),
            ):
                found.append(json.loads(raw))
        return {"value": value, "matches": found[:200], "scanned": scanned, "truncated": truncated,
                "note": "matched by substring in STIX pattern or name"}

    def build(self) -> McpServer:
        srv = McpServer("zarqa-taxii", instructions="Read-only STIX/TAXII 2.1 bridge for threat intelligence.")
        col = {"collection": {"type": "string", "description": "collection id from list_collections"}}
        srv.tool("list_collections", "List readable TAXII collections.", {"type": "object", "properties": {}})(self.list_collections)
        srv.tool("get_objects", "Get STIX objects from a collection, optionally by type and added_after.",
                 {"type": "object", "properties": {**col, "type": {"type": "string"},
                  "added_after": {"type": "string", "description": "ISO-8601 or now-7d"},
                  "limit": {"type": "integer"}}, "required": ["collection"]})(self.get_objects)
        srv.tool("get_object", "Get one STIX object by id.",
                 {"type": "object", "properties": {**col, "id": {"type": "string"}},
                  "required": ["collection", "id"]})(self.get_object)
        srv.tool("find_indicator", "Find indicators whose pattern mentions a value (IP, domain, URL, hash).",
                 {"type": "object", "properties": {**col, "value": {"type": "string"}}, "required": ["value"]})(self.find_indicator)
        return srv


def add_args(p: argparse.ArgumentParser) -> None:
    p.add_argument("--url", required=True, help="TAXII 2.1 API root URL")
    p.add_argument("--collection", action="append", default=[], help="allowed collection id (repeatable)")
    p.add_argument("--max-pages", type=int, default=20)
    p.add_argument("--insecure", action="store_true")
    p.add_argument("--ca-bundle", default="")


def run(a: argparse.Namespace) -> None:
    TaxiiBridge(a.url, a.collection, a.max_pages, verify_tls=not a.insecure, ca_bundle=a.ca_bundle).build().serve()
