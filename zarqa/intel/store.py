"""The knowledge store: documents, the entities found in them, and how they relate.

* ``documents``  what was collected (feed item, page, PDF, pasted text, connector result), with its text.
* ``entities``   indicators (IPs, domains, URLs, emails, hashes), CVEs, ATT&CK techniques, threat actors,
                 malware, tools, campaigns, targeted sectors and countries. One row per (type, value).
* ``mentions``   where an entity was found: the document, the sentence it came from, how it was found
                 (``rules``, ``dictionary``, ``model``, ``feed``, ``connector``, ``manual``) and in what role
                 (``malicious``, ``benign``, ``victim``, ``reference`` or empty when unknown).
* ``relations``  "X uses Y", "X targets Y", ... between two entities, each with the sentence that says so.

Every statement Zarqa keeps points back to a document and a sentence, so it can be checked.
"""

from __future__ import annotations

import hashlib
import json
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from .. import db
from . import attack
from .extract import guess_type, normalize

INDICATOR_TYPES = ("ipv4", "ipv6", "domain", "url", "email", "md5", "sha1", "sha256")
NAMED_TYPES = ("actor", "malware", "tool", "campaign", "sector", "country")
TYPES = (*INDICATOR_TYPES, "cve", "technique", *NAMED_TYPES)
METHODS = ("rules", "dictionary", "model", "feed", "connector", "manual")
CONTEXTS = ("", "malicious", "benign", "victim", "reference")
RELATIONS = ("uses", "targets", "exploits", "attributed_to", "communicates_with", "drops", "delivers",
             "variant_of", "related_to")
DEFAULT_TTL_DAYS = {"ipv4": 30, "ipv6": 30, "url": 60, "domain": 90, "email": 180}


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="microseconds")


def _j(v) -> str:
    return json.dumps(v or [], separators=(",", ":"))


def entity_key(etype: str, value: str) -> tuple[str, str, str]:
    """(type, stored value, display) for an entity. Indicators are normalised; named entities are matched
    case-insensitively and resolved to their ATT&CK name when the name or an alias is known."""
    etype = (etype or "").strip().lower()
    value = (value or "").strip()
    if etype not in TYPES:
        raise ValueError(f"unknown entity type {etype!r}")
    if not value or len(value) > 2048:
        raise ValueError("empty or oversized value")
    if etype in INDICATOR_TYPES or etype == "cve":
        v = normalize(etype, value)
        got = guess_type(v)
        if got != etype and not (etype == "domain" and got is None and "." in v):
            raise ValueError(f"{value!r} is not a valid {etype}")
        return etype, v, v
    if etype == "technique":
        t = attack.technique(value)
        if not t:
            raise ValueError(f"{value!r} is not an ATT&CK technique ID")
        return etype, t["id"], f"{t['id']} {t['name']}"
    if etype in ("actor", "malware", "tool", "campaign"):
        hit = attack.lookup(value)
        if hit and (hit["kind"] == etype or {hit["kind"], etype} <= {"malware", "tool"}):
            return hit["kind"], attack.norm(hit["name"]), hit["name"]
    return etype, attack.norm(value), value[:200]


class KnowledgeStore:
    def __init__(self, path: Path, ttl_days: dict | None = None):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.ttl = {**DEFAULT_TTL_DAYS, **(ttl_days or {})}
        self._lock = threading.Lock()
        self._init()

    def _conn(self):
        return db.connect(self.path, timeout=30)

    def _init(self) -> None:
        with self._conn() as c:
            c.executescript("""
            CREATE TABLE IF NOT EXISTS documents (
                id INTEGER PRIMARY KEY AUTOINCREMENT, source TEXT NOT NULL, kind TEXT NOT NULL, url TEXT DEFAULT '',
                title TEXT DEFAULT '', published TEXT DEFAULT '', fetched TEXT NOT NULL, sha TEXT NOT NULL UNIQUE,
                text TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'new', error TEXT DEFAULT '', method TEXT DEFAULT '',
                summary TEXT DEFAULT '', tags TEXT DEFAULT '[]', review TEXT DEFAULT '', added_by TEXT DEFAULT '',
                relevance INTEGER, relevance_reason TEXT DEFAULT '', extracted TEXT DEFAULT '');
            CREATE INDEX IF NOT EXISTS documents_status ON documents(status);
            CREATE INDEX IF NOT EXISTS documents_fetched ON documents(fetched);
            CREATE TABLE IF NOT EXISTS entities (
                id INTEGER PRIMARY KEY AUTOINCREMENT, type TEXT NOT NULL, value TEXT NOT NULL, display TEXT NOT NULL,
                first_seen TEXT NOT NULL, last_seen TEXT NOT NULL, seen_count INTEGER NOT NULL DEFAULT 1,
                confidence INTEGER NOT NULL DEFAULT 50, tags TEXT DEFAULT '[]', expires TEXT DEFAULT '',
                status TEXT NOT NULL DEFAULT 'active', ref TEXT DEFAULT '', note TEXT DEFAULT '',
                UNIQUE(type, value));
            CREATE INDEX IF NOT EXISTS entities_seen ON entities(last_seen);
            CREATE TABLE IF NOT EXISTS mentions (
                id INTEGER PRIMARY KEY AUTOINCREMENT, entity_id INTEGER NOT NULL, document_id INTEGER NOT NULL,
                snippet TEXT DEFAULT '', method TEXT NOT NULL, context TEXT DEFAULT '', created TEXT NOT NULL,
                UNIQUE(entity_id, document_id, method));
            CREATE INDEX IF NOT EXISTS mentions_doc ON mentions(document_id);
            CREATE INDEX IF NOT EXISTS mentions_entity ON mentions(entity_id);
            CREATE TABLE IF NOT EXISTS relations (
                id INTEGER PRIMARY KEY AUTOINCREMENT, src INTEGER NOT NULL, rel TEXT NOT NULL, dst INTEGER NOT NULL,
                document_id INTEGER NOT NULL, snippet TEXT DEFAULT '', method TEXT NOT NULL, created TEXT NOT NULL,
                UNIQUE(src, rel, dst, document_id));
            CREATE INDEX IF NOT EXISTS relations_src ON relations(src);
            CREATE INDEX IF NOT EXISTS relations_dst ON relations(dst);
            CREATE TABLE IF NOT EXISTS seen_keys (key TEXT PRIMARY KEY, source TEXT, seen TEXT, document_id INTEGER);
            CREATE TABLE IF NOT EXISTS source_state (
                name TEXT PRIMARY KEY, last_pull TEXT DEFAULT '', last_ok TEXT DEFAULT '', last_error TEXT DEFAULT '',
                pulls INTEGER DEFAULT 0, documents INTEGER DEFAULT 0, etag TEXT DEFAULT '', modified TEXT DEFAULT '');
            """)

    # ---- documents ----
    def add_document(self, *, source: str, kind: str, text: str, url: str = "", title: str = "",
                     published: str = "", tags: list[str] | None = None, added_by: str = "",
                     max_chars: int = 200_000) -> dict:
        """Store a document once (by content). Returns ``{id, new}``."""
        text = (text or "")[:max_chars]
        if not text.strip():
            raise ValueError("document has no text")
        sha = hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()
        with self._lock, self._conn() as c:
            r = c.execute("SELECT id FROM documents WHERE sha=?", (sha,)).fetchone()
            if r:
                return {"id": int(r[0]), "new": False}
            cur = c.execute(
                "INSERT INTO documents (source, kind, url, title, published, fetched, sha, text, tags, added_by) "
                "VALUES (?,?,?,?,?,?,?,?,?,?)",
                (source, kind, url[:2000], (title or url or source)[:500], published[:40], now(), sha, text,
                 _j(tags), added_by[:100]))
            c.commit()
            return {"id": int(cur.lastrowid), "new": True}

    def document(self, doc_id: int, *, with_text: bool = True) -> dict | None:
        cols = "*" if with_text else ", ".join(_DOC_COLS)
        with self._conn() as c:
            r = c.execute(f"SELECT {cols} FROM documents WHERE id=?", (int(doc_id),)).fetchone()  # nosec B608
        return _doc(r) if r else None

    def documents(self, *, status: str | None = None, source: str | None = None, q: str = "", limit: int = 50,
                  offset: int = 0, min_relevance: int | None = None, order: str = "newest",
                  tag: str | None = None) -> list[dict]:
        where, args = [], []
        if status:
            where.append("status=?")
            args.append(status)
        if source:
            where.append("source=?")
            args.append(source)
        if q:
            where.append("(title LIKE ? OR text LIKE ?)")
            args += [f"%{q}%", f"%{q}%"]
        if min_relevance is not None:
            where.append("relevance >= ?")
            args.append(int(min_relevance))
        if tag:
            where.append("tags LIKE ?")
            args.append(f'%"{tag}"%')
        # fixed column names; every value is a bound parameter
        sql = f"SELECT {', '.join(_DOC_COLS)} FROM documents"  # nosec B608
        if where:
            sql += " WHERE " + " AND ".join(where)
        sql += (" ORDER BY COALESCE(relevance, -1) DESC, id DESC" if order == "relevance" else " ORDER BY id DESC")
        sql += " LIMIT ? OFFSET ?"
        with self._conn() as c:
            rows = c.execute(sql, (*args, int(limit), int(offset))).fetchall()
        return [_doc(r) for r in rows]

    def update_document(self, doc_id: int, **fields) -> None:
        allowed = {"status", "error", "method", "summary", "review", "relevance", "relevance_reason", "extracted",
                   "title", "tags"}
        sets = {k: (_j(v) if k == "tags" else v) for k, v in fields.items() if k in allowed}
        if not sets:
            return
        with self._lock, self._conn() as c:
            c.execute(f"UPDATE documents SET {', '.join(f'{k}=?' for k in sets)} WHERE id=?",  # nosec B608
                      (*sets.values(), int(doc_id)))
            c.commit()

    # ---- entities ----
    def upsert_entity(self, etype: str, value: str, *, confidence: int = 50, tags: list[str] | None = None,
                      seen: str | None = None) -> dict:
        etype, v, display = entity_key(etype, value)
        ts = seen or now()
        days = self.ttl.get(etype)
        expires = (datetime.now(timezone.utc) + timedelta(days=int(days))).isoformat(timespec="seconds") if days else ""
        ref = ""
        if etype == "technique":
            ref = v
        elif etype in ("actor", "malware", "tool", "campaign"):
            hit = attack.lookup(display)
            ref = hit["id"] if hit else ""
        conf = max(0, min(100, int(confidence)))
        with self._lock, self._conn() as c:
            r = c.execute("SELECT id, confidence, tags, status FROM entities WHERE type=? AND value=?",
                          (etype, v)).fetchone()
            if r:
                merged = sorted(set(json.loads(r[2] or "[]")) | set(tags or []))
                status = "active" if r[3] == "expired" else r[3]
                c.execute("UPDATE entities SET last_seen=?, seen_count=seen_count+1, confidence=?, tags=?, "
                          "expires=?, status=? WHERE id=?",
                          (ts, max(int(r[1]), conf), _j(merged), expires, status, r[0]))
                c.commit()
                return {"id": int(r[0]), "type": etype, "value": v, "new": False}
            cur = c.execute("INSERT INTO entities (type, value, display, first_seen, last_seen, confidence, tags, "
                            "expires, ref) VALUES (?,?,?,?,?,?,?,?,?)",
                            (etype, v, display, ts, ts, conf, _j(sorted(set(tags or []))), expires, ref))
            c.commit()
            return {"id": int(cur.lastrowid), "type": etype, "value": v, "new": True}

    def add_mention(self, entity_id: int, document_id: int, *, method: str, snippet: str = "",
                    context: str = "") -> None:
        if method not in METHODS:
            raise ValueError(f"unknown method {method!r}")
        context = context if context in CONTEXTS else ""
        with self._lock, self._conn() as c:
            c.execute("INSERT INTO mentions (entity_id, document_id, snippet, method, context, created) "
                      "VALUES (?,?,?,?,?,?) ON CONFLICT(entity_id, document_id, method) DO UPDATE SET "
                      "snippet=excluded.snippet, context=excluded.context",
                      (int(entity_id), int(document_id), snippet[:600], method, context, now()))
            c.commit()

    def set_context(self, document_id: int, entity_id: int, context: str, snippet: str = "") -> None:
        """Record the role the model gave an indicator in a document (on its rules mention, or a new one)."""
        if context not in CONTEXTS:
            return
        with self._lock, self._conn() as c:
            c.execute("UPDATE mentions SET context=? WHERE document_id=? AND entity_id=?",
                      (context, int(document_id), int(entity_id)))
            c.commit()
        if snippet:
            self.add_mention(entity_id, document_id, method="model", snippet=snippet, context=context)

    def add_relation(self, src: int, rel: str, dst: int, document_id: int, *, method: str, snippet: str = "") -> bool:
        if rel not in RELATIONS or src == dst:
            return False
        with self._lock, self._conn() as c:
            cur = c.execute("INSERT INTO relations (src, rel, dst, document_id, snippet, method, created) "
                            "VALUES (?,?,?,?,?,?,?) ON CONFLICT(src, rel, dst, document_id) DO NOTHING",
                            (int(src), rel, int(dst), int(document_id), snippet[:600], method, now()))
            c.commit()
            return bool(cur.rowcount)

    def entity(self, entity_id: int) -> dict | None:
        with self._conn() as c:
            r = c.execute("SELECT * FROM entities WHERE id=?", (int(entity_id),)).fetchone()
        return _ent(r) if r else None

    def find(self, etype: str, value: str) -> dict | None:
        try:
            etype, v, _ = entity_key(etype, value)
        except ValueError:
            return None
        with self._conn() as c:
            r = c.execute("SELECT * FROM entities WHERE type=? AND value=?", (etype, v)).fetchone()
        return _ent(r) if r else None

    def lookup(self, value: str) -> list[dict]:
        """Every entity matching a value, whatever its type (an indicator, CVE, technique or name)."""
        out = []
        kind = guess_type(value)
        cands = [kind] if kind and kind != "technique" else []
        if kind == "technique":
            cands = ["technique"]
        cands += [t for t in NAMED_TYPES if t not in cands]
        for t in cands:
            e = self.find(t, value)
            if e and e not in out:
                out.append(e)
        return out

    def entities(self, *, etype: str | None = None, q: str = "", status: str | None = "active", limit: int = 100,
                 offset: int = 0, order: str = "last_seen") -> list[dict]:
        where, args = [], []
        if etype:
            types = [t.strip() for t in etype.split(",") if t.strip()]
            where.append(f"type IN ({','.join('?' * len(types))})")
            args += types
        if q:
            where.append("(value LIKE ? OR display LIKE ?)")
            args += [f"%{q}%", f"%{q}%"]
        if status:
            where.append("status=?")
            args.append(status)
        col = {"last_seen": "last_seen DESC", "seen": "seen_count DESC, last_seen DESC", "first_seen": "first_seen DESC",
               "confidence": "confidence DESC, last_seen DESC"}.get(order, "last_seen DESC")
        # where, col: fixed fragments chosen in code; every value is a bound parameter
        sql = "SELECT * FROM entities" + (" WHERE " + " AND ".join(where) if where else "")  # nosec B608
        sql += f" ORDER BY {col} LIMIT ? OFFSET ?"
        with self._conn() as c:
            rows = c.execute(sql, (*args, int(limit), int(offset))).fetchall()  # nosec B608
        return [_ent(r) for r in rows]

    def mentions(self, *, entity_id: int | None = None, document_id: int | None = None, limit: int = 200) -> list[dict]:
        where, args = [], []
        if entity_id is not None:
            where.append("m.entity_id=?")
            args.append(int(entity_id))
        if document_id is not None:
            where.append("m.document_id=?")
            args.append(int(document_id))
        sql = ("SELECT m.id, m.entity_id, m.document_id, m.snippet, m.method, m.context, m.created, e.type, e.value, "
               "e.display, d.title, d.url, d.source FROM mentions m JOIN entities e ON e.id=m.entity_id "
               "JOIN documents d ON d.id=m.document_id")
        if where:
            sql += " WHERE " + " AND ".join(where)
        sql += " ORDER BY m.id DESC LIMIT ?"
        with self._conn() as c:
            rows = c.execute(sql, (*args, int(limit))).fetchall()
        keys = ("id", "entity_id", "document_id", "snippet", "method", "context", "created", "type", "value",
                "display", "title", "url", "source")
        return [dict(zip(keys, r, strict=True)) for r in rows]

    def relations(self, *, entity_id: int | None = None, document_id: int | None = None, limit: int = 200) -> list[dict]:
        where, args = [], []
        if entity_id is not None:
            where.append("(r.src=? OR r.dst=?)")
            args += [int(entity_id), int(entity_id)]
        if document_id is not None:
            where.append("r.document_id=?")
            args.append(int(document_id))
        sql = ("SELECT r.id, r.src, s.type, s.display, r.rel, r.dst, t.type, t.display, r.document_id, r.snippet, "
               "r.method, d.title FROM relations r JOIN entities s ON s.id=r.src JOIN entities t ON t.id=r.dst "
               "JOIN documents d ON d.id=r.document_id")
        if where:
            sql += " WHERE " + " AND ".join(where)
        sql += " ORDER BY r.id DESC LIMIT ?"
        with self._conn() as c:
            rows = c.execute(sql, (*args, int(limit))).fetchall()
        keys = ("id", "src", "src_type", "src_display", "rel", "dst", "dst_type", "dst_display", "document_id",
                "snippet", "method", "title")
        return [dict(zip(keys, r, strict=True)) for r in rows]

    def add_tags(self, entity_id: int, tags: list[str]) -> None:
        """Add tags without counting it as a new sighting."""
        with self._lock, self._conn() as c:
            r = c.execute("SELECT tags FROM entities WHERE id=?", (int(entity_id),)).fetchone()
            if r is None:
                return
            merged = sorted(set(json.loads(r[0] or "[]")) | {str(t)[:40] for t in tags})
            c.execute("UPDATE entities SET tags=? WHERE id=?", (_j(merged), int(entity_id)))
            c.commit()

    def set_status(self, entity_id: int, status: str, note: str = "") -> None:
        if status not in ("active", "expired", "false_positive", "allowlisted"):
            raise ValueError("status must be active, expired, false_positive or allowlisted")
        with self._lock, self._conn() as c:
            c.execute("UPDATE entities SET status=?, note=? WHERE id=?", (status, note[:500], int(entity_id)))
            c.commit()

    def expire(self) -> int:
        """Mark indicators past their expiry date as expired. Returns how many."""
        ts = datetime.now(timezone.utc).isoformat(timespec="seconds")
        with self._lock, self._conn() as c:
            cur = c.execute("UPDATE entities SET status='expired' WHERE status='active' AND expires != '' AND expires < ?",
                            (ts,))
            c.commit()
            return int(cur.rowcount or 0)

    def clear_extraction(self, document_id: int, method: str) -> None:
        """Remove one method's mentions and relations for a document (before re-running it)."""
        with self._lock, self._conn() as c:
            c.execute("DELETE FROM mentions WHERE document_id=? AND method=?", (int(document_id), method))
            c.execute("DELETE FROM relations WHERE document_id=? AND method=?", (int(document_id), method))
            c.commit()

    # ---- bookkeeping for collectors ----
    def seen(self, key: str) -> bool:
        with self._conn() as c:
            return c.execute("SELECT 1 FROM seen_keys WHERE key=?", (key,)).fetchone() is not None

    def mark_seen(self, key: str, source: str, document_id: int | None) -> None:
        with self._lock, self._conn() as c:
            c.execute("INSERT INTO seen_keys (key, source, seen, document_id) VALUES (?,?,?,?) ON CONFLICT(key) DO "
                      "UPDATE SET source=excluded.source, seen=excluded.seen, document_id=excluded.document_id",
                      (key[:1000], source, now(), document_id))
            c.commit()

    def source_state(self, name: str | None = None) -> dict:
        with self._conn() as c:
            rows = c.execute("SELECT name, last_pull, last_ok, last_error, pulls, documents, etag, modified "
                             "FROM source_state").fetchall()
        keys = ("name", "last_pull", "last_ok", "last_error", "pulls", "documents", "etag", "modified")
        states = {r[0]: dict(zip(keys, r, strict=True)) for r in rows}
        return states.get(name, {}) if name else states

    def record_pull(self, name: str, *, ok: bool, error: str = "", documents: int = 0, etag: str = "",
                    modified: str = "") -> None:
        ts = now()
        with self._lock, self._conn() as c:
            c.execute("INSERT INTO source_state (name) VALUES (?) ON CONFLICT(name) DO NOTHING", (name,))
            c.execute("UPDATE source_state SET last_pull=?, pulls=pulls+1, documents=documents+?, last_error=? "
                      "WHERE name=?", (ts, int(documents), "" if ok else error[:500], name))
            if ok:
                c.execute("UPDATE source_state SET last_ok=?, etag=?, modified=? WHERE name=?",
                          (ts, etag[:200], modified[:100], name))
            c.commit()

    def stats(self) -> dict:
        with self._conn() as c:
            docs = dict(c.execute("SELECT status, COUNT(*) FROM documents GROUP BY status").fetchall())
            ents = dict(c.execute("SELECT type, COUNT(*) FROM entities WHERE status='active' GROUP BY type").fetchall())
            rels = c.execute("SELECT COUNT(*) FROM relations").fetchone()[0]
        return {"documents": {k: int(v) for k, v in docs.items()}, "entities": {k: int(v) for k, v in ents.items()},
                "relations": int(rels)}


_DOC_COLS = ("id", "source", "kind", "url", "title", "published", "fetched", "status", "error", "method", "summary",
             "tags", "review", "added_by", "relevance", "relevance_reason", "extracted")


def _doc(r) -> dict:
    d = dict(zip(r.keys(), r, strict=True)) if hasattr(r, "keys") else dict(zip(_DOC_COLS, r, strict=True))
    d["tags"] = json.loads(d.get("tags") or "[]")
    d.pop("sha", None)
    return d


def _ent(r) -> dict:
    d = dict(zip(r.keys(), r, strict=True))
    d["tags"] = json.loads(d.get("tags") or "[]")
    return d


def store_for(cfg) -> KnowledgeStore:
    ttl = ((cfg.raw or {}).get("intel") or {}).get("ttl_days") or {}
    return KnowledgeStore(cfg.data_dir / "intel.sqlite", ttl_days=ttl)


def is_indicator(etype: str) -> bool:
    return etype in INDICATOR_TYPES


def as_dict(x: Any) -> dict:
    return dict(x) if isinstance(x, dict) else {}
