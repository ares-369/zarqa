"""Append-only audit log of every connector tool call (SQLite).

Two layers: database triggers refuse UPDATE and DELETE, and every row carries
``hash = sha256(prev_hash + row)``, so a row changed or removed with another
tool (or by editing the file) breaks the chain. ``verify()`` walks it. Cutting
rows off the end cannot be seen from the chain alone: keep the ``head`` hash
somewhere else (a ticket, a log line) if that matters.
"""

from __future__ import annotations

import hashlib
import json
import re
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .. import db

_SECRETISH = re.compile(r"(?i)(pass(word)?|secret|token|api[_-]?key|authorization|cookie)")


def redact(obj: Any) -> Any:
    if isinstance(obj, dict):
        return {k: ("***" if _SECRETISH.search(str(k)) else redact(v)) for k, v in obj.items()}
    if isinstance(obj, list):
        return [redact(v) for v in obj]
    return obj


_FIELDS = ("ts", "actor", "ref", "connector", "tool", "arguments", "decision", "status", "attempts",
           "duration_ms", "result_bytes", "error")


def row_hash(prev: str, row: tuple) -> str:
    body = json.dumps([prev, *[("" if v is None else v) for v in row]], separators=(",", ":"), default=str)
    return hashlib.sha256(body.encode()).hexdigest()


class AuditLog:
    def __init__(self, db_path: Path):
        self.path = Path(db_path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        with self._conn() as c:
            c.execute("""CREATE TABLE IF NOT EXISTS audit (
                id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT NOT NULL, actor TEXT, ref TEXT,
                connector TEXT NOT NULL, tool TEXT NOT NULL, arguments TEXT, decision TEXT NOT NULL,
                status TEXT NOT NULL, attempts INTEGER, duration_ms INTEGER, result_bytes INTEGER,
                error TEXT)""")
            c.execute("CREATE INDEX IF NOT EXISTS audit_ts ON audit(ts)")
            for col in ("prev_hash", "hash"):
                db.add_column(c, "audit", col, "TEXT")
            # append-only: refuse updates and deletes at the database level
            if db.is_pg():
                c.execute("CREATE OR REPLACE FUNCTION audit_append_only() RETURNS trigger LANGUAGE plpgsql AS "
                          "$f$ BEGIN RAISE EXCEPTION 'audit log is append-only'; END $f$")
                if not c.execute("SELECT 1 FROM pg_trigger WHERE tgname = 'audit_no_change' AND tgrelid = "
                                 "'audit'::regclass").fetchone():
                    c.execute("CREATE TRIGGER audit_no_change BEFORE UPDATE OR DELETE OR TRUNCATE ON audit "
                              "FOR EACH STATEMENT EXECUTE FUNCTION audit_append_only()")
            else:
                c.execute("CREATE TRIGGER IF NOT EXISTS audit_no_update BEFORE UPDATE ON audit "
                          "BEGIN SELECT RAISE(ABORT, 'audit log is append-only'); END")
                c.execute("CREATE TRIGGER IF NOT EXISTS audit_no_delete BEFORE DELETE ON audit "
                          "BEGIN SELECT RAISE(ABORT, 'audit log is append-only'); END")

    def _conn(self):
        return db.connect(self.path)

    def record(self, *, connector: str, tool: str, arguments: dict, decision: str, status: str,
               actor: str = "", ref: str = "", attempts: int = 0, duration_ms: int = 0,
               result_bytes: int = 0, error: str = "") -> None:
        row = (datetime.now(timezone.utc).isoformat(timespec="seconds"), actor, ref, connector, tool,
               json.dumps(redact(arguments), sort_keys=True)[:4000], decision, status, attempts,
               duration_ms, result_bytes, error[:1000])
        with self._lock:
            c = self._conn()
            c.isolation_level = None             # explicit transaction below
            try:
                c.execute("BEGIN IMMEDIATE")   # other processes (CLI, MCP) append to the same chain
                last = c.execute("SELECT hash FROM audit ORDER BY id DESC LIMIT 1").fetchone()
                prev = (last[0] if last else "") or ""
                c.execute("INSERT INTO audit (ts, actor, ref, connector, tool, arguments, decision, status, "
                          "attempts, duration_ms, result_bytes, error, prev_hash, hash) "
                          "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)", (*row, prev, row_hash(prev, row)))
                c.execute("COMMIT")
            except Exception:
                c.execute("ROLLBACK")
                raise
            finally:
                c.close()

    def verify(self) -> dict:
        """Walk the hash chain. Rows from before the chain existed are counted, not checked."""
        legacy = checked = 0
        prev = ""
        broken: list[dict] = []
        c = self._conn()
        try:
            cols = ", ".join(_FIELDS)   # fixed column names, no input
            for r in c.execute(f"SELECT id, {cols}, prev_hash, hash FROM audit ORDER BY id"):  # nosec B608
                rid, vals, ph, h = r[0], tuple(r[1:1 + len(_FIELDS)]), r[-2], r[-1]
                if h is None and not checked:
                    legacy += 1
                    continue
                checked += 1
                if (ph or "") != prev:
                    broken.append({"id": rid, "problem": "previous hash does not match (a row was removed or "
                                                         "changed before this one)"})
                if h != row_hash(ph or "", vals):
                    broken.append({"id": rid, "problem": "row content does not match its hash"})
                prev = h or ""
        finally:
            c.close()
        return {"ok": not broken, "rows_checked": checked, "rows_before_chain": legacy, "head": prev,
                "broken": broken[:50]}

    def recent(self, limit: int = 100, ref: str | None = None) -> list[dict]:
        q = "SELECT * FROM audit"
        args: tuple = ()
        if ref:
            q += " WHERE ref=?"
            args = (ref,)
        q += " ORDER BY id DESC LIMIT ?"
        with self._conn() as c:
            c.row_factory = sqlite3.Row
            return [dict(r) for r in c.execute(q, (*args, int(limit)))]
