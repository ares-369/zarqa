"""Investigations and their steps (data/investigations.sqlite)."""

from __future__ import annotations

import json
import threading
from pathlib import Path

from .. import db
from ..intel.store import now


class InvestigationStore:
    def __init__(self, path: Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        with self._conn() as c:
            c.executescript("""
            CREATE TABLE IF NOT EXISTS investigations (
                id INTEGER PRIMARY KEY AUTOINCREMENT, question TEXT NOT NULL, status TEXT NOT NULL,
                created TEXT NOT NULL, finished TEXT DEFAULT '', actor TEXT DEFAULT '', outcome TEXT DEFAULT '',
                confidence INTEGER, assessment TEXT DEFAULT '', review TEXT DEFAULT '', error TEXT DEFAULT '',
                job_id TEXT DEFAULT '');
            CREATE TABLE IF NOT EXISTS investigation_steps (
                id INTEGER PRIMARY KEY AUTOINCREMENT, inv_id INTEGER NOT NULL, n INTEGER NOT NULL,
                connector TEXT, tool TEXT, arguments TEXT, ok INTEGER, result TEXT, thought TEXT, ts TEXT);
            CREATE INDEX IF NOT EXISTS investigation_steps_inv ON investigation_steps(inv_id);
            """)

    def _conn(self):
        return db.connect(self.path, timeout=30)

    def create(self, question: str, actor: str = "") -> int:
        with self._lock, self._conn() as c:
            cur = c.execute("INSERT INTO investigations (question, status, created, actor) VALUES (?,?,?,?)",
                            (question[:2000], "running", now(), actor[:100]))
            c.commit()
            return int(cur.lastrowid)

    def set_job(self, inv_id: int, job_id: str) -> None:
        with self._lock, self._conn() as c:
            c.execute("UPDATE investigations SET job_id=? WHERE id=?", (job_id, int(inv_id)))
            c.commit()

    def add_step(self, inv_id: int, s: dict) -> None:
        with self._lock, self._conn() as c:
            c.execute("INSERT INTO investigation_steps (inv_id, n, connector, tool, arguments, ok, result, thought, ts) "
                      "VALUES (?,?,?,?,?,?,?,?,?)",
                      (int(inv_id), int(s["n"]), s["connector"], s["tool"], json.dumps(s.get("arguments") or {})[:4000],
                       int(bool(s["ok"])), (s.get("result") or "")[:30_000], s.get("thought", ""), now()))
            c.commit()

    def finish(self, inv_id: int, *, status: str, assessment: dict | None, review: str = "", error: str = "") -> None:
        a = assessment or {}
        with self._lock, self._conn() as c:
            c.execute("UPDATE investigations SET status=?, finished=?, outcome=?, confidence=?, assessment=?, review=?, "
                      "error=? WHERE id=?", (status, now(), a.get("outcome", ""), a.get("confidence"),
                                             json.dumps(a, ensure_ascii=False) if a else "", review[:1000], error[:500],
                                             int(inv_id)))
            c.commit()

    def get(self, inv_id: int) -> dict | None:
        with self._conn() as c:
            r = c.execute("SELECT * FROM investigations WHERE id=?", (int(inv_id),)).fetchone()
            if not r:
                return None
            steps = c.execute("SELECT n, connector, tool, arguments, ok, result, thought, ts FROM investigation_steps "
                              "WHERE inv_id=? ORDER BY n", (int(inv_id),)).fetchall()
        d = dict(zip(r.keys(), r, strict=True))
        d["assessment"] = json.loads(d["assessment"]) if d["assessment"] else None
        d["steps"] = [{"n": s[0], "connector": s[1], "tool": s[2], "arguments": json.loads(s[3] or "{}"), "ok": bool(s[4]),
                       "result": s[5], "thought": s[6], "ts": s[7]} for s in steps]
        return d

    def list(self, limit: int = 50) -> list[dict]:
        with self._conn() as c:
            rows = c.execute("SELECT id, question, status, created, finished, actor, outcome, confidence, review "
                             "FROM investigations ORDER BY id DESC LIMIT ?", (int(limit),)).fetchall()
        keys = ("id", "question", "status", "created", "finished", "actor", "outcome", "confidence", "review")
        return [dict(zip(keys, r, strict=True)) for r in rows]

    def mark_orphans(self) -> int:
        """Investigations left running by a restart can never finish: mark them."""
        with self._lock, self._conn() as c:
            cur = c.execute("UPDATE investigations SET status='stopped', error='server restarted' WHERE status='running'")
            c.commit()
            return int(cur.rowcount or 0)


def store_for(cfg) -> InvestigationStore:
    return InvestigationStore(cfg.data_dir / "investigations.sqlite")
