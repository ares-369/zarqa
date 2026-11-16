"""Background jobs.

Hunts can run for minutes. Jobs are recorded in SQLite so the UI can poll for
progress, with cooperative stop and pause. No external broker is needed.

Two modes (``jobs.mode``):

  local  (default) the server runs jobs on its own thread pool.
  queue  the server only records jobs; ``zarqa worker`` processes claim and
         run them. Workers can be restarted or added without touching the UI.
         Stop and pause go through the database, so they reach any worker.

In queue mode a job is a named task with JSON parameters (zarqa/tasks.py), and
it runs with the access of the person who started it.
"""

from __future__ import annotations

import contextvars
import json
import sqlite3
import threading
import time
import traceback
import uuid
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from typing import Any

_MAX_RESULT_CHARS = 250_000
_DEFAULT_JOB_BUDGET_SEC = 900.0


# Each worker thread runs one job at a time; remember which, so progress
# events can be attributed to the job that produced them.
_current = threading.local()


def current_job_id() -> str | None:
    """ID of the job running on this thread, or None outside a job."""
    return getattr(_current, "job_id", None)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class JobControl:
    """Passed into a job's function so it can be paused/stopped cooperatively.
    The function calls checkpoint() at safe boundaries (between tools/steps)."""

    def __init__(self, mgr: JobManager, job_id: str, max_runtime_sec: float = _DEFAULT_JOB_BUDGET_SEC):
        self.mgr = mgr
        self.job_id = job_id
        self.started_monotonic = time.monotonic()
        self.max_runtime_sec = max_runtime_sec

    @property
    def cancelled(self) -> bool:
        return self.mgr._control.get(self.job_id) == "cancel"

    def checkpoint(self) -> bool:
        """Block while paused; update heartbeat; return False if cancelled or budget exceeded."""
        while self._state() == "pause":
            time.sleep(0.4 if self.job_id in self.mgr._control else 2.0)
        if time.monotonic() - self.started_monotonic > self.max_runtime_sec:
            self.mgr._control[self.job_id] = "cancel"
            return False
        try:
            self.mgr._set(self.job_id, heartbeat=_now())
        except Exception:
            pass
        return self._state() != "cancel"

    def _state(self) -> str:
        """run | pause | cancel. Local jobs: in memory; jobs run by a worker: the database's control column."""
        local = self.mgr._control.get(self.job_id)
        if local == "cancel" or not self.mgr.remote_control:
            return local or "run"
        return self.mgr.control_of(self.job_id) or local or "run"


class JobManager:
    def __init__(self, db_path, max_workers: int = 3, *, mode: str = "local", stale_after_sec: float = 600.0):
        from pathlib import Path
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        if mode not in ("local", "queue"):
            raise ValueError("jobs.mode must be local or queue")
        self.db_path = str(db_path)
        self.mode = mode
        self.remote_control = mode == "queue"   # pause/stop may come from another process
        self.stale_after_sec = float(stale_after_sec)
        self.pool = ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix="zarqa-job")
        self._control: dict[str, str] = {}
        self._init_db()
        if mode == "local":
            self._reconcile_orphans()
        else:
            self.reconcile_stale()

    @classmethod
    def from_config(cls, cfg, *, max_workers: int | None = None) -> JobManager:
        j = (getattr(cfg, "raw", None) or {}).get("jobs") or {}
        return cls(cfg.data_dir / "zarqa.sqlite", max_workers=int(max_workers or j.get("threads", 3) or 3),
                   mode=str(j.get("mode", "local") or "local"),
                   stale_after_sec=float(j.get("stale_after_sec", 600) or 600))

    def _conn(self):
        from . import db
        con = db.connect(self.db_path, timeout=30)
        try:
            con.execute("PRAGMA journal_mode=WAL")
            con.execute("PRAGMA busy_timeout=5000")
        except Exception:
            pass
        return con

    def _init_db(self):
        with self._conn() as conn:
            conn.execute("""
            CREATE TABLE IF NOT EXISTS jobs (
                id TEXT PRIMARY KEY,
                kind TEXT NOT NULL,
                meta TEXT NOT NULL,
                status TEXT NOT NULL,
                created TEXT NOT NULL,
                heartbeat TEXT DEFAULT '',
                finished TEXT,
                result TEXT,
                error TEXT
            )""")
            from .db import add_column
            for col, ddl in (("heartbeat", "TEXT DEFAULT ''"), ("task", "TEXT"), ("params", "TEXT"),
                             ("control", "TEXT DEFAULT 'run'"), ("worker", "TEXT")):
                add_column(conn, "jobs", col, ddl)
            conn.execute("CREATE INDEX IF NOT EXISTS jobs_queue ON jobs(status, created)")
            conn.commit()

    def _reconcile_orphans(self):
        """On startup the thread pool is empty, so any job still marked
        queued/running in SQLite is a ghost from a previous process (crash,
        reboot, redeploy). Mark them interrupted so the UI never shows a job
        that will never finish."""
        with self._conn() as conn:
            conn.execute(
                "UPDATE jobs SET status='interrupted', finished=?, "
                "error='Process restarted before this job completed.' "
                "WHERE status IN ('queued','running') AND worker IS NULL",
                (_now(),),
            )
            conn.commit()

    def _set(self, job_id: str, **fields):
        cols = ", ".join(f"{k}=?" for k in fields)
        with self._conn() as conn:
            # Column names and placeholders are fixed in code; values are always bound.
            conn.execute(f"UPDATE jobs SET {cols} WHERE id=?", (*fields.values(), job_id))  # nosec B608
            conn.commit()

    def reconcile_stale(self) -> int:
        """Queue mode: a running job whose worker stopped sending heartbeats is marked interrupted."""
        cutoff = datetime.fromtimestamp(time.time() - self.stale_after_sec, timezone.utc).isoformat()
        with self._conn() as conn:
            n = conn.execute("UPDATE jobs SET status='interrupted', finished=?, error='The worker stopped "
                             "(no heartbeat) before this job completed.' WHERE status='running' AND heartbeat < ?",
                             (_now(), cutoff)).rowcount
            conn.commit()
        return n

    def control_of(self, job_id: str) -> str | None:
        with self._conn() as conn:
            r = conn.execute("SELECT control FROM jobs WHERE id=?", (job_id,)).fetchone()
        return r[0] if r else None

    def submit(
        self,
        kind: str,
        meta: dict[str, Any],
        fn: Callable[[JobControl], dict] | None,
        *,
        deduplicate: bool = True,
        task: str | None = None,
        params: dict[str, Any] | None = None,
    ) -> str:
        """Run ``fn`` here (local mode), or record the named ``task`` for a worker (queue mode).

        Callers pass both where they can: the closure keeps local mode (and tests) simple, the task and
        its JSON parameters let any worker run the same job."""
        meta_json = json.dumps(meta, sort_keys=True)
        if self.mode == "queue" and task:
            return self._enqueue(kind, meta_json, task, params or {}, deduplicate)
        if fn is None:
            from .tasks import run_task
            fn = lambda ctl: run_task(task, params or {}, ctl, jobs=self)  # noqa: E731
        if deduplicate:
            with self._conn() as conn:
                existing = conn.execute(
                    "SELECT id FROM jobs WHERE kind=? AND meta=? AND status IN ('queued','running') LIMIT 1",
                    (kind, meta_json),
                ).fetchone()
                if existing and existing[0] in self._control:
                    return str(existing[0])
        job_id = uuid.uuid4().hex[:12]
        now_ts = _now()
        self._control[job_id] = "run"
        with self._conn() as conn:
            conn.execute(
                "INSERT INTO jobs (id, kind, meta, status, created, heartbeat) VALUES (?,?,?,?,?,?)",
                (job_id, kind, meta_json, "queued", now_ts, now_ts),
            )
            conn.commit()
        # Run with the submitter's context: a job started by a person keeps that person's access
        # (zarqa/access.py); scheduler threads have none and see everything.
        self.pool.submit(contextvars.copy_context().run, self._run, job_id, fn)
        return job_id

    def _enqueue(self, kind: str, meta_json: str, task: str, params: dict, deduplicate: bool) -> str:
        from .access import current
        from .tasks import TASKS
        if task not in TASKS:
            raise ValueError(f"unknown task {task!r}")
        a = current()
        params = {**params, "_access": None if a is None else a.to_dict()}
        with self._conn() as conn:
            if deduplicate:
                r = conn.execute("SELECT id FROM jobs WHERE kind=? AND meta=? AND status IN ('queued','running') "
                                 "LIMIT 1", (kind, meta_json)).fetchone()
                if r:
                    return str(r[0])
            job_id = uuid.uuid4().hex[:12]
            conn.execute("INSERT INTO jobs (id, kind, meta, status, created, heartbeat, task, params, control) "
                         "VALUES (?,?,?,?,?,?,?,?,?)",
                         (job_id, kind, meta_json, "queued", _now(), _now(), task, json.dumps(params), "run"))
            # worker '' marks a queued task: a local job manager starting up must leave it alone
            conn.execute("UPDATE jobs SET worker='' WHERE id=?", (job_id,))
            conn.commit()
        return job_id

    def claim(self, worker: str) -> dict | None:
        """Take the oldest queued task (queue mode). Safe with many workers: one transaction holds the lock."""
        conn = self._conn()
        conn.isolation_level = None
        try:
            conn.execute("BEGIN IMMEDIATE")
            r = conn.execute("SELECT id, task, params FROM jobs WHERE status='queued' AND task IS NOT NULL "
                             "ORDER BY created LIMIT 1").fetchone()
            if not r:
                conn.execute("COMMIT")
                return None
            conn.execute("UPDATE jobs SET status='running', worker=?, heartbeat=? WHERE id=?", (worker, _now(), r[0]))
            conn.execute("COMMIT")
        except Exception:
            conn.execute("ROLLBACK")
            raise
        finally:
            conn.close()
        return {"id": r[0], "task": r[1], "params": json.loads(r[2] or "{}")}

    def run_claimed(self, job: dict) -> None:
        """Run a claimed task in this process (a worker), as the person who queued it."""
        from .access import Access, run_as
        from .tasks import run_task
        params = dict(job["params"])
        a = params.pop("_access", None)
        acc = Access.from_dict(a) if a else None
        self._run(job["id"], lambda ctl: run_as(acc, run_task, job["task"], params, ctl, jobs=self),
                  already_running=True)

    def _run(self, job_id: str, fn: Callable[[JobControl], dict], *, already_running: bool = False):
        if not already_running:
            self._set(job_id, status="running", heartbeat=_now())
        ctl = JobControl(self, job_id)
        _current.job_id = job_id   # lets emit_event() tag progress events with this job
        try:
            result = fn(ctl)
            cancelled = self._control.get(job_id) == "cancel" or (
                self.remote_control and self.control_of(job_id) == "cancel")
            status = "cancelled" if cancelled else "done"
            serialized = json.dumps(result)
            if len(serialized) > _MAX_RESULT_CHARS:
                serialized = json.dumps({"truncated": True, "preview": serialized[:_MAX_RESULT_CHARS]})
            self._set(job_id, status=status, heartbeat=_now(), finished=_now(), result=serialized)
        except Exception as exc:
            self._set(job_id, status="error", heartbeat=_now(), finished=_now(),
                      error=f"{exc}\n{traceback.format_exc()[-800:]}")
        finally:
            _current.job_id = None
            self._control.pop(job_id, None)

    # ---- cooperative control ----
    def cancel(self, job_id: str) -> bool:
        if job_id in self._control:
            self._control[job_id] = "cancel"
            self._set_control(job_id, "cancel")
            return True
        if self.remote_control:
            with self._conn() as conn:
                # a queued job is cancelled at once; a running one when its worker next checks
                n = conn.execute("UPDATE jobs SET status='cancelled', control='cancel', finished=? "
                                 "WHERE id=? AND status='queued'", (_now(), job_id)).rowcount
                n += conn.execute("UPDATE jobs SET control='cancel' WHERE id=? AND status='running'",
                                  (job_id,)).rowcount
                conn.commit()
            return n > 0
        return False

    def pause(self, job_id: str) -> bool:
        if self._control.get(job_id) == "run":
            self._control[job_id] = "pause"
            self._set_control(job_id, "pause")
            return True
        return self.remote_control and self._swap_control(job_id, "run", "pause")

    def resume(self, job_id: str) -> bool:
        if self._control.get(job_id) == "pause":
            self._control[job_id] = "run"
            self._set_control(job_id, "run")
            return True
        return self.remote_control and self._swap_control(job_id, "pause", "run")

    def _set_control(self, job_id: str, state: str) -> None:
        try:
            self._set(job_id, control=state)
        except Exception:
            pass

    def _swap_control(self, job_id: str, old: str, new: str) -> bool:
        with self._conn() as conn:
            n = conn.execute("UPDATE jobs SET control=? WHERE id=? AND status IN ('queued','running') "
                             "AND COALESCE(control,'run')=?", (new, job_id, old)).rowcount
            conn.commit()
        return n > 0

    def get(self, job_id: str) -> dict | None:
        with self._conn() as conn:
            conn.row_factory = sqlite3.Row
            row = conn.execute("SELECT * FROM jobs WHERE id=?", (job_id,)).fetchone()
        if not row:
            return None
        d = dict(row)
        d["meta"] = json.loads(d["meta"]) if d["meta"] else {}
        d["result"] = json.loads(d["result"]) if d["result"] else None
        return d

    def list(self, limit: int = 20) -> list[dict]:
        with self._conn() as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(
                "SELECT id, kind, meta, status, created, finished FROM jobs ORDER BY created DESC LIMIT ?",
                (limit,),
            ).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            d["meta"] = json.loads(d["meta"]) if d["meta"] else {}
            out.append(d)
        return out
