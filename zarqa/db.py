"""Storage: SQLite by default, PostgreSQL as an option chosen at install time.

SQLite needs nothing installed and is right for one machine. PostgreSQL lets
several machines (servers and workers) share one database:

    pip install 'zarqa[postgres]'
    zarqa init --database postgres          # or set database.url in config.yaml

    database:
      url: "postgresql://zarqa@db.example.org/zarqa"   # password in .env (ZARQA_DB_URL or PGPASSWORD)
      schema: zarqa

Stores keep writing the same SQL. With PostgreSQL, ``connect()`` returns a
connection that looks like ``sqlite3`` to them and adapts the few differences
(placeholders, auto-increment ids, PRAGMA table_info, LIKE, write locks, the
reserved word ``user``). The full-text index and the audit triggers have their
own PostgreSQL versions in their stores.
"""

from __future__ import annotations

import hashlib
import os
import re
import sqlite3
import threading
from pathlib import Path
from typing import Any

_settings: dict[str, Any] = {"url": None, "schema": "zarqa"}
_pools: dict[str, Any] = {}
_schemas_made: set[tuple[str, str]] = set()
_serial: dict[tuple[str, str, str], bool] = {}
_lock = threading.Lock()


def configure(url: str | None, schema: str = "zarqa") -> None:
    """Called when the config loads. ``url`` empty or None: SQLite."""
    url = (url or "").strip() or None
    if url and not url.startswith(("postgresql://", "postgres://")):
        raise ValueError("database.url must start with postgresql:// (leave it empty for SQLite)")
    if not re.fullmatch(r"[a-z_][a-z0-9_]{0,62}", schema or ""):
        raise ValueError("database.schema must be lowercase letters, digits or _")
    _settings.update(url=url, schema=schema)


def url() -> str | None:
    return _settings["url"] or os.getenv("ZARQA_DB_URL") or None


def schema() -> str:
    return _settings["schema"] if _settings["url"] else (os.getenv("ZARQA_DB_SCHEMA") or _settings["schema"])


def child_env() -> dict[str, str]:
    """Environment for Zarqa's own bridge processes (local intel), so they open the same database."""
    if not is_pg():
        return {}
    env = {"ZARQA_DB_URL": url() or "", "ZARQA_DB_SCHEMA": schema()}
    if os.getenv("ZARQA_DB_SCHEMA_PER_DIR"):
        env["ZARQA_DB_SCHEMA_PER_DIR"] = "1"
    return env


def is_pg() -> bool:
    return bool(url())


def kind() -> str:
    return "postgres" if is_pg() else "sqlite"


def _schema_for(path) -> str:
    # Tests run the whole suite against one PostgreSQL database: give each data folder its own schema.
    if os.getenv("ZARQA_DB_SCHEMA_PER_DIR"):
        return "t_" + hashlib.sha1(str(Path(path).resolve().parent).encode(), usedforsecurity=False).hexdigest()[:16]
    return schema()


def connect(path, timeout: float = 10):
    """A connection for the store at ``path``: sqlite3 (default) or the PostgreSQL adapter."""
    if not is_pg():
        c = sqlite3.connect(path, timeout=timeout)
        c.row_factory = sqlite3.Row
        return c
    return PgConnection(url(), _schema_for(path))


def add_column(c, table: str, column: str, ddl: str) -> None:
    """Add a column if it is missing. Safe when several processes upgrade the same database at once:
    one of them adds it, the others see "duplicate column" (or "already exists") and carry on."""
    if not re.fullmatch(r"\w+", table) or not re.fullmatch(r"\w+", column):
        raise ValueError("bad table or column name")
    if column in {r[1] for r in c.execute(f"PRAGMA table_info({table})")}:
        return
    try:
        c.execute(f"ALTER TABLE {table} ADD COLUMN {column} {ddl}")
    except sqlite3.OperationalError as exc:
        if "duplicate column" not in str(exc).lower() and "already exists" not in str(exc).lower():
            raise
    except sqlite3.DatabaseError as exc:      # PostgreSQL errors arrive as DatabaseError through the adapter
        if "already exists" not in str(exc).lower():
            raise


# ---------------------------------------------------------------- PostgreSQL


class Row(tuple):
    """Like sqlite3.Row: r[0], r["name"], dict(r), r.keys()."""

    def __new__(cls, names, values):
        r = super().__new__(cls, values)
        r._names = names
        return r

    def keys(self):
        return list(self._names)

    def __getitem__(self, k):
        if isinstance(k, str):
            try:
                return tuple.__getitem__(self, self._names.index(k))
            except ValueError:
                raise IndexError(f"no column {k!r}") from None
        return tuple.__getitem__(self, k)


def _row_factory(cursor):
    names = [d.name for d in cursor.description or []]
    return lambda values: Row(names, values)


def _pool(dsn: str):
    """One small pool per database; the schema is chosen on each checkout."""
    with _lock:
        if dsn not in _pools:
            try:
                from psycopg_pool import ConnectionPool
            except ImportError as exc:
                raise RuntimeError("PostgreSQL needs the postgres extra: pip install 'zarqa[postgres]'") from exc
            _pools[dsn] = ConnectionPool(dsn, min_size=1, max_size=int(os.getenv("ZARQA_DB_POOL", "10")),
                                         timeout=float(os.getenv("ZARQA_DB_TIMEOUT", "10")), open=True,
                                         kwargs={"row_factory": _row_factory, "autocommit": False})
        return _pools[dsn]


def _use_schema(conn, dsn: str, schema: str) -> None:
    if (dsn, schema) not in _schemas_made:
        try:
            conn.execute(f'CREATE SCHEMA IF NOT EXISTS "{schema}"')
            conn.commit()
        except Exception as exc:          # two connections creating it at once: PostgreSQL reports a duplicate
            conn.rollback()
            if "already exists" not in str(exc) and "duplicate key" not in str(exc):
                raise
        _schemas_made.add((dsn, schema))
    conn.execute(f'SET search_path TO "{schema}"')
    conn.commit()


_QUOTED = re.compile(r"'(?:[^']|'')*'")


def _outside_quotes(sql: str, fn) -> str:
    out, last = [], 0
    for m in _QUOTED.finditer(sql):
        out.append(fn(sql[last:m.start()]))
        out.append(m.group(0).replace("%", "%%"))
        last = m.end()
    out.append(fn(sql[last:]))
    return "".join(out)


def translate(sql: str) -> str:
    """SQLite statement -> PostgreSQL statement (the subset Zarqa's stores use)."""
    def plain(s: str) -> str:
        s = s.replace("%", "%%").replace("?", "%s")
        s = re.sub(r"\bINTEGER\s+PRIMARY\s+KEY\s+AUTOINCREMENT\b", "BIGSERIAL PRIMARY KEY", s, flags=re.I)
        s = re.sub(r"\bINTEGER\b", "BIGINT", s)
        s = re.sub(r"\bNOT\s+LIKE\b", "NOT ILIKE", s, flags=re.I)
        s = re.sub(r"(?<!I)\bLIKE\b", "ILIKE", s)
        s = re.sub(r'(?<![."\w])user(?![\w"(])', '"user"', s)
        return s
    return _outside_quotes(sql, plain)


def _params(params) -> tuple:
    return tuple(int(p) if isinstance(p, bool) else p for p in (params or ()))


def _err(exc: Exception) -> Exception:
    """psycopg errors as the sqlite3 errors the stores already handle."""
    try:
        import psycopg
        if isinstance(exc, psycopg.errors.IntegrityError):
            return sqlite3.IntegrityError(str(exc))
        if isinstance(exc, (psycopg.errors.UndefinedTable, psycopg.errors.UndefinedColumn)):
            return sqlite3.OperationalError(str(exc))
        if isinstance(exc, psycopg.errors.RaiseException):
            return sqlite3.DatabaseError(str(exc))
    except ImportError:          # pragma: no cover
        pass
    return sqlite3.DatabaseError(str(exc))


class PgCursor:
    def __init__(self, rows=None, rowcount: int = -1, lastrowid=None):
        self._rows = list(rows or [])
        self.rowcount = rowcount
        self.lastrowid = lastrowid

    def fetchone(self):
        return self._rows.pop(0) if self._rows else None

    def fetchall(self):
        rows, self._rows = self._rows, []
        return rows

    def __iter__(self):
        while self._rows:
            yield self._rows.pop(0)


class PgConnection:
    """sqlite3-like connection on a pooled PostgreSQL connection. Use it as ``with connect(...) as c:``
    or call close(); either returns it to the pool."""

    def __init__(self, dsn: str, schema: str):
        self.schema = schema
        self._pool = _pool(dsn)
        self._conn = self._pool.getconn()
        try:
            _use_schema(self._conn, dsn, schema)
        except Exception:
            self._pool.putconn(self._conn)
            self._conn = None
            raise
        self.isolation_level = ""        # accepted and ignored; transactions are explicit below
        self.row_factory = None

    # -- sqlite3 API subset --
    def execute(self, sql: str, params=()) -> PgCursor:
        s = sql.strip()
        up = s.upper()
        try:
            if up.startswith("PRAGMA"):
                return self._pragma(s)
            if up in ("BEGIN", "BEGIN IMMEDIATE", "BEGIN EXCLUSIVE"):
                # SQLite's write lock: one writer at a time for this schema
                self._conn.execute("SELECT pg_advisory_xact_lock(hashtext(%s))", (f"zarqa:{self.schema}",))
                return PgCursor()
            if up == "COMMIT":
                self._conn.commit()
                return PgCursor()
            if up == "ROLLBACK":
                self._conn.rollback()
                return PgCursor()
            q = translate(s)
            want_id = up.startswith("INSERT") and " RETURNING " not in up and self._serial_table(s)
            if want_id:
                q += " RETURNING id"
            cur = self._conn.execute(q, _params(params))
            rows = cur.fetchall() if cur.description else []
            if want_id:
                return PgCursor([], cur.rowcount, rows[0][0] if rows else None)
            return PgCursor(rows, cur.rowcount)
        except Exception as exc:
            if exc.__class__.__module__.startswith("psycopg"):
                self._conn.rollback()
                raise _err(exc) from exc
            raise

    def executescript(self, script: str) -> None:
        for stmt in _split(script):
            self.execute(stmt)
        self.commit()

    def commit(self) -> None:
        self._conn.commit()

    def rollback(self) -> None:
        self._conn.rollback()

    def close(self) -> None:
        if self._conn is not None:
            try:
                self._conn.rollback()
            finally:
                self._pool.putconn(self._conn)
                self._conn = None

    def __enter__(self):
        return self

    def __exit__(self, exc_type, *_):
        if self._conn is None:
            return False
        if exc_type is None:
            self._conn.commit()
        else:
            self._conn.rollback()
        self.close()
        return False

    def __del__(self):
        try:
            self.close()
        except Exception:
            pass

    # -- helpers --
    def _pragma(self, s: str) -> PgCursor:
        m = re.match(r"PRAGMA\s+table_info\((\w+)\)", s, re.I)
        if not m:
            return PgCursor()            # journal_mode, busy_timeout: nothing to do
        cur = self._conn.execute("SELECT ordinal_position, column_name FROM information_schema.columns "
                                 "WHERE table_schema = current_schema() AND table_name = %s "
                                 "ORDER BY ordinal_position", (m.group(1).lower(),))
        return PgCursor([(r[0] - 1, r[1]) for r in cur.fetchall()])

    def _serial_table(self, sql: str) -> bool:
        m = re.match(r"INSERT\s+INTO\s+(\w+)", sql, re.I)
        if not m:
            return False
        key = (str(self._pool), self.schema, m.group(1).lower())
        if key not in _serial:
            r = self._conn.execute("SELECT column_default FROM information_schema.columns WHERE table_schema = "
                                   "current_schema() AND table_name = %s AND column_name = 'id'",
                                   (m.group(1).lower(),)).fetchone()
            _serial[key] = bool(r and r[0] and str(r[0]).startswith("nextval"))
        return _serial[key]


def _split(script: str) -> list[str]:
    parts, buf, quote = [], [], False
    for ch in script:
        if ch == "'":
            quote = not quote
        if ch == ";" and not quote:
            parts.append("".join(buf))
            buf = []
        else:
            buf.append(ch)
    parts.append("".join(buf))
    return [p.strip() for p in parts if p.strip()]
