"""Shared helpers for bridges: HTTP session with auth from env, time ranges, caps."""

from __future__ import annotations

import os
import re
from datetime import datetime, timedelta, timezone

import requests

from .server import ToolInputError

_REL = re.compile(r"^now(?:-(\d{1,5})([mhdw]))?(?:/([mhdw]))?$")   # now, now-7d, now-7d/d (rounded down)
_UNITS = {"m": "minutes", "h": "hours", "d": "days", "w": "weeks"}


def session_from_env(prefix: str = "BRIDGE", verify_tls: bool = True, ca_bundle: str = "") -> requests.Session:
    """Auth comes only from environment variables (set by the connector's env:).

    ``<P>_TOKEN`` -> Bearer; ``<P>_API_KEY`` + optional ``<P>_API_KEY_HEADER``
    (default ``Authorization``); ``<P>_USERNAME``/``<P>_PASSWORD`` -> Basic.
    """
    s = requests.Session()
    s.verify = ca_bundle or verify_tls
    tok = os.getenv(f"{prefix}_TOKEN", "")
    key = os.getenv(f"{prefix}_API_KEY", "")
    user, pw = os.getenv(f"{prefix}_USERNAME", ""), os.getenv(f"{prefix}_PASSWORD", "")
    if tok:
        s.headers["Authorization"] = f"Bearer {tok}"
    elif key:
        s.headers[os.getenv(f"{prefix}_API_KEY_HEADER", "Authorization")] = os.getenv(f"{prefix}_API_KEY_PREFIX", "") + key
    elif user:
        s.auth = (user, pw)
    s.headers["User-Agent"] = "zarqa-bridge"
    return s


def bridge_now() -> datetime:
    """The bridge's "now". ``BRIDGE_NOW`` (ISO-8601) pins it, so work over a frozen copy of data sees
    the same time window on every run (used by benchmarks)."""
    v = os.getenv("BRIDGE_NOW", "").strip()
    if v:
        dt = datetime.fromisoformat(v.replace("Z", "+00:00"))
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    return datetime.now(timezone.utc)


def parse_time(value: str, *, default: str) -> datetime:
    """Accept ISO-8601 or relative ``now``, ``now-24h``, ``now-7d``, with optional rounding down (``now-7d/d``)."""
    v = (value or default).strip()
    now = bridge_now()
    m = _REL.match(v)
    if m:
        t = now - timedelta(**{_UNITS[m.group(2)]: int(m.group(1))}) if m.group(1) else now
        r = m.group(3)
        if r == "m":
            t = t.replace(second=0, microsecond=0)
        elif r == "h":
            t = t.replace(minute=0, second=0, microsecond=0)
        elif r in ("d", "w"):
            t = t.replace(hour=0, minute=0, second=0, microsecond=0)
            if r == "w":
                t -= timedelta(days=t.weekday())
        return t
    try:
        dt = datetime.fromisoformat(v.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ToolInputError(f"time {v!r} must be ISO-8601 or like now-24h") from exc
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def time_window(args: dict, max_days: int) -> tuple[datetime, datetime]:
    start = parse_time(str(args.get("time_from", "")), default="now-24h")
    end = parse_time(str(args.get("time_to", "")), default="now")
    if end <= start:
        raise ToolInputError("time_to must be after time_from")
    if end - start > timedelta(days=max_days):
        raise ToolInputError(f"time window is longer than the {max_days}-day limit; narrow it")
    return start, end


def baseline_window(args: dict, max_days: int) -> tuple[datetime, datetime, datetime]:
    """(baseline_start, recent_start, recent_end) for first-seen checks: the recent window comes from
    time_from/time_to, the baseline is the ``baseline_days`` before it. Both together stay within max_days."""
    start, end = time_window(args, max_days)
    try:
        days = float(args.get("baseline_days") or 14)
    except (TypeError, ValueError) as exc:
        raise ToolInputError("baseline_days must be a number") from exc
    days = max(1.0, days)
    if (end - start) + timedelta(days=days) > timedelta(days=max_days):
        raise ToolInputError(f"recent window plus baseline_days is longer than the {max_days}-day limit; shorten one")
    return start - timedelta(days=days), start, end


def cap(value, default: int, maximum: int) -> int:
    try:
        n = int(value if value is not None else default)
    except (TypeError, ValueError) as exc:
        raise ToolInputError("size must be an integer") from exc
    return max(1, min(n, maximum))


def check_status(r: requests.Response) -> None:
    if r.status_code in (401, 403):
        raise PermissionError(f"HTTP {r.status_code}: the source refused the bridge's credentials")
    if r.status_code >= 400:
        raise RuntimeError(f"HTTP {r.status_code}: {r.text[:300]}")


def _flatten(d, prefix: str = "") -> dict:
    out: dict = {}
    for k, v in (d or {}).items():
        key = f"{prefix}{k}"
        if isinstance(v, dict):
            out.update(_flatten(v, key + "."))
        else:
            out[key] = v
    return out


def _empty(v) -> bool:
    return v is None or v == "" or v == [] or v == {}


def _cut(v, limit: int):
    if isinstance(v, str) and len(v) > limit:
        return v[:limit] + f"...(+{len(v) - limit} chars)"
    return v


def compact_hits(hits: list[dict], *, max_value: int = 600, drop: tuple[str, ...] = ("_id", "_index")) -> dict:
    """Make search hits cheaper to read without losing information the model needs.

    Hits are flattened to dotted field names (the names queries use), empty values are dropped,
    very long values are cut, and every field with the same value in all hits is moved to
    ``common`` and shown once. Each hit keeps only what differs.
    """
    rows = [{k: _cut(v, max_value) for k, v in _flatten(h).items() if not _empty(v) and k not in drop}
            for h in hits]
    if len(rows) < 2:
        return {"common": {}, "hits": rows}
    keys = set(rows[0])
    for r in rows[1:]:
        keys &= set(r)
    common = {k: rows[0][k] for k in sorted(keys) if all(r[k] == rows[0][k] for r in rows[1:])}
    return {"common": common, "hits": [{k: v for k, v in r.items() if k not in common} for r in rows]}

