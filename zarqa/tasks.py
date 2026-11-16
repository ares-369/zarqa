"""Named background tasks, so a job can be queued in the database and run by any worker.

Each task takes JSON parameters and returns a small JSON result. Modules register their
tasks here as they are added (feed pulls, extraction, investigations, watches).
"""

from __future__ import annotations

from typing import Any


def _cfg():
    from .config import get_config
    return get_config()


def ping(p: dict, ctl, jobs) -> dict:
    """A no-op task, used by tests and ``zarqa doctor`` to check the job runner."""
    return {"ok": True, "echo": str(p.get("echo", ""))[:100]}


TASKS: dict[str, Any] = {"ping": ping}


def run_task(name: str, params: dict, ctl=None, *, jobs=None) -> dict:
    if name not in TASKS:
        raise ValueError(f"unknown task {name!r}")
    return TASKS[name](params, ctl, jobs) or {}
