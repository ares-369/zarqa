"""Background schedule inside the server: pull sources when due, expire old indicators.

One thread, a 60-second tick. Work runs as jobs (see jobs.py), so it shows on the Jobs page and is
never run twice at once for the same source.
"""

from __future__ import annotations

import logging
import threading
import time

_log = logging.getLogger("zarqa.scheduler")


class Scheduler:
    def __init__(self, cfg_getter, jobs, *, tick_sec: float = 60.0):
        self._cfg = cfg_getter
        self.jobs = jobs
        self.tick_sec = tick_sec
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._last_expire = 0.0

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._thread = threading.Thread(target=self._loop, name="zarqa-scheduler", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()

    def _loop(self) -> None:
        while not self._stop.wait(self.tick_sec):
            try:
                self.tick()
            except Exception as exc:          # keep the schedule alive whatever one tick does
                _log.warning("scheduler tick failed: %s", exc)

    def tick(self) -> list[str]:
        from .access import run_as, scheduler_access
        from .intel.service import due_sources
        from .intel.store import store_for
        cfg = self._cfg()
        store = store_for(cfg)
        started = []
        acc = scheduler_access(cfg)
        for name in due_sources(cfg, store):
            jid = run_as(acc, self.jobs.submit, "pull", {"source": name}, None, task="pull",
                         params={"source": name, "actor": "scheduler"})
            started.append(jid)
        from .brand.watch import due as brand_due
        from .brand.watch import store_for as brand_store
        if brand_due(cfg, brand_store(cfg)):
            started.append(run_as(acc, self.jobs.submit, "brand", {"brand": "watch"}, None, task="brand", params={}))
        if time.monotonic() - self._last_expire > 3600:
            self._last_expire = time.monotonic()
            store.expire()
        return started
