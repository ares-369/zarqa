"""Per-connector pacing: evenly spaced calls, ``rate_per_min`` per connector."""

from __future__ import annotations

import threading
import time
from collections.abc import Callable


class Pacer:
    def __init__(self, clock: Callable[[], float] = time.monotonic, sleep: Callable[[float], None] = time.sleep):
        self._next: dict[str, float] = {}
        self._lock = threading.Lock()
        self._clock, self._sleep = clock, sleep

    def acquire(self, key: str, per_min: int) -> float:
        """Block until ``key`` may make its next call; returns seconds waited."""
        gap = 60.0 / max(1, per_min)
        with self._lock:
            now = self._clock()
            slot = max(now, self._next.get(key, now))
            self._next[key] = slot + gap
        wait = slot - now
        if wait > 0:
            self._sleep(wait)
        return wait
