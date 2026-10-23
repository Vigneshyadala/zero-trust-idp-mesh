"""Sliding-window rate limiter, in memory (one process).

Configured with IDP_RATE_LIMIT="<requests>/<seconds>", default "30/60".
Set it to "off" to disable. Blocked attempts are not recorded, so an
attacker cannot extend their own lockout by hammering the endpoint.
"""
from __future__ import annotations

import math
import os
import threading
import time
from collections import deque

MAX_KEYS = 10_000


class RateLimiter:
    def __init__(self, limit: int, window: int, clock=time.monotonic) -> None:
        self._limit = limit
        self._window = window
        self._clock = clock
        self._hits: dict[str, deque] = {}
        self._lock = threading.Lock()

    def check(self, key: str) -> tuple[bool, int]:
        """Return (allowed, retry_after_seconds)."""
        now = self._clock()
        with self._lock:
            if len(self._hits) > MAX_KEYS:
                self._sweep(now)
            hits = self._hits.setdefault(key, deque())
            while hits and now - hits[0] >= self._window:
                hits.popleft()
            if len(hits) >= self._limit:
                return False, max(1, math.ceil(self._window - (now - hits[0])))
            hits.append(now)
            return True, 0

    def _sweep(self, now: float) -> None:
        stale = [k for k, h in self._hits.items() if not h or now - h[-1] >= self._window]
        for k in stale:
            del self._hits[k]


def limiter_from_env() -> RateLimiter | None:
    raw = os.getenv("IDP_RATE_LIMIT", "30/60").strip().lower()
    if raw in ("", "0", "off"):
        return None
    limit, window = raw.split("/")
    return RateLimiter(int(limit), int(window))


_limiter: RateLimiter | None = limiter_from_env()


def get_limiter() -> RateLimiter | None:
    return _limiter


def set_limiter(limiter: RateLimiter | None) -> None:
    global _limiter
    _limiter = limiter