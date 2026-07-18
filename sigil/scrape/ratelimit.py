"""RateLimiter (Phase 8, WS-E E-ii) — the per-host politeness primitive SIGIL lacked. Enforces a
minimum interval between requests to the SAME host (keyed on the normalized host from ScrapeScope, so
two spellings can't split a host's budget), serialized per host (concurrency 1/host). The site's
robots `crawl-delay` raises the interval (`max(our_min, site_delay)`). The clock + sleep are
injectable so tests assert the COMPUTED wait deterministically without real sleeping. This is
POLITENESS, never evasion — throttling protects the third party, per doctrine §VI."""
from __future__ import annotations

import threading
import time
from typing import Callable, Dict


class RateLimiter:
    def __init__(self, min_interval: float = 1.0, *,
                 clock: Callable[[], float] = time.monotonic,
                 sleep: Callable[[float], None] = time.sleep):
        self.min_interval = float(min_interval)
        self._clock = clock
        self._sleep = sleep
        self._last: Dict[str, float] = {}
        self._locks: Dict[str, threading.Lock] = {}
        self._guard = threading.Lock()

    def _lock_for(self, host: str) -> threading.Lock:
        with self._guard:
            return self._locks.setdefault(host, threading.Lock())

    def wait_time(self, host: str, *, host_min: float = 0.0) -> float:
        """The seconds a request to `host` must wait right now (does not mutate). `host_min` = the
        site's crawl-delay, which raises the floor."""
        interval = max(self.min_interval, float(host_min))
        last = self._last.get(host)
        if last is None:
            return 0.0
        return max(0.0, interval - (self._clock() - last))

    def acquire(self, host: str, *, host_min: float = 0.0) -> float:
        """Block (via the injected sleep) until it is polite to fetch `host`; record the fetch time.
        Returns the seconds actually waited. Serialized per host."""
        with self._lock_for(host):
            wait = self.wait_time(host, host_min=host_min)
            if wait > 0:
                self._sleep(wait)
            self._last[host] = self._clock()
            return wait
