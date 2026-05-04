"""
planner.budget — three concurrent budgets enforced fail-closed.

Per FORGE PROTOCOL § 3.3:

  - request budget   (rate + total)
  - token budget     (per-engagement cap)
  - wall-clock budget

Hitting any cap pauses execution and surfaces to the operator.

Usage from the planner:

    budget = Budget(request_max=1000, token_max=50_000, wall_clock_max=8*3600)
    budget.start()
    ...
    budget.charge(requests=1, tokens=200)
    if budget.exhausted():  # tuple (bool, reason)
        ...
    seconds_left = budget.wall_clock_remaining()
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field

from ..common import logging as v2log


_log = v2log.get_logger(__name__)


_DEFAULT_REQUEST_MAX = 1000
_DEFAULT_TOKEN_MAX = 50_000.0     # rough proxy for $50 of model spend at sane rates
_DEFAULT_WALL_CLOCK_S = 8 * 3600  # 8h
_DEFAULT_RATE_REQUESTS_PER_MIN = 60


@dataclass
class Budget:
    """Three concurrent budgets. Charges accumulate; checks fail closed."""

    request_max: int = _DEFAULT_REQUEST_MAX
    token_max: float = _DEFAULT_TOKEN_MAX
    wall_clock_max_seconds: float = _DEFAULT_WALL_CLOCK_S
    rate_requests_per_min: int = _DEFAULT_RATE_REQUESTS_PER_MIN

    request_used: int = 0
    token_used: float = 0.0
    started_at: float = 0.0  # monotonic seconds; 0 = not started
    _rate_window_start: float = 0.0
    _rate_window_count: int = 0

    def start(self, started_at: float | None = None) -> None:
        self.started_at = started_at if started_at is not None else time.monotonic()
        self._rate_window_start = self.started_at
        self._rate_window_count = 0
        _log.info(
            "planner.budget.started",
            request_max=self.request_max, token_max=self.token_max,
            wall_clock_max_seconds=self.wall_clock_max_seconds,
        )

    def charge(self, *, requests: int = 0, tokens: float = 0.0) -> None:
        self.request_used += requests
        self.token_used += tokens
        # rolling rate window
        now = time.monotonic()
        if now - self._rate_window_start >= 60.0:
            self._rate_window_start = now
            self._rate_window_count = 0
        self._rate_window_count += requests

    def elapsed_seconds(self) -> float:
        if self.started_at == 0.0:
            return 0.0
        return time.monotonic() - self.started_at

    def wall_clock_remaining(self) -> float:
        return max(0.0, self.wall_clock_max_seconds - self.elapsed_seconds())

    def exhausted(self) -> tuple[bool, str]:
        if self.request_used >= self.request_max:
            return True, f"request budget {self.request_used}/{self.request_max}"
        if self.token_used >= self.token_max:
            return True, f"token budget {self.token_used:.0f}/{self.token_max:.0f}"
        if self.started_at and self.elapsed_seconds() >= self.wall_clock_max_seconds:
            return True, (
                f"wall-clock {int(self.elapsed_seconds())}s/"
                f"{int(self.wall_clock_max_seconds)}s"
            )
        return False, ""

    def can_charge(self, *, requests: int = 0, tokens: float = 0.0) -> bool:
        """Pre-check: would charging push us over a cap? Used by planner to
        skip an action when it would breach mid-flight (fail-closed)."""
        if self.request_used + requests > self.request_max:
            return False
        if self.token_used + tokens > self.token_max:
            return False
        if self.started_at and self.elapsed_seconds() >= self.wall_clock_max_seconds:
            return False
        return True

    def rate_limited(self) -> bool:
        """True if the current rolling minute exceeds rate_requests_per_min."""
        now = time.monotonic()
        if now - self._rate_window_start >= 60.0:
            return False
        return self._rate_window_count >= self.rate_requests_per_min

    def to_dict(self) -> dict[str, float | int]:
        return {
            "request_max": self.request_max,
            "request_used": self.request_used,
            "token_max": self.token_max,
            "token_used": self.token_used,
            "wall_clock_max_seconds": self.wall_clock_max_seconds,
            "elapsed_seconds": int(self.elapsed_seconds()),
            "wall_clock_remaining": int(self.wall_clock_remaining()),
        }
