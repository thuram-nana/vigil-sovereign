"""
planner.watchdog — monitors planner for pathological behaviour.

Per FORGE PROTOCOL § 3.3:
  - watches for thrashing on dead branches
  - watches for drift away from charter scope
  - watches for suspiciously high error rates
  - watches for opsec posture violations

The watchdog has authority to halt the planner; the planner does
NOT have authority to disable the watchdog. Concretely: the
watchdog owns its own `halted` flag, and the planner queries it
between steps. There is no API on this class to clear `halted`.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from typing import Iterable

from ..common import ethics
from ..common import logging as v2log
from ..common.errors import OutOfScope
from .budget import Budget
from .goal_tree import GoalTree


_log = v2log.get_logger(__name__)


@dataclass
class Watchdog:
    """Read-only-from-the-planner monitor.  The planner cannot reach
    `halted` to clear it; only this class does, and only on construction.
    """

    engagement_slug: str
    tree: GoalTree
    budget: Budget

    # thresholds
    thrash_window: int = 30                # last N decisions
    thrash_min_unique: int = 3             # if fewer than this many unique nodes touched, halt
    error_rate_window: int = 50            # last N tick reports
    error_rate_threshold: float = 0.5      # >50% errors → halt

    # state — private
    _halted: bool = field(default=False, init=False)
    _halt_reason: str = field(default="", init=False)
    _recent_node_ids: deque = field(default_factory=lambda: deque(maxlen=64), init=False)
    _recent_errors: deque = field(default_factory=lambda: deque(maxlen=64), init=False)

    @property
    def halted(self) -> bool:
        return self._halted

    @property
    def halt_reason(self) -> str:
        return self._halt_reason

    def _halt(self, reason: str) -> None:
        if not self._halted:
            self._halted = True
            self._halt_reason = reason
            _log.warning(
                "planner.watchdog.halt",
                slug=self.engagement_slug, reason=reason,
            )

    def record_step(self, *, node_id: int, error: bool) -> None:
        self._recent_node_ids.append(node_id)
        self._recent_errors.append(1 if error else 0)

    def check(self, *, target_urls_in_step: Iterable[str] = ()) -> None:
        """Run all checks. Sets `halted` if any fires."""
        if self._halted:
            return

        # 1. budget
        ex, reason = self.budget.exhausted()
        if ex:
            self._halt(f"budget: {reason}")
            return

        # 2. thrashing
        if len(self._recent_node_ids) >= self.thrash_window:
            recent = list(self._recent_node_ids)[-self.thrash_window:]
            unique = len(set(recent))
            if unique < self.thrash_min_unique:
                self._halt(
                    f"thrash: {self.thrash_window} steps touched only "
                    f"{unique} unique nodes (threshold {self.thrash_min_unique})"
                )
                return

        # 3. error rate
        if len(self._recent_errors) >= self.error_rate_window:
            recent = list(self._recent_errors)[-self.error_rate_window:]
            rate = sum(recent) / len(recent)
            if rate >= self.error_rate_threshold:
                self._halt(
                    f"error rate {rate:.0%} >= {self.error_rate_threshold:.0%} "
                    f"over last {self.error_rate_window} steps"
                )
                return

        # 4. scope drift — every URL touched this step must be in charter scope.
        # If the engagement has a signed charter, enforce; otherwise charter
        # might be a draft and we skip (intake-time gate handled this).
        try:
            ethics.is_charter_signed(self.engagement_slug)
        except Exception:
            return
        for url in target_urls_in_step:
            if not url:
                continue
            try:
                ethics.require_in_scope(self.engagement_slug, url)
            except OutOfScope as e:
                self._halt(f"scope drift: {e}")
                return
