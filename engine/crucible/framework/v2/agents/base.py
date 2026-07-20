"""
agents.base — common Agent interface.

Every specialist agent subclasses `Agent`, sets `name`, and
implements `should_run()` and `step()`. The coordinator schedules
them via these two methods. Agents read from and write to the
blackboard exclusively; no agent calls another agent directly.

Per FORGE PROTOCOL § 3.4 critical rules:
  - Each agent has a defined role and stays in lane.
  - The blackboard is append-only; agents post new events rather
    than editing in place.
  - The critique-agent is mandatory; findings are not promoted to
    the report until critique-agent has signed off.
"""

from __future__ import annotations

import abc
from typing import Any

from ..common import logging as v2log
from .blackboard import Blackboard


class Agent(abc.ABC):
    """Base class for every agent under MAO.

    Subclasses set the class-level `name` attribute. They keep their
    own per-engagement cursor (`self._cursor`) of the last event id
    they consumed.  Subclasses do not edit the blackboard; they only
    `bb.post(...)`.
    """

    name: str = "abstract-agent"

    def __init__(self, blackboard: Blackboard, engagement_slug: str) -> None:
        self.bb = blackboard
        self.slug = engagement_slug
        self.engagement_id = blackboard.engagement_id(engagement_slug)
        self._cursor: int = 0
        self._log = v2log.get_logger(f"agent.{self.name}")

    @abc.abstractmethod
    def should_run(self) -> bool:
        """Return True if there is work for this agent right now.

        Cheap; called every tick. Implementations typically check
        `bb.latest_event_id() > self._cursor` plus class-specific
        conditions (e.g., presence of unclaimed hypotheses).
        """

    @abc.abstractmethod
    def step(self) -> int:
        """Do one unit of work; return the number of events posted.

        Implementations should advance `self._cursor` to whatever
        event id they consumed up through, so they don't reprocess
        on the next tick.
        """

    # ---- helpers commonly needed by subclasses ----

    def _new_events(self, kinds: tuple[str, ...] | None = None) -> list:
        """Events posted to this engagement since this agent's cursor."""
        from .models import EventKind
        events = self.bb.read(
            engagement=self.engagement_id,
            since_id=self._cursor,
            kinds=tuple(kinds) if kinds else None,  # type: ignore[arg-type]
        )
        return events

    def _advance_cursor(self) -> None:
        """Move the cursor to the latest event id seen."""
        self._cursor = self.bb.latest_event_id(engagement=self.engagement_id)
