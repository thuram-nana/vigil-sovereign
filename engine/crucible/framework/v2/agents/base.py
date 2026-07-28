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

    # ---- agent-to-agent coordination (S5) ----

    def send_message(self, recipient: str, body: str, *, topic: str = "", refs=None) -> int:
        """Send a DIRECTED coordination message to another agent. The blackboard forces the sender to this
        agent's own name (anti-spoof). It is a COORDINATION HINT the recipient may consider on its next
        tick — NEVER a fact/finding/observation, and it authorizes nothing (the recipient still routes any
        action it prompts through its own gate + oracle). Returns the new event id."""
        return self.bb.post(
            engagement=self.engagement_id, kind="agent_message", agent_name=self.name,
            payload={"sender": self.name, "recipient": str(recipient), "topic": str(topic)[:200],
                     "body": str(body)[:2000], "refs": [int(x) for x in (refs or [])]})

    def read_inbox(self, *, since_id: int | None = None) -> list:
        """The directed messages ADDRESSED to this agent, in id order after ``since_id`` (default: this
        agent's own cursor — a durable read-once). Consumed as advisory HINTS; never as evidence."""
        return self.bb.inbox(engagement=self.engagement_id, recipient=self.name,
                             since_id=self._cursor if since_id is None else since_id)
