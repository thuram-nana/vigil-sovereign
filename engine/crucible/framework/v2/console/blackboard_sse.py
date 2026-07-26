"""
console.blackboard_sse — tail the append-only agent blackboard for the Live view.

The engine's ``engage --spine`` mirrors every agent event — the 14 kinds (observation,
hypothesis, plan, action, result, finding, critique, decision, reward, critic_verdict,
reflection, refusal, tool_call, tool_result) — onto the append-only blackboard
(``agents.blackboard.Blackboard``) under ``engagement=<slug>``. This module does an
incremental, read-only replay of that spine for one engagement so the console can stream
it as Server-Sent Events with a DURABLE cursor: each event is emitted as
``id: <event_id>`` so an ``EventSource`` reconnect resumes from ``Last-Event-ID`` without
gaps or replays.

Read-only by construction: it only calls ``Blackboard.replay(since_id=…)`` (the unified
replay API) — it never posts, supersedes, or edits. The blackboard stays append-only; a
dead reader can never perturb the engine.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any


def _row_to_event(row: Any) -> dict[str, Any]:
    """A JSON-serializable view of one BlackboardEventRow — the fields the Live timeline and
    graph render (kind, agent, payload, and the provenance links). ``id`` rides the SSE
    ``id:`` line separately (the durable cursor), so it is included here too for the client."""
    return {
        "id": row.id,
        "kind": row.kind,
        "agent": row.agent_name,
        "posted_at": row.posted_at,
        "payload": row.payload,
        "parent_id": row.parent_id,
        "supersedes_id": row.supersedes_id,
    }


class BlackboardTailer:
    """Incremental, read-only replay of one engagement's blackboard spine. ``read_new()``
    returns ``(event_id, event_dict)`` pairs appended since the last call and advances the
    cursor. Resilient: an engagement that has not been registered yet (no ``--spine`` run has
    posted for this slug) yields ``[]`` until it appears; any read error yields ``[]`` rather
    than breaking the stream.

    The blackboard is opened lazily on first read so constructing a tailer for a not-yet-started
    engagement is free. ``since_id`` is the durable cursor a reconnecting client supplies (from
    ``Last-Event-ID`` or ``?since=``); ``0`` replays the whole spine for that engagement.
    """

    def __init__(self, slug: str, *, since_id: int = 0, db_path: Path | None = None) -> None:
        self._slug = slug or ""
        self._cursor = max(0, int(since_id or 0))
        self._db_path = db_path
        self._bb: Any = None
        self._open_failed = False

    def _blackboard(self) -> Any:
        if self._bb is None and not self._open_failed:
            try:
                from ..agents.blackboard import open_blackboard
                self._bb = open_blackboard(db_path=self._db_path)
            except Exception:
                self._open_failed = True
                self._bb = None
        return self._bb

    def read_new(self) -> list[tuple[int, dict[str, Any]]]:
        if not self._slug:
            return []
        bb = self._blackboard()
        if bb is None:
            return []
        try:
            # replay(since_id=cursor) is the unified, read-only cursor API. create=False under the
            # hood raises for an unregistered engagement — a not-yet-started run — which we treat as
            # "nothing yet" (empty), retrying on the next poll once the engine registers the slug.
            rows = bb.replay(engagement=self._slug, since_id=self._cursor)
        except Exception:
            return []
        out: list[tuple[int, dict[str, Any]]] = []
        for row in rows:
            self._cursor = max(self._cursor, int(row.id))
            out.append((int(row.id), _row_to_event(row)))
        return out

    def close(self) -> None:
        if self._bb is not None:
            try:
                self._bb.close()
            except Exception:
                pass
            self._bb = None
