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
        # target_event_id -> the target finding's verified_by_oracle (True=fact, False=lead). Populated as
        # finding events stream by; a reconnect (cursor past the finding) falls back to a direct bb.get().
        # Used ONLY to CALIBRATE the display of a critic verdict (below) — never to change the spine.
        self._finding_grounding: dict[int, bool] = {}

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
            ev = _row_to_event(row)
            if row.kind == "finding":
                self._finding_grounding[int(row.id)] = bool((row.payload or {}).get("verified_by_oracle"))
            elif row.kind == "critic_verdict":
                self._calibrate_critic(ev, bb)
            out.append((int(row.id), ev))
        return out

    # ---- display calibration (view-only; the stored spine is never touched) ----

    def _target_grounding(self, target_event_id: Any, bb: Any) -> bool | None:
        """Is a critic verdict's TARGET finding a fact (True) or a lead (False)? None when the target is
        not a known finding. Cached; a cache miss (reconnect past the finding) reads the row directly."""
        try:
            tid = int(target_event_id)
        except (TypeError, ValueError):
            return None
        if tid in self._finding_grounding:
            return self._finding_grounding[tid]
        try:
            tgt = bb.get(tid)
        except Exception:
            tgt = None
        if tgt is not None and getattr(tgt, "kind", None) == "finding":
            g = bool((tgt.payload or {}).get("verified_by_oracle"))
            self._finding_grounding[tid] = g
            return g
        return None

    def _calibrate_critic(self, ev: dict[str, Any], bb: Any) -> None:
        """Annotate a critic_verdict's EMITTED view (never the stored row) so the UI can render an
        objection to a LEAD calmly instead of as an alarm. Doctrine-preserving: a critic is advisory and
        the oracle stays the sole authority — this only changes how the verdict READS.

          * A verdict about a finding that never claimed to be a fact (target is a LEAD) is ROUTINE noise —
            a lead cannot be promoted or demoted by a critic. It is flagged ``routine`` so the feed can fold
            the flood, and an OBJECT on a lead is additionally marked ``expected`` with a calm note and a
            downgraded ``display_severity`` ('major' -> 'info'): the finding was correctly a lead all along.
          * A verdict about a CONFIRMED fact (target is a FACT) is NOT routine and keeps its real severity —
            an object here is a genuine demotion (a fact whose proof did not re-ground) and must stay loud."""
        pl = ev.get("payload")
        if not isinstance(pl, dict):
            return
        verdict = str(pl.get("verdict") or "")
        sev = str(pl.get("severity") or "info")
        grounded = self._target_grounding(pl.get("target_event_id"), bb)
        pl = dict(pl)  # copy: enrich the view, leave the append-only row untouched
        pl["target_grounding"] = "fact" if grounded is True else ("lead" if grounded is False else None)
        if grounded is False:
            pl["routine"] = True
            if verdict == "object":
                pl["display_severity"] = "info"
                pl["expected"] = True
                pl["display_note"] = "lead — not oracle-grounded (expected)"
            else:
                pl["display_severity"] = sev
                pl["expected"] = False
        else:
            pl["routine"] = False
            pl["expected"] = False
            pl["display_severity"] = sev
        ev["payload"] = pl

    def close(self) -> None:
        if self._bb is not None:
            try:
                self._bb.close()
            except Exception:
                pass
            self._bb = None
