"""
agents.blackboard — append-only event log shared by every agent.

Per FORGE PROTOCOL § 3.4 critical rules:

  - Append-only: past observations are never edited, only superseded
    by newer events with explicit reference to what they supersede.
  - Single source of truth for engagement state.
  - Every agent reads from and writes to the blackboard.

Storage: SQLite at framework/v2/.blackboard/store.sqlite (gitignored).
The schema in schema.sql carries triggers that refuse UPDATE/DELETE
on the events table.  The Python API below similarly does not expose
any mutating operation other than `post()` and the supersession
helper.
"""

from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

from ..common import logging as v2log
from ..common import paths
from ..common.errors import CrucibleError
from .models import (
    ALL_EVENT_KINDS,
    BlackboardEvent,
    EventKind,
    PAYLOAD_BY_KIND,
    now_iso,
)


_log = v2log.get_logger(__name__)


_SCHEMA_SQL = Path(__file__).parent / "schema.sql"


def blackboard_path() -> Path:
    return paths.v2_root() / ".blackboard" / "store.sqlite"


class BlackboardError(CrucibleError):
    """Anything wrong with a blackboard operation (validation, IO)."""


@dataclass
class BlackboardEventRow:
    """Materialised view of a row, with payload already deserialised."""

    id: int
    engagement_id: int
    kind: EventKind
    agent_name: str
    posted_at: str
    payload: dict[str, Any]
    parent_id: int | None
    supersedes_id: int | None

    @classmethod
    def from_sqlite(cls, row: sqlite3.Row) -> BlackboardEventRow:
        return cls(
            id=int(row["id"]),
            engagement_id=int(row["engagement_id"]),
            kind=row["kind"],
            agent_name=row["agent_name"],
            posted_at=row["posted_at"],
            payload=json.loads(row["payload_json"]),
            parent_id=row["parent_id"],
            supersedes_id=row["supersedes_id"],
        )


# ---------------------------------------------------------------------------
# Blackboard
# ---------------------------------------------------------------------------


class Blackboard:
    """Append-only event log for an engagement."""

    def __init__(self, *, db_path: Path | None = None) -> None:
        self.path = db_path or blackboard_path()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(self.path, detect_types=sqlite3.PARSE_DECLTYPES)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA foreign_keys = ON")
        self._migrate()

    # context manager helpers
    def __enter__(self) -> Blackboard:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def close(self) -> None:
        self._conn.close()

    # ---- migrations ----

    def _migrate(self) -> None:
        self._conn.executescript(_SCHEMA_SQL.read_text(encoding="utf-8"))
        self._conn.commit()

    # ---- engagement registry ----

    def engagement_id(self, slug: str, *, create: bool = True) -> int:
        row = self._conn.execute(
            "SELECT id FROM bb_engagements WHERE slug = ?", (slug,),
        ).fetchone()
        if row is not None:
            return int(row["id"])
        if not create:
            raise BlackboardError(f"no blackboard engagement with slug {slug!r}")
        cur = self._conn.execute(
            "INSERT INTO bb_engagements(slug, started_at) VALUES(?, ?)",
            (slug, now_iso()),
        )
        self._conn.commit()
        eid = int(cur.lastrowid or 0)
        _log.info("agents.blackboard.engagement_started", slug=slug, id=eid)
        return eid

    def close_engagement(self, slug: str) -> None:
        self._conn.execute(
            "UPDATE bb_engagements SET closed_at = ? WHERE slug = ?",
            (now_iso(), slug),
        )
        self._conn.commit()

    # ---- post (the only write path) ----

    def post(
        self,
        *,
        engagement: str | int,
        kind: EventKind,
        agent_name: str,
        payload: dict[str, Any],
        parent_id: int | None = None,
        supersedes_id: int | None = None,
    ) -> int:
        """Insert a new event. Validates payload against the kind's schema."""

        if kind not in ALL_EVENT_KINDS:
            raise BlackboardError(f"unknown event kind {kind!r}")

        # Resolve engagement id
        eid = engagement if isinstance(engagement, int) else self.engagement_id(engagement)

        # Validate payload
        payload_cls = PAYLOAD_BY_KIND[kind]
        try:
            validated = payload_cls.model_validate(payload).model_dump(by_alias=True)
        except Exception as e:
            raise BlackboardError(
                f"payload for kind={kind!r} did not validate: {e}"
            ) from e

        # If supersedes_id is set, verify the target exists and matches kind/engagement.
        if supersedes_id is not None:
            row = self._conn.execute(
                "SELECT engagement_id, kind FROM events WHERE id = ?",
                (supersedes_id,),
            ).fetchone()
            if row is None:
                raise BlackboardError(
                    f"supersedes_id={supersedes_id} not found in events"
                )
            if int(row["engagement_id"]) != eid:
                raise BlackboardError(
                    f"supersedes_id={supersedes_id} belongs to a different engagement"
                )
            if row["kind"] != kind:
                raise BlackboardError(
                    f"supersedes_id={supersedes_id} has kind={row['kind']!r}; "
                    f"new event has kind={kind!r}"
                )

        cur = self._conn.execute(
            """
            INSERT INTO events
              (engagement_id, kind, agent_name, posted_at, payload_json,
               parent_id, supersedes_id)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (eid, kind, agent_name, now_iso(),
             json.dumps(validated, default=str), parent_id, supersedes_id),
        )
        self._conn.commit()
        new_id = int(cur.lastrowid or 0)
        _log.info(
            "agents.blackboard.posted",
            event_id=new_id, engagement_id=eid, kind=kind, agent=agent_name,
            supersedes=supersedes_id,
        )
        return new_id

    def supersede(
        self,
        *,
        old_id: int,
        new_payload: dict[str, Any],
        agent_name: str,
        parent_id: int | None = None,
    ) -> int:
        """Convenience: post a new event with supersedes_id=old_id,
        copying engagement, kind, and (by default) parent_id from the
        old event so the provenance chain stays intact across edits.

        Pass `parent_id` explicitly to override.
        """
        row = self._conn.execute(
            "SELECT engagement_id, kind, parent_id FROM events WHERE id = ?",
            (old_id,),
        ).fetchone()
        if row is None:
            raise BlackboardError(f"cannot supersede missing event id={old_id}")
        if parent_id is None:
            parent_id = row["parent_id"]
        return self.post(
            engagement=int(row["engagement_id"]),
            kind=row["kind"],
            agent_name=agent_name,
            payload=new_payload,
            parent_id=parent_id,
            supersedes_id=old_id,
        )

    # ---- read ----

    def get(self, event_id: int) -> BlackboardEventRow | None:
        row = self._conn.execute(
            "SELECT * FROM events WHERE id = ?", (event_id,),
        ).fetchone()
        return BlackboardEventRow.from_sqlite(row) if row is not None else None

    def read(
        self,
        *,
        engagement: str | int,
        kinds: Iterable[EventKind] | None = None,
        agent: str | None = None,
        since_id: int = 0,
        include_superseded: bool = False,
        limit: int = 1000,
    ) -> list[BlackboardEventRow]:
        """Read events for an engagement. Defaults exclude superseded rows."""
        eid = engagement if isinstance(engagement, int) else self.engagement_id(engagement, create=False)

        sql = ["SELECT e.* FROM events e"]
        params: list[Any] = []
        if not include_superseded:
            sql.append(
                "LEFT JOIN events s ON s.supersedes_id = e.id"
            )
        sql.append("WHERE e.engagement_id = ?")
        params.append(eid)
        if not include_superseded:
            sql.append("AND s.id IS NULL")
        if since_id > 0:
            sql.append("AND e.id > ?")
            params.append(since_id)
        if kinds:
            placeholders = ",".join("?" * len(list(kinds)))
            sql.append(f"AND e.kind IN ({placeholders})")
            params.extend(list(kinds))
        if agent is not None:
            sql.append("AND e.agent_name = ?")
            params.append(agent)
        sql.append("ORDER BY e.id ASC LIMIT ?")
        params.append(limit)

        rows = self._conn.execute(" ".join(sql), tuple(params)).fetchall()
        return [BlackboardEventRow.from_sqlite(r) for r in rows]

    def replay(
        self,
        *,
        engagement: str | int,
        since_id: int = 0,
        kinds: Iterable[EventKind] | None = None,
        include_superseded: bool = False,
        limit: int = 100_000,
    ) -> list[BlackboardEventRow]:
        """Replay the event spine in strict id (logical-clock) order from ``since_id`` — the
        unified subscribe/replay API every subsystem reads the stream through. A consumer polls
        with the last id it saw as ``since_id`` to receive only new events (a durable cursor);
        ``since_id=0`` replays the whole stream. Superseded rows are excluded by default so a
        replay reflects the current view — pass ``include_superseded=True`` for the full,
        never-edited history (the audit view). Read-only; the log stays append-only."""
        return self.read(engagement=engagement, since_id=since_id, kinds=kinds,
                         include_superseded=include_superseded, limit=limit)

    def count(
        self, *, engagement: str | int, kind: EventKind | None = None,
    ) -> int:
        eid = engagement if isinstance(engagement, int) else self.engagement_id(engagement, create=False)
        if kind is None:
            row = self._conn.execute(
                "SELECT COUNT(*) AS c FROM events WHERE engagement_id = ?", (eid,),
            ).fetchone()
        else:
            row = self._conn.execute(
                "SELECT COUNT(*) AS c FROM events "
                "WHERE engagement_id = ? AND kind = ?",
                (eid, kind),
            ).fetchone()
        return int(row["c"])

    def latest_event_id(self, *, engagement: str | int) -> int:
        eid = engagement if isinstance(engagement, int) else self.engagement_id(engagement, create=False)
        row = self._conn.execute(
            "SELECT MAX(id) AS m FROM events WHERE engagement_id = ?", (eid,),
        ).fetchone()
        return int(row["m"] or 0)


def open_blackboard(*, db_path: Path | None = None) -> Blackboard:
    return Blackboard(db_path=db_path)
