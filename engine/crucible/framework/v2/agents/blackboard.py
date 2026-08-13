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
from typing import Any, Iterable, Mapping

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
        paths.secure_dir(self.path.parent)            # owner-only spine dir (X2)
        self._conn = sqlite3.connect(self.path, detect_types=sqlite3.PARSE_DECLTYPES)
        paths.secure_existing(self.path)              # 0600 the spine DB (dir 0700 guards WAL sidecars)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA foreign_keys = ON")
        # X3: under WAL (set in schema.sql), synchronous=NORMAL drops the per-commit fsync
        # (durable across app crashes; only an OS/power crash can lose the last commit) — the
        # standard, safe WAL setting. The append-only log, its ids/posted_at and the immutability
        # triggers are unaffected; only the fsync per post() is elided.
        self._conn.execute("PRAGMA synchronous = NORMAL")
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
        # A v1 store predates the S5 `agent_message` kind, whose CHECK is baked into the events table at
        # CREATE time — `CREATE TABLE IF NOT EXISTS` cannot widen an existing CHECK. So rebuild the table for
        # a v1 DB (append-only preserved: every row copied verbatim; the new kind is purely additive).
        row = self._conn.execute(
            "SELECT value FROM bb_schema_meta WHERE key = 'version'").fetchone()
        if row is not None and int(row["value"]) < 2:
            self._migrate_to_v2()

    def _migrate_to_v2(self) -> None:
        """Widen ``events.kind`` to include ``agent_message`` by rebuilding the table (SQLite cannot ALTER a
        CHECK). Every existing row is copied verbatim (a DROP TABLE is not a DELETE, so the append-only
        no-delete trigger does not fire); the indexes + append-only triggers are recreated.

        CRASH-ATOMIC: the whole rebuild runs inside ONE explicit transaction (SQLite supports transactional
        DDL), so a failure at any point ROLLS BACK to the intact v1 table — the durable audit spine is never
        left half-migrated, dropped, or bricked. A leftover ``events_v2`` from an interrupted prior attempt
        is dropped first (self-healing). FKs are disabled around the rebuild (a no-op inside a transaction,
        so it is toggled OUTSIDE the txn) and re-enabled in ``finally``; ``foreign_key_check`` after guards
        against an orphaned parent_id/supersedes_id."""
        _STMTS = (
            "DROP TABLE IF EXISTS events_v2",                 # self-heal an interrupted prior rebuild
            """CREATE TABLE events_v2 (
                    id              INTEGER PRIMARY KEY AUTOINCREMENT,
                    engagement_id   INTEGER NOT NULL REFERENCES bb_engagements(id),
                    kind            TEXT NOT NULL CHECK(kind IN (
                        'observation','hypothesis','plan','action',
                        'result','finding','critique','decision',
                        'reward','critic_verdict','reflection','refusal',
                        'tool_call','tool_result','agent_message')),
                    agent_name      TEXT NOT NULL,
                    posted_at       TEXT NOT NULL,
                    payload_json    TEXT NOT NULL,
                    parent_id       INTEGER REFERENCES events_v2(id),
                    supersedes_id   INTEGER REFERENCES events_v2(id))""",
            """INSERT INTO events_v2 (id, engagement_id, kind, agent_name, posted_at, payload_json,
                                      parent_id, supersedes_id)
                   SELECT id, engagement_id, kind, agent_name, posted_at, payload_json,
                          parent_id, supersedes_id FROM events""",
            "DROP TABLE events",
            "ALTER TABLE events_v2 RENAME TO events",
            "CREATE INDEX IF NOT EXISTS idx_events_eng_kind   ON events(engagement_id, kind)",
            "CREATE INDEX IF NOT EXISTS idx_events_eng_id     ON events(engagement_id, id)",
            "CREATE INDEX IF NOT EXISTS idx_events_agent      ON events(agent_name)",
            "CREATE INDEX IF NOT EXISTS idx_events_supersedes ON events(supersedes_id)",
            "CREATE INDEX IF NOT EXISTS idx_events_parent     ON events(parent_id)",
            "DROP TRIGGER IF EXISTS bb_events_no_update",
            "CREATE TRIGGER bb_events_no_update BEFORE UPDATE ON events "
            "BEGIN SELECT RAISE(FAIL, 'blackboard events are append-only; supersede with a new row'); END",
            "DROP TRIGGER IF EXISTS bb_events_no_delete",
            "CREATE TRIGGER bb_events_no_delete BEFORE DELETE ON events "
            "BEGIN SELECT RAISE(FAIL, 'blackboard events are append-only; cannot DELETE'); END",
            "UPDATE bb_schema_meta SET value = '2' WHERE key = 'version'",
        )
        prev_iso = self._conn.isolation_level
        self._conn.isolation_level = None                    # manual, explicit transaction control
        self._conn.execute("PRAGMA foreign_keys = OFF")      # (a no-op inside a txn) — toggle outside it
        try:
            self._conn.execute("BEGIN IMMEDIATE")
            for stmt in _STMTS:
                self._conn.execute(stmt)
            self._conn.execute("COMMIT")                     # atomic: v1 → v2 all-or-nothing
        except Exception:
            self._conn.execute("ROLLBACK")                   # any failure → intact v1, no half-state
            raise
        finally:
            self._conn.execute("PRAGMA foreign_keys = ON")
            self._conn.isolation_level = prev_iso
        # guard against an orphaned parent_id/supersedes_id surviving the rebuild (fail loud, not silent)
        bad = self._conn.execute("PRAGMA foreign_key_check").fetchall()
        if bad:
            raise BlackboardError(f"blackboard v2 migration left {len(bad)} orphaned foreign-key row(s)")

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

        # S5 anti-spoof: a directed agent_message's `sender` MUST equal the posting agent, so a message can
        # never forge its origin — the RECORDED poster (agent_name) is authoritative, not the payload claim.
        if kind == "agent_message" and str(validated.get("sender", "")) != str(agent_name):
            raise BlackboardError(
                f"agent_message sender={validated.get('sender')!r} does not match the posting agent "
                f"{agent_name!r} (anti-spoof)")

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
        parent_id: int | None = None,
        since_id: int = 0,
        include_superseded: bool = False,
        limit: int = 1000,
    ) -> list[BlackboardEventRow]:
        """Read events for an engagement. Defaults exclude superseded rows.

        ``parent_id`` (X3) restricts to the direct children of one event — served by the
        ``idx_events_parent`` index, so a consumer that wants only the events posted ABOUT a
        given event (e.g. the critic verdicts on a finding) reads O(children) rows instead of
        scanning every event of that kind and filtering in Python. Additive: ``None`` (default)
        yields the identical query as before."""
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
        if parent_id is not None:
            sql.append("AND e.parent_id = ?")
            params.append(parent_id)
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

    def inbox(
        self, *, engagement: str | int, recipient: str, since_id: int = 0, limit: int = 1000,
    ) -> list[BlackboardEventRow]:
        """The directed ``agent_message`` events ADDRESSED to ``recipient``, in strict id order after
        ``since_id`` (a durable cursor — pass the last id you drained). Read-only over the append-only log.
        A message is a COORDINATION hint the recipient MAY consider; it is NEVER a fact/finding/observation
        and no fact-building path reads this kind, so draining an inbox can never promote anything."""
        rows = self.read(engagement=engagement, since_id=since_id, kinds=["agent_message"], limit=limit)
        return [r for r in rows if str((r.payload or {}).get("recipient", "")) == str(recipient)]

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

    # ---- library listing (the engagement roster, newest activity first) ----

    _LIST_ENGAGEMENTS_SQL = """
        SELECT e.id          AS id,
               e.slug        AS slug,
               e.started_at  AS started_at,
               e.closed_at   AS closed_at,
               COUNT(v.id)   AS events,
               MIN(v.posted_at) AS first_event_at,
               MAX(v.posted_at) AS last_event_at,
               SUM(CASE WHEN v.kind = 'finding' THEN 1 ELSE 0 END) AS findings
          FROM bb_engagements e
          LEFT JOIN events v
                 ON v.engagement_id = e.id
                AND NOT EXISTS (SELECT 1 FROM events s WHERE s.supersedes_id = v.id)
         GROUP BY e.id, e.slug, e.started_at, e.closed_at
    """

    def list_engagements(
        self,
        *,
        labels: Mapping[str, str] | None = None,
        limit: int = 500,
    ) -> list[dict[str, Any]]:
        """Every engagement the spine knows about — a stable identity plus TIMESTAMPS — newest
        activity FIRST. This is the engagement-library roster: the operator comes back months
        later and needs to see WHICH jobs exist and WHEN each was worked on, not an alphabetical
        list of directories.

        Per engagement: the registry ``id`` + ``slug`` (the stable identity), ``started_at`` (when
        the engagement was registered), ``first_seen`` / ``last_activity`` (the first and last event
        actually posted — falling back to ``started_at`` for an engagement registered but never
        posted to), ``closed_at``, and the current-view counts (``events``, ``findings``, ``facts``).
        Superseded rows are excluded, so the counts match the current view the rest of the console
        renders (``read``'s default), not the full audit history.

        A FACT is a finding whose payload carries ``verified_by_oracle`` — the same provenance flag
        the telemetry collector folds on. This method DERIVES; it never mints, promotes, or writes.

        ``labels`` is an OPTIONAL, caller-supplied ``slug -> human label`` mapping stamped onto the
        rows as ``label``. It is PRESENTATION metadata and it is deliberately INJECTED rather than
        stored: there is no label column, no label write path, and nothing here ever puts a label
        into an event payload — so renaming an engagement cannot touch a signed byte or invalidate
        a certificate. An unlabelled engagement gets ``""`` (the UI falls back to the slug).

        Read-only over the append-only log. Total: it never raises for a fresh/empty spine.
        """
        rows = self._conn.execute(self._LIST_ENGAGEMENTS_SQL).fetchall()

        # FACT counts need the payload flag, so they cannot come from the aggregate above. Findings
        # are the rarest kind on a spine, so this is a small, indexed read (idx_events_eng_kind).
        facts: dict[int, int] = {}
        for r in self._conn.execute(
            "SELECT v.engagement_id AS eid, v.payload_json AS payload_json FROM events v "
            "WHERE v.kind = 'finding' "
            "  AND NOT EXISTS (SELECT 1 FROM events s WHERE s.supersedes_id = v.id)"
        ):
            try:
                payload = json.loads(r["payload_json"])
            except (TypeError, ValueError):     # a payload we cannot parse is never counted a fact
                continue
            if isinstance(payload, dict) and payload.get("verified_by_oracle"):
                eid = int(r["eid"])
                facts[eid] = facts.get(eid, 0) + 1

        label_map = dict(labels or {})
        out: list[dict[str, Any]] = []
        for r in rows:
            slug = str(r["slug"])
            started = str(r["started_at"])
            out.append({
                "id": int(r["id"]),
                "slug": slug,
                # presentation only — injected by the caller, never read from or written to the spine
                "label": str(label_map.get(slug, "") or ""),
                "started_at": started,
                "first_seen": str(r["first_event_at"] or started),
                "last_activity": str(r["last_event_at"] or started),
                "closed_at": r["closed_at"],
                "events": int(r["events"] or 0),
                "findings": int(r["findings"] or 0),
                "facts": int(facts.get(int(r["id"]), 0)),
            })
        # newest activity first. posted_at/started_at are `now_iso()` (UTC, second precision), which
        # sorts lexicographically == chronologically; the slug breaks ties deterministically.
        out.sort(key=lambda e: (e["last_activity"], e["slug"]), reverse=True)
        return out[: max(0, int(limit))]


def open_blackboard(*, db_path: Path | None = None) -> Blackboard:
    return Blackboard(db_path=db_path)
