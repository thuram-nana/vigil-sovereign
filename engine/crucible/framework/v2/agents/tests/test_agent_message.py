"""
S5 — agent-to-agent directed messaging (`agent_message` kind + anti-spoof + inbox).

Doctrine under test:
  * a message is DIRECTED + addressed (recipient), and the inbox is per-recipient + directional
    (B's inbox holds messages to B; A does not see them unless addressed);
  * ANTI-SPOOF: the payload `sender` MUST equal the posting agent — a message can't forge its origin;
  * MESSAGE != FACT (the central guard): agent_message is coordination only. No sequence of messages
    ever becomes a finding/observation, is never returned by a finding read, and never enters a
    fact/critique kind — only a fired oracle mints a fact;
  * a v1 blackboard (pre-S5) migrates to v2 (rows preserved + append-only intact + the new kind enabled);
  * the Agent base send_message/read_inbox helpers force the sender and read only addressed messages.
"""

from __future__ import annotations

import sqlite3

import pytest

from framework.v2.agents.base import Agent
from framework.v2.agents.blackboard import Blackboard, BlackboardError


def _bb(tmp_path):
    return Blackboard(db_path=tmp_path / "bb.db")


def _msg(sender, recipient, body="hi"):
    return {"sender": sender, "recipient": recipient, "topic": "t", "body": body}


# ---- the directed channel ---------------------------------------------------

def test_post_and_inbox_are_directional(tmp_path):
    bb = _bb(tmp_path)
    mid = bb.post(engagement="e", kind="agent_message", agent_name="recon",
                  payload=_msg("recon", "exploit", "try /admin"))
    assert bb.get(mid).kind == "agent_message"
    to_exploit = bb.inbox(engagement="e", recipient="exploit")
    assert [r.payload["body"] for r in to_exploit] == ["try /admin"]
    assert bb.inbox(engagement="e", recipient="recon") == []          # directional: recon isn't addressed


def test_anti_spoof_sender_must_equal_poster(tmp_path):
    bb = _bb(tmp_path)
    with pytest.raises(BlackboardError, match="anti-spoof"):
        bb.post(engagement="e", kind="agent_message", agent_name="recon",
                payload=_msg("exploit", "critique", "forged"))     # sender != poster
    # the honest case (sender == poster) is fine
    assert bb.post(engagement="e", kind="agent_message", agent_name="recon",
                   payload=_msg("recon", "critique"))


def test_inbox_durable_cursor(tmp_path):
    bb = _bb(tmp_path)
    m1 = bb.post(engagement="e", kind="agent_message", agent_name="a", payload=_msg("a", "b", "1"))
    bb.post(engagement="e", kind="agent_message", agent_name="a", payload=_msg("a", "b", "2"))
    assert [r.payload["body"] for r in bb.inbox(engagement="e", recipient="b")] == ["1", "2"]
    assert [r.payload["body"] for r in bb.inbox(engagement="e", recipient="b", since_id=m1)] == ["2"]


# ---- MESSAGE != FACT (the central guard) ------------------------------------

def test_messages_never_become_facts(tmp_path):
    bb = _bb(tmp_path)
    # a whole conversation of messages, some with fact-sounding bodies
    for i in range(10):
        bb.post(engagement="e", kind="agent_message", agent_name="recon",
                payload=_msg("recon", "exploit", f"CONFIRMED sqli at /x?{i} — status=fact"))
    # they are ALL agent_message; none minted a finding / observation / result / critique / tool_result
    assert bb.count(engagement="e", kind="agent_message") == 10
    for fact_kind in ("finding", "observation", "result", "critique", "tool_result", "decision"):
        assert bb.count(engagement="e", kind=fact_kind) == 0
    # a finding read never returns a message (kind-scoped), and a full replay tags each as agent_message
    assert bb.read(engagement="e", kinds=["finding"]) == []
    assert {r.kind for r in bb.replay(engagement="e")} == {"agent_message"}


def test_agent_message_payload_cannot_masquerade_as_a_finding(tmp_path):
    bb = _bb(tmp_path)
    # even a payload carrying finding-shaped fields validates against AgentMessagePayload (extras dropped),
    # so the stored record is a plain message — it can never be read back as a FindingPayload/critique.
    mid = bb.post(engagement="e", kind="agent_message", agent_name="recon",
                  payload={"sender": "recon", "recipient": "exploit", "body": "x",
                           "severity": "Critical", "critique_status": "confirmed"})
    stored = bb.get(mid).payload
    assert "severity" not in stored and "critique_status" not in stored
    assert stored["intent"] == "coordination"


# ---- v1 → v2 migration (durable store predates S5) --------------------------

def test_v1_store_migrates_to_v2_preserving_rows_and_append_only(tmp_path):
    p = tmp_path / "v1.db"
    c = sqlite3.connect(p)
    c.executescript(
        """
        CREATE TABLE bb_schema_meta(key TEXT PRIMARY KEY, value TEXT NOT NULL);
        INSERT INTO bb_schema_meta VALUES('version','1');
        CREATE TABLE bb_engagements(id INTEGER PRIMARY KEY AUTOINCREMENT, slug TEXT UNIQUE NOT NULL,
            started_at TEXT NOT NULL, closed_at TEXT);
        CREATE TABLE events(id INTEGER PRIMARY KEY AUTOINCREMENT,
            engagement_id INTEGER NOT NULL REFERENCES bb_engagements(id),
            kind TEXT NOT NULL CHECK(kind IN ('observation','finding','tool_result')),
            agent_name TEXT NOT NULL, posted_at TEXT NOT NULL, payload_json TEXT NOT NULL,
            parent_id INTEGER REFERENCES events(id), supersedes_id INTEGER REFERENCES events(id));
        CREATE TRIGGER bb_events_no_delete BEFORE DELETE ON events
            BEGIN SELECT RAISE(FAIL,'append-only'); END;
        INSERT INTO bb_engagements(slug, started_at) VALUES('e','t0');
        INSERT INTO events(engagement_id, kind, agent_name, posted_at, payload_json)
            VALUES(1,'finding','recon','t1','{}');
        """
    )
    c.commit()
    c.close()

    bb = Blackboard(db_path=p)                                       # opening runs _migrate → _migrate_to_v2
    ver = bb._conn.execute("SELECT value FROM bb_schema_meta WHERE key='version'").fetchone()[0]
    assert ver == "2"
    assert bb.count(engagement="e", kind="finding") == 1            # the old row survived verbatim
    assert bb.get(bb.post(engagement="e", kind="agent_message", agent_name="a",
                          payload=_msg("a", "b"))).kind == "agent_message"   # new kind now allowed
    with pytest.raises(sqlite3.IntegrityError):                     # append-only trigger survived the rebuild
        bb._conn.execute("DELETE FROM events WHERE id = 1")


_V1_SCHEMA = """
CREATE TABLE bb_schema_meta(key TEXT PRIMARY KEY, value TEXT NOT NULL);
INSERT INTO bb_schema_meta VALUES('version','1');
CREATE TABLE bb_engagements(id INTEGER PRIMARY KEY AUTOINCREMENT, slug TEXT UNIQUE NOT NULL,
    started_at TEXT NOT NULL, closed_at TEXT);
CREATE TABLE events(id INTEGER PRIMARY KEY AUTOINCREMENT,
    engagement_id INTEGER NOT NULL REFERENCES bb_engagements(id),
    kind TEXT NOT NULL CHECK(kind IN ('observation','finding')),
    agent_name TEXT NOT NULL, posted_at TEXT NOT NULL, payload_json TEXT NOT NULL,
    parent_id INTEGER REFERENCES events(id), supersedes_id INTEGER REFERENCES events(id));
CREATE TRIGGER bb_events_no_delete BEFORE DELETE ON events BEGIN SELECT RAISE(FAIL,'append-only'); END;
INSERT INTO bb_engagements(slug, started_at) VALUES('e','t0');
INSERT INTO events(engagement_id, kind, agent_name, posted_at, payload_json) VALUES(1,'finding','recon','t1','{}');
"""


def test_v2_migration_self_heals_a_leftover_events_v2(tmp_path):
    # a crashed pre-fix attempt could leave an orphan `events_v2`; the migration must DROP IF EXISTS it and
    # still complete (not brick the durable store on "table events_v2 already exists").
    p = tmp_path / "leftover.db"
    c = sqlite3.connect(p)
    c.executescript(_V1_SCHEMA)
    c.execute("CREATE TABLE events_v2(id INTEGER)")             # simulate the leftover
    c.commit()
    c.close()
    bb = Blackboard(db_path=p)
    assert bb._conn.execute("SELECT value FROM bb_schema_meta WHERE key='version'").fetchone()[0] == "2"
    assert bb.count(engagement="e", kind="finding") == 1


def test_v2_migration_is_crash_atomic(tmp_path):
    # a failure MID-rebuild must ROLL BACK to the intact v1 table — the durable audit spine is never left
    # dropped/half-migrated (SQLite transactional DDL). Simulate a crash: run the rebuild inside a txn and
    # ROLLBACK before COMMIT, then confirm v1 survived and the real migration recovers cleanly.
    p = tmp_path / "crash.db"
    c = sqlite3.connect(p)
    c.executescript(_V1_SCHEMA)
    c.commit()
    c.isolation_level = None
    c.execute("BEGIN IMMEDIATE")
    c.execute("CREATE TABLE events_v2(id INTEGER PRIMARY KEY)")
    c.execute("DROP TABLE events")                             # mid-rebuild
    c.execute("ROLLBACK")                                      # crash before COMMIT
    assert c.execute("SELECT COUNT(*) FROM events").fetchone()[0] == 1        # events restored by rollback
    assert c.execute("SELECT value FROM bb_schema_meta WHERE key='version'").fetchone()[0] == "1"
    assert c.execute("SELECT name FROM sqlite_master WHERE name='events_v2'").fetchone() is None
    c.close()
    bb = Blackboard(db_path=p)                                 # the real migration recovers the intact v1
    assert bb.count(engagement="e", kind="finding") == 1
    assert bb.get(bb.post(engagement="e", kind="agent_message", agent_name="a",
                          payload=_msg("a", "b"))).kind == "agent_message"


def test_v2_migration_rolls_back_on_a_real_mid_rebuild_failure(tmp_path, monkeypatch):
    # exercise the REAL `_migrate_to_v2` except:→ROLLBACK path (not a raw-connection proxy): inject a failure
    # AFTER `DROP TABLE events` — the exact window that previously lost the durable spine — and prove the
    # rollback restores the intact v1 table, then a clean re-open recovers it to v2.
    import framework.v2.agents.blackboard as bb_mod

    class _CrashConn(sqlite3.Connection):
        def execute(self, sql, *a):
            if "ALTER TABLE events_v2 RENAME" in sql:          # fires right after DROP TABLE events
                raise RuntimeError("simulated crash mid-rebuild")
            return super().execute(sql, *a)

    p = tmp_path / "crash_real.db"
    c = sqlite3.connect(p)
    c.executescript(_V1_SCHEMA)
    c.commit()
    c.close()

    real_connect = sqlite3.connect
    opened = []

    def crash_connect(*a, **k):
        k["factory"] = _CrashConn
        conn = real_connect(*a, **k)
        opened.append(conn)
        return conn

    monkeypatch.setattr(bb_mod.sqlite3, "connect", crash_connect)
    with pytest.raises(RuntimeError, match="simulated crash"):
        Blackboard(db_path=p)                                  # __init__ → _migrate_to_v2 raises through ROLLBACK
    for conn in opened:
        conn.close()                                           # release the leaked write lock before re-reading
    monkeypatch.undo()

    c = sqlite3.connect(p)                                     # on disk: the ROLLBACK left intact v1
    assert c.execute("SELECT COUNT(*) FROM events").fetchone()[0] == 1
    assert c.execute("SELECT value FROM bb_schema_meta WHERE key='version'").fetchone()[0] == "1"
    assert c.execute("SELECT name FROM sqlite_master WHERE name='events_v2'").fetchone() is None
    c.close()
    bb = Blackboard(db_path=p)                                 # a real re-open now migrates cleanly to v2
    assert bb.count(engagement="e", kind="finding") == 1
    assert bb.get(bb.post(engagement="e", kind="agent_message", agent_name="a",
                          payload=_msg("a", "b"))).kind == "agent_message"


# ---- the Agent base helpers -------------------------------------------------

class _Probe(Agent):
    name = "probe"

    def should_run(self):
        return False

    def step(self):
        return 0


def test_agent_helpers_force_sender_and_read_only_addressed(tmp_path):
    bb = _bb(tmp_path)
    a = _Probe(bb, "e")
    # another agent messages the probe; the probe messages back
    bb.post(engagement="e", kind="agent_message", agent_name="recon", payload=_msg("recon", "probe", "hint"))
    mid = a.send_message("recon", "ack", topic="re: hint")
    assert bb.get(mid).payload["sender"] == "probe"                 # helper forces the real sender
    assert [r.payload["body"] for r in a.read_inbox(since_id=0)] == ["hint"]   # only messages TO the probe
