-- ============================================================================
-- CRUCIBLE v2 — Blackboard schema, version 1.
--
-- Single SQLite DB at framework/v2/.blackboard/store.sqlite.  All
-- engagements share the DB; queries filter by engagement_id.  Events
-- are APPEND-ONLY: triggers below refuse UPDATE and DELETE.  The
-- "supersession" pattern is the only way to revise an event — a new
-- row points at the old via supersedes_id; both rows persist.
-- ============================================================================

PRAGMA foreign_keys = ON;
PRAGMA journal_mode = WAL;

CREATE TABLE IF NOT EXISTS bb_schema_meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
INSERT OR IGNORE INTO bb_schema_meta(key, value) VALUES ('version', '1');

-- ----------------------------------------------------------------------------
-- Engagements lookup. Same slug as the MLS engagements table; the IDs
-- are not shared because the two stores are independent.
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS bb_engagements (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    slug        TEXT UNIQUE NOT NULL,
    started_at  TEXT NOT NULL,
    closed_at   TEXT
);

-- ----------------------------------------------------------------------------
-- The append-only event log.
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS events (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    engagement_id   INTEGER NOT NULL REFERENCES bb_engagements(id),
    kind            TEXT NOT NULL CHECK(kind IN (
        'observation','hypothesis','plan','action',
        'result','finding','critique','decision'
    )),
    agent_name      TEXT NOT NULL,
    posted_at       TEXT NOT NULL,
    payload_json    TEXT NOT NULL,
    parent_id       INTEGER REFERENCES events(id),
    supersedes_id   INTEGER REFERENCES events(id)
);

CREATE INDEX IF NOT EXISTS idx_events_eng_kind  ON events(engagement_id, kind);
CREATE INDEX IF NOT EXISTS idx_events_eng_id    ON events(engagement_id, id);
CREATE INDEX IF NOT EXISTS idx_events_agent     ON events(agent_name);
CREATE INDEX IF NOT EXISTS idx_events_supersedes ON events(supersedes_id);
CREATE INDEX IF NOT EXISTS idx_events_parent    ON events(parent_id);

-- Append-only enforcement at the SQL level.  These triggers are belt-
-- and-braces; the Python API does not expose UPDATE or DELETE either.
DROP TRIGGER IF EXISTS bb_events_no_update;
CREATE TRIGGER bb_events_no_update
BEFORE UPDATE ON events
BEGIN
    SELECT RAISE(FAIL, 'blackboard events are append-only; supersede with a new row');
END;

DROP TRIGGER IF EXISTS bb_events_no_delete;
CREATE TRIGGER bb_events_no_delete
BEFORE DELETE ON events
BEGIN
    SELECT RAISE(FAIL, 'blackboard events are append-only; cannot DELETE');
END;
