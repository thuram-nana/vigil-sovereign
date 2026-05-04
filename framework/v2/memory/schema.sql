-- ============================================================================
-- CRUCIBLE v2 — Memory & Learning Substrate (MLS) schema, version 1.
--
-- Every engagement is durably recorded so future engagements can query their
-- past:  what worked against stacks like this, which payloads paid off, where
-- time was wasted, which playbook sections are high-yield against which
-- archetype.
--
-- Embeddings are stored as BLOB columns (array.array('f').tobytes()).  The
-- dimensionality is set by the active embedder and recorded in schema_meta.
-- ============================================================================

PRAGMA foreign_keys = ON;
PRAGMA journal_mode = WAL;

-- ----------------------------------------------------------------------------
-- Schema version + embedder metadata
-- ----------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS schema_meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

INSERT OR IGNORE INTO schema_meta(key, value) VALUES ('version', '1');

-- ----------------------------------------------------------------------------
-- engagements — one row per target/charter pair
-- ----------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS engagements (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    slug            TEXT UNIQUE NOT NULL,
    target_url      TEXT,
    archetype       TEXT,                       -- e.g. "PHP-Smarty SMM-panel fork"
    fingerprint_json TEXT,                      -- raw UTI fingerprint output
    business_context TEXT,
    started_at      TEXT NOT NULL,              -- ISO-8601 UTC
    ended_at        TEXT,                       -- nullable until closed
    posture         TEXT,                       -- TEST / AUDIT / EMULATE
    embedding       BLOB,                       -- engagement-level vector
    notes           TEXT
);

CREATE INDEX IF NOT EXISTS idx_engagements_archetype ON engagements(archetype);

-- ----------------------------------------------------------------------------
-- findings — confirmed bugs (one per finding file under targets/<slug>/findings/)
-- ----------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS findings (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    engagement_id   INTEGER NOT NULL,
    slug            TEXT NOT NULL,              -- NNN-short-slug
    title           TEXT NOT NULL,
    severity        TEXT NOT NULL CHECK(severity IN ('Critical','High','Medium','Low','Info')),
    cvss_vector     TEXT,
    cvss_base       REAL,
    bug_class       TEXT,                       -- IDOR, mass-assignment, ...
    surface         TEXT,                       -- endpoint or feature path
    summary         TEXT NOT NULL,
    impact          TEXT,
    embedding       BLOB,
    discovered_at   TEXT NOT NULL,
    FOREIGN KEY (engagement_id) REFERENCES engagements(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_findings_class      ON findings(bug_class);
CREATE INDEX IF NOT EXISTS idx_findings_engagement ON findings(engagement_id);
CREATE INDEX IF NOT EXISTS idx_findings_severity   ON findings(severity);

-- ----------------------------------------------------------------------------
-- hypotheses — the full hypothesis log, including refuted ones
-- ----------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS hypotheses (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    engagement_id   INTEGER NOT NULL,
    handle          TEXT NOT NULL,              -- H-NNN
    bug_class       TEXT,
    surface         TEXT,
    given_text      TEXT,
    if_text         TEXT,
    then_text       TEXT,
    because_text    TEXT,
    refute_on       TEXT,
    cheap_test      TEXT,
    status          TEXT NOT NULL CHECK(status IN ('open','confirmed','refuted','surprised','deferred')),
    confidence      REAL,
    embedding       BLOB,
    created_at      TEXT NOT NULL,
    closed_at       TEXT,
    FOREIGN KEY (engagement_id) REFERENCES engagements(id) ON DELETE CASCADE,
    UNIQUE(engagement_id, handle)
);

CREATE INDEX IF NOT EXISTS idx_hyp_class  ON hypotheses(bug_class);
CREATE INDEX IF NOT EXISTS idx_hyp_status ON hypotheses(status);

-- ----------------------------------------------------------------------------
-- payloads — every payload tried, with outcome
-- ----------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS payloads (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    engagement_id   INTEGER,
    bug_class       TEXT NOT NULL,
    payload_text    TEXT NOT NULL,
    target_surface  TEXT,
    archetype       TEXT,                       -- denormalised for cross-engagement queries
    outcome         TEXT NOT NULL CHECK(outcome IN ('success','failure','blocked','partial','unknown')),
    notes           TEXT,
    used_at         TEXT NOT NULL,
    FOREIGN KEY (engagement_id) REFERENCES engagements(id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_payloads_class    ON payloads(bug_class, outcome);
CREATE INDEX IF NOT EXISTS idx_payloads_archetype ON payloads(archetype, bug_class);

-- ----------------------------------------------------------------------------
-- dead_ends — refuted hypotheses with the reason
-- ----------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS dead_ends (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    engagement_id   INTEGER,
    archetype       TEXT,
    technique       TEXT NOT NULL,
    surface         TEXT,
    reason          TEXT NOT NULL,
    embedding       BLOB,
    recorded_at     TEXT NOT NULL,
    FOREIGN KEY (engagement_id) REFERENCES engagements(id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_dead_ends_archetype ON dead_ends(archetype, technique);

-- ----------------------------------------------------------------------------
-- archetype_priors — Bayesian-flavoured prior tracker
-- ----------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS archetype_priors (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    archetype       TEXT NOT NULL,
    bug_class       TEXT NOT NULL,
    surface_pattern TEXT,                       -- optional refinement, e.g. "/api/*/orders"
    successes       INTEGER NOT NULL DEFAULT 0,
    attempts        INTEGER NOT NULL DEFAULT 0,
    last_updated    TEXT NOT NULL,
    UNIQUE(archetype, bug_class, surface_pattern)
);

CREATE INDEX IF NOT EXISTS idx_priors_archetype ON archetype_priors(archetype);
CREATE INDEX IF NOT EXISTS idx_priors_class     ON archetype_priors(bug_class);

-- ----------------------------------------------------------------------------
-- playbook_outcomes — finding yield per playbook section per archetype
-- ----------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS playbook_outcomes (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    playbook_id         TEXT NOT NULL,           -- e.g. "11-cryptography"
    section             TEXT,                    -- e.g. "11.3 padding-oracle"
    engagement_id       INTEGER NOT NULL,
    archetype           TEXT,
    findings_yielded    INTEGER NOT NULL DEFAULT 0,
    time_spent_minutes  INTEGER NOT NULL DEFAULT 0,
    notes               TEXT,
    recorded_at         TEXT NOT NULL,
    FOREIGN KEY (engagement_id) REFERENCES engagements(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_pb_outcomes_id        ON playbook_outcomes(playbook_id);
CREATE INDEX IF NOT EXISTS idx_pb_outcomes_archetype ON playbook_outcomes(archetype, playbook_id);
