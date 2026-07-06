-- ============================================================================
-- CRUCIBLE v2 — Intelligence & Reconnaissance durable store, schema version 2.
--
-- The Intelligence Engine reasons over the world-model in memory, but its raw
-- inputs and resolved outputs are durable so a run can be replayed, audited, and
-- learned from across engagements. Five append-mostly tables:
--
--   intel_observations   — every Observation ever ingested (the atomic intel fact,
--                          full model JSON preserved so a run replays byte-for-byte)
--   intel_entities       — resolved entities (many refs → one asset), with the
--                          full Entity JSON (members + merge_log) preserved
--   intel_entity_members — flattened membership, for fast "what cluster is X in"
--   intel_merge_log      — every union step, citing the signal that justified it
--   intel_source_yield   — cross-engagement source-yield learning: which recon
--                          source pays off against which archetype (feeds the
--                          ReconPlanner's priors)
--
-- Ordering is by the world-model's monotonic `seq`, never wallclock. Writes go
-- through a single writer (intel.ingest.IntelIngest); these tables are otherwise
-- read-only to the rest of the system.
-- ============================================================================

-- ----------------------------------------------------------------------------
-- intel_observations — the append-only observation log
-- ----------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS intel_observations (
    obs_id          TEXT PRIMARY KEY,            -- stable; also the world-model provenance key
    engagement_slug TEXT,
    source          TEXT NOT NULL,
    source_kind     TEXT NOT NULL,
    collector       TEXT,
    subject_node_id TEXT NOT NULL,               -- world-model node id (kind:key)
    relation        TEXT,                        -- edge kind, or NULL for a node claim
    object_node_id  TEXT,
    claim_key       TEXT NOT NULL,               -- (subject|relation|object) fusion key
    polarity        TEXT NOT NULL,               -- affirms / refutes
    confidence      REAL NOT NULL,
    reliability     REAL NOT NULL,               -- source weight() at ingest time
    seq             INTEGER NOT NULL,            -- monotonic world-model time
    observed_at     TEXT,
    obs_json        TEXT NOT NULL                -- full Observation.model_dump_json (round-trips)
);

CREATE INDEX IF NOT EXISTS idx_intel_obs_claim   ON intel_observations(claim_key);
CREATE INDEX IF NOT EXISTS idx_intel_obs_subject ON intel_observations(subject_node_id);
CREATE INDEX IF NOT EXISTS idx_intel_obs_source  ON intel_observations(source_kind, seq);
CREATE INDEX IF NOT EXISTS idx_intel_obs_engmt   ON intel_observations(engagement_slug, seq);

-- ----------------------------------------------------------------------------
-- intel_entities — resolved entities (one row per cluster)
-- ----------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS intel_entities (
    canonical_id    TEXT NOT NULL,
    engagement_slug TEXT,
    tier            TEXT NOT NULL,               -- asset / owner
    primary_kind    TEXT NOT NULL,
    confidence      REAL NOT NULL,               -- bottleneck of the merge tree
    member_count    INTEGER NOT NULL DEFAULT 1,
    owned_by        TEXT,                        -- comma-joined owner canonical ids (ASSET_OWNS)
    seq             INTEGER NOT NULL,
    entity_json     TEXT NOT NULL,               -- full Entity.model_dump_json (members + merge_log)
    PRIMARY KEY (engagement_slug, canonical_id)
);

CREATE INDEX IF NOT EXISTS idx_intel_ent_conf ON intel_entities(confidence);
CREATE INDEX IF NOT EXISTS idx_intel_ent_kind ON intel_entities(primary_kind);

-- ----------------------------------------------------------------------------
-- intel_entity_members — flattened membership (fast reverse lookup)
-- ----------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS intel_entity_members (
    engagement_slug TEXT,
    canonical_id    TEXT NOT NULL,
    member_node_id  TEXT NOT NULL,
    member_kind     TEXT NOT NULL,
    seq             INTEGER NOT NULL,
    PRIMARY KEY (engagement_slug, canonical_id, member_node_id)
);

CREATE INDEX IF NOT EXISTS idx_intel_members_node ON intel_entity_members(member_node_id);

-- ----------------------------------------------------------------------------
-- intel_merge_log — audit trail of every union step
-- ----------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS intel_merge_log (
    event_id        TEXT NOT NULL,
    engagement_slug TEXT,
    canonical_id    TEXT NOT NULL,
    a_node_id       TEXT NOT NULL,
    b_node_id       TEXT NOT NULL,
    trigger         TEXT NOT NULL,               -- signal kind (shared_cert / shared_ip / cname ...)
    total_llr_bits  REAL NOT NULL,
    probability     REAL NOT NULL,
    seq             INTEGER NOT NULL,
    PRIMARY KEY (engagement_slug, event_id)
);

CREATE INDEX IF NOT EXISTS idx_intel_merge_ent ON intel_merge_log(engagement_slug, canonical_id);

-- ----------------------------------------------------------------------------
-- intel_source_yield — cross-engagement source-yield learning
-- ----------------------------------------------------------------------------
-- Tracks, per recon source and target archetype, how much verified value the
-- source produced: observations ingested, distinct entities it helped resolve,
-- and confirmed findings downstream of assets it discovered. The ReconPlanner
-- reads these as a calibrated prior — a source that has never paid off against
-- this archetype is deprioritised without being disabled.

CREATE TABLE IF NOT EXISTS intel_source_yield (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    source_kind         TEXT NOT NULL,
    archetype           TEXT NOT NULL DEFAULT '',
    queries             INTEGER NOT NULL DEFAULT 0,   -- how many times queried
    observations_yielded INTEGER NOT NULL DEFAULT 0,
    entities_yielded    INTEGER NOT NULL DEFAULT 0,   -- distinct assets it helped resolve
    findings_downstream INTEGER NOT NULL DEFAULT 0,   -- confirmed bugs on assets it discovered
    last_updated        TEXT NOT NULL,
    UNIQUE(source_kind, archetype)
);

CREATE INDEX IF NOT EXISTS idx_intel_yield_source ON intel_source_yield(source_kind);
