-- VSCP initial schema (W13-7 / #500). VSCP's OWN tables in VSCP's OWN database.
-- Deliberately holds NO assessment findings, evidence, or oracle context — the control
-- plane records deployments, trust authorities and issued authorizations, nothing from
-- the assessment product.

-- Deployment registry: the fielded control-plane instances VSCP governs.
CREATE TABLE IF NOT EXISTS deployments (
    id            TEXT PRIMARY KEY,          -- caller-supplied stable id
    name          TEXT NOT NULL,
    environment   TEXT NOT NULL,             -- e.g. production | staging | development
    created_at    TEXT NOT NULL DEFAULT (datetime('now')),
    created_by    TEXT NOT NULL              -- principal (role/subject) that registered it
);

-- Trust authorities: the public keys VSCP trusts to sign control-plane facts. Stores
-- ONLY public material (never a private key, never product signing material).
CREATE TABLE IF NOT EXISTS trust_authorities (
    id              TEXT PRIMARY KEY,
    name            TEXT NOT NULL,
    public_key_b64  TEXT NOT NULL,           -- base64(32-byte Ed25519 pubkey), canonical-validated
    created_at      TEXT NOT NULL DEFAULT (datetime('now')),
    created_by      TEXT NOT NULL
);

-- Authorization issuance ledger: signed, hash-chained authorization records minted by
-- VSCP's own key. The signature/digest/chain fields make each row offline-verifiable.
CREATE TABLE IF NOT EXISTS authorizations (
    seq                    INTEGER PRIMARY KEY,   -- position on VSCP's own chain
    subject                TEXT NOT NULL,
    scope                  TEXT NOT NULL,
    effect                 TEXT NOT NULL,         -- allow (a refused issuance is never persisted)
    issued_at              INTEGER NOT NULL,
    digest                 TEXT NOT NULL,
    signature_b64          TEXT NOT NULL,
    signer_public_key_b64  TEXT NOT NULL,
    entry_hash             TEXT NOT NULL,
    prev_hash              TEXT NOT NULL,
    revoked_at             INTEGER
);
