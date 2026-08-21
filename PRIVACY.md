# Privacy & evidence-retention position

This document states the **real** position on the third-party credential material VIGIL captures
during an authorized engagement, how long it is retained, and how it can be erased. It is true of
the shipped code (see the decision record `knowledge/decisions/0008-crypto-shred-erasure-for-append-only-evidence.md`
and the mechanism in `engine/crucible/framework/v2/common/crypto_shred.py` /
`engine/crucible/framework/v2/agents/evidence_erasure.py`).

## What is captured

During a live engagement the executor archives the HTTP evidence needed to prove a finding:

- `request.http` — the request line and headers, **including** `Authorization` / `Cookie` request
  lines when the target requires them (credential *header names* are masked in the human-readable
  dump per `common/redact.py`, but the request as sent may still authenticate with a real token);
- `response.http` and `response.body` — the raw response, kept **byte-faithful** because
  over-masking a body would destroy the very proof a finding rests on;
- small credential-adjacent excerpts can also be reflected into the append-only event spine
  (`ResultPayload.body_excerpt`, `ObservationPayload.raw_excerpt`).

These live under `targets/<slug>/evidence/<action_id>/` (owner-only, 0600) and in the append-only
SQLite spine (`framework/v2/.blackboard/store.sqlite`, owner-only).

## Retention

The event spine is **append-only by design** (SQLite triggers + a governance-signed hash chain):
it is a tamper-evident audit log and is **never** silently deleted or edited. Evidence is retained
for the life of the engagement record so findings remain independently re-verifiable.

## Erasure (right to erasure)

Because the spine is append-only, credential material is erased by **crypto-shredding**, not
deletion:

- credential-bearing material is sealed under a **per-engagement key** (AES-256-GCM) held in a
  shreddable keystore that lives **outside** the append-only spine
  (`framework/v2/.evidence-keys/`, override with `CRUCIBLE_EVIDENCE_KEYS_DIR`);
- an erasure request destroys that key:

  ```
  python3 -m framework.v2 erase-evidence --engagement <slug> --reason "<request ref>" --yes
  ```

- after the key is destroyed, any **sealed** ciphertext — on disk, or **in any off-host backup copy of
  the ciphertext** — is cryptographically unrecoverable, while every append-only row is byte-for-byte
  unchanged and the audit chain still verifies. A signed tombstone is appended to the spine recording
  that (and when) erasure happened.

> **Honest scope (what is and is not sealed today).** The on-disk evidence archive is sealed at erasure
> and crypto-shredded. The sealing primitive (`crypto_shred.seal_text`) can also seal a credential
> excerpt destined for the append-only spine (`ResultPayload.body_excerpt`,
> `ObservationPayload.raw_excerpt`), **but seal-at-capture is not yet wired into the live executor**
> (staged as a follow-up with the reporter/redaction work). Until it is, excerpts already written to the
> spine are stored in plaintext and are **not** made unrecoverable by crypto-shredding — do not rely on
> erasing them. The DEK keystore (`framework/v2/.evidence-keys/`) **must never be replicated to the same
> off-host location as the ciphertext**, or a backup could resurrect a shredded key.

Erasure is **irreversible** and **per-engagement**: it cannot be undone, and it affects only the
named engagement. The command is destructive and default-denies without `--yes`.

## Honest limitations

- **Seal-at-capture is not yet the default.** Today the on-disk archive is turned into ciphertext at
  *erasure* time. Crypto-shredding an off-host backup is therefore fully effective for backups taken
  **after** an erasure/seal; a backup taken while evidence was still plaintext may still contain that
  plaintext. Making the live executor seal credential material **at capture** (so plaintext never
  reaches disk or a backup) is a planned follow-up tracked with the redaction work (W6-5 #456) and the
  off-host backup work (W7-2 #460); it is deferred because it changes the byte-identity of every
  evidence file and must ship together with the readers and the evidence manifest.
- **The Data Processing Agreement (W14-2 #504) and the claims registry (W0-3 #398)** are maintained in
  their own issues; they cite this document and ADR-0008 as the source of truth for the erasure
  mechanism.
