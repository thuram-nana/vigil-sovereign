# ADR 0008 — Crypto-shredding for the right-to-erasure of append-only evidence (W16-8)

- **Status:** Accepted
- **Scope:** VIGIL (`/home/kali/vigil`, repo `thuram-nana/vigil-sovereign`) — W16 declared-limitation
  burndown, item W16-8. Closes the retention/deletion-policy gap the audit flagged as a *policy
  collision, not a missing feature* (issue #514).
- **Affects:** new `engine/crucible/framework/v2/common/crypto_shred.py` (the crypto-shred core),
  new `engine/crucible/framework/v2/agents/evidence_erasure.py` (the wired erasure path + CLI),
  new path helpers `evidence_archive_dir` / `evidence_keys_dir` in
  `engine/crucible/framework/v2/common/paths.py`, the `erase-evidence` subcommand in
  `framework/v2/__main__.py`, `PRIVACY.md`, `DATA-GROUND-TRUTH.md`, and the test suite
  `engine/crucible/framework/v2/agents/tests/test_evidence_erasure.py`.

## Context — the policy collision

The engagement event spine is **append-only by SQLite trigger** (`agents/schema.sql`:
`bb_events_no_update` / `bb_events_no_delete`) *and* by API discipline (the Python `Blackboard`
exposes only `post()` / `supersede()`). On top of that, `agents/spine_chain.py` builds a
hash-linked, governance-signed chain over the log whose per-event digest covers the event payload,
so any edit / reorder / deletion of a row is cryptographically detectable.

Independently, captured evidence contains **real credentials**: the live HTTP executor
(`agents/http_executor.py`) archives `request.http` (with `Authorization` / `Cookie` request lines),
`response.http`, and the raw `response.body` to `targets/<slug>/evidence/<action_id>/`
(`common/paths.evidence_dir`); and credential-adjacent bytes can be reflected into a spine payload
excerpt (`ResultPayload.body_excerpt`, `ObservationPayload.raw_excerpt`).

These two facts collide. A data-protection erasure request ("delete the credential material you hold
for engagement X") cannot be honoured by DELETE/UPDATE: the trigger refuses it, and even if the
trigger were relaxed, the deletion would break the append-only guarantee and the spine hash-chain —
destroying the tamper-evidence the whole system rests on. Before this ADR there was **no erasure path
at all**, which is not tenable for a system that captures third-party credentials.

The header-VALUE masking already in `common/redact.py` (X2) reduces but does not eliminate the
problem: it masks known credential *headers* in the human-readable `.http` dumps, but the raw
`response.body` is deliberately left byte-faithful (over-masking a body would destroy the proof a
finding rests on), and masking is not erasure — an erasure request must be able to make specific
retained material **unrecoverable**.

## Decision — crypto-shred with a per-engagement key held OFF the spine

We do **not** delete or rewrite anything on the append-only spine. Instead:

1. **Seal, don't store-in-clear (for the append-only sink).** Credential-bearing material destined
   for the append-only spine is sealed under a per-engagement **Data Encryption Key (DEK)** with
   AES-256-GCM (`crypto_shred.EvidenceKeyring.seal_text`). The spine row then holds an opaque
   ciphertext token; the digest — and therefore the chain — covers the ciphertext.
2. **Keep the key OUTSIDE the append-only store.** The DEK lives in a **shreddable** keystore
   (`paths.evidence_keys_dir()` → `framework/v2/.evidence-keys/<slug>.dek`, owner-only, gitignored,
   overridable to a separate mount/HSM via `CRUCIBLE_EVIDENCE_KEYS_DIR`). This directory is a plain
   filesystem path — **not** append-only — precisely so a key *can* be destroyed.
3. **Erase by destroying the key.** `erase-evidence` (CLI) →
   `agents.evidence_erasure.erase_engagement_evidence()`:
   (a) seals every plaintext file in the on-disk evidence archive *in place* under the DEK (a
   filesystem rewrite — permitted, the filesystem is not append-only), (b) **shreds the DEK**
   (best-effort overwrite, then unlink — the unlink is the authoritative act), and (c) **appends** a
   signed `decision` tombstone to the spine recording that erasure happened (fingerprint of the
   destroyed key, algorithm, file count, timestamp, operator reason). If governance signers are
   supplied it re-anchors the spine head over the post-erasure log.

After a shred, the ciphertext left behind — on disk, in an off-host backup copy, or embedded as a
sealed excerpt in an append-only spine payload — is cryptographically unrecoverable, while every
append-only row is byte-for-byte unchanged and the spine hash-chain still verifies.

### Why crypto-shredding (over the alternatives)

- **Silent delete / trigger relaxation — rejected.** Breaks append-only and the tamper-evident
  chain. This is the collision itself.
- **Redaction-at-capture alone — insufficient.** Header-name masking helps but cannot erase the raw
  body, and is not reversible-on-request. It is complementary (tracked as W6-5 #456), not a
  substitute for an erasure guarantee.
- **A separate, mutable evidence store — heavier and weaker.** Would still leave the append-only
  spine excerpts un-erasable and duplicates the credential into a second at-rest location.
- **Crypto-shredding — chosen.** It is the only option that (i) satisfies erasure, (ii) preserves
  append-only *and* the hash-chain, and (iii) extends to **off-host backups** (W7-2 #460): destroying
  the single key renders every ciphertext copy, wherever it was replicated, unrecoverable. This is
  why the audit listed it first.

## Consequences

- **The append-only guarantee is unchanged.** Erasure never issues a DELETE/UPDATE; it only appends a
  tombstone. The `bb_events_no_update` / `bb_events_no_delete` triggers still fire, and the signed
  hash-chain still verifies over the post-erasure log (pinned by the tests).
- **Erasure is irreversible and per-engagement.** Once a DEK is shredded, the operator cannot recover
  that engagement's sealed evidence — by design. The CLI is destructive and **default-denies** without
  an explicit `--yes`. The shred is targeted: shredding engagement A does not touch engagement B.
- **The strongest form of the guarantee (protecting *earlier* off-host backups) requires
  seal-at-capture to be the default.** This ADR ships the crypto-shred core, the wired erasure path,
  and the sealed-excerpt primitive for the spine; it makes the on-disk archive ciphertext at erasure
  time. Turning on **seal-at-capture by default across the live HTTP executor** — so plaintext
  credentials never touch disk (or a backup) even before an erasure request — changes the byte-identity
  of every evidence file and the evidence manifest, and is staged as a follow-up rolled out together
  with the reporter/exploit-agent readers and the redaction work (W6-5 #456). Until then, a backup
  taken *before* an erasure may still hold plaintext; the honest position is stated in `PRIVACY.md`.
- **Data-protection commitments.** `PRIVACY.md` and `DATA-GROUND-TRUTH.md` state the real position
  (what is captured, where it lives, how erasure works, and the seal-at-capture residual). The Data
  Processing Agreement (W14-2 #504) and the claims registry (W0-3 #398) are owned by their own issues;
  this ADR is the source of truth they cite for the erasure mechanism.

## How it is verified

`engine/crucible/framework/v2/agents/tests/test_evidence_erasure.py` (runs in the required
**CRUCIBLE core** CI job, which executes the whole `framework/v2` tree):

- credential material is unrecoverable after erasure (on disk *and* via a sealed spine excerpt) while
  `verify_spine_chain` still passes and the erased rows' digests are unchanged;
- **negative control:** after erasure the append-only triggers still refuse DELETE/UPDATE, and the
  count only grows by the one tombstone (records cannot be removed or rewritten by the mechanism);
- **negative control:** the shred is per-engagement (a sibling engagement stays fully recoverable);
- **negative control:** a tampered / cross-engagement ciphertext is rejected (AEAD auth failure), an
  unsafe engagement id fails closed, and the destructive CLI default-denies without `--yes`.
