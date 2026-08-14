---
name: vigil-i2-transparency-log
description: "VIGIL I2 — witnessed transparency log (split-view-resistant checkpoints) + a shared-core keyless-Ed25519-forgery fix; MERGED PR #8"
metadata: 
  node_type: memory
  type: project
  originSessionId: 7758e121-f349-47d5-886b-6bb5a1d60e27
  modified: 2026-07-20T21:48:24.783Z
---

VIGIL innovation phase **I2** (part of [[vigil-fusion-program]]) — MERGED to main @0d4ce90 (PR #8), all 6 CI green. Module `integration/vigil_integration/transparency.py` (import-clean, vigil_core only), tests `integration/tests/test_transparency.py` (19) + `packages/core/vigil_core/tests/test_weak_keys.py` (6).

**What it is:** a witnessed transparency log over SIGIL's signed spine head (`SignedChainHead` already carries a cumulative Merkle root over pruned leaves — the [[sigil-hardprune-program]] substrate). A `Checkpoint` is a public, domain-separated (`vigil-transparency-checkpoint-v1\x00`) summary of the head. A `Witness.cosign` verifies the new checkpoint is an append-only extension of its own tracked tip (`consistent()`: fail-closed on shrink/last_seq-rollback/broken-link/same-height-fork) then signs, **refusing (ConsistencyError) on any inconsistency** → an honest witness never equivocates. `verify_witnessed` = raw m-of-n quorum; `verify_split_view_resistant` = quorum AND `is_split_view_resistant`; `is_split(a,b)` lets a client prove a fork.

**Load-bearing HONESTY correction (the whole point):** split-view PREVENTION is a **quorum-intersection** property — it holds ONLY under a **strict majority (2·threshold > n) of DISTINCT, CANONICAL, non-low-order keys**. Below that (incl. `threshold==1`, which the trust model blesses) two DISJOINT quorums can each countersign a different fork with NO witness equivocating; only detection + per-witness non-equivocation remain. `is_split_view_resistant` encodes exactly this and fails closed on empty set / duplicate key / weak key. Do NOT claim a quorum prevents equivocation unconditionally.

**The review chain (4 rounds, each caught the NEXT defect one level deeper — the adversarial re-check on the FIXED branch is what surfaced each):**
1. BLOCK — docstring claimed split-view prevention unconditionally + the split-view test was green-washed (never instantiated a Witness). Fix: conditional-on-strict-majority + real Witness-driven tests.
2. HIGH — distinct-key check counted `key_id`s, but `TrustRoot` dedups key_ids only (two key_ids CAN share one pubkey). Fix: count distinct public keys.
3. BLOCK — deduped over the base64 STRING, but Ed25519 base64 is trailing-bit MALLEABLE (`base64.b64decode(validate=True)` accepts ~3 non-canonical encodings of one 32-byte key). Fix: dedup over the decoded key.
4. BLOCK (deepest, shared-core) — decoded-byte dedup still missed **low-order / identity Ed25519 points**: the identity point has two sign-bit encodings (distinct bytes), AND a low-order public key admits a **KEYLESS signature forgery** — `R=identity, S=0` verifies for ANY message — so one key under two key_ids forges a strict-majority quorum, defeating `verify_threshold` EVERYWHERE (CRUCIBLE evidence certs too, not just I2).

**The core fix (`vigil_core.crypto.load_public_key`, fixes it globally):** reject **non-canonical (y ≥ p)** encodings and **low-order points** (libsodium `ge25519_has_small_order` 7-entry blocklist, sign-bit-agnostic `& 0x7f`; covers all 8 torsion points because the two order-4 points share y=0). Proven 0 false-rejects over 8000 real keys; pyca verify is cofactorless so no mixed-order forgery survives. Regression: CRUCIBLE evidence+entitlement 109, integration 76, sigil-governor 33 all green. **LESSON: a low-order/identity Ed25519 public key = a keyless forgery against m-of-n threshold verify; ALWAYS reject non-canonical + small-order pubkeys at the load chokepoint — no legit keygen ever produces one.**

Also fixed a **pre-existing** CRUCIBLE-core CI red (unrelated to I2): restored `engine/crucible/targets/_template/` scaffold that the subtree clean removed (`test_charter_path_for_template`).

Deferred external-service refinement: OpenTimestamps Bitcoin anchoring of a checkpoint hash. SCITT/OpenVEX cert vocabulary also part of the I2-family plan (not yet built).
