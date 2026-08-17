# ADR 0006 — Transparency checkpoint v2: commit the prune boundary to make the merkle root fork-decidable

- **Status:** Accepted
- **Scope:** VIGIL (`/home/kali/vigil`, repo `thuram-nana/vigil-sovereign`) — Claim 6 "state-root residuals", slice C-S1
- **Affects:** `integration/vigil_integration/transparency.py` and every consumer of a witnessed checkpoint

## Context

A `transparency.Checkpoint` is the public, witnessable summary of a signed spine head. Before this change
it carried five fields (`last_seq`, `entry_count`, `head_hash`, `merkle_root`, `prev_checkpoint_hash`).
`is_split` — the primitive that lets a client prove a split view after the fact — keyed **only** on
`head_hash`, because a differing `merkle_root` at the same `head_hash` + `entry_count` was *un-decidable
from the summary alone*: an honest re-prune boundary looked byte-identical to a fabricated cumulative root.
Keying on the root would have false-accused a benign prune, so the root was deliberately ignored (and
authenticated only elsewhere, via the owner-signed head and the archive chain).

The residual: a producer could present two checkpoints at the same height and head with **different**
cumulative roots and neither `is_split` nor `consistent` would call it a fork.

The prune boundary is exactly what makes the root decidable, and it already lives on `SignedChainHead`
(`base_seq`, `base_count` — the same quantities the anti-rollback floor's `check_floor` guards). At one
absolute `entry_count` **and** one prune boundary the leaf set is fixed, so the cumulative Merkle root is a
deterministic function of it.

## Decision

1. **Commit the boundary.** `Checkpoint` gains `base_seq` / `base_count` (default `0` = nothing pruned),
   included in `to_dict()` and populated by `checkpoint_of()` from the head. They are therefore part of the
   checkpoint's **signed identity** (`checkpoint_hash` / witness co-signature).

2. **Make the root fork-decidable.** `is_split(a, b)` is now: same height AND (`head_hash` differs OR
   (**same** `base_seq` AND **same** `base_count` AND `merkle_root` differs)). A benign re-prune *moves*
   the boundary, so it stays excluded — **no false accusation**. A fabricated root at the same boundary is
   caught. `consistent` / `_segment_extends` gain the mirror: monotonic `base_seq`/`base_count` guards
   (they may not shrink = un-prune) and the same-height-same-boundary-different-root fork clause.

3. **Wire-format rotation (anti-replay).** The signing bytes changed, so the witness domain is bumped
   `vigil-transparency-checkpoint-v1\x00` → `…-v2\x00` and the multi-segment type marker
   `vigil.multi-segment-checkpoint.v1` → `.v2`. A v1 witness signature can **never** verify under v2, and
   vice-versa. This is mirrored in the standalone offline verifier
   (`docs/proof-carrying-finding/verify_vf.py`) and the auditor registry (`vigil_core.spine_domains`).

### Honest scope (what this does NOT claim)

- Only the *fork-decidability from the 5-field summary* is closed. A **cross-boundary** root difference
  (different `base_*` **and** different root) remains a legitimate re-prune, still excluded from `is_split`
  — a genuine cross-boundary equivocation is still caught via `head_hash` (a real fork differs there).
- No change to the trust model: split-view *prevention* is still the conditional strict-majority quorum
  property; this slice strengthens after-the-fact *detection* only.
- base_*=0 everywhere reproduces the pre-C-S1 verdicts byte-for-byte (no-op fidelity).

## Migration

Existing **persisted v1 witnessed checkpoints verify only under the v1 domain**. The witness roster
re-checkpoints forward at v2 — a rotation, like a floor re-sign. Persisted-tip reconstructions read the new
fields optional-with-default (`base_* = 0` for a v1 envelope), so an unpruned v1 tip round-trips
byte-identically; a **pruned** head's checkpoint now round-trips its boundary (previously there was no such
checkpoint field, so nothing regresses).

## Consequences

- `witness_service._checkpoint_from_obj` and `apps/sigil/sigil/spine/witness.py` reconstruct `base_*`
  (else a witnessed checkpoint over a pruned head would fail to re-verify after reload).
- Later slices (C-S4) that anchor a floor advance to a witnessed checkpoint inherit the boundary fields for
  free — the anchor now carries `base_*` / root, which is why C-S1 lands before C-S4.
