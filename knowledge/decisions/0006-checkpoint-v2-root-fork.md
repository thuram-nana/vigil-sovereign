# ADR 0006 — Transparency checkpoint v2: commit the prune boundary (and why the merkle root is NOT a fork signal)

- **Status:** Accepted (superseding an earlier draft of this same ADR — see "Correction" below)
- **Scope:** VIGIL (`/home/kali/vigil`, repo `thuram-nana/vigil-sovereign`) — Claim 6 "state-root residuals", slice C-S1
- **Affects:** `integration/vigil_integration/transparency.py` and every consumer of a witnessed checkpoint

## Context

A `transparency.Checkpoint` is the public, witnessable summary of a signed spine head. Before this change
it carried five fields (`last_seq`, `entry_count`, `head_hash`, `merkle_root`, `prev_checkpoint_hash`).
`is_split` — the primitive that lets a client prove a split view after the fact — keyed **only** on
`head_hash`. The stated residual was that a differing `merkle_root` at the same `head_hash` + `entry_count`
was not adjudicated, and the first draft of this slice proposed committing the prune boundary
(`base_seq`/`base_count`) to make that root difference "decidable" — the theory being that at one
`entry_count` **and** one prune boundary the leaf set is fixed, so the cumulative root would be a
deterministic function of it.

## Correction — that theory is false; the cumulative root is prune-schedule-dependent

An adversarial review disproved the decidability premise with the real merkle functions. The
`cumulative_merkle_root` is **not** a canonical function of the leaf set `[0..base_seq)`. It is a running
left-**fold over the prune SCHEDULE**:

- `apps/sigil/sigil/spine/merkle.py`: `chain_cumulative(prior, delta) = H("C:" ‖ prior ‖ "|" ‖ delta)`,
  folded **once per prune operation**, where each `delta` is `merkle_root(the batch of records that prune
  removed)`.
- `apps/sigil/sigil/spine/prune.py`: the prune boundaries `[k_prev..K)` are **operator-chosen** (the
  safety check only requires contiguity); nothing pins a canonical batching cadence.

So two **honest** producers that prune the *same* records to the *same* final boundary using *different
batch sizes* produce **different** cumulative roots. Meanwhile `head_hash` is schedule-**invariant**: it
hash-links the entire ordered entry chain (the re-based live-window tip), independent of how the pruned
prefix was batched. Reproduced: pruning `[0..40)` in one step vs. `[0..20)` then `[20..40)` yields two
different cumulative roots for an identical entry history.

**Consequence for fork detection:** keying `is_split` on a same-boundary root difference would emit
"cryptographic proof of a fork" for two views that agree on **every entry** — a false accusation of an
honest re-prune (e.g. a restore-from-archive that re-prunes on a different cadence, or two replicas). That
is exactly the "never false-accused" property the slice promised, broken. `head_hash` already provides
complete and sound fork detection at a given height, so adjudicating the root adds **no** real detection
power and only introduces false positives.

## Decision (sound version)

1. **Commit the boundary — for identity + un-prune detection, NOT for root adjudication.** `Checkpoint`
   gains `base_seq` / `base_count` (default `0` = nothing pruned), in `to_dict()` and populated by
   `checkpoint_of()` from the head. They become part of the checkpoint's **signed identity**, so a witness
   quorum attests the prune boundary, and a checkpoint **chain** can reject an **un-prune** (a boundary that
   moves *backwards* = an older-snapshot replay). These two properties are sound and were confirmed so.

2. **Do NOT adjudicate the `merkle_root` as a fork signal.** `is_split` stays keyed solely on `head_hash`
   (identical to v1 behavior). `consistent` / `_segment_extends` add the monotonic `base_seq`/`base_count`
   non-shrink guards (un-prune detection) but **no** same-boundary-root-fork clause. A same-tip, same-height
   root/boundary difference is treated as an honest re-prune, never a fork.

3. **Wire-format rotation (anti-replay).** Committing `base_*` in `to_dict()` changed the signed bytes, so
   the witness domain is bumped `vigil-transparency-checkpoint-v1\x00` → `…-v2\x00` and the multi-segment
   type marker `vigil.multi-segment-checkpoint.v1` → `.v2`. A v1 witness signature can **never** verify under
   v2, and vice-versa. Mirrored in the standalone offline verifier (`docs/proof-carrying-finding/verify_vf.py`)
   and the auditor registry (`vigil_core.spine_domains`). This rotation is still justified: the signed
   identity genuinely gained fields (the boundary), independent of the (dropped) root-adjudication idea.

### Honest scope (what this does NOT claim)

- **The `merkle_root` is not a fork signal and cannot be one from the summary**, because it is
  prune-schedule-dependent. `head_hash` is the sole, sound fork commitment (a genuine content fork differs
  there). This is unchanged from v1 — the value C-S1 adds is the boundary commitment + un-prune guard, not
  root fork-decidability.
- No change to the trust model: split-view *prevention* remains the conditional strict-majority quorum
  property; this slice strengthens the *identity* a witness attests (now including the boundary) and adds
  after-the-fact *un-prune* detection only.
- A fully-dishonest producer that also controls the witness quorum is not closed by any of this (irreducible;
  only INDEPENDENT witnesses close it — a deployment property).
- base_*=0 everywhere reproduces the pre-C-S1 verdicts for every realizable head (no-op fidelity: an unpruned
  head has `base_*=0` and `cumulative_merkle_root=""`, so no witnessed pair can reach a base_*=0
  different-root state).

## Migration

Existing **persisted v1 witnessed checkpoints verify only under the v1 domain**. The witness roster
re-checkpoints forward at v2 — a rotation, like a floor re-sign; it fails **closed** (an off-box-retained v1
anchor stops verifying until re-checkpointed), an operational cost, not a silent break. Persisted-tip
reconstructions read the new fields optional-with-default (`base_* = 0` for a v1 envelope), so an unpruned v1
tip round-trips byte-identically; a **pruned** head's checkpoint now round-trips its boundary.

## Consequences

- `witness_service._checkpoint_from_obj` and `apps/sigil/sigil/spine/witness.py` reconstruct `base_*`
  (else a witnessed checkpoint over a pruned head would fail to re-verify after reload).
- Later slices (C-S4) that anchor a floor advance to a witnessed checkpoint inherit the boundary fields for
  free — the anchor now carries `base_*`, which is why C-S1 lands before C-S4. (C-S4 anchors the ANTI-ROLLBACK
  floor to the witnessed boundary/last_seq — a sound use of the committed boundary that does not depend on the
  disproven root-decidability.)
