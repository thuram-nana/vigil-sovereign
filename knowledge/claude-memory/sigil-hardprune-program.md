---
name: sigil-hardprune-program
description: "SIGIL cold-archive hard-prune (record deletion) program — VAULT-PRUNE design, Slices A/B/C merged, D/E remaining"
metadata: 
  node_type: memory
  type: project
  originSessionId: 7758e121-f349-47d5-886b-6bb5a1d60e27
  modified: 2026-07-19T23:43:13.574Z
---

SIGIL cold-archive **hard-prune** (record DELETION from the append-only spine) — the C1 tamper-evidence
tradeoff the owner explicitly signed off on (2026-07). Design = **VAULT-PRUNE** (won a 16-agent judge panel,
0 fatal flaws). Prune deletes `[0..K)` from the live set behind a signed Merkle snapshot + MOVES pruned
segments to an offline archive (recoverable; bounded C1 exposure). Repo `/home/kali/sigil`
(thuram-nana/sigil). Full spec: `<scratchpad>/hardprune_SPEC.md`; census+fold-list: `<scratchpad>/sliceC_census.md`;
per-bearer fold specs: `<scratchpad>/sliceC_foldspecs.md`.

**Doctrine:** spine is append-only, hash-chained, Ed25519-signed. Hard-prune keeps `entry_count` ABSOLUTE
(base_count + live) so verify/classify_head/signed-head are reused. Every slice = build → dual adversarial
review + independent re-check on the FIXED code → merge. Each review round has caught a REAL defect.

MERGED to main (byte-identical until an actual prune; **no prune ships until Slice E**):
- **Slice A** @e72991b (PR #18) — head-schema v2 (6 fields: base_seq, base_prev_hash, base_count,
  cumulative_merkle_root, snapshot_seq, prev_head_hash; defaulted to no-prune identity). Version-conditional
  `_head_payload` (v1 signs byte-identical). `classify_head` by-seq window + left-edge pin + UNCONDITIONAL
  signature check. Review caught BLOCK: sig check was gated behind `signed_live>0` → a forged unsigned
  zero-anchor head read benign (fail-open) → fixed unconditional.
- **Slice B** @1726e8e (PR #19) — durable external `floor.json` (SIGIL_HOME root, OUTSIDE spine/ so reset
  can't lower it; 0600; monotonic {entry_count PRIMARY, last_seq, base_seq, base_count} + prev_head_hash
  meta-chain). `checkpoint()` advances it under a `floor_lock` flock (re-load-under-lock = last-writer-
  MONOTONIC). `sigil floor status|reset --yes`. Review+re-check caught 2 MED (non-atomic advance→backwards
  race; the FIX's own os.open bricked signing) + 2 LOW (overclaim comment; misleading `sigil sign`). Honest
  limit: a same-host attacker who can write head.json can also rewrite the UNSIGNED floor.json — floor only
  protects out-of-band / reset-survival / head-only-overwrite verifiers.
- **Slice C** @14c1327 (PR #20) — `spine/snapshot.py`: `SnapshotState` (one associative sub-state per
  bearer) + `build()` (prefix folder) + `load()` (EMPTY identity in Slice C; VERIFIES head sig before
  trusting any declared prune, fails closed). 12 monotonic-security bearers rewired to seed-from-load + fold
  the live window (iter_records(since_seq=base_seq-1)) — byte-identical under the empty snapshot. Census
  found 16 bearers (design named ~11); "~9 provably incomplete" confirmed. fold==scan proven per bearer
  (identity + monkeypatched-split, mutation-checked). Orchestrated fan-out (12 rewriters+12 checkers+4
  test-hardeners+holistic dual review). Caught: creation-cap keyed WRONG record shape (would RESET the
  account-creation cap post-prune = FATAL false-clean); isinstance(str) guard dropped non-str keys the scan
  keeps → list-of-rows forms; archivist kept only fact-kinds vs kinds=None; **HIGH: load() trusted a forged
  snapshot's governance state (kill-switch release / rogue device authz) WITHOUT verifying the head sig** →
  `_verified_prune_boundary` now calls verify_checkpoint before trusting a prune. Bearers: nonce-highwater
  (max), killswitch latch (LWW bool), creation cap (PAIR-keyed count OR service|origin), mesh
  capability/authorized (LWW keep-revoked), promotion (LWW keep-revoked), approvals (referential-floor
  ASSERT), archivist current-view+ledgers, gesture-arm ledger (set-union), budget day-cap (retention
  invariant), warden-anchor CLI (max), device-approval dedup (min-seq). 478 pytest green.

REMAINING (see [[sigil-spine-rotation]] for the retain-all base this builds on):
- **Slice D** — `kind="snapshot"` writer + Merkle accumulator (binary, dup-last-on-odd; cumulative =
  H(prior‖delta)) + §7 referential guards (dangling parent/supersedes; oldest-open-workflow floor
  K≤min(open seq); K aligns to a sealed-segment first_seq) + archive COPY (copy→verify→NEVER-drop) +
  `sigil spine verify --with-archive` full genesis re-attach. NO live drop yet.
- **Slice E** — the tamper-model-changing cutover: PHASE A (prune.intent fsync → append snapshot →
  lock-free archive copy+verify → sign v2 head to head.json.next STAGING). PHASE B: **B1 os.replace(head.next→head)
  = THE COMMIT INSTANT** (verify + all folds flip together, keyed to head.snapshot_seq / floored at base_seq)
  → B2 floor advance → B3 manifest re-base (fresh-read set-difference, generation++) → B4 trash+unlink. +
  resolve()/PrunedRef + HTTP 410 for the ~11 content-lookup sites. **REQUIRED GATE: kill-9 crash-fuzz at
  each A/B barrier (verify-clean, no lost ack, fold-equivalence, panic-never-blocked).** Owner-key-gated +
  fleet-upgrade-gated (every paired device advertises max_head_schema>=2) + explicit flag-day sign-off.
- **Live-spine (LAST, after ALL merges):** owner runs backup→migrate→compact→verify on the real 93MB spine.
  Perf note for D/E: load() calling verify_checkpoint on every consumer when snapshot_seq>=0 needs a
  change_token cache (dormant in Slice C — legit heads carry snapshot_seq=-1).
