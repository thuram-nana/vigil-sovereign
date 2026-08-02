# Witness trust model + time anchoring (design spec, draft v0.1)

> Status: **DRAFT — design, not a guarantee.** This states the trust assumptions, collusion tolerance, clock
> model, and external-anchor fallback for the witnessed, time-bounded Continuous Attestation Log **before** the
> VF-1c wiring is built on them, so they can be reviewed adversarially and implemented honestly. Every guarantee
> below states what it assumes and what breaks it (§5). Designing a witnessed transparency layer is squarely a
> "don't roll your own" area — external review is warranted before real-world reliance.

Companion to `PROTOCOL.md` (parties, modes, binding) and `REMEDIATION-SEMANTICS.md` (the negative proof + state
machine). This document is about **Mode W** (§3 of the protocol): witnessing the attestation *series head* and
folding a witness-observed **time** into the co-signed checkpoint.

## 1. What a witness attests (and what it does NOT)

A witness co-signs a **`Checkpoint`** — a summary of the attestation-series head:
`{last_seq, entry_count, head_hash, merkle_root, prev_checkpoint_hash}`
(`integration/vigil_integration/transparency.py:58-79`), chained to the prior checkpoint. A witness signs it
**only** after checking it consistently EXTENDS the last checkpoint that witness tracked (`Witness.would_accept`
→ `consistent()`, `transparency.py:103-116`: no record-count shrink, no `last_seq` rollback, an intact chain
link, no same-height fork). So a witness vouches for **log-state continuity**, nothing more.

A witness does **NOT** attest that any finding is true, that a remediation actually holds, or that an oracle
fired. That is the oracle's job and only the oracle's (the standing authority invariant). The witness layer
adds exactly two properties on top of the already-oracle-confirmed, signed, chained series:
**non-equivocation** (two verifiers cannot be shown divergent series) and a **time bound** (§4). Conflating
"witnessed" with "true" would be an overclaim — the doc, the code, and the exports must not.

## 2. Independence and collusion tolerance

Split-view resistance is a property of **distinct, independently-operated** witnesses. The code enforces the
cryptographic half and is explicit about the operational half it cannot:

- `is_split_view_resistant` (`transparency.py:244-268`) returns true **only** for a **strict-majority** quorum
  (`2*threshold > n`) over `n` **distinct, canonical** Ed25519 keys. It fails closed on an empty set, on any
  **duplicate public key** (two `key_id`s, one pubkey would collapse the quorum — `TrustRoot` dedups `key_id`s
  only), and on any non-canonical (`y ≥ p`) or **low-order** key (a low-order key admits a keyless forgery).
- **Collusion tolerance (prevention).** With a strict majority, any two quorums intersect in `≥ 2t − n`
  witnesses, and an honest, *stateful* witness never signs two forks. So split-view is **prevented** unless
  `≥ 2t − n` witnesses actively equivocate (are dishonest/colluding). The system therefore tolerates up to
  **`2t − n − 1`** colluding witnesses for *prevention*.
- **Below strict majority (`2t ≤ n`)** two disjoint quorums can each sign a different fork with **no** witness
  equivocating — prevention is impossible; only **per-witness non-equivocation + DETECTION** remain (a single
  honest witness that sees both views detects the fork). `verify_witnessed` proves *a* quorum signed;
  `verify_split_view_resistant` is the one that gives the full guarantee, and only at strict majority.
- **The operational assumption the code CANNOT enforce.** Distinct keys ≠ distinct operators. If the producer P
  holds all the witness keys, the quorum is **theater**. Prevention/detection are only real when the witnesses
  are run by **mutually-distrusting parties** — e.g. O, V, a neutral third party, and a public log. This is a
  deployment trust assumption, stated here and surfaced at verify time (the verifier is handed the witness
  `TrustRoot` out-of-band and must satisfy itself the keys are independently operated); it is **not** implied by
  a passing `is_split_view_resistant`.

## 3. Wiring (what VF-1c adds)

The primitives exist but are **not wired to the attestation series**, and the checkpoint carries **no time**
(the fields in §1 have no timestamp — `transparency.py:72-79`). VF-1c:

1. Emits a `Checkpoint` over the **Continuous Attestation Log head** (the signed, chained drift series of
   VF-1b), not just a spine head.
2. Extends the co-signed bytes with each witness's **observed time** (§4) so the quorum carries a time bound.
3. Verifies the quorum with `verify_split_view_resistant`, checks the checkpoint chain for gaps/rollback, and
   exposes the time bound to the VIGIL-free verifier.

## 4. The clock model — an honest "time bound"

Each witness, when it co-signs, includes the **time it observed** the checkpoint, `τ_i`, **inside** the signed
bytes (so `τ_i` is signed DATA, never a wall-clock read in the verify math — consistent with the determinism
invariant and the existing dead-man's-switch pattern).

- **What the quorum time means.** `T_witness = median(τ_i over the quorum)`. Under the assumptions *(a
  strict-majority-honest quorum, and a bounded inter-witness clock skew δ)*, the median is sandwiched between
  two honest witnesses' clocks, so `|T_witness − (true time the checkpoint was witnessed)| ≤ δ`. The median (not
  min or max) is deliberate: a single dishonest witness reporting an extreme `τ` cannot move a
  strict-majority-honest median.
- **CRUCIAL — "quorum" means the PRESENTED SIGNING quorum, not the roster.** The verifier judges the sigs it is
  handed, and a fully-dishonest **producer** curates them: it can drop honest witnesses' sigs and present only a
  quorum of its choosing. So the honest-majority assumption must hold over the **signing** set, which the
  producer controls — not over the n-key roster. Consequently a roster **minority** of `floor(t/2)+1` colluding
  signers can shift `T` (back- or post-date), *possibly below* the `2t−n−1` non-equivocation tolerance: **the
  clock bound is STRICTLY WEAKER than non-equivocation** (do not present them as equally robust). The verifier
  cannot check signer honesty; it can only (a) demand a larger presented quorum (`min_distinct_signers` toward
  `n`, so honest sigs cannot be silently dropped) and (b) defer any HARD time claim to the external anchor (§5).
- **What it bounds — and what it does NOT.** It bounds **when the checkpoint was WITNESSED**, i.e. when the
  attestation-series head existed and was presented to the quorum. It does **NOT** by itself prove *when the
  oracle re-fired*. A producer can present an OLD (un-re-verified) head to honest witnesses *today* and get a
  recent `T_witness` — that truthfully says "this head existed and was witnessed today," **not** "a fresh
  re-verification ran today." **Re-proof freshness is a separate property**: it lives in the attestation record
  itself (the drift tick's recorded time, VF-1b) and, against the target, in the **target-echoed nonce** of the
  Mode-L driver (VF-1a / PROTOCOL §5). The continuous-proof claim "still-remediated as of ~T" is sound only
  when the RECORD carries a fresh re-proof AND that record's checkpoint carries a `T_witness` near T. The spec,
  the log, and the docs must keep these two times distinct and never let a recent witness time stand in for a
  stale re-proof.
- **Strength.** This is a quorum civil-time bound with **no external service** — weaker than a single trusted
  timestamp. It is honestly labelled as such.

## 5. External anchor (the stronger, deferred fallback)

For a stronger, single-source time/inclusion guarantee, anchor the checkpoint out-of-band:

- **Inclusion (built).** `scitt.py` implements RFC-6962 Merkle inclusion + a SCITT-style `Receipt` and a
  `StatementLog` whose roots are anchored to witnessed checkpoints (`scitt.py:6-9, 233-238`). A regulator/court
  verifies the DSSE governance signatures, the inclusion proof against the log root, and the anchoring
  checkpoint — **offline**. **Caller-pinned root:** the verifier MUST pin the expected log root out-of-band; a
  receipt that carries its own root and is trusted is not a proof (this was a real prior review finding).
- **Trusted time (designed hook, not built).** An **RFC3161 TSA** token or an **OpenTimestamps/blockchain**
  proof over `checkpoint_hash` (`transparency.py:97-100`) yields a single, externally-trusted "existed no later
  than T" that does not depend on witness honesty or clocks. This is the already-designed deferred hook; when
  built it SUPERSEDES the median-clock bound for the "no-later-than" claim and downgrades §4 to a
  liveness/recency signal.

## 6. Security considerations (assumptions + what breaks)

- **Independence.** All the above is theater if one party runs the whole quorum. Prevention needs a
  strict-majority quorum of independently-operated, honest witnesses (§2); the deployment must ensure it, and
  the verifier must satisfy itself of it — a green `is_split_view_resistant` proves distinct *keys*, not
  distinct *operators*.
- **Collusion.** Prevention tolerates `≤ 2t − n − 1` colluding witnesses; beyond that only detection remains,
  and below strict majority even prevention is gone.
- **Clock.** `T_witness` assumes a strict-majority-honest quorum and bounded skew δ; it bounds *witnessing*
  time, not re-proof time (§4). Prefer the external anchor (§5) where a hard time guarantee is required.
- **Liveness.** Witnessing cannot be forced; a producer can decline to seek a quorum. Absence of a fresh
  witnessed checkpoint is itself a signal (a gap in the series), which the chain check surfaces — the log is
  **gap-detectable**, and a missing tick is not silently a "still-secure."
- **Scope of the guarantee.** Witnessing adds non-equivocation + a time bound to an **already oracle-confirmed,
  signed** series. It never promotes a finding, never stands in for the oracle, and never converts "witnessed"
  into "true."

## 7. Relationship to what is built

Built: `transparency.py` (`Checkpoint`, `consistent`, `Witness.cosign`, `verify_witnessed`,
`verify_split_view_resistant`, distinct-canonical-key enforcement) and `scitt.py` (RFC-6962 inclusion + SCITT
receipt + checkpoint-anchored `StatementLog`). **Not yet built** (VF-1b→VF-1c, each its own reviewed slice):
the signed+chained Continuous Attestation Log itself, emitting checkpoints over ITS head, folding the
witness-observed time into the co-signed bytes, and exposing the quorum time bound + gap/rollback detection to
the VIGIL-free verifier. The RFC3161/OTS external-time anchor (§5) remains a designed, deferred hook.
