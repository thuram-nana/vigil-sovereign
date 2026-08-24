# W8-3 — Witness provisioning, and the production posture refuses a solo / non-distinct witness set

Issue: [#469](https://github.com/thuram-nana/vigil-sovereign/issues/469) ·
Milestone: W8 — SPLIT-VIEW RESISTANCE IS DETECTION, NOT PREVENTION.

This record addresses a control whose weakest form ships as the default: a witnessed anti-rollback
checkpoint co-signed by ONE witness is rollback **DETECTION** via off-box retention, **not** split-view
**PREVENTION** — and solo is exactly what `sigil.spine.witness.witness_trust_root` falls back to (owner-only,
threshold 1) when no roster is configured. There was also no tooling to stand up an additional independent
witness without hand-editing a roster, and no production check that refused a solo (or non-distinct) set.

## Detection vs. prevention — the distinction this closes

* **Detection** (baseline, always holds): a witness that co-signs only an append-only extension of the tip
  it has already seen never *vouches for a fork*, and an off-box-retained witnessed checkpoint lets a
  verifier CATCH a later same-host head+floor co-rewrite. A solo / `threshold == 1` self-witness gives this
  and nothing more — the producer is signing its own anchor.
* **Prevention** (conditional): an operator cannot obtain a witness quorum for two forks at one height ONLY
  when the witness set is a **strict majority of DISTINCT witnesses** (`2·threshold > n` over `n` distinct
  canonical keys). Then any two quorums must share ≥1 honest witness, which refuses the second, conflicting
  fork. This is the exact property `transparency.is_split_view_resistant` already decides — W8-3 **reuses**
  it, it does not re-implement it.
* **Uncheckable residual (stated, never claimed away):** distinctness of *keys* is checkable; INDEPENDENCE
  of the *parties* custodying them is a deployment property code cannot verify. A strict-majority roster
  whose keys are all held by one operator is arithmetically resistant but provides no real independence.

## The claim (registered in the claims registry — [W0-3] #398, id `W8-3`)

<!-- CLAIM:W8-3 -->
> Under `VIGIL_POSTURE=production` (or `prod`, case-insensitive) the refuse-to-start production gate REFUSES `vigil up` / `vigil engage` unless the transparency-log witness set is a STRICT MAJORITY of DISTINCT witnesses — the `witness` precondition must be `DISTINCT-QUORUM`, decided by REUSING `transparency.is_split_view_resistant` (`2*threshold > n` over `n` distinct canonical keys). A solo self-witness (the shipped default, reported `SOLO`) is refused as detection-not-prevention, and witnesses that share a canonical key are refused as `NOT-DISTINCT` (any base64 encoding of one Ed25519 key collapses to one point, so a roster cannot fake a quorum from a single key); a sub-majority threshold or a non-canonical / low-order key is likewise refused fail-closed. The provisioning tool `python -m vigil_integration.witness_provision` stands up an additional witness end-to-end with no hand-editing (`add` mints a new persistent 0600 key and registers it; `register` adds an out-of-band independent witness's advertised public key) and RECOMPUTES the strict-majority threshold, and it refuses to register a duplicate canonical key so the tooling can never itself build a non-distinct roster. This is ADDITIVE and OPT-IN: with `VIGIL_POSTURE` unset the gate is inert and the non-production default is byte-identical to before.

## Why this is TRUE of the code

- **Reuses the merged distinctness rule.** `witness_provision.roster_posture`
  (`integration/vigil_integration/witness_provision.py`) builds a `vigil_core.TrustRoot` from the on-disk
  roster and calls `transparency.is_split_view_resistant` as the sole authority for the pass/fail verdict —
  it returns `DISTINCT-QUORUM` only when that rule holds AND there are ≥2 witnesses. The dedup is over the
  DECODED 32-byte Ed25519 point (not the malleable base64 string), and a non-canonical / low-order key fails
  closed — both inherited from `is_split_view_resistant`, not re-derived.
- **First-class production precondition.** The `witness` control is registered in the SHARED
  `vigil_core.doctor.REQUIRED_CONTROLS` (good-state `DISTINCT-QUORUM`), so `vigil doctor` and `sigil doctor`
  render it and `evaluate_production_gate` (`integration/vigil_integration/doctor.py`, probe
  `_posture_witness`) gates on it — the same fail-closed, opt-in machinery as the other seven controls.
- **End-to-end provisioning, no hand-editing.** `provision_witness` mints a persistent 0600 witness key via
  `witness_service.load_or_create_witness_key` and `register_authorizer` appends it with a recomputed
  `strict_majority_threshold(n) = n // 2 + 1`, atomically (0600). Two `add`s reach `DISTINCT-QUORUM`.
- **The negative control is real.** Two authorizers sharing one canonical key are rejected `NOT-DISTINCT`,
  `is_split_view_resistant` returns `False` for that trust root, and the gate names `witness` in its
  refusal — all exercised in `integration/tests/test_witness_provision_posture.py`.

## Honest residual (infra)

Genuine independence needs the second witness on a DIFFERENT operator's box. `witness_service serve`
(shipped, W-A3) is the transport an independent party runs on their own host over a WireGuard/Tailscale
tunnel, advertising its key at `GET /pubkey`; `witness_provision register --pubkey` pins that key. The
END-TO-END stand-up against a REAL separate host is an infrastructure step this tooling PREPARES but cannot
perform inside a hermetic CI check — it needs a second host and a tunnel. The falsifiable required-CI core
is the posture gate + the distinctness rejection (`is_split_view_resistant`), which run offline and
deterministically; the cross-host stand-up is the stated residual.

## FATAL-2

`witness_provision` imports only `vigil_core` + the `vigil_core`-only `transparency` layer at module level
(key MINTING lazily pulls the `vigil_core`-only `witness_service`), so the offense-plane `_posture_witness`
probe reads the roster and decides distinctness WITHOUT co-loading `sigil` / `framework` / `strix`. A
subprocess boundary test in `test_witness_provision_posture.py` asserts no forbidden plane is imported.
