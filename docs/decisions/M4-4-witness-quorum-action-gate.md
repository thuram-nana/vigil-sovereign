# M4.4 — the optional witness-quorum conjunct (6c) is the authority gate's default-off, demote-only veto

Milestone: M4 — ASSURANCE CONSOLIDATION · conjunct 6c (`authority/gate.py` `authorize_action`, armed through `authority/witness_quorum_gate.py`), kept distinct from the continuous-assurance witness (`attestation_witness.py`, which countersigns a *reprove* series head, not a live ACTION).

## The claim (registered in the claims registry — id `M4-4-witness-quorum`)

<!-- CLAIM:M4-4-witness-quorum -->
> **Registered claim:** The authority gate's optional witness-quorum conjunct (6c) is OPT-IN, DEFAULT-OFF, and DEMOTE-ONLY: when it is armed with a witness_quorum_fn it DENIES (denial_code witness_quorum) an otherwise-authorized action for which fewer than the configured N-of-M independent oracle-witnesses corroborate, it runs ONLY as the final conjunct after every other leg (the blast-radius veto 6b included) has cleared, it is byte-identical to the gate without it when unarmed, and it adds no new OracleKind and no change to the frozen _ALL_ORACLES.

## Why this exists

The authority gate is the one checkpoint every target-touching action passes. Its verdict is a conjunction and the first failure wins. Some deployments want a stronger corroboration requirement than a single oracle firing: an N-of-M quorum of *independent* oracle-witnesses before a sensitive action is authorized. M4.4 adds that as conjunct 6c, built to the same discipline as the blast-radius veto (6b):

- **Opt-in and default-off.** The conjunct runs only when `authorize_action` is passed a `witness_quorum_fn` (and, for the proceed-below-quorum path, a `witness_quorum_ack`). Absent them the gate never evaluates the quorum and its decision is byte-identical to a build without the conjunct — `make gate` stays byte-identical because no payload code path changed.
- **Demote-only.** The conjunct can only turn an otherwise-ALLOW into a DENY (code `witness_quorum`); it never widens authority. It runs as the *final* conjunct, after every other leg — including the 6b blast veto — has already cleared the action.
- **No new oracle surface.** The quorum re-executes existing oracle-witnesses; it adds no `OracleKind` (the enum stays at 49) and does not touch the frozen `_ALL_ORACLES` fallback (which stays at 15).

Threading the conjunct through every production engagement caller so a deployment *requires* the quorum on every applicable action is named follow-on work; the mechanism is built and reachable, armed per-call, and default-off today (recorded as `LIMIT-witness-quorum-action-gate-default-off` in `docs/limitations/inventory.json`).
