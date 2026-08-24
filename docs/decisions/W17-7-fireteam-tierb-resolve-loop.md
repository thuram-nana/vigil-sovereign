# W17-7 — wire the fireteam Tier-B escalation resolve loop

**Milestone:** W17 — GOVERNANCE COMPLETENESS · **Issue:** #541 · **Registers in:** W0-3 #398.

## The claim under test

A fireteam member that proposes a dangerous / over-cap tool never runs it — it emits an
`EscalationRequest` that the `ConfirmationRegistry` QUEUES as PENDING in its durable, per-engagement
`EscalationLedger`. The registry's `resolve()` is authorized ONLY by a cryptographically signed operator
approval and never auto-approves. But until this issue NOTHING in production ever CALLED `resolve()`:
`live.wiring` built the registry, pinned the trusted approver, and left a comment saying "the sovereign
Tier-B resolve loop … is the remaining wiring step". So in practice an over-cap escalation had exactly
one possible fate — auto-REJECT at its `deadline_seq` (600 injected-sequence ticks). There was no path
for the operator to actually approve one.

This slice wires that missing caller. The sovereign signs an approval envelope
(`vigil fireteam approve`, owner key) that lands in a per-engagement signed inbox; the offense side (the
live engine's `deploy_fireteam`, and the standalone `vigil fireteam resolve`) drives `resolve_pending`,
which reads back the envelope and applies the registry's signed-only `resolve()`. The offense side holds
no private key, so it can only VERIFY a sovereign-signed approval, never mint one.

<!-- CLAIM:W17-7 --> The sovereign Tier-B escalation resolve loop is wired to a production caller: an over-cap fireteam member escalation reaches an OPERATOR DECISION — the registry's signed-only resolve() applied over an owner-signed approval envelope read back from the per-engagement inbox — instead of only ever auto-rejecting at its deadline, while a pending escalation with NO decision still fails closed (EXPIRED) at its deadline_seq and, within the deadline, stays PENDING and visible — the safe default preserved, not replaced.

## Where it is enforced

`integration/vigil_integration/fireteam/resolver.py` — `resolve_pending` is THE resolve loop and the
production caller of the registry's `resolve()` / `expire()`. For each pending escalation, in
deterministic key order:

1. **operator decision** — if a matching sovereign-signed envelope is in the inbox, call
   `registry.resolve(key, envelope, seq=now_seq)`. That verifies the Ed25519 signature against the pinned
   trusted approver key AND the exact `(engagement, wave_id, member_id, seq, "approved", True)` bytes, and
   — because `now_seq` is passed — EXPIRES a LATE approval instead of honouring it (the deadline beats a
   late signature). A durable APPROVED is committed BEFORE it is returned actionable (DEFECT-2 ordering).
2. **fail-closed deadline (preserved)** — with no envelope and `now_seq` past the escalation's
   `deadline_seq`, `registry.expire` auto-REJECTS it (EXPIRED). The safe default is preserved.
3. **still pending → visible** — with no envelope and still within the deadline, the escalation stays
   PENDING and is surfaced to the live UI feed (`fireteam.escalation.pending`, with a positive
   `ticks_remaining`) so the operator can still decide before it expires.

The production callers are `live.wiring.deploy_fireteam` (every approved wave drains the signed inbox and
sweeps deadline expiries) and the `vigil fireteam list | approve | resolve` CLI. The stale "remaining
wiring step" comment is removed.

## Why the negative controls matter

The gate is not a no-op: a forged / untrusted-key / cross-engagement / late / no-trust-root approval never
reaches APPROVED — it degrades to REJECTED or EXPIRED — and a pending escalation with no decision still
auto-rejects at its deadline. `test_fireteam_resolve_loop.py` pins all of these against the real ledger +
registry + inbox (no framework, no network — the P5 sovereign leg).
