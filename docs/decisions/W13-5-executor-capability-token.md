# W13-5 — Capability tokens are validated at the EXECUTOR boundary (single-use, nine-field bound)

Issue: [#498](https://github.com/thuram-nana/vigil-sovereign/issues/498) ·
Milestone: W13 — SOVEREIGN CONTROL PLANE (ANTIC programme) · Blocked by [W13-2] #495, [W13-3] #496,
[W13-4] #497 · Shares the operation-hash notion with [W0-11] #406.

## The claim (registered in the claims registry — [W0-3] #398, id `W13-5`)

<!-- CLAIM:W13-5 -->
> **Registered claim (W0-3 #398):** The offense executor validates a nine-field-bound, single-use, owner-signed capability token immediately before it launches a tool, and burns the token's nonce in the existing O_EXCL nonce ledger, so an authorization decision cannot be stale, replayed, or reused for a different operation by the time execution happens.

## Why this exists

An authorization decision is made far from the thing that acts — the gate chain runs, an owner approves, a
plan is composed — so by the time the OFFENSE executor actually launches a tool the decision can be **stale,
replayed, or reused for a DIFFERENT operation**. W13-5 closes that window: the executor validates a token
bound to the EXACT operation it is about to run, right before it runs it, and burns a single-use nonce so
the same authorization cannot fire twice or be transplanted onto another operation.

## This is a FACADE over existing machinery, NOT a second policy engine

The programme's HARD CONSTRAINT (the anti-pattern the red-pen caught in `vigil patch`): `sovereign_bridge`
and its siblings are facades over the existing gates, never a parallel policy decision point. A capability
token makes **no authorization decision** — the gate chain (`conjunctive_gate` / `sovereign_bridge` /
`require_capability` / WARDEN tiers) already decided. A token is the owner-signed *receipt* of that
decision, bound to a concrete operation; this layer only VALIDATES that a presented token matches the
operation the executor is about to run and CONSUMES its nonce exactly once. It reuses:

- the **O_EXCL single-use nonce ledger** (`integration/vigil_integration/live/nonce_ledger.py` —
  `NonceLedger`, the atomic exclusive-create serialization point), imported directly (same class identity);
- `vigil_core`'s Ed25519 sign / `verify_one` / `canonical_json` / `load_public_key` — the same crypto the
  sibling `approval_token` (per-action approval) uses; and
- the same fail-closed discipline as `approval_token`, of which this is the executor-boundary sibling with
  the fuller nine-field binding.

## The nine bound fields (all signed; every one validated against the operation the executor is about to run)

`deployment`, `engagement`, `operation_hash` (over tool+target+args), normalized `target`, `tool`,
`danger_class`, `policy_digest`, `expiry`, and a single-use `nonce`. A mismatch on any one is a fail-closed
DENY; a token past expiry is void; a replayed nonce loses the atomic O_EXCL race and is refused.

## Where it is TRUE of the code

- **The token** — `integration/vigil_integration/live/capability_token.py`: `CapabilityToken` (nine bound
  fields + signature), `verify_capability_token` (pure fail-closed check of all nine), and
  `consume_capability_token` / `require_capability_token` (atomic check-and-burn through the O_EXCL ledger).
  Import-clean (`vigil_core` + stdlib only), so it crosses the two-env boundary like `approval_token`.
- **The executor boundary** — `integration/vigil_integration/live/external_tool.py`:
  `_capability_boundary_refusal` builds the `CapabilityGrant` describing the EXACT operation the runner is
  about to launch (its real argv → `operation_hash`, the normalized target, the tool, the danger class, the
  enforced `policy_digest`) and calls `require_capability_token` **immediately before** `backend.run(...)`.
  It is consulted on EVERY exec path in `run_external_tool`; a refused token returns `status="refused"`
  before any subprocess is launched.
- **Proof** — `integration/tests/test_capability_token.py` proves the token machinery (valid authorizes
  exactly once; the four AC negative controls — replay, different operation_hash, past expiry, different
  target — each refused; every one of the nine bound fields enforced; sleeper-window, forged-signature and
  non-owner-key refusals; the ledger is the existing O_EXCL `NonceLedger` by class identity) AND the
  STRUCTURAL invariant that `run_external_tool` consults the boundary before it runs (pure AST, with its own
  negative control proving the structural check is not a no-op). `integration/tests/test_executor_capability_boundary.py`
  drives the REAL runner end-to-end: a valid token launches the tool and burns the nonce; a replayed,
  expired, different-operation or different-engagement token is refused with the tool never launched (a spy
  backend records launches).

## The test that fails without this change (observed, not assumed)

`integration/tests/test_capability_token.py` imports `vigil_integration.live.capability_token` at module
scope; on a tree without W13-5 that module does not exist and the file ERRORs at collection. Additionally
its structural test `test_executor_consults_the_capability_boundary_before_running` fails on the pre-change
`external_tool.py` (the boundary call is absent — verified against `git show HEAD:…`).

## Residual / blocking_work (honest)

- **Making a capability token MANDATORY for every executor invocation.** Today the boundary enforces the
  token whenever a `CapabilityCheck` is threaded (the architecturally-consistent shape — `approval_token`
  is likewise per-action / opt-in); when none is threaded the existing gate chain governs, unchanged, so
  the ~30 existing byte-identical runner callers are not broken. Minting the token at the sovereign
  approval leg and threading it through `HexstrikeAgentBody._run_via_external_tool` (and every other
  caller) so that a production deployment REQUIRES a token on every run is follow-on work.
- **Revocation propagation** is out of scope for this slice (the token is single-use + short-window; a
  short-TTL revocation set is the general mechanism, as `vigil_core.capability` already documents).
