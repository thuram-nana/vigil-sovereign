# S6 — one gate of record (unification)

## Decision

The pure authorization-gate composition (`conjunctive_decide` + `GateVerdict` / `CrucibleResult` /
`DestructionOutcome`) now lives in the neutral shared core **`vigil_core.gate`**. Both processes import the
**same** gate-of-record primitive from there; `vigil_integration.conjunctive_gate` re-exports it (byte-identical
back-compat for every existing importer) and keeps the offense wrapper `build_offense_gate`.

The primitive is a leaf (stdlib only; the WARDEN result is duck-typed via a `WardenDecision` Protocol), so it
never drags `framework`/`strix` into the owner-key process — the two-env boundary is preserved. Its fail-closed
invariants are pinned by `packages/core/vigil_core/tests/test_gate.py`:

- only an explicit WARDEN `"auto"` opens the gate — an unrecognised outcome is a **DENY**, never a silent ALLOW;
- any conjunct **raising** is a DENY (never caught-and-continued); CRUCIBLE (killswitch) is checked first;
- the destructive m-of-n conjunct uses a **strict `authorized is True`** identity check (a truthy-but-not-`True`
  value must not open an irreversible action);
- a destructive action with **no** destruction gate wired is a DENY.

## What is already unified (do not re-do)

The **offense live `vigil engage` path already routes every tool call through `conjunctive_decide`**
(`live/wiring.py:_build_gate` → `build_offense_gate` → `authorize_tool_call` → the executor proceeds only on
`verdict.allowed`). The WARDEN **tier ruleset** is already a single source: `vigil_core.warden_tiers` is a
golden-vector-pinned byte-faithful port of the Rust kernel `tiers.rs` (S2). So "one gate of record" holds today
for the offense live engine, and S6 makes the composition primitive itself neutrally shared so a **sovereign**
composition can reuse it without importing the offense engine.

## What is deliberately DEFERRED — and why (the honest "where it fails")

Folding the remaining action-bearing edges into `conjunctive_decide` is **not** a mechanical fold: each native
edge enforces a conjunct the base composition does not model, so a naive fold would **drop a conjunct and turn a
fail-closed DENY into an ALLOW** — the one thing the gate must never do. These are deferred to their own careful,
additive slices (S7/S8), where the edge's existing checks stay inside the `crucible_authorize` thunk and
`conjunctive_decide` only *adds* the WARDEN / m-of-n legs on top:

- **Raw framework path** (`vigil crucible engage` → `http_executor.gated_fetch` / `scope_gate`): enforces a
  **charter-file signature** check (`require_charter_signed`), a **running per-engagement request budget** (deny at
  cap — the live path's CRUCIBLE budget conjunct is currently inert), and **URL/method-derived destructiveness**
  (POST/PUT/DELETE, `/admin`, `/delete`, …). A fold that dropped any of these, or passed `destructive=False` where
  the URL implies destructive, would regress a deny to an allow (and skip the m-of-n leg).
- **MCP tool invoker**: has an **entitlement** conjunct (`require_capability`) with no analog in the base
  composition; folding it without threading entitlement into a thunk turns an un-entitled tool from DENY to ALLOW.
- **SIGIL Governor** (sovereign): its tier is drawn from the **Rust kernel (`tiers.rs`, the G2 owner-signed binary
  pin)**, not the Python port. Re-pointing it at `vigil_core.warden_tiers` would move sovereign classification
  integrity off the signed binary. The Governor also has **promotion** and **A0-observe-under-kill** semantics that
  `conjunctive_decide`'s killswitch-first shape does not model, so it must be **composed around**, never replaced.
  Any tier-source change must be golden-verified to not classify a name *lower* (A2/A3 → A0/A1) than the kernel.

## Follow-up for the sovereign fold (S7/S8)

The core's verdict `reason` strings still say "CRUCIBLE" (e.g. `"CRUCIBLE denied: …"`). This is intentional for
S6 — byte-identical semantics was the mandate, and existing `test_conjunctive_gate.py` cases assert on these
substrings. When the sovereign composition (SIGIL Governor) reuses this core, genericize the strings to "domain
authority" **together with** updating those assertions, as a deliberate (non-byte-identical) change in that slice.

## Invariant

No fold may turn a fail-closed DENY into an ALLOW; the m-of-n destructive conjunct is preserved; composition is via
the pure `conjunctive_decide` in **each** process — never one in-process gate that both holds the owner key and can
import `framework`/`strix`.
