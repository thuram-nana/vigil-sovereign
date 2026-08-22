# W13-6 — Restricted mode: a safe landing state, over the EXISTING kill-switch, never a new policy engine

Issue: [#499](https://github.com/thuram-nana/vigil-sovereign/issues/499) ·
Milestone: W13 — SOVEREIGN CONTROL PLANE (ANTIC programme) · Interacts with [W10-5b] #478 (`vigil panic`),
[W13-2] #495 (`sovereign_bridge`), and the integrity verifier ([W16-STD] integrity_verifier).

## The claim (registered in the claims registry — [W0-3] #398, id `W13-6`)

<!-- CLAIM:W13-6 -->
> **Registered claim (W0-3 #398):** VIGIL has a RESTRICTED MODE — a safe landing state between fully-operational and the `vigil panic` hard-stop. It is a FACADE over the existing machinery, never a second policy engine: entering restricted mode TRIPS the existing per-engagement kill-switch (the same primitive `vigil panic` trips), so the ALREADY-EXISTING conjunctive authority gate REFUSES every target-touching / mutating action, fail-closed and persistently, while the process stays UP so read-only diagnosis, evidence access, audit export and authorization repair still work. An integrity failure (`enforce_integrity_or_restrict`, over the existing `verify_integrity` audit) transitions the system into restricted mode rather than crashing or continuing, and a clean audit leaves it fully-operational. Entering and leaving are recorded on a `vigil_core` hash-chained, tamper-evident ledger that survives a restart, and `emergency-stop` enters the mode deliberately. Enforcement of the integrity→restrict transition is OPT-IN at this stage: it fires when `enforce_integrity_or_restrict` is invoked (directly, or from the integrity monitor's alarm-sink), and AUTO-invoking it on every integrity-monitor tick / at boot is named follow-on work below.

## Why this exists

Before W13-6 the system had exactly two states: fully operational, or the `vigil panic` HARD-STOP
(kill-switches tripped **and** the process/units killed and masked). An integrity failure therefore had no
safe middle ground — it either kept running on a spine it could no longer trust, or it took the whole
process down and lost the ability to diagnose the failure and export the evidence about it. Restricted mode
is that middle ground.

## The design — reuse, not a parallel engine (the HARD CONSTRAINT)

The red-pen caught a parallel policy engine forming in `vigil patch` this session, and #499 forbids
repeating it. So restricted mode decides **nothing** on its own:

* **Refusal routes through the EXISTING kill-switch/gate.** `restricted_mode.enter_restricted_mode` trips
  the existing `framework.v2.authority.killswitch.KillSwitch` for every engagement (via
  `restricted_mode.trip_all_killswitches`, the same `KillSwitch` primitive `vigil panic` uses). The
  ALREADY-EXISTING `authorize_action` → `conjunctive_gate` → `sovereign_bridge` chain then denies every
  gated action with the kill-switch's own `halted` denial code. There is **no new gate**.
  `restricted_mode_permits()` only NAMES the reduced read-only surface (diagnostics / evidence-export /
  audit-export / authorization-repair) so a caller/test can assert the mode per capability — it makes no
  authorization decision and touches no target.
* **The transitions are a RECORD, not a decision.** Enter/leave are appended to a hash-chained ledger built
  from the same `vigil_core` chain primitive the signed spine uses (`append_entry` over `digest_payload`),
  so they are on the chain, tamper-evident (a tampered/deleted line is rejected on read), and survive a
  restart (the current mode is the last transition on disk).
* **The integrity check reuses `verify_integrity`.** `enforce_integrity_or_restrict` runs the existing
  audit and, on a FAIL, enters restricted mode; it never raises for an integrity failure.

`vigil emergency-stop` enters the mode deliberately (distinct from `vigil panic`, which additionally
contains the process/units); `--leave` records a deliberate leave transition and `--status` prints the mode.

## Honest scope / follow-on work

Actually CLEARING a tripped kill-switch stays a separate, explicit operator act (authorization repair) —
leaving restricted mode records the audit event but never silently re-arms the target-touching path. And
AUTO-invoking `enforce_integrity_or_restrict` on every integrity-monitor tick and at process boot (so a
production box lands in restricted mode with no operator in the loop) is named follow-on work and is pinned
by an `xfail` in `integration/tests/test_restricted_mode.py`.
