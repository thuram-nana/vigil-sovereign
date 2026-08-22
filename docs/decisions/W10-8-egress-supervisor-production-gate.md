# W10-8 — The seccomp egress supervisor is FORCED ON under the production posture, and its bound is stated

Issue: [#481](https://github.com/thuram-nana/vigil-sovereign/issues/481) ·
Milestone: W10 — SECURITY CONTROLS THAT DO NOT FIRE (fail-open).

This record addresses a control that **ships off-by-default and whose own docstring says it is not a
complete control** — so it must be (a) actually engaged in the production posture and (b) documented with
its bound, never sold as a complete egress boundary.

## The claim (registered in the claims registry — [W0-3] #398, id `W10-8`)

<!-- CLAIM:W10-8 -->
> The seccomp egress supervisor (`tools/egress-guard`, a connect/sendto/sendmsg seccomp user-notify filter) is off-by-default and opt-in outside production; under `VIGIL_POSTURE=production` (or `prod`, case-insensitive) it is FORCED on in `require` (fail-closed) mode regardless of `VIGIL_EGRESS_GUARD`, and the refuse-to-start production gate REFUSES `vigil up` / `vigil engage` unless its binary is built — the `egress-supervisor` precondition must be `ARMED`, and a MISSING_BINARY refuses the start. Its stated bound is documented next to where it is presented: it refuses a tool's OWN non-loopback egress and a mis-built argv, it is NOT a containment boundary for hostile code, and it does not cover a 32-bit binary, `sendmmsg`, or `io_uring` — so it is never presented as a complete egress control.

## Why this is TRUE of the code

- **Off-by-default, opt-in outside production.** `enabled()` / `required()`
  (`integration/vigil_integration/live/egress_guard.py`) read `VIGIL_EGRESS_GUARD`; unset ⇒ the guard is
  off and a spawn's argv is byte-identical to before. Nothing already deployed changes.
- **Forced on in production.** `_production_forced()` reads the ONE shared posture parse
  (`vigil_core.posture.production_posture`, pure stdlib, no cross-boundary import). When it is armed,
  `_mode()` returns `require` regardless of `VIGIL_EGRESS_GUARD`, so `enabled()` and `required()` are both
  true — `wrap_argv` wraps every spawn and RAISES `EgressGuardUnavailable` if the binary is missing rather
  than spawning unguarded.
- **Refuse-to-start gate precondition.** `_posture_egress_supervisor`
  (`integration/vigil_integration/doctor.py`) reports `ARMED` only when the guard is enabled AND its binary
  is present; `OFF` when not enabled; `MISSING_BINARY` when enabled but not built. It is a member of the
  shared `REQUIRED_CONTROLS` registry (`vigil_core.doctor`), so `evaluate_production_gate` refuses
  `vigil up` / `vigil engage` under the production posture unless it is `ARMED`. Fail-closed: a probe that
  cannot read the state is `UNKNOWN` ⇒ UNMET.
- **The bound is documented next to where it is presented.** The `egress_guard.py` module docstring carries
  the three HONEST BOUNDs (TOCTOU on `CONTINUE`; the native-arch / `sendmmsg` / `io_uring` gaps and the
  32-bit branch; the NO_NEW_PRIVS privilege-strip that makes it refuse `nmap`). The README production-gate
  section and the registry requirement text both restate that it is NOT a containment boundary and does not
  cover 32-bit / `sendmmsg` / `io_uring`, so the docs never present it as a complete control.

## How it is verified

Pinned in `integration/tests/test_doctor_production_gate.py` (required job
`integration two-env boundary (P5)`):

- `test_production_posture_forces_the_egress_supervisor_on` — under production the guard is forced to
  `require` mode even with `VIGIL_EGRESS_GUARD` unset; the NEGATIVE CONTROL asserts a non-production posture
  does NOT force it (it stays off unless the env opts in).
- `test_gate_refuses_when_egress_supervisor_binary_missing` — armed production + a missing binary ⇒ the gate
  is `MISSING_BINARY`/UNMET and refuses to start; the negative control (binary present) ⇒ `ARMED`/met.
- `test_wrap_argv_fails_closed_under_production_when_binary_missing` — the spawn-level fail-closed: under
  production `wrap_argv` raises rather than spawning unguarded when the binary is absent.

The existing `test_gate_passes_when_all_satisfied` and `test_gate_refuses_each_condition_independently` now
carry `egress-supervisor` as a seventh precondition, and `test_readme_posture_block_is_ci_regenerated_from_the_registry`
(`integration/tests/test_doctor_consolidation.py`) keeps the README block in lock-step with the registry.

## The bound, restated (never a complete control)

The supervisor is a control against a tool's **own defaults and a mis-built argv** — the recurring class
where `wapiti` reached `wapiti3.ovh`, `wapp` downloaded a database, `nuclei` phoned home. It is **not** a
sandbox for hostile code: the kernel-isolation boundary is `sandbox_exec` (bwrap `--unshare-all`). It
filters `connect`/`sendto`/`sendmsg` on the native architecture only, so a 32-bit binary, `sendmmsg`, or
`io_uring` submission would pass unseen. Enabling it in production closes the off-by-default gap; stating
the bound keeps it from being mistaken for the whole answer.
