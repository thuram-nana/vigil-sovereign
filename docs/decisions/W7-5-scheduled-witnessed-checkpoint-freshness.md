# W7-5 — Schedule the off-box witnessed checkpoint, and FAIL on a stale anchor

Issue: [#463](https://github.com/thuram-nana/vigil-sovereign/issues/463) ·
Milestone: W7 — BACKUP / DISASTER RECOVERY.
Depends on [W7-8](https://github.com/thuram-nana/vigil-sovereign/issues/466) (timers installed + enabled);
feeds [W6-7](https://github.com/thuram-nana/vigil-sovereign/issues/458) and
[W8-3](https://github.com/thuram-nana/vigil-sovereign/issues/469).

## The defect

The off-box witnessed checkpoint — the anchor the whole HA anti-rollback / failover interlock depends on
(`docs/architecture/HA-PROFILE.md` §3) — was emitted **manually and unscheduled**, and the guard did **not**
check its freshness. A months-old anchor still passed, silently widening the rollback window to whatever the
operator's last manual run was.

## The claim (register in the claims registry, [W0-3] #398)

> The off-box witnessed checkpoint is emitted **on a timer that ships enabled in the production posture**, and
> the anti-rollback / HA-failover guard **REFUSES an anchor older than a documented freshness bound**
> (`VIGIL_ANCHOR_REFUSE_AFTER_S`, default 24h) — as well as an un-dated or future-dated one — **fail-closed**.
> Staleness is **alarmed before** the refusal bound is crossed (`VIGIL_ANCHOR_WARN_AFTER_S`, default 6h). The
> bound is enforced identically on both planes (sovereign owner-witness and offense governance-witness).

This claim is TRUE of the code as of W7-5:

- **The timestamp.** Each emit stamps an unsigned top-level `emitted_at` (unix seconds) into the envelope —
  `witnessed_anchor.dump_witnessed_envelope` / `witness.dump_witnessed`, both gated so `emitted_at=None` OMITS
  the key (a legacy envelope stays byte-identical, and cross-plane byte-compat is preserved). It is
  **deliberately NOT part of the signed `Checkpoint`** — signing it would change the checkpoint's cross-plane
  signed identity and break re-verify. `witnessed_anchor.envelope_emitted_at` reads it plane-neutrally.
- **The freshness verdict.** `witnessed_anchor.freshness_verdict(emitted_at, now=…, warn_after_s=…,
  refuse_after_s=…)` returns `fresh` / `stale-warn` / `stale-refuse` / `unknown-age` / `future-skew`. It is
  **fail-closed**: a missing timestamp (`unknown-age`) and a future-dated one past the skew tolerance
  (`future-skew`) both `refuse`. One implementation, so the two planes cannot drift.
- **The guard refuses a stale anchor.** `tools/ha/spine_failover_guard.evaluate_promotion(…, now=…)` (used by
  `sigil floor promote-passive` and the standalone tool), `sigil.spine.floor_witness.verify_floor_against_witnessed`,
  and `vigil_integration.floor_witness.verify_highwater_against_witnessed` all enforce freshness on the
  **selected (highest)** anchor — the one they will actually rely on — via `select_highest_witnessed_with_age`,
  and refuse (exit 2 / `ok=False`) when it is stale. The CLI/standalone paths pass the wall clock, so
  production enforces it; a `now=None` library caller keeps the pre-W7-5 behaviour (backward-compatible).
- **The scheduler + alert.** `witnessed_anchor.run_checkpoint_once` / `run_checkpoint_monitor` emit on an
  injectable cadence + clock, refresh `emitted_at` **even on an idle spine** (liveness), write a **dead-man
  heartbeat**, and — before refreshing — raise a `warning` alarm when the current anchor is past the warn
  bound (and `critical` past refusal, `error` on emit failure). `emit_heartbeat_is_stale` is the dead-man.
- **The timers (production posture).** `apps/sigil/deploy/systemd/sigil-checkpoint.{service,timer}`
  (`sigil checkpoint emit --out <off-box>`, owner-signed) and
  `infra/systemd/vigil-checkpoint.{service,timer}` (`vigil floor witness --watch`, governance-signed) both fire
  every 15 min (far under the 6h/24h bounds) and carry `[Install] WantedBy=timers.target` — the same
  ship-and-enable convention as `vigil-integrity.timer` / `vigil-ha-mirror.timer`.

Pinned by:
- `integration/tests/test_checkpoint_freshness.py` (offense/plane-neutral) — runs in the required sovereign
  integration CI leg (whole `integration/tests` dir minus the framework-only ignore list; this file imports
  only `vigil_core` + `vigil_integration`, so it is auto-included and cannot silently skip).
- `apps/sigil/tests/test_ha_failover_guard.py` (sovereign) — runs in the required `SIGIL governor gates` CI
  job, which executes the whole `apps/sigil/tests/` directory.

Both suites include a test that **FAILS on a tree without the fix** (the pre-W7-5 API has no `now` argument
and no `emitted_at`, so the same in-scope anchor that PASSES with `now=None` cannot be judged stale — the
call raises), and a **negative control** asserted in the same run: a back-dated anchor is refused while a
fresh one is accepted, proving the gate is not a no-op.

## Honest scope (do not overclaim)

`emitted_at` is an **unsigned, fail-closed operational-drift signal**: it catches a scheduled emitter that
STOPPED (the actual W7-5 hazard) and refuses an un-datable/future-dated anchor. It is **not** a tamper
control — a same-host owner/governance key-holder who could forward-date it already defeats the whole local
floor (the irreducible all-keys-compromised limit documented in HA-PROFILE §4). The anchor's **signature** +
the anti-rollback **consistency** checks remain the tamper controls; the freshness gate sits *on top of*
them, never in their place. Legacy anchors carry no `emitted_at` and are refused fail-closed once a clock is
supplied — the migration is: re-emit with the scheduled emitter (which the timer does immediately).

## The offense↔sovereign mirror (acceptance criterion)

The freshness logic is a single plane-neutral module (`vigil_integration.witnessed_anchor`), imported by both
the offense floor witness (`vigil_integration.floor_witness`, governance-signed) and the sovereign side
(`apps/sigil/sigil/spine/floor_witness.py` + `tools/ha/spine_failover_guard.py`, owner-signed). One
implementation, one envelope format, one set of bounds — the sovereign and offense guards cannot drift, and a
scheduled anchor from either plane is read by the other's freshness reader.

> **Registration:** fold this claim into the claims registry when [W0-3] #398 lands; until then this decision
> record is the source of truth for the claim and its honest scope.
