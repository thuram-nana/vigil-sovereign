# W7-1 — Define, document and ASSERT the disaster-recovery objectives (RPO / RTO)

Issue: [#459](https://github.com/thuram-nana/vigil-sovereign/issues/459) ·
Milestone: W7 — BACKUP / DISASTER RECOVERY.
Builds on [W7-3](https://github.com/thuram-nana/vigil-sovereign/issues/461) (a restore must be drilled before
it can be timed honestly) and [W7-2](https://github.com/thuram-nana/vigil-sovereign/issues/460);
related to [W8-1](https://github.com/thuram-nana/vigil-sovereign/issues/467) (the staleness monitor is the
operational half of the RPO).

## The defect

**No RPO or RTO stated anywhere** — only cadence hints in timer comments — and the drill proved the round-trip
*works* but never that it works *fast enough* or recovers *fresh enough* data. A customer could not be told how
much data they can lose or how long recovery takes, and **RTO was unbounded because failover is fully manual**.

## The objectives (numbers)

| Objective | Value | What it bounds | Enforced by |
|-----------|-------|----------------|-------------|
| **RPO** — Recovery Point Objective | **24 hours** (`86400 s`) | The most data a disaster can cost, in time. Bounded by the **backup cadence**: `vigil-backup.timer` / `vigil-backup-push.timer` fire `OnCalendar=daily`. | The daily timers keep the newest good copy ≤ 24h old; the `vigil-alerts` staleness monitor ([W8-1] #467) alarms if a timer stops firing so the newest copy ages past the RPO; and the drill fails if the backup it restored is older than the RPO. |
| **RTO** — Recovery Time Objective | **30 minutes** (`1800 s`) | The budget for the **`vigil restore` data-restore step** (decrypt + verify the signed manifest + stage + atomic swap + post-restore re-verify). | The recovery drill times the real restore and fails if it runs longer. |

Both numbers live in exactly one place in code — `tools/backup/objectives.py` (`RPO_SECONDS`, `RTO_SECONDS`)
— and this table quotes them. Tighten the timers **and** those constants together to promise a shorter RPO.

### Honest scope of the RTO (the issue's own point)

The RTO measures the **automated data restore only**. It does **NOT** include operator **detection** of the
outage, the human **decision** to fail over, provisioning **fresh hardware**, or **DNS / service cutover** —
those remain **manual** and are the operator's runbook time, not something this code can measure or promise.
Recovery is *fail-over-assisted*, not fully automatic; claiming an automated end-to-end failover RTO would be
untrue, so we do not. The manual steps and their rough time budget are the operator's DR runbook; the number
above is the one the software is accountable for and the one the drill enforces.

## The claim (register in the claims registry, [W0-3] #398)

<!-- CLAIM:W7-1 -->
> VIGIL states its disaster-recovery objectives numerically — RPO = 24 hours (the daily backup / off-host-push cadence) and RTO = 30 minutes (the `vigil restore` data-restore budget) — and the recovery drill ASSERTS them: it times the real restore and measures the age of the backup it restored, and fails fail-closed when the recovery time exceeds the RTO or the data loss exceeds the RPO. The RTO covers the automated data restore only, not manual detection / decision / hardware / DNS cutover, which stays the operator's runbook time.

This claim is TRUE of the code as of W7-1:

- **One source of truth, unit-testable and deterministic.** `tools/backup/objectives.py` defines `RPO_SECONDS`
  / `RTO_SECONDS` and the pure gate `assert_within_objectives(recovery_seconds=…, data_loss_seconds=…)`, which
  RAISES `ObjectiveError` when the recovery time exceeds the RTO **or** the data loss exceeds the RPO.
  `data_loss_seconds(backup_name)` reads a backup's age from its `YYYYmmdd-HHMMSS` subdir name (fail-closed on
  an unparseable name). Both take an injectable `now` — no global RNG, no hidden wallclock on the assertion
  path. The module imports neither trust domain (FATAL-2 neutral), so the offense CLI, the sovereign leg, and
  the systemd drill (as a plain `python3 tools/backup/objectives.py check …`) all use the same numbers.

- **The drill enforces them end to end.** `tools/backup/recovery_drill.sh` times the real `vigil restore` and,
  after the round-trip, invokes `objectives.py check --recovery-seconds <measured> --backup-name <subdir>` —
  a non-zero exit fails the drill. "The round-trip works" is no longer enough; it must meet the objectives.

- **The negative control proves the assertion is live.** `VIGIL_DRILL_INJECT_DELAY_S` adds a real delay to the
  timed restore; with a tightened `VIGIL_RTO_SECONDS` the drill FAILS, and the objective-check CLI FAILS on a
  stale backup name — both asserted in `integration/tests/test_backup_dr_objectives.py`, alongside default-bound
  negative controls over `assert_within_objectives` itself (a restore just over 30 min, a backup just over 24h,
  are each rejected). Deleting the objective module or the drill's enforcement turns the suite red.

## Where it runs in CI

`integration/tests/test_backup_dr_objectives.py` runs in the required **integration two-env boundary (P5)** job
(offense leg — the drill's restore re-verifies the spine/evidence, which needs `framework`). The scheduled
on-host enforcement is `vigil-backup-drill.service` / `.timer`, whose failure raises a [W8-1] #467 alert.

## Residuals (honest)

- The manual failover steps (detection, decision, hardware, DNS) are outside the measured RTO by design; their
  budget is the operator's runbook, not a software promise.
- The drill mints a fresh backup, so the data-loss it measures on its own round-trip is ~0; the *operational*
  RPO — "is the newest backup on the host younger than 24h?" — is held by the daily timers plus the W8-1
  staleness monitor, not by the drill. The drill's RPO assertion is what catches restoring an over-age backup
  (e.g. an older retained copy) and keeps the two halves honest.
