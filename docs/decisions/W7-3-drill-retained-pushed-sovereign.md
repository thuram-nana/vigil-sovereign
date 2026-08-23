# W7-3 — Drill a retained backup and the pushed off-host copy, and cover the sovereign plane

Issue: [#461](https://github.com/thuram-nana/vigil-sovereign/issues/461) ·
Milestone: W7 — BACKUP / DISASTER RECOVERY.
Blocked by [W7-2](https://github.com/thuram-nana/vigil-sovereign/issues/460) and
[W7-4](https://github.com/thuram-nana/vigil-sovereign/issues/462) (both merged);
its failure alerts via [W8-1](https://github.com/thuram-nana/vigil-sovereign/issues/467);
it is what makes [W7-1](https://github.com/thuram-nana/vigil-sovereign/issues/459)'s timing honest.

## The defect

The shipped drill round-tripped **only a freshly-minted backup** — nothing verified that a
retained/pruned backup, or the copy pushed off-host, still restores — and the drill unit was **offense-only**:
the sovereign plane, whose whole point is a verifiable signed chain, was never drilled.

## What is now drilled

| Path | Offense plane | Sovereign plane |
|------|---------------|-----------------|
| Fresh round-trip + re-verify | `test_backup_recovery_drill.py` (shell drill) | `test_backup_recovery_drill_sovereign.py` |
| **Retained / pruned** backup restores | `test_drill_restores_a_retained_pruned_backup` — three backups, real `retention.prune`, restore a survivor (newest, and an older one via `--allow-rollback`) | `test_sovereign_drill_of_a_retained_superseded_backup` — an older superseded backup still restores to its point-in-time state |
| **Off-host pushed** copy restores | `test_drill_restores_the_pushed_off_host_copy` (restore FROM the push destination) + the scheduled `recovery_drill.sh` `VIGIL_DRILL_PUSH_DIR` leg | — (the push is an offense-orchestrated step) |
| Chain re-verify AFTER restore | the restore's spine/segment/evidence re-verify | `test_sovereign_drill_restores_and_reverifies_the_signed_chain` (`verified: True` ⇒ the staged chain re-verified) |
| **Negative control** — corrupted backup detected | `test_negative_control_corrupted_retained_backup_is_detected_by_the_cli` + inner-body tamper | `test_negative_control_corrupted_retained_sovereign_backup_is_detected` + a tampered-record chain re-verify |

Scope split (honest): the offense retained-drill runs the real `tools.backup.retention.prune` over the
orchestrator's timestamped-dir layout; the sovereign `.sglbk` is a single file the orchestrator wraps in that
same dir, so the sovereign leg (pure-`sigil`, no offense venv) models "retained" as an older, superseded backup
that still restores. Restoring both planes from one retained/pushed dir end-to-end needs the sovereign venv and
is the scheduled two-plane `recovery_drill.sh` run, not a hermetic unit.

## The claims (register in the claims registry, [W0-3] #398)

### Offense plane

<!-- CLAIM:W7-3a -->
> The offense recovery drill covers more than a freshly-minted backup: it restores a backup that has been through retention and pruning, and one fetched from the off-host push destination, and re-verifies each; and a corrupted retained backup is detected fail-closed — a non-zero restore that writes no spine/keys to the destination — rather than restored silently broken.

Enforced by `vigil_integration.backup.restore_offense_backup` (it decrypts, verifies the governance-signed
manifest + every file sha256 BEFORE writing, stages, re-verifies the restored spine chain + segment view +
evidence bundles, and swaps atomically — refusing fail-closed at every step). Proven by
`integration/tests/test_backup_dr_drill_coverage.py`.

### Sovereign plane

<!-- CLAIM:W7-3b -->
> The sovereign plane is drilled too: a create→restore round-trip into a fresh home re-verifies the restored spine's signed chain after restore, a retained (superseded) sovereign backup still restores to its exact point-in-time state, and a corrupted retained sovereign backup is detected fail-closed rather than restored silently broken.

Enforced by `sigil.backup.restore_backup` (decrypt, verify the owner-signed manifest + file hashes, stage,
re-verify the restored spine's keyless chain/binding, then swap the captured units atomically — never reporting
success on an unverified restore). Proven by `apps/sigil/tests/test_backup_recovery_drill_sovereign.py`.

## Where it runs in CI

- `integration/tests/test_backup_dr_drill_coverage.py` → **integration two-env boundary (P5)** (offense leg;
  the restore re-verifies via `framework`).
- `apps/sigil/tests/test_backup_recovery_drill_sovereign.py` → **SIGIL governor gates (P7 — offense gate +
  authn)** (the whole `apps/sigil/tests/` dir; pure-Python, sovereign-only, FATAL-2 clean).

## Schedule + alerting (already wired)

`vigil-backup-drill.service` / `.timer` run the drill weekly; the service's `ExecStopPost` records a heartbeat
that `vigil-alerts` ([W8-1] #467) turns into a staleness/failure alarm — so a drill that starts failing (a
backup pipeline gone silently broken) surfaces within one cadence. Set `VIGIL_DRILL_PUSH_DIR` on the unit to
add the off-host-copy restore leg to the scheduled drill.

## Residuals (honest)

- The two-plane retained/pushed restore end-to-end (both planes from one pushed, pruned dir) is the scheduled
  `recovery_drill.sh` run, which needs the sovereign venv; the hermetic CI units drill each plane's retained /
  pushed / corruption paths in its own leg.
- `--allow-rollback` is required to restore an older retained backup (its `backup_seq` is behind the host trust
  anchor's latest) — that refusal is correct, and the drill exercises both the refusal and the deliberate
  override.
