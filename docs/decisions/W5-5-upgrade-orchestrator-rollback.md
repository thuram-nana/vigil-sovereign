# W5-5 — `vigil upgrade`: backup → verify → migrate → verify → report, with ROLLBACK

Issue: [#449](https://github.com/thuram-nana/vigil-sovereign/issues/449) ·
Milestone: W5 — UPGRADE & DATA MIGRATION (the biggest product risk).

## The defect

`sigil spine migrate` was **manual and invoked by no automated path**; only `prune` hard-failed on a
legacy (pre-segment) spine (`prune.py`, `check_prune_safe`). An operator who upgraded the binary and just
ran would operate on an un-migrated store until something happened to hit `prune` — a silent degraded
state, with no crash-safe, rolling-back migration path and no startup refusal.

## The claim (register in the claims registry, [W0-3] #398)

> `vigil upgrade` (and its sovereign leg `sigil upgrade`) performs an automated, crash-safe data
> migration of the sovereign SIGIL spine: **verify(before) → backup → verify(backup) → migrate →
> verify(after) → report**. It **refuses to proceed** if the store does not already verify, or if the
> backup it took is not itself restorable — in both cases **nothing is mutated**. If any step *after* the
> verified backup fails (including a `KeyboardInterrupt`), it **rolls the store back to the verified
> backup** and re-verifies it, so an interrupted upgrade **never leaves a half-migrated store**.
> Separately, the sovereign **startup refuses to run a normal command against an un-migrated (legacy,
> pre-segment) store that already holds data**, naming the command that fixes it.

This claim is TRUE of the code as of W5-5:

- **The orchestrator** — `apps/sigil/sigil/spine/upgrade.py::upgrade()`:
  - `verify(before)` — refuses (`SpineError`, no mutation) a spine that does not `store.verify()`; never
    migrates corruption forward.
  - `backup` — tar.gz of the WHOLE spine dir into a sibling dir (`…/backups`), guarded to be **outside**
    the spine dir so it is never swept into the migrate/rollback of that dir.
  - `verify(backup)` — extracts the backup to a scratch dir (path-traversal-safe: stdlib `filter="data"`
    plus an explicit membership check), opens a store over it, `verify()`s it, and asserts its record
    count equals the live count. A backup that cannot be restored is not a safety net → refuse
    (`SpineError`, no mutation).
  - `migrate` — `store.migrate()` (legacy single-file → retain-all segment layout) + seal + gzip
    `compact()`, each under the store's own cross-process lock.
  - `verify(after)` — re-`verify()` + a **record-count-preserved** guard (retain-all must lose no record).
  - **rollback** — the whole `migrate…verify(after)` block is wrapped so that ANY `BaseException`
    (`KeyboardInterrupt` included) triggers `restore_from_backup()`: the current (possibly half-migrated)
    spine dir is moved ASIDE to a quarantine, the verified backup is extracted in its place, and the
    quarantine is dropped only after a successful extract (if the extract fails, the original is moved
    back — never NO spine dir). The restored store is re-verified; the failure is re-raised as
    `UpgradeFailed`, which carries the full `report` so the CLI can print exactly what happened and where
    the backup lives.
- **The CLI** — `sigil upgrade` (`apps/sigil/sigil/cli.py::cmd_upgrade`): `--check` reports whether a
  migration is needed (exit 3 if it is, mutating nothing); a plain run performs the upgrade and exits 2 on
  a refusal or a failed-and-rolled-back upgrade. `vigil upgrade`
  (`integration/vigil_integration/cli.py::_cmd_upgrade`) is the offense-side native verb: it EXECs
  `.venv-sovereign/bin/sigil upgrade` in its OWN venv via `dispatch("sigil", …)`, passing `--check` /
  `--no-backup` through — it imports NO `sigil` (FATAL-2: the two trust domains never co-load, exactly as
  `vigil backup`/`restore` do).
- **The startup gate** — `apps/sigil/sigil/spine/upgrade.py::migration_needed` / `assert_operable`, wired
  at `apps/sigil/sigil/cli.py::main` via `_assert_store_operable_or_exit`: any non-recovery command run
  against a legacy (no manifest) spine whose data file is non-empty is refused (exit 3) with the fix named.
  The recovery/diagnostic verbs (`upgrade`, `spine`, `doctor`, `restore`, `backup`, `vault`, `kernel`) are
  exempt so the operator can always reach the fix. Detection is by the data file's SIZE (O(1)), so the gate
  never scans a large spine at startup.

## Why "migration needed" is *legacy-with-data*, not *any legacy*

A brand-new install writes the legacy single-file layout until its first migrate/rotate, and that layout
is byte-identically readable — it is not "degraded". So the gate fires only on a legacy store that
**already holds data** (a non-empty data file with no manifest): the exact "operator upgraded onto a
pre-segment store with history" case. A fresh/empty store is operable; the install flow runs `vigil
upgrade` once, which establishes the manifest, after which the gate is satisfied forever. This keeps the
gate from locking out a fresh install while still refusing to run a store with real history in the old
layout.

## Migration scope (builds on W5-1 #445 / W5-2 #446)

The schema/payload evolution is **additive by contract**: `schema_version` is informational and NOT part
of the digested `cert_digest` (see `models.py` / the W5-1 decision record), and a record cannot be
rewritten without breaking the chain. So the migration this orchestrator runs is the **structural**
legacy→segment conversion. A future non-additive migration plugs into the SAME frame — between the two
`verify()` gates, inside the backup/rollback wrapper — without changing the safety envelope.

## Tests (fail-without-the-fix + negative controls)

`apps/sigil/tests/test_spine_upgrade.py` (runs in the required `SIGIL governor gates (P7 …)` CI job, which
executes the whole `apps/sigil/tests/` directory):

- happy path — migrate + verify + every record preserved + backup restorable + `migration_needed`
  round-trips True→False;
- **rollback on a mid-migration failure** — a fault injected AFTER migrate+seal completes rolls the store
  back to the verified backup (`rollback_verified` True), and the store is back in the legacy layout with
  every record — the completed migration is undone (never half-migrated);
- rollback on a retain-all record-count change;
- **kill-during-migrate** — a forked child performs the durable half of `migrate()` and is **SIGKILL**'d
  before the manifest write (the real crash window); the state is asserted restorable BOTH ways: a fresh
  store auto-reconciles the orphan, AND the verified backup restores cleanly;
- fail-closed refusals (negative controls): a non-verifying spine is refused with no mutation; an
  unrestorable backup is refused with no mutation; the backup verifier rejects a count mismatch;
- the startup gate raises and names the command on a legacy store, and is a no-op (negative control) on a
  migrated store; the CLI gate refuses a non-exempt command (exit 3) and exempts the recovery verbs.

`integration/tests/test_cli_upgrade_forwards.py` (P5 integration job, sovereign leg — framework-free +
sigil-free): `vigil upgrade` forwards to the sovereign `sigil upgrade`, passes `--check`/`--no-backup`
through, propagates the sovereign exit code, is a native (non-passthrough) verb, and the `cli` module
import pulls neither trust domain.

Every test FAILS on a pre-W5-5 tree: `sigil.spine.upgrade` does not exist (import error), `sigil upgrade`
and `vigil upgrade` are not registered verbs, and there was no startup refusal.

## What remains live-only

Nothing hardware-gated. The orchestrator, rollback, and startup gate are exercised end to end with real
temp stores and a real `SIGKILL`. The one integration seam that cannot run in a unit test is the actual
cross-venv EXEC (`.venv-sovereign/bin/sigil upgrade`), which requires a built sovereign venv on the host;
it is proven by mock-forwarding here and shares the exact `dispatch` path that `vigil backup`/`restore`
use in production.

> **Registration:** fold this claim into the claims registry when [W0-3] #398 lands; until then this
> decision record is the source of truth for the claim. The N-1→N upgrade/rollback harness of
> [W5-7] #451 builds on this orchestrator.
