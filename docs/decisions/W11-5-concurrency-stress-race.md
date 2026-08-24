# W11-5 — concurrency stress, race detection, and flake tracking for the shared spine

**Milestone:** W11 — TESTING DEPTH · **Issue:** #486 · **Registers in:** W0-3 #398.

## The claim under test

In production more than one *engagement* (a logical actor/session — the bridge server, the gesture
daemon, a governed `engage` run) can be live at once against the SAME `SIGIL_HOME` spine: they append
and read concurrently while rotation/compaction rewrites segments underneath both. The C-1 (#392) fix
that landed as PR #551 (`db41bdcd`, parent `a00bac4e`) made the read path generation-aware, but until
W11-5 there was no concurrency STRESS harness driving two engagements against one spine, no negative
control proving that harness catches the pre-fix race, and no flake tracking (historical pass rates +
explicit quarantine) over the repeat-stress it introduces.

### Concurrency correctness

<!-- CLAIM:W11-5 --> Two engagements sharing one segmented spine stay a single contiguous `verify()`-green chain with every record attributed to the engagement that wrote it, and a reader that races a concurrent compaction's segment supersession re-resolves and completes instead of raising, because `SpineStore._resolve_segments` treats only a strictly-forward manifest-generation move as a benign supersession to retry while a segment missing at an unchanged or regressed generation still fails closed.

Enforced in `apps/sigil/sigil/spine/store.py` — `SpineStore._resolve_segments`. Compaction commits the
new-generation manifest BEFORE it unlinks the plaintext it superseded, so a reader can only find a file
missing because its own snapshot is stale (the live generation moved strictly forward). That case is a
bounded retry; every other missing-segment case (generation unchanged, regressed, or the manifest
vanished to -1) is genuine loss and raises, naming the missing segment (invariant 15: no fail-open).

Proven by `apps/sigil/tests/test_spine_concurrency_stress.py`:

| Property | Test |
|----------|------|
| TWO engagements + a compactor + readers on ONE spine → one contiguous verified chain, no cross-log (#532) | `test_two_engagements_one_spine_stay_contiguous_and_attributed` |
| A reader racing a compaction supersession re-resolves (deterministic C-1 driver; FAILS on the pre-fix parent) | `test_concurrent_engagement_read_survives_compaction_supersession` |
| NEGATIVE CONTROL: a segment genuinely gone at an unchanged generation STILL raises, not tolerated as churn | `test_genuine_segment_loss_still_raises_under_concurrent_engagements` |

The failure is *observed*, not assumed: run against the parent of the C-1 fix
(`git checkout a00bac4e -- apps/sigil/sigil/spine/store.py`), the deterministic C-1 test fails for every
read path with `SpineError: references a missing segment`; restoring HEAD's `store.py` turns it green.
The exact repro is in `RED-PEN-BRIEF.md`.

### Flake tracking — historical pass rates + EXPLICIT quarantine

<!-- CLAIM:W11-5-flake --> A test can be quarantined (skipped as known-flaky) only when it is registered in `docs/flake/quarantine.json` with a reason and a tracking issue: `require_registered_quarantine` returns the entry for a registered id and raises `QuarantineError` for any unregistered id, so there is no silent-quarantine path.

Enforced in `tools/flake/flake_tracker.py` — `require_registered_quarantine`. Historical per-test pass
rates are computed from an append-only JSONL outcome ledger (`docs/flake/ledger.jsonl`), which every CI
repeat of the stress suite enriches (published as a `flake-ledger` artifact, since a PR runner cannot
push); `flaky_tests` surfaces below-threshold quarantine CANDIDATES as a signal, never an auto-skip.

Proven by `apps/sigil/tests/test_flake_tracking.py`:
`test_quarantine_is_explicit_not_silent`, `test_check_quarantine_explicit_flags_only_unregistered`,
`test_pass_rate_computed_from_the_ledger`, `test_committed_ledger_has_real_history_for_the_stress_harness`.

## Where the four-part programme bar is met

1. **Behaviour** — the two-engagement stress harness, the deterministic C-1 driver, the flake tracker,
   the required-job repeat stress, and the scheduled heavy (TSan + high-iteration) counterpart.
2. **Fail-without-fix** — the C-1 driver fails on the parent commit (repro above / in `RED-PEN-BRIEF.md`).
3. **Negative control** — `test_genuine_segment_loss_still_raises_under_concurrent_engagements` (real
   loss still fails closed) and the flake-tracker negatives (unknown outcome, malformed ledger,
   unregistered quarantine all rejected).
4. **Required CI** — both test files run in the required `SIGIL governor gates (P7 — offense gate + authn)`
   job (whole-`apps/sigil/tests/` collection), plus the plugin-free repeat-stress step in the same job.

## Heavy work, split out and labelled honestly

ThreadSanitizer on the Rust WARDEN kernel (a real DATA-RACE detector — `cargo test` alone only sees an
observably-wrong result, not a race) needs a nightly toolchain + `rust-src` and a std rebuilt with the
sanitizer (minutes, network). It is therefore wired in the scheduled/manual `.github/workflows/concurrency-race.yml`,
NOT on every PR, and is enumerated with its reason in
`docs/tests/test_required_checks_canonical.py::KNOWN_NONPR_ADVISORY`. The deterministic per-PR race
coverage is the required governor stress job plus the WARDEN kernel's own `cargo test` (which includes
the flock'd concurrent-append test). The TSan job was NOT validated in the author's offline sandbox
(no network for the nightly + `rust-src` + compiler-rt install); on the schedule it is authoritative and
fails loudly.
