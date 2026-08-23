# W11-6 — load + soak testing: a documented throughput floor and memory-leak detection

Issue: [#487](https://github.com/thuram-nana/vigil-sovereign/issues/487) ·
Milestone: W11 — SCALE & ENDURANCE.

## The claim (registered in the claims registry — [W0-3] #398, id `W11-6`)

<!-- CLAIM:W11-6 -->
> **Registered claim (W11-6 #487):** The soak harness drives a real sustained-load scan that holds a documented throughput floor (a run below it fails) and tracks process RSS across the whole run (a detected memory leak fails); an artificially-leaking fixture is DETECTED by the same leak check, and its clean twin is not. The fast, scaled half — the leak detector with its leaking-fixture negative control and a scaled run against a conservative CI floor — runs in the required CRUCIBLE eval job; the full multi-minute sustained soak at the SLA floor is the scheduled soak.yml workflow, not a per-PR gate.

## Why this exists

`framework/v2/eval/soak.py` was a **determinism check** — it ran one scan (at `N=8` in the test) and
re-ran it to prove the `ScanReport` fingerprint was byte-identical. That is a valuable invariant, but it
is **not a soak**: nothing drove SUSTAINED load, and nothing watched memory over a long-running process.
Calling the file `soak.py` therefore overclaimed the capability — itself the kind of claim problem the
W0 credibility programme exists to end. "A skipped proof and a passing proof are the same colour on a
dashboard"; so are a soak test and a determinism check that share a filename.

## What is TRUE of the code as of W11-6

The harness is now a real load + soak harness, split by cost into a falsifiable per-PR core and a
long-running scheduled endurance run — the same smoke-vs-nightly split `livefire.yml` already uses.

- **A documented throughput floor.** `SUSTAINED_THROUGHPUT_FLOOR_RPS` (30 rps) is the SLA floor the full
  soak enforces; `CI_THROUGHPUT_FLOOR_RPS` (15 rps) is the deliberately conservative floor the scaled
  per-PR run enforces. Both are far below the ~90 rps the loopback fixture measures locally, so the gate
  catches an order-of-magnitude regression without going flaky on a shared runner. `throughput_holds` is
  a pure predicate: a below-floor number returns `False`, so `run_soak_sustained(...).passed` is `False`
  when the floor is breached.
- **Memory tracked across a long-running process.** `current_rss_mb()` reads the LIVE resident set from
  `/proc/self/statm` (not `ru_maxrss`, a high-water mark that never falls and so cannot reveal a leak's
  shape). `run_soak_sustained` samples RSS after every iteration and `detect_leak` flags a leak only when
  BOTH a sustained positive least-squares slope AND a real net growth hold — so noise or a one-off
  warmup allocation cannot masquerade as a leak, while a genuine climb is caught. A detected leak makes
  the run's `passed` `False`.
- **The negative control.** `LeakingWorkload` allocates and RETAINS memory each iteration; sampled over
  real RSS its series is DETECTED as a leak (`test_leaking_fixture_is_detected`). Its healthy twin
  `clean_workload` allocates and frees each iteration and is NOT flagged
  (`test_clean_fixture_is_not_flagged`). If the detector were a no-op, the first test fails — the gate is
  not vacuous.
- **The name is now honest.** `soak.py` describes a real soak. The corrected claim is registered here.

## The honest CI split

- **Required, per-PR** (`CRUCIBLE eval + benchmark corpus`, which runs `framework/v2/eval` wholesale):
  `framework/v2/eval/tests/test_soak_leak.py` — the pure leak detector, the leaking-fixture negative
  control over real RSS, the throughput-floor predicate, and a SCALED sustained run against the
  conservative CI floor that also proves the scanner itself does not leak and stays replay-deterministic
  across iterations.
- **Scheduled, not a PR gate** (`.github/workflows/soak.yml`, job `soak full run (nightly)`): the FULL
  multi-minute sustained soak at the SLA floor via `python3 -m framework.v2.eval.soak --sustained`, which
  exits non-zero — turning the job red — on a floor breach, a detected leak, or a determinism divergence.
  It is enumerated in `docs/tests/test_required_checks_canonical.py`'s `KNOWN_NONPR_ADVISORY` with a
  stated reason, and `test_full_soak_is_a_scheduled_job_not_a_pr_gate` pins that it stays schedule-only,
  honestly labelled, and really drives the sustained entrypoint.

## Residual / limitation

The leak signal is process RSS via `/proc/self/statm`, so the real-memory negative control is Linux-only
(it `skipif`s elsewhere; the CI runner is `ubuntu-latest`). The pure `detect_leak` tests and the
throughput checks are platform-independent. The full endurance run at the true SLA floor rides a schedule,
not per-PR CI — by design, because a multi-minute soak cannot sit on the per-PR critical path.
