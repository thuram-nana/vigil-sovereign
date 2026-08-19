# Performance-regression gate (`tools/perf`)

**Issue:** W2-6 / [#423](https://github.com/thuram-nana/vigil-sovereign/issues/423)

CI had exactly one regression gate — **accuracy** (`make bench`, the signed recall/precision
scorecard). A change that halved throughput or doubled peak memory of the hot integrity paths
shipped green, because `make bench` was never CI-invoked and nothing measured wall-clock,
throughput or peak memory. This directory adds the missing dimension.

## What it gates

`perf_bench.py` measures real, deterministic, load-bearing `vigil_core` hot paths — canonical
JSON, payload digests, and the hash-linked spine chain build + verify — and, for each, records:

| metric | what | gated? |
|---|---|---|
| `wall_s` | best-of-N wall clock for one run (min ⇒ least jitter) | via `rel_speed` |
| `throughput_ops_s` | logical work units / second | via `rel_speed` |
| `peak_bytes` | tracemalloc **peak** python-allocated bytes (deterministic) | **yes** — memory floor |
| `rel_speed` | `throughput / a same-run calibration probe` | **yes** — throughput/wall floor |
| `maxrss_kb` | `getrusage` peak RSS | recorded only (process-wide + monotonic ⇒ a poor gate) |

**Why the time gate is normalised.** Absolute wall clock is meaningless across machines, so a
committed absolute floor would false-fail forever. Each run first measures a **calibration probe**
and gates on the dimensionless ratio `rel_speed = case_throughput / calibration_throughput`. A
faster CPU speeds both numerator and denominator, so the ratio is stable; a code change that slows
only the case moves the ratio and the gate fires.

The probe exercises the **same stdlib primitives** the hot paths lean on (`json.dumps` +
`hashlib.sha256`) over fixed neutral data, but **never through `vigil_core`**. That is deliberate:
those primitives are C-accelerated and their speed relative to pure bytecode swings widely across
CPUs (e.g. SHA-NI), so a pure-bytecode probe would drift the ratio machine-to-machine — sharing the
primitives makes the hardware acceleration cancel. It still catches every regression in the code we
**own** — a slowdown *inside* `canonical_json` / `build_chain` moves the case but not the probe
(which calls `json`/`hashlib` directly, not our wrappers) — the only blind spot is a regression in
`json`/`hashlib` themselves, which are stdlib and not ours to break.

## The gate (bands)

- **throughput floor**: fail if `rel_speed < baseline.rel_speed × (1 − 0.45)` (below 55% of
  baseline; catches the "halves throughput" 2× regression while tolerating cross-machine drift).
- **memory floor**: fail if `peak_bytes > baseline.peak_bytes × (1 + 0.30) + 8 KiB` (catches the
  "doubles peak RSS" 2× regression with wide margin).

Bands live in the committed baseline and can be tuned there.

## Commands

```bash
make bench-perf            # check hot paths vs the committed baseline; non-zero exit on regression
make bench-perf-record     # RE-RECORD the baseline (explicit, reviewed change — COMMIT the diff)
python tools/perf/perf_bench.py selftest   # prove the gate bites (negative control, by hand)
```

`bench-perf-record` rewrites `baselines/perf-baseline.json`; the change shows up in the diff and
goes through review like any other file. **CI never self-updates the baseline.**

## Where it runs in CI

- **Advisory workflow** `.github/workflows/bench-perf.yml` runs `make bench-perf` on every PR. It is
  **advisory (non-blocking)**: it is deliberately *not* in the required-status-checks set, because a
  wall-clock gate wants its baseline re-recorded on the CI runner class before it blocks merges.
- **Required check**: the gate *logic* and its **negative control** are proven in
  `docs/tests/test_perf_gate.py`, which rides the already-required docs-only job (`pytest docs/tests
  -q`, pytest + stdlib only). That test fails if `evaluate()` is turned into a no-op, if the
  baseline is deleted, or if the wiring drifts — so the gate cannot silently rot.

## Negative control

`synthetic_slow_run` is a deliberately ~10× slowed, memory-heavy variant of a fast synthetic case.
`selftest` (and `test_end_to_end_slowed_path_is_rejected`) record a baseline for the fast case, then
measure the slowed variant against it and assert it is **rejected**. The gate being a no-op is a
test failure, not an assumption.

## Honest limits

- The committed baseline was captured on the development machine, not a GitHub runner. The bands are
  intentionally generous so the advisory job is reliably green cross-machine; re-record on the CI
  runner (`make bench-perf-record`, committed via review) to tighten sensitivity before promoting
  the job to required.
- The gated memory metric is tracemalloc **peak python-allocated bytes** — deterministic and
  machine-independent — used as the sound proxy for the "peak RSS" the issue names; raw `ru_maxrss`
  is recorded but not gated (it is process-wide and monotonic, a poor gate).
