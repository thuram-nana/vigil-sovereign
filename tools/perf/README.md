# Performance-regression gate (`tools/perf`)

**Issue:** W2-6 / [#423](https://github.com/thuram-nana/vigil-sovereign/issues/423)

CI had exactly one regression gate — **accuracy** (`make bench`, the signed recall/precision
scorecard). A change that halved throughput or doubled peak memory of the hot integrity paths
shipped green, because `make bench` was never CI-invoked and nothing measured wall-clock,
throughput or peak memory. This directory adds the missing dimension.

## What it gates

`perf_bench.py` measures real, deterministic, load-bearing hot paths and, for each, records:

| metric | what | gated? |
|---|---|---|
| `wall_s` | best-of-N wall clock for one run (min ⇒ least jitter) | via `rel_speed` |
| `throughput_ops_s` | logical work units / second | via `rel_speed` |
| `peak_bytes` | tracemalloc **peak** python-allocated bytes (deterministic) | **yes** — memory floor |
| `rel_speed` | `throughput / a same-run calibration probe` | **yes** — throughput/wall floor |
| `maxrss_kb` | `getrusage` peak RSS | recorded only (process-wide + monotonic ⇒ a poor gate) |

The gated cases (`gated_cases()`, run by `check` / `record`) are:

| case | what | kind |
|---|---|---|
| `canonical_json.nested`, `digest_payload.nested`, `sha256_hex.1kb` | `vigil_core` canonical JSON / digest primitives | real, C-accelerated |
| `build_chain.1000`, `verify_chain.1000` | the hash-linked spine chain build + verify | real, C-accelerated |
| `scan.plan_fixed_corpus` | the planner's real hot loop — `knowledge.operators.saturate` to a fixpoint **then** `worldmodel.pathsearch.best_paths` — over a fixed N-node world (the **#828 shape**, shrunk) | real, pure-Python engine |
| `synthetic.chaining`, `synthetic.pathsearch`, `synthetic.saturate` | on-tree complexity **models** of the three hot-path shapes (O(N) fold, O(E·logV) Dijkstra, O(N) seen-set dedup), each with a planted O(N²) twin used as the negative control | synthetic, stdlib |

**The regression gate that would have caught #828.** #828 was a ~2h *scan* — not a slow primitive but
an **algorithmic** blow-up in the planner's super-linear paths. The `scan.plan_fixed_corpus` case is a
live sensor over the real `saturate` + `best_paths`; the three `synthetic.*` cases model those paths'
on-tree complexity and each ships a planted O(N²) twin (rolling-hash → re-fold-the-prefix; min-heap →
linear-min-scan; seen-**set** → seen-**list**) that returns the *identical* logical result. At the
committed N the twin is 20–100× slower — the negative control (`selftest` and the required
`docs/tests/test_perf_gate.py`) proves the fence **rejects every twin and passes every on-tree
variant**, so an O(N²) regression at these sites cannot ship green.

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

Two layers, both exercised (not assumed):

- **Constant-factor.** `synthetic_slow_run` is a deliberately ~10× slowed, memory-heavy variant of a
  fast synthetic case. `selftest` (and `test_end_to_end_slowed_path_is_rejected`) record a baseline
  for the fast case, then measure the slowed variant against it and assert it is **rejected**.
- **Algorithmic (the #828 class).** For each of `synthetic.chaining` / `synthetic.pathsearch` /
  `synthetic.saturate`, `selftest` and `test_planted_quadratic_slowdown_is_rejected_on_tree_passes`
  record the **on-tree** variant's baseline *in the same run* (so the proof is immune to cross-machine
  ratio drift), then measure the planted **O(N²)** twin against it and assert the on-tree variant
  **passes** and the twin is **rejected**. The twin returns the identical logical result to its
  on-tree twin, so "slower" is the only thing the gate can be reacting to. The gate being a no-op is a
  test failure, not an assumption.

## Honest limits

- The committed baseline was captured on the development machine, not a GitHub runner. The bands are
  intentionally generous so the advisory job is reliably green cross-machine; re-record on the CI
  runner (`make bench-perf-record`, committed via review) to tighten sensitivity before promoting
  the job to required.
- **Pure-Python cases drift more than the C-accelerated ones.** `scan.plan_fixed_corpus` and the three
  `synthetic.*` cases are pure Python, so their `rel_speed` (against a `json`+`sha256` C-accelerated
  probe) carries more machine-to-machine drift than the `vigil_core` cases, where the shared C
  primitives cancel cleanly. The wide −45 % band, the **advisory** (non-blocking) status, and the
  re-record workflow absorb that drift; the committed-baseline check on these is a trend sensor. The
  hard, drift-immune guarantee — *the fence catches an O(N²) regression at these sites* — comes from
  the **same-run** algorithmic negative control above, which does not depend on the committed baseline
  at all.
- The gated memory metric is tracemalloc **peak python-allocated bytes** — deterministic and
  machine-independent — used as the sound proxy for the "peak RSS" the issue names; raw `ru_maxrss`
  is recorded but not gated (it is process-wide and monotonic, a poor gate).
