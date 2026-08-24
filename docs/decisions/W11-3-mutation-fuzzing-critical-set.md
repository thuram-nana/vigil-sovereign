# W11-3 — mutation testing + coverage-guided fuzzing on the security-critical set

**Milestone:** W11 — TESTING DEPTH · **Issue:** #484 · **Registers in:** W0-3 #398.

## The claim under test

A mutation score is only meaningful if a KILLED/SURVIVED verdict actually measures test adequacy: a
suite that kills nothing, or a harness rigged to report everything killed, would show the same green
number as a real one. VIGIL's mutation programme therefore stands on a proof that the gate has
*sensitivity* — teeth — before any full mutmut/cosmic-ray run is trusted. That proof runs on every PR,
fast and unconditionally, against the real WARDEN gate decision.

<!-- CLAIM:W11-3 --> The mutation gate has proven sensitivity: an adequate test KILLS a boundary mutant of the real WARDEN gate decision (`vigil_core.warden_tiers.gate`) while a deliberately-weak test lets the SAME mutant SURVIVE, and the unmutated source SURVIVES even the adequate test — so a KILLED verdict is caused by the mutation, and a green mutation score cannot be a rubber stamp.

## Where it is enforced

`tools/mutation/mutation_probe.py` — `evaluate` compiles a (possibly mutated) function source in a fresh
namespace, runs a caller-supplied test against it, and returns `KILLED` (the test raised) or `SURVIVED`
(the test passed). It is the standard-library kill/survive engine — `ast` + `inspect` only, no offense
import and no external tool — that reduces the mutmut/cosmic-ray kill contract to something a required PR
job can exercise. `mutate_boundary` applies the classic boundary swap (`<=`→`<`) a mutation tester flips.

## How it is proven

`integration/tests/test_mutation_gate_sensitivity.py` mutates the boundary comparator of the REAL
`vigil_core.warden_tiers.gate` (the `tier <= A1` auto/queued split — production code, not a toy) and:

| Property | Test |
|----------|------|
| SENSITIVITY — an adequate suite detects the mutant | `test_adequate_test_kills_the_boundary_mutant` |
| NEGATIVE CONTROL — a deliberately-weak test lets the same mutant survive | `test_weak_test_lets_the_mutant_survive_the_negative_control` |
| KILLED is load-bearing — the unmutated source survives even the strong test | `test_identity_mutant_survives_even_the_strong_test_so_KILLED_is_load_bearing` |

The failure is *observed*, not assumed: an `evaluate` rigged to always report `KILLED` fails the negative
control, and a `mutate_boundary` that changed nothing fails the load-bearing test. The suite runs in the
required `integration two-env boundary (P5)` CI job (stdlib + `vigil_core`, so it stays in the sovereign
leg and never trips `assert_no_offense`).

## The rest of the deliverable (heavy runs, honestly labelled)

* **Critical-set manifest** — `tools/mutation/critical-set.json` enumerates the gate/oracle/verifier/
  signing/parser files. It is the single source of truth: `integration/tests/test_mutation_critical_set.py`
  (required) fails the build if the mutmut target list (`pyproject.toml [tool.mutmut].paths_to_mutate`) or
  the cosmic-ray list (`tools/mutation/cosmic-ray.toml`) drifts from it, and if any declared fuzz target
  lacks a harness, a committed non-empty seed corpus, or a fast required test.
* **cargo-fuzz** — `apps/sigil/kernel/fuzz/` drives the WARDEN classifier through
  `tiers::invariant_violation`; its fast required counterpart `apps/sigil/kernel/tests/fuzz_smoke.rs` runs
  in the `WARDEN Rust kernel (A10 durability)` job and carries a broken-classifier negative control.
* **atheris** — `tools/fuzz/atheris/` fuzzes the JSON-canonicalisation, spine-record and HTTP-request
  parsers; the required `integration/tests/test_fuzz_corpus_replay.py` replays each committed corpus and
  asserts each parser/verifier has teeth.
* **Full mutmut / cosmic-ray / cargo-fuzz / atheris runs** — `.github/workflows/mutation-fuzz.yml`, a
  weekly SCHEDULED (+ dispatch) job. It is deliberately NOT a required PR check (mutmut/cosmic-ray re-run
  the suite per mutant; cargo-fuzz needs a nightly libFuzzer toolchain), and is accounted for as a non-PR
  job in `docs/tests/test_required_checks_canonical.py`.

## Residual

The scheduled `mutation-fuzz` workflow installs mutmut/cosmic-ray/atheris/cargo-fuzz from the package index
(not the committed hash-locks) and needs a nightly Rust toolchain + clang; it has not been executed on a
scheduled runner in this branch. Its per-PR value is fully delivered by the four fast required proofs
above — the scheduled run only widens the mutant/input space and is a signal, never a merge blocker.
