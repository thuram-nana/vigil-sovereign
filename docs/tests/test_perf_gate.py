"""The performance-regression gate is real, committed, and NOT a no-op (W2-6 / #423).

WHY THIS TEST EXISTS. CI had exactly one regression gate — accuracy (`make bench`, the signed
recall/precision scorecard). A change that halved throughput or doubled peak memory of the hot
integrity paths shipped green because `make bench` was never CI-invoked and nothing measured
wall-clock / throughput / peak memory. W2-6 adds `tools/perf/perf_bench.py` (a wall-clock /
throughput / peak-memory floor over the `vigil_core` hot paths), a committed baseline, an
advisory CI job that runs it, and this test.

This test rides the ALREADY-REQUIRED `docs/tests` job ("the briefing explains every agent and
capability", `pytest docs/tests -q`), which installs only pytest and imports nothing beyond the
standard library. The harness is stdlib-only at import time (its real `vigil_core` cases are
imported lazily), so importing it here is safe and this proof runs in a REQUIRED check without
adding a new required check or touching `.github/required-status-checks.txt`.

WHAT IT PROVES:

  (a) The gate's core `evaluate()` is not a no-op — fed a halved-throughput or doubled-memory
      measurement it REPORTS the regression; fed an at-baseline measurement it PASSES. This is
      the deterministic negative control (pure numbers, no measurement noise).

  (b) End-to-end: a deliberately SLOWED + memory-heavy variant of a real case, measured live and
      checked against the FAST variant's freshly-recorded baseline, is REJECTED — the
      "artificially slowed path must fail" acceptance criterion, exercised, not assumed.

  (c) The committed baseline exists, parses, carries the documented bands, and names the real
      hot-path cases — so "baselines are committed" is guarded, and deleting/emptying the file
      fails here.

  (d) The wiring is true of the code: the `make bench-perf` target exists, the advisory workflow
      exists and invokes the harness with SHA-pinned actions, and the advisory job name is NOT in
      the canonical required-check set (it stays advisory; the required set is unchanged).

HOW TO SEE IT BITE BY HAND (the failure is real on a tree without the fix, not assumed):
  * make `evaluate()` always return `(True, [])`  -> (a) and (b) fail;
  * empty tools/perf/baselines/perf-baseline.json  -> (c) fails;
  * delete the `bench-perf` Makefile target        -> (d) fails.
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
PERF_DIR = REPO / "tools" / "perf"
BASELINE = PERF_DIR / "baselines" / "perf-baseline.json"
WORKFLOW = REPO / ".github" / "workflows" / "bench-perf.yml"
MAKEFILE = REPO / "Makefile"
CANONICAL = REPO / ".github" / "required-status-checks.txt"

# Import the harness as a top-level module without importing the `tools` package (which would be
# unnecessary) and without pulling vigil_core (the real cases are lazy).
sys.path.insert(0, str(PERF_DIR))
import perf_bench as pb  # noqa: E402


# ---------------------------------------------------------------------------
# (a) deterministic negative control: pure numbers, no measurement noise.
# ---------------------------------------------------------------------------
def _measurement(rel_speed: float, peak_bytes: int) -> pb.Measurement:
    return pb.Measurement(
        wall_s=0.01, throughput_ops_s=rel_speed * 1e6, peak_bytes=peak_bytes,
        maxrss_kb=0, rel_speed=rel_speed,
    )


BASE_ENTRY = {"rel_speed": 1.0, "peak_bytes": 100_000}


def test_gate_passes_at_baseline():
    ok, reasons = pb.evaluate("x", BASE_ENTRY, _measurement(1.0, 100_000))
    assert ok, f"a measurement equal to baseline must pass, got: {reasons}"


def test_gate_rejects_halved_throughput():
    # Throughput cut to 50% of baseline (rel_speed 1.0 -> 0.5): below the 55% floor -> reject.
    ok, reasons = pb.evaluate("x", BASE_ENTRY, _measurement(0.5, 100_000))
    assert not ok, "halved throughput must be rejected (the 'halves throughput' regression)"
    assert any("throughput regressed" in r for r in reasons), reasons


def test_gate_rejects_doubled_memory():
    ok, reasons = pb.evaluate("x", BASE_ENTRY, _measurement(1.0, 200_000))
    assert not ok, "doubled peak memory must be rejected (the 'doubles peak RSS' regression)"
    assert any("peak memory grew" in r for r in reasons), reasons


def test_gate_tolerates_noise_within_band():
    # A 10% slowdown and a 10% memory bump are within-band jitter -> must NOT false-fail.
    ok, _ = pb.evaluate("x", BASE_ENTRY, _measurement(0.9, 110_000))
    assert ok, "small within-band jitter must not trip the gate (else it false-fails on CI)"


# ---------------------------------------------------------------------------
# (b) end-to-end negative control: measure a real slowed path and reject it.
# ---------------------------------------------------------------------------
def test_end_to_end_slowed_path_is_rejected():
    cal = pb.calibrate()
    fast = pb.synthetic_fast_case()
    slow = pb.synthetic_slow_case()

    fast_m = pb.measure(fast, cal)
    baseline_entry = pb._entry_from_measurement(fast_m)

    ok_clean, reasons_clean = pb.evaluate(fast.name, baseline_entry, fast_m)
    assert ok_clean, f"clean path must pass its own baseline, got: {reasons_clean}"

    slow_m = pb.measure(slow, cal)
    ok_slow, reasons_slow = pb.evaluate(slow.name, baseline_entry, slow_m)
    assert not ok_slow, (
        "the artificially slowed path was NOT rejected — the gate is a no-op. "
        f"slow rel_speed={slow_m.rel_speed:.4f} vs baseline {baseline_entry['rel_speed']:.4f}"
    )


# ---------------------------------------------------------------------------
# (b2) ALGORITHMIC negative control (#828 class): the planted O(N^2) twin of each hot-path SHAPE
#      is rejected, while its on-tree variant passes. Pure stdlib, so this rides the required
#      docs/tests job with no engine/vigil_core import. Same-run baseline => drift-immune.
# ---------------------------------------------------------------------------
def _underlying_equal(label: str) -> bool:
    """The planted twin must return the IDENTICAL logical result to its on-tree variant, so a
    rejection can only be about speed — not a different (cheaper) computation."""
    if label == "synthetic.chaining":
        return pb._chain_fast(pb.SYNTH_CHAIN_N) == pb._chain_quadratic(pb.SYNTH_CHAIN_N)
    if label == "synthetic.pathsearch":
        adj = pb._synth_graph(pb.SYNTH_PATH_N)
        return pb._dijkstra_fast(adj) == pb._dijkstra_quadratic(adj)
    if label == "synthetic.saturate":
        sigs = pb._synth_sigs(pb.SYNTH_SATURATE_N)
        return pb._dedup_fast(sigs) == pb._dedup_quadratic(sigs)
    raise AssertionError(f"unknown pair label {label!r}")


def test_planted_quadratic_slowdown_is_rejected_on_tree_passes():
    """The regression gate that would have caught #828: for each hot-path shape, a planted O(N^2)
    variant is REJECTED and the on-tree variant PASSES — measured live, not assumed."""
    cal = pb.calibrate()
    pairs = pb.synthetic_algorithmic_pairs()
    assert {p[0] for p in pairs} == {"synthetic.chaining", "synthetic.pathsearch", "synthetic.saturate"}
    for label, ontree, quad in pairs:
        assert _underlying_equal(label), (
            f"{label}: the quadratic twin must compute the SAME result as on-tree, else a "
            "rejection could be a different computation rather than a slowdown"
        )
        on_m = pb.measure(ontree, cal)
        base = pb._entry_from_measurement(on_m)
        ok_on, reasons_on = pb.evaluate(label, base, on_m)
        assert ok_on, f"{label}: on-tree variant must pass its own baseline, got: {reasons_on}"

        quad_m = pb.measure(quad, cal)
        ok_quad, reasons_quad = pb.evaluate(f"{label}.quadratic", base, quad_m)
        assert not ok_quad, (
            f"the planted O(N^2) {label} was NOT rejected — the fence misses the #828 class. "
            f"quadratic rel_speed={quad_m.rel_speed:.4f} vs on-tree baseline {base['rel_speed']:.4f}"
        )
        assert any("throughput regressed" in r for r in reasons_quad), reasons_quad


# ---------------------------------------------------------------------------
# (c) the baseline is committed, well-formed, and covers the real hot paths.
# ---------------------------------------------------------------------------
EXPECTED_CASES = {
    "canonical_json.nested", "digest_payload.nested", "sha256_hex.1kb",
    "build_chain.1000", "verify_chain.1000",
    # the fixed-corpus scan sensor + the on-tree synthetic-N algorithmic cases (#828 class).
    "scan.plan_fixed_corpus",
    "synthetic.chaining", "synthetic.pathsearch", "synthetic.saturate",
}


def test_committed_baseline_is_present_and_covers_real_cases():
    assert BASELINE.is_file(), f"committed baseline missing: {BASELINE}"
    doc = json.loads(BASELINE.read_text(encoding="utf-8"))
    assert doc.get("schema") == 1
    bands = doc.get("bands", {})
    assert {"regress_frac", "grow_frac", "mem_slack_bytes"} <= set(bands), bands
    cases = doc.get("cases", {})
    missing = EXPECTED_CASES - set(cases)
    assert not missing, f"baseline omits real hot-path cases: {missing}"
    for name, entry in cases.items():
        assert entry["rel_speed"] > 0, f"{name}: non-positive rel_speed baseline"
        assert entry["peak_bytes"] >= 0, f"{name}: negative peak_bytes baseline"


# ---------------------------------------------------------------------------
# (d) the wiring is true of the code, and the job stays ADVISORY.
# ---------------------------------------------------------------------------
def test_make_target_exists():
    text = MAKEFILE.read_text(encoding="utf-8")
    assert re.search(r"^bench-perf:", text, re.M), "Makefile has no `bench-perf` target"
    assert re.search(r"^bench-perf-record:", text, re.M), "Makefile has no `bench-perf-record` target"
    assert "perf_bench.py" in text, "the bench-perf target does not invoke perf_bench.py"


def test_workflow_exists_invokes_harness_and_pins_actions():
    assert WORKFLOW.is_file(), f"advisory workflow missing: {WORKFLOW}"
    wf = WORKFLOW.read_text(encoding="utf-8")
    assert "perf_bench.py" in wf, "workflow does not run the harness"
    # every third-party action is SHA-pinned (40-hex), never a bare tag.
    uses = re.findall(r"uses:\s*([^\s#]+)", wf)
    third_party = [u for u in uses if not u.startswith("./")]
    assert third_party, "workflow uses no actions?"
    for u in third_party:
        assert re.search(r"@[0-9a-f]{40}$", u), f"action not SHA-pinned: {u}"


def test_advisory_job_is_not_in_required_set():
    """The bench job must stay advisory — the 13-check required set is unchanged."""
    wf = WORKFLOW.read_text(encoding="utf-8")
    m = re.search(r"^\s*name:\s*(.+?)\s*$", wf, re.M)
    assert m, "workflow has no job/workflow name"
    job_name = m.group(1).strip().strip("\"'")
    canonical = {
        ln.strip() for ln in CANONICAL.read_text(encoding="utf-8").splitlines()
        if ln.strip() and not ln.strip().startswith("#")
    }
    assert job_name not in canonical, (
        f"the advisory bench job {job_name!r} must NOT be in the required set "
        "(required-status-checks.txt stays byte-identical; promotion is a separate reviewed change)"
    )
