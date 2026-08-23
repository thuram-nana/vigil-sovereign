"""Coverage is measured (line AND branch) and ratcheted, and the gate is NOT a no-op (W2-4 / #421).

WHY THIS TEST EXISTS. There was no coverage measurement anywhere — the "coverage guards" only proved a
path collected >0 tests. This test proves real line+branch coverage is now measured for a package, that
a committed floor exists, and that the gate bites: a measurement below the floor (as when a test that
covers the package is deleted) turns the required CI job red.

This test rides the ALREADY-REQUIRED `the briefing explains every agent and capability` job
(`pytest docs/tests -q`), which installs only pytest and imports nothing beyond the standard library.
The guard (`tools/coverage/coverage_ratchet.py`) is stdlib-only and imports neither trust domain.

WHAT IT PROVES:

  (a) The gate's pure `evaluate()` is not a no-op — fed a below-floor LINE or BRANCH measurement it
      REPORTS the regression; fed an at/above-floor measurement it PASSES. Deterministic controls.

  (b) `measured_from_report()` computes line and branch percentages from a coverage.py JSON report's
      raw counts (so the gate is stable across coverage versions).

  (c) The committed thresholds file (`tools/coverage/coverage-thresholds.json`) exists, parses, and
      carries a real line+branch floor for the gated `vigil_core` package.

  (d) The wiring is true of the code: the required `vigil_core — shared integrity substrate` job
      measures coverage with `--cov-branch`, runs the ratchet guard, and publishes a coverage artifact.

HOW TO SEE IT BITE BY HAND (the failure is real on a tree without the fix, not assumed):
  * drop `--cov-branch` / the ratchet step from the vigil-core CI job -> test_ci_job_measures_and_gates fails;
  * make `evaluate()` always return `(True, [])`                      -> the (a) controls fail;
  * empty tools/coverage/coverage-thresholds.json                     -> test_committed_thresholds_are_real fails.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
GUARD_DIR = REPO / "tools" / "coverage"
THRESHOLDS = GUARD_DIR / "coverage-thresholds.json"
CI_YAML = REPO / ".github" / "workflows" / "ci.yml"

JOB_NAME = "vigil_core — shared integrity substrate"

sys.path.insert(0, str(GUARD_DIR))
import coverage_ratchet


# --- (a) the pure gate is not a no-op -------------------------------------------------------------
def test_evaluate_passes_at_or_above_floor():
    assert coverage_ratchet.evaluate("p", 85.0, 75.0, 85.0, 75.0)[0] is True
    assert coverage_ratchet.evaluate("p", 91.2, 80.0, 85.0, 75.0)[0] is True


def test_evaluate_rejects_a_line_regression():
    ok, reasons = coverage_ratchet.evaluate("p", 84.9, 80.0, 85.0, 75.0)
    assert not ok
    assert any("LINE" in r for r in reasons)


def test_evaluate_rejects_a_branch_regression():
    ok, reasons = coverage_ratchet.evaluate("p", 90.0, 74.9, 85.0, 75.0)
    assert not ok
    assert any("BRANCH" in r for r in reasons)


# --- (b) the report parser -----------------------------------------------------------------------
def test_measured_from_report_uses_raw_counts():
    report = {"totals": {"covered_lines": 90, "num_statements": 100,
                         "covered_branches": 3, "num_branches": 4}}
    line, branch = coverage_ratchet.measured_from_report(report)
    assert abs(line - 90.0) < 1e-9 and abs(branch - 75.0) < 1e-9


def test_measured_from_report_treats_zero_of_a_measure_as_full():
    report = {"totals": {"covered_lines": 10, "num_statements": 10,
                         "covered_branches": 0, "num_branches": 0}}
    line, branch = coverage_ratchet.measured_from_report(report)
    assert line == 100.0 and branch == 100.0  # no branches to miss -> not a divide-by-zero fail-open


# --- (c) the committed thresholds ----------------------------------------------------------------
def test_committed_thresholds_are_real():
    assert THRESHOLDS.is_file(), f"missing thresholds file: {THRESHOLDS}"
    data = coverage_ratchet.load_thresholds(THRESHOLDS)
    line, branch = coverage_ratchet.package_floors(data, "vigil_core")
    assert 0.0 < line <= 100.0 and 0.0 < branch <= 100.0, (line, branch)
    # A floor that is a real, non-trivial gate — not 0% (which would be a no-op).
    assert line >= 50.0 and branch >= 50.0, "a floor this low would not gate the security-critical core"


# --- (d) the CI wiring is true -------------------------------------------------------------------
def _job_block(name: str) -> str | None:
    lines = CI_YAML.read_text(encoding="utf-8").splitlines()
    start = next((i for i, l in enumerate(lines) if l.strip() == f"name: {name}"), None)
    if start is None:
        return None
    end = len(lines)
    for j in range(start + 1, len(lines)):
        if re.match(r"^  [A-Za-z0-9_-]+:\s*$", lines[j]):
            end = j
            break
    return "\n".join(lines[start:end])


def test_ci_job_measures_and_gates():
    block = _job_block(JOB_NAME)
    assert block is not None, f"no ci.yml job named {JOB_NAME!r}"
    assert "--cov=vigil_core" in block and "--cov-branch" in block, "line+branch coverage not measured"
    assert "coverage_ratchet.py check" in block, "the coverage ratchet gate is not invoked"
    assert "upload-artifact" in block and "coverage-vigil_core" in block, "no coverage artifact published"
