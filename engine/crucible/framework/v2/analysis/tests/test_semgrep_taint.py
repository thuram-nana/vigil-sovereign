"""
Real dataflow proof: the SemgrepAnalyzer (taint mode, shipped ruleset)
distinguishes reachable source->sink flows from sanitized equivalents —
which a regex matcher cannot. Skipped when semgrep is not installed.
"""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from ..analyzers.builtin import PatternAnalyzer
from ..analyzers.external import SemgrepAnalyzer
from ..models import AnalysisTarget

_BENCH = Path(__file__).resolve().parent.parent / "benchmark" / "python"

requires_semgrep = pytest.mark.skipif(
    shutil.which("semgrep") is None,
    reason="semgrep not installed (pip install semgrep) — real-dataflow test",
)

_EXPECTED_CWES = {"CWE-78", "CWE-89", "CWE-918", "CWE-95", "CWE-22", "CWE-1336"}


@requires_semgrep
def test_taint_detects_every_vulnerable_flow() -> None:
    findings = SemgrepAnalyzer().analyze(AnalysisTarget(root=str(_BENCH / "vulnerable.py")))
    assert len(findings) == 6
    assert {f.cwe for f in findings} == _EXPECTED_CWES


@requires_semgrep
def test_taint_is_clean_on_sanitized_equivalents() -> None:
    # Same sinks, dataflow broken (parameterised / sanitised / constant).
    # Taint analysis must produce ZERO findings here.
    findings = SemgrepAnalyzer().analyze(AnalysisTarget(root=str(_BENCH / "sanitized.py")))
    assert findings == []


@requires_semgrep
def test_taint_beats_regex_on_the_sanitized_file() -> None:
    # The contrast that justifies the upgrade: the regex pattern analyzer
    # false-positives on the sanitized file (it still sees eval(...)),
    # while taint analysis correctly stays silent.
    regex_hits = PatternAnalyzer().analyze(AnalysisTarget(root=str(_BENCH / "sanitized.py")))
    taint_hits = SemgrepAnalyzer().analyze(AnalysisTarget(root=str(_BENCH / "sanitized.py")))
    assert len(regex_hits) > len(taint_hits) == 0
