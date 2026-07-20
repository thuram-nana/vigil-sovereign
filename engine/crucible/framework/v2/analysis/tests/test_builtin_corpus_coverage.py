"""
Honest built-in (regex) coverage over the vulnpy corpus, and the
orchestrator recording an unavailable analyzer as skipped over that same
tree. The regex fallback reaches a subset (5/8) — this pins that truth so
nobody can quietly claim 8/8.
"""

from __future__ import annotations

from pathlib import Path

from ..analyzers.builtin import PatternAnalyzer
from ..models import AnalysisFinding, AnalysisTarget
from ..orchestrator import run_analysis

_CORPUS_CODE = (
    Path(__file__).resolve().parents[2] / "eval" / "corpus" / "vulnpy" / "code"
)

# CWE the built-in ruleset genuinely reaches, per corpus file.
_EXPECTED_CWE: dict[str, str] = {
    "cmdi.py": "CWE-78",
    "codeinj.py": "CWE-95",
    "deserialize.py": "CWE-502",
    "sqli.py": "CWE-89",
    "ssti.py": "CWE-1336",
}
# Classes the regex cannot reach without real taint tracking.
_EXPECTED_MISSES = {"ssrf.py", "pathtrav.py", "xxe.py"}


def test_builtin_reaches_exactly_five_of_eight_corpus_classes() -> None:
    pa = PatternAnalyzer()
    hits: dict[str, str] = {}
    misses: set[str] = set()
    for src in sorted(_CORPUS_CODE.glob("*.py")):
        findings = pa.analyze(AnalysisTarget(root=str(src)))
        if findings:
            hits[src.name] = findings[0].cwe
        else:
            misses.add(src.name)

    assert hits == _EXPECTED_CWE          # 5 files, correct CWE each
    assert misses == _EXPECTED_MISSES      # 3 genuinely out of reach
    assert len(hits) == 5 and len(misses) == 3


class _UnavailableTaint:
    name = "semgrep"

    def is_available(self) -> tuple[bool, str]:
        return False, "semgrep not on PATH"

    def analyze(self, target: AnalysisTarget) -> list[AnalysisFinding]:
        raise AssertionError("must not run when unavailable")


def test_orchestrator_records_skip_for_unavailable_analyzer() -> None:
    report = run_analysis(
        AnalysisTarget(root=str(_CORPUS_CODE)),
        analyzers=[PatternAnalyzer(), _UnavailableTaint()],
    )
    # The pattern analyzer ran and produced real findings...
    assert "pattern" in report.analyzers_run
    assert report.findings
    # ...and the absent taint engine was recorded as skipped, with a reason
    # — visible degradation, never a silent drop.
    skipped = {s.name: s.reason for s in report.analyzers_skipped}
    assert "semgrep" in skipped
    assert "PATH" in skipped["semgrep"]
