"""
eval.produce_daa — score DAA's real analysis against a benchmark corpus.

A `FindingProducer` that runs DAA's dataflow analysis (semgrep taint by
default) over each benchmark target's source file and maps findings to
`ProducedFinding`, so the eval harness measures the ACTUAL tool against
ground truth — not a fixture.

Kept out of `eval/__init__` (it imports the analysis layer). Used with the
shipped `vulnpy` corpus (`eval/corpus/vulnpy/`), which deliberately mixes
classes the dataflow rules cover (SQLi, command injection, SSRF, path
traversal, SSTI, code injection) with classes they do NOT (insecure
deserialization, XXE) — so the measured detection rate is honest, not
rigged to 100%.
"""

from __future__ import annotations

from pathlib import Path

from ..analysis.analyzers.external import SemgrepAnalyzer
from ..analysis.models import AnalysisTarget, Analyzer
from .models import BenchmarkTarget, ProducedFinding

# CWE -> the bug-class label the corpus ground truth uses. Keep in sync
# with eval/corpus/vulnpy/corpus.json.
_CWE_CLASS: dict[str, str] = {
    "CWE-89": "SQL Injection",
    "CWE-78": "OS Command Injection",
    "CWE-918": "SSRF",
    "CWE-22": "Path Traversal",
    "CWE-1336": "Server-Side Template Injection",
    "CWE-95": "Code Injection",
    "CWE-502": "Insecure Deserialization",
    "CWE-611": "XXE",
    "CWE-943": "NoSQL Injection",
}


def builtin_vulnpy_code_dir() -> Path:
    return Path(__file__).resolve().parent / "corpus" / "vulnpy" / "code"


def builtin_vulnjs_code_dir() -> Path:
    return Path(__file__).resolve().parent / "corpus" / "vulnjs" / "code"


class DaaCorpusProducer:
    """Run DAA over each corpus target's source file. `code_dir` holds the
    files named by target slug; the analyzer defaults to semgrep taint
    (dataflow). Targets whose file is absent, or that the analyzer is
    unavailable for, simply produce no findings (scored as misses)."""

    def __init__(self, code_dir: Path | None = None, analyzer: Analyzer | None = None) -> None:
        self._code_dir = code_dir if code_dir is not None else builtin_vulnpy_code_dir()
        self._analyzer = analyzer if analyzer is not None else SemgrepAnalyzer()

    def __call__(self, target: BenchmarkTarget) -> list[ProducedFinding]:
        src = self._code_dir / target.slug
        if not src.is_file():
            return []
        available, _ = self._analyzer.is_available()
        if not available:
            return []
        findings = self._analyzer.analyze(AnalysisTarget(root=str(src)))
        out: list[ProducedFinding] = []
        for f in findings:
            bug_class = _CWE_CLASS.get(f.cwe, f.cwe or "Static-Analysis Lead")
            out.append(ProducedFinding(
                bug_class=bug_class,
                surface=target.slug,
                summary=f.message[:160],
                confidence=0.8,
                detection_keys=[f.cwe] if f.cwe else [],
            ))
        return out
