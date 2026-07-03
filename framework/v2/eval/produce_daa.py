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

Degradation honesty: when the configured analyzer is unavailable (e.g.
semgrep not installed), a scored run must NOT quietly emit zero findings —
that reads as a real 0/8 regression when the truth is "the tool never
ran". The producer raises `DegradedAnalysis` (carrying a `SkippedAnalyzer`
record, the same shape the orchestrator uses) so the eval consumer can
tell "analyzer absent" apart from "analyzer ran, found nothing". Call
`degradation()` to preflight without triggering the raise.

An always-available, honest fallback is available via
`DaaCorpusProducer.pattern_fallback()`: the built-in regex analyzer, which
reaches a real subset of the corpus (5 of the 8 classes — SQLi, command
injection, SSTI, code injection, insecure deserialization; it does NOT
reach SSRF, path traversal, or XXE, which need real taint tracking). It is
never 8/8, and nothing here claims it is.
"""

from __future__ import annotations

from pathlib import Path

from ..analysis.analyzers.builtin import PatternAnalyzer
from ..analysis.analyzers.external import SemgrepAnalyzer
from ..analysis.models import AnalysisTarget, Analyzer, SkippedAnalyzer
from ..common.errors import CrucibleError
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


class DegradedAnalysis(CrucibleError):
    """The producer could not run its analyzer, so the measurement is
    degraded rather than legitimately empty. Carries the same
    `SkippedAnalyzer` record the analysis orchestrator emits, so the eval
    consumer (SIL) can distinguish "analyzer absent" from "found nothing"
    and refuse to score a degraded run as a real 0.

    It is a recoverable CrucibleError, not an EthicsViolation: no trust
    boundary was crossed, the tool just was not present."""

    def __init__(self, skipped: SkippedAnalyzer) -> None:
        self.skipped = skipped
        super().__init__(
            f"analyzer {skipped.name!r} unavailable — measurement degraded, "
            f"not a real zero ({skipped.reason})"
        )


def builtin_vulnpy_code_dir() -> Path:
    return Path(__file__).resolve().parent / "corpus" / "vulnpy" / "code"


def builtin_vulnjs_code_dir() -> Path:
    return Path(__file__).resolve().parent / "corpus" / "vulnjs" / "code"


class DaaCorpusProducer:
    """Run DAA over each corpus target's source file. `code_dir` holds the
    files named by target slug; the analyzer defaults to semgrep taint
    (dataflow).

    If the analyzer is unavailable the producer raises `DegradedAnalysis`
    rather than returning `[]` — a silent empty result would be scored as a
    real 0/8 regression. Preflight with `degradation()` to decide whether a
    scored run is meaningful before invoking the harness. Targets whose
    source file is simply absent produce no findings (a genuine miss, not a
    degradation)."""

    def __init__(self, code_dir: Path | None = None, analyzer: Analyzer | None = None) -> None:
        self._code_dir = code_dir if code_dir is not None else builtin_vulnpy_code_dir()
        self._analyzer = analyzer if analyzer is not None else SemgrepAnalyzer()

    @classmethod
    def pattern_fallback(cls, code_dir: Path | None = None) -> "DaaCorpusProducer":
        """A producer backed by the always-available built-in regex
        analyzer. Honest recall is a subset of the corpus (5/8), never
        8/8; use it when no external taint engine is provisioned but a
        real, non-degraded measurement is still wanted."""
        return cls(code_dir=code_dir, analyzer=PatternAnalyzer())

    @property
    def analyzer_name(self) -> str:
        return self._analyzer.name

    def degradation(self) -> SkippedAnalyzer | None:
        """Return a `SkippedAnalyzer` record iff the configured analyzer is
        unavailable, else None. Lets a caller detect a degraded run without
        triggering the `DegradedAnalysis` raise mid-harness."""
        available, reason = self._analyzer.is_available()
        if available:
            return None
        return SkippedAnalyzer(name=self._analyzer.name, reason=reason)

    def __call__(self, target: BenchmarkTarget) -> list[ProducedFinding]:
        skipped = self.degradation()
        if skipped is not None:
            raise DegradedAnalysis(skipped)

        src = self._code_dir / target.slug
        if not src.is_file():
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
