"""
DAA producer honesty: an unavailable analyzer degrades LOUDLY, never as a
silent 0/8; the always-available regex fallback reports its true (subset)
recall over the vulnpy corpus.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import pytest

from ...analysis.models import AnalysisFinding, AnalysisTarget
from ...common.errors import EvalError
from ..corpus import load_corpus
from ..harness import run_harness
from ..produce_daa import DaaCorpusProducer, DegradedAnalysis

_CORPUS = Path(__file__).resolve().parent.parent / "corpus" / "vulnpy"
_NOW = datetime(2026, 1, 1, tzinfo=timezone.utc)


class _UnavailableAnalyzer:
    """Stand-in for a taint engine that is not provisioned on the host."""

    name = "semgrep"

    def is_available(self) -> tuple[bool, str]:
        return False, "semgrep not on PATH"

    def analyze(self, target: AnalysisTarget) -> list[AnalysisFinding]:
        raise AssertionError("must not run when unavailable")


# --- degradation is explicit, never a bare [] ------------------------------


def test_degradation_preflight_reports_skip() -> None:
    prod = DaaCorpusProducer(analyzer=_UnavailableAnalyzer())
    skipped = prod.degradation()
    assert skipped is not None
    assert skipped.name == "semgrep"
    assert "PATH" in skipped.reason


def test_unavailable_analyzer_raises_degraded_not_empty() -> None:
    prod = DaaCorpusProducer(analyzer=_UnavailableAnalyzer())
    corpus = load_corpus(_CORPUS)
    with pytest.raises(DegradedAnalysis) as ei:
        prod(corpus.targets[0])
    # The raised signal carries the orchestrator-shaped skip record.
    assert ei.value.skipped.name == "semgrep"
    assert "degraded" in str(ei.value)


def test_harness_surfaces_degradation_instead_of_scoring_zero() -> None:
    """The whole point: a degraded run must not read as a real 0/8. The
    harness turns the producer's DegradedAnalysis into a loud EvalError
    naming the target — no silent zero-score run is ever recorded."""
    corpus = load_corpus(_CORPUS)
    prod = DaaCorpusProducer(analyzer=_UnavailableAnalyzer())
    with pytest.raises(EvalError) as ei:
        run_harness(corpus, prod, run_id="degraded", created_at=_NOW)
    assert isinstance(ei.value.__cause__, DegradedAnalysis)


# --- the always-available fallback reports its TRUE recall -----------------


_EXPECTED_HITS = {"sqli.py", "cmdi.py", "ssti.py", "codeinj.py", "deserialize.py"}
_EXPECTED_MISSES = {"ssrf.py", "pathtrav.py", "xxe.py"}


def test_pattern_fallback_is_available() -> None:
    assert DaaCorpusProducer.pattern_fallback().degradation() is None


def test_pattern_fallback_true_corpus_recall_is_five_of_eight() -> None:
    corpus = load_corpus(_CORPUS)
    assert corpus.total_ground_truth() == 8

    run = run_harness(
        corpus, DaaCorpusProducer.pattern_fallback(), run_id="fallback", created_at=_NOW
    )

    # Honest subset: 5 of 8 classes, zero false positives. NOT 8/8 — SSRF,
    # path traversal, and XXE need real taint tracking the regex lacks.
    assert run.aggregate.true_positives == 5
    assert run.aggregate.ground_truth_count == 8
    assert run.aggregate.false_positives == 0
    assert run.aggregate.detection_rate == round(5 / 8, 6)

    by_slug = {t.slug: t for t in run.per_target}
    hits = {s for s in by_slug if by_slug[s].true_positives == 1}
    misses = {s for s in by_slug if by_slug[s].true_positives == 0}
    assert hits == _EXPECTED_HITS
    assert misses == _EXPECTED_MISSES
