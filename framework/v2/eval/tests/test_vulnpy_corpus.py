"""
Measure DAA's real dataflow detection against the vulnpy corpus.

This is an honest benchmark: the corpus mixes 6 classes the taint rules
cover with 2 they do not (insecure deserialization, XXE), so the expected
detection rate is 6/8 = 0.75 with zero false positives — not a rigged
100%. Skipped when semgrep is absent.
"""

from __future__ import annotations

import shutil
from datetime import datetime, timezone
from pathlib import Path

import pytest

from ..corpus import load_corpus
from ..harness import run_harness
from ..produce_daa import DaaCorpusProducer

_CORPUS = Path(__file__).resolve().parent.parent / "corpus" / "vulnpy"
_NOW = datetime(2026, 1, 1, tzinfo=timezone.utc)

requires_semgrep = pytest.mark.skipif(
    shutil.which("semgrep") is None,
    reason="semgrep not installed — real-corpus detection measurement",
)


@requires_semgrep
def test_dataflow_detection_is_honest_six_of_eight() -> None:
    corpus = load_corpus(_CORPUS)
    assert corpus.total_ground_truth() == 8

    run = run_harness(corpus, DaaCorpusProducer(), run_id="vulnpy", created_at=_NOW)

    # 6 taint-class vulns detected; 2 (deserialization, XXE) honestly missed.
    assert run.aggregate.true_positives == 6
    assert run.aggregate.detection_rate == 0.75
    # No false positives — taint analysis does not fire on the missed files.
    assert run.aggregate.false_positives == 0
    assert run.aggregate.precision == 1.0


@requires_semgrep
def test_the_misses_are_the_expected_classes() -> None:
    corpus = load_corpus(_CORPUS)
    run = run_harness(corpus, DaaCorpusProducer(), run_id="vulnpy", created_at=_NOW)
    by_slug = {t.slug: t for t in run.per_target}
    # The two classes with no taint rule are the misses.
    assert by_slug["deserialize.py"].true_positives == 0
    assert by_slug["xxe.py"].true_positives == 0
    # Everything with a taint rule is caught.
    for slug in ("sqli.py", "cmdi.py", "ssrf.py", "pathtrav.py", "ssti.py", "codeinj.py"):
        assert by_slug[slug].true_positives == 1
