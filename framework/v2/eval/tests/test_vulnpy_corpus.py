"""
Measure DAA's real dataflow detection against the vulnpy corpus.

History (the improvement is the point): the corpus was built with 6
taint-rule classes plus 2 the ruleset did NOT cover (insecure
deserialization CWE-502, XXE CWE-611), measuring an honest 6/8. Taint
rules for those two classes were then added (daa-py-insecure-deserialization,
daa-py-xxe), closing the named gap to 8/8 — a hand-run of exactly what the
SIL loop automates (gap -> rule -> remeasure). Skipped when semgrep is
absent.
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

_ALL_SLUGS = (
    "sqli.py", "cmdi.py", "ssrf.py", "pathtrav.py", "ssti.py",
    "codeinj.py", "deserialize.py", "xxe.py",
)


@requires_semgrep
def test_dataflow_detection_full_corpus() -> None:
    corpus = load_corpus(_CORPUS)
    assert corpus.total_ground_truth() == 8

    run = run_harness(corpus, DaaCorpusProducer(), run_id="vulnpy", created_at=_NOW)

    # All 8 classes detected after closing the CWE-502/CWE-611 gap, no FPs.
    assert run.aggregate.true_positives == 8
    assert run.aggregate.detection_rate == 1.0
    assert run.aggregate.false_positives == 0
    assert run.aggregate.precision == 1.0


@requires_semgrep
def test_every_class_is_detected() -> None:
    corpus = load_corpus(_CORPUS)
    run = run_harness(corpus, DaaCorpusProducer(), run_id="vulnpy", created_at=_NOW)
    by_slug = {t.slug: t for t in run.per_target}
    for slug in _ALL_SLUGS:
        assert by_slug[slug].true_positives == 1, f"{slug} not detected"
