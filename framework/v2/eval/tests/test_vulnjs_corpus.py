"""
Measure DAA's dataflow detection on the JavaScript corpus — the second
language. Proves multi-language taint: the same SemgrepAnalyzer + shipped
ruleset detects source->sink flows in Express/Node code. Skipped when
semgrep is absent.
"""

from __future__ import annotations

import shutil
from datetime import datetime, timezone
from pathlib import Path

import pytest

from ..corpus import load_corpus
from ..harness import run_harness
from ..produce_daa import DaaCorpusProducer, builtin_vulnjs_code_dir

_CORPUS = Path(__file__).resolve().parent.parent / "corpus" / "vulnjs"
_NOW = datetime(2026, 1, 1, tzinfo=timezone.utc)

requires_semgrep = pytest.mark.skipif(
    shutil.which("semgrep") is None,
    reason="semgrep not installed — JS dataflow detection measurement",
)

_SLUGS = ("cmdi.js", "codeinj.js", "ssrf.js", "sqli.js", "pathtrav.js", "nosqli.js")


@requires_semgrep
def test_js_dataflow_detection_full_corpus() -> None:
    corpus = load_corpus(_CORPUS)
    assert corpus.total_ground_truth() == 6

    producer = DaaCorpusProducer(code_dir=builtin_vulnjs_code_dir())
    run = run_harness(corpus, producer, run_id="vulnjs", created_at=_NOW)

    assert run.aggregate.true_positives == 6
    assert run.aggregate.detection_rate == 1.0
    assert run.aggregate.false_positives == 0


@requires_semgrep
def test_every_js_class_detected() -> None:
    corpus = load_corpus(_CORPUS)
    producer = DaaCorpusProducer(code_dir=builtin_vulnjs_code_dir())
    run = run_harness(corpus, producer, run_id="vulnjs", created_at=_NOW)
    by_slug = {t.slug: t for t in run.per_target}
    for slug in _SLUGS:
        assert by_slug[slug].true_positives == 1, f"{slug} not detected"
