"""Tests for eval.corpus (loading) and eval.harness (run + persist)."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from ...common.errors import EvalError
from ..corpus import load_corpus
from ..harness import load_run, run_harness, save_run
from ..models import BenchmarkTarget, ProducedFinding

_NOW = datetime(2026, 1, 1, tzinfo=timezone.utc)

_CORPUS_DOC = {
    "name": "demo-corpus",
    "version": "1",
    "targets": [
        {
            "slug": "acme-shop",
            "name": "Acme Shop",
            "ground_truth": [
                {"id": "g1", "bug_class": "IDOR", "surface": "/api/orders/{id}"},
                {"id": "g2", "bug_class": "SSRF", "surface": "/webhook"},
            ],
        }
    ],
}


def test_load_corpus_from_file(tmp_path: Path) -> None:
    p = tmp_path / "corpus.json"
    p.write_text(json.dumps(_CORPUS_DOC), encoding="utf-8")
    corpus = load_corpus(p)
    assert corpus.name == "demo-corpus"
    assert corpus.total_ground_truth() == 2


def test_load_corpus_from_directory_with_target_files(tmp_path: Path) -> None:
    (tmp_path / "corpus.json").write_text(
        json.dumps({"name": "dir-corpus", "version": "2"}), encoding="utf-8"
    )
    target = {
        "slug": "blog",
        "name": "Blog",
        "ground_truth": [{"id": "b1", "bug_class": "XSS", "surface": "/comment"}],
    }
    (tmp_path / "blog.target.json").write_text(json.dumps(target), encoding="utf-8")
    corpus = load_corpus(tmp_path)
    assert corpus.name == "dir-corpus"
    assert corpus.version == "2"
    assert [t.slug for t in corpus.targets] == ["blog"]


def test_load_corpus_missing_path_raises(tmp_path: Path) -> None:
    with pytest.raises(EvalError):
        load_corpus(tmp_path / "does-not-exist.json")


def test_load_corpus_invalid_json_raises(tmp_path: Path) -> None:
    p = tmp_path / "corpus.json"
    p.write_text("{not json", encoding="utf-8")
    with pytest.raises(EvalError):
        load_corpus(p)


def test_directory_without_manifest_raises(tmp_path: Path) -> None:
    (tmp_path / "blog.target.json").write_text("{}", encoding="utf-8")
    with pytest.raises(EvalError):
        load_corpus(tmp_path)


def test_run_harness_with_deterministic_producer(tmp_path: Path) -> None:
    p = tmp_path / "corpus.json"
    p.write_text(json.dumps(_CORPUS_DOC), encoding="utf-8")
    corpus = load_corpus(p)

    def producer(target: BenchmarkTarget) -> list[ProducedFinding]:
        # Rediscover exactly the IDOR, miss the SSRF.
        return [ProducedFinding(bug_class="IDOR", surface="/api/orders/{id}")]

    run = run_harness(corpus, producer, run_id="r1", created_at=_NOW, label="unit")
    assert run.aggregate.true_positives == 1
    assert run.aggregate.detection_rate == 0.5
    assert run.label == "unit"


def test_run_harness_producer_failure_raises(tmp_path: Path) -> None:
    p = tmp_path / "corpus.json"
    p.write_text(json.dumps(_CORPUS_DOC), encoding="utf-8")
    corpus = load_corpus(p)

    def bad_producer(target: BenchmarkTarget) -> list[ProducedFinding]:
        raise RuntimeError("planner crashed")

    with pytest.raises(EvalError) as ei:
        run_harness(corpus, bad_producer, run_id="r1", created_at=_NOW)
    assert "acme-shop" in str(ei.value)


def test_run_roundtrip_persistence(tmp_path: Path) -> None:
    p = tmp_path / "corpus.json"
    p.write_text(json.dumps(_CORPUS_DOC), encoding="utf-8")
    corpus = load_corpus(p)

    def producer(target: BenchmarkTarget) -> list[ProducedFinding]:
        return [ProducedFinding(bug_class="IDOR", surface="/api/orders/{id}")]

    run = run_harness(corpus, producer, run_id="r1", created_at=_NOW)
    out = save_run(run, tmp_path / "run.json")
    reloaded = load_run(out)
    assert reloaded.run_id == run.run_id
    assert reloaded.aggregate.true_positives == 1
    assert reloaded.per_target[0].missed_ground_truth_ids == ["g2"]
