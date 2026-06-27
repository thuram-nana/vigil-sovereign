"""
eval — Milestone M2: the evaluation harness.

Self-improvement is unfalsifiable without measurement. Before SIL
(Pillar 3) may propose a change to the framework, the change must be
scored: did detection go up, did false-positives go down, did anything
regress? This package is that measurement substrate.

It is deliberately decoupled from any live target. The harness scores a
set of *produced* findings against a benchmark corpus of *ground-truth*
findings. How the produced findings are obtained — a deterministic
fixture, a replayed engagement, or a live planner run via an adapter —
is the caller's choice (`FindingProducer` protocol). That decoupling is
what makes the harness itself testable offline and deterministic.

Public surface:

    from framework.v2.eval import (
        GroundTruthFinding, BenchmarkTarget, BenchmarkCorpus,
        ProducedFinding, TargetScore, EvalRun, RegressionReport,
        score_target, score_run, compare_runs,
        load_corpus, run_harness, FindingProducer,
    )

The eval layer makes no trust decision and sends no traffic. It reads a
corpus, scores findings, and writes run records. SIL gates merges on
its output; it does not act on its own.
"""

from __future__ import annotations

from .corpus import load_corpus
from .harness import FindingProducer, run_harness
from .models import (
    AggregateScore,
    BenchmarkCorpus,
    BenchmarkTarget,
    EvalRun,
    GroundTruthFinding,
    ProducedFinding,
    RegressionReport,
    TargetScore,
)
from .regression import compare_runs
from .scoring import score_run, score_target

__all__ = [
    "GroundTruthFinding",
    "BenchmarkTarget",
    "BenchmarkCorpus",
    "ProducedFinding",
    "TargetScore",
    "AggregateScore",
    "EvalRun",
    "RegressionReport",
    "score_target",
    "score_run",
    "compare_runs",
    "load_corpus",
    "run_harness",
    "FindingProducer",
]
