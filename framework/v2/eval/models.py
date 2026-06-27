"""
eval.models — schemas for the evaluation harness.

A benchmark corpus is a set of targets, each with a known, curated set
of ground-truth findings. A run produces findings per target; scoring
matches produced against ground truth to yield detection/precision/
recall, aggregates across the corpus, and records the result so two
runs can be compared for regression.

All shapes are pure validated data. Matching and scoring live in
scoring.py; comparison in regression.py.
"""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field, model_validator


# ---------------------------------------------------------------------------
# Corpus
# ---------------------------------------------------------------------------


class GroundTruthFinding(BaseModel):
    """A vulnerability known to exist in a benchmark target. The harness
    scores a run by how many of these it rediscovers."""

    model_config = ConfigDict(extra="forbid")

    id: str = Field(min_length=1, description="Stable id, unique within the target.")
    bug_class: str = Field(min_length=1, description="Canonical class: IDOR, SQLi, SSRF, ...")
    surface: str = Field(min_length=1, description="Endpoint / feature / flow it lives on.")
    severity: str = Field(default="medium", pattern=r"^(info|low|medium|high|critical)$")
    cwe: str = Field(default="", description="Optional CWE id, e.g. CWE-89.")
    description: str = Field(default="")
    detection_keys: list[str] = Field(
        default_factory=list,
        description="Optional extra signals (param names, tokens) that a "
        "produced finding may carry instead of an exact surface match.",
    )

    def normalized_bug_class(self) -> str:
        return _normalize_class(self.bug_class)


class BenchmarkTarget(BaseModel):
    """One target in the corpus, with its curated ground truth."""

    model_config = ConfigDict(extra="forbid")

    slug: str = Field(min_length=1)
    name: str = Field(min_length=1)
    archetype: str = Field(default="generic-web")
    description: str = Field(default="")
    ground_truth: list[GroundTruthFinding] = Field(default_factory=list)

    @model_validator(mode="after")
    def _unique_gt_ids(self) -> "BenchmarkTarget":
        ids = [g.id for g in self.ground_truth]
        if len(set(ids)) != len(ids):
            raise ValueError(f"target {self.slug!r} has duplicate ground-truth ids")
        return self


class BenchmarkCorpus(BaseModel):
    """The full set of benchmark targets. The unit a run scores against."""

    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1)
    version: str = Field(default="0")
    targets: list[BenchmarkTarget] = Field(default_factory=list)

    @model_validator(mode="after")
    def _unique_slugs(self) -> "BenchmarkCorpus":
        slugs = [t.slug for t in self.targets]
        if len(set(slugs)) != len(slugs):
            raise ValueError("corpus has duplicate target slugs")
        return self

    def total_ground_truth(self) -> int:
        return sum(len(t.ground_truth) for t in self.targets)


# ---------------------------------------------------------------------------
# Produced findings (what a run emits)
# ---------------------------------------------------------------------------


class ProducedFinding(BaseModel):
    """A finding the framework emitted for a target during a run. Mapped
    from a blackboard FindingPayload by an adapter, or supplied directly
    by a deterministic producer in tests."""

    model_config = ConfigDict(extra="forbid")

    bug_class: str = Field(min_length=1)
    surface: str = Field(default="")
    summary: str = Field(default="")
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)
    detection_keys: list[str] = Field(default_factory=list)

    def normalized_bug_class(self) -> str:
        return _normalize_class(self.bug_class)


# ---------------------------------------------------------------------------
# Scores
# ---------------------------------------------------------------------------


class MatchedPair(BaseModel):
    """A produced finding matched to a ground-truth id."""

    model_config = ConfigDict(extra="forbid")

    ground_truth_id: str
    bug_class: str
    surface: str


class TargetScore(BaseModel):
    """Per-target detection metrics."""

    model_config = ConfigDict(extra="forbid")

    slug: str
    ground_truth_count: int = Field(ge=0)
    true_positives: int = Field(ge=0)
    false_positives: int = Field(ge=0)
    matched: list[MatchedPair] = Field(default_factory=list)
    missed_ground_truth_ids: list[str] = Field(default_factory=list)

    @property
    def false_negatives(self) -> int:
        return self.ground_truth_count - self.true_positives

    @property
    def detection_rate(self) -> float:
        """recall — fraction of ground truth rediscovered."""
        return _ratio(self.true_positives, self.ground_truth_count)

    @property
    def precision(self) -> float:
        produced = self.true_positives + self.false_positives
        return _ratio(self.true_positives, produced)

    @property
    def f1(self) -> float:
        p, r = self.precision, self.detection_rate
        return 0.0 if (p + r) == 0 else round(2 * p * r / (p + r), 6)


class AggregateScore(BaseModel):
    """Corpus-wide rollup. Micro-averaged (sum counts, then divide) so a
    target with more ground truth weighs proportionally."""

    model_config = ConfigDict(extra="forbid")

    targets: int = Field(ge=0)
    ground_truth_count: int = Field(ge=0)
    true_positives: int = Field(ge=0)
    false_positives: int = Field(ge=0)

    @property
    def false_negatives(self) -> int:
        return self.ground_truth_count - self.true_positives

    @property
    def detection_rate(self) -> float:
        return _ratio(self.true_positives, self.ground_truth_count)

    @property
    def precision(self) -> float:
        produced = self.true_positives + self.false_positives
        return _ratio(self.true_positives, produced)

    @property
    def f1(self) -> float:
        p, r = self.precision, self.detection_rate
        return 0.0 if (p + r) == 0 else round(2 * p * r / (p + r), 6)


class EvalRun(BaseModel):
    """A scored run over a corpus. The record SIL compares for regression."""

    model_config = ConfigDict(extra="forbid")

    run_id: str = Field(min_length=1)
    label: str = Field(default="", description="Human label, e.g. a git sha or 'baseline'.")
    corpus_name: str
    corpus_version: str = Field(default="0")
    created_at: datetime
    per_target: list[TargetScore] = Field(default_factory=list)
    aggregate: AggregateScore


# ---------------------------------------------------------------------------
# Regression
# ---------------------------------------------------------------------------


class RegressionReport(BaseModel):
    """The verdict comparing a candidate run to a baseline. SIL gates a
    merge on `passed`."""

    model_config = ConfigDict(extra="forbid")

    baseline_run_id: str
    candidate_run_id: str
    passed: bool
    detection_rate_delta: float
    precision_delta: float
    newly_missed_ground_truth: list[str] = Field(
        default_factory=list,
        description="Ground-truth ids detected in baseline but missed now.",
    )
    newly_detected_ground_truth: list[str] = Field(
        default_factory=list,
        description="Ground-truth ids missed in baseline but detected now.",
    )
    reasons: list[str] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


def _ratio(num: int, den: int) -> float:
    return 0.0 if den == 0 else round(num / den, 6)


def _normalize_class(raw: str) -> str:
    """Canonicalise a bug-class label for matching: lowercase, strip,
    collapse separators. 'SQL Injection' / 'sql-injection' / 'SQLi' do
    not auto-unify (different surface vocab); this only removes
    formatting noise within the same label."""
    return "".join(ch for ch in raw.strip().lower() if ch.isalnum())
