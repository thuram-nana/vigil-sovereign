"""
eval.scoring — match produced findings to ground truth and score.

Matching rule (deterministic, greedy, one-to-one):

  A produced finding matches a ground-truth finding iff their normalized
  bug classes are equal AND at least one surface signal lines up:
    - normalized surfaces are equal or one contains the other, OR
    - their detection_keys intersect, OR
    - a ground-truth detection_key appears in the produced surface.

  Each ground-truth finding is matched at most once. A produced finding
  that matches no remaining ground truth is a false positive (e.g. a
  duplicate report, or a spurious detection).

The asymmetry is intentional: rediscovering a known bug is a true
positive; reporting something with no ground-truth counterpart is a
false positive. Benchmark targets must therefore have *complete* ground
truth for false-positive counts to be meaningful — a caveat the corpus
documents per target.
"""

from __future__ import annotations

from datetime import datetime

from .models import (
    AggregateScore,
    BenchmarkCorpus,
    BenchmarkTarget,
    EvalRun,
    GroundTruthFinding,
    MatchedPair,
    ProducedFinding,
    TargetScore,
)


def _norm_surface(raw: str) -> str:
    s = raw.strip().lower().rstrip("/")
    return s


def _matches(gt: GroundTruthFinding, pf: ProducedFinding) -> bool:
    if gt.normalized_bug_class() != pf.normalized_bug_class():
        return False

    gs = _norm_surface(gt.surface)
    ps = _norm_surface(pf.surface)
    if gs and ps and (gs == ps or gs in ps or ps in gs):
        return True

    gt_keys = {k.strip().lower() for k in gt.detection_keys if k.strip()}
    pf_keys = {k.strip().lower() for k in pf.detection_keys if k.strip()}
    if gt_keys & pf_keys:
        return True
    if ps and any(k in ps for k in gt_keys):
        return True
    return False


def score_target(target: BenchmarkTarget, produced: list[ProducedFinding]) -> TargetScore:
    """Greedy one-to-one match of produced findings against the target's
    ground truth."""
    unmatched_gt: list[GroundTruthFinding] = list(target.ground_truth)
    matched: list[MatchedPair] = []
    false_positives = 0

    for pf in produced:
        hit_index: int | None = None
        for i, gt in enumerate(unmatched_gt):
            if _matches(gt, pf):
                hit_index = i
                break
        if hit_index is None:
            false_positives += 1
            continue
        gt = unmatched_gt.pop(hit_index)
        matched.append(MatchedPair(ground_truth_id=gt.id, bug_class=gt.bug_class, surface=gt.surface))

    return TargetScore(
        slug=target.slug,
        ground_truth_count=len(target.ground_truth),
        true_positives=len(matched),
        false_positives=false_positives,
        matched=matched,
        missed_ground_truth_ids=[gt.id for gt in unmatched_gt],
    )


def _aggregate(per_target: list[TargetScore]) -> AggregateScore:
    return AggregateScore(
        targets=len(per_target),
        ground_truth_count=sum(t.ground_truth_count for t in per_target),
        true_positives=sum(t.true_positives for t in per_target),
        false_positives=sum(t.false_positives for t in per_target),
    )


def score_run(
    *,
    run_id: str,
    corpus: BenchmarkCorpus,
    produced_by_slug: dict[str, list[ProducedFinding]],
    created_at: datetime,
    label: str = "",
) -> EvalRun:
    """Score every target in `corpus` against the produced findings keyed
    by target slug. Targets absent from `produced_by_slug` are scored
    with zero produced findings (all ground truth missed) — a run that
    skips a target is a detection failure, not an excused absence."""
    per_target = [
        score_target(t, produced_by_slug.get(t.slug, [])) for t in corpus.targets
    ]
    return EvalRun(
        run_id=run_id,
        label=label,
        corpus_name=corpus.name,
        corpus_version=corpus.version,
        created_at=created_at,
        per_target=per_target,
        aggregate=_aggregate(per_target),
    )
