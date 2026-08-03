"""
eval.gate — a zero-tolerance regression gate over benchmark scoreboards.

A benchmark that nobody enforces rots. This turns a committed baseline of per-app,
per-tool confusion counts into a CI gate: a candidate run must not regress
CRUCIBLE's accuracy against the baseline. Three things fail the gate, all of them
the properties the whole project stakes credibility on:

  * a NEW false positive (fp went up) — the zero-FP thesis broke somewhere,
  * a NEWLY-MISSED finding (tp went down) — coverage regressed,
  * a PRECISION drop — the accuracy/noise trade-off got worse.

It is deliberately asymmetric: fewer FPs, more TPs, or higher precision are
improvements, never failures (they just mean it is time to refresh the baseline).

The committed baseline (``eval/baselines/``) is the in-process benchmark app, which
runs anywhere with no Docker — the CI spine. An operator who runs the dockerized
corpus snapshots their OWN baseline for the apps they can stand up; the gate logic
is identical. Apps in the baseline that a candidate run skipped (e.g. Docker absent
in this environment) are reported as WARNINGS, not failures — a missing container is
an environment gap, not a code regression.
"""

from __future__ import annotations

import json
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field

from ..common.errors import EvalError
from .validation import MeasuredBoard


class GateError(EvalError):
    """A malformed or unreadable baseline file."""


class ToolScore(BaseModel):
    """One tool's confusion counts on one app — the baseline unit.

    ``recall`` and ``ground_truth_count`` are DERIVED from the confusion counts
    (recall = tp/(tp+fn); ground truth = tp+fn = every planted bug), so the stored
    unit stays a minimal tp/fp/fn triple and an older baseline file loads unchanged.
    They are surfaced explicitly so a recall regression is a NAMED gate failure, not
    only an implication of a tp drop."""

    model_config = ConfigDict(extra="forbid")

    tp: int = Field(ge=0)
    fp: int = Field(ge=0)
    fn: int = Field(ge=0)

    @property
    def precision(self) -> float:
        d = self.tp + self.fp
        return round(self.tp / d, 6) if d else 0.0

    @property
    def recall(self) -> float:
        d = self.tp + self.fn
        return round(self.tp / d, 6) if d else 0.0

    @property
    def ground_truth_count(self) -> int:
        return self.tp + self.fn


class Baseline(BaseModel):
    """A committed snapshot: per app, per tool, the confusion counts to hold the
    line at. ``label`` is a human tag (a git sha / date passed in, never stamped
    here — the module must stay deterministic)."""

    model_config = ConfigDict(extra="forbid")

    label: str = ""
    scores: dict[str, dict[str, ToolScore]] = Field(default_factory=dict)

    @classmethod
    def load(cls, path: str | Path) -> "Baseline":
        p = Path(path).expanduser()
        try:
            return cls.model_validate_json(p.read_text(encoding="utf-8"))
        except OSError as e:
            raise GateError(f"cannot read baseline {p}: {e}") from e
        except ValueError as e:
            raise GateError(f"baseline {p} is not a valid Baseline: {e}") from e

    def dump(self, path: str | Path) -> Path:
        p = Path(path).expanduser()
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(self.model_dump_json(indent=2) + "\n", encoding="utf-8")
        return p


class GateVerdict(BaseModel):
    """The gate outcome. ``passed`` is the CI exit signal; ``regressions`` are the
    hard failures, ``warnings`` the non-fatal notes (missing app/tool), and
    ``improvements`` the deltas that beat the baseline (a nudge to refresh it)."""

    model_config = ConfigDict(extra="forbid")

    passed: bool
    regressions: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    improvements: list[str] = Field(default_factory=list)


def snapshot(results: dict[str, list[MeasuredBoard]], *, label: str = "") -> Baseline:
    """Turn a run's per-app measured boards into a committable :class:`Baseline`."""
    scores: dict[str, dict[str, ToolScore]] = {}
    for app, boards in results.items():
        scores[app] = {
            mb.scoreboard.tool: ToolScore(
                tp=mb.scoreboard.true_positives,
                fp=mb.scoreboard.false_positives,
                fn=mb.scoreboard.false_negatives,
            )
            for mb in boards
        }
    return Baseline(label=label, scores=scores)


def gate(
    results: dict[str, list[MeasuredBoard]],
    baseline: Baseline,
    *,
    tools: tuple[str, ...] = ("crucible",),
) -> GateVerdict:
    """Compare a candidate run to ``baseline`` and return a :class:`GateVerdict`.

    Only ``tools`` are gated (default: CRUCIBLE — the tool whose zero-FP / recall
    properties we own; incumbents vary by host and are not a pass/fail signal). For
    each baselined app+tool: fp must not rise, tp must not fall, precision must not
    drop. A candidate missing an app/tool the baseline had is a warning, not a fail
    — an environment gap (no container) is not a code regression."""
    regressions: list[str] = []
    warnings: list[str] = []
    improvements: list[str] = []

    for app, base_tools in baseline.scores.items():
        cand = results.get(app)
        if cand is None:
            warnings.append(f"{app}: in baseline but not in candidate run (skipped/unavailable)")
            continue
        cand_by_tool = {mb.scoreboard.tool: mb.scoreboard for mb in cand}
        for tool, base in base_tools.items():
            if tools and tool not in tools:
                continue
            c = cand_by_tool.get(tool)
            if c is None:
                warnings.append(f"{app}/{tool}: in baseline but tool did not run")
                continue
            if c.false_positives > base.fp:
                regressions.append(
                    f"{app}/{tool}: false positives {base.fp} -> {c.false_positives} (NEW FP)")
            if c.true_positives < base.tp:
                regressions.append(
                    f"{app}/{tool}: true positives {base.tp} -> {c.true_positives} (NEWLY MISSED)")
            if c.precision < base.precision:
                regressions.append(
                    f"{app}/{tool}: precision {base.precision:.3f} -> {c.precision:.3f} (DROP)")
            # Named recall-floor check: candidate recall must not fall below the
            # baseline's. Asymmetric — higher recall (more of the ground truth found)
            # is an improvement, never a failure. A recall drop at an unchanged ground
            # truth already implies a tp drop, but naming it makes a coverage
            # regression an explicit, self-describing gate failure.
            if c.recall < base.recall:
                regressions.append(
                    f"{app}/{tool}: recall {base.recall:.3f} -> {c.recall:.3f} (DROP)")
            if c.false_positives < base.fp or c.true_positives > base.tp or c.recall > base.recall:
                improvements.append(
                    f"{app}/{tool}: tp {base.tp}->{c.true_positives}, fp {base.fp}->{c.false_positives}, "
                    f"recall {base.recall:.3f}->{c.recall:.3f}")

    return GateVerdict(
        passed=not regressions,
        regressions=regressions,
        warnings=warnings,
        improvements=improvements,
    )
