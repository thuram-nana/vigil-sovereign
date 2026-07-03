"""
calibration.models — typed schemas for the exploitability-calibration layer.

The audit finding this layer answers: a "confirmed" finding used to carry a
hardcoded `1.0` confidence, and nothing ever measured whether that number was
honest. Calibration replaces the constant with a probability *learned from
recorded outcomes*.

Four shapes carry that story:

  Prediction         what the framework believed at scoring time — the raw
                     model score in [0, 1], the feature hash that produced it,
                     the model version, and whether a deterministic oracle
                     (see verify/) fired. This is the input to calibration.
  Outcome            what actually happened to the finding once the operator
                     (or a fix, or a dispute) resolved it — a single label.
                     This is the ground truth calibration learns from.
  Bin                one reliability-diagram bucket: the mean predicted
                     probability vs. the mean observed exploitable-rate.
  CalibrationReport  the aggregate reliability of a set of predictions —
                     Expected Calibration Error (ECE) and Brier score over
                     the bins. Lower is better for both.

Nothing here fits or applies a mapping (that is calibrate.py) and nothing
persists (that is ledger.py). These are pure, validated data shapes.

Ground-truth mapping (`label_to_target`)
-----------------------------------------
Calibration needs a binary target — "was this finding really exploitable?" —
for each labelled prediction:

  EXPLOITABLE      -> 1.0   the claim held; a real, reachable vulnerability.
  REMEDIATED       -> 1.0   it was a real vulnerability that got fixed; the
                            prediction that it was exploitable was *correct*.
  FALSE_POSITIVE   -> 0.0   the claim did not hold; nothing was exploitable.
  DISPUTED         -> None  ground truth is unknown; excluded from fitting and
                            from every reliability metric. Never guessed.
"""

from __future__ import annotations

import enum

from pydantic import BaseModel, ConfigDict, Field


class OutcomeLabel(str, enum.Enum):
    """The resolved disposition of a finding — calibration's ground truth.

    `label_to_target` maps these to a binary exploitability target; DISPUTED
    maps to None and is excluded from every fit and metric."""

    EXPLOITABLE = "exploitable"          # confirmed real & reachable
    REMEDIATED = "remediated"            # was real, since fixed  (target 1)
    DISPUTED = "disputed"                # ground truth unknown   (excluded)
    FALSE_POSITIVE = "false_positive"    # claim did not hold     (target 0)


# label -> binary exploitability target (None means "exclude from calibration")
_LABEL_TARGET: dict[OutcomeLabel, float | None] = {
    OutcomeLabel.EXPLOITABLE: 1.0,
    OutcomeLabel.REMEDIATED: 1.0,
    OutcomeLabel.FALSE_POSITIVE: 0.0,
    OutcomeLabel.DISPUTED: None,
}


def label_to_target(label: OutcomeLabel) -> float | None:
    """The binary exploitability target for a label, or None to exclude it.

    See the module docstring for the rationale of each mapping. DISPUTED is
    the only label that returns None — its ground truth is genuinely unknown,
    so it never contributes to a fit or a reliability number."""
    return _LABEL_TARGET[label]


class Prediction(BaseModel):
    """What the framework believed about one finding at scoring time.

    `raw_score` is the model's uncalibrated exploitability score in [0, 1].
    `oracle_confirmed` records whether a deterministic verify/ oracle fired —
    it contributes a strong *prior* during calibration, but the number it
    resolves to is still learned from outcomes (see calibrate.py), never the
    old hardcoded 1.0. `feature_hash` and `model_version` make a prediction
    attributable and reproducible."""

    model_config = ConfigDict(extra="forbid")

    finding_id: str = Field(min_length=1, description="Stable id of the finding scored.")
    raw_score: float = Field(
        ge=0.0, le=1.0, description="Uncalibrated model exploitability score."
    )
    feature_hash: str = Field(
        min_length=1, description="Hash of the feature vector that produced the score."
    )
    model_version: str = Field(
        min_length=1, description="Version tag of the scoring model, for attribution."
    )
    oracle_confirmed: bool = Field(
        description="True iff a deterministic verify/ oracle fired for this finding."
    )


class Outcome(BaseModel):
    """The resolved ground truth for one finding — what calibration learns from."""

    model_config = ConfigDict(extra="forbid")

    finding_id: str = Field(min_length=1, description="Stable id of the finding resolved.")
    label: OutcomeLabel = Field(description="The finding's resolved disposition.")

    @property
    def target(self) -> float | None:
        """The binary exploitability target for this outcome (None if excluded)."""
        return label_to_target(self.label)


class Bin(BaseModel):
    """One bucket of a reliability diagram: predicted vs. observed.

    `mean_pred` is the average calibrated probability the model assigned to
    the predictions that fell in this bucket; `mean_actual` is the fraction of
    them that were actually exploitable. A perfectly calibrated model has
    `mean_pred == mean_actual` in every populated bin."""

    model_config = ConfigDict(extra="forbid")

    index: int = Field(ge=0, description="Bin ordinal, 0-based, low probability first.")
    lower: float = Field(ge=0.0, le=1.0, description="Inclusive lower probability edge.")
    upper: float = Field(ge=0.0, le=1.0, description="Upper probability edge.")
    count: int = Field(ge=0, description="Number of predictions that fell in this bin.")
    mean_pred: float = Field(
        ge=0.0, le=1.0, default=0.0, description="Mean predicted probability in the bin."
    )
    mean_actual: float = Field(
        ge=0.0, le=1.0, default=0.0, description="Observed exploitable-rate in the bin."
    )

    @property
    def gap(self) -> float:
        """|mean_pred - mean_actual| — this bin's contribution to miscalibration."""
        return abs(self.mean_pred - self.mean_actual)


class CalibrationReport(BaseModel):
    """The aggregate reliability of a set of predictions.

    `ece` (Expected Calibration Error) is the count-weighted average bin gap;
    `brier` is the mean squared error between predicted probability and
    outcome. Both are in a "lower is better" sense. `n` counts only the
    labelled, non-DISPUTED predictions that actually contributed."""

    model_config = ConfigDict(extra="forbid")

    n: int = Field(ge=0, description="Number of labelled predictions scored.")
    ece: float = Field(ge=0.0, le=1.0, description="Expected Calibration Error.")
    brier: float = Field(ge=0.0, le=1.0, description="Brier score (mean squared error).")
    bins: list[Bin] = Field(default_factory=list, description="Reliability-diagram bins.")
