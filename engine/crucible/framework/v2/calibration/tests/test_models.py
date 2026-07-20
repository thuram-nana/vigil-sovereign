"""Tests for calibration.models — schemas and the ground-truth mapping."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from ..models import (
    Bin,
    CalibrationReport,
    Outcome,
    OutcomeLabel,
    Prediction,
    label_to_target,
)


def test_label_to_target_mapping() -> None:
    assert label_to_target(OutcomeLabel.EXPLOITABLE) == 1.0
    assert label_to_target(OutcomeLabel.REMEDIATED) == 1.0
    assert label_to_target(OutcomeLabel.FALSE_POSITIVE) == 0.0
    # DISPUTED is the only excluded label.
    assert label_to_target(OutcomeLabel.DISPUTED) is None


def test_outcome_target_property() -> None:
    assert Outcome(finding_id="f1", label=OutcomeLabel.EXPLOITABLE).target == 1.0
    assert Outcome(finding_id="f2", label=OutcomeLabel.DISPUTED).target is None


def test_prediction_rejects_out_of_range_score() -> None:
    with pytest.raises(ValidationError):
        Prediction(
            finding_id="f1", raw_score=1.5, feature_hash="h",
            model_version="v1", oracle_confirmed=False,
        )


def test_prediction_forbids_extra_fields() -> None:
    with pytest.raises(ValidationError):
        Prediction(
            finding_id="f1", raw_score=0.5, feature_hash="h",
            model_version="v1", oracle_confirmed=False, bogus=1,
        )


def test_prediction_requires_nonempty_ids() -> None:
    with pytest.raises(ValidationError):
        Prediction(
            finding_id="", raw_score=0.5, feature_hash="h",
            model_version="v1", oracle_confirmed=True,
        )


def test_bin_gap() -> None:
    b = Bin(index=0, lower=0.0, upper=0.1, count=4, mean_pred=0.05, mean_actual=0.25)
    assert abs(b.gap - 0.20) < 1e-12


def test_calibration_report_defaults() -> None:
    r = CalibrationReport(n=0, ece=0.0, brier=0.0)
    assert r.bins == []
