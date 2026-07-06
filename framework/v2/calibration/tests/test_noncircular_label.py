"""
Wave 3 — the calibration ground truth is no longer circular.

The audit's silent hole: the critique-agent labelled every oracle-confirmed
finding EXPLOITABLE and fed the same oracle's confidence in as the prediction, so
the learned `oracle_prior` collapsed to ~1.0 — the calibrator certifying the
oracle against itself. With the fix, resolved labels come from an INDEPENDENT
adjudicator, and the prior reflects the real exploitable-rate.

These tests exercise the calibrator on both the honest (independent) data and the
old circular data, to pin the difference the fix makes.
"""

from __future__ import annotations

from framework.v2.calibration.calibrate import fit
from framework.v2.calibration.ledger import OutcomeLedger
from framework.v2.calibration.models import Outcome, OutcomeLabel, Prediction


def _ledger(labels: list[OutcomeLabel]) -> OutcomeLedger:
    led = OutcomeLedger()
    for i, label in enumerate(labels):
        led.add_prediction(
            Prediction(finding_id=f"f{i}", raw_score=0.9, feature_hash="h",
                       model_version="v", oracle_confirmed=True),
            seq=2 * i,
        )
        led.record_outcome(Outcome(finding_id=f"f{i}", label=label), seq=2 * i + 1)
    return led


def test_independent_adjudication_gives_prior_below_one() -> None:
    # 8 oracle-confirmed findings; an INDEPENDENT adjudicator found 3 were false
    # positives — the thing the old circular label could never represent.
    labels = [OutcomeLabel.FALSE_POSITIVE] * 3 + [OutcomeLabel.EXPLOITABLE] * 5
    cal = fit(_ledger(labels).pairs())
    assert cal.oracle_prior is not None
    assert cal.oracle_prior < 1.0
    assert abs(cal.oracle_prior - 5 / 8) < 1e-9  # the true exploitable-rate


def test_circular_labeling_would_have_yielded_a_vacuous_prior() -> None:
    # The old behaviour: EXPLOITABLE for every oracle-confirmed finding. This is
    # exactly the vacuous prior the fix avoids — documented here as the contrast.
    cal = fit(_ledger([OutcomeLabel.EXPLOITABLE] * 8).pairs())
    assert cal.oracle_prior == 1.0


def test_disputed_labels_are_excluded_from_the_fit() -> None:
    # The autonomous path now abstains (DISPUTED) rather than fabricate a label;
    # DISPUTED contributes no target, so a ledger of only-abstentions trains
    # nothing (identity fallback) — honest, not overconfident.
    cal = fit(_ledger([OutcomeLabel.DISPUTED] * 12).pairs())
    assert cal.oracle_prior is None or cal.method == "identity"
