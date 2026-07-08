"""
calibration — calibrated exploitability scoring + the outcome ledger.

The audit this layer answers: a "confirmed" finding used to carry a hardcoded
`1.0` confidence, and nothing measured whether that number was honest. This
layer replaces the constant with a probability *learned from recorded
outcomes*, and measures its own reliability.

The pipeline:

    score a finding        -> Prediction (raw_score, oracle_confirmed, ...)
    write it               -> OutcomeLedger.add_prediction(pred, seq=...)
    resolve it later       -> OutcomeLedger.record_outcome(Outcome(...), seq=...)
    fit the mapping        -> cal = fit(ledger.pairs())
    apply it               -> p = cal.calibrate(raw_score, oracle_confirmed)
    measure reliability    -> reliability_report(ledger.pairs(), cal)

Three disciplines make it honest:

- **Learned, never hardcoded.** The calibrated number — including the boost an
  oracle-confirmed finding gets — is fit from outcomes via isotonic regression
  (pure-Python PAV). Nothing returns 1.0; probabilities clamp to MAX_PROB.
- **Identity fallback.** Under fewer than MIN_LABELS outcomes there is no
  honest calibration, so the fit degrades to a passthrough that says so.
- **Deterministic.** The ledger orders by a caller-supplied sequence int, not
  a wallclock, so every fit and metric is byte-stable and replayable.

Public surface (import from here, not from submodules):

    from framework.v2.calibration import (
        OutcomeLabel, Prediction, Outcome, Bin, CalibrationReport,
        label_to_target,
        OutcomeLedger, LedgerEntry, LedgerError,
        Calibrator, fit, calibrate as fit_calibrator,
        pav, brier_score, measure_ece, reliability_report,
        MIN_LABELS, MIN_ORACLE_LABELS, MAX_PROB,
    )
"""

from __future__ import annotations

from .calibrate import (
    MAX_PROB,
    MIN_LABELS,
    MIN_ORACLE_LABELS,
    Calibrator,
    brier_score,
    fit,
    measure_ece,
    pav,
    reliability_report,
)
from .conformal import ConformalBand, band_for_prediction, conformal_band, conformal_halfwidth
from .ledger import LedgerEntry, LedgerError, OutcomeLedger
from .models import (
    Bin,
    CalibrationReport,
    Outcome,
    OutcomeLabel,
    Prediction,
    label_to_target,
)

__all__ = [
    # models
    "OutcomeLabel",
    "Prediction",
    "Outcome",
    "Bin",
    "CalibrationReport",
    "label_to_target",
    # ledger
    "OutcomeLedger",
    "LedgerEntry",
    "LedgerError",
    # calibrate
    "Calibrator",
    "fit",
    "pav",
    "brier_score",
    "measure_ece",
    "reliability_report",
    "MIN_LABELS",
    "MIN_ORACLE_LABELS",
    "MAX_PROB",
    # conformal
    "ConformalBand",
    "conformal_band",
    "conformal_halfwidth",
    "band_for_prediction",
]
