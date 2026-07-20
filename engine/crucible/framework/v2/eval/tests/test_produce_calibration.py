"""Tests for eval.produce's calibrated-confidence path.

The unit under test: a critique-CONFIRMED finding used to carry a hardcoded
`1.0` confidence. `map_finding`/`map_findings` now accept an optional
calibrator (a fitted `calibration.Calibrator` or an `OutcomeLedger` to fit one
from). When supplied, the produced confidence is a probability *learned from
recorded outcomes* — never a hardcoded certainty. When omitted, the legacy
naive table is preserved verbatim for backward compatibility.

These tests prove all three behaviors:
  1. fitted calibrator  -> confirmed confidence == the calibrated value, < 1.0.
  2. no calibrator      -> legacy backward-compat value; identity (sparse)
                           calibrator -> the honest 0.9 prior, never 1.0.
  3. verified_by_oracle -> the learned oracle prior raises the confidence.
"""

from __future__ import annotations

from ...agents.models import FindingPayload
from ...calibration import (
    OutcomeLabel,
    Outcome,
    OutcomeLedger,
    Prediction,
    fit,
)
from ..produce import map_finding, map_findings


def _finding(status: str = "confirmed", *, oracle: bool = False, **kw: object) -> FindingPayload:
    base = dict(
        finding_slug="001-idor",
        title="IDOR on orders",
        severity="High",
        bug_class="IDOR",
        surface="/api/orders/{id}",
        summary="Any user can read any order",
        critique_status=status,
        verified_by_oracle=oracle,
    )
    base.update(kw)
    return FindingPayload.model_validate(base)


# A deliberately skewed synthetic outcome set: many high-scoring findings
# (including oracle-confirmed ones) turned out to be false positives, so an
# honest calibrator must map the top raw score well below 1.0, and must learn
# a *modest* oracle prior rather than inheriting the old certainty.
_SKEWED = [
    # (finding_id, raw_score, oracle_confirmed, label)
    ("a", 0.9, True, OutcomeLabel.EXPLOITABLE),
    ("b", 0.9, True, OutcomeLabel.FALSE_POSITIVE),
    ("c", 0.9, True, OutcomeLabel.FALSE_POSITIVE),
    ("d", 0.9, False, OutcomeLabel.FALSE_POSITIVE),
    ("e", 0.8, False, OutcomeLabel.EXPLOITABLE),
    ("f", 0.7, False, OutcomeLabel.FALSE_POSITIVE),
    ("g", 0.5, False, OutcomeLabel.EXPLOITABLE),
    ("h", 0.3, False, OutcomeLabel.FALSE_POSITIVE),
    ("i", 0.1, False, OutcomeLabel.FALSE_POSITIVE),
]


def _skewed_ledger() -> OutcomeLedger:
    ledger = OutcomeLedger()
    for i, (fid, raw, oracle, label) in enumerate(_SKEWED):
        ledger.add_prediction(
            Prediction(
                finding_id=fid,
                raw_score=raw,
                feature_hash="h",
                model_version="v1",
                oracle_confirmed=oracle,
            ),
            seq=i,
        )
        ledger.record_outcome(Outcome(finding_id=fid, label=label), seq=100 + i)
    return ledger


# --- 1. fitted calibrator: confirmed confidence is learned, and < 1.0 --------


def test_confirmed_confidence_is_calibrated_not_one() -> None:
    cal = fit(_skewed_ledger().pairs())
    assert cal.method == "isotonic"  # enough data to actually calibrate

    pf = map_finding(_finding("confirmed"), calibrator=cal)

    # The confidence is the calibrated probability for the honest 0.9 prior,
    # NOT the old hardcoded 1.0.
    assert pf.confidence == cal.calibrate(0.9, oracle_confirmed=False)
    assert pf.confidence < 1.0


def test_ledger_is_accepted_and_fit_on_the_spot() -> None:
    ledger = _skewed_ledger()
    cal = fit(ledger.pairs())

    # Passing the ledger itself must yield the same result as passing a fitted
    # calibrator — produce fits it internally.
    via_ledger = map_finding(_finding("confirmed"), calibrator=ledger).confidence
    via_cal = map_finding(_finding("confirmed"), calibrator=cal).confidence
    assert via_ledger == via_cal
    assert via_ledger < 1.0


# --- 2. no calibrator -> backward compat; identity -> honest prior -----------


def test_no_calibrator_uses_honest_prior_never_one() -> None:
    # No map_finding path emits a false certainty of 1.0: the bare (no-calibrator)
    # "confirmed" confidence is the honest 0.9 prior, not 1.0 (audit fix).
    assert map_finding(_finding("confirmed")).confidence == 0.9
    assert map_finding(_finding("confirmed")).confidence < 1.0
    assert map_finding(_finding("pending")).confidence == 0.6
    assert map_finding(_finding("objections")).confidence == 0.2


def test_identity_calibrator_uses_honest_prior_never_one() -> None:
    # Too few labelled outcomes to calibrate honestly -> identity calibrator.
    sparse = fit(_skewed_ledger().pairs()[:4])
    assert sparse.method == "identity"

    pf = map_finding(_finding("confirmed"), calibrator=sparse)
    # Even an unfitted calibrator refuses to re-emit a false 1.0: it passes the
    # honest 0.9 "confirmation is not certainty" prior straight through.
    assert pf.confidence == 0.9
    assert pf.confidence < 1.0


# --- 3. verified_by_oracle raises the (still learned, still < 1.0) prior ------


def test_oracle_confirmation_raises_but_does_not_pin_confidence() -> None:
    cal = fit(_skewed_ledger().pairs())
    assert cal.oracle_prior is not None  # a prior was actually learned

    plain = map_finding(_finding("confirmed", oracle=False), calibrator=cal)
    oracle = map_finding(_finding("confirmed", oracle=True), calibrator=cal)

    # Oracle confirmation contributes a learned prior via noisy-OR: strictly
    # higher than the non-oracle finding, but still short of certainty.
    assert oracle.confidence > plain.confidence
    assert oracle.confidence < 1.0
    assert oracle.confidence == cal.calibrate(0.9, oracle_confirmed=True)


# --- map_findings applies the calibrator to every mapped finding -------------


def test_map_findings_applies_calibrator_to_each() -> None:
    cal = fit(_skewed_ledger().pairs())
    findings = [_finding("confirmed"), _finding("confirmed", finding_slug="002")]

    produced = map_findings(findings, calibrator=cal)
    expected = cal.calibrate(0.9, oracle_confirmed=False)
    assert len(produced) == 2
    assert all(pf.confidence == expected for pf in produced)
    assert all(pf.confidence < 1.0 for pf in produced)


def test_map_findings_without_calibrator_is_backward_compatible() -> None:
    findings = [_finding("confirmed"), _finding("pending")]
    # Default confirmed_only filter + legacy confidence, both unchanged.
    produced = map_findings(findings)
    assert len(produced) == 1
    # Honest prior, never a false 1.0 (audit fix); calibrator learns the real value.
    assert produced[0].confidence == 0.9
