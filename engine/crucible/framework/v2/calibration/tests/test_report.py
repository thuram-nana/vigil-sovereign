"""P2 — the calibration report: deterministic ECE/Brier + reliability bins over labelled outcomes, with the
honesty invariant (calibration re-scores displayed confidence only; it never promotes a lead to a fact)."""
from __future__ import annotations

from framework.v2.calibration.ledger import OutcomeLedger
from framework.v2.calibration.models import Outcome, OutcomeLabel, Prediction
from framework.v2.calibration.report import render_markdown, report_from_ledger, report_from_pairs


def _pair(fid, score, label):
    return (
        Prediction(finding_id=fid, raw_score=score, feature_hash="h", model_version="v1",
                   oracle_confirmed=(label == OutcomeLabel.EXPLOITABLE)),
        Outcome(finding_id=fid, label=label),
    )


def test_calibration_report_is_deterministic_and_honest():
    pairs = [
        _pair("a", 0.9, OutcomeLabel.EXPLOITABLE), _pair("b", 0.8, OutcomeLabel.EXPLOITABLE),
        _pair("c", 0.2, OutcomeLabel.FALSE_POSITIVE), _pair("d", 0.1, OutcomeLabel.FALSE_POSITIVE),
    ]
    r1 = report_from_pairs(pairs)
    assert r1 == report_from_pairs(pairs), "report must be deterministic"
    assert r1["n"] == 4
    assert 0.0 <= r1["ece"] <= 1.0 and 0.0 <= r1["brier"] <= 1.0
    assert len(r1["bins"]) == 10
    assert "never promotes a lead to a fact" in r1["invariant"]
    md = render_markdown(r1)
    assert "Confidence calibration report" in md and "ECE" in md


def test_report_from_ledger_roundtrips_and_absent_is_empty(tmp_path):
    led = OutcomeLedger()
    led.add_prediction(Prediction(finding_id="a", raw_score=0.9, feature_hash="h", model_version="v1",
                                  oracle_confirmed=True), seq=0)
    led.record_outcome(Outcome(finding_id="a", label=OutcomeLabel.EXPLOITABLE), seq=1)
    p = tmp_path / "led.json"
    led.save(p)
    assert report_from_ledger(p)["n"] == 1
    assert report_from_ledger(tmp_path / "does-not-exist.json")["n"] == 0  # honest empty, never an error
