"""Tests for calibration.ledger — append-only, deterministic round-trip."""

from __future__ import annotations

import pytest

from ..ledger import LedgerError, OutcomeLedger
from ..models import Outcome, OutcomeLabel, Prediction


def _pred(fid: str, score: float, oracle: bool = False) -> Prediction:
    return Prediction(
        finding_id=fid, raw_score=score, feature_hash=f"h-{fid}",
        model_version="v1", oracle_confirmed=oracle,
    )


def _sample() -> OutcomeLedger:
    led = OutcomeLedger()
    led.add_prediction(_pred("f1", 0.9, oracle=True), seq=1)
    led.add_prediction(_pred("f2", 0.4), seq=2)
    led.add_prediction(_pred("f3", 0.7, oracle=True), seq=3)
    led.record_outcome(Outcome(finding_id="f1", label=OutcomeLabel.EXPLOITABLE), seq=4)
    led.record_outcome(Outcome(finding_id="f2", label=OutcomeLabel.FALSE_POSITIVE), seq=5)
    return led


def test_pairs_returns_only_resolved() -> None:
    led = _sample()
    pairs = led.pairs()
    assert [p.finding_id for p, _o in pairs] == ["f1", "f2"]  # f3 unresolved
    assert led.resolved_count == 2
    assert len(led) == 3


def test_duplicate_prediction_refused() -> None:
    led = OutcomeLedger()
    led.add_prediction(_pred("f1", 0.5), seq=1)
    with pytest.raises(LedgerError):
        led.add_prediction(_pred("f1", 0.6), seq=2)


def test_outcome_for_unknown_finding_refused() -> None:
    led = OutcomeLedger()
    with pytest.raises(LedgerError):
        led.record_outcome(Outcome(finding_id="ghost", label=OutcomeLabel.EXPLOITABLE), seq=1)


def test_double_outcome_refused() -> None:
    led = OutcomeLedger()
    led.add_prediction(_pred("f1", 0.5), seq=1)
    led.record_outcome(Outcome(finding_id="f1", label=OutcomeLabel.EXPLOITABLE), seq=2)
    with pytest.raises(LedgerError):
        led.record_outcome(Outcome(finding_id="f1", label=OutcomeLabel.DISPUTED), seq=3)


def test_json_round_trip_preserves_everything() -> None:
    led = _sample()
    led2 = OutcomeLedger.from_json(led.to_json())
    assert len(led2) == 3
    assert led2.resolved_count == 2
    assert [p.finding_id for p, _o in led2.pairs()] == ["f1", "f2"]
    p1 = led2.pairs()[0][0]
    assert p1.oracle_confirmed is True
    assert p1.raw_score == 0.9


def test_serialisation_is_deterministic_across_insertion_order() -> None:
    a = _sample()
    b = OutcomeLedger()
    # Insert in a different order; seqs define canonical order.
    b.add_prediction(_pred("f3", 0.7, oracle=True), seq=3)
    b.add_prediction(_pred("f2", 0.4), seq=2)
    b.add_prediction(_pred("f1", 0.9, oracle=True), seq=1)
    b.record_outcome(Outcome(finding_id="f2", label=OutcomeLabel.FALSE_POSITIVE), seq=5)
    b.record_outcome(Outcome(finding_id="f1", label=OutcomeLabel.EXPLOITABLE), seq=4)
    assert a.to_json() == b.to_json()


def test_save_and_load(tmp_path) -> None:
    led = _sample()
    p = tmp_path / "sub" / "ledger.json"
    led.save(p)
    assert p.is_file()
    led2 = OutcomeLedger.load(p)
    assert led2.resolved_count == 2


def test_load_missing_file_errors(tmp_path) -> None:
    with pytest.raises(LedgerError):
        OutcomeLedger.load(tmp_path / "nope.json")


def test_from_json_rejects_bad_json() -> None:
    with pytest.raises(LedgerError):
        OutcomeLedger.from_json("{not json")


def test_from_json_rejects_wrong_schema_version() -> None:
    with pytest.raises(LedgerError):
        OutcomeLedger.from_json('{"schema_version": 999, "entries": []}')


def test_from_json_rejects_duplicate_finding() -> None:
    doc = (
        '{"schema_version": 1, "entries": ['
        '{"seq": 1, "prediction": {"finding_id": "f1", "raw_score": 0.5,'
        ' "feature_hash": "h", "model_version": "v1", "oracle_confirmed": false},'
        ' "outcome": null, "outcome_seq": null},'
        '{"seq": 2, "prediction": {"finding_id": "f1", "raw_score": 0.6,'
        ' "feature_hash": "h", "model_version": "v1", "oracle_confirmed": false},'
        ' "outcome": null, "outcome_seq": null}]}'
    )
    with pytest.raises(LedgerError):
        OutcomeLedger.from_json(doc)


def test_from_json_rejects_mismatched_outcome_id() -> None:
    doc = (
        '{"schema_version": 1, "entries": ['
        '{"seq": 1, "prediction": {"finding_id": "f1", "raw_score": 0.5,'
        ' "feature_hash": "h", "model_version": "v1", "oracle_confirmed": false},'
        ' "outcome": {"finding_id": "other", "label": "exploitable"},'
        ' "outcome_seq": 2}]}'
    )
    with pytest.raises(LedgerError):
        OutcomeLedger.from_json(doc)
