"""
Nervous-System N2 — the reward fan-out (calibration.reward_bus).

One confirmed-finding outcome fans out to the sinks a caller owns — the check-ordering bandit
(by check productivity), the calibration ledger (by the NON-CIRCULAR corroboration label), and
the event spine (a reward event) — with no sink double-fed. The label rule is single-sourced
here so the critique agent and the bus never drift apart.
"""

from __future__ import annotations

from framework.v2.calibration.ledger import OutcomeLedger
from framework.v2.calibration.models import OutcomeLabel, Prediction
from framework.v2.calibration.reward_bus import credit_outcome, outcome_label
from framework.v2.scanner.learning import ContextualBandit


def test_outcome_label_is_non_circular() -> None:
    assert outcome_label(True, 2) is OutcomeLabel.EXPLOITABLE     # >=2 distinct kinds corroborate
    assert outcome_label(True, 1) is OutcomeLabel.DISPUTED        # a single oracle can't self-certify
    assert outcome_label(True, 5) is OutcomeLabel.EXPLOITABLE
    assert outcome_label(False, 9) is OutcomeLabel.DISPUTED       # a silent oracle is never auto-FP


def test_credit_outcome_updates_the_bandit_by_productivity() -> None:
    b = ContextualBandit()
    before = b.expected_value("ctx", "arm")
    r = credit_outcome(oracle_fired=True, distinct_confirming_kinds=1, seq=1,
                       bandit=b, context="ctx", arm="arm")
    assert "bandit" in r.updated and b.expected_value("ctx", "arm") > before   # a hit raised alpha
    b2 = ContextualBandit()
    credit_outcome(oracle_fired=False, distinct_confirming_kinds=0, seq=2,
                   bandit=b2, context="c", arm="a")
    assert b2.expected_value("c", "a") < 0.5                       # a miss lowered it


def test_credit_outcome_records_a_non_circular_ledger_pair() -> None:
    led = OutcomeLedger()
    pred = Prediction(finding_id="f#1", raw_score=0.9, feature_hash="h",
                      model_version="v1", oracle_confirmed=True)
    r = credit_outcome(oracle_fired=True, distinct_confirming_kinds=2, seq=1,
                       ledger=led, prediction=pred)
    assert "ledger" in r.updated and r.label is OutcomeLabel.EXPLOITABLE
    pairs = led.pairs()
    assert pairs and pairs[0][1].label is OutcomeLabel.EXPLOITABLE
    # single-oracle confirmation → DISPUTED (excluded from calibration), never EXPLOITABLE
    led2 = OutcomeLedger()
    pred2 = Prediction(finding_id="f#2", raw_score=0.9, feature_hash="h",
                       model_version="v1", oracle_confirmed=True)
    r2 = credit_outcome(oracle_fired=True, distinct_confirming_kinds=1, seq=2,
                        ledger=led2, prediction=pred2)
    assert r2.label is OutcomeLabel.DISPUTED


def test_credit_outcome_emits_a_spine_reward_and_only_touches_provided_sinks() -> None:
    class _Sink:
        def __init__(self):
            self.calls = []

        def reward(self, source, reward, **kw):
            self.calls.append((source, reward, kw))

    s = _Sink()
    r = credit_outcome(oracle_fired=True, distinct_confirming_kinds=2, seq=1,
                       spine_sink=s, target_event_id=7, arm="boolean_sqli")
    assert r.updated == ["spine"]                                  # ONLY the spine was touched
    assert s.calls and s.calls[0][0] == "reward-bus" and s.calls[0][1] == 1.0
    assert s.calls[0][2]["signal"] == "corroborated" and s.calls[0][2]["target_event_id"] == 7
