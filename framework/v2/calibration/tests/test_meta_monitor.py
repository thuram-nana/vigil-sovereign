"""
Nervous-System N6 — learning about learning.

The meta-monitor reads the outcome ledger and reports whether the LEARNERS are healthy —
enough independent labels, calibrated probabilities, realised coverage — and recommends effort
modulation. It can only make the system MORE cautious (gather evidence / trust confidence less);
it never gates a surface or promotes a finding. The policy provider generalises the bandit's
learned value to order (never gate) any decision.
"""

from __future__ import annotations

from framework.v2.calibration.ledger import OutcomeLedger
from framework.v2.calibration.meta_monitor import (
    BanditPolicyProvider,
    assess_learner_health,
    rank_by_policy,
)
from framework.v2.calibration.models import Outcome, OutcomeLabel, Prediction
from framework.v2.scanner.learning import ContextualBandit


def _led(rows: list[tuple[float, OutcomeLabel]]) -> OutcomeLedger:
    led = OutcomeLedger()
    for i, (score, label) in enumerate(rows):
        fid = f"f#{i}"
        led.add_prediction(Prediction(finding_id=fid, raw_score=score, feature_hash="h",
                                      model_version="v1", oracle_confirmed=True), seq=2 * i)
        led.record_outcome(Outcome(finding_id=fid, label=label), seq=2 * i + 1)
    return led


_E, _F = OutcomeLabel.EXPLOITABLE, OutcomeLabel.FALSE_POSITIVE


def test_sparse_data_recommends_gather_evidence() -> None:
    sig = assess_learner_health(_led([(0.9, _E), (0.1, _F), (0.8, _E)]))
    assert sig.n_labels == 3 and sig.recommend == "gather_evidence"
    assert sig.coverage_realized is None and sig.calibrated is False


def test_well_calibrated_is_ok() -> None:
    rows = [(0.9, _E)] * 5 + [(0.1, _F)] * 5                 # predictions track outcomes
    sig = assess_learner_health(_led(rows))
    assert sig.n_labels == 10 and sig.calibrated and sig.recommend == "ok"


def test_miscalibrated_recommends_trusting_confidence_less() -> None:
    rows = [(0.9, _F)] * 10                                  # confident 0.9 but all false positives
    sig = assess_learner_health(_led(rows))
    assert sig.ece > 0.15 and sig.recommend == "trust_confidence_less"


def test_meta_signal_can_only_make_the_system_more_cautious() -> None:
    for rows in ([(0.9, _F)] * 10, [(0.9, _E)] * 5 + [(0.1, _F)] * 5, [(0.9, _E)]):
        rec = assess_learner_health(_led(rows)).recommend
        assert rec in ("ok", "gather_evidence", "trust_confidence_less")   # never gates/skips


def test_realized_coverage_is_measured_with_enough_data() -> None:
    rows = [(0.9, _E)] * 10 + [(0.1, _F)] * 10               # 20 labels → non-trivial band, measured
    sig = assess_learner_health(_led(rows))
    assert sig.coverage_realized is not None                 # realised coverage measured


def test_realized_coverage_is_none_when_the_band_is_trivial() -> None:
    # 16 labels: the temporal split fits on 8, where alpha=0.1 yields the TRIVIAL [0,1] band
    # (q>=1.0). Coverage is UNMEASURED (None), never a false 1.0 — the N6 review fix that keeps
    # the under-coverage gate honest at the boundary where it first activates.
    rows = [(0.9, _E)] * 8 + [(0.1, _F)] * 8
    sig = assess_learner_health(_led(rows))
    assert sig.n_labels == 16 and sig.coverage_realized is None


# ---- policy provider: orders, never gates -----------------------------------


def test_bandit_policy_provider_orders_without_dropping() -> None:
    b = ContextualBandit()
    b.update("ctx", "hot", True)                             # raise hot's posterior
    b.update("ctx", "cold", False)                           # lower cold's
    prov = BanditPolicyProvider(b)
    assert prov.value("ctx", "hot") > prov.value("ctx", "cold")
    ranked = rank_by_policy("ctx", ["cold", "hot", "mid"], prov)
    assert ranked[0] == "hot" and set(ranked) == {"cold", "hot", "mid"}   # ordered, none dropped
    # no provider → unchanged order (default behaviour, byte-identical)
    assert rank_by_policy("ctx", ["cold", "hot", "mid"], None) == ["cold", "hot", "mid"]
