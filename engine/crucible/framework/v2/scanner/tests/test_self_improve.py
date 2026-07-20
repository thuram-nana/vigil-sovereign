"""
scanner.self_improve — gap mining + gated capability proposals.

These tests exercise real behaviour, not fixtures shaped to pass:

  * a routed bug_class with NO producing check surfaces a MISSING_CHECK gap and
    a proposal that targets it with the oracle_kind the verify layer *actually*
    routes that class to (asserted against the live BUG_CLASS_ORACLES table);
  * a class that HAS a check but shows zero recall in a real BenchmarkReport
    surfaces a LOW_RECALL gap;
  * a class whose OutcomeLedger findings mostly resolved false-positive surfaces
    a LOW_CONFIRM_RATE gap (and a well-behaved class does NOT);
  * the MergeGate REJECTS without approvals / with a red eval and APPROVES only
    with eval-green + enough approvals;
  * the module exposes NO apply()/writer — proposals are never auto-applied.
"""

from __future__ import annotations

import pytest

from framework.v2.calibration.ledger import OutcomeLedger
from framework.v2.calibration.models import Outcome, OutcomeLabel, Prediction
from framework.v2.scanner import self_improve as si
from framework.v2.scanner.benchmark import BenchmarkReport, ClassScore
from framework.v2.scanner.checks import BOOLEAN_SQLI, DEFAULT_CHECKS
from framework.v2.verify import BUG_CLASS_ORACLES, OracleKind


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


def _prediction(fid: str, *, oracle_confirmed: bool = True) -> Prediction:
    return Prediction(
        finding_id=fid,
        raw_score=0.8,
        feature_hash="fh",
        model_version="v0",
        oracle_confirmed=oracle_confirmed,
    )


def _seeded_ledger(rows: list[tuple[str, OutcomeLabel]]) -> OutcomeLedger:
    """Build a ledger from (finding_id, label) rows with a monotonic seq."""
    ledger = OutcomeLedger()
    seq = 0
    for fid, label in rows:
        ledger.add_prediction(_prediction(fid), seq=seq)
        seq += 1
    for fid, label in rows:
        ledger.record_outcome(Outcome(finding_id=fid, label=label), seq=seq)
        seq += 1
    return ledger


# ---------------------------------------------------------------------------
# missing-check gaps (structural coverage holes)
# ---------------------------------------------------------------------------


def test_missing_check_gap_targets_idor_with_achieved_state():
    # DEFAULT_CHECKS has no IDOR producer, yet the verifier routes idor to
    # ACHIEVED_STATE — so it must surface as a structural gap.
    gaps = si.analyze_gaps(checks=DEFAULT_CHECKS)
    by_class = {g.bug_class: g for g in gaps}

    assert "idor" in by_class, "idor is routed but unproduced -> must be a gap"
    idor = by_class["idor"]
    assert idor.source is si.GapSource.MISSING_CHECK
    # the gap copies the verifier's OWN routing, not an invented oracle.
    assert idor.oracle_kinds == list(BUG_CLASS_ORACLES["idor"])
    assert OracleKind.ACHIEVED_STATE in idor.oracle_kinds
    assert idor.metric is None  # structural, not empirical

    proposals = si.draft_proposals(gaps)
    prop = next(p for p in proposals if p.bug_class == "idor")
    assert prop.oracle_kind is OracleKind.ACHIEVED_STATE
    assert prop.gap_id == idor.id
    assert prop.executable is False
    assert prop.status == "draft"
    assert "{" in prop.payload_template_skeleton or "victim" in prop.payload_template_skeleton


def test_a_produced_class_is_not_a_missing_check_gap():
    # boolean_sqli IS produced by DEFAULT_CHECKS -> never a MISSING_CHECK gap.
    gaps = si.analyze_gaps(checks=DEFAULT_CHECKS)
    missing = {g.bug_class for g in gaps if g.source is si.GapSource.MISSING_CHECK}
    assert "boolean_sqli" not in missing
    assert "xss" not in missing


def test_every_missing_gap_is_actually_unproduced_and_routed():
    checks = DEFAULT_CHECKS
    produced = {c.bug_class for c in checks}
    gaps = si.analyze_gaps(checks=checks)
    for g in (x for x in gaps if x.source is si.GapSource.MISSING_CHECK):
        assert g.bug_class not in produced
        assert g.bug_class in BUG_CLASS_ORACLES
        assert len(g.oracle_kinds) >= 1


# ---------------------------------------------------------------------------
# low-recall gaps (empirical: a check exists but the benchmark misses it)
# ---------------------------------------------------------------------------


def _report_with(per_class: dict[str, ClassScore]) -> BenchmarkReport:
    return BenchmarkReport(
        true_positives=0, false_positives=0, false_negatives=0,
        precision=1.0, recall=0.0, f1=0.0, per_class=per_class,
    )


def test_zero_recall_produced_class_yields_low_recall_gap():
    # boolean_sqli has a producing check, so a zero-recall benchmark result is a
    # genuine LOW_RECALL gap (not a missing-check one).
    report = _report_with(
        {"boolean_sqli": ClassScore(
            bug_class="boolean_sqli", true_positives=0, false_negatives=1)}
    )
    gaps = si.analyze_gaps(benchmark_report=report, checks=DEFAULT_CHECKS)
    low = [g for g in gaps if g.source is si.GapSource.LOW_RECALL]
    assert any(g.bug_class == "boolean_sqli" for g in low)
    gap = next(g for g in low if g.bug_class == "boolean_sqli")
    assert gap.metric == 0.0
    assert gap.oracle_kinds == list(BUG_CLASS_ORACLES["boolean_sqli"])

    prop = next(p for p in si.draft_proposals(gaps) if p.gap_id == gap.id)
    # the proposal targets the class's PRIMARY oracle, which for boolean_sqli is
    # now the SPRT boolean-inference oracle (Wave 5), with the 2-probe
    # differential as the fallback.
    assert prop.oracle_kind is OracleKind.BOOLEAN_INFERENCE


def test_full_recall_class_yields_no_low_recall_gap():
    report = _report_with(
        {"boolean_sqli": ClassScore(
            bug_class="boolean_sqli", true_positives=1, false_negatives=0)}
    )
    gaps = si.analyze_gaps(benchmark_report=report, checks=DEFAULT_CHECKS)
    assert not any(
        g.source is si.GapSource.LOW_RECALL and g.bug_class == "boolean_sqli"
        for g in gaps
    )


def test_unproduced_class_low_recall_is_not_double_counted():
    # idor has no check: a zero-recall benchmark row must NOT add a second
    # (LOW_RECALL) gap on top of the MISSING_CHECK one.
    report = _report_with(
        {"idor": ClassScore(bug_class="idor", true_positives=0, false_negatives=1)}
    )
    gaps = si.analyze_gaps(benchmark_report=report, checks=DEFAULT_CHECKS)
    idor_gaps = [g for g in gaps if g.bug_class == "idor"]
    assert len(idor_gaps) == 1
    assert idor_gaps[0].source is si.GapSource.MISSING_CHECK


# ---------------------------------------------------------------------------
# low-confirm-rate gaps (empirical: findings resolve mostly false-positive)
# ---------------------------------------------------------------------------


def test_low_confirm_rate_class_yields_gap():
    # 4 boolean_sqli findings resolved: 1 exploitable, 3 false-positive -> 25%.
    rows = [
        ("bsqli-1", OutcomeLabel.EXPLOITABLE),
        ("bsqli-2", OutcomeLabel.FALSE_POSITIVE),
        ("bsqli-3", OutcomeLabel.FALSE_POSITIVE),
        ("bsqli-4", OutcomeLabel.FALSE_POSITIVE),
    ]
    ledger = _seeded_ledger(rows)
    mapping = {fid: "boolean_sqli" for fid, _ in rows}

    gaps = si.analyze_gaps(ledger=ledger, ledger_bug_classes=mapping, checks=DEFAULT_CHECKS)
    low = [g for g in gaps if g.source is si.GapSource.LOW_CONFIRM_RATE]
    assert any(g.bug_class == "boolean_sqli" for g in low)
    gap = next(g for g in low if g.bug_class == "boolean_sqli")
    assert gap.metric == pytest.approx(0.25)


def test_healthy_confirm_rate_no_gap_and_disputed_excluded():
    # 3 exploitable, 1 disputed (excluded) -> confirm-rate over resolved = 3/3.
    rows = [
        ("ok-1", OutcomeLabel.EXPLOITABLE),
        ("ok-2", OutcomeLabel.EXPLOITABLE),
        ("ok-3", OutcomeLabel.REMEDIATED),
        ("ok-4", OutcomeLabel.DISPUTED),
    ]
    ledger = _seeded_ledger(rows)
    mapping = {fid: "boolean_sqli" for fid, _ in rows}
    gaps = si.analyze_gaps(ledger=ledger, ledger_bug_classes=mapping, checks=DEFAULT_CHECKS)
    assert not any(
        g.source is si.GapSource.LOW_CONFIRM_RATE and g.bug_class == "boolean_sqli"
        for g in gaps
    )


def test_ledger_below_min_samples_is_not_flagged():
    rows = [("t-1", OutcomeLabel.FALSE_POSITIVE), ("t-2", OutcomeLabel.FALSE_POSITIVE)]
    ledger = _seeded_ledger(rows)
    mapping = {fid: "boolean_sqli" for fid, _ in rows}
    gaps = si.analyze_gaps(
        ledger=ledger, ledger_bug_classes=mapping, checks=DEFAULT_CHECKS,
        min_ledger_samples=3,
    )
    assert not any(g.source is si.GapSource.LOW_CONFIRM_RATE for g in gaps)


def test_ledger_ignored_without_bug_class_mapping():
    # Without a finding_id -> bug_class map, the ledger cannot be mined per class
    # (Prediction carries no bug_class); we must NOT invent one.
    rows = [("x-1", OutcomeLabel.FALSE_POSITIVE)] * 1
    ledger = _seeded_ledger([("x-1", OutcomeLabel.FALSE_POSITIVE)])
    gaps = si.analyze_gaps(ledger=ledger, checks=DEFAULT_CHECKS)
    assert not any(g.source is si.GapSource.LOW_CONFIRM_RATE for g in gaps)


# ---------------------------------------------------------------------------
# determinism & ordering
# ---------------------------------------------------------------------------


def test_analyze_gaps_is_deterministic_and_priority_sorted():
    a = si.analyze_gaps(checks=DEFAULT_CHECKS)
    b = si.analyze_gaps(checks=DEFAULT_CHECKS)
    assert [g.id for g in a] == [g.id for g in b]
    priorities = [g.priority for g in a]
    assert priorities == sorted(priorities, reverse=True)


def test_draft_proposals_preserve_gap_order():
    gaps = si.analyze_gaps(checks=DEFAULT_CHECKS)
    proposals = si.draft_proposals(gaps)
    assert [p.gap_id for p in proposals] == [g.id for g in gaps]


# ---------------------------------------------------------------------------
# merge gate — governance control (authorise, never apply)
# ---------------------------------------------------------------------------


def _one_proposal() -> si.CapabilityProposal:
    gaps = si.analyze_gaps(checks=DEFAULT_CHECKS)
    return si.draft_proposals(gaps)[0]


def test_gate_rejects_without_approvals():
    gate = si.MergeGate()
    d = gate.evaluate(_one_proposal(), eval_green=True, approvals=0, threshold=2)
    assert d.approved is False
    assert d.verdict is si.Verdict.REJECTED
    assert "approvals" in d.reason


def test_gate_rejects_on_red_eval_even_with_approvals():
    gate = si.MergeGate()
    d = gate.evaluate(_one_proposal(), eval_green=False, approvals=5, threshold=2)
    assert d.approved is False
    assert "eval red" in d.reason


def test_gate_approves_only_with_green_eval_and_enough_approvals():
    gate = si.MergeGate()
    prop = _one_proposal()
    assert gate.evaluate(prop, eval_green=True, approvals=1, threshold=2).approved is False
    d = gate.evaluate(prop, eval_green=True, approvals=2, threshold=2)
    assert d.approved is True
    assert d.verdict is si.Verdict.APPROVED
    assert d.proposal_id == prop.id


def test_gate_rejects_zero_threshold_as_governance_hole():
    gate = si.MergeGate()
    with pytest.raises(ValueError):
        gate.evaluate(_one_proposal(), eval_green=True, approvals=0, threshold=0)


# ---------------------------------------------------------------------------
# the never-self-applied invariant
# ---------------------------------------------------------------------------


def test_module_exposes_no_apply_or_writer():
    # The whole point: this loop proposes, it never self-modifies. There must be
    # no function that applies a proposal or writes check code.
    forbidden = (
        "apply", "apply_proposal", "self_apply", "write_check", "install",
        "install_check", "commit", "merge", "deploy", "patch", "mutate",
    )
    for name in forbidden:
        assert not hasattr(si, name), f"self_improve must not expose {name}()"
    # the gate authorises but does not apply
    assert not hasattr(si.MergeGate, "apply")
    assert si.SELF_APPLY is False
    # every proposal is a spec, never executable
    for p in si.draft_proposals(si.analyze_gaps(checks=DEFAULT_CHECKS)):
        assert p.executable is False


def test_narrowing_the_check_set_widens_the_gap_set():
    # Real behaviour: fewer producers -> more structural gaps. Passing only the
    # boolean-SQLi check must surface xss (routed, now unproduced) as a gap.
    few = si.analyze_gaps(checks=(BOOLEAN_SQLI,))
    all_checks = si.analyze_gaps(checks=DEFAULT_CHECKS)
    few_classes = {g.bug_class for g in few if g.source is si.GapSource.MISSING_CHECK}
    all_classes = {g.bug_class for g in all_checks if g.source is si.GapSource.MISSING_CHECK}
    assert "xss" in few_classes
    assert "xss" not in all_classes
    assert all_classes < few_classes
