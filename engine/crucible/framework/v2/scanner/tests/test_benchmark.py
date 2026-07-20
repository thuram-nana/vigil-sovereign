"""
scanner.benchmark — the honest "is it any good" number.

The harness stands a labelled, deliberately-vulnerable app up on loopback, runs a
real WebScanCampaign against it, and scores the oracle-confirmed findings against
the ground-truth manifest. The two properties that matter:

  * RECALL — the scanner confirms the seeded, oracle-observable bugs (boolean
    SQLi, reflected XSS, IDOR) at or above a real threshold.
  * PRECISION — it confirms NOTHING on the manifest's SAFE parameters. This is
    the oracle anchor's whole promise: a finding exists only when a
    deterministic oracle fired, so the false-positive rate on non-bugs is zero.

Everything is deterministic and loopback-only.
"""

from __future__ import annotations

from framework.v2.scanner.benchmark import (
    GROUND_TRUTH,
    BenchmarkReport,
    run_benchmark,
)
from framework.v2.scanner.insertion import InsertionKind


def test_benchmark_scores_recall_and_zero_false_positives() -> None:
    report = run_benchmark()

    assert isinstance(report, BenchmarkReport)

    # RECALL: the seeded, oracle-confirmable bugs are found. Three are planted
    # (SQLi, XSS, IDOR); require a real detection rate, not a token one.
    assert report.recall >= 0.66, f"recall too low: {report.recall} ({report.confirmed})"
    assert report.true_positives >= 2

    # PRECISION (the oracle-anchored property): zero findings on SAFE params,
    # and therefore no false positives anywhere in the confusion matrix.
    assert report.safe_param_hits == [], f"flagged a SAFE parameter: {report.safe_param_hits}"
    assert report.false_positives == 0, f"false positives: {report.false_positive_pairs}"
    assert report.precision == 1.0


def test_benchmark_confirms_each_planted_class() -> None:
    report = run_benchmark()
    confirmed = {(m.bug_class, m.param) for m in report.confirmed}

    # Each distinct oracle route lands its own class on its own parameter.
    assert ("boolean_sqli", "term") in confirmed      # differential oracle
    assert ("xss", "bio") in confirmed                # side-effect oracle
    assert ("idor", "docid") in confirmed             # achieved-state oracle

    # per-class breakdown agrees and shows no class-level false positives.
    for bc in ("boolean_sqli", "xss", "idor"):
        assert report.per_class[bc].true_positives == 1
        assert report.per_class[bc].false_positives == 0


def test_manifest_safe_params_are_never_in_expected_set() -> None:
    # Sanity on the manifest itself: the SAFE controls and the planted vulns are
    # disjoint by parameter, so a SAFE hit is unambiguously a false positive.
    vuln_params = {v.param for v in GROUND_TRUTH.vulns}
    assert vuln_params.isdisjoint(GROUND_TRUTH.safe_params)


def test_custom_campaign_factory_is_used() -> None:
    # A caller may inject their own campaign (narrower check set). Here we scope
    # it to only the reflected-XSS check, so the report should confirm exactly
    # that class and score the other two planted bugs as false negatives.
    from framework.v2.scanner.campaign import WebScanCampaign
    from framework.v2.scanner.checks import REFLECTED_XSS

    def factory(send):  # type: ignore[no-untyped-def]
        return WebScanCampaign(
            send, checks=(REFLECTED_XSS,),
            insertion_kinds=(InsertionKind.QUERY_VALUE,), enable_oob=False,
        )

    report = run_benchmark(factory)
    confirmed = {(m.bug_class, m.param) for m in report.confirmed}
    assert confirmed == {("xss", "bio")}
    # still zero false positives — the XSS-only sweep must not trip a SAFE param
    assert report.false_positives == 0
    # the two un-probed classes are honest false negatives
    assert report.false_negatives == 2
