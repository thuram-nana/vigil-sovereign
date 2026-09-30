"""
memory.fleet.FleetRollup — the VERDICT-PRESERVING cross-engagement result roll-up.

The hard invariant: aggregation never launders a verdict. These tests exercise a roll-up over
engagements whose verdicts span {FACT, LEAD, INCONCLUSIVE, CLEAN} and assert each is preserved
in the aggregate:

  * INCONCLUSIVE never rounds up to CLEAN (inconclusive dominates clean in the fleet join);
  * CLEAN aggregates ONLY from real per-engagement CLEANs, and "not assessed" never becomes
    clean (the coverage certificate's bounds are preserved);
  * LEAD never rounds up to FACT (a coverage-axis "finding" verdict is NOT a finding-axis FACT;
    an ungrounded / passive lead is never a fact);
  * FACT counts only from a real per-engagement FACT with its certificate; a reverifiable fact
    is RE-EXECUTED, so a tampered cert is a failure, never a fact.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from framework.v2.memory.fleet import FleetError, FleetRollup
from framework.v2.verify.adapter import FindingContext
from framework.v2.verify.confirmation import confirm_finding

# ---------------------------------------------------------------------------
# synthetic report.json docs (the scanner.report.build_report shape)
# ---------------------------------------------------------------------------


def _report(*, target, verdicts, exercised, inconclusive, corpus_wide, findings):
    return {
        "tool": "CRUCIBLE",
        "target": target,
        "summary": {"by_grounding": {}},
        "verdict_by_class": verdicts,
        "coverage_verdict": {
            "corpus_classes": len(exercised) + len(inconclusive),
            "classes_exercised": exercised,
            "classes_inconclusive": inconclusive,
            "clean_is_corpus_wide": corpus_wide,
        },
        "findings": findings,
    }


def _active(bug_class, grounding, *, check_id=""):
    return {"kind": "active", "bug_class": bug_class, "grounding": grounding, "check_id": check_id}


def _passive(bug_class):
    return {"kind": "passive", "bug_class": bug_class, "grounding": "unclassified", "check_id": ""}


# ---------------------------------------------------------------------------
# (1) all four verdict classes are preserved; nothing is laundered
# ---------------------------------------------------------------------------


def test_all_verdict_classes_preserved_no_laundering() -> None:
    roll = FleetRollup()
    # Engagement A: xss CLEAN, boolean_sqli FINDING (with a real FACT), ssti INCONCLUSIVE,
    # open_redirect FINDING-in-coverage but its finding is an ungrounded LEAD, plus a passive LEAD.
    roll.add_report(_report(
        target="http://a.example",
        verdicts={"xss": "clean", "boolean_sqli": "finding", "ssti": "inconclusive",
                  "open_redirect": "finding"},
        exercised=["boolean_sqli", "open_redirect", "xss"],
        inconclusive=["ssti"],
        corpus_wide=False,
        findings=[
            _active("boolean_sqli", "fact", check_id="sqli-1"),   # FACT (cert-backed)
            _active("open_redirect", "ungrounded"),               # LEAD (coverage says finding)
            _passive("passive:missing-header"),                   # LEAD
        ],
    ))
    # Engagement B: xss CLEAN again, but ssti CLEAN here — the join with A's inconclusive must
    # stay INCONCLUSIVE (the sharpest inconclusive->clean laundering vector).
    roll.add_report(_report(
        target="http://b.example",
        verdicts={"xss": "clean", "ssti": "clean"},
        exercised=["ssti", "xss"],
        inconclusive=[],
        corpus_wide=False,
        findings=[_active("xss", "unclassified")],   # an active lead
    ))

    out = roll.to_rollup_dict()
    vbc = out["verdict_by_class"]
    bounds = out["coverage_bounds"]

    # CLEAN survives only where BOTH engagements were clean.
    assert vbc["xss"] == "clean"
    assert bounds["classes_clean"] == ["xss"]
    # INCONCLUSIVE is preserved, NOT laundered to clean despite B's clean ssti.
    assert vbc["ssti"] == "inconclusive"
    assert "ssti" not in bounds["classes_clean"]
    assert "ssti" in bounds["classes_inconclusive"]
    # FINDING (coverage axis) preserved.
    assert vbc["boolean_sqli"] == "finding"
    assert vbc["open_redirect"] == "finding"
    assert set(bounds["classes_finding"]) == {"boolean_sqli", "open_redirect"}

    # FACT axis: exactly ONE real fact (boolean_sqli). open_redirect is a coverage "finding" but
    # its finding is ungrounded — it must NOT be laundered into a fact.
    assert out["facts"]["by_class"] == {"boolean_sqli": 1}
    assert out["facts"]["count"] == 1
    assert "open_redirect" not in out["facts"]["by_class"]

    # LEAD axis: the ungrounded active + the passive + B's unclassified active = 3 leads.
    assert out["leads"]["count"] == 3
    assert out["leads"]["by_bucket"]["active:ungrounded"] == 1
    assert out["leads"]["by_bucket"]["passive"] == 1

    # fleet is NOT corpus-wide clean (findings + inconclusive present).
    assert bounds["clean_is_corpus_wide"] is False


# ---------------------------------------------------------------------------
# (2) CLEAN aggregates ONLY from real per-engagement cleans
# ---------------------------------------------------------------------------


def test_clean_only_from_unanimous_cleans() -> None:
    roll = FleetRollup()
    for t in ("http://a", "http://b"):
        roll.add_report(_report(
            target=t, verdicts={"xss": "clean"}, exercised=["xss"], inconclusive=[],
            corpus_wide=True, findings=[]))
    assert roll.to_rollup_dict()["verdict_by_class"]["xss"] == "clean"

    # one more engagement leaves xss inconclusive → the whole-fleet verdict drops to inconclusive.
    roll.add_report(_report(
        target="http://c", verdicts={"xss": "inconclusive"}, exercised=[], inconclusive=["xss"],
        corpus_wide=False, findings=[]))
    out = roll.to_rollup_dict()
    assert out["verdict_by_class"]["xss"] == "inconclusive"
    assert "xss" not in out["coverage_bounds"]["classes_clean"]


def test_corpus_wide_clean_requires_every_engagement_and_zero_inconclusive() -> None:
    # two engagements, each corpus-wide clean over its own corpus, disjoint clean classes.
    roll = FleetRollup()
    roll.add_report(_report(target="http://a", verdicts={"xss": "clean"}, exercised=["xss"],
                            inconclusive=[], corpus_wide=True, findings=[]))
    roll.add_report(_report(target="http://b", verdicts={"cors": "clean"}, exercised=["cors"],
                            inconclusive=[], corpus_wide=True, findings=[]))
    assert roll.to_rollup_dict()["coverage_bounds"]["clean_is_corpus_wide"] is True

    # add a NOT-corpus-wide engagement carrying an inconclusive class → fleet clean-wide drops,
    # and the not-assessed class is inconclusive (never laundered to clean).
    roll.add_report(_report(target="http://c", verdicts={"ssti": "inconclusive"}, exercised=[],
                            inconclusive=["ssti"], corpus_wide=False, findings=[]))
    out = roll.to_rollup_dict()
    assert out["coverage_bounds"]["clean_is_corpus_wide"] is False
    assert out["verdict_by_class"]["ssti"] == "inconclusive"


# ---------------------------------------------------------------------------
# (3) the coverage certificate's bounds are preserved
# ---------------------------------------------------------------------------


def _coverage_cert(*, target_host, n_finding, n_clean, n_inconclusive, surfaces,
                   frontier_truncated=0, budget=False, probes=()):
    return {
        "schema": "vigil-coverage-certificate/1",
        "scope": "test",
        "target_host": target_host,
        "denominator": {
            "surfaces_reached": surfaces,
            "insertion_points_probed": surfaces,
            "distinct_classes_probed": 1,
            "frontier_truncated": frontier_truncated,
            "max_pages": 25,
            "max_depth": 4,
            "budget_exhausted": budget,
        },
        "probes": list(probes),
        "summary": {"n_finding": n_finding, "n_clean": n_clean, "n_inconclusive": n_inconclusive},
    }


def test_coverage_certificate_bounds_preserved() -> None:
    roll = FleetRollup()
    roll.add_coverage_certificate(_coverage_cert(
        target_host="a", n_finding=1, n_clean=2, n_inconclusive=3, surfaces=5,
        frontier_truncated=0, budget=False,
        probes=[{"class": "xss", "verdict": "clean"}, {"class": "ssti", "verdict": "inconclusive"}]))
    roll.add_coverage_certificate(_coverage_cert(
        target_host="b", n_finding=0, n_clean=1, n_inconclusive=4, surfaces=2,
        frontier_truncated=7, budget=True,
        probes=[{"class": "xss", "verdict": "clean"}]))

    cb = roll.to_rollup_dict()["coverage_certificate_bounds"]
    # summed, and the inconclusive count is SURFACED, never dropped.
    assert cb["n_finding"] == 1
    assert cb["n_clean"] == 3
    assert cb["n_inconclusive"] == 7
    assert cb["surfaces_reached"] == 7
    assert cb["certificates"] == 2
    # any truncation / budget-exhaustion marks the pooled reach as bounded.
    assert cb["reach_bounded"] is True
    assert cb["budget_exhausted"] is True

    # the cert's per-probe verdicts also fold into the coverage join — ssti stays inconclusive.
    vbc = roll.to_rollup_dict()["verdict_by_class"]
    assert vbc["ssti"] == "inconclusive"
    assert vbc["xss"] == "clean"


def test_folds_a_real_coverage_certificate_from_a_scan() -> None:
    # prove SHAPE-compatibility with the real certificate builder, and that its bounds survive.
    pytest.importorskip("bs4", reason="scanner crawl needs bs4")
    from framework.v2.eval.benchmark_app import serve
    from framework.v2.eval.benchmark_run import loopback_send
    from framework.v2.scanner.campaign import WebScanCampaign
    from framework.v2.scanner.insertion import InsertionKind
    from framework.v2.verify import coverage_oracle as co

    with serve() as base:
        report = WebScanCampaign(
            loopback_send, max_pages=15, max_depth=3, enable_oob=False,
            insertion_kinds=(InsertionKind.QUERY_VALUE,),
        ).run(base)
    cert = co.build_coverage_certificate(report, max_pages=15, max_depth=3, budget_exhausted=False)

    roll = FleetRollup()
    roll.add_coverage_certificate(cert)
    cb = roll.to_rollup_dict()["coverage_certificate_bounds"]
    assert cb["certificates"] == 1
    assert cb["n_finding"] == cert["summary"]["n_finding"]
    assert cb["n_inconclusive"] == cert["summary"]["n_inconclusive"]


def test_real_report_reverifiable_and_cert_compose_without_laundering() -> None:
    """The end-to-end shape-compat + non-laundering proof on REAL scanner artifacts: the
    honest report-fact label (grounding=="fact") equals the INDEPENDENTLY re-executed fact
    count from reverifiable.json, the coverage certificate's inconclusive bound is preserved
    verbatim, and a benchmark with real inconclusives is never reported corpus-wide clean."""
    pytest.importorskip("bs4", reason="scanner crawl needs bs4")
    from framework.v2.eval.benchmark_app import serve
    from framework.v2.eval.benchmark_run import loopback_send
    from framework.v2.scanner import report as rpt
    from framework.v2.scanner.campaign import WebScanCampaign
    from framework.v2.scanner.insertion import InsertionKind
    from framework.v2.verify import coverage_oracle as co

    with serve() as base:
        r = WebScanCampaign(
            loopback_send, max_pages=20, max_depth=3, enable_oob=False,
            insertion_kinds=(InsertionKind.QUERY_VALUE,),
        ).run(base)
    report_doc = json.loads(rpt.to_json(r))            # real report.json
    rev_doc = json.loads(r.model_dump_json())          # real reverifiable.json (certs retained)
    cert = co.build_coverage_certificate(r, max_pages=20, max_depth=3, budget_exhausted=False)

    roll = FleetRollup()
    roll.add_report(report_doc, source_id="bench")
    roll.add_coverage_certificate(cert, source_id="bench")
    roll.add_reverifiable(rev_doc, source_id="bench", reverify=True)
    out = roll.to_rollup_dict()

    # the honest report-fact label matches the independently RE-EXECUTED fact count — no fact is
    # invented and none is lost; every reverifiable fact actually re-fired (0 failures).
    assert out["facts"]["count"] == out["reverified_facts"]["count"]
    assert out["reverified_facts"]["failures"] == 0
    assert out["facts"]["by_class"] == out["reverified_facts"]["by_class"]
    # the certificate's inconclusive bound is preserved VERBATIM — not rounded into clean.
    assert out["coverage_certificate_bounds"]["n_inconclusive"] == cert["summary"]["n_inconclusive"]
    # a benchmark that leaves classes inconclusive is NEVER corpus-wide clean.
    assert out["coverage_bounds"]["classes_inconclusive"]
    assert out["coverage_bounds"]["clean_is_corpus_wide"] is False


# ---------------------------------------------------------------------------
# (4) reverifiable facts are RE-EXECUTED — a tampered cert is never a fact
# ---------------------------------------------------------------------------

_CANARY = "vgLK7tQ2mXb9Zp4WdR"
_BUG = "request_smuggling"


def _desync(*, genuine=True):
    return FindingContext.from_smuggling_desync(
        canary=_CANARY, technique="CL.TE",
        conflict_second={"channel": True, "status": 400,
                         "body": (f"HTTP/1.1 400 Bad Request GET /{_CANARY}" if genuine
                                  else "HTTP/1.1 200 OK ordinary")},
        control_second={"channel": True, "status": 200, "body": "HTTP/1.1 200 OK ordinary"},
        bug_class=_BUG)


def _rev_finding(slug, *, genuine=True):
    ctx = _desync(genuine=genuine)
    c = confirm_finding(finding={"bug_class": _BUG}, context=ctx)
    return {"check_id": slug, "bug_class": _BUG, "confirmed_by": c.confirmed_by.value,
            "confidence": c.confidence, "oracle_context": ctx.model_dump(mode="json")}


def test_reverifiable_facts_reexecuted_tamper_not_a_fact() -> None:
    # one genuine fact + one whose retained evidence was tampered (claim kept, canary dropped).
    tampered = _rev_finding("t", genuine=True)
    tampered["oracle_context"] = _desync(genuine=False).model_dump(mode="json")
    bundle = {"target": "http://x", "active_findings": [_rev_finding("g", genuine=True), tampered]}

    roll = FleetRollup()
    roll.add_reverifiable(bundle, reverify=True)
    out = roll.to_rollup_dict()["reverified_facts"]
    assert out["count"] == 1                 # only the genuine one re-fires
    assert out["by_class"] == {_BUG: 1}
    assert out["failures"] == 1              # the tampered cert is a failure, NOT a fact


def test_reverifiable_lead_without_cert_is_not_a_fact() -> None:
    roll = FleetRollup()
    roll.add_reverifiable({"active_findings": [{"bug_class": "xss", "oracle_context": None}]},
                          reverify=True)
    out = roll.to_rollup_dict()["reverified_facts"]
    assert out["count"] == 0 and out["failures"] == 1


def test_demoted_recorded_verdict_never_a_reverified_fact() -> None:
    """PoC C — the recorded-verdict gate: a finding the engagement recorded as demoted
    (verified_by_oracle=False, grounding='contradicted') with a STILL-RE-FIRING cert must NEVER
    be counted as a reverified fact. It is a rejected lead, not a fact and not a cert failure."""
    demoted = _rev_finding("d", genuine=True)
    demoted["verified_by_oracle"] = False
    demoted["grounding"] = "contradicted"
    roll = FleetRollup()
    roll.add_reverifiable({"active_findings": [demoted]}, reverify=True)
    out = roll.to_rollup_dict()["reverified_facts"]
    assert out["count"] == 0
    assert out["by_class"] == {}
    assert out["rejected_leads"] == 1
    # prove the excluded lead's OWN cert really would have re-verified — so exclusion is a verdict
    # decision (enforced), not a broken cert.
    from framework.v2.verify import reverify as _rv
    r = _rv.reverify_finding({"bug_class": _BUG, "oracle_context": demoted["oracle_context"]})
    assert r.ok and r.reproduced


def test_recorded_verdict_gate_applies_even_under_no_reverify() -> None:
    # a demoted entry is rejected regardless of reverify mode — the gate is not re-execution.
    demoted = _rev_finding("d", genuine=True)
    demoted["verified_by_oracle"] = False
    roll = FleetRollup()
    roll.add_reverifiable({"active_findings": [demoted]}, reverify=False)
    out = roll.to_rollup_dict()["reverified_facts"]
    assert out["count"] == 0 and out["rejected_leads"] == 1


def test_grounding_non_fact_rejected_ungrounded_hypothesis() -> None:
    for g in ("ungrounded", "hypothesis", "unclassified"):
        f = _rev_finding("x", genuine=True)
        f["grounding"] = g
        roll = FleetRollup()
        roll.add_reverifiable({"active_findings": [f]}, reverify=True)
        assert roll.to_rollup_dict()["reverified_facts"]["count"] == 0, g


def test_scanner_shape_without_recorded_verdict_still_counts() -> None:
    # a raw scanner AuditFinding carries NEITHER verified_by_oracle NOR grounding — its
    # active_findings ARE the confirmed set, so it falls through to the cert+re-fire check and is
    # counted (no regression to the real scanner path).
    roll = FleetRollup()
    roll.add_reverifiable({"active_findings": [_rev_finding("g", genuine=True)]}, reverify=True)
    out = roll.to_rollup_dict()["reverified_facts"]
    assert out["count"] == 1 and out["rejected_leads"] == 0 and out["failures"] == 0


def test_no_reverify_stamps_reverify_skipped_marker() -> None:
    """PoC F / FIX B(2) — the output tells a consumer whether re-execution was performed."""
    roll = FleetRollup()
    roll.add_reverifiable({"active_findings": [_rev_finding("g", genuine=True)]}, reverify=False)
    assert roll.to_rollup_dict()["reverified_facts"]["reverify_skipped"] is True

    roll2 = FleetRollup()
    roll2.add_reverifiable({"active_findings": [_rev_finding("g", genuine=True)]}, reverify=True)
    assert roll2.to_rollup_dict()["reverified_facts"]["reverify_skipped"] is False

    # no reverifiable folded at all ⇒ nothing was skipped.
    assert FleetRollup().to_rollup_dict()["reverified_facts"]["reverify_skipped"] is False


# ---------------------------------------------------------------------------
# corpus-wide clean is a strict, client-facing assurance
# ---------------------------------------------------------------------------


def test_corpus_wide_clean_false_under_bounded_reach_cert() -> None:
    """PoC D — a bounded-reach engagement (budget exhausted / frontier truncated) must NOT
    contribute to a corpus-wide-clean claim."""
    roll = FleetRollup()
    roll.add_report(_report(target="http://a", verdicts={"xss": "clean"}, exercised=["xss"],
                            inconclusive=[], corpus_wide=True, findings=[]))
    roll.add_coverage_certificate(_coverage_cert(
        target_host="b", n_finding=0, n_clean=1, n_inconclusive=0, surfaces=1,
        frontier_truncated=9, budget=True, probes=[{"class": "ssti", "verdict": "clean"}]))
    out = roll.to_rollup_dict()
    assert out["coverage_certificate_bounds"]["reach_bounded"] is True
    assert out["coverage_bounds"]["clean_is_corpus_wide"] is False


def test_corpus_wide_clean_requires_coverage_block_in_every_report() -> None:
    """PoC E — a report that made clean claims but never declared corpus-wide-clean over its own
    corpus (no coverage block) cannot yield a fleet corpus-wide-clean."""
    roll = FleetRollup()
    roll.add_report(_report(target="http://a", verdicts={"xss": "clean"}, exercised=["xss"],
                            inconclusive=[], corpus_wide=True, findings=[]))
    # report B: clean verdict_by_class but NO coverage_verdict block
    roll.add_report({"tool": "CRUCIBLE", "target": "http://b",
                     "verdict_by_class": {"cors": "clean"}, "findings": []})
    assert roll.to_rollup_dict()["coverage_bounds"]["clean_is_corpus_wide"] is False


def test_unknown_verdict_normalized_to_inconclusive_in_output() -> None:
    """PoC (garbage) — a non-lattice verdict string must never appear in the surfaced output and
    must never read as clean."""
    roll = FleetRollup()
    roll.add_report({"verdict_by_class": {"xss": "clean_ish_totally_fine", "sqli": "garbage"},
                     "findings": []})
    out = roll.to_rollup_dict()
    assert out["verdict_by_class"] == {"sqli": "inconclusive", "xss": "inconclusive"}
    assert out["coverage_bounds"]["classes_clean"] == []


# ---------------------------------------------------------------------------
# (5) hygiene: determinism + malformed input
# ---------------------------------------------------------------------------


def test_rollup_is_deterministic() -> None:
    r = _report(target="http://a", verdicts={"xss": "clean", "ssti": "inconclusive"},
                exercised=["xss"], inconclusive=["ssti"], corpus_wide=False,
                findings=[_active("boolean_sqli", "fact", check_id="s")])
    a, b = FleetRollup(), FleetRollup()
    a.add_report(r)
    b.add_report(dict(r))
    assert json.dumps(a.to_rollup_dict(), sort_keys=True) == json.dumps(b.to_rollup_dict(), sort_keys=True)


def test_malformed_inputs_raise_fleet_error() -> None:
    roll = FleetRollup()
    with pytest.raises(FleetError):
        roll.add_report({"not": "a report"})
    with pytest.raises(FleetError):
        roll.add_coverage_certificate({"schema": "something-else"})
    with pytest.raises(FleetError):
        roll.add_reverifiable({"no": "active_findings"})


def test_add_engagement_dir_folds_present_artifacts(tmp_path: Path) -> None:
    d = tmp_path / "run-001"
    d.mkdir()
    (d / "report.json").write_text(json.dumps(_report(
        target="http://a", verdicts={"xss": "clean"}, exercised=["xss"], inconclusive=[],
        corpus_wide=True, findings=[_active("boolean_sqli", "fact", check_id="s")])), encoding="utf-8")
    (d / "coverage-cert.json").write_text(json.dumps(_coverage_cert(
        target_host="a", n_finding=0, n_clean=1, n_inconclusive=0, surfaces=1)), encoding="utf-8")
    roll = FleetRollup()
    sid = roll.add_engagement(d)
    assert sid == "run-001"
    out = roll.to_rollup_dict()
    assert out["facts"]["count"] == 1
    assert out["coverage_certificate_bounds"]["certificates"] == 1
