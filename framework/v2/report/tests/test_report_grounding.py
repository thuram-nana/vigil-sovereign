"""
Grounding: the report re-executes each finding's proof and grades it FACT / DEMOTED /
LEAD. Prove-don't-guess starts here — a stored ``verified_by_oracle`` flag is never
trusted; only a proof that re-fires NOW earns FACT.
"""

from __future__ import annotations

from framework.v2.agents.models import FindingPayload
from framework.v2.report.grounding import (
    GRADE_DEMOTED,
    GRADE_FACT,
    GRADE_LEAD,
    grade_finding,
    grade_findings,
)

from .conftest import firing_ctx, make_demoted, make_fact, make_lead, nonfiring_ctx


def test_genuine_oracle_finding_grades_fact_with_certificate() -> None:
    g = grade_finding(make_fact())
    assert g.grade == GRADE_FACT and g.is_fact and not g.is_lead
    # a fact carries its provenance: the oracle kind, a calibrated (never 1.0) confidence,
    # and a re-runnable certificate digest that binds the exact retained evidence.
    assert g.oracle_kind == "differential_response"
    assert g.confidence is not None and 0.0 < g.confidence < 1.0
    assert g.certificate_digest and len(g.certificate_digest) == 64


def test_stale_proof_is_demoted_not_a_fact() -> None:
    # recorded as oracle-confirmed, but the retained evidence no longer diverges → the
    # oracle does not re-fire → DEMOTED (a lead), never asserted as a fact.
    g = grade_finding(make_demoted())
    assert g.grade == GRADE_DEMOTED
    assert g.is_lead and not g.is_fact
    assert g.certificate_digest is None and g.oracle_kind is None


def test_relabelled_bug_class_is_demoted() -> None:
    # claims 'rce' but the retained context only proves boolean_sqli — the class binding
    # in re-verification refuses it, so it can never grade as an RCE fact.
    f = make_fact(slug="004-relabel", bug_class="rce")
    g = grade_finding(f)
    assert g.grade == GRADE_DEMOTED and not g.is_fact


def test_missing_oracle_context_is_demoted() -> None:
    f = FindingPayload(
        finding_slug="005-noctx", title="Confirmed but no evidence", severity="High",
        bug_class="boolean_sqli", surface="GET /x", summary="s",
        verified_by_oracle=True, critique_status="confirmed", oracle_context=None,
    )
    g = grade_finding(f)
    assert g.grade == GRADE_DEMOTED and not g.is_fact


def test_llm_advisory_finding_grades_lead() -> None:
    g = grade_finding(make_lead())
    assert g.grade == GRADE_LEAD and g.is_lead and not g.is_fact
    assert g.certificate_digest is None


def test_dryrun_advisory_lead_is_labelled_in_reason() -> None:
    f = make_lead(slug="006-dry")
    f = f.model_copy(update={"critique_dryrun": True})
    g = grade_finding(f)
    assert g.grade == GRADE_LEAD
    assert "dry-run" in g.reason.lower()


def test_grade_findings_accepts_dicts_and_pairs() -> None:
    rows = grade_findings([
        (make_fact().model_dump(), 11),   # a (finding-dict, event_id) pair
        make_lead(),                       # a bare model
    ])
    assert [g.grade for g in rows] == [GRADE_FACT, GRADE_LEAD]
    assert rows[0].event_id == 11


def test_grade_is_deterministic() -> None:
    f = make_fact()
    a, b = grade_finding(f), grade_finding(f)
    assert (a.grade, a.certificate_digest, a.confidence) == (b.grade, b.certificate_digest, b.confidence)
