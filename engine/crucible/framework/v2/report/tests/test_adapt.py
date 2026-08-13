"""
report.adapt — the stored-scan-export adapter, tested against a REAL stored run.

The adapter exists because ``generate_reports()`` could not consume a finished run: the stored
``report.json`` is the scanner EXPORT shape, while the renderers validate
``agents.models.FindingPayload``, so feeding one to the other raised a pydantic
``ValidationError`` — which is precisely why a dossier built from a real run carried no
human-readable reports at all.

The fixture in ``fixtures/`` is copied verbatim from a real console run against a loopback
target (``.console/runs/20260729-112009-041``): a 13-finding ``report.json`` (2 oracle-confirmed
active findings and 11 passive observations) and the ``reverifiable.json`` that retains the two
``oracle_context`` blocks. Copying it in keeps the test hermetic while keeping it honest — every
assertion below is about bytes the engine really produced, not a hand-built ideal.

The properties under test are the two rules the module is built on: never invent, never lose.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from framework.v2.report.adapt import (
    adapt_scan_export,
    auditfinding_to_payload,
    slugify,
    split_location,
)
from framework.v2.report.generate import ReportMeta, generate_reports
from framework.v2.report.grounding import GRADE_FACT, grade_findings

_FIXTURES = Path(__file__).parent / "fixtures"


def _export() -> dict:
    return json.loads((_FIXTURES / "stored-report.json").read_text(encoding="utf-8"))


def _reverifiable() -> dict:
    return json.loads((_FIXTURES / "stored-reverifiable.json").read_text(encoding="utf-8"))


# ---------------------------------------------------------------------------
# the blocker itself: the stored export cannot be rendered, the adapted one can
# ---------------------------------------------------------------------------


def test_the_stored_export_shape_is_rejected_by_the_renderers() -> None:
    """The defect this module fixes, pinned. If this ever stops raising, the adapter's reason for
    existing has changed and its mapping needs re-examining rather than silently trusting."""
    with pytest.raises(Exception):
        generate_reports(_export()["findings"], ReportMeta(target="t"))


def test_adapted_findings_render_all_three_reports() -> None:
    res = adapt_scan_export(_export(), [_reverifiable()])
    docs = generate_reports(res.findings, ReportMeta(target="t"))
    assert set(docs) == {"executive", "technical", "remediation-roadmap"}
    for body in docs.values():
        assert body.strip()


def test_every_stored_finding_survives_the_translation() -> None:
    """Never lose: 13 findings in, 13 findings out, and each keeps its own identity."""
    export = _export()
    res = adapt_scan_export(export, [_reverifiable()])
    assert len(res.findings) == len(export["findings"]) == 13
    assert len({f["finding_slug"] for f in res.findings}) == 13, "slugs must be unique"
    titles_in = [f["title"] for f in export["findings"]]
    titles_out = [f["title"] for f in res.findings]
    assert titles_in == titles_out, "titles must be copied verbatim, in order"


# ---------------------------------------------------------------------------
# the proof join — the reason a once-confirmed finding is not falsely demoted
# ---------------------------------------------------------------------------


def test_the_join_attaches_retained_proofs_so_findings_grade_as_facts() -> None:
    res = adapt_scan_export(_export(), [_reverifiable()])
    assert res.proofs_joined == 2 and res.proofs_unjoined == 0

    graded = grade_findings(res.findings)
    facts = [g for g in graded if g.grade == GRADE_FACT]
    assert len(facts) == 2, "both retained proofs must RE-FIRE at report time"
    assert {g.finding.bug_class for g in facts} == {"boolean_sqli", "xss"}
    # a fact carries the provenance the grader only populates on a real re-fire
    for g in facts:
        assert g.oracle_kind and g.certificate_digest and g.confidence is not None


def test_without_the_reverifiable_document_nothing_is_falsely_demoted() -> None:
    """The failure mode the join prevents. With no retained evidence to attach, a once-confirmed
    finding must read as UNPROVEN — never as a proof that FAILED, which is a different and
    alarming claim — and the finding must say why in its own summary."""
    res = adapt_scan_export(_export(), [])
    assert res.proofs_joined == 0 and res.proofs_unjoined == 2

    graded = grade_findings(res.findings)
    assert not any(g.grade == GRADE_FACT for g in graded), "no evidence in, no fact out"
    assert not any(g.finding.verified_by_oracle for g in graded), (
        "verified_by_oracle must stay False, or the grader reports these as proofs that failed "
        "re-verification rather than as proofs that were never present")

    active = next(f for f in res.findings if f["bug_class"] == "boolean_sqli")
    assert "not available when this document was produced" in active["summary"]
    assert any("no saved evidence available" in n for n in res.notes)


def test_a_proof_is_never_attached_to_a_different_kind_of_finding() -> None:
    """The join relaxes the insertion point but never the bug class or the oracle, so a retained
    proof cannot migrate onto an unrelated finding and manufacture a fact."""
    rv = _reverifiable()
    for f in rv["active_findings"]:
        f["bug_class"] = "totally_unrelated_class"
    res = adapt_scan_export(_export(), [rv])
    assert res.proofs_joined == 0
    assert not any(g.grade == GRADE_FACT for g in grade_findings(res.findings))


def test_unmatched_retained_proofs_are_counted_and_explained() -> None:
    rv = _reverifiable()
    rv["active_findings"].append({
        "check_id": "elsewhere", "bug_class": "ssrf", "insertion_point": "",
        "confirmed_by": "oob_callback", "oracle_context": {"bug_class": "ssrf"},
    })
    res = adapt_scan_export(_export(), [rv])
    assert res.proofs_unused == 1
    assert any("did not correspond to any finding" in n for n in res.notes)


# ---------------------------------------------------------------------------
# never invent — fields with no source stay empty
# ---------------------------------------------------------------------------


def test_fields_with_no_source_are_left_empty_not_fabricated() -> None:
    res = adapt_scan_export(_export(), [_reverifiable()])
    for f in res.findings:
        assert f["impact"] == "", "the export carries no impact statement; none may be invented"
        assert f["cvss_vector"] == "" and f["cvss_base"] is None
        assert f["derived_from_hypothesis"] is None
        assert f["oracle_rationale"] == ""


def test_a_passive_observation_gets_no_oracle_provenance() -> None:
    """`confirmed_by` reads "passive" for a header observation. That names a source, not a
    deterministic check, so it must never be rendered as the oracle that fired."""
    res = adapt_scan_export(_export(), [_reverifiable()])
    passives = [f for f in res.findings if f["bug_class"] == "passive"]
    assert len(passives) == 11
    for f in passives:
        assert f["oracle_kind"] is None and f["oracle_context"] is None
        assert f["verified_by_oracle"] is False
        assert f["confidence"] is None, "'Certain' is not an exploitability probability"


def test_the_export_extras_are_carried_rather_than_dropped() -> None:
    """FindingPayload has nowhere to put the scanner's own remediation text or its CWE/CAPEC
    references, so they must come back alongside — or the translation silently loses them."""
    res = adapt_scan_export(_export(), [_reverifiable()])
    assert set(res.extras) == {f["finding_slug"] for f in res.findings}
    sqli = next(e for e in res.extras.values() if e.kind == "active" and "sqli" in e.slug)
    assert "CWE-89" in sqli.references
    assert "parameterised" in sqli.scanner_remediation
    assert sqli.parameter == "q"
    assert sqli.recorded_confidence and sqli.recorded_grounding == "fact"


# ---------------------------------------------------------------------------
# severity + totality
# ---------------------------------------------------------------------------


def test_an_unrecognised_severity_is_not_inflated_and_is_not_lost() -> None:
    export = _export()
    export["findings"][0]["severity"] = "Catastrophic"
    res = adapt_scan_export(export, [_reverifiable()])
    adapted = res.findings[0]
    assert adapted["severity"] == "Info", "an unplaceable rating must not be inflated"
    assert "Catastrophic" in adapted["summary"], "the original rating must survive in the text"
    assert any("Catastrophic" in n for n in res.notes)


@pytest.mark.parametrize("bad", [None, [], "text", {}, {"findings": "not a list"}])
def test_a_malformed_export_yields_an_explained_empty_result(bad) -> None:
    res = adapt_scan_export(bad, [])
    assert res.findings == [] and res.notes, "a malformed document explains itself, never raises"


def test_helpers() -> None:
    assert split_location("http://h/s?q=t  [query_value:0]") == ("http://h/s?q=t", "query_value:0")
    assert split_location("http://h/s") == ("http://h/s", "")
    assert split_location("") == ("", "")
    assert slugify("Missing X-Frame-Options (clickjacking)") == "missing-x-frame-options-clickjacking"
    assert slugify("") == "finding"
    # long titles are truncated at the limit and never left with a trailing separator
    long = slugify("x" * 200)
    assert len(long) == 48 and not long.endswith("-")


def test_auditfinding_coercion_never_manufactures_a_proof() -> None:
    """The shared coercion used wherever a retained proof must be graded. It fills descriptive
    fields only so validation succeeds; a finding with no retained context still grades as a lead."""
    payload = auditfinding_to_payload(
        {"check_id": "c1", "bug_class": "idor", "confirmed_by": "achieved_state",
         "oracle_context": None})
    assert payload["oracle_context"] is None
    assert grade_findings([payload])[0].grade != GRADE_FACT
