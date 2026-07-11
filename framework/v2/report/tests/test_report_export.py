"""
Machine exports (SARIF 2.1.0 + structured JSON): they consume the SAME graded findings
as the Markdown docs, state each finding's grounding, carry a fact's certificate/oracle
provenance, never dress a lead as a fact, and render byte-identically twice.
"""

from __future__ import annotations

import json

from framework.v2.report import ReportMeta
from framework.v2.report.export import (
    build_export_doc,
    export_json,
    export_sarif,
    to_json,
    to_sarif,
)
from framework.v2.report.grounding import grade_findings

from .conftest import make_demoted, make_fact, make_lead


def _graded():
    return grade_findings([make_fact(), make_demoted(), make_lead()])


# ---------------------------------------------------------------------------
# JSON export
# ---------------------------------------------------------------------------


def test_json_export_is_valid_and_states_grounding() -> None:
    doc = json.loads(to_json(_graded(), ReportMeta(target="acme")))
    assert doc["schema"] == "crucible.report/v1"
    assert doc["tool"]["name"] == "CRUCIBLE"
    assert doc["target"] == "acme"
    # 1 proven fact, 2 leads (one demoted).
    assert doc["summary"]["facts"] == 1
    assert doc["summary"]["leads"] == 2
    assert doc["summary"]["by_grounding"] == {"fact": 1, "demoted": 1, "lead": 1}
    by_slug = {f["slug"]: f for f in doc["findings"]}
    assert by_slug["001-sqli"]["grounding"] == "fact"
    assert by_slug["002-stale"]["grounding"] == "demoted"
    assert by_slug["003-idor"]["grounding"] == "lead"


def test_json_fact_carries_certificate_and_lead_does_not() -> None:
    doc = json.loads(to_json(_graded()))
    by_slug = {f["slug"]: f for f in doc["findings"]}
    fact = by_slug["001-sqli"]["provenance"]
    assert fact["is_fact"] is True
    assert fact["oracle_kind"] == "differential_response"
    assert fact["confidence"] == 0.87  # calibrated, never 1.0
    assert fact["certificate"].startswith("sha256:")
    # a lead is never dressed in a fact's provenance.
    lead = by_slug["003-idor"]["provenance"]
    assert lead["is_fact"] is False
    assert lead["oracle_kind"] is None
    assert lead["confidence"] is None
    assert lead["certificate"] is None
    # a demoted lead recorded an oracle but its proof no longer re-fires → no certificate.
    demoted = by_slug["002-stale"]["provenance"]
    assert demoted["is_fact"] is False
    assert demoted["certificate"] is None


def test_json_priority_order_is_facts_only() -> None:
    doc = json.loads(to_json(_graded()))
    slugs = [r["slug"] for r in doc["priority_order"]]
    assert slugs == ["001-sqli"]  # only the proven fact is prioritised


# ---------------------------------------------------------------------------
# SARIF 2.1.0 export
# ---------------------------------------------------------------------------


def test_sarif_shape_is_2_1_0() -> None:
    doc = json.loads(to_sarif(_graded(), ReportMeta(target="acme")))
    assert doc["version"] == "2.1.0"
    assert doc["$schema"].endswith("sarif-2.1.0.json")
    assert isinstance(doc["runs"], list) and len(doc["runs"]) == 1
    run = doc["runs"][0]
    driver = run["tool"]["driver"]
    assert driver["name"] == "CRUCIBLE"
    # one rule per bug class; one result per finding.
    rule_ids = {r["id"] for r in driver["rules"]}
    assert {"boolean_sqli", "idor"} <= rule_ids
    assert len(run["results"]) == 3
    for res in run["results"]:
        assert res["ruleId"] and res["level"] in ("error", "warning", "note")
        assert res["message"]["text"]
        assert res["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]


def test_sarif_fact_levelled_by_severity_lead_capped_at_note() -> None:
    results = json.loads(to_sarif(_graded()))["runs"][0]["results"]
    by_slug = {r["properties"]["slug"]: r for r in results}
    # the Critical fact → error; it carries its proof.
    fact = by_slug["001-sqli"]
    assert fact["level"] == "error"
    assert fact["properties"]["grounding"] == "fact"
    assert fact["properties"]["oracleKind"] == "differential_response"
    assert fact["properties"]["certificate"].startswith("sha256:")
    # the High demoted lead is NOT levelled 'error' — an unproven lead never blocks CI.
    assert by_slug["002-stale"]["level"] == "note"
    assert by_slug["002-stale"]["properties"]["grounding"] == "demoted"
    assert by_slug["003-idor"]["level"] == "note"


# ---------------------------------------------------------------------------
# determinism + convenience wrappers
# ---------------------------------------------------------------------------


def test_exports_are_byte_identical_twice() -> None:
    meta = ReportMeta(target="acme", window_start="2026-07-01", window_end="2026-07-09")
    assert to_json(_graded(), meta) == to_json(_graded(), meta)
    assert to_sarif(_graded(), meta) == to_sarif(_graded(), meta)


def test_export_wrappers_grade_raw_findings() -> None:
    raw = [make_fact(), make_demoted(), make_lead()]
    assert export_json(raw) == to_json(grade_findings(raw))
    assert export_sarif(raw) == to_sarif(grade_findings(raw))


def test_no_wallclock_on_default_path() -> None:
    doc = json.loads(to_json(_graded(), ReportMeta(target="acme")))
    assert "generated_at" not in doc          # deterministic by default
    stamped = json.loads(to_json(_graded(), ReportMeta(target="acme",
                                                       generated_at="2026-07-10T00:00:00+00:00")))
    assert stamped["generated_at"] == "2026-07-10T00:00:00+00:00"  # opt-in only


def test_build_doc_matches_json() -> None:
    graded = _graded()
    assert json.loads(to_json(graded)) == build_export_doc(graded)


# ---------------------------------------------------------------------------
# ONE SARIF dialect: `scan` and `report` agree on schema/version/tool identity
# ---------------------------------------------------------------------------


def test_scan_and_report_sarif_share_one_dialect() -> None:
    # `scan --format sarif` (scanner.report over a ScanReport) and `report --format sarif`
    # (report.export over graded findings) MUST emit the same SARIF dialect: identical
    # $schema, version, and tool-driver identity, both routed through the shared envelope.
    from framework.v2.scanner.campaign import ScanReport
    from framework.v2.scanner.report import to_sarif as scan_to_sarif

    report_doc = json.loads(to_sarif(_graded(), ReportMeta(target="acme")))
    scan_doc = json.loads(scan_to_sarif(ScanReport(
        target="http://127.0.0.1:8000/", pages_crawled=0, requests_audited=0,
        active_findings=[], passive_findings=[], discovered_endpoints=[])))

    for doc in (report_doc, scan_doc):
        assert doc["$schema"].endswith("sarif-2.1.0.json")
        assert doc["version"] == "2.1.0"
        assert isinstance(doc["runs"], list) and len(doc["runs"]) == 1
    # the two producers are byte-for-byte the same identity (no drift possible)
    r_driver = report_doc["runs"][0]["tool"]["driver"]
    s_driver = scan_doc["runs"][0]["tool"]["driver"]
    assert r_driver["name"] == s_driver["name"] == "CRUCIBLE"
    assert r_driver["informationUri"] == s_driver["informationUri"]
    assert report_doc["$schema"] == scan_doc["$schema"]
