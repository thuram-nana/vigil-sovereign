"""
The reporter — a ScanReport rendered to JSON, SARIF 2.1.0, and HTML, each enriched
with remediation + CWE refs and marking oracle-confirmed findings re-verifiable.
"""

from __future__ import annotations

import json

from framework.v2.scanner.campaign import ScanReport
from framework.v2.scanner.engine import AuditFinding
from framework.v2.scanner.passive import PassiveFinding
from framework.v2.scanner.report import build_report, render, to_sarif


def _report() -> ScanReport:
    return ScanReport(
        target="http://127.0.0.1:8000/",
        pages_crawled=3, requests_audited=5,
        active_findings=[
            AuditFinding(check_id="boolean-sqli", bug_class="boolean_sqli",
                         insertion_point="query_value:q", param="q", confidence=0.95,
                         confirmed_by="differential_response", rationale="rows diverged",
                         oracle_context={"bug_class": "boolean_sqli"}),
            AuditFinding(check_id="m5-fw-git-config", bug_class="exposure",
                         insertion_point="request:m5-fw-git-config", param="(request)",
                         confidence=0.9, confirmed_by="achieved_state",
                         rationale="repositoryformatversion present",
                         oracle_context={"bug_class": "exposure"}),
        ],
        passive_findings=[
            PassiveFinding(check_id="missing-hsts", title="Missing HSTS", severity="Low",
                           confidence="Certain", url="http://127.0.0.1:8000/", evidence="no STS header"),
        ],
        discovered_endpoints=["GET http://127.0.0.1:8000/api/items"],
    )


def test_json_report_is_structured_and_enriched() -> None:
    doc = json.loads(render(_report(), "json"))
    assert doc["tool"] == "CRUCIBLE"
    assert doc["summary"]["confirmed"] == 2
    assert doc["summary"]["discovered_endpoints"] == 1
    # the SQLi finding carries remediation + a CWE + is re-verifiable
    sqli = next(f for f in doc["findings"] if f["bug_class"] == "boolean_sqli")
    assert "parameterised" in sqli["remediation"].lower()
    assert "CWE-89" in sqli["references"] and sqli["re_verifiable"] is True
    # the exposure finding pulled remediation from its library entry
    exp = next(f for f in doc["findings"] if f["bug_class"] == "exposure")
    assert exp["remediation"] and exp["confirmed_by"] == "achieved_state"


def test_sarif_is_valid_2_1_0_shape() -> None:
    doc = json.loads(to_sarif(_report()))
    assert doc["version"] == "2.1.0"
    run = doc["runs"][0]
    assert run["tool"]["driver"]["name"] == "CRUCIBLE"
    rule_ids = {r["id"] for r in run["tool"]["driver"]["rules"]}
    assert {"boolean_sqli", "exposure"} <= rule_ids
    # confirmed SQLi maps to error level with a location + re-verifiable property
    res = next(r for r in run["results"] if r["ruleId"] == "boolean_sqli")
    assert res["level"] == "error"
    assert res["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
    assert res["properties"]["reVerifiable"] is True


def test_html_report_has_summary_and_cards() -> None:
    out = render(_report(), "html")
    assert "<!doctype html>" in out.lower()
    assert "Severity summary" in out and "boolean_sqli" in out
    assert "re-verifiable" in out  # the certificate note
    # remediation text is rendered
    assert "parameterised" in out.lower() or "prepared" in out.lower()


def test_build_report_sorts_by_severity() -> None:
    doc = build_report(_report())
    sevs = [f["severity"] for f in doc["findings"]]
    ranks = {"Critical": 5, "High": 4, "Medium": 3, "Low": 2, "Info": 1}
    assert sevs == sorted(sevs, key=lambda s: -ranks.get(s, 0))
