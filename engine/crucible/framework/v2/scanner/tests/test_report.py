"""
The reporter — a ScanReport rendered to JSON, SARIF 2.1.0, and HTML, each enriched
with remediation + CWE refs and marking oracle-confirmed findings re-verifiable.

Anti-hallucination P4b: the export states each finding's LIVE grounding — the report
re-executes every confirmed finding's oracle at render time, so a finding whose proof no
longer reproduces is labelled (default) or withheld (--strict-evidence), never blanket-
asserted as a proven fact.
"""

from __future__ import annotations

import json

from framework.v2.scanner.campaign import ScanReport
from framework.v2.scanner.engine import AuditFinding
from framework.v2.scanner.passive import PassiveFinding
from framework.v2.scanner.report import build_report, render, to_sarif
from framework.v2.verify.adapter import FindingContext
from framework.v2.verify.confirmation import confirm_finding

# The confirmable fixture is a path_traversal FILE-CONTENT signature with its benign CONTROL
# retained — an ATTRIBUTED side-effect proof. It used to be a boolean_sqli benign-vs-payload
# differential; that inference has no attribution step (its control is a DIFFERENT STRING, not a
# same-shape negative) and minted High FACTs at rate 1.0 against a static page behind a WAF
# tautology rule and against strict input validation, on targets with no database, so it is
# LEAD-only now (verify.verifier.DIFFERENTIAL_LEAD_ONLY_CLASSES). Nothing about the reporting
# plumbing under test changes — only the evidence it is anchored to.
_SIGNATURE = "root:x:0:0:"
_READ_SINK = "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin"
_CONTROL_SINK = "<p>ordinary document</p>"


def _sqli_finding(sink=None) -> AuditFinding:
    """A confirmed path_traversal. ``sink`` defaults to the real file read; pass ``_CONTROL_SINK``
    for the twin whose proof does NOT re-fire."""
    ctx = FindingContext.from_side_effect(
        _SIGNATURE, _READ_SINK if sink is None else sink,
        bug_class="path_traversal", control_sink=_CONTROL_SINK)
    c = confirm_finding(finding={"bug_class": "path_traversal"}, context=ctx)
    return AuditFinding(
        check_id="path-traversal", bug_class="path_traversal", insertion_point="query_value:q",
        param="q", confidence=c.confidence if c else 0.5,
        confirmed_by=c.confirmed_by.value if c else "side_effect",
        rationale="file content signature read", oracle_context=ctx.model_dump(mode="json"))


def _exposure_finding() -> AuditFinding:
    ctx = FindingContext.from_state({"repositoryformatversion": "0"},
                                    {"repositoryformatversion": "0"}, bug_class="exposure")
    c = confirm_finding(finding={"bug_class": "exposure"}, context=ctx)
    return AuditFinding(
        check_id="m5-fw-git-config", bug_class="exposure", insertion_point="request:m5-fw-git-config",
        param="(request)", confidence=c.confidence if c else 0.9,
        confirmed_by=c.confirmed_by.value if c else "achieved_state",
        rationale="repositoryformatversion present", oracle_context=ctx.model_dump(mode="json"))


def _report(active=None) -> ScanReport:
    return ScanReport(
        target="http://127.0.0.1:8000/",
        pages_crawled=3, requests_audited=5,
        active_findings=active if active is not None else [_sqli_finding(), _exposure_finding()],
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
    # the SQLi finding carries remediation + a CWE + is re-verifiable AND re-grounds as fact
    sqli = next(f for f in doc["findings"] if f["bug_class"] == "path_traversal")
    assert "canonicalise" in sqli["remediation"].lower()
    assert "CWE-22" in sqli["references"] and sqli["re_verifiable"] is True
    assert sqli["grounding"] == "fact"                          # re-executed at render time
    # the exposure finding pulled remediation from its library entry
    exp = next(f for f in doc["findings"] if f["bug_class"] == "exposure")
    assert exp["remediation"] and exp["confirmed_by"] == "achieved_state"
    # the summary carries the grounding breakdown
    assert doc["summary"]["by_grounding"].get("fact") == 2


def test_sarif_is_valid_2_1_0_shape() -> None:
    doc = json.loads(to_sarif(_report()))
    assert doc["version"] == "2.1.0"
    run = doc["runs"][0]
    assert run["tool"]["driver"]["name"] == "CRUCIBLE"
    rule_ids = {r["id"] for r in run["tool"]["driver"]["rules"]}
    assert {"path_traversal", "exposure"} <= rule_ids
    # confirmed SQLi maps to error level with a location + re-verifiable + grounding property
    res = next(r for r in run["results"] if r["ruleId"] == "path_traversal")
    assert res["level"] == "error"
    assert res["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
    assert res["properties"]["reVerifiable"] is True
    assert res["properties"]["grounding"] == "fact"


def test_html_report_has_summary_and_cards() -> None:
    out = render(_report(), "html")
    assert "<!doctype html>" in out.lower()
    assert "Severity summary" in out and "path_traversal" in out
    assert "re-verified (fact)" in out                          # the live grounding badge
    assert "re-verified at render time" in out                  # the honest footer
    assert "canonicalise" in out.lower() or "allowlisted" in out.lower()


def test_build_report_sorts_by_severity() -> None:
    doc = build_report(_report())
    sevs = [f["severity"] for f in doc["findings"]]
    ranks = {"Critical": 5, "High": 4, "Medium": 3, "Low": 2, "Info": 1}
    assert sevs == sorted(sevs, key=lambda s: -ranks.get(s, 0))


# ---- anti-hallucination P4b: honest grounding + strict export ---------------


def test_non_reproducing_finding_is_labelled_ungrounded_not_fact() -> None:
    # a finding recorded active whose oracle_context no longer re-fires (non-divergent)
    # is labelled ungrounded in the export and the footer says so — never asserted a fact.
    doc = build_report(_report(active=[_sqli_finding(_CONTROL_SINK)]))
    f = doc["findings"][0]
    assert f["grounding"] == "ungrounded" and f["bug_class"] == "path_traversal"
    assert doc["summary"]["by_grounding"].get("fact", 0) == 0
    html_out = render(_report(active=[_sqli_finding(_CONTROL_SINK)]), "html")
    assert "did NOT re-ground" in html_out                      # honest footer


def test_strict_evidence_withholds_ungrounded_findings_from_export() -> None:
    # strict mode removes the non-reproducing finding from the RENDERED document...
    active = [_sqli_finding(), _sqli_finding(_CONTROL_SINK)]            # one grounds, one does not
    strict = build_report(_report(active=active), strict_evidence=True)
    strict_active = [f for f in strict["findings"] if f["kind"] == "active"]
    assert len(strict_active) == 1 and strict_active[0]["grounding"] == "fact"
    # ...but the grounding SUMMARY still counts the full active set (nothing hidden from truth)
    assert strict["summary"]["by_grounding"].get("ungrounded") == 1
    assert strict["summary"]["strict_evidence"] is True
    # default (non-strict) keeps both active findings, labelled
    labelled = build_report(_report(active=active))
    assert len([f for f in labelled["findings"] if f["kind"] == "active"]) == 2
    # the strict HTML footer must NOT claim withheld findings "are shown as leads" —
    # it says they were WITHHELD (the honesty bug the review caught).
    strict_html = render(_report(active=active), "html", strict_evidence=True)
    assert "WITHHELD from this report" in strict_html
    assert "are shown as leads" not in strict_html
    # non-strict HTML DOES show them as leads
    assert "are shown as leads" in render(_report(active=active), "html")
