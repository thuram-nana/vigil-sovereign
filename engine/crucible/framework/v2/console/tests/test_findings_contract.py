"""
P3 Findings table — pin the DATA CONTRACT the UI's honest FACT/LEAD split depends on.

The Findings screen shows a finding CONFIRMED (a FACT, green shield) only when it is oracle-
grounded, and everything else as a LEAD. It reads the rendered `build_report` document
(what /api/report/<run> serves), whose per-finding `grounding` is the LIVE veracity verdict:
"fact" iff the finding's own oracle re-fires over its retained evidence. This test proves the
report gives the UI exactly that signal — an oracle-confirmed active grounds as "fact" with a
real oracle kind, while a passive-hygiene finding is a lead (kind "passive", never a fact).
"""

from __future__ import annotations

from framework.v2.scanner.campaign import ScanReport
from framework.v2.scanner.engine import AuditFinding
from framework.v2.scanner.passive import PassiveFinding
from framework.v2.scanner.report import build_report
from framework.v2.verify.adapter import FindingContext
from framework.v2.verify.confirmation import confirm_finding


def _confirmed_active() -> AuditFinding:
    ctx = FindingContext.from_http_responses(
        {"status": 200, "body": "No results."},
        {"status": 200, "body": "id=1 alice user\nid=2 bob admin"},
        bug_class="boolean_sqli",
        discriminator={"dimensions": ["status", "length", "lexical"]},
    )
    c = confirm_finding(finding={"bug_class": "boolean_sqli"}, context=ctx)
    return AuditFinding(
        check_id="boolean-sqli", bug_class="boolean_sqli", insertion_point="query", param="q",
        endpoint="https://app/search", confidence=c.confidence,
        confirmed_by=c.confirmed_by.value, rationale="differential across status/length/lexical",
        oracle_context=ctx.model_dump(mode="json"),
    )


def test_report_grounds_a_confirmed_active_as_fact_and_a_passive_as_lead() -> None:
    report = ScanReport(
        target="https://app/",
        active_findings=[_confirmed_active()],
        passive_findings=[PassiveFinding(
            check_id="missing-csp", title="Missing Content-Security-Policy",
            severity="Medium", confidence="Certain", url="https://app/", evidence="CSP header absent")],
    )
    doc = build_report(report)
    by_kind = {f["kind"]: f for f in doc["findings"]}

    # the oracle-confirmed active re-grounds as a FACT with a real oracle kind → UI shows CONFIRMED.
    active = by_kind["active"]
    assert active["grounding"] == "fact"
    assert active["confirmed_by"] and active["confirmed_by"] not in ("passive", "static-lead")
    assert active["re_verifiable"] is True

    # the passive-hygiene finding is a LEAD by construction — never oracle-confirmed.
    passive = by_kind["passive"]
    assert passive["grounding"] != "fact"
    assert passive["confirmed_by"] == "passive"

    # and the summary honestly separates them (confirmed count vs passive count).
    assert doc["summary"]["confirmed"] == 1 and doc["summary"]["passive"] == 1
