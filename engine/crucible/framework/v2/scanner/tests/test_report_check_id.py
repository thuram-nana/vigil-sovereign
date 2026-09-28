"""GAP A — the rendered report must carry the producing check's STABLE id for a FIXABLE finding,
and must NOT carry one for a LEAD.

Why this exists: the console Fixes screen derives each fixable finding's ``ref`` from the rendered
``report.json`` (``console/api.py::remediate_plan`` → ``f.get("check_id")``), and the gated
``vigil patch --finding-ref`` ladder keys on exactly that id. The report model used to DROP
``check_id`` even though ``build_report`` had it in hand, so the ref was always "" and the UI fell
back to "no stable finding reference on record" for every run.

THE INVARIANT (one-directional, total, and the published contract in ``scanner/report.py`` and
``report/adapt.py``)::

    check_id != ""   ==>   grounding == "fact"

i.e. a reference exists ONLY where this finding's own oracle RE-FIRED at render time. Everything
else is a LEAD and carries "": a passive-hygiene finding, a DOM-XSS candidate, AND an ACTIVE
finding whose proof no longer re-grounds (ungrounded / contradicted / hypothesis) — which
``remediate_plan`` itself counts as a lead. A lead must never acquire a reference that makes it
look apply-able. (Passive findings DO have their own ``check_id`` on the source object; the report
deliberately does not propagate it.)

Nothing else about the rendered finding shape changes.
"""

from __future__ import annotations

import json

from framework.v2.scanner.campaign import ScanReport
from framework.v2.scanner.domxss import DomXssCandidate
from framework.v2.scanner.engine import AuditFinding
from framework.v2.scanner.passive import PassiveFinding
from framework.v2.scanner.report import build_report, render, to_sarif
from framework.v2.verify.adapter import FindingContext
from framework.v2.verify.confirmation import confirm_finding

# the exact rendered finding keys — a regression guard so this change is an ADDITION, not a reshape.
_EXPECTED_FINDING_KEYS = {
    "kind", "bug_class", "title", "severity", "confidence", "location", "confirmed_by",
    "evidence", "remediation", "references", "re_verifiable", "grounding", "check_id",
}


# The confirmable fixture is a path_traversal FILE-CONTENT signature with its benign CONTROL
# retained — an ATTRIBUTED side-effect proof. It used to be a boolean_sqli benign-vs-payload
# differential; that inference has no attribution step and minted High FACTs at rate 1.0 against a
# static page behind a WAF tautology rule and against strict input validation, on targets with no
# database, so it is LEAD-only now (verify.verifier.DIFFERENTIAL_LEAD_ONLY_CLASSES). Nothing about
# the plumbing under test changes — only the evidence it is anchored to.
_SIGNATURE = "root:x:0:0:"
_READ_SINK = "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin"
_CONTROL_SINK = "<p>ordinary document</p>"


def _confirmed_active(check_id: str = "path-traversal") -> AuditFinding:
    ctx = FindingContext.from_side_effect(
        _SIGNATURE, _READ_SINK, bug_class="path_traversal", control_sink=_CONTROL_SINK)
    c = confirm_finding(finding={"bug_class": "path_traversal"}, context=ctx)
    assert c is not None, "fixture must be oracle-confirmed for this test to mean anything"
    return AuditFinding(
        check_id=check_id, bug_class="path_traversal", insertion_point="query_value:q", param="q",
        endpoint="http://127.0.0.1:8000/file", confidence=c.confidence,
        confirmed_by=c.confirmed_by.value,
        rationale="file-content signature present under the payload, absent from the control",
        oracle_context=ctx.model_dump(mode="json"),
    )


def _report_with_leads(check_id: str = "path-traversal") -> ScanReport:
    return ScanReport(
        target="http://127.0.0.1:8000/",
        active_findings=[_confirmed_active(check_id)],
        passive_findings=[PassiveFinding(
            check_id="missing-hsts", title="Missing HSTS", severity="Low", confidence="Certain",
            url="http://127.0.0.1:8000/", evidence="no STS header")],
        dom_xss_candidates=[DomXssCandidate(
            source="location.hash", sink="innerHTML", confidence="Firm",
            evidence="el.innerHTML = location.hash")],
    )


def test_active_finding_carries_its_check_id() -> None:
    doc = build_report(_report_with_leads("path-traversal"))
    active = next(f for f in doc["findings"] if f["kind"] == "active")
    # the id is the FINDING's, not a constant we invented
    assert active["check_id"] == "path-traversal"
    assert active["grounding"] == "fact"          # only a re-grounded fact is offered as fixable


def test_check_id_is_taken_from_the_finding_not_hardcoded() -> None:
    doc = build_report(_report_with_leads("some-other-check-id"))
    active = next(f for f in doc["findings"] if f["kind"] == "active")
    assert active["check_id"] == "some-other-check-id"


def test_check_id_survives_json_serialisation() -> None:
    # the console reads the SERIALIZED report.json, so the field must survive render(), not just
    # build_report() — this is the byte-level half of the plumbing.
    doc = json.loads(render(_report_with_leads(), "json"))
    active = next(f for f in doc["findings"] if f["kind"] == "active")
    assert active["check_id"] == "path-traversal"


def test_leads_carry_no_check_id() -> None:
    doc = build_report(_report_with_leads())
    passive = next(f for f in doc["findings"] if f["kind"] == "passive")
    dom = next(f for f in doc["findings"] if f["kind"] == "dom_xss_candidate")
    # a lead is NOT fixable — it must not carry a reference the apply ladder could key on,
    # even though the PassiveFinding object itself has a check_id ("missing-hsts").
    assert passive["check_id"] == "" and dom["check_id"] == ""
    assert passive["grounding"] != "fact" and dom["grounding"] != "fact"


def _ungrounded_active(check_id: str = "path-traversal") -> AuditFinding:
    """An ACTIVE finding whose proof does NOT re-fire: the signature is ALREADY in the benign
    control, so its presence under the payload is not attributable to a file read."""
    ctx = FindingContext.from_side_effect(
        _SIGNATURE, _READ_SINK, bug_class="path_traversal", control_sink=_READ_SINK)
    c = confirm_finding(finding={"bug_class": "path_traversal"}, context=ctx)
    return AuditFinding(
        check_id=check_id, bug_class="path_traversal", insertion_point="query_value:q", param="q",
        confidence=c.confidence if c else 0.5,
        confirmed_by=c.confirmed_by.value if c else "side_effect",
        rationale="signature already present in the control",
        oracle_context=ctx.model_dump(mode="json"))


def test_ungrounded_active_is_a_lead_and_gets_NO_reference() -> None:
    # An active finding whose proof no longer re-fires is a LEAD at render time — `remediate_plan`
    # counts it as one and never offers it — so it must NOT carry the reference that makes a finding
    # look apply-able. (It keeps its identity internally: the raw AuditFinding / reverifiable artifact
    # still hold its check_id; only the RENDERED, operator-facing document withholds it.)
    doc = build_report(ScanReport(target="http://127.0.0.1:8000/",
                                  active_findings=[_ungrounded_active("path-traversal")]))
    active = doc["findings"][0]
    assert active["grounding"] != "fact"
    assert active["check_id"] == "", "a non-fact must never render a fixable reference"


def test_every_rendered_reference_implies_a_fact() -> None:
    """The invariant itself, over a document that mixes ALL four kinds: a re-grounded active fact, an
    active that no longer re-grounds, a passive lead, and a DOM-XSS candidate."""
    mixed = _report_with_leads("path-traversal")
    mixed.active_findings.append(_ungrounded_active("boolean-sqli-stale"))
    doc = build_report(mixed)
    assert len(doc["findings"]) == 4
    for f in doc["findings"]:
        if f["check_id"]:
            assert f["grounding"] == "fact", f      # check_id != "" ⇒ grounding == "fact"
    # and exactly one finding — the re-grounded fact — carries a reference at all.
    assert [f["check_id"] for f in doc["findings"] if f["check_id"]] == ["path-traversal"]


def test_rendered_finding_shape_is_otherwise_unchanged() -> None:
    # regression guard: check_id is an ADDITION at the end; every other key (and value) stands.
    doc = build_report(_report_with_leads())
    for f in doc["findings"]:
        assert set(f.keys()) == _EXPECTED_FINDING_KEYS, f
        assert list(f.keys())[-1] == "check_id", "appended last — existing key order preserved"
    active = next(f for f in doc["findings"] if f["kind"] == "active")
    assert "canonicalise" in active["remediation"].lower()
    assert "CWE-22" in active["references"] and active["re_verifiable"] is True
    assert doc["summary"]["confirmed"] == 1 and doc["summary"]["passive"] == 1
    assert doc["summary"]["dom_xss_candidates"] == 1
    # the SARIF dialect is deliberately NOT reshaped by this change (its properties bag is an
    # explicit, pinned set) — pin that so a future edit is a deliberate one.
    sarif = json.loads(to_sarif(_report_with_leads()))
    res = next(r for r in sarif["runs"][0]["results"] if r["ruleId"] == "path_traversal")
    assert set(res["properties"]) == {"kind", "confidence", "confirmedBy", "reVerifiable", "grounding"}
