"""
Wave 3 — the certificate re-verifier mechanizes prove-don't-guess.

A confirmed finding retains the exact evidence the oracle judged (its
`oracle_context`). Because the oracles are pure, that certificate re-verifies
offline: reconstruct the context, re-run the oracle, and confirm the verdict
reproduces. A one-byte change to the retained evidence, or a claimed confidence
that no longer matches, is caught.
"""

from __future__ import annotations

import json

from framework.v2.verify import reverify
from framework.v2.verify.adapter import FindingContext
from framework.v2.verify.confirmation import confirm_finding

_BASE = {"status": 200, "body": "No results found."}
_DIVERGENT = {
    "status": 200,
    "body": "id=1 name=alice role=user\nid=2 name=bob role=admin\nid=3 name=carol role=user",
}


def _ctx(mutated: dict) -> FindingContext:
    return FindingContext.from_http_responses(
        _BASE, mutated, bug_class="boolean_sqli",
        discriminator={"dimensions": ["status", "length", "lexical"]},
    )


def _finding_from(ctx: FindingContext) -> dict:
    """Build an AuditFinding-shaped dict carrying the certificate and the claim
    exactly as the scanner engine would."""
    confirmed = confirm_finding(finding={"bug_class": "boolean_sqli"}, context=ctx)
    assert confirmed is not None
    return {
        "check_id": "boolean-sqli",
        "bug_class": "boolean_sqli",
        "confirmed_by": confirmed.confirmed_by.value,
        "confidence": confirmed.confidence,
        "oracle_context": ctx.model_dump(mode="json"),
    }


def test_genuine_certificate_reproduces() -> None:
    r = reverify.reverify_finding(_finding_from(_ctx(_DIVERGENT)))
    assert r.reproduced and r.matches_claim is True and r.ok
    assert r.confirmed_by == "differential_response"


def test_tampered_evidence_fails_reverification() -> None:
    finding = _finding_from(_ctx(_DIVERGENT))
    # swap the retained evidence for a non-divergent pair while keeping the claim:
    # the differential no longer fires, so the certificate must NOT reproduce
    finding["oracle_context"] = _ctx(dict(_BASE)).model_dump(mode="json")
    r = reverify.reverify_finding(finding)
    assert not r.reproduced and r.matches_claim is False and not r.ok


def test_claim_mismatch_is_flagged() -> None:
    finding = _finding_from(_ctx(_DIVERGENT))
    finding["confidence"] = 0.123  # evidence still fires, but the claimed score is wrong
    r = reverify.reverify_finding(finding)
    assert r.reproduced and r.matches_claim is False and not r.ok


def test_reverify_refuses_a_bug_class_the_evidence_does_not_prove() -> None:
    # the retained evidence adjudicates boolean_sqli; asking it to re-verify 'rce' (a
    # relabelled finding) must NOT reproduce — the requested class is load-bearing, not
    # silently overridden by the context's own embedded class. This is the binding that
    # stops a genuine SQLi proof from grounding a fabricated RCE claim.
    ctx = _ctx(_DIVERGENT).model_dump(mode="json")
    flipped = reverify.reverify_context(ctx, bug_class="rce")
    assert not flipped.reproduced and not flipped.ok and "does not match" in flipped.note
    # the genuine class still reproduces cleanly
    genuine = reverify.reverify_context(ctx, bug_class="boolean_sqli")
    assert genuine.reproduced and genuine.ok


def test_reverify_report_and_cli(tmp_path) -> None:
    good = _finding_from(_ctx(_DIVERGENT))
    report = {"target": "http://t/", "active_findings": [good]}
    results = reverify.reverify_document(report)
    assert results and all(r.ok for r in results)

    good_path = tmp_path / "report.json"
    good_path.write_text(json.dumps(report), encoding="utf-8")
    assert reverify.main([str(good_path)]) == 0

    tampered = dict(good)
    tampered["oracle_context"] = _ctx(dict(_BASE)).model_dump(mode="json")
    bad_path = tmp_path / "bad.json"
    bad_path.write_text(json.dumps({"active_findings": [tampered]}), encoding="utf-8")
    assert reverify.main([str(bad_path)]) == 2
