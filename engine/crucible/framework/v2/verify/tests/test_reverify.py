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

# The DIFFERENTIAL_RESPONSE certificate these plumbing tests re-verify is the SOUND one:
# a Wave-4.2 request-smuggling DESYNC (a UNIQUE high-entropy canary echoed in VIGIL's own second
# response on the conflict leg and ABSENT from the identical no-conflict control leg). It used to be
# a `boolean_sqli` benign-vs-payload differential, which is no longer confirmable at all: a bare
# differential has no attribution step, so it minted FACTs on a WAF block page and on strict input
# validation against targets with no database (see verify.verifier.DIFFERENTIAL_LEAD_ONLY_CLASSES).
# The plumbing under test is unchanged — a real DIFFERENTIAL_RESPONSE certificate, tamperable to a
# non-firing twin — it is now anchored to evidence that actually proves something.
_CANARY = "vgLK7tQ2mXb9Zp4WdR"
_BUG_CLASS = "request_smuggling"
_CHECK_ID = "smuggling-CL.TE"


def _desync_ctx(*, genuine: bool = True) -> FindingContext:
    """A re-verifiable desync certificate. ``genuine=False`` drops the canary from the conflict
    leg, so the oracle does NOT re-fire (the tampered / would-be-fabricated twin)."""
    return FindingContext.from_smuggling_desync(
        canary=_CANARY, technique="CL.TE",
        conflict_second={"channel": True, "status": 400,
                         "body": (f"HTTP/1.1 400 Bad Request: unrecognised method GET /{_CANARY}"
                                  if genuine else "HTTP/1.1 200 OK ordinary second response")},
        control_second={"channel": True, "status": 200,
                        "body": "HTTP/1.1 200 OK ordinary second response"},
        bug_class=_BUG_CLASS,
    )


def _finding_from(ctx: FindingContext) -> dict:
    """Build an AuditFinding-shaped dict carrying the certificate and the claim
    exactly as the scanner engine would."""
    confirmed = confirm_finding(finding={"bug_class": _BUG_CLASS}, context=ctx)
    assert confirmed is not None
    return {
        "check_id": _CHECK_ID,
        "bug_class": _BUG_CLASS,
        "confirmed_by": confirmed.confirmed_by.value,
        "confidence": confirmed.confidence,
        "oracle_context": ctx.model_dump(mode="json"),
    }


def test_genuine_certificate_reproduces() -> None:
    r = reverify.reverify_finding(_finding_from(_desync_ctx()))
    assert r.reproduced and r.matches_claim is True and r.ok
    assert r.confirmed_by == "differential_response"


def test_tampered_evidence_fails_reverification() -> None:
    finding = _finding_from(_desync_ctx())
    # swap the retained evidence for a canary-free conflict leg while keeping the claim: the
    # unique-canary differential no longer fires, so the certificate must NOT reproduce
    finding["oracle_context"] = _desync_ctx(genuine=False).model_dump(mode="json")
    r = reverify.reverify_finding(finding)
    assert not r.reproduced and r.matches_claim is False and not r.ok


def test_claim_mismatch_is_flagged() -> None:
    finding = _finding_from(_desync_ctx())
    finding["confidence"] = 0.123  # evidence still fires, but the claimed score is wrong
    r = reverify.reverify_finding(finding)
    assert r.reproduced and r.matches_claim is False and not r.ok


def test_reverify_refuses_a_bug_class_the_evidence_does_not_prove() -> None:
    # the retained evidence adjudicates request_smuggling; asking it to re-verify 'rce' (a
    # relabelled finding) must NOT reproduce — the requested class is load-bearing, not
    # silently overridden by the context's own embedded class. This is the binding that
    # stops a genuine SQLi proof from grounding a fabricated RCE claim.
    ctx = _desync_ctx().model_dump(mode="json")
    flipped = reverify.reverify_context(ctx, bug_class="rce")
    assert not flipped.reproduced and not flipped.ok and "does not match" in flipped.note
    # the genuine class still reproduces cleanly
    genuine = reverify.reverify_context(ctx, bug_class=_BUG_CLASS)
    assert genuine.reproduced and genuine.ok


def test_reverify_report_and_cli(tmp_path) -> None:
    good = _finding_from(_desync_ctx())
    report = {"target": "http://t/", "active_findings": [good]}
    results = reverify.reverify_document(report)
    assert results and all(r.ok for r in results)

    good_path = tmp_path / "report.json"
    good_path.write_text(json.dumps(report), encoding="utf-8")
    assert reverify.main([str(good_path)]) == 0

    tampered = dict(good)
    tampered["oracle_context"] = _desync_ctx(genuine=False).model_dump(mode="json")
    bad_path = tmp_path / "bad.json"
    bad_path.write_text(json.dumps({"active_findings": [tampered]}), encoding="utf-8")
    assert reverify.main([str(bad_path)]) == 2
