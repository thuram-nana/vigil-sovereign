"""
Replay-the-Proof (Screen A) — the console re-fires an EXTERNALLY-supplied report/finding
document's RETAINED oracle certificates OFFLINE via ``actions.replay_document``.

It is a PURE re-computation over the paste (``verify.reverify.reverify_document``): no target,
no scope, no traffic. A genuine certificate reproduces; a tampered one (claimed confirmed but the
retained evidence no longer re-fires, or a claimed confidence that no longer holds) is bucketed as
CONTRADICTED; a malformed/oversized body fails CLOSED with an error and never crashes.
"""

from __future__ import annotations

from framework.v2.console import actions
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
    confirmed = confirm_finding(finding={"bug_class": "boolean_sqli"}, context=ctx)
    assert confirmed is not None
    return {
        "check_id": "boolean-sqli",
        "bug_class": "boolean_sqli",
        "confirmed_by": confirmed.confirmed_by.value,
        "confidence": confirmed.confidence,
        "oracle_context": ctx.model_dump(mode="json"),
    }


def test_genuine_report_reproduces_offline() -> None:
    good = _finding_from(_ctx(_DIVERGENT))
    out = actions.replay_document({"doc": {"target": "http://t/", "active_findings": [good]}})
    assert "error" not in out
    assert out["total"] == 1
    assert out["reproduced"] == 1
    assert out["contradicted"] == 0
    assert out["ungrounded"] == 0
    r = out["results"][0]
    assert r["reproduced"] is True
    assert r["bucket"] == "reproduced"
    assert r["confirmed_by"] == "differential_response"


def test_tampered_certificate_is_contradicted() -> None:
    """A finding that CLAIMS a certificate the retained evidence no longer reproduces."""
    tampered = _finding_from(_ctx(_DIVERGENT))
    # swap in non-divergent evidence while keeping the (now false) claim → the differential can't re-fire.
    tampered["oracle_context"] = _ctx(dict(_BASE)).model_dump(mode="json")
    out = actions.replay_document({"doc": {"active_findings": [tampered]}})
    assert "error" not in out
    assert out["total"] == 1
    assert out["reproduced"] == 0
    assert out["contradicted"] == 1
    r = out["results"][0]
    assert r["reproduced"] is False
    assert r["matches_claim"] is False
    assert r["bucket"] == "contradicted"


def test_claim_mismatch_is_contradicted() -> None:
    """Evidence still fires, but the claimed confidence no longer matches → CONTRADICTED."""
    finding = _finding_from(_ctx(_DIVERGENT))
    finding["confidence"] = 0.123
    out = actions.replay_document({"doc": finding})   # single-finding document (no active_findings)
    assert "error" not in out
    assert out["total"] == 1
    assert out["contradicted"] == 1
    assert out["results"][0]["bucket"] == "contradicted"


def test_ungrounded_finding_has_no_certificate() -> None:
    """A finding carrying no oracle_context and no claim re-verifies to UNGROUNDED, not a fact."""
    out = actions.replay_document({"doc": {"bug_class": "xss", "check_id": "x"}})
    assert "error" not in out
    assert out["total"] == 1
    assert out["ungrounded"] == 1
    assert out["results"][0]["bucket"] == "ungrounded"


def test_malformed_bodies_fail_closed() -> None:
    for bad in (
        "not-a-dict",
        {},                                   # no doc
        {"doc": "not-a-dict"},
        {"doc": {}},                          # neither a report nor a finding-shaped object
        {"doc": {"active_findings": "nope"}},  # active_findings not a list
    ):
        out = actions.replay_document(bad)
        assert isinstance(out, dict)
        assert "error" in out, f"expected fail-closed error for {bad!r}"


def test_oversized_document_is_refused() -> None:
    huge = {"doc": {"active_findings": [{"bug_class": "x"}] * (actions._REPLAY_MAX_FINDINGS + 1)}}
    out = actions.replay_document(huge)
    assert "error" in out and "too large" in out["error"]


def test_replay_issues_no_traffic_and_needs_no_target() -> None:
    """The action takes NO target/scope arg and re-fires purely over the retained context."""
    import inspect

    sig = inspect.signature(actions.replay_document)
    assert list(sig.parameters) == ["body"], "replay takes only the parsed body — no target/scope/run_dir"
