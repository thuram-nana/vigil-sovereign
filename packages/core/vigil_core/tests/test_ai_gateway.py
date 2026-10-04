"""The one AI-egress chokepoint (``vigil_core.ai_gateway``), proven in isolation.

The core is a PURE composition: classify -> redact -> case-authorize -> model-route -> provenance ->
output-verify -> audit, with every environment-specific step injected through an ``EgressCase``. These
tests drive it with spies, each pairing a POSITIVE control (the step does its job) with a SAFE-NEGATIVE
control (the step refuses / fails closed), so no assertion is a no-op.
"""
from __future__ import annotations

import pytest

from vigil_core import ai_gateway as G
from vigil_core.redact import MASK


_SECRET = "sk-ant-PLANTED-super-secret-value-xyz"


def _spy_invoke():
    """An invoke closure that records what it received and that it ran — the stand-in for a model call."""
    seen: dict = {"ran": False, "payload": None}

    def invoke(redacted):
        G.assert_in_egress("spy")          # a real adapter guards itself here; a bypass fails closed
        seen["ran"] = True
        seen["payload"] = dict(redacted)
        return {"decision": "ok"}

    return invoke, seen


@pytest.fixture(autouse=True)
def _clean_audit():
    G.reset_audit()
    yield
    G.reset_audit()


# ── step 1: classify ────────────────────────────────────────────────────────────────────────────

def test_classify_flags_secret_bearing_vs_ordinary():
    inv, _ = _spy_invoke()
    secret_case = G.EgressCase(path="t", invoke=inv, backend="anthropic")
    ordinary = G.classify_payload({"system": "be helpful", "user": "scan http://h/"}, secret_case)
    bearing = G.classify_payload({"system": "be helpful", "user": f"Authorization: Bearer {_SECRET}"}, secret_case)
    assert ordinary.sensitivity == "ordinary"
    assert bearing.sensitivity == "secret-bearing"
    assert ordinary.path == "t"


# ── step 2: redact (symmetric masker) ───────────────────────────────────────────────────────────

def test_redact_masks_free_text_and_structured_secrets():
    red, n = G.redact_payload({
        "system": "ordinary instructions",
        "user": f"use Authorization: Bearer {_SECRET} and api_key={_SECRET}",
        "structured": {"url": "http://h/", "api_key": _SECRET},
    })
    assert _SECRET not in red["user"]
    assert _SECRET not in str(red["structured"])
    assert red["structured"]["url"] == "http://h/"          # non-secret structure preserved
    assert red["system"] == "ordinary instructions"          # ordinary text untouched (negative control)
    assert n >= 2 and MASK in red["user"]


# ── step 3: case-authorize gate ────────────────────────────────────────────────────────────────

def test_case_gate_deny_refuses_before_invoke():
    inv, seen = _spy_invoke()
    case = G.EgressCase(path="t", invoke=inv, backend="anthropic",
                        authorize=lambda: (False, "egress disabled by operator"))
    res = G.egress({"system": "s", "user": "u"}, case=case)
    assert res.refused and res.refusal_kind == "case"
    assert seen["ran"] is False                              # the model was never called
    assert res.record.invoked is False and res.record.outcome == "refused_case"


def test_case_gate_allow_lets_egress_proceed():
    inv, seen = _spy_invoke()
    case = G.EgressCase(path="t", invoke=inv, backend="anthropic", authorize=lambda: (True, "ok"))
    res = G.egress({"system": "s", "user": "u"}, case=case)
    assert res.ok and seen["ran"] is True and res.record.case_authorized is True


def test_case_gate_that_raises_is_a_deny():
    inv, seen = _spy_invoke()

    def boom():
        raise RuntimeError("gate blew up")

    case = G.EgressCase(path="t", invoke=inv, backend="anthropic", authorize=boom)
    res = G.egress({"system": "s", "user": "u"}, case=case)
    assert res.refused and res.refusal_kind == "case" and seen["ran"] is False


# ── step 4: model-route (sovereignty ladder) ─────────────────────────────────────────────────────

def test_sovereignty_refusal_happens_before_invoke():
    inv, seen = _spy_invoke()

    def deny(name):
        raise PermissionError(f"backend {name!r} refused by tier AIR_GAPPED")

    case = G.EgressCase(path="t", invoke=inv, backend="anthropic", assert_permitted=deny)
    res = G.egress({"system": "s", "user": "u"}, case=case)
    assert res.refused and res.refusal_kind == "sovereignty"
    assert seen["ran"] is False                              # refused BEFORE the invoke closure ran …
    assert res.record.invoked is False                       # … so the SDK import (inside invoke) never ran
    assert "AIR_GAPPED" in res.record.reason


def test_sovereignty_permits_when_backend_allowed():
    inv, seen = _spy_invoke()
    case = G.EgressCase(path="t", invoke=inv, backend="ollama", assert_permitted=lambda name: None)
    res = G.egress({"system": "s", "user": "u"}, case=case)
    assert res.ok and seen["ran"] is True and res.record.sovereignty_permitted is True


def test_auto_backend_skips_pre_assert_but_still_invokes():
    # An empty backend name means "auto-selected" — the gateway does not pre-assert (the invoke enforces
    # its own per-candidate sovereignty); it must still run the call.
    inv, seen = _spy_invoke()
    tripped = {"n": 0}

    def _assert(name):
        tripped["n"] += 1

    case = G.EgressCase(path="t", invoke=inv, backend="", assert_permitted=_assert)
    res = G.egress({"system": "s", "user": "u"}, case=case)
    assert res.ok and seen["ran"] is True and tripped["n"] == 0


# ── step 4/6: the provider is never in the trust root ─────────────────────────────────────────────

def test_provider_in_trust_root_is_refused():
    inv, seen = _spy_invoke()
    case = G.EgressCase(path="t", invoke=inv, backend="anthropic",
                        provider_identity="anthropic", trust_root_ids=frozenset({"anthropic", "owner-key"}))
    res = G.egress({"system": "s", "user": "u"}, case=case)
    assert res.refused and res.refusal_kind == "trust_root"
    assert seen["ran"] is False and res.record.provider_in_trust_root is True


def test_provider_not_in_trust_root_is_permitted_and_marked_untrusted():
    inv, seen = _spy_invoke()
    case = G.EgressCase(path="t", invoke=inv, backend="anthropic",
                        provider_identity="anthropic", trust_root_ids=frozenset({"owner-key", "ca-root"}))
    res = G.egress({"system": "s", "user": "u"}, case=case)
    assert res.ok and seen["ran"] is True
    assert res.record.provider_in_trust_root is False        # step 6: provider attributed as untrusted
    assert res.record.provider_authoritative is False        # a model output is never authoritative


# ── step 5: the redacted payload is what the model receives (symmetric redaction, in ONE place) ───

def test_invoke_receives_the_redacted_payload_not_the_secret():
    inv, seen = _spy_invoke()
    case = G.EgressCase(path="t", invoke=inv, backend="ollama", assert_permitted=lambda n: None)
    res = G.egress({"system": "ok", "user": f"Authorization: Bearer {_SECRET}"}, case=case)
    assert res.ok
    assert _SECRET not in seen["payload"]["user"]            # the model NEVER saw the credential
    assert _SECRET not in str(res.redacted)
    assert res.record.redaction_applied is True and res.record.classification.sensitivity == "secret-bearing"


# ── step 5: an invoke that raises is recorded then re-raised (URK propagation contract) ───────────

def test_invoke_exception_is_recorded_and_reraised():
    def invoke(redacted):
        G.assert_in_egress("spy")
        raise ValueError("backend overloaded")

    case = G.EgressCase(path="t", invoke=invoke, backend="ollama", assert_permitted=lambda n: None)
    with pytest.raises(ValueError):
        G.egress({"system": "s", "user": "u"}, case=case)
    recs = G.audit_log()
    assert recs and recs[-1].outcome == "error" and recs[-1].invoked is True


# ── step 7: a unified record is emitted for every egress (ring + injected sink) ───────────────────

def test_unified_record_is_emitted_to_ring_and_sink():
    inv, _ = _spy_invoke()
    sunk: list = []
    case = G.EgressCase(path="live_think", invoke=inv, backend="anthropic", assert_permitted=lambda n: None,
                        audit_sink=sunk.append, provenance=lambda out: {"answered_backend": "anthropic"})
    res = G.egress({"system": "s", "user": "u"}, case=case)
    assert res.ok
    assert len(sunk) == 1 and sunk[0] is res.record
    assert G.audit_log()[-1] is res.record
    d = res.record.to_dict()
    for key in ("path", "backend", "redaction_applied", "sovereignty_permitted", "invoked",
                "provider_authoritative", "provider_in_trust_root", "outcome", "timestamp"):
        assert key in d
    assert d["path"] == "live_think" and d["extra"]["answered_backend"] == "anthropic"


def test_a_failing_audit_sink_never_breaks_egress():
    inv, seen = _spy_invoke()

    def bad_sink(_rec):
        raise RuntimeError("sink down")

    case = G.EgressCase(path="t", invoke=inv, backend="ollama", assert_permitted=lambda n: None,
                        audit_sink=bad_sink)
    res = G.egress({"system": "s", "user": "u"}, case=case)
    assert res.ok and seen["ran"] is True                    # the egress completed despite the sink error


# ── the gateway is the ONLY egress path: a direct bypass fails closed ─────────────────────────────

def test_direct_invoke_bypass_fails_closed():
    inv, seen = _spy_invoke()
    # calling the invoke closure DIRECTLY (not via egress) is outside the egress context → fail closed
    with pytest.raises(G.EgressBypass):
        inv({"system": "s", "user": "u"})
    assert seen["ran"] is False


def test_assert_in_egress_is_true_only_inside_egress():
    assert G.in_egress() is False
    inside = {"seen": False}

    def invoke(redacted):
        inside["seen"] = G.in_egress()
        G.assert_in_egress("x")          # does not raise here
        return "ok"

    case = G.EgressCase(path="t", invoke=invoke, backend="ollama", assert_permitted=lambda n: None)
    G.egress({"system": "s", "user": "u"}, case=case)
    assert inside["seen"] is True
    assert G.in_egress() is False        # the context is cleared on the way out
