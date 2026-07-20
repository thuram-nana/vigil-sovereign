"""The conjunctive offense gate (P7 Slice 3): CRUCIBLE-authority AND WARDEN, first-failure-wins,
fail-closed. Both halves injected as thunks, so the composition is tested without CRUCIBLE/kernel."""

from __future__ import annotations

import pytest

from vigil_integration.conjunctive_gate import (
    CrucibleResult,
    build_offense_gate,
    conjunctive_decide,
)
from vigil_integration.warden_gate import ToolDecision


def _cru(allowed: bool, reason: str = "ok"):
    return lambda: CrucibleResult(allowed=allowed, reason=reason)


def _cru_raises(exc: Exception):
    def f() -> CrucibleResult:
        raise exc
    return f


def _war(outcome: str, tier: str = "A2", tool: str = "http.get", reason: str = "r"):
    return lambda: ToolDecision(tool, tier, outcome, reason)


def test_crucible_deny_short_circuits_before_warden():
    called: list[int] = []

    def war() -> ToolDecision:
        called.append(1)
        return ToolDecision("http.get", "A0", "auto", "")

    v = conjunctive_decide(crucible_authorize=_cru(False, "out_of_scope"), warden_decide=war)
    assert v.outcome == "deny" and v.allowed is False
    assert v.crucible_allowed is False
    assert not called  # WARDEN half is never reached once CRUCIBLE denies (first-failure-wins)


def test_crucible_error_or_ethics_raise_fails_closed():
    # a raised EthicsViolation (e.g. killswitch tripped / expired) must DENY, not propagate/allow
    v = conjunctive_decide(
        crucible_authorize=_cru_raises(RuntimeError("engagement halted")),
        warden_decide=_war("auto"),
    )
    assert v.outcome == "deny" and v.crucible_allowed is None and v.warden is None


def test_both_allow_only_when_in_envelope_and_warden_auto():
    v = conjunctive_decide(crucible_authorize=_cru(True), warden_decide=_war("auto", "A1"))
    assert v.allowed is True and v.outcome == "allow"


def test_in_envelope_but_warden_queue_yields_queue():
    v = conjunctive_decide(crucible_authorize=_cru(True), warden_decide=_war("queue", "A2"))
    assert v.allowed is False and v.outcome == "queue" and v.crucible_allowed is True
    assert v.warden is not None and v.warden.outcome == "queue"


def test_warden_deny_yields_deny_even_in_envelope():
    v = conjunctive_decide(crucible_authorize=_cru(True), warden_decide=_war("deny", "A3"))
    assert v.outcome == "deny" and v.crucible_allowed is True


def test_warden_error_fails_closed():
    def war() -> ToolDecision:
        raise RuntimeError("kernel binary missing")

    v = conjunctive_decide(crucible_authorize=_cru(True), warden_decide=war)
    assert v.outcome == "deny" and v.crucible_allowed is True and v.warden is None


def test_only_auto_allows_unknown_warden_outcome_fails_closed():
    # BLOCK-3 regression: an unexpected WARDEN outcome must DENY, never default to ALLOW.
    for bad in ("allow", "", "maybe", "APPROVE"):
        v = conjunctive_decide(crucible_authorize=_cru(True), warden_decide=_war(bad))
        assert v.outcome == "deny" and v.allowed is False, f"outcome {bad!r} must fail closed"
    # and the ONLY outcome that allows is exactly "auto"
    assert conjunctive_decide(crucible_authorize=_cru(True), warden_decide=_war("auto")).outcome == "allow"


def test_build_offense_gate_refuses_none_trust_root():
    # BLOCK-4 regression: a None trust_root would load the authority UNSIGNED -> refuse to build.
    with pytest.raises(ValueError, match="trust_root"):
        build_offense_gate(slug="acme", trust_root=None, classify=lambda n: "A3")
