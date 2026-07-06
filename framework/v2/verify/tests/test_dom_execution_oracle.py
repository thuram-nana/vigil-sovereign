"""
The DOM-execution oracle — confirms DOM-XSS by proving injected JavaScript
executed in a real DOM (a unique canary reached the driver's execution binding),
not by reflection. These are pure tests over the oracle; the browser-driven end
to end path lives in scanner/tests/test_browser_xss.py (skip-gated on Chromium).
"""

from __future__ import annotations

from framework.v2.verify.adapter import FindingContext
from framework.v2.verify.models import OracleKind
from framework.v2.verify.oracles import dom_execution_oracle
from framework.v2.verify.verifier import OracleVerifier

_CANARY = "cxss00deadbeef"


def test_fires_when_canary_reached_the_execution_binding() -> None:
    sig = dom_execution_oracle([_CANARY], _CANARY)
    assert sig.fired and sig.kind is OracleKind.DOM_EXECUTION and sig.confidence >= 0.9


def test_does_not_fire_without_a_binding_call() -> None:
    assert not dom_execution_oracle([], _CANARY).fired
    assert not dom_execution_oracle(["some-other-call"], _CANARY).fired


def test_rejects_trivial_canary() -> None:
    assert not dom_execution_oracle(["ab"], "ab").fired


def test_routes_dom_xss_to_execution_first() -> None:
    kinds = OracleVerifier().oracles_for("dom_xss")
    assert kinds[0] is OracleKind.DOM_EXECUTION
    # the static side-effect lead remains as a fallback
    assert OracleKind.SIDE_EFFECT in kinds


def test_confirms_and_certificate_round_trips() -> None:
    ctx = FindingContext.from_dom_execution([f"x {_CANARY} y"], _CANARY)
    result = OracleVerifier().confirm(ctx.to_verifier_context())
    assert result.confirmed
    assert any(s.kind is OracleKind.DOM_EXECUTION and s.fired for s in result.signals)
    # re-verify from the serialized certificate
    rebuilt = FindingContext.model_validate(ctx.model_dump())
    assert OracleVerifier().confirm(rebuilt.to_verifier_context()).confirmed
