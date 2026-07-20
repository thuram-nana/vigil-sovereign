"""
The evaluation oracle — confirms server-side template / expression-language
injection by proving the server EVALUATED an injected expression, never on mere
reflection. This is the distinction Burp's SSTI checks make, made deterministic:
the computed result must appear, the raw template text must not.
"""

from __future__ import annotations

from framework.v2.verify.oracles import evaluation_oracle
from framework.v2.verify.models import OracleKind
from framework.v2.verify.verifier import OracleVerifier, normalize_bug_class
from framework.v2.verify.adapter import FindingContext

_RAW = "{{31337*31337}}"
_RESULT = str(31337 * 31337)  # 982007569


def test_fires_when_expression_is_evaluated() -> None:
    body = f"<h1>Welcome</h1>\nresult={_RESULT}\n<footer>x</footer>"
    sig = evaluation_oracle(_RAW, _RESULT, body)
    assert sig.fired and sig.kind is OracleKind.EVALUATION and sig.confidence >= 0.9


def test_does_not_fire_on_reflection() -> None:
    # the raw template text survived -> reflected, not evaluated
    body = f"echo: {_RAW}"
    sig = evaluation_oracle(_RAW, _RESULT, body)
    assert not sig.fired


def test_does_not_fire_when_result_absent() -> None:
    sig = evaluation_oracle(_RAW, _RESULT, "no result here at all")
    assert not sig.fired


def test_does_not_fire_when_result_is_in_the_benign_control() -> None:
    # the number is part of the page regardless of the payload
    body = f"account balance: {_RESULT}"
    sig = evaluation_oracle(_RAW, _RESULT, body, control_body=f"account balance: {_RESULT}")
    assert not sig.fired


def test_rejects_trivial_expected_result() -> None:
    assert not evaluation_oracle("{{1}}", "1", "the answer is 1").fired


def test_routes_ssti_to_evaluation_first_and_confirms() -> None:
    # ssti now routes EVALUATION ahead of the reflection/differential fallbacks
    assert OracleKind.EVALUATION in OracleVerifier().oracles_for("ssti")
    assert OracleVerifier().oracles_for("ssti")[0] is OracleKind.EVALUATION
    assert normalize_bug_class("server_side_template_injection") == "ssti"

    ctx = FindingContext.from_evaluation(_RAW, _RESULT, f"x result={_RESULT} y",
                                         control_body="x no result y")
    result = OracleVerifier().confirm(ctx.to_verifier_context())
    assert result.confirmed
    assert any(s.kind is OracleKind.EVALUATION and s.fired for s in result.signals)


def test_certificate_round_trips_through_the_adapter() -> None:
    ctx = FindingContext.from_evaluation(_RAW, _RESULT, f"result={_RESULT}")
    dumped = ctx.model_dump()
    rebuilt = FindingContext.model_validate(dumped)
    assert OracleVerifier().confirm(rebuilt.to_verifier_context()).confirmed
