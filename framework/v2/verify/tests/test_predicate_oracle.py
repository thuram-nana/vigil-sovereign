"""
Wave 7 — the achieved-state rubber-stamp is gone.

State classes (CORS/host-header/redirect/JWT/IDOR/race) used to have the CHECK
compute a boolean and pass {"k": True} vs {"k": that_boolean} to the oracle, which
merely re-asserted it. Now the check hands over the RAW observed values plus a
declarative predicate, and the oracle evaluates the dangerous condition itself —
citing the values as evidence, and refusing safe evidence.
"""

from __future__ import annotations

from framework.v2.verify.adapter import FindingContext
from framework.v2.verify.confirmation import confirm_finding
from framework.v2.verify.oracles import predicate_oracle
from framework.v2.verify.verifier import OracleVerifier


def _cors_predicate() -> dict:
    return {"all": [
        {"any": [{"eq": [{"var": "acao"}, {"var": "evil_origin"}]},
                 {"eq": [{"var": "acao"}, "*"]}]},
        {"ieq": [{"var": "acac"}, "true"]},
    ]}


def test_reflected_evil_origin_with_credentials_fires_with_evidence() -> None:
    sig = predicate_oracle(
        {"acao": "https://evil", "acac": "true", "evil_origin": "https://evil"},
        _cors_predicate(),
    )
    assert sig.fired and sig.confidence >= 0.7
    assert "true" in sig.evidence and "evil" in sig.evidence  # cites the real values


def test_wildcard_with_credentials_fires() -> None:
    assert predicate_oracle(
        {"acao": "*", "acac": "true", "evil_origin": "https://evil"}, _cors_predicate()
    ).fired


def test_scoped_cors_does_not_fire() -> None:
    # the audit's point: a properly-scoped policy must NOT confirm, even though
    # the OLD rubber-stamp path would have if the check mis-decided
    assert not predicate_oracle(
        {"acao": "https://app.example", "acac": "true", "evil_origin": "https://evil"},
        _cors_predicate(),
    ).fired


def test_wildcard_without_credentials_does_not_fire() -> None:
    assert not predicate_oracle(
        {"acao": "*", "acac": "false", "evil_origin": "https://evil"}, _cors_predicate()
    ).fired


def test_predicate_finding_is_reverifiable() -> None:
    ctx = FindingContext.from_predicate(
        {"acao": "*", "acac": "true", "evil_origin": "https://evil"},
        _cors_predicate(), bug_class="cors",
    )
    restored = FindingContext.model_validate(ctx.model_dump(mode="json"))
    confirmed = confirm_finding({"bug_class": "cors"}, restored, OracleVerifier())
    assert confirmed is not None and confirmed.confirmed_by.value == "achieved_state"


def test_malformed_predicate_refuses_rather_than_crashes() -> None:
    sig = predicate_oracle({"x": 1}, {"bogus_op": [1, 2]})
    assert not sig.fired and "malformed" in sig.evidence


def test_operators() -> None:
    # gt (race), min_len + contains (idor), not + in (jwt alg:none)
    assert predicate_oracle({"s": 5, "m": 1}, {"gt": [{"var": "s"}, {"var": "m"}]}).fired
    assert not predicate_oracle({"s": 1, "m": 1}, {"gt": [{"var": "s"}, {"var": "m"}]}).fired
    idor = {"all": [{"min_len": [{"var": "vb"}, 8]}, {"contains": [{"var": "ab"}, {"var": "vb"}]}]}
    assert predicate_oracle({"vb": "victim-secret", "ab": "leak: victim-secret here"}, idor).fired
    assert not predicate_oracle({"vb": "short", "ab": "leak: short"}, idor).fired  # < 8 chars
    jwt = {"all": [{"not": {"in": [{"var": "none"}, {"var": "u"}]}},
                   {"in": [{"var": "garb"}, {"var": "u"}]}]}
    assert predicate_oracle({"none": 200, "garb": 401, "u": [0, 401, 403]}, jwt).fired
    assert not predicate_oracle({"none": 200, "garb": 200, "u": [0, 401, 403]}, jwt).fired
