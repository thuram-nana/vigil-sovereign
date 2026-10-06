"""
Wave 7 — the achieved-state rubber-stamp is gone; Lane S — the structural FACT-eligibility grammar.

State classes (CORS/host-header/redirect/JWT/IDOR/race) used to have the CHECK compute a boolean and pass
{"k": True} vs {"k": that_boolean} to the oracle, which merely re-asserted it. Now the check hands over the
RAW observed values plus a declarative predicate, and the oracle evaluates the dangerous condition itself —
citing the values as evidence, refusing safe evidence, and (Lane S) refusing a predicate that carries no
POSITIVE DISCRIMINATOR (a VIGIL-injected provenance-ref canary / a strict reduction floor / a numeric
achieved-comparison / a present-absent differential).
"""

from __future__ import annotations

from framework.v2.verify.adapter import FindingContext
from framework.v2.verify.confirmation import confirm_finding
from framework.v2.verify.oracles import predicate_oracle
from framework.v2.verify.verifier import OracleVerifier


def _cors_predicate() -> dict:
    # The REAL CorsActiveCheck predicate: a hostile Origin reflected back WITH credentials. A wildcard
    # (`*`)+credentials is NOT browser-exploitable, so the sound builder does not treat it as a FACT and
    # the predicate carries no `*` arm.
    return {"all": [
        {"eq": [{"var": "acao"}, {"var": "evil_origin"}]},
        {"ieq": [{"var": "acac"}, "true"]},
    ]}


# evil_origin is a VIGIL-injected canary the producer cannot author, so eq[acao, evil_origin] is a PD2.
_CORS_PREFS = {"evil_origin": "canary"}


def test_reflected_evil_origin_with_credentials_fires_with_evidence() -> None:
    sig = predicate_oracle(
        {"acao": "https://evil", "acac": "true", "evil_origin": "https://evil"},
        _cors_predicate(), provenance_refs=_CORS_PREFS,
    )
    assert sig.fired and sig.confidence >= 0.7
    assert "true" in sig.evidence and "evil" in sig.evidence  # cites the real values


def test_wildcard_with_credentials_is_not_a_fact() -> None:
    # `*`+credentials is not credential-readable in a browser, so the sound predicate (a reflected-origin
    # MATCH on the canary) does not fire on a wildcard — matching CorsActiveCheck's deliberate exclusion.
    assert not predicate_oracle(
        {"acao": "*", "acac": "true", "evil_origin": "https://evil"}, _cors_predicate(),
        provenance_refs=_CORS_PREFS,
    ).fired


def test_scoped_cors_does_not_fire() -> None:
    # the audit's point: a properly-scoped policy must NOT confirm, even though
    # the OLD rubber-stamp path would have if the check mis-decided
    assert not predicate_oracle(
        {"acao": "https://app.example", "acac": "true", "evil_origin": "https://evil"},
        _cors_predicate(), provenance_refs=_CORS_PREFS,
    ).fired


def test_wildcard_without_credentials_does_not_fire() -> None:
    assert not predicate_oracle(
        {"acao": "*", "acac": "false", "evil_origin": "https://evil"}, _cors_predicate(),
        provenance_refs=_CORS_PREFS,
    ).fired


def test_predicate_finding_is_reverifiable() -> None:
    ctx = FindingContext.from_predicate(
        {"acao": "https://evil", "acac": "true", "evil_origin": "https://evil"},
        _cors_predicate(), bug_class="cors", provenance_refs=_CORS_PREFS,
    )
    restored = FindingContext.model_validate(ctx.model_dump(mode="json"))
    confirmed = confirm_finding({"bug_class": "cors"}, restored, OracleVerifier())
    assert confirmed is not None and confirmed.confirmed_by.value == "achieved_state"


def test_malformed_predicate_refuses_rather_than_crashes() -> None:
    sig = predicate_oracle({"x": 1}, {"bogus_op": [1, 2]})
    assert not sig.fired and "malformed" in sig.evidence


def test_operators() -> None:
    # gt over two DISTINCT captured counts (race limit-overrun — PD-NUM)
    assert predicate_oracle({"s": 5, "m": 1}, {"gt": [{"var": "s"}, {"var": "m"}]}).fired
    assert not predicate_oracle({"s": 1, "m": 1}, {"gt": [{"var": "s"}, {"var": "m"}]}).fired
    # idor as a present/absent DIFFERENTIAL (PD4): the victim marker is PRESENT in the attacker's cross-read
    # but ABSENT from the attacker's OWN object; a min_len floor on the marker is the distinctiveness gate.
    idor = {"all": [
        {"min_len": [{"var": "disc"}, 8]},
        {"contains": [{"var": "ab"}, {"var": "disc"}]},
        {"not": {"contains": [{"var": "own"}, {"var": "disc"}]}},
    ]}
    assert predicate_oracle(
        {"disc": "victim-secret", "ab": "leak: victim-secret here", "own": "the attacker's own object"},
        idor).fired
    # the SAME marker present in the attacker's own object too -> no differential -> does NOT fire
    assert not predicate_oracle(
        {"disc": "victim-secret", "ab": "leak: victim-secret here", "own": "also has victim-secret"},
        idor).fired
    # jwt alg:none accepted as a status-set DIFFERENTIAL (PD4 over `in`): the none-token is NOT rejected
    # (its status is not in the unauthorized set) while a garbage token IS rejected.
    jwt = {"all": [{"not": {"in": [{"var": "none"}, {"var": "u"}]}},
                   {"in": [{"var": "garb"}, {"var": "u"}]}]}
    assert predicate_oracle({"none": 200, "garb": 401, "u": [0, 401, 403]}, jwt).fired
    assert not predicate_oracle({"none": 200, "garb": 200, "u": [0, 401, 403]}, jwt).fired
