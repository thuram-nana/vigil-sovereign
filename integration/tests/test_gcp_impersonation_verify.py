"""E3 — end-to-end OFFLINE wiring of the GCP service-account IMPERSONATION capability
(gcp_impersonation_verify), with a MUTATION-VERIFIED near-zero-FP differential battery.

A retained capture flows: capture -> confirm(oracle) -> admit(FACT over the registered
`cloud_exploit.gcp.sa_impersonation` branch) -> signed D2 certificate -> OFFLINE re-verify (which re-fires the
oracle) -> veracity-firewall claim-grounding. The D2 cert binding and the firewall re-execution engage
AUTOMATICALLY (both are generic over any finding carrying an `oracle_context`), so this proves the whole
offline path with FIXTURE captures, zero network.

The soundness of E3 rests on the CONFIRMING-side anti-laundering gate: an impersonation confirmed at an
attacker-controlled endpoint, or an echo of a DIFFERENT service-account, is admitted as a LEAD, never a FACT.
Each control below breaks EXACTLY ONE firing field then REPAIRS it back to a FACT — so a non-FACT is proven to
be caused by the broken field, never a vacuous pass.

Mint/reverify need the offense engine, so these importorskip framework and run in the offense (crucible) leg.
FATAL-2 (gcp_impersonation_verify's framework imports are function-local) is asserted in test_two_env_boundary.
"""
import copy

import pytest

pytest.importorskip("framework.v2.verify.gcp_impersonation_capture")  # mint/reverify require the offense engine

from vigil_integration.live.gcp_impersonation_verify import gcp_impersonation_verify

# A well-formed capture: a generateAccessToken mint AS svc-b, confirmed by a tokeninfo echo of svc-b at a
# trusted Google endpoint, fingerprint-bound. The `token` carries a PLAINTEXT sentinel to prove secret-safety.
_GOOD = {
    "mint": {
        "method": "generateAccessToken",
        "target": "svc-b@proj.iam.gserviceaccount.com",
        "token": "ya29.PLAINTEXT_IMPERSONATION_TOKEN_VALUE",
        "credential_fingerprint": "fp-imp-1",
        "endpoint": ("https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/"
                     "svc-b@proj.iam.gserviceaccount.com:generateAccessToken"),
    },
    "confirming_call": {
        "action": "tokeninfo", "status": 200, "credential_fingerprint": "fp-imp-1",
        "endpoint": "https://oauth2.googleapis.com/tokeninfo", "tls_verified": True, "no_proxy": True,
        "no_redirect": True, "resolved_peer": "142.250.72.10", "response_digest": "sha256:eee",
        "response": {"email": "svc-b@proj.iam.gserviceaccount.com", "sub": "102938475610293847561",
                     "expires_in": 3599},
    },
}


def _signers_and_trust():
    from vigil_core import AuthorizerKey, TrustRoot, generate_keypair
    kp = generate_keypair()
    signers = [("gov0", kp.private_key_b64)]
    tr = TrustRoot(threshold=1, authorizers=[
        AuthorizerKey(key_id="gov0", name="gov0", public_key_b64=kp.public_key_b64)])
    return signers, tr


def test_capture_mints_a_fact_that_reverifies_offline():
    signers, tr = _signers_and_trust()

    r = gcp_impersonation_verify(_GOOD, engagement_slug="e3test", signers=signers)
    assert r.is_fact is True and r.verdict == "FACT", r.reason
    assert r.certificate is not None and r.certificate.signed is not None
    assert r.finding_ref.startswith("gcp:")

    # SECRET-SAFE: the retained proof carries no plaintext minted token.
    assert "PLAINTEXT" not in str(r.oracle_context)

    # the D2 cert re-verifies OFFLINE — re-fires the oracle (reproduction) AND routes each fact sentence
    # through the veracity firewall (claim-grounding). Both engage with no wiring of their own.
    from framework.v2.evidence.certify import verify_certificate
    v = verify_certificate(r.certificate.signed, oracle_context=r.oracle_context, trust_root=tr)
    assert v.ok is True, "a minted E3 FACT must re-verify offline from its certificate"


def test_a_tampered_oracle_context_fails_reverification():
    signers, tr = _signers_and_trust()
    r = gcp_impersonation_verify(_GOOD, engagement_slug="e3test", signers=signers)
    assert r.is_fact

    from framework.v2.evidence.certify import verify_certificate
    bad = copy.deepcopy(r.oracle_context)
    bad["gcp_impersonation_capture"]["confirming_call"]["status"] = 403   # break the confirming call
    v = verify_certificate(r.certificate.signed, oracle_context=bad, trust_root=tr)
    assert v.ok is False, "a failed confirming call must fail re-verification (the firewall demotes it)"


def _is_fact(cap) -> bool:
    signers, _ = _signers_and_trust()
    return gcp_impersonation_verify(cap, engagement_slug="e3test", signers=signers).is_fact


def _mutate(fn) -> bool:
    """Deep-copy the good capture, apply the one-field break, return whether it still mints a FACT."""
    cap = copy.deepcopy(_GOOD)
    fn(cap)
    return _is_fact(cap)


def test_baseline_is_a_fact():
    assert _is_fact(copy.deepcopy(_GOOD)) is True


def test_anti_laundering_attacker_endpoint_is_never_a_fact_mutation_verified():
    # THE CRUX: a confirming call at an attacker-controlled 'tokeninfo' endpoint is an honest LEAD, never a
    # FACT — even though the identity echo names the real target SA. Break -> not-FACT; restore -> FACT.
    assert _mutate(lambda c: c["confirming_call"].__setitem__(
        "endpoint", "https://oauth2.googleapis.com.evil.example/tokeninfo")) is False
    assert _is_fact(copy.deepcopy(_GOOD)) is True


def test_echo_of_a_different_sa_is_never_a_fact_mutation_verified():
    # The confirming call succeeds and is trusted, but it resolves a DIFFERENT service-account than the mint
    # target — this does NOT prove impersonation OF B. Break -> not-FACT; restore -> FACT.
    assert _mutate(lambda c: c["confirming_call"]["response"].__setitem__(
        "email", "svc-other@proj.iam.gserviceaccount.com")) is False
    assert _is_fact(copy.deepcopy(_GOOD)) is True


def test_fingerprint_unbound_is_never_a_fact_mutation_verified():
    # The confirming call introspected a token whose fingerprint differs from the minted token's — the call
    # may have used a DIFFERENT token. Break -> not-FACT; restore -> FACT.
    assert _mutate(lambda c: c["confirming_call"].__setitem__(
        "credential_fingerprint", "fp-DIFFERENT")) is False
    assert _is_fact(copy.deepcopy(_GOOD)) is True


def test_malformed_target_sa_is_never_a_fact_mutation_verified():
    # The mint target is not a *.gserviceaccount.com email / uid — not a named service-account. Break ->
    # not-FACT; restore -> FACT. (The echo email is aligned so ONLY the target shape is what breaks it.)
    def _break(c):
        c["mint"]["target"] = "attacker@evil.example"
        c["confirming_call"]["response"]["email"] = "attacker@evil.example"
    assert _mutate(_break) is False
    assert _is_fact(copy.deepcopy(_GOOD)) is True


def test_non_impersonation_mint_method_is_never_a_fact_mutation_verified():
    # A non-impersonation mint verb (a plain userinfo read is not an iamcredentials mint). Break -> not-FACT.
    assert _mutate(lambda c: c["mint"].__setitem__("method", "GET /userinfo")) is False
    assert _is_fact(copy.deepcopy(_GOOD)) is True


def test_a_uid_named_target_also_mints_a_fact():
    # The target may be named by numeric unique-id; the confirming `sub` echo must then match it.
    cap = copy.deepcopy(_GOOD)
    cap["mint"]["target"] = "102938475610293847561"
    assert _is_fact(cap) is True


def test_a_malformed_capture_never_raises_and_is_not_a_fact():
    signers, _ = _signers_and_trust()
    for bad in ({}, {"mint": {}}, {"mint": {"method": "signJwt"}}, {"confirming_call": {}}, None, "x", 123, []):
        r = gcp_impersonation_verify(bad, engagement_slug="e3test", signers=signers)
        assert r.is_fact is False, f"a malformed capture must never be a FACT: {bad!r}"
        assert r.certificate is None
