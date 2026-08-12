"""E5 (part B) — end-to-end OFFLINE wiring of the exposed-secret VALIDITY capability (secret_verify).

A retained capture flows: capture -> confirm(oracle) -> admit(FACT over the registered
`cloud_exploit.secret.credential_validity` branch) -> signed D2 certificate -> OFFLINE re-verify (which
re-fires the oracle) -> veracity-firewall claim-grounding. The D2 cert binding and the firewall re-execution
engage AUTOMATICALLY (both are generic over any finding carrying an `oracle_context`), so this proves the
whole offline path with FIXTURE captures, zero network. The anti-laundering control is exercised: a capture
'confirmed' at an attacker-controlled endpoint is admitted as a LEAD, never a FACT.

Mint/reverify need the offense engine, so these importorskip framework and run in the offense (crucible) leg.
FATAL-2 (secret_verify's framework imports are function-local; the module co-loads no framework at import) is
asserted separately in test_two_env_boundary.py.
"""
import copy

import pytest

pytest.importorskip("framework.v2.verify.secret_capture")   # mint/reverify require the offense engine

from vigil_integration.live.secret_verify import secret_verify

_AWS = {
    "secret_type": "aws_access_key",
    "credential": {"identifier": "AKIA1234567890ABCDEF", "secret": "AKIA_PLAINTEXT_SECRET_VALUE",
                   "credential_fingerprint": "fp-aws-1", "source": "js:app.min.js:1024"},
    "confirming_call": {"action": "sts:GetCallerIdentity", "status": 200, "credential_fingerprint": "fp-aws-1",
                        "endpoint": "https://sts.us-east-1.amazonaws.com/", "tls_verified": True,
                        "no_proxy": True, "no_redirect": True, "resolved_peer": "1.2.3.4",
                        "response_digest": "sha256:aaa",
                        "response": {"Arn": "arn:aws:iam::123456789012:user/leaked",
                                     "Account": "123456789012", "UserId": "AIDAEXAMPLE"}},
}
_GH = {
    "secret_type": "github_pat",
    "credential": {"identifier": "ghp_", "secret": "ghp_PLAINTEXT_TOKEN", "credential_fingerprint": "fp-gh-1",
                   "source": "git:.github/workflows/ci.yml:5"},
    "confirming_call": {"action": "github:GET /user", "status": 200, "credential_fingerprint": "fp-gh-1",
                        "endpoint": "https://api.github.com/user", "tls_verified": True, "no_proxy": True,
                        "no_redirect": True, "resolved_peer": "140.82.121.6", "response_digest": "sha256:bbb",
                        "response": {"login": "leakeduser", "id": 12345678}},
}


def _signers_and_trust():
    from vigil_core import AuthorizerKey, TrustRoot, generate_keypair
    kp = generate_keypair()
    signers = [("gov0", kp.private_key_b64)]
    tr = TrustRoot(threshold=1, authorizers=[
        AuthorizerKey(key_id="gov0", name="gov0", public_key_b64=kp.public_key_b64)])
    return signers, tr


@pytest.mark.parametrize("which", ["aws", "github"])
def test_capture_mints_a_fact_that_reverifies_offline(which):
    cap = _AWS if which == "aws" else _GH
    signers, tr = _signers_and_trust()

    r = secret_verify(cap, engagement_slug="e5test", signers=signers)
    assert r.is_fact is True and r.verdict == "FACT", r.reason
    assert r.certificate is not None and r.certificate.signed is not None
    assert r.finding_ref.startswith("secret:")

    # SECRET-SAFE: the retained proof carries no plaintext secret.
    assert "PLAINTEXT" not in str(r.oracle_context)

    # the D2 cert re-verifies OFFLINE — re-fires the oracle (reproduction) AND routes each fact sentence
    # through the veracity firewall (claim-grounding). Both engage with no wiring of their own.
    from framework.v2.evidence.certify import verify_certificate
    v = verify_certificate(r.certificate.signed, oracle_context=r.oracle_context, trust_root=tr)
    assert v.ok is True, "a minted E5 FACT must re-verify offline from its certificate"


def test_a_tampered_oracle_context_fails_reverification():
    signers, tr = _signers_and_trust()
    r = secret_verify(_AWS, engagement_slug="e5test", signers=signers)
    assert r.is_fact

    from framework.v2.evidence.certify import verify_certificate
    bad = copy.deepcopy(r.oracle_context)
    bad["secret_capture"]["confirming_call"]["status"] = 403   # break the confirming call
    v = verify_certificate(r.certificate.signed, oracle_context=bad, trust_root=tr)
    assert v.ok is False, "a failed confirming call must fail re-verification (the firewall demotes it)"


def test_anti_laundering_capture_is_never_a_fact_mutation_verified():
    # A capture 'confirmed' at an attacker-controlled endpoint is an honest LEAD, never a FACT — the crux
    # of E5's soundness. Mutation-verified: launder -> not-FACT; restore the real endpoint -> FACT.
    signers, _tr = _signers_and_trust()
    laundered = copy.deepcopy(_AWS)
    laundered["confirming_call"]["endpoint"] = "https://sts.evil.com/"
    r = secret_verify(laundered, engagement_slug="e5test", signers=signers)
    assert r.is_fact is False and r.verdict in ("LEAD", "INCONCLUSIVE"), r.reason
    assert r.certificate is None
    # restore -> FACT (proves the non-FACT was caused by the laundered endpoint, not a vacuous pass)
    assert secret_verify(_AWS, engagement_slug="e5test", signers=signers).is_fact is True


def test_a_malformed_capture_never_raises_and_is_not_a_fact():
    signers, _ = _signers_and_trust()
    for bad in ({}, {"secret_type": "aws_access_key"}, {"credential": {}}, None, "x", 123, []):
        r = secret_verify(bad, engagement_slug="e5test", signers=signers)
        assert r.is_fact is False, f"a malformed capture must never be a FACT: {bad!r}"
        assert r.certificate is None
