"""E1-Slice3 — end-to-end OFFLINE wiring of the IMDS/metadata credential-capture capability (imds_verify).

A retained capture flows: capture -> confirm(oracle) -> admit(FACT over the registered
`cloud_exploit.imds.credential_capture` branch) -> signed D2 certificate -> OFFLINE re-verify (which re-fires
the oracle) -> veracity-firewall claim-grounding. The D2 cert binding and the firewall re-execution engage
AUTOMATICALLY (both are generic over any finding carrying an `oracle_context`), so this proves the whole
offline path with a FIXTURE, zero network. A LEAD-only capture (a failed confirming call) is admitted as a
LEAD, never a FACT — mutation-verified so the control is load-bearing.

Mint/reverify need the offense engine, so these importorskip framework and run in the offense (crucible) leg.
FATAL-2 (imds_verify's framework imports are function-local; the module co-loads no framework at import) is
asserted separately in test_two_env_boundary.py.
"""
import copy

import pytest

pytest.importorskip("framework.v2.verify.imds_capture")   # mint/reverify require the offense engine

from vigil_integration.live.imds_verify import imds_verify


def _fixtures():
    # The proven, mutation-tested capture fixtures the oracle's own suite uses — one source of truth.
    from framework.v2.verify.tests.test_imds_capture import _AWS_CAP, _GCP_CAP
    return _AWS_CAP, _GCP_CAP


def _signers_and_trust():
    from vigil_core import AuthorizerKey, TrustRoot, generate_keypair
    kp = generate_keypair()
    signers = [("gov0", kp.private_key_b64)]
    tr = TrustRoot(threshold=1, authorizers=[
        AuthorizerKey(key_id="gov0", name="gov0", public_key_b64=kp.public_key_b64)])
    return signers, tr


@pytest.mark.parametrize("which", ["aws", "gcp"])
def test_capture_mints_a_fact_that_reverifies_offline(which):
    aws, gcp = _fixtures()
    cap = aws if which == "aws" else gcp
    signers, tr = _signers_and_trust()

    r = imds_verify(cap, engagement_slug="e1test", signers=signers)
    assert r.is_fact is True and r.verdict == "FACT", r.reason
    assert r.certificate is not None and r.certificate.signed is not None
    assert r.finding_ref.startswith("imds:")

    # the D2 cert re-verifies OFFLINE — this re-fires the oracle (reproduction) AND routes each fact
    # sentence through the veracity firewall (claim-grounding). Both engage with no wiring of their own.
    from framework.v2.evidence.certify import verify_certificate
    v = verify_certificate(r.certificate.signed, oracle_context=r.oracle_context, trust_root=tr)
    assert v.ok is True, "a minted E1 FACT must re-verify offline from its certificate"


def test_a_tampered_oracle_context_fails_reverification():
    aws, _ = _fixtures()
    signers, tr = _signers_and_trust()
    r = imds_verify(aws, engagement_slug="e1test", signers=signers)
    assert r.is_fact

    from framework.v2.evidence.certify import verify_certificate
    bad = copy.deepcopy(r.oracle_context)
    bad["imds_capture"]["confirming_call"]["status"] = 401   # break the confirming call
    v = verify_certificate(r.certificate.signed, oracle_context=bad, trust_root=tr)
    assert v.ok is False, "a broken confirming call must fail re-verification (the firewall demotes it)"


def test_lead_only_capture_is_never_a_fact_mutation_verified():
    # A capture whose confirming call did not succeed is an honest LEAD, never a FACT.
    aws, _ = _fixtures()
    signers, _tr = _signers_and_trust()

    lead = copy.deepcopy(aws)
    lead["confirming_call"]["status"] = 401                  # break ONE field
    r = imds_verify(lead, engagement_slug="e1test", signers=signers)
    assert r.is_fact is False and r.verdict in ("LEAD", "INCONCLUSIVE"), r.reason
    assert r.certificate is None                             # no signed cert for a non-FACT

    # repair the same field -> FACT again, proving the negative was CAUSED by the broken confirming call
    # (a load-bearing control, not a vacuous pass).
    r2 = imds_verify(aws, engagement_slug="e1test", signers=signers)
    assert r2.is_fact is True


def test_a_malformed_capture_never_raises_and_is_not_a_fact():
    signers, _ = _signers_and_trust()
    for bad in ({}, {"provider": "aws"}, {"credential": {}}, {"confirming_call": {}}, None, "x", 123, []):
        r = imds_verify(bad, engagement_slug="e1test", signers=signers)
        assert r.is_fact is False, f"a malformed capture must never be a FACT: {bad!r}"
        assert r.certificate is None
