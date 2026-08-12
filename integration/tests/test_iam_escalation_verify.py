"""E2 (BUILD-PLAN §E2) — end-to-end OFFLINE wiring of the IAM privilege-escalation PRIMITIVE capability
(iam_escalation_verify).

A retained IAM-policy capture flows: capture -> confirm(oracle) -> admit(FACT over the registered
`cloud_exploit.iam.privilege_escalation` branch) -> signed D2 certificate -> OFFLINE re-verify (which re-fires
the oracle) -> veracity-firewall claim-grounding. The D2 cert binding and the firewall re-execution engage
AUTOMATICALLY (both are generic over any finding carrying an `oracle_context`), so this proves the whole
offline path with FIXTURE captures, zero cloud. The mutation-verified controls exercise every anti-overclaim
guard: break ONE field -> not-FACT, repair -> FACT, so each control is load-bearing.

Mint/reverify need the offense engine, so these importorskip framework and run in the offense (crucible) leg.
FATAL-2 (iam_escalation_verify's framework imports are function-local; the module co-loads no framework at
import) is asserted separately in test_two_env_boundary.py.
"""
import copy

import pytest

pytest.importorskip("framework.v2.verify.iam_escalation_capture")   # mint/reverify require the offense engine

from vigil_integration.live.iam_escalation_verify import iam_escalation_verify

# A genuine strict-gain escalation per primitive family: base cannot reach the target, the primitive
# unconditionally grants an edge that does.
_TRUST_REWRITE = {
    "base_principal": "role/dev", "target_resource": "s3/crown-jewels", "target_access": "admin",
    "graph": {"grants": [{"principal": "role/admin", "resource": "s3/crown-jewels", "access": "admin"}],
              "assume": [], "member_of": []},
    "escalation": {"primitive": "assume_role_trust_rewrite", "via": "role/admin",
                   "statements": [{"effect": "Allow",
                                   "action": ["sts:AssumeRole", "iam:UpdateAssumeRolePolicy"],
                                   "resource": ["role/admin"]}]},
}
_CREATE_KEY = {
    "base_principal": "user/dev", "target_resource": "s3/crown", "target_access": "admin",
    "graph": {"grants": [{"principal": "user/admin", "resource": "s3/crown", "access": "admin"}]},
    "escalation": {"primitive": "create_access_key", "via": "user/admin",
                   "statements": [{"effect": "Allow", "action": ["iam:CreateAccessKey"],
                                   "resource": ["user/admin"]}]},
}


def _signers_and_trust():
    from vigil_core import AuthorizerKey, TrustRoot, generate_keypair
    kp = generate_keypair()
    signers = [("gov0", kp.private_key_b64)]
    tr = TrustRoot(threshold=1, authorizers=[
        AuthorizerKey(key_id="gov0", name="gov0", public_key_b64=kp.public_key_b64)])
    return signers, tr


@pytest.mark.parametrize("which", ["trust_rewrite", "create_key"])
def test_capture_mints_a_fact_that_reverifies_offline(which):
    cap = _TRUST_REWRITE if which == "trust_rewrite" else _CREATE_KEY
    signers, tr = _signers_and_trust()

    r = iam_escalation_verify(cap, engagement_slug="e2test", signers=signers)
    assert r.is_fact is True and r.verdict == "FACT", r.reason
    assert r.certificate is not None and r.certificate.signed is not None
    assert r.finding_ref.startswith("iam:")

    # SECRET-FREE: the retained proof carries no credential material (only IAM ids/actions/resources).
    assert "secret" not in str(r.oracle_context).lower() or "resource" in str(r.oracle_context).lower()

    # the D2 cert re-verifies OFFLINE — re-fires the oracle (reproduction) AND routes each fact sentence
    # through the veracity firewall (claim-grounding). Both engage with no wiring of their own.
    from framework.v2.evidence.certify import verify_certificate
    v = verify_certificate(r.certificate.signed, oracle_context=r.oracle_context, trust_root=tr)
    assert v.ok is True, "a minted E2 FACT must re-verify offline from its certificate"


def test_a_tampered_oracle_context_fails_reverification():
    signers, tr = _signers_and_trust()
    r = iam_escalation_verify(_TRUST_REWRITE, engagement_slug="e2test", signers=signers)
    assert r.is_fact

    from framework.v2.evidence.certify import verify_certificate
    bad = copy.deepcopy(r.oracle_context)
    # drop sts:AssumeRole (trust-rewrite is a FALSE edge without it) — must fail re-verification.
    bad["iam_escalation_capture"]["escalation"]["statements"][0]["action"] = ["iam:UpdateAssumeRolePolicy"]
    v = verify_certificate(r.certificate.signed, oracle_context=bad, trust_root=tr)
    assert v.ok is False, "a non-firing re-derivation must fail re-verification (the firewall demotes it)"


def test_strict_gain_is_load_bearing_mutation_verified():
    # The central anti-overclaim guard: a target ALREADY reachable in the base closure is NOT escalation.
    signers, _ = _signers_and_trust()
    already = copy.deepcopy(_TRUST_REWRITE)
    already["graph"]["assume"] = [{"src": "role/dev", "dst": "role/admin"}]   # dev can already assume admin
    r = iam_escalation_verify(already, engagement_slug="e2test", signers=signers)
    assert r.is_fact is False and r.verdict in ("LEAD", "INCONCLUSIVE"), r.reason
    assert r.certificate is None
    # restore -> FACT (proves the non-FACT was the lack of strict gain, not a vacuous pass).
    assert iam_escalation_verify(_TRUST_REWRITE, engagement_slug="e2test", signers=signers).is_fact is True


@pytest.mark.parametrize("mutate", [
    # each breaks ONE field of the trust-rewrite FACT so it must NOT be a FACT.
    lambda c: c["escalation"]["statements"][0].__setitem__("condition", {"StringEquals": {"x": "y"}}),
    lambda c: c["escalation"]["statements"][0].__setitem__("not_action", ["s3:GetObject"]),
    lambda c: c["escalation"]["statements"][0].__setitem__("action", ["iam:UpdateAssumeRolePolicy"]),
    lambda c: c["escalation"]["statements"][0].__setitem__("resource", ["role/dev-*"]),
    lambda c: c["escalation"]["statements"].append(
        {"effect": "Deny", "not_action": ["s3:GetObject"], "resource": ["*"]}),
    lambda c: c["escalation"].__setitem__("boundary", {"statements": [
        {"effect": "Allow", "action": ["s3:GetObject"], "resource": ["*"]}]}),
])
def test_each_fp_trap_prevents_a_fact_mutation_verified(mutate):
    signers, _ = _signers_and_trust()
    cap = copy.deepcopy(_TRUST_REWRITE)
    mutate(cap)
    r = iam_escalation_verify(cap, engagement_slug="e2test", signers=signers)
    assert r.is_fact is False and r.certificate is None, r.reason
    # the UNMUTATED capture is still a FACT — the control is load-bearing, not a vacuous always-LEAD.
    assert iam_escalation_verify(_TRUST_REWRITE, engagement_slug="e2test", signers=signers).is_fact is True


def test_a_malformed_capture_never_raises_and_is_not_a_fact():
    signers, _ = _signers_and_trust()
    for bad in ({}, {"base_principal": "role/dev"}, {"escalation": {}}, None, "x", 123, []):
        r = iam_escalation_verify(bad, engagement_slug="e2test", signers=signers)
        assert r.is_fact is False, f"a malformed capture must never be a FACT: {bad!r}"
        assert r.certificate is None
