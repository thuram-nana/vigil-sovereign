"""I4 — m-of-n threshold authorization for destructive / high-blast offense actions.

Load-bearing properties: a destructive action is authorized ONLY when a quorum of distinct trusted
authorizers signed THIS exact action, the OWNER is mandatorily among them, the authorization is
in-window, not a long-lived sleeper, and not already consumed. Every failure is fail-closed."""

from __future__ import annotations

import pytest

from vigil_core import (
    AuthorizerKey,
    TrustRoot,
    evidence_signing_bytes,
    generate_keypair,
    sign,
)
from vigil_integration.destruction_gate import (
    DEFAULT_POLICY,
    DestructionAuthorization,
    DestructionPolicy,
    DestructionRefused,
    DestructiveAction,
    Signature,
    SignedDestructionAuthorization,
    authorization_signing_bytes,
    authorize_destruction,
    require_destruction_authorization,
    sign_authorization,
)

OWNER, WORKER, POLICY = generate_keypair(), generate_keypair(), generate_keypair()
TRUST = TrustRoot(threshold=2, authorizers=[
    AuthorizerKey(key_id="owner", name="owner", public_key_b64=OWNER.public_key_b64),
    AuthorizerKey(key_id="worker", name="worker", public_key_b64=WORKER.public_key_b64),
    AuthorizerKey(key_id="policy", name="policy", public_key_b64=POLICY.public_key_b64)])
OWNER_ID = "owner"

NOW = 1_000_000.0
_SIGNERS = {"owner": OWNER, "worker": WORKER, "policy": POLICY}


def _action(**over):
    base = dict(action_id="rm-target-db-001", engagement_slug="acme", target="db.acme.internal",
                blast_class="destructive")
    base.update(over)
    return DestructiveAction(**base)


def _auth(action=None, *, not_before=NOW - 10, not_after=NOW + 300, nonce="nonce-abc-123"):
    a = action or _action()
    return DestructionAuthorization(
        action_id=a.action_id, engagement_slug=a.engagement_slug, target=a.target,
        blast_class=a.blast_class, not_before=not_before, not_after=not_after, nonce=nonce)


def _signed(auth=None, signer_ids=("owner", "worker", "policy")):
    auth = auth or _auth()
    return sign_authorization(auth, [(kid, _SIGNERS[kid].private_key_b64) for kid in signer_ids])


def _decide(action=None, signed=None, **over):
    kw = dict(trust_root=TRUST, now=NOW, owner_key_id=OWNER_ID)
    kw.update(over)
    return authorize_destruction(action or _action(), signed or _signed(), **kw)


def test_full_quorum_with_owner_authorizes():
    d = _decide()
    assert d.authorized is True and d.nonce == "nonce-abc-123"


def test_quorum_without_owner_is_refused():
    # worker + policy meet threshold 2, but the owner's mandatory signature is absent
    d = _decide(signed=_signed(signer_ids=("worker", "policy")))
    assert d.authorized is False and "owner" in d.reason


def test_below_threshold_is_refused():
    d = _decide(signed=_signed(signer_ids=("owner",)))  # 1 < 2
    assert d.authorized is False and "threshold" in d.reason


def test_owner_plus_one_meets_threshold_and_owner_requirement():
    for second in ("worker", "policy"):
        d = _decide(signed=_signed(signer_ids=("owner", second)))
        assert d.authorized is True


def test_action_binding_rejects_a_different_target():
    # an authorization for db.acme.internal cannot authorize destruction of a different target
    auth = _auth(_action(target="db.acme.internal"))
    d = _decide(action=_action(target="prod.acme.internal"), signed=_signed(auth))
    assert d.authorized is False and "binding" in d.reason


def test_action_binding_rejects_a_different_action_id_or_class():
    auth = _auth(_action(action_id="rm-target-db-001", blast_class="destructive"))
    signed = _signed(auth)
    assert _decide(action=_action(action_id="DIFFERENT"), signed=signed).authorized is False
    assert _decide(action=_action(blast_class="high-blast"), signed=signed).authorized is False


def test_outside_the_window_is_refused():
    assert _decide(now=NOW - 100).authorized is False   # before not_before (NOW-10)
    assert _decide(now=NOW + 10_000).authorized is False  # after not_after (NOW+300)


def test_dead_mans_switch_rejects_a_long_lived_sleeper():
    # a pre-signed authorization valid for far longer than the policy max is void
    sleeper = _auth(not_before=NOW - 10, not_after=NOW + 100_000)  # ~28h window
    d = _decide(signed=_signed(sleeper))
    assert d.authorized is False and "lifetime" in d.reason


def test_window_exactly_at_the_policy_bound_is_allowed():
    lifetime = DEFAULT_POLICY.max_authorization_lifetime
    edge = _auth(not_before=NOW, not_after=NOW + lifetime)  # exactly max lifetime
    assert _decide(signed=_signed(edge), now=NOW + 1).authorized is True
    over = _auth(not_before=NOW, not_after=NOW + lifetime + 1)
    assert _decide(signed=_signed(over), now=NOW + 1).authorized is False


def test_single_use_replay_is_refused():
    consumed = {"nonce-abc-123"}
    d = _decide(is_consumed=lambda n: n in consumed)
    assert d.authorized is False and "consumed" in d.reason


def test_single_use_check_error_fails_closed():
    def boom(_n):
        raise RuntimeError("spine unavailable")
    d = _decide(is_consumed=boom)
    assert d.authorized is False and "fail closed" in d.reason


def test_empty_nonce_is_refused():
    d = _decide(signed=_signed(_auth(nonce="")))
    assert d.authorized is False and "nonce" in d.reason


def test_tampered_authorization_breaks_the_threshold():
    # sign one authorization, then mutate a field the signature covers → threshold fails
    signed = _signed(_auth(_action(target="db.acme.internal")))
    tampered = SignedDestructionAuthorization(
        authorization=DestructionAuthorization(
            **{**signed.authorization.signing_payload(), "target": "prod.acme.internal"}),
        signatures=signed.signatures)
    # bind the ACTION to the tampered target so binding passes and only the sig check can catch it
    d = _decide(action=_action(target="prod.acme.internal"), signed=tampered)
    assert d.authorized is False and "threshold" in d.reason


def test_malformed_signature_material_fails_closed():
    signed = _signed()
    bad = SignedDestructionAuthorization(
        authorization=signed.authorization,
        signatures=(Signature(key_id="owner", signature_b64="!!!not-base64!!!"),
                    signed.signatures[1]))
    d = _decide(signed=bad)
    assert d.authorized is False  # IntegrityError normalized to a deny, not raised


def test_non_gated_blast_class_is_refused_here():
    # a caller cannot route a non-destructive class through this gate; and a destructive action
    # mislabelled 'benign' would fail binding anyway. This gate only speaks for gated classes.
    a = DestructiveAction(action_id="x", engagement_slug="acme", target="t", blast_class="benign")
    auth = DestructionAuthorization(action_id="x", engagement_slug="acme", target="t",
                                    blast_class="benign", not_before=NOW - 1, not_after=NOW + 10,
                                    nonce="n1")
    d = authorize_destruction(a, sign_authorization(auth, [("owner", OWNER.private_key_b64),
                                                           ("worker", WORKER.private_key_b64)]),
                              trust_root=TRUST, now=NOW, owner_key_id=OWNER_ID)
    assert d.authorized is False and "not threshold-gated" in d.reason


def test_a_destruction_authorization_signature_cannot_be_an_evidence_cert():
    # domain separation: the exact bytes signed for a destruction authorization are prefixed with a
    # distinct domain tag, so a signature over a same-shaped evidence certificate does not authorize.
    auth = _auth()
    cert_payload = auth.signing_payload()  # identical field bytes, different domain
    assert authorization_signing_bytes(auth) != evidence_signing_bytes(cert_payload)
    # a signature made over the EVIDENCE bytes must not satisfy the destruction verify
    ev_sigs = (Signature(key_id="owner", signature_b64=sign(OWNER.private_key_b64, evidence_signing_bytes(cert_payload))),
               Signature(key_id="worker", signature_b64=sign(WORKER.private_key_b64, evidence_signing_bytes(cert_payload))))
    d = _decide(signed=SignedDestructionAuthorization(authorization=auth, signatures=ev_sigs))
    assert d.authorized is False and "threshold" in d.reason


def test_require_raises_on_refusal_and_returns_nonce_on_allow():
    assert require_destruction_authorization(
        _action(), _signed(), trust_root=TRUST, now=NOW, owner_key_id=OWNER_ID) == "nonce-abc-123"
    with pytest.raises(DestructionRefused, match="owner"):
        require_destruction_authorization(
            _action(), _signed(signer_ids=("worker", "policy")),
            trust_root=TRUST, now=NOW, owner_key_id=OWNER_ID)


def test_import_clean_no_offense_modules():
    import sys
    import vigil_integration.destruction_gate  # noqa: F401
    assert not any(m == "framework" or m.startswith("framework.")
                   or m == "strix" or m.startswith("strix.") for m in sys.modules)
