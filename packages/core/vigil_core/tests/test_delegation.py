"""S4 — owner-root identity delegation (`vigil_core.delegation`).

Proves the owner cryptographically ties the offense-governance TrustRoot to itself: a delegation the OWNER
signed (right role, in scope, unexpired) yields the delegated root; a forged/wrong-owner/out-of-scope/
wrong-role/expired/unsigned/tampered/duplicate-key delegation is REFUSED (fail-closed), and the cert
round-trips as inert JSON verified with vigil_core alone.

Run: pytest packages/core/vigil_core/tests/test_delegation.py -q
"""
import base64

import pytest

from vigil_core import AuthorizerKey, TrustRoot, generate_keypair, sign
from vigil_core.delegation import (
    OFFENSE_GOVERNANCE_ROLE,
    DelegationCert,
    DelegationError,
    _msg,
    sign_delegation,
    verify_delegation,
)

OWNER = generate_keypair()
GOV = generate_keypair()
GOV_AUTH = AuthorizerKey(key_id="root0", name="root0", public_key_b64=GOV.public_key_b64)
NOW, NOT_AFTER = 1000, 2000


def _cert(*, scope="loopback", authorizers=(GOV_AUTH,), threshold=1, not_after=NOT_AFTER):
    return sign_delegation(OWNER, role=OFFENSE_GOVERNANCE_ROLE, scope=scope,
                           authorizers=list(authorizers), threshold=threshold, not_after=not_after)


def _owner_signed(cert: DelegationCert) -> DelegationCert:
    """Sign a hand-built cert with the OWNER key, bypassing sign_delegation's mint-time guards — so a test
    can hand verify_delegation a validly-signed-but-malformed cert and exercise its VERIFY-path backstops."""
    return cert.model_copy(update={"sig": sign(OWNER.private_key_b64, _msg(cert._core()))})


def _verify(cert, *, owner=OWNER.public_key_b64, now=NOW, role=OFFENSE_GOVERNANCE_ROLE, scope="loopback"):
    return verify_delegation(cert, trusted_owner_pubkey=owner, now=now, role=role, scope=scope)


def test_owner_signed_delegation_yields_the_delegated_root():
    root = _verify(_cert())
    assert isinstance(root, TrustRoot) and root.threshold == 1
    assert [a.public_key_b64 for a in root.authorizers] == [GOV.public_key_b64]


def test_wrong_owner_key_is_refused():
    with pytest.raises(DelegationError, match="not by the trusted owner"):
        _verify(_cert(), owner=generate_keypair().public_key_b64)


def test_wrong_role_is_refused():
    with pytest.raises(DelegationError, match="role"):
        _verify(_cert(), role="some-other-role")


def test_out_of_scope_is_refused_but_wildcard_covers_any():
    with pytest.raises(DelegationError, match="scope"):
        _verify(_cert(scope="loopback"), scope="other-target")
    # a "*" delegation covers any scope
    assert _verify(_cert(scope="*"), scope="anything") is not None


def test_expired_is_refused():
    with pytest.raises(DelegationError, match="expired"):
        _verify(_cert(not_after=NOT_AFTER), now=NOT_AFTER + 1)
    # exactly at not_after is still valid (<=)
    assert _verify(_cert(not_after=NOT_AFTER), now=NOT_AFTER) is not None


def test_unsigned_is_refused():
    cert = _cert().model_copy(update={"sig": ""})
    with pytest.raises(DelegationError, match="unsigned"):
        _verify(cert)


def test_tampered_core_under_a_stale_signature_is_refused():
    cert = _cert(scope="loopback")
    forged = cert.model_copy(update={"scope": "*"})   # widen scope, keep the old signature
    with pytest.raises(DelegationError, match="does not verify"):
        _verify(forged, scope="anything")


def test_bad_threshold_refused_at_sign():
    with pytest.raises(DelegationError, match="threshold"):
        _cert(threshold=2, authorizers=(GOV_AUTH,))       # 2-of-1 impossible → refused at sign


def test_verify_backstops_bad_threshold_under_a_valid_signature():
    # A hand-built cert with an out-of-range threshold, owner-signed directly (bypassing sign_delegation's
    # mint guard) — the VERIFY-path threshold backstop must still refuse it.
    cert = _owner_signed(DelegationCert(owner_pubkey=OWNER.public_key_b64, role=OFFENSE_GOVERNANCE_ROLE,
                                        scope="loopback", not_after=NOT_AFTER, authorizers=[GOV_AUTH],
                                        threshold=2))
    with pytest.raises(DelegationError, match="invalid threshold"):
        _verify(cert)


def test_duplicate_authorizer_key_ids_refused_at_sign_and_verify():
    dup = AuthorizerKey(key_id="root0", name="dup", public_key_b64=generate_keypair().public_key_b64)
    with pytest.raises(DelegationError, match="duplicate authorizer key_ids"):
        _cert(authorizers=(GOV_AUTH, dup), threshold=1)   # same key_id "root0" twice → refused at sign
    # verify-path backstop: owner-signed directly, bypassing the mint guard
    cert = _owner_signed(DelegationCert(owner_pubkey=OWNER.public_key_b64, role=OFFENSE_GOVERNANCE_ROLE,
                                        scope="loopback", not_after=NOT_AFTER,
                                        authorizers=[GOV_AUTH, dup], threshold=1))
    with pytest.raises(DelegationError, match="duplicate authorizer key_ids"):
        _verify(cert)


def test_duplicate_authorizer_pubkeys_refused_at_sign_and_verify():
    # Distinct key_ids, SAME pubkey — would let ONE keyholder satisfy a nominal m-of-n. Must be refused.
    twin = AuthorizerKey(key_id="root1", name="twin", public_key_b64=GOV.public_key_b64)
    with pytest.raises(DelegationError, match="duplicate authorizer public keys"):
        _cert(authorizers=(GOV_AUTH, twin), threshold=2)  # refused at sign (footgun root can't be minted)
    # verify-path backstop: owner-signed directly, bypassing the mint guard
    cert = _owner_signed(DelegationCert(owner_pubkey=OWNER.public_key_b64, role=OFFENSE_GOVERNANCE_ROLE,
                                        scope="loopback", not_after=NOT_AFTER,
                                        authorizers=[GOV_AUTH, twin], threshold=2))
    with pytest.raises(DelegationError, match="duplicate authorizer public keys"):
        _verify(cert)


def test_verify_rejects_unsupported_schema_version():
    cert = _owner_signed(DelegationCert(schema_version=2, owner_pubkey=OWNER.public_key_b64,
                                        role=OFFENSE_GOVERNANCE_ROLE, scope="loopback", not_after=NOT_AFTER,
                                        authorizers=[GOV_AUTH], threshold=1))
    with pytest.raises(DelegationError, match="schema_version"):
        _verify(cert)


def test_verify_rejects_a_non_canonical_authorizer_key():
    # An all-zero (identity / small-order) authorizer pubkey is rejected eagerly at derive time (I2 weak-key
    # rule), not deferred to anchor-1, so the returned root is guaranteed usable.
    weak = AuthorizerKey(key_id="w", name="weak", public_key_b64=base64.b64encode(bytes(32)).decode())
    cert = sign_delegation(OWNER, role=OFFENSE_GOVERNANCE_ROLE, scope="loopback", authorizers=[weak],
                           threshold=1, not_after=NOT_AFTER)
    with pytest.raises(DelegationError, match="invalid public key"):
        _verify(cert)


def test_empty_role_or_scope_refused_at_sign():
    with pytest.raises(DelegationError, match="non-empty role"):
        sign_delegation(OWNER, role="  ", scope="loopback", authorizers=[GOV_AUTH], threshold=1,
                        not_after=NOT_AFTER)
    with pytest.raises(DelegationError, match="non-empty scope"):
        sign_delegation(OWNER, role=OFFENSE_GOVERNANCE_ROLE, scope="", authorizers=[GOV_AUTH], threshold=1,
                        not_after=NOT_AFTER)

