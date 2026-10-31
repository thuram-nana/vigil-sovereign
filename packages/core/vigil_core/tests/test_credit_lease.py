"""Slice G — the credit-launch-lease seam contract (the sovereign mints, the keyless offense plane verifies).

Load-bearing invariants (a false-green would let a forged lease authorize spend + a launch, or let a lease
be re-aimed at another tenant / host / window / amount):
  * an owner-signed lease round-trips: verify True under the owner trust root;
  * a tamper of ANY committed field (units / scope_host / org / window / nonce / slug) breaks the signature
    (detected — the fields are all inside the canonical signing bytes);
  * a wrong-key signature is refused (not the owner);
  * a quorum-collapsing trust root (duplicate authorizer pubkeys) is refused at this layer;
  * verify is fail-closed and never raises (malformed signature material -> (False, reason));
  * domain separation: the lease signing bytes carry the distinct credit-launch-lease tag.
"""
from __future__ import annotations

import copy
from datetime import datetime, timedelta, timezone

import pytest

from vigil_core import (
    AuthorizerKey,
    CreditLaunchLease,
    SignedCreditLaunchLease,
    TrustRoot,
    credit_lease_signing_bytes,
    generate_keypair,
    sign_credit_launch_lease,
    verify_credit_launch_lease,
)
from vigil_core.spine_domains import DOMAIN_TAGS

OWNER = generate_keypair()
ATTACKER = generate_keypair()
_T0 = datetime(2026, 1, 1, tzinfo=timezone.utc)


def _owner_root():
    return TrustRoot(threshold=1, authorizers=[
        AuthorizerKey(key_id="owner", name="owner", public_key_b64=OWNER.public_key_b64)])


def _lease(**over):
    base = dict(engagement_slug="cust_abc", org_id="org_acme", scope_host="apme.cm",
                units_reserved=10, not_before=_T0, not_after=_T0 + timedelta(hours=8),
                nonce="n-1", issued_at=1000.0)
    base.update(over)
    return CreditLaunchLease(**base)


def _signed(**over):
    return sign_credit_launch_lease(_lease(**over), {"owner": OWNER.private_key_b64})


def test_owner_signed_lease_roundtrips():
    signed = _signed()
    ok, reason = verify_credit_launch_lease(signed, _owner_root())
    assert ok, reason


def test_wrong_key_is_refused():
    signed = sign_credit_launch_lease(_lease(), {"owner": ATTACKER.private_key_b64})
    ok, _ = verify_credit_launch_lease(signed, _owner_root())
    assert ok is False


@pytest.mark.parametrize("field,newval", [
    ("units_reserved", 1_000_000), ("scope_host", "evil.example"), ("org_id", "org_evil"),
    ("nonce", "n-2"), ("engagement_slug", "cust_other"),
])
def test_tampering_any_bound_field_breaks_the_signature(field, newval):
    signed = _signed()
    tampered = SignedCreditLaunchLease(
        document=signed.document.model_copy(update={field: newval}),
        signatures=list(signed.signatures))
    ok, _ = verify_credit_launch_lease(tampered, _owner_root())
    assert ok is False, f"tampering {field} must break the owner signature"


def test_tampering_the_window_breaks_the_signature():
    signed = _signed()
    tampered = SignedCreditLaunchLease(
        document=signed.document.model_copy(update={"not_after": _T0 + timedelta(days=365)}),
        signatures=list(signed.signatures))
    ok, _ = verify_credit_launch_lease(tampered, _owner_root())
    assert ok is False


def test_quorum_collapsing_trust_root_refused():
    dup = TrustRoot(threshold=2, authorizers=[
        AuthorizerKey(key_id="a", name="a", public_key_b64=OWNER.public_key_b64),
        AuthorizerKey(key_id="b", name="b", public_key_b64=OWNER.public_key_b64)])
    ok, reason = verify_credit_launch_lease(_signed(), dup)
    assert ok is False and "duplicate" in reason.lower()


def test_verify_is_fail_closed_on_malformed_signature():
    from vigil_core import Signature
    bad = SignedCreditLaunchLease(document=_lease(), signatures=[Signature(key_id="owner", signature_b64="!!!")])
    ok, _ = verify_credit_launch_lease(bad, _owner_root())   # must not raise
    assert ok is False


def test_window_validator_rejects_inverted():
    with pytest.raises(ValueError):
        _lease(not_after=_T0 - timedelta(hours=1))


def test_units_must_be_positive():
    with pytest.raises(ValueError):
        _lease(units_reserved=0)


def test_signing_bytes_carry_the_distinct_domain_tag():
    body = credit_lease_signing_bytes(_lease())
    assert body.startswith(DOMAIN_TAGS["credit-launch-lease"])
    assert body != credit_lease_signing_bytes(_lease(units_reserved=11))   # units are in the signed bytes
