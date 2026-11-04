"""AEGIS-SaaS — the monitoring-authority seam contract (the sovereign mints, the keyless AEGIS plane verifies).

Load-bearing invariants (a false-green would let a forged grant authorize monitoring, let an OBSERVE grant
be flipped to BLOCK without the owner, or let a monitoring grant REPLAY as an offense-test authority):
  * an owner-signed grant round-trips (observe AND block) under the owner trust root;
  * a tamper of ANY committed field (org / host / mode / window) breaks the signature;
  * mode is INSIDE the signed bytes: observe and block sign DIFFERENT bytes (no silent observe->block);
  * CAPABILITY SEPARATION is cryptographic: a monitoring-authority signature does NOT verify as an
    offense-test EngagementAuthority (distinct domain tag) and vice-versa — own != offense-test != observe;
  * a wrong-key signature is refused; a quorum-collapsing trust root (duplicate pubkeys) is refused;
  * verify is fail-closed and never raises (malformed signature material -> (False, reason));
  * the window validator rejects an inverted/empty window.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from vigil_core import (
    AuthorizerKey,
    EngagementAuthority,
    MonitoringAuthority,
    MonitoringMode,
    SignedAuthority,
    SignedMonitoringAuthority,
    TargetEnvironment,
    TrustRoot,
    generate_keypair,
    monitoring_authority_signing_bytes,
    sign_monitoring_authority,
    verify_engagement_authority,
    verify_monitoring_authority,
)
from vigil_core.spine_domains import DOMAIN_TAGS

OWNER = generate_keypair()
ATTACKER = generate_keypair()
_T0 = datetime(2026, 1, 1, tzinfo=timezone.utc)
_T1 = _T0 + timedelta(hours=8)


def _owner_root():
    return TrustRoot(threshold=1, authorizers=[
        AuthorizerKey(key_id="owner", name="owner", public_key_b64=OWNER.public_key_b64)])


def _auth(**over):
    base = dict(org_id="org_acme", host="apme.cm", mode=MonitoringMode.OBSERVE,
                not_before=_T0, not_after=_T1, issued_by="owner")
    base.update(over)
    return MonitoringAuthority(**base)


def _signed(**over):
    return sign_monitoring_authority(_auth(**over), {"owner": OWNER.private_key_b64})


def test_owner_signed_grant_roundtrips_observe_and_block():
    for mode in (MonitoringMode.OBSERVE, MonitoringMode.BLOCK):
        ok, reason = verify_monitoring_authority(_signed(mode=mode), _owner_root())
        assert ok, (mode, reason)


def test_wrong_key_is_refused():
    signed = sign_monitoring_authority(_auth(), {"owner": ATTACKER.private_key_b64})
    ok, _ = verify_monitoring_authority(signed, _owner_root())
    assert ok is False


@pytest.mark.parametrize("field,newval", [
    ("org_id", "org_evil"), ("host", "evil.example"), ("mode", MonitoringMode.BLOCK), ("issued_by", "mallory"),
])
def test_tampering_any_bound_field_breaks_the_signature(field, newval):
    signed = _signed()                                   # a signed OBSERVE grant
    tampered = SignedMonitoringAuthority(
        document=signed.document.model_copy(update={field: newval}),
        signatures=list(signed.signatures))
    ok, _ = verify_monitoring_authority(tampered, _owner_root())
    assert ok is False, f"tampering {field} must break the owner signature"


def test_tampering_the_window_breaks_the_signature():
    signed = _signed()
    tampered = SignedMonitoringAuthority(
        document=signed.document.model_copy(update={"not_after": _T0 + timedelta(days=365)}),
        signatures=list(signed.signatures))
    ok, _ = verify_monitoring_authority(tampered, _owner_root())
    assert ok is False


def test_observe_and_block_sign_different_bytes_no_silent_flip():
    # mode is INSIDE the signed canonical bytes, so an OBSERVE grant's signature cannot authorize a BLOCK:
    # flipping mode requires a fresh owner signature (the owner-side observe->block control).
    assert monitoring_authority_signing_bytes(_auth(mode=MonitoringMode.OBSERVE)) != \
        monitoring_authority_signing_bytes(_auth(mode=MonitoringMode.BLOCK))


def test_capability_separation_monitoring_sig_is_not_an_offense_authority():
    # The core doctrine: own != offense-test != observe != block, made CRYPTOGRAPHIC by the distinct domain
    # tag. An owner signature over a MonitoringAuthority must NOT satisfy a verify of an EngagementAuthority
    # (the offense-test capability) built from the same host/window — even reusing the exact signature bytes.
    signed = _signed(mode=MonitoringMode.BLOCK)
    forged_offense = SignedAuthority(
        document=EngagementAuthority(
            engagement_slug="cust_acme__apme.cm", environment=TargetEnvironment.LIVE, scope=["apme.cm"],
            not_before=_T0, not_after=_T1),
        signatures=list(signed.signatures))               # the monitoring grant's owner signatures, reused
    ok, _ = verify_engagement_authority(forged_offense, _owner_root())
    assert ok is False, "a monitoring-authority signature must NOT verify as an offense EngagementAuthority"


def test_quorum_collapsing_trust_root_refused():
    dup = TrustRoot(threshold=2, authorizers=[
        AuthorizerKey(key_id="a", name="a", public_key_b64=OWNER.public_key_b64),
        AuthorizerKey(key_id="b", name="b", public_key_b64=OWNER.public_key_b64)])
    ok, reason = verify_monitoring_authority(_signed(), dup)
    assert ok is False and "duplicate" in reason.lower()


def test_verify_is_fail_closed_on_malformed_signature():
    from vigil_core import Signature
    bad = SignedMonitoringAuthority(document=_auth(),
                                    signatures=[Signature(key_id="owner", signature_b64="!!!")])
    ok, _ = verify_monitoring_authority(bad, _owner_root())   # must not raise
    assert ok is False


def test_window_validator_rejects_inverted():
    with pytest.raises(ValueError):
        _auth(not_after=_T0 - timedelta(hours=1))


def test_signing_bytes_carry_the_distinct_domain_tag():
    body = monitoring_authority_signing_bytes(_auth())
    assert body.startswith(DOMAIN_TAGS["monitoring-authority"])
    # and NOT any sibling capability's tag (non-replay at the byte level)
    assert not body.startswith(DOMAIN_TAGS["credit-launch-lease"])
    assert not body.startswith(b"crucible-authority-v1\x00")
