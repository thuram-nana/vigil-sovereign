"""AEGIS AS-2g — the owner-signed ORIGIN BINDING contract (the sovereign mints, the keyless plane verifies).

Load-bearing invariants a false-green would break (a grant forwarded to an UNBOUND/forged origin; a binding for
one tenant rebinding another's grant; a tampered origin/commitment still accepted; a secret in the published
record):

  * the binding round-trips sign -> serialize (JSON) -> parse -> verify under the OWNER root;
  * a one-field / one-byte tamper breaks the signature (every field is in the signed bytes);
  * the digest is the sha256 of the SIGNING BYTES — deterministic, signature-independent (re-signing is stable);
  * ``grant_binds_origin`` passes ONLY when origin + commitment + subject + edge_chain all match and the digest
    is the grant's ``origin_binding_sha256`` (the full cross-check the data plane runs); every mismatch fails
    CLOSED, and it never raises on hostile input;
  * an IP-literal / non-https origin is refused at construction; a non-hex commitment is refused;
  * the binding domain tag is DISTINCT — a v2 grant signature can never replay as a binding, or vice-versa;
  * verify is fail-closed and never raises; a quorum-collapsing trust root is refused.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from vigil_core import (
    AegisOriginBinding,
    AuthorizerKey,
    AuthoritySubject,
    MonitoringAuthorityV2,
    MonitoringCapability,
    MonitoringLease,
    OriginTuple,
    SignedAegisOriginBinding,
    TrustRoot,
    aegis_origin_binding_signing_bytes,
    generate_keypair,
    grant_binds_origin,
    origin_binding_digest,
    origin_binding_publish_path,
    sign_aegis_origin_binding,
    verify_aegis_origin_binding,
)
from vigil_core.authority_v2 import monitoring_authority_v2_signing_bytes, sign_monitoring_authority_v2

OWNER = generate_keypair()
ATTACKER = generate_keypair()

_T0 = datetime(2026, 1, 1, tzinfo=timezone.utc)
_T_END = _T0 + timedelta(days=30)
_L0 = _T0 + timedelta(hours=1)
_L1 = _L0 + timedelta(hours=1)
_NOW = _L0 + timedelta(minutes=10)
_COMMIT = "a" * 64


def _owner_root(key=OWNER):
    return TrustRoot(threshold=1, authorizers=[
        AuthorizerKey(key_id="owner", name="owner", public_key_b64=key.public_key_b64)])


def _subject(**over):
    base = dict(org_id="org_acme", host="api.example.com")
    base.update(over)
    return AuthoritySubject(**base)


def _origin(**over):
    base = dict(scheme="https", host="origin.example.com", port=443)
    base.update(over)
    return OriginTuple(**base)


def _binding(**over) -> AegisOriginBinding:
    base = dict(subject=_subject(), origin=_origin(), edge_chain="shared_actor",
                origin_secret_sha256=_COMMIT, epoch=1, issued_at=10.0)
    base.update(over)
    return AegisOriginBinding(**base)


def _signed(doc=None, key=OWNER) -> SignedAegisOriginBinding:
    return sign_aegis_origin_binding(doc or _binding(), {"owner": key.private_key_b64})


def _bound_grant(digest: str, **over) -> MonitoringAuthorityV2:
    base = dict(subject=_subject(), capabilities=[MonitoringCapability.OBSERVE], epoch=1, not_before=_T0,
                not_after=_T_END, lease=MonitoringLease(not_before=_L0, not_after=_L1), instance_id="inst-01",
                edge_chain="shared_actor", origin=_origin(), origin_binding_sha256=digest, issued_at=10.0)
    base.update(over)
    return MonitoringAuthorityV2(**base)


# --- round-trip + tamper ------------------------------------------------------------------------------
def test_binding_round_trips_and_verifies_under_the_owner_root():
    signed = _signed()
    raw = signed.model_dump_json()
    back = SignedAegisOriginBinding.model_validate_json(raw)
    ok, why = verify_aegis_origin_binding(back, _owner_root())
    assert ok, why


def test_a_one_field_tamper_breaks_the_signature():
    signed = _signed()
    for upd in ({"origin_secret_sha256": "b" * 64}, {"edge_chain": "other-edge"}, {"epoch": 2}):
        tampered = signed.model_copy(update={"document": signed.document.model_copy(update=upd)})
        assert verify_aegis_origin_binding(tampered, _owner_root())[0] is False, upd
    # a different origin host too
    bad_origin = signed.document.model_copy(update={"origin": _origin(host="evil.example.com")})
    assert verify_aegis_origin_binding(signed.model_copy(update={"document": bad_origin}), _owner_root())[0] is False


def test_an_attacker_signature_does_not_verify_under_the_owner_root():
    signed = _signed(key=ATTACKER)
    assert verify_aegis_origin_binding(signed, _owner_root())[0] is False


# --- digest determinism -------------------------------------------------------------------------------
def test_digest_is_over_signing_bytes_and_is_signature_independent():
    doc = _binding()
    d1 = origin_binding_digest(sign_aegis_origin_binding(doc, {"owner": OWNER.private_key_b64}))
    d2 = origin_binding_digest(sign_aegis_origin_binding(doc, {"owner": OWNER.private_key_b64}))
    d_doc = origin_binding_digest(doc)
    import hashlib
    assert d1 == d2 == d_doc == hashlib.sha256(aegis_origin_binding_signing_bytes(doc)).hexdigest()
    assert len(d1) == 64 and all(c in "0123456789abcdef" for c in d1)
    # a different document -> a different digest
    assert origin_binding_digest(_binding(epoch=2)) != d_doc


def test_signing_bytes_are_deterministic_and_capability_order_free_of_the_tag():
    # same logical binding -> byte-identical signing bytes; the tag is distinct from the v2 grant tag.
    assert aegis_origin_binding_signing_bytes(_binding()) == aegis_origin_binding_signing_bytes(_binding())
    assert aegis_origin_binding_signing_bytes(_binding()).startswith(b"vigil-aegis-origin-binding-v1\x00")


# --- construction validators --------------------------------------------------------------------------
def test_ip_literal_and_non_https_origin_are_refused():
    with pytest.raises(ValueError):
        _binding(origin=OriginTuple(scheme="https", host="169.254.169.254", port=443))
    with pytest.raises(ValueError):
        OriginTuple(scheme="http", host="origin.example.com", port=80)


def test_a_non_hex_commitment_is_refused():
    for bad in ("z" * 64, "a" * 63, "deadbeef", "g" * 64):
        with pytest.raises(ValueError):
            _binding(origin_secret_sha256=bad)
    # uppercase hex is NORMALIZED to lowercase (the digest the grant carries is always lowercase), not refused
    assert _binding(origin_secret_sha256="A" * 64).origin_secret_sha256 == "a" * 64


# --- the full cross-check (the data plane's AS-2g check) ----------------------------------------------
def test_grant_binds_origin_passes_for_a_correctly_bound_grant():
    signed = _signed()
    g = _bound_grant(origin_binding_digest(signed))
    ok, reason = grant_binds_origin(g, signed, _owner_root())
    assert ok and reason == "bound"


def test_grant_binds_origin_fails_closed_on_every_mismatch():
    signed = _signed()
    digest = origin_binding_digest(signed)
    root = _owner_root()
    # 1. grant carries the WRONG digest
    assert grant_binds_origin(_bound_grant("c" * 64), signed, root)[0] is False
    # 2. grant's origin differs from the binding's origin
    g_other_origin = _bound_grant(digest, origin=_origin(host="other.example.com"),
                                  origin_binding_sha256=digest)
    assert grant_binds_origin(g_other_origin, signed, root)[0] is False
    # 3. grant's edge_chain differs
    assert grant_binds_origin(_bound_grant(digest, edge_chain="x"), signed, root)[0] is False
    # 4. binding for a different subject
    other = _signed(_binding(subject=_subject(org_id="org_evil")))
    assert grant_binds_origin(_bound_grant(origin_binding_digest(other)), other, root)[0] is False  # subject != grant
    # 5. binding does not verify under the owner root (attacker-signed)
    forged = _signed(key=ATTACKER)
    assert grant_binds_origin(_bound_grant(origin_binding_digest(forged)), forged, root)[0] is False


def test_grant_binds_origin_treats_an_unbound_grant_as_unbound():
    signed = _signed()
    unbound = MonitoringAuthorityV2(subject=_subject(), capabilities=[MonitoringCapability.OBSERVE], epoch=1,
                                    not_before=_T0, not_after=_T_END,
                                    lease=MonitoringLease(not_before=_L0, not_after=_L1), instance_id="inst-01")
    ok, reason = grant_binds_origin(unbound, signed, _owner_root())
    assert ok is False and "unbound" in reason


def test_verify_is_fail_closed_on_a_quorum_collapsing_root_and_never_raises():
    signed = _signed()
    dup = TrustRoot(threshold=2, authorizers=[
        AuthorizerKey(key_id="a", name="a", public_key_b64=OWNER.public_key_b64),
        AuthorizerKey(key_id="b", name="b", public_key_b64=OWNER.public_key_b64)])
    ok, why = verify_aegis_origin_binding(signed, dup)
    assert ok is False and "duplicate" in why


# --- domain separation --------------------------------------------------------------------------------
def test_a_v2_grant_signature_can_never_replay_as_a_binding():
    # sign a v2 grant, then try to read its signature as a binding over a binding document with the same fields:
    # the domain tags differ, so the signature cannot verify across purposes.
    g = _bound_grant("a" * 64)
    sg = sign_monitoring_authority_v2(g, {"owner": OWNER.private_key_b64})
    assert aegis_origin_binding_signing_bytes(_binding()) != monitoring_authority_v2_signing_bytes(g)
    # a binding wrapper carrying the grant's signature does not verify (distinct signed bytes)
    crossed = SignedAegisOriginBinding(document=_binding(), signatures=sg.signatures)
    assert verify_aegis_origin_binding(crossed, _owner_root())[0] is False


def test_publish_path_is_content_addressed_and_carries_no_host_string():
    p = origin_binding_publish_path(_subject())
    assert p.endswith(".binding.json") and "api.example.com" not in p and "org_acme" not in p
    # distinct subjects -> distinct paths; same subject -> stable
    assert origin_binding_publish_path(_subject()) == p
    assert origin_binding_publish_path(_subject(host="www.example.com")) != p
