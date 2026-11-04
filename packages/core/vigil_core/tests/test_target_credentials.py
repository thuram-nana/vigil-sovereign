"""The owner-signed TEST-CREDENTIAL roster core (vigil_core.target_credentials) — W3's signed-credential
source for the BOLA/IDOR autoseeder.

Locks: domain-tagged + format-stable signing bytes (a golden prefix — a canonicalisation change that would
invalidate every prior signature fails here); owner sign -> verify round-trip; a tampered role / header /
slug FAILS (fail-closed); malformed signature material is a clean (False, reason), never a crash; threshold
not met fails; a quorum-collapsing (duplicate-pubkey) trust root is rejected; the model validators (one
credential per role, positive window); headers_for; and that signing pulls in NO framework / strix (the
two-env boundary that makes it usable in a sovereign venv).
"""

from __future__ import annotations

import subprocess
import sys
from datetime import datetime, timedelta, timezone

import pytest

from vigil_core import AuthorizerKey, TrustRoot, generate_keypair
from vigil_core.target_credentials import (
    CredentialHeader,
    CredentialRole,
    SignedTargetCredentials,
    TargetCredentials,
    AccountCredential,
    sign_target_credentials,
    target_credentials_signing_bytes,
    verify_target_credentials,
)

_TS = datetime(2026, 1, 2, 3, 4, 5, tzinfo=timezone.utc)


def _doc(**over) -> TargetCredentials:
    base = dict(
        engagement_slug="apme-cm",
        credentials=[
            AccountCredential(role=CredentialRole.ATTACKER,
                           auth_headers=[CredentialHeader(name="Cookie", value="sid=attacker")]),
            AccountCredential(role=CredentialRole.VICTIM,
                           auth_headers=[CredentialHeader(name="Cookie", value="sid=victim")]),
            AccountCredential(role=CredentialRole.UNAUTHORIZED_PEER,
                           auth_headers=[CredentialHeader(name="Authorization", value="Bearer peer")]),
        ],
    )
    base.update(over)
    return TargetCredentials(**base)


def _owner_root():
    kp = generate_keypair()
    tr = TrustRoot(threshold=1, authorizers=[
        AuthorizerKey(key_id="owner", name="owner", public_key_b64=kp.public_key_b64)])
    return kp, tr


def test_signing_bytes_are_domain_tagged_and_stable():
    b = target_credentials_signing_bytes(_doc())
    assert b.startswith(b"crucible-target-credentials-v1\x00")
    # deterministic: identical document -> identical bytes
    assert target_credentials_signing_bytes(_doc()) == b
    # a distinct domain from the engagement authority (no cross-kind replay)
    assert b"crucible-authority-v1" not in b


def test_sign_then_verify_round_trip():
    kp, tr = _owner_root()
    signed = sign_target_credentials(_doc(), {"owner": kp.private_key_b64})
    ok, reason = verify_target_credentials(signed, tr)
    assert ok, reason


def test_tampered_document_fails_closed():
    kp, tr = _owner_root()
    signed = sign_target_credentials(_doc(), {"owner": kp.private_key_b64})
    # swap the victim cookie — the signature no longer matches the canonical bytes
    tampered = signed.model_copy(update={"document": _doc(credentials=[
        AccountCredential(role=CredentialRole.ATTACKER,
                       auth_headers=[CredentialHeader(name="Cookie", value="sid=attacker")]),
        AccountCredential(role=CredentialRole.VICTIM,
                       auth_headers=[CredentialHeader(name="Cookie", value="sid=STOLEN")]),
        AccountCredential(role=CredentialRole.UNAUTHORIZED_PEER,
                       auth_headers=[CredentialHeader(name="Authorization", value="Bearer peer")]),
    ])})
    ok, reason = verify_target_credentials(tampered, tr)
    assert not ok and reason


def test_malformed_signature_is_failclosed_not_a_crash():
    from vigil_core.models import Signature
    _, tr = _owner_root()
    bad = SignedTargetCredentials(document=_doc(),
                                  signatures=[Signature(key_id="owner", signature_b64="not-base64!!")])
    ok, reason = verify_target_credentials(bad, tr)        # must not raise
    assert not ok and "malformed" in reason.lower()


def test_threshold_not_met_fails():
    kp1, _ = _owner_root()
    kp2 = generate_keypair()
    tr2 = TrustRoot(threshold=2, authorizers=[
        AuthorizerKey(key_id="owner", name="owner", public_key_b64=kp1.public_key_b64),
        AuthorizerKey(key_id="second", name="second", public_key_b64=kp2.public_key_b64)])
    signed = sign_target_credentials(_doc(), {"owner": kp1.private_key_b64})   # only 1 of 2
    ok, reason = verify_target_credentials(signed, tr2)
    assert not ok and reason


def test_quorum_collapsing_trust_root_is_rejected():
    kp, _ = _owner_root()
    dup = TrustRoot(threshold=2, authorizers=[
        AuthorizerKey(key_id="a", name="a", public_key_b64=kp.public_key_b64),
        AuthorizerKey(key_id="b", name="b", public_key_b64=kp.public_key_b64)])   # same pubkey, 2 ids
    signed = sign_target_credentials(_doc(), {"a": kp.private_key_b64})
    ok, reason = verify_target_credentials(signed, dup)
    assert not ok and "collapse" in reason.lower()


def test_headers_for_returns_pairs_or_empty():
    doc = _doc()
    assert doc.headers_for(CredentialRole.ATTACKER) == [("Cookie", "sid=attacker")]
    assert doc.headers_for(CredentialRole.VICTIM) == [("Cookie", "sid=victim")]
    assert doc.headers_for(CredentialRole.UNAUTHORIZED_PEER) == [("Authorization", "Bearer peer")]
    # a roster missing a role returns [] for it (not an error)
    one = _doc(credentials=[AccountCredential(role=CredentialRole.VICTIM,
                                           auth_headers=[CredentialHeader(name="Cookie", value="v")])])
    assert one.headers_for(CredentialRole.ATTACKER) == []
    assert one.headers_for(CredentialRole.VICTIM) == [("Cookie", "v")]


def test_duplicate_role_is_rejected():
    with pytest.raises(ValueError, match="duplicate credential role"):
        _doc(credentials=[
            AccountCredential(role=CredentialRole.VICTIM,
                           auth_headers=[CredentialHeader(name="Cookie", value="a")]),
            AccountCredential(role=CredentialRole.VICTIM,
                           auth_headers=[CredentialHeader(name="Cookie", value="b")])])


def test_validity_window_must_be_positive_and_optional():
    # a valid window is accepted
    _doc(not_before=_TS, not_after=_TS + timedelta(hours=8))
    # no window is fine (both None)
    _doc()
    # a non-positive window is refused
    with pytest.raises(ValueError, match="not_after must be strictly after not_before"):
        _doc(not_before=_TS, not_after=_TS)


def test_empty_roster_and_headerless_credential_are_refused():
    with pytest.raises(ValueError):
        _doc(credentials=[])                              # min_length=1
    with pytest.raises(ValueError):
        AccountCredential(role=CredentialRole.VICTIM, auth_headers=[])   # min_length=1


def test_signing_pulls_in_no_framework_or_strix():
    """The two-env boundary: the sovereign owner signs with vigil_core ALONE — importing + using the
    primitive must not drag in framework / strix (which a sovereign venv does not install)."""
    code = (
        "import sys; import vigil_core.target_credentials as m;"
        "from vigil_core import generate_keypair, AuthorizerKey, TrustRoot;"
        "kp=generate_keypair();"
        "d=m.TargetCredentials(engagement_slug='s', credentials=[m.AccountCredential(role=m.CredentialRole.VICTIM,"
        "auth_headers=[m.CredentialHeader(name='Cookie', value='x')])]);"
        "s=m.sign_target_credentials(d, {'owner': kp.private_key_b64});"
        "tr=TrustRoot(threshold=1, authorizers=[AuthorizerKey(key_id='owner', name='owner', public_key_b64=kp.public_key_b64)]);"
        "ok,_=m.verify_target_credentials(s, tr); assert ok;"
        "bad=[x for x in sys.modules if x=='framework' or x.startswith('framework.') or x=='strix' or x.startswith('strix.')];"
        "assert not bad, bad; print('PURE')"
    )
    r = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    assert "PURE" in r.stdout
