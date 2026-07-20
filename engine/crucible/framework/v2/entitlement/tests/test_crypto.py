"""Tests for entitlement.crypto — Ed25519 primitives and threshold verify."""

from __future__ import annotations

import base64

import pytest

from vigil_core import IntegrityError
from .. import crypto
from ..models import AuthorizerKey, Signature, TrustRoot


def _authorizer(key_id: str) -> tuple[AuthorizerKey, str]:
    kp = crypto.generate_keypair()
    return (
        AuthorizerKey(key_id=key_id, name=key_id, public_key_b64=kp.public_key_b64),
        kp.private_key_b64,
    )


def test_sign_verify_roundtrip() -> None:
    kp = crypto.generate_keypair()
    msg = b"the exact bytes"
    sig = crypto.sign(kp.private_key_b64, msg)
    assert crypto.verify_one(kp.public_key_b64, msg, sig) is True


def test_verify_rejects_wrong_message() -> None:
    kp = crypto.generate_keypair()
    sig = crypto.sign(kp.private_key_b64, b"message A")
    assert crypto.verify_one(kp.public_key_b64, b"message B", sig) is False


def test_verify_rejects_wrong_key() -> None:
    signer = crypto.generate_keypair()
    other = crypto.generate_keypair()
    sig = crypto.sign(signer.private_key_b64, b"m")
    assert crypto.verify_one(other.public_key_b64, b"m", sig) is False


def test_malformed_public_key_raises() -> None:
    with pytest.raises(IntegrityError):
        crypto.verify_one("not-base64!!", b"m", base64.b64encode(b"x" * 64).decode())


def test_malformed_signature_length_raises() -> None:
    kp = crypto.generate_keypair()
    short_sig = base64.b64encode(b"too short").decode()
    with pytest.raises(IntegrityError):
        crypto.verify_one(kp.public_key_b64, b"m", short_sig)


def test_threshold_met_two_of_three() -> None:
    a0, p0 = _authorizer("a0")
    a1, p1 = _authorizer("a1")
    a2, _p2 = _authorizer("a2")
    tr = TrustRoot(threshold=2, authorizers=[a0, a1, a2])
    msg = b"canonical"
    sigs = [
        Signature(key_id="a0", signature_b64=crypto.sign(p0, msg)),
        Signature(key_id="a1", signature_b64=crypto.sign(p1, msg)),
    ]
    res = crypto.verify_threshold(msg, sigs, tr)
    assert res.satisfied is True
    assert set(res.valid_signers) == {"a0", "a1"}


def test_threshold_not_met_one_of_two() -> None:
    a0, p0 = _authorizer("a0")
    a1, _p1 = _authorizer("a1")
    tr = TrustRoot(threshold=2, authorizers=[a0, a1])
    msg = b"canonical"
    sigs = [Signature(key_id="a0", signature_b64=crypto.sign(p0, msg))]
    res = crypto.verify_threshold(msg, sigs, tr)
    assert res.satisfied is False


def test_unknown_signer_does_not_count() -> None:
    a0, _p0 = _authorizer("a0")
    stranger = crypto.generate_keypair()
    tr = TrustRoot(threshold=1, authorizers=[a0])
    msg = b"canonical"
    sigs = [Signature(key_id="stranger", signature_b64=crypto.sign(stranger.private_key_b64, msg))]
    res = crypto.verify_threshold(msg, sigs, tr)
    assert res.satisfied is False
    assert res.valid_signers == ()


def test_duplicate_signer_counts_once() -> None:
    a0, p0 = _authorizer("a0")
    a1, _p1 = _authorizer("a1")
    tr = TrustRoot(threshold=2, authorizers=[a0, a1])
    msg = b"canonical"
    # Same authoriser signs twice; must not satisfy a 2-of-2 threshold.
    sigs = [
        Signature(key_id="a0", signature_b64=crypto.sign(p0, msg)),
        Signature(key_id="a0", signature_b64=crypto.sign(p0, msg)),
    ]
    res = crypto.verify_threshold(msg, sigs, tr)
    assert res.satisfied is False
    assert res.valid_signers == ("a0",)


def test_forged_signature_with_known_key_id_rejected() -> None:
    # An attacker presents a real key_id but a signature they cannot
    # produce (signed by a key they control). It must not count.
    a0, _p0 = _authorizer("a0")
    attacker = crypto.generate_keypair()
    tr = TrustRoot(threshold=1, authorizers=[a0])
    msg = b"canonical"
    sigs = [Signature(key_id="a0", signature_b64=crypto.sign(attacker.private_key_b64, msg))]
    res = crypto.verify_threshold(msg, sigs, tr)
    assert res.satisfied is False
