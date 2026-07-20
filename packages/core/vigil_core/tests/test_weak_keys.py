"""Reject non-canonical and low-order Ed25519 public keys at load.

A low-order (small-subgroup) public key admits a KEYLESS signature forgery — R = identity, S = 0
verifies under it for ANY message — so one such key registered under k key_ids would forge a k-of-n
threshold quorum with no private key at all. A non-canonical (y >= p) encoding gives one point
several byte-strings (a key-identity ambiguity). Neither is ever produced by a legitimate keygen, so
rejecting them has zero false positives while closing a real forgery against verify_threshold
(hence against every signed-evidence and witnessed-checkpoint verification built on it)."""

from __future__ import annotations

import base64

import pytest

from vigil_core import (
    AuthorizerKey,
    IntegrityError,
    Signature,
    TrustRoot,
    generate_keypair,
    sign,
)
from vigil_core.crypto import load_public_key, verify_one, verify_threshold

_P = 2**255 - 19


def _b64(b: bytes) -> str:
    return base64.b64encode(b).decode()


def _point(y: int, sign_bit: int) -> str:
    return _b64((y | (sign_bit << 255)).to_bytes(32, "little"))


IDENTITY = _point(1, 0)      # the neutral element (0, 1)
IDENTITY_ALT = _point(1, 1)  # SAME identity point, other sign-bit encoding (distinct bytes)
ZERO = _b64(bytes(32))       # order-4 point
ORDER2 = _b64(b"\xec" + b"\xff" * 31)  # p-1, order 2
FORGED_SIG = _b64(base64.b64decode(IDENTITY) + bytes(32))  # R = identity || S = 0


def test_low_order_public_keys_are_rejected():
    for key in (IDENTITY, IDENTITY_ALT, ZERO, ORDER2):
        with pytest.raises(IntegrityError, match="low-order"):
            load_public_key(key)


def test_the_keyless_forgery_is_refused_before_verification():
    # R = identity, S = 0 would verify for any message under the identity key — but the key is
    # rejected at load, so the forgery never reaches pyca's verify.
    with pytest.raises(IntegrityError):
        verify_one(IDENTITY, b"any message at all", FORGED_SIG)


def test_a_low_order_key_cannot_forge_a_threshold_quorum():
    # the real impact: one low-order key under two key_ids would otherwise forge a 2-of-3 quorum
    # with NO private key. verify_threshold now fails closed (raises on the weak key material).
    real = generate_keypair()
    tr = TrustRoot(threshold=2, authorizers=[
        AuthorizerKey(key_id="a", name="a", public_key_b64=IDENTITY),
        AuthorizerKey(key_id="b", name="b", public_key_b64=IDENTITY_ALT),
        AuthorizerKey(key_id="c", name="c", public_key_b64=real.public_key_b64)])
    sigs = [Signature(key_id="a", signature_b64=FORGED_SIG),
            Signature(key_id="b", signature_b64=FORGED_SIG)]
    with pytest.raises(IntegrityError):
        verify_threshold(b"forge me", sigs, tr)


def test_non_canonical_y_encodings_are_rejected():
    # y in [p, 2^255-1] are the only non-canonical encodings; all must be rejected, both sign bits.
    for k in range(19):
        with pytest.raises(IntegrityError, match="non-canonical"):
            load_public_key(_b64((_P + k).to_bytes(32, "little")))
        with pytest.raises(IntegrityError, match="non-canonical"):
            load_public_key(_b64(((_P + k) | (1 << 255)).to_bytes(32, "little")))


def test_all_real_keys_are_accepted_and_verify():
    # zero false positives: every legitimately-generated key loads and verifies as before.
    for _ in range(200):
        kp = generate_keypair()
        load_public_key(kp.public_key_b64)  # no raise
        assert verify_one(kp.public_key_b64, b"m", sign(kp.private_key_b64, b"m")) is True
