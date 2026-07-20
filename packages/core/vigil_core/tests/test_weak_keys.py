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


IDENTITY = _point(1, 0)      # the neutral element (0, 1), order 1
IDENTITY_ALT = _point(1, 1)  # SAME identity point, other sign-bit encoding (distinct bytes)
ZERO = _b64(bytes(32))       # y=0, order 4
ORDER2 = _b64(b"\xec" + b"\xff" * 31)  # p-1, order 2
FORGED_SIG = _b64(base64.b64decode(IDENTITY) + bytes(32))  # R = identity || S = 0

# The full edwards25519 8-torsion subgroup (all points of order dividing 8), each in BOTH sign-bit
# encodings — every one must be rejected, or the keyless forgery survives for that point.
_ORDER8_A = bytes.fromhex("26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05")
_ORDER8_B = bytes.fromhex("c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a")
_TORSION = (
    bytes(32),                       # y=0, order 4 (sign 0)
    b"\x00" * 31 + b"\x80",          # y=0, order 4 (sign 1) — sign-agnostic blocklist must still catch
    b"\x01" + bytes(31),             # identity, order 1 (sign 0)
    b"\x01" + bytes(30) + b"\x80",   # identity, order 1 (sign 1)
    b"\xec" + b"\xff" * 31,          # p-1, order 2 (sign 0)
    b"\xec" + b"\xff" * 30 + b"\x7f",  # p-1, order 2 (sign 1 cleared to 0x7f)
    _ORDER8_A,                        # order 8 (sign 0)
    _ORDER8_A[:31] + bytes([_ORDER8_A[31] | 0x80]),   # order 8 (sign 1)
    _ORDER8_B,                        # order 8 (sign 0)
    _ORDER8_B[:31] + bytes([_ORDER8_B[31] | 0x80]),   # order 8 (sign 1)
)


def test_low_order_public_keys_are_rejected():
    for key in (IDENTITY, IDENTITY_ALT, ZERO, ORDER2):
        with pytest.raises(IntegrityError, match="low-order"):
            load_public_key(key)


def test_the_entire_8_torsion_subgroup_is_rejected():
    # explicit completeness: every low-order point (orders 1,2,4,8), both sign encodings, is barred.
    for raw in _TORSION:
        assert len(raw) == 32
        with pytest.raises(IntegrityError, match="low-order"):  # all have canonical y<p → low-order
            load_public_key(_b64(raw))


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
