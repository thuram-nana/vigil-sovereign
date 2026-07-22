"""Adversarial tests for vigil_core.sealing — the at-rest AEAD sealed box (audit G1).

Proves: round-trip; wrong KEK / wrong context / any tamper / truncation / bad magic / bad version all
FAIL CLOSED (SealError), never a silent wrong value; KEK-length + type validation; nonce freshness;
is_sealed shape check does not confuse plaintext for a seal.
"""
from __future__ import annotations

import pytest

from vigil_core import SealError, is_sealed, new_kek, seal, unseal


def test_round_trip():
    kek = new_kek()
    pt = b"owner-ed25519-private-key-bytes\x00\x01\xfe"
    blob = seal(kek, pt)
    assert blob != pt
    assert unseal(kek, blob) == pt


def test_round_trip_with_context():
    kek = new_kek()
    pt = b"sk-ant-SECRET"
    blob = seal(kek, pt, context=b"anthropic-api-key")
    assert unseal(kek, blob, context=b"anthropic-api-key") == pt


def test_wrong_kek_fails_closed():
    blob = seal(new_kek(), b"secret")
    with pytest.raises(SealError):
        unseal(new_kek(), blob)


def test_context_mismatch_fails_closed():
    kek = new_kek()
    blob = seal(kek, b"owner-key-bytes", context=b"owner")
    # a blob sealed as an owner key must NOT open as an operator key (domain/purpose binding)
    with pytest.raises(SealError):
        unseal(kek, blob, context=b"operator")


def test_bitflip_tamper_fails_closed():
    kek = new_kek()
    blob = bytearray(seal(kek, b"a" * 64))
    blob[-1] ^= 0x01  # flip a tag bit
    with pytest.raises(SealError):
        unseal(kek, bytes(blob))
    blob2 = bytearray(seal(kek, b"a" * 64))
    blob2[20] ^= 0x80  # flip a ciphertext bit
    with pytest.raises(SealError):
        unseal(kek, bytes(blob2))


def test_truncation_fails_closed():
    kek = new_kek()
    blob = seal(kek, b"payload")
    for cut in (0, 5, len(blob) - 1):
        with pytest.raises(SealError):
            unseal(kek, blob[:cut])


def test_bad_magic_and_version_fail_closed():
    kek = new_kek()
    blob = bytearray(seal(kek, b"x"))
    bad_magic = bytes(b"XXXX") + bytes(blob[4:])
    with pytest.raises(SealError):
        unseal(kek, bad_magic)
    blob[4] = 99  # bogus version
    with pytest.raises(SealError):
        unseal(kek, bytes(blob))


def test_kek_length_validated():
    for bad in (b"", b"short", b"x" * 31, b"x" * 33):
        with pytest.raises(SealError):
            seal(bad, b"p")
        with pytest.raises(SealError):
            unseal(bad, seal(new_kek(), b"p"))


def test_non_bytes_inputs_rejected():
    kek = new_kek()
    with pytest.raises(SealError):
        seal(kek, "a string is not bytes")  # type: ignore[arg-type]
    with pytest.raises(SealError):
        seal(kek, b"p", context="ctx-str")  # type: ignore[arg-type]


def test_nonce_is_fresh_per_seal():
    kek = new_kek()
    a = seal(kek, b"same")
    b = seal(kek, b"same")
    assert a != b  # random nonce ⇒ different ciphertext for identical plaintext
    assert unseal(kek, a) == unseal(kek, b) == b"same"


def test_is_sealed_does_not_confuse_plaintext():
    kek = new_kek()
    assert is_sealed(seal(kek, b"real")) is True
    assert is_sealed(b"") is False
    assert is_sealed(b"just some plaintext value") is False
    assert is_sealed(b"VSL1") is False  # magic alone, too short to be a real seal
    assert is_sealed("not-bytes") is False  # type: ignore[arg-type]
