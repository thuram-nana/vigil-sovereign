"""Tests for vigil_core.rotation — the pure re-encryption primitives behind key rotation (audit W9-2).

Proves the ONE invariant every rotation is built on: rewrap moves a sealed blob from old-key custody to
new-key custody with BOTH controls enforced — the new blob opens under the new key to the exact original
(no data loss) AND no longer opens under the old key (a real rotation, not a no-op). Any failure raises
RotationError and returns nothing (fail-closed). Includes the negative controls the acceptance criteria
demand: a no-op same-key rotation is refused, and a blob the old key cannot even read is refused.
"""
from __future__ import annotations

import pytest

from vigil_core.rotation import RotationError, rewrap, rewrap_or_seal, verify_opens_to
from vigil_core.sealing import is_sealed, new_kek, seal, unseal

CTX = b"vigil/test/rotation"


def test_rewrap_new_key_reads_and_old_key_no_longer_decrypts():
    old, new = new_kek(), new_kek()
    secret = b"the-32-byte-DEK-or-owner-seed-!!"
    blob = seal(old, secret, context=CTX)

    rotated = rewrap(old, new, blob, context=CTX)

    # POSITIVE: material sealed before rotation still reads, under the NEW key, to the exact bytes.
    assert unseal(new, rotated, context=CTX) == secret
    # NEGATIVE control: the old key can no longer open the re-wrapped blob (custody actually moved).
    with pytest.raises(Exception):
        unseal(old, rotated, context=CTX)


def test_rewrap_refuses_same_key_noop():
    k = new_kek()
    blob = seal(k, b"x" * 32, context=CTX)
    with pytest.raises(RotationError):
        rewrap(k, k, blob, context=CTX)  # rotating to the SAME key is a no-op, not a rotation


def test_rewrap_refuses_blob_old_key_cannot_open():
    old, new, other = new_kek(), new_kek(), new_kek()
    # a blob sealed under `other` — `old` cannot open it, so it cannot be rotated old->new.
    blob = seal(other, b"y" * 32, context=CTX)
    with pytest.raises(RotationError):
        rewrap(old, new, blob, context=CTX)


def test_rewrap_refuses_wrong_context():
    old, new = new_kek(), new_kek()
    blob = seal(old, b"z" * 32, context=b"context-A")
    with pytest.raises(RotationError):
        rewrap(old, new, blob, context=b"context-B")  # cannot open under the wrong context => refused


def test_rewrap_or_seal_migrates_legacy_plaintext():
    new = new_kek()
    plaintext = b"legacy-plaintext-key-bytes-here!"
    out = rewrap_or_seal(new_kek(), new, plaintext, context=CTX)
    assert is_sealed(out)                                   # now sealed
    assert unseal(new, out, context=CTX) == plaintext       # opens to the exact original under the new key


def test_rewrap_or_seal_rewraps_a_seal():
    old, new = new_kek(), new_kek()
    blob = seal(old, b"a" * 32, context=CTX)
    out = rewrap_or_seal(old, new, blob, context=CTX)
    assert unseal(new, out, context=CTX) == b"a" * 32
    with pytest.raises(Exception):
        unseal(old, out, context=CTX)


def test_verify_opens_to_is_total():
    k = new_kek()
    blob = seal(k, b"payload-bytes", context=CTX)
    assert verify_opens_to(k, blob, b"payload-bytes", context=CTX) is True
    assert verify_opens_to(k, blob, b"WRONG", context=CTX) is False      # wrong expected plaintext
    assert verify_opens_to(new_kek(), blob, b"payload-bytes", context=CTX) is False  # wrong key
    assert verify_opens_to(k, b"not-a-seal", b"payload-bytes", context=CTX) is False  # malformed => False, no raise
