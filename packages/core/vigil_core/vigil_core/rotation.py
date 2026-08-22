"""vigil_core.rotation — pure re-encryption primitives for key rotation (audit W9-2).

The dependency-pure, both-env-importable heart of key rotation. Rotating a wrapping key (the TPM KEK) or
a data key (the spine DEK) means the SAME plaintext must move from being sealed under the OLD key to being
sealed under a FRESH key, and — crucially — the operation must be provably correct BEFORE anything on disk
is swapped, so a half-rotation can never leave data unreadable. This module holds ONLY that logic: given
old-key/new-key/blob it re-wraps and PROVES the result, holding no key custody and doing no I/O (WHERE the
KEK lives, and the atomic disk swap, are the caller's concern — kept out of this pure core so SIGIL's
offense-free import guarantee is unaffected, exactly like :mod:`vigil_core.sealing`).

The one invariant every rotation is built on — :func:`rewrap` — is a re-seal with TWO proofs baked in
before it returns:

  * POSITIVE control: the freshly re-wrapped blob opens under the NEW key to bytes IDENTICAL to what the
    OLD key opened. Material sealed before rotation still reads afterwards — no data loss.
  * NEGATIVE control: the freshly re-wrapped blob does NOT open under the OLD key. Rotation actually moved
    custody; the old key is genuinely retired, not a no-op that leaves both keys valid.

Either proof failing raises :class:`RotationError` and NOTHING is returned — the caller has staged no
change, so the trust root stays whole (fail-closed). "We do not roll our own crypto": the AEAD underneath
is :mod:`vigil_core.sealing` (pyca ``cryptography``).
"""
from __future__ import annotations

from .sealing import SealError, is_sealed, seal, unseal


class RotationError(Exception):
    """A key rotation could not be proven correct and was refused (fail-closed). Raised when a re-wrapped
    blob does not open under the new key to the exact original, when it STILL opens under the old key (a
    no-op rotation), or on malformed input. Never leaks key material in its message."""


def rewrap(old_key: bytes, new_key: bytes, blob: bytes, *, context: bytes = b"") -> bytes:
    """Move one sealed ``blob`` from ``old_key`` custody to ``new_key`` custody, under the SAME AEAD
    ``context``, and PROVE the move before returning.

    Opens ``blob`` under ``old_key`` (raising :class:`RotationError` if it cannot — a blob the old key
    can't read cannot be rotated), re-seals the plaintext under ``new_key``, then asserts BOTH controls:
    the new blob opens under ``new_key`` to the exact original plaintext (positive) AND does NOT open
    under ``old_key`` (negative). Returns the proven new blob. Fail-closed on any failure."""
    if not isinstance(blob, (bytes, bytearray)):
        raise RotationError("blob to rotate must be bytes")
    if old_key == new_key:
        raise RotationError("refusing to rotate to the SAME key — that is a no-op, not a rotation")
    try:
        plaintext = unseal(old_key, bytes(blob), context=context)
    except SealError as e:
        raise RotationError(f"cannot open the blob under the old key (wrong key/context or tampered): {e}") from e
    new_blob = seal(new_key, plaintext, context=context)
    # POSITIVE control: the new blob must open under the new key to the exact original plaintext.
    try:
        if unseal(new_key, new_blob, context=context) != plaintext:
            raise RotationError("re-wrapped blob did not round-trip under the new key (refusing to swap)")
    except SealError as e:
        raise RotationError(f"re-wrapped blob failed to open under the new key: {e}") from e
    # NEGATIVE control: the new blob must NOT open under the old key — proving custody actually moved.
    try:
        unseal(old_key, new_blob, context=context)
    except SealError:
        return new_blob  # expected: the old key can no longer read the re-wrapped blob
    raise RotationError("re-wrapped blob STILL opens under the old key — rotation would be a no-op")


def rewrap_or_seal(old_key: bytes, new_key: bytes, raw: bytes, *, context: bytes = b"") -> bytes:
    """Rotate ``raw`` under a new key whether it is currently SEALED or legacy PLAINTEXT.

    If ``raw`` is a vigil seal, delegate to :func:`rewrap` (both controls enforced). If it is legacy
    plaintext (a not-yet-migrated secret found during a rotation), seal it under ``new_key`` and verify it
    round-trips — a rotation MIGRATES plaintext to sealed rather than leaving it in the clear. Returns the
    proven new blob; fail-closed on any failure."""
    if is_sealed(raw):
        return rewrap(old_key, new_key, raw, context=context)
    new_blob = seal(new_key, bytes(raw), context=context)
    try:
        if unseal(new_key, new_blob, context=context) != bytes(raw):
            raise RotationError("sealed-from-plaintext blob did not round-trip under the new key")
    except SealError as e:
        raise RotationError(f"sealing legacy plaintext under the new key failed: {e}") from e
    return new_blob


def verify_opens_to(key: bytes, blob: bytes, expected_plaintext: bytes, *, context: bytes = b"") -> bool:
    """True iff ``blob`` opens under ``key`` (and ``context``) to EXACTLY ``expected_plaintext``. Total —
    any tamper / wrong-key / wrong-context returns False, never raises. A post-swap belt-and-suspenders
    check the caller runs against bytes re-read from disk."""
    try:
        return unseal(key, bytes(blob), context=context) == bytes(expected_plaintext)
    except SealError:
        return False
