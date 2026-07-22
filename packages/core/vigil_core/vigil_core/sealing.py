"""vigil_core.sealing — authenticated encryption of secrets AT REST (an AEAD "sealed box").

The confidentiality primitive for VIGIL's at-rest trust roots — private keys, the LLM API key, service
secrets, and (a later slice) spine payloads. Today those live as PLAINTEXT behind only 0600 file perms;
this closes that gap (audit G1). It is deliberately PURE: given a 32-byte key-encryption-key (KEK) it
seals/opens a byte blob with ChaCha20-Poly1305 AEAD, holding NO key custody and doing NO I/O. WHERE the
KEK comes from (a TPM-sealed provider, an injected test key) is the caller's concern, kept out of this
dependency-pure core so SIGIL's offense-free import guarantee is unaffected.

Guarantees:
  * Confidentiality + integrity: the ciphertext is authenticated; any bit-flip, truncation, wrong KEK,
    version bump, or context mismatch fails to open (raises :class:`SealError`) — it NEVER returns a
    value that was not exactly what was sealed under this KEK and context.
  * Domain/context binding: every seal binds a fixed domain tag + a caller ``context`` into the AEAD
    additional-authenticated-data, so a blob sealed as (say) an owner key cannot be opened as an
    operator key, and a blob from one field cannot be swapped into another.
  * Fail-closed + total on untrusted bytes: opening malformed/tampered input raises :class:`SealError`,
    never a silent wrong value and never an uncaught crypto exception.

Nonce discipline: a fresh 96-bit random nonce per seal (``os.urandom``). Safe for the LOW-VOLUME
key/secret use here (birthday-bound far beyond any realistic count of sealed secrets under one KEK). The
higher-volume spine-payload slice will use a per-record data key rather than reuse one KEK across many
records. "We do not roll our own crypto": the AEAD is pyca ``cryptography``.
"""
from __future__ import annotations

import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

_MAGIC = b"VSL1"                      # VIGIL SeaL, format 1
_VERSION = 1
_KEK_LEN = 32
_NONCE_LEN = 12
_TAG_LEN = 16
_HEADER_LEN = len(_MAGIC) + 1 + _NONCE_LEN
_DOMAIN = b"vigil-core/sealing/v1"


class SealError(Exception):
    """A seal could not be opened: tampered, truncated, wrong KEK, wrong context, or malformed. Also
    raised on a malformed KEK/plaintext at seal time. Never leaks key material in its message."""


def _check_kek(kek: bytes) -> None:
    if not isinstance(kek, (bytes, bytearray)) or len(kek) != _KEK_LEN:
        raise SealError(f"KEK must be exactly {_KEK_LEN} bytes")


def _aad(context: bytes) -> bytes:
    if not isinstance(context, (bytes, bytearray)):
        raise SealError("context must be bytes")
    # domain tag + NUL + caller context — binds the blob to its purpose so it can't be repurposed.
    return _DOMAIN + b"\x00" + bytes(context)


def new_kek() -> bytes:
    """A fresh random 32-byte KEK, for provisioning a new sealed-KEK. Not persisted by this module."""
    return os.urandom(_KEK_LEN)


def seal(kek: bytes, plaintext: bytes, *, context: bytes = b"") -> bytes:
    """Encrypt ``plaintext`` under ``kek`` (32 bytes), binding ``context`` into the AEAD AAD. Returns a
    self-describing blob ``magic || version || nonce(12) || ct+tag``. Raises :class:`SealError` on a bad
    KEK/plaintext/context."""
    _check_kek(kek)
    if not isinstance(plaintext, (bytes, bytearray)):
        raise SealError("plaintext must be bytes")
    aad = _aad(context)
    nonce = os.urandom(_NONCE_LEN)
    ct = ChaCha20Poly1305(bytes(kek)).encrypt(nonce, bytes(plaintext), aad)
    return _MAGIC + bytes((_VERSION,)) + nonce + ct


def unseal(kek: bytes, blob: bytes, *, context: bytes = b"") -> bytes:
    """Open a blob produced by :func:`seal` under the SAME ``kek`` and ``context``. Raises
    :class:`SealError` on any tamper / wrong-key / wrong-context / malformation; never returns an
    unauthenticated value, never raises a raw crypto exception."""
    _check_kek(kek)
    if not isinstance(blob, (bytes, bytearray)) or len(blob) < _HEADER_LEN + _TAG_LEN:
        raise SealError("sealed blob is malformed or truncated")
    b = bytes(blob)
    if b[: len(_MAGIC)] != _MAGIC:
        raise SealError("sealed blob has a bad magic (not a vigil seal)")
    if b[len(_MAGIC)] != _VERSION:
        raise SealError(f"unsupported seal version {b[len(_MAGIC)]}")
    aad = _aad(context)
    nonce = b[len(_MAGIC) + 1 : _HEADER_LEN]
    ct = b[_HEADER_LEN:]
    try:
        return ChaCha20Poly1305(bytes(kek)).decrypt(nonce, ct, aad)
    except InvalidTag as e:
        raise SealError("sealed blob failed authentication (wrong KEK/context or tampered)") from e
    except Exception as e:  # noqa: BLE001 — any crypto/parse error is a fail-closed SealError, never a crash
        raise SealError(f"could not open sealed blob: {type(e).__name__}") from e


def is_sealed(blob: bytes) -> bool:
    """True iff ``blob`` looks like a vigil seal (magic + known version + minimum length). Lets callers
    migrate a store transparently (open sealed bytes, pass through legacy plaintext during a one-time
    migration) WITHOUT ever mistaking arbitrary plaintext for a seal — the AEAD tag is still the real
    gate; this is only a fast shape check."""
    return (
        isinstance(blob, (bytes, bytearray))
        and len(blob) >= _HEADER_LEN + _TAG_LEN
        and bytes(blob[: len(_MAGIC)]) == _MAGIC
        and blob[len(_MAGIC)] == _VERSION
    )
