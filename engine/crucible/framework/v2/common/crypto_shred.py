"""
common.crypto_shred — per-engagement crypto-shredding of at-rest evidence (W16-8).

THE POLICY COLLISION this resolves (ADR knowledge/decisions/0008): the event spine is
append-only by SQLite trigger (``agents/schema.sql``), yet captured evidence contains real
``Authorization`` / ``Cookie`` headers and response bodies (``common/paths.evidence_dir``).
A DELETE/UPDATE to satisfy a data-protection erasure request would either be refused by the
trigger or, if the trigger were relaxed, would destroy the append-only / tamper-evidence
guarantee. Neither is acceptable.

THE MECHANISM — crypto-shredding. Credential-bearing evidence is SEALED under a per-engagement
Data Encryption Key (DEK). The DEK is held OUTSIDE the append-only spine, in a shreddable
keystore (``paths.evidence_keys_dir``). Erasure = destroy the DEK. Afterwards:

  * any SEALED ciphertext left behind — on disk, or in an off-host backup of the CIPHERTEXT (never
    the key) — is cryptographically UNRECOVERABLE. NB: sealing a spine-payload excerpt is SUPPORTED
    (``seal_text``) but seal-at-capture is NOT yet wired into the live executor, so credential
    excerpts already written to the append-only spine are stored in PLAINTEXT and are not erasable by
    this mechanism (documented in PRIVACY.md "Honest scope"; wiring is a staged follow-up); and
  * every append-only row is byte-for-byte UNCHANGED and the spine hash-chain
    (``agents/spine_chain``) still verifies, because the chain digest covers the bytes that were
    stored, which erasure never touches.

So tamper-evidence SURVIVES erasure: nothing is deleted or rewritten in the spine; only a key
that lives elsewhere is destroyed.

AEAD: AES-256-GCM (``cryptography``). Sealed blob layout::

    b"EVS1" | nonce(12 bytes) | ciphertext+tag

The engagement slug is bound in as GCM associated data, so a blob sealed for engagement A can
never be unsealed as B even if both keys exist (defence in depth against cross-engagement
replay). The DEK never appears in the sealed blob. Sealing uses a fresh random nonce, so it is
NOT byte-deterministic — a sealed excerpt is a stable opaque token for one capture that reveals
nothing about the plaintext.

Fail-closed: a missing DEK makes ``unseal`` raise ``EvidenceShredded`` (there is nothing to
decrypt with — the correct post-erasure state); a tampered/wrong-engagement blob raises
``CryptoShredError`` (AEAD authentication failure), never a silent partial/garbage return.

Offense-plane, sigil-free, offline. No network, no wallclock in the ciphertext.
"""

from __future__ import annotations

import base64
import hashlib
import os
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from . import paths

# Sealed-blob framing.
_MAGIC = b"EVS1"
_NONCE_BYTES = 12
_KEY_BYTES = 32                       # AES-256
_ALGORITHM = "AES-256-GCM"
_TEXT_PREFIX = "evs1:"                # base64 text wrapper for embedding in a JSON/spine field

# Engagement slugs are used as DEK filenames; keep them filesystem-safe and reject anything
# that could traverse out of the keystore. Slugs in this framework are already constrained to
# this set (see targets/ dir names); the guard is defence in depth, and it FAILS CLOSED.
_SAFE_SLUG = re.compile(r"^[A-Za-z0-9._-]+$")


class CryptoShredError(RuntimeError):
    """A crypto-shred operation failed (bad blob, auth failure, unsafe engagement id)."""


class EvidenceShredded(CryptoShredError):
    """The DEK is gone — the sealed evidence has been crypto-shredded and is unrecoverable.

    A subclass of ``CryptoShredError`` so broad callers still catch it, but distinct so an
    erasure test / audit can assert the *erased* state specifically rather than a generic
    decrypt failure."""


def _now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _safe_slug(engagement: str) -> str:
    slug = str(engagement)
    if not _SAFE_SLUG.match(slug):
        raise CryptoShredError(
            f"unsafe engagement id for a DEK filename: {engagement!r} "
            f"(allowed: letters, digits, '.', '_', '-')")
    return slug


@dataclass(frozen=True)
class ShredReceipt:
    """Proof of a crypto-shred: WHICH key was destroyed (by fingerprint, not the key itself),
    WHEN, and whether a key was actually present to destroy. The fingerprint lets an audit bind
    the receipt to the sealed ciphertext without ever exposing the (now-destroyed) key."""

    engagement: str
    algorithm: str
    key_fingerprint: str      # sha256 hex of the destroyed DEK, or "" if none was present
    shredded_at: str          # iso-8601 UTC
    shredded: bool            # True iff a DEK existed and was destroyed by this call

    def to_dict(self) -> dict[str, object]:
        return {
            "engagement": self.engagement,
            "algorithm": self.algorithm,
            "key_fingerprint": self.key_fingerprint,
            "shredded_at": self.shredded_at,
            "shredded": self.shredded,
        }


class EvidenceKeyring:
    """Per-engagement DEK store backed by a shreddable, owner-only keystore directory.

    One 32-byte DEK per engagement, at ``<keys_dir>/<slug>.dek`` (0600). The directory is the
    single thing an erasure destroys; it lives OUTSIDE the append-only spine precisely so it
    CAN be destroyed without touching an append-only row."""

    def __init__(self, *, keys_dir: Path | None = None) -> None:
        self.keys_dir = keys_dir or paths.evidence_keys_dir()

    # ---- key lifecycle ----

    def _key_path(self, engagement: str) -> Path:
        return self.keys_dir / f"{_safe_slug(engagement)}.dek"

    def has_key(self, engagement: str) -> bool:
        return self._key_path(engagement).is_file()

    def _load_key(self, engagement: str, *, create: bool) -> bytes:
        kp = self._key_path(engagement)
        if kp.is_file():
            dek = kp.read_bytes()
            if len(dek) != _KEY_BYTES:
                raise CryptoShredError(
                    f"DEK for {engagement!r} is {len(dek)} bytes, expected {_KEY_BYTES}")
            return dek
        if not create:
            # No key on disk. For an unseal this is the post-erasure state: fail closed.
            raise EvidenceShredded(
                f"no DEK for engagement {engagement!r} — evidence is crypto-shredded "
                f"(or was never sealed); nothing to decrypt with")
        dek = os.urandom(_KEY_BYTES)
        paths.secure_dir(self.keys_dir)                 # 0700 keystore dir (only if we create it)
        paths.secure_write(kp, dek)                     # 0600, no world-readable window
        return dek

    def key_fingerprint(self, engagement: str) -> str:
        """sha256 hex of the engagement's DEK, or '' if none exists. Identifies the key
        without exposing it — bound into the ShredReceipt."""
        kp = self._key_path(engagement)
        if not kp.is_file():
            return ""
        return hashlib.sha256(kp.read_bytes()).hexdigest()

    def shred(self, engagement: str) -> ShredReceipt:
        """Destroy the engagement's DEK. Best-effort overwrite of the key file with random
        bytes (fsync'd) before unlinking — but crypto-shredding does NOT rely on the overwrite
        succeeding on the underlying media: unlinking the only copy of the key is what renders
        the ciphertext unrecoverable, including any off-host backup copy of the ciphertext.
        Idempotent: shredding an already-absent key returns ``shredded=False``."""
        kp = self._key_path(engagement)
        if not kp.is_file():
            return ShredReceipt(
                engagement=str(engagement), algorithm=_ALGORITHM,
                key_fingerprint="", shredded_at=_now_iso(), shredded=False)
        dek = kp.read_bytes()
        fp = hashlib.sha256(dek).hexdigest()
        try:
            with open(kp, "r+b", buffering=0) as f:
                f.write(os.urandom(len(dek)))
                f.flush()
                os.fsync(f.fileno())
        except OSError:
            pass                                        # overwrite is best-effort; unlink is authoritative
        kp.unlink()
        return ShredReceipt(
            engagement=str(engagement), algorithm=_ALGORITHM,
            key_fingerprint=fp, shredded_at=_now_iso(), shredded=True)

    # ---- seal / unseal (bytes) ----

    def seal(self, engagement: str, plaintext: bytes) -> bytes:
        """Seal ``plaintext`` under the engagement DEK (creating the DEK on first use). Returns
        the framed sealed blob. Binds the engagement slug as AEAD associated data."""
        if not isinstance(plaintext, (bytes, bytearray)):
            raise CryptoShredError("seal() takes bytes; encode text first")
        dek = self._load_key(engagement, create=True)
        nonce = os.urandom(_NONCE_BYTES)
        ct = AESGCM(dek).encrypt(nonce, bytes(plaintext), _safe_slug(engagement).encode("utf-8"))
        return _MAGIC + nonce + ct

    def unseal(self, engagement: str, blob: bytes) -> bytes:
        """Recover the plaintext from a sealed blob. Raises ``EvidenceShredded`` if the DEK is
        gone (post-erasure), ``CryptoShredError`` on a malformed blob or AEAD auth failure
        (tamper / wrong engagement) — never a silent garbage return."""
        if not isinstance(blob, (bytes, bytearray)) or len(blob) < len(_MAGIC) + _NONCE_BYTES + 16:
            raise CryptoShredError("sealed blob is too short or not bytes")
        blob = bytes(blob)
        if blob[: len(_MAGIC)] != _MAGIC:
            raise CryptoShredError("sealed blob is missing the EVS1 magic")
        dek = self._load_key(engagement, create=False)   # raises EvidenceShredded if absent
        nonce = blob[len(_MAGIC): len(_MAGIC) + _NONCE_BYTES]
        ct = blob[len(_MAGIC) + _NONCE_BYTES:]
        try:
            return AESGCM(dek).decrypt(nonce, ct, _safe_slug(engagement).encode("utf-8"))
        except InvalidTag as e:
            raise CryptoShredError(
                "sealed evidence failed authentication — tampered ciphertext or wrong "
                "engagement") from e

    # ---- seal / unseal (text, for embedding in a JSON / spine payload field) ----

    def seal_text(self, engagement: str, plaintext: str) -> str:
        """Seal a credential-bearing STRING destined for the append-only spine (an
        ``ObservationPayload.raw_excerpt`` / ``ResultPayload.body_excerpt`` that may reflect a
        token or Set-Cookie). Returns a base64 text token safe to store in a JSON field. The
        spine digest then covers this opaque token; erasing the DEK renders it unrecoverable
        while the row and the chain stay unchanged."""
        blob = self.seal(engagement, plaintext.encode("utf-8"))
        return _TEXT_PREFIX + base64.b64encode(blob).decode("ascii")

    def unseal_text(self, engagement: str, token: str) -> str:
        if not isinstance(token, str) or not token.startswith(_TEXT_PREFIX):
            raise CryptoShredError("not a sealed-text token (missing 'evs1:' prefix)")
        try:
            blob = base64.b64decode(token[len(_TEXT_PREFIX):], validate=True)
        except (ValueError, TypeError) as e:
            raise CryptoShredError("sealed-text token is not valid base64") from e
        return self.unseal(engagement, blob).decode("utf-8")


def is_sealed(blob: bytes | str) -> bool:
    """True if ``blob`` is a crypto-shred sealed artifact (bytes blob or text token). Lets an
    idempotent erasure skip already-sealed files without a key."""
    if isinstance(blob, (bytes, bytearray)):
        return bytes(blob[: len(_MAGIC)]) == _MAGIC
    if isinstance(blob, str):
        return blob.startswith(_TEXT_PREFIX)
    return False
