"""Ed25519 primitives + m-of-n threshold verify.

VENDORED VERBATIM from CRUCIBLE `framework/v2/entitlement/crypto.py` (owner's own work).
"We do not roll our own crypto" — Ed25519 is pyca `cryptography`. Signing helpers are
provisioning-only; the runtime only ever verifies. The sole change from the source is a
local `IntegrityError` in place of the framework's `EntitlementError` (decoupling).
"""
from __future__ import annotations

import base64
import binascii
from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)

from .models import AuthorizerKey, Signature, TrustRoot


class IntegrityError(Exception):
    """Malformed key/signature material (a provisioning error, not an attacker path)."""


def _b64decode_exact(value: str, expected_len: int, what: str) -> bytes:
    try:
        raw = base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error) as e:
        raise IntegrityError(f"{what} is not valid base64: {e}") from e
    if len(raw) != expected_len:
        raise IntegrityError(f"{what} decodes to {len(raw)} bytes, expected {expected_len}")
    return raw


def load_public_key(public_key_b64: str) -> Ed25519PublicKey:
    return Ed25519PublicKey.from_public_bytes(_b64decode_exact(public_key_b64, 32, "Ed25519 public key"))


def verify_one(public_key_b64: str, message: bytes, signature_b64: str) -> bool:
    """True iff a valid Ed25519 signature; False on bad sig; raises only on malformed material."""
    pub = load_public_key(public_key_b64)
    sig = _b64decode_exact(signature_b64, 64, "Ed25519 signature")
    try:
        pub.verify(sig, message)
        return True
    except InvalidSignature:
        return False


@dataclass(frozen=True)
class ThresholdResult:
    satisfied: bool
    valid_signers: tuple[str, ...]
    threshold: int
    reason: str


def verify_threshold(message: bytes, signatures: list[Signature], trust_root: TrustRoot) -> ThresholdResult:
    """Count distinct trust-root authorisers with a valid signature; compare to threshold."""
    by_id: dict[str, AuthorizerKey] = {a.key_id: a for a in trust_root.authorizers}
    valid: list[str] = []
    seen: set[str] = set()
    for sig in signatures:
        if sig.key_id in seen:
            continue
        seen.add(sig.key_id)
        authorizer = by_id.get(sig.key_id)
        if authorizer is None:
            continue
        if verify_one(authorizer.public_key_b64, message, sig.signature_b64):
            valid.append(sig.key_id)
    satisfied = len(valid) >= trust_root.threshold
    reason = (
        f"{len(valid)} valid distinct signature(s) >= threshold {trust_root.threshold}"
        if satisfied else
        f"only {len(valid)} valid distinct signature(s) < threshold {trust_root.threshold}"
    )
    return ThresholdResult(satisfied=satisfied, valid_signers=tuple(valid), threshold=trust_root.threshold, reason=reason)


@dataclass(frozen=True)
class KeyPair:
    public_key_b64: str
    private_key_b64: str


def generate_keypair() -> KeyPair:
    priv = Ed25519PrivateKey.generate()
    raw_priv = priv.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    raw_pub = priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return KeyPair(
        public_key_b64=base64.b64encode(raw_pub).decode("ascii"),
        private_key_b64=base64.b64encode(raw_priv).decode("ascii"),
    )


def sign(private_key_b64: str, message: bytes) -> str:
    raw = _b64decode_exact(private_key_b64, 32, "Ed25519 private key")
    priv = Ed25519PrivateKey.from_private_bytes(raw)
    return base64.b64encode(priv.sign(message)).decode("ascii")
