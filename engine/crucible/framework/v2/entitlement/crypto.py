"""
entitlement.crypto — Ed25519 primitives and m-of-n threshold verify.

We do not roll our own crypto. Ed25519 sign/verify is `cryptography`
(pyca); we wrap it for typed errors and a clean threshold API.

Threshold model: an entitlement is valid iff at least `trust_root.threshold`
*distinct* authorisers from the trust root produced a valid signature
over the canonical bytes. Properties enforced here:

  - A signature whose key_id is not in the trust root does not count.
  - A key_id cannot be counted twice (duplicate signatures collapse).
  - An invalid signature does not count and does not abort the tally —
    we count valid distinct contributors and compare to the threshold.

This is a simple, fully-verifiable multisig. It is forward-compatible
with FROST-Ed25519: a FROST group produces a single standard Ed25519
signature verifiable against the group public key, so a trust root with
one authoriser (the group key) and threshold 1 verifies a FROST
signature with no change to this code.

Signing helpers (`generate_keypair`, `sign`) exist for operator-side
provisioning tooling and tests. The runtime only ever *verifies*.
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

from ..common.errors import EntitlementError
from .models import AuthorizerKey, Signature, TrustRoot


# ---------------------------------------------------------------------------
# Key encoding
# ---------------------------------------------------------------------------


def _b64decode_exact(value: str, expected_len: int, what: str) -> bytes:
    try:
        raw = base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error) as e:
        raise EntitlementError(f"{what} is not valid base64: {e}") from e
    if len(raw) != expected_len:
        raise EntitlementError(
            f"{what} decodes to {len(raw)} bytes, expected {expected_len}"
        )
    return raw


def load_public_key(public_key_b64: str) -> Ed25519PublicKey:
    raw = _b64decode_exact(public_key_b64, 32, "Ed25519 public key")
    return Ed25519PublicKey.from_public_bytes(raw)


def verify_one(public_key_b64: str, message: bytes, signature_b64: str) -> bool:
    """True iff `signature_b64` is a valid Ed25519 signature over
    `message` under `public_key_b64`. Never raises on a bad signature —
    returns False — but raises EntitlementError on malformed key/sig
    material (a provisioning error, not an attacker-controlled path)."""
    pub = load_public_key(public_key_b64)
    sig = _b64decode_exact(signature_b64, 64, "Ed25519 signature")
    try:
        pub.verify(sig, message)
        return True
    except InvalidSignature:
        return False


# ---------------------------------------------------------------------------
# Threshold verification
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ThresholdResult:
    """Outcome of a threshold check over a canonical message."""

    satisfied: bool
    valid_signers: tuple[str, ...]   # distinct key_ids that signed validly
    threshold: int
    reason: str


def verify_threshold(
    message: bytes,
    signatures: list[Signature],
    trust_root: TrustRoot,
) -> ThresholdResult:
    """Count distinct trust-root authorisers with a valid signature over
    `message`; compare to the threshold."""
    by_id: dict[str, AuthorizerKey] = {a.key_id: a for a in trust_root.authorizers}

    valid: list[str] = []
    seen: set[str] = set()
    for sig in signatures:
        if sig.key_id in seen:
            continue  # a key contributes at most once
        seen.add(sig.key_id)
        authorizer = by_id.get(sig.key_id)
        if authorizer is None:
            continue  # not a trusted authoriser
        if verify_one(authorizer.public_key_b64, message, sig.signature_b64):
            valid.append(sig.key_id)

    satisfied = len(valid) >= trust_root.threshold
    if satisfied:
        reason = (
            f"{len(valid)} valid distinct signature(s) "
            f">= threshold {trust_root.threshold}"
        )
    else:
        reason = (
            f"only {len(valid)} valid distinct signature(s) "
            f"< threshold {trust_root.threshold} "
            f"(trust root has {len(trust_root.authorizers)} authoriser(s))"
        )
    return ThresholdResult(
        satisfied=satisfied,
        valid_signers=tuple(valid),
        threshold=trust_root.threshold,
        reason=reason,
    )


# ---------------------------------------------------------------------------
# Provisioning helpers (operator-side issuance + tests; never the runtime)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class KeyPair:
    """A freshly generated Ed25519 keypair, base64-encoded. The private
    key is the issuance secret; it never touches the runtime host."""

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
    """Produce a base64 Ed25519 signature. Issuance tooling / tests only."""
    raw = _b64decode_exact(private_key_b64, 32, "Ed25519 private key")
    priv = Ed25519PrivateKey.from_private_bytes(raw)
    return base64.b64encode(priv.sign(message)).decode("ascii")
