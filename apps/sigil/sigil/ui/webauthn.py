"""Slice 1c-iii — WebAuthn (FIDO2) assertion + registration verification for the OWNER passkey login.

Pure, dependency-light verification: the assertion HOT PATH needs NO CBOR — `authenticatorData` is a fixed
binary layout parsed by slicing, `clientDataJSON` is JSON, and the signature is verified with pyca
`cryptography` (already a dependency). Registration takes the WebAuthn-L2 `getPublicKey()` DER
SubjectPublicKeyInfo, so there is no attestation-CBOR parse either; registration is OWNER-gated, so a bad
key only fails the owner's own later login (never a grant).

Phishing-resistant by construction: the authenticator signs over `authenticatorData ‖ SHA256(clientDataJSON)`
and `clientDataJSON` binds the ORIGIN and TYPE — so an assertion is cryptographically tied to the RP origin,
which a software Ed25519 proof-of-possession cannot claim.

COSE alg ids accepted: -7 = ES256 (ECDSA P-256 + SHA-256), -257 = RS256 (RSA PKCS#1v1.5 + SHA-256),
-8 = EdDSA (Ed25519).

Stdlib + `cryptography` only — no framework/strix/vigil_core. Offense-free by construction.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
from dataclasses import dataclass
from typing import Optional

COSE_ES256 = -7
COSE_RS256 = -257
COSE_EDDSA = -8
SUPPORTED_ALGS = frozenset({COSE_ES256, COSE_RS256, COSE_EDDSA})

_FLAG_UP = 0x01   # User Present
_FLAG_UV = 0x04   # User Verified


def b64url_nopad(raw: bytes) -> str:
    """base64url-encode WITHOUT padding (the WebAuthn wire form)."""
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def b64url_decode(s: str) -> bytes:
    """Decode a base64url string, tolerant of missing padding. Fail-closed callers wrap this in try/except."""
    s = str(s or "")
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def challenge_b64url(challenge: str) -> str:
    """The `clientDataJSON.challenge` value the RP expects for a server challenge STRING: the challenge bytes
    are `utf8(challenge)`, so the authenticator echoes `base64url(utf8(challenge))` (no padding). This is the
    single contract the SPA must honour (it passes `TextEncoder().encode(challenge)` as the challenge)."""
    return b64url_nopad(challenge.encode("utf-8"))


@dataclass(frozen=True)
class AuthenticatorData:
    rp_id_hash: bytes
    up: bool
    uv: bool
    sign_count: int


def parse_authenticator_data(data: bytes) -> "Optional[AuthenticatorData]":
    """Parse the fixed prefix `rpIdHash[32] ‖ flags[1] ‖ signCount[4 big-endian]`. The assertion path needs
    only this prefix (attested-credential-data / extensions follow, and are present only at registration).
    Returns None on a too-short buffer (fail-closed)."""
    if not isinstance(data, (bytes, bytearray)) or len(data) < 37:
        return None
    flags = data[32]
    return AuthenticatorData(rp_id_hash=bytes(data[0:32]), up=bool(flags & _FLAG_UP),
                             uv=bool(flags & _FLAG_UV), sign_count=int.from_bytes(data[33:37], "big"))


def _verify_signature(spki_der: bytes, cose_alg: int, message: bytes, signature: bytes) -> bool:
    """Verify `signature` over `message` with the DER SubjectPublicKeyInfo key, per COSE alg. Fail-closed:
    any load/verify error, an unsupported alg, or an alg/key-type mismatch → False."""
    try:
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa
        from cryptography.hazmat.primitives.serialization import load_der_public_key
        pub = load_der_public_key(spki_der)
        if cose_alg == COSE_ES256 and isinstance(pub, ec.EllipticCurvePublicKey):
            pub.verify(signature, message, ec.ECDSA(hashes.SHA256()))
            return True
        if cose_alg == COSE_RS256 and isinstance(pub, rsa.RSAPublicKey):
            pub.verify(signature, message, padding.PKCS1v15(), hashes.SHA256())
            return True
        if cose_alg == COSE_EDDSA and isinstance(pub, ed25519.Ed25519PublicKey):
            pub.verify(signature, message)
            return True
        return False
    except Exception:  # noqa: BLE001 — malformed key / bad signature → NOT verified (fail-closed)
        return False


@dataclass(frozen=True)
class AssertionResult:
    ok: bool
    sign_count: int = 0
    reason: str = ""


def verify_assertion(*, spki_der: bytes, cose_alg: int, authenticator_data: bytes, client_data_json: bytes,
                     signature: bytes, expected_challenge: str, allowed_origins, rp_id: str,
                     stored_sign_count: int, require_uv: bool = False) -> AssertionResult:
    """Verify a WebAuthn `navigator.credentials.get()` assertion, FAIL-CLOSED. In order: clientData.type ==
    'webauthn.get'; clientData.challenge == the minted (single-use) challenge; clientData.origin in the
    allowlist; authenticatorData.rpIdHash == sha256(rpId); User-Present (+ User-Verified if required);
    signCount strictly greater than stored (unless both 0 — a non-counting authenticator, no clone signal);
    and the signature over `authenticatorData ‖ sha256(clientDataJSON)`."""
    try:
        cd = json.loads(client_data_json)
    except (ValueError, TypeError):
        return AssertionResult(False, reason="client_data")
    if not isinstance(cd, dict) or cd.get("type") != "webauthn.get":
        return AssertionResult(False, reason="type")
    if not hmac.compare_digest(str(cd.get("challenge", "")), challenge_b64url(expected_challenge)):
        return AssertionResult(False, reason="challenge")
    if str(cd.get("origin", "")) not in set(allowed_origins):
        return AssertionResult(False, reason="origin")
    ad = parse_authenticator_data(authenticator_data)
    if ad is None:
        return AssertionResult(False, reason="authenticator_data")
    if not hmac.compare_digest(ad.rp_id_hash, hashlib.sha256(rp_id.encode("utf-8")).digest()):
        return AssertionResult(False, reason="rp_id")
    if not ad.up or (require_uv and not ad.uv):
        return AssertionResult(False, reason="user_presence")
    if not (ad.sign_count == 0 and stored_sign_count == 0) and ad.sign_count <= stored_sign_count:
        return AssertionResult(False, reason="signcount")     # clone / replay
    message = bytes(authenticator_data) + hashlib.sha256(bytes(client_data_json)).digest()
    if not _verify_signature(spki_der, cose_alg, message, signature):
        return AssertionResult(False, reason="signature")
    return AssertionResult(True, sign_count=ad.sign_count)


def verify_registration(*, client_data_json: bytes, expected_challenge: str, allowed_origins) -> "Optional[str]":
    """Validate the clientDataJSON of a `navigator.credentials.create()` at registration (owner-gated): type
    == 'webauthn.create', challenge matches the minted one, origin is allowlisted. Returns None on success or
    a short reason CODE on failure (the credential public key itself is taken from the L2 getPublicKey DER by
    the caller). Fail-closed."""
    try:
        cd = json.loads(client_data_json)
    except (ValueError, TypeError):
        return "client_data"
    if not isinstance(cd, dict) or cd.get("type") != "webauthn.create":
        return "type"
    if not hmac.compare_digest(str(cd.get("challenge", "")), challenge_b64url(expected_challenge)):
        return "challenge"
    if str(cd.get("origin", "")) not in set(allowed_origins):
        return "origin"
    return None
