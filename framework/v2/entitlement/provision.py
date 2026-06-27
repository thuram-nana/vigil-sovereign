"""
entitlement.provision — operator-side issuance tooling.

The runtime only ever *verifies* entitlements. Creating them — building
a trust root, signing an entitlement with authoriser private keys,
issuing a revocation list — is a governance act performed out of band,
on a host the issuance keys live on (ideally HSM-backed). This module
is that tooling.

Authoriser private keys are the institution's crown jewels. They never
belong on a runtime host and never in source control. In production an
authoriser signs by exporting only the canonical bytes
(`canonical.entitlement_signing_bytes`) to the signer and collecting a
base64 signature back; `sign_entitlement` is the convenience path for a
single-host issuance ceremony or for tests.
"""

from __future__ import annotations

import json
from pathlib import Path

from ..common import paths
from .canonical import entitlement_signing_bytes, revocation_signing_bytes
from .crypto import KeyPair, generate_keypair, sign
from .models import (
    AuthorizerKey,
    EntitlementDocument,
    RevocationDocument,
    Signature,
    SignedEntitlement,
    SignedRevocation,
    TrustRoot,
)


def new_authorizer(key_id: str, name: str) -> tuple[AuthorizerKey, str]:
    """Generate an authoriser. Returns the public AuthorizerKey (for the
    trust root) and the base64 private key (kept by the authoriser, never
    distributed)."""
    kp: KeyPair = generate_keypair()
    return (
        AuthorizerKey(key_id=key_id, name=name, public_key_b64=kp.public_key_b64),
        kp.private_key_b64,
    )


def build_trust_root(authorizers: list[AuthorizerKey], threshold: int) -> TrustRoot:
    return TrustRoot(threshold=threshold, authorizers=authorizers)


def sign_entitlement(
    document: EntitlementDocument,
    signers: dict[str, str],
) -> SignedEntitlement:
    """Sign `document` with each (key_id -> private_key_b64) in
    `signers`. The caller is responsible for supplying at least the
    trust root's threshold of authorised signers."""
    msg = entitlement_signing_bytes(document)
    signatures = [
        Signature(key_id=key_id, signature_b64=sign(priv_b64, msg))
        for key_id, priv_b64 in signers.items()
    ]
    return SignedEntitlement(document=document, signatures=signatures)


def sign_revocation(
    document: RevocationDocument,
    signers: dict[str, str],
) -> SignedRevocation:
    msg = revocation_signing_bytes(document)
    signatures = [
        Signature(key_id=key_id, signature_b64=sign(priv_b64, msg))
        for key_id, priv_b64 in signers.items()
    ]
    return SignedRevocation(document=document, signatures=signatures)


# ---------------------------------------------------------------------------
# Persistence
# ---------------------------------------------------------------------------


def _write_json(path: Path, payload: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(payload, encoding="utf-8")


def write_trust_root(trust_root: TrustRoot, path: Path | None = None) -> Path:
    p = path or paths.trust_root_path()
    _write_json(p, json.dumps(trust_root.model_dump(mode="json"), indent=2))
    return p


def write_entitlement(signed: SignedEntitlement, path: Path | None = None) -> Path:
    p = path or paths.entitlement_path()
    _write_json(p, json.dumps(signed.model_dump(mode="json"), indent=2))
    return p


def write_revocation(signed: SignedRevocation, path: Path | None = None) -> Path:
    p = path or paths.revocation_path()
    _write_json(p, json.dumps(signed.model_dump(mode="json"), indent=2))
    return p
