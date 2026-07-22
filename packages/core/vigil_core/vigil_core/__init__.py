"""vigil_core — the shared, tamper-evident integrity substrate for the VIGIL monorepo.

The SINGLE source of truth for the signed hash-chain, canonical JSON, Ed25519 (+ m-of-n threshold)
crypto, and the trust-root / chain models. Historically these primitives were maintained twice — once in
CRUCIBLE (`framework/v2/{evidence,entitlement}`) and once vendored into SIGIL (`sigil/reuse/`); the SIGIL
copy evolved AHEAD (the v2 Merkle-prune `SignedChainHead`). This package promotes SIGIL's v2 form to the
canonical core that both engines depend on. It is version-conditional: a `schema_version < 2` head drops
the v2 fields from its signing payload, so **every existing v1-signed head verifies byte-identically** —
adopting this core breaks no prior signature (the `crucible-evidence-v1\x00` domain tag is unchanged).

Deliberately dependency-minimal (cryptography + pydantic) and namespace-pure: it imports NO `framework.*`,
NO `strix.*`, and NO `sigil.*`. That purity is what lets SIGIL keep its offense-free-by-construction
guarantee (its `assert_no_offense()` — which lives in SIGIL, NOT here — bars importing the offense engine)
while still sharing this core with the offensive side.
"""
from __future__ import annotations

from .canonical import canonical_json, digest_payload, evidence_signing_bytes, sha256_hex
from .chain import append_entry, build_chain, sign_head, verify_chain, verify_head
from .crypto import IntegrityError, KeyPair, generate_keypair, sign, verify_one, verify_threshold
from .models import AuthorizerKey, ChainEntry, Signature, SignedChainHead, TrustRoot
from .sealing import SealError, is_sealed, new_kek, seal, unseal
from .vault import Vault, VaultLocked

__all__ = [
    "canonical_json", "digest_payload", "evidence_signing_bytes", "sha256_hex",
    "append_entry", "build_chain", "sign_head", "verify_chain", "verify_head",
    "generate_keypair", "sign", "verify_one", "verify_threshold", "KeyPair", "IntegrityError",
    "AuthorizerKey", "ChainEntry", "Signature", "SignedChainHead", "TrustRoot",
    "seal", "unseal", "new_kek", "is_sealed", "SealError",
    "Vault", "VaultLocked",
]
