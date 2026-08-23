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
from .capability import (
    Attenuation, Capability, CapabilityError, EffectiveCapability, IdentityAttestation, WielderProof,
    attenuate, authorize_reverification, identity_digest, identity_matches, prove_wielder, sign_capability,
    sign_identity_attestation, verify_capability, verify_identity_attestation, verify_wielder_proof,
)
from .chain import append_entry, build_chain, sign_head, verify_chain, verify_head
from .crypto import IntegrityError, KeyPair, generate_keypair, sign, verify_one, verify_threshold
from .hard_guardrail import (
    HardBlockError, assert_not_hard_blocked, candidate_hosts, is_hard_blocked, normalize_domain,
    protected_guard_enabled,
)
from .install_manifest import (
    INSTALL_MANIFEST_SCHEMA, InstallManifest, InstallManifestError, InstallManifestRefused,
    build_manifest, ensure_operable, manifest_path, new_install_id, read_manifest, verify_manifest,
    write_manifest,
)
from .highwater import (
    HighWaterDowngrade, HighWaterError, advance_highwater, check_highwater, highwater_lock, load_highwater,
    read_highwater_dict, strict_highwater_enabled, verify_highwater_signature,
)
from .models import AuthorizerKey, ChainEntry, Signature, SignedChainHead, TrustRoot
from .signed_build_manifest import (
    ALL_STATES as BUILD_INTEGRITY_STATES,
    BUILD_MANIFEST_DOMAIN, BUILD_MANIFEST_SCHEMA, BuildArtifact, BuildIntegrityResult,
    BuildIntegrityState, BuildManifestError, MANIFEST_FILENAME as BUILD_MANIFEST_FILENAME,
    SignedBuildManifest, TRUST_ROOT_FILENAME as BUILD_TRUST_ROOT_FILENAME,
    build_manifest_from_specs, build_signed_manifest, digest_file, digest_tree,
    evaluate_build_integrity, load_trust_root as load_build_trust_root,
    parse_signed_manifest, read_signed_manifest, sign_manifest, verify_build_integrity,
)
from .rbac import (
    OFFENSE_ACTION_PERM, PERMISSIONS, ROLES, offense_perm_for, offense_route_key, role_can,
)
from .rotation import RotationError, rewrap, rewrap_or_seal, verify_opens_to
from .sealing import SealError, is_sealed, new_kek, seal, unseal
from .target_classification import (
    AUTHORIZED_CLASSES, ClassificationResult, DeploymentMode, RegisteredAsset, RegisteredAssetStore,
    TargetClass, classify_target, is_authorized, normalize_target,
)
from .vault import Vault, VaultLocked

__all__ = [
    "canonical_json", "digest_payload", "evidence_signing_bytes", "sha256_hex",
    "append_entry", "build_chain", "sign_head", "verify_chain", "verify_head",
    "load_highwater", "check_highwater", "advance_highwater", "highwater_lock",
    "read_highwater_dict", "verify_highwater_signature", "strict_highwater_enabled",
    "HighWaterError", "HighWaterDowngrade",
    "generate_keypair", "sign", "verify_one", "verify_threshold", "KeyPair", "IntegrityError",
    "HardBlockError", "assert_not_hard_blocked", "candidate_hosts", "is_hard_blocked",
    "normalize_domain", "protected_guard_enabled",
    "INSTALL_MANIFEST_SCHEMA", "InstallManifest", "InstallManifestError", "InstallManifestRefused",
    "build_manifest", "ensure_operable", "manifest_path", "new_install_id", "read_manifest",
    "verify_manifest", "write_manifest",
    "AuthorizerKey", "ChainEntry", "Signature", "SignedChainHead", "TrustRoot",
    "BUILD_INTEGRITY_STATES", "BUILD_MANIFEST_DOMAIN", "BUILD_MANIFEST_SCHEMA", "BuildArtifact",
    "BuildIntegrityResult", "BuildIntegrityState", "BuildManifestError", "BUILD_MANIFEST_FILENAME",
    "SignedBuildManifest", "BUILD_TRUST_ROOT_FILENAME", "build_manifest_from_specs",
    "build_signed_manifest", "digest_file", "digest_tree", "evaluate_build_integrity",
    "load_build_trust_root", "parse_signed_manifest", "read_signed_manifest", "sign_manifest",
    "verify_build_integrity",
    "ROLES", "PERMISSIONS", "role_can", "OFFENSE_ACTION_PERM", "offense_perm_for", "offense_route_key",
    "seal", "unseal", "new_kek", "is_sealed", "SealError",
    "RotationError", "rewrap", "rewrap_or_seal", "verify_opens_to",
    "TargetClass", "DeploymentMode", "AUTHORIZED_CLASSES", "RegisteredAsset", "RegisteredAssetStore",
    "ClassificationResult", "normalize_target", "classify_target", "is_authorized",
    "Vault", "VaultLocked",
    "IdentityAttestation", "Capability", "Attenuation", "EffectiveCapability", "WielderProof",
    "CapabilityError", "sign_identity_attestation", "verify_identity_attestation", "identity_digest",
    "identity_matches", "sign_capability", "attenuate", "verify_capability", "authorize_reverification",
    "prove_wielder", "verify_wielder_proof",
]
