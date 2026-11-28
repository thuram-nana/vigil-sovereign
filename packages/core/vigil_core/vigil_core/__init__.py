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
from .key_backend import (
    BACKEND_ENV as OWNER_KEY_BACKEND_ENV,
    FileBackend, HardwareKeyUnavailable, KeyBackend, KeyBackendError, Pkcs11Backend, Pkcs11Config,
    TokenSigner, describe_owner_backend, open_pkcs11_signer, select_owner_backend,
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
from .credit_lease import (
    ENVELOPE_TOKENS_PER_CREDIT,
    CreditLaunchLease, SignedCreditLaunchLease, credit_lease_signing_bytes,
    sign_credit_launch_lease, verify_credit_launch_lease,
)
from . import run_budget
from .run_budget import RunBudgetExceeded
from . import run_tier
from .authority import (
    EngagementAuthority, SignedAuthority, TargetEnvironment, authority_signing_bytes,
    sign_engagement_authority, verify_engagement_authority,
)
from .monitoring_authority import (
    MonitoringAuthority, MonitoringMode, SignedMonitoringAuthority, monitoring_authority_signing_bytes,
    sign_monitoring_authority, verify_monitoring_authority,
)
from .connected_repo_record import (
    BlockThreshold, ConnectedRepoRecord, SignedConnectedRepoRecord, check_repo as check_connected_repo,
    connected_repo_signing_bytes, repo_owner_name, sign_connected_repo_record, verify_connected_repo_record,
)
from .shard_assignment_record import (
    ShardAssignmentRecord, SignedShardAssignmentRecord, check_tenant_component,
    shard_assignment_signing_bytes, sign_shard_assignment_record, verify_shard_assignment_record,
)
from .authority_v2 import (
    ENFORCING_CAPABILITIES,
    AuthorityDecision, AuthorityOutcome, AuthoritySubject, AuthorityWithdrawal, EnforceRelease,
    EnforcementOverride, EpochStatement, MonitoringAuthorityV2, MonitoringCapability,
    MonitoringLease, MonitoringRevocationV2, OriginTuple, OverrideTarget, SignedEnforceRelease,
    SignedEpochStatement, SignedMonitoringAuthorityV2, SignedMonitoringRevocationV2, SubjectKind,
    authority_publish_path, check_dns_host, check_component as check_authority_component,
    enforce_release_signing_bytes, epoch_statement_signing_bytes, evaluate_authority,
    monitoring_authority_v2_signing_bytes, monitoring_revocation_v2_signing_bytes,
    sign_enforce_release, sign_epoch_statement, sign_monitoring_authority_v2,
    sign_monitoring_revocation_v2, verify_enforce_release, verify_epoch_statement,
    verify_monitoring_authority_v2, verify_monitoring_revocation_v2,
)
from .aegis_origin_binding import (
    AegisOriginBinding, SignedAegisOriginBinding, aegis_origin_binding_signing_bytes,
    grant_binds_origin, origin_binding_digest, origin_binding_publish_path,
    sign_aegis_origin_binding, verify_aegis_origin_binding,
)
from .aegis_schemas import (
    ALL_OUTCOME_CLASSES, BASELINE_REACHABLE_OUTCOMES, EVENT_V2_SCHEMA, HEALTH_V1_SCHEMA,
    RESPONSE_MANIFEST_SCHEMA, AdapterCapability, AegisEventV2, AssetRef, CanonicalModel, Criticality,
    EffectVerification, EngineHealth, EngineHealthState, OutcomeClass, PlacementState,
    ResponseDeadlines, ResponseManifest, baseline_response_manifest, clean_token as clean_aegis_token,
)
from .aegis_anchors import (
    ANCHOR1_SCHEME, AegisAnchorError, AnchorVerification, ProducerAnchor, connector_secret_ref,
    open_and_verify_producer_anchor, produce_producer_anchor, record_cert_digest, require_trustworthy,
    verify_anchored_record, verify_anchored_record_sealed, verify_owner_anchor, verify_producer_anchor,
)
from .protection_contract import (
    BASELINE_SIGIL_PROVIDER, PROTECTION_CONTRACT_SCHEMA, PROVIDER_REGISTRY_SCHEMA, AuthorizedActions,
    BindingState, Budgets, CertState, CustomerPrerequisites, Dimensions, DuplicateProviderError,
    EdgeBlock, EnforceReleaseProjection, EnforcementTerms, FailureBasis, FailurePolicy, Headline,
    LeaseProjection, LicensingMode, LockState, OriginBinding, OriginBlock, OriginLock, PostureDimension,
    ProtectionContract, ProviderDescriptor, ProviderRegistry, ReleaseState, RequiredSensor,
    RevocationProjection, RevocationState, SignerRole, TrustAssumptions, ViewerTls,
    baseline_provider_registry,
)
from .contract_eval import (
    HEADLINE_LADDER, NOT_OBSERVED_BASELINE, HostProtectionPreview, enforcement_reasons, grade_contract,
    grade_enforcement, grade_headline, headline_floor, preview_host,
)
from .defense_control import (
    STANDDOWN_ALREADY_STOOD_DOWN, STANDDOWN_NOT_ENFORCING, HostDefenseControl, defense_control_host,
)
from .onboarding import (
    ONBOARDING_STEPS, STATUS_CURRENT, STATUS_DONE, STATUS_TODO, STEP_PLAN, STEP_PROVE_HOST, STEP_TURN_ON,
    OnboardingJourney, OnboardingStep, onboarding_journey,
)
from .redpen_action import (
    REDPEN_ACTION_SEAM_SUBDIR, REDPEN_FIX_ACTION, REDPEN_RETEST_ACTION, redpen_action_marker,
)
from .retest_reproof import (
    RETEST_OUTCOME_SEAM_SUBDIR, RETEST_REPROOF_SEAM_SUBDIR,
    retest_reproof_outcome, retest_reproof_ticket, ticket_identity,
)
from .engagement_completion import (
    EngagementCompletion, EngagementOutcome, SignedEngagementCompletion,
    engagement_completion_signing_bytes, sign_engagement_completion, verify_engagement_completion,
)
from .target_credentials import (
    CredentialHeader, CredentialRole, SignedTargetCredentials, TargetCredentials, AccountCredential,
    sign_target_credentials, target_credentials_signing_bytes, verify_target_credentials,
)
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
    OFFENSE_ACTION_PERM, PERMISSIONS, ROLES, offense_perm_for, offense_route_key, role_can, role_can_global,
)
from .rotation import RotationError, rewrap, rewrap_or_seal, verify_opens_to
from .sealing import SealError, is_sealed, new_kek, seal, unseal
from .target_classification import (
    AUTHORIZED_CLASSES, ClassificationResult, DeploymentMode, RegisteredAsset, RegisteredAssetStore,
    TargetClass, classify_target, is_authorized, normalize_target,
)
from .vault import Vault, VaultLocked
from .escrow import (
    EscrowBundle, EscrowError, EscrowRequest, Share, escrow_passphrase, maybe_escrow,
    parse_public_metadata, recover_passphrase, recover_secret, split_secret,
)

__all__ = [
    "canonical_json", "digest_payload", "evidence_signing_bytes", "sha256_hex",
    "append_entry", "build_chain", "sign_head", "verify_chain", "verify_head",
    "load_highwater", "check_highwater", "advance_highwater", "highwater_lock",
    "read_highwater_dict", "verify_highwater_signature", "strict_highwater_enabled",
    "HighWaterError", "HighWaterDowngrade",
    "generate_keypair", "sign", "verify_one", "verify_threshold", "KeyPair", "IntegrityError",
    "HardBlockError", "assert_not_hard_blocked", "candidate_hosts", "is_hard_blocked",
    "normalize_domain", "protected_guard_enabled",
    "KeyBackend", "FileBackend", "Pkcs11Backend", "Pkcs11Config", "TokenSigner",
    "KeyBackendError", "HardwareKeyUnavailable", "OWNER_KEY_BACKEND_ENV",
    "select_owner_backend", "describe_owner_backend", "open_pkcs11_signer",
    "INSTALL_MANIFEST_SCHEMA", "InstallManifest", "InstallManifestError", "InstallManifestRefused",
    "build_manifest", "ensure_operable", "manifest_path", "new_install_id", "read_manifest",
    "verify_manifest", "write_manifest",
    "AuthorizerKey", "ChainEntry", "Signature", "SignedChainHead", "TrustRoot",
    "EngagementAuthority", "SignedAuthority", "TargetEnvironment", "authority_signing_bytes",
    "sign_engagement_authority", "verify_engagement_authority",
    "MonitoringAuthority", "MonitoringMode", "SignedMonitoringAuthority", "monitoring_authority_signing_bytes",
    "sign_monitoring_authority", "verify_monitoring_authority",
    "BlockThreshold", "ConnectedRepoRecord", "SignedConnectedRepoRecord", "check_connected_repo",
    "connected_repo_signing_bytes", "repo_owner_name", "sign_connected_repo_record", "verify_connected_repo_record",
    "ShardAssignmentRecord", "SignedShardAssignmentRecord", "check_tenant_component",
    "shard_assignment_signing_bytes", "sign_shard_assignment_record", "verify_shard_assignment_record",
    "ENFORCING_CAPABILITIES",
    "AuthorityDecision", "AuthorityOutcome", "AuthoritySubject", "AuthorityWithdrawal", "EnforceRelease",
    "EnforcementOverride", "EpochStatement", "MonitoringAuthorityV2", "MonitoringCapability",
    "MonitoringLease", "MonitoringRevocationV2", "OriginTuple", "OverrideTarget", "SignedEnforceRelease",
    "SignedEpochStatement", "SignedMonitoringAuthorityV2", "SignedMonitoringRevocationV2", "SubjectKind",
    "authority_publish_path", "check_dns_host", "check_authority_component",
    "enforce_release_signing_bytes", "epoch_statement_signing_bytes", "evaluate_authority",
    "monitoring_authority_v2_signing_bytes", "monitoring_revocation_v2_signing_bytes",
    "sign_enforce_release", "sign_epoch_statement", "sign_monitoring_authority_v2",
    "sign_monitoring_revocation_v2", "verify_enforce_release", "verify_epoch_statement",
    "verify_monitoring_authority_v2", "verify_monitoring_revocation_v2",
    "AegisOriginBinding", "SignedAegisOriginBinding", "aegis_origin_binding_signing_bytes",
    "grant_binds_origin", "origin_binding_digest", "origin_binding_publish_path",
    "sign_aegis_origin_binding", "verify_aegis_origin_binding",
    "REDPEN_ACTION_SEAM_SUBDIR", "REDPEN_FIX_ACTION", "REDPEN_RETEST_ACTION", "redpen_action_marker",
    "RETEST_REPROOF_SEAM_SUBDIR", "RETEST_OUTCOME_SEAM_SUBDIR",
    "retest_reproof_ticket", "retest_reproof_outcome", "ticket_identity",
    "EngagementCompletion", "EngagementOutcome", "SignedEngagementCompletion",
    "engagement_completion_signing_bytes", "sign_engagement_completion", "verify_engagement_completion",
    "CredentialHeader", "CredentialRole", "SignedTargetCredentials", "TargetCredentials",
    "AccountCredential", "sign_target_credentials", "target_credentials_signing_bytes",
    "verify_target_credentials",
    "ENVELOPE_TOKENS_PER_CREDIT",
    "CreditLaunchLease", "SignedCreditLaunchLease", "credit_lease_signing_bytes",
    "sign_credit_launch_lease", "verify_credit_launch_lease",
    "run_budget", "RunBudgetExceeded", "run_tier",
    "BUILD_INTEGRITY_STATES", "BUILD_MANIFEST_DOMAIN", "BUILD_MANIFEST_SCHEMA", "BuildArtifact",
    "BuildIntegrityResult", "BuildIntegrityState", "BuildManifestError", "BUILD_MANIFEST_FILENAME",
    "SignedBuildManifest", "BUILD_TRUST_ROOT_FILENAME", "build_manifest_from_specs",
    "build_signed_manifest", "digest_file", "digest_tree", "evaluate_build_integrity",
    "load_build_trust_root", "parse_signed_manifest", "read_signed_manifest", "sign_manifest",
    "verify_build_integrity",
    "ROLES", "PERMISSIONS", "role_can", "role_can_global", "OFFENSE_ACTION_PERM", "offense_perm_for",
    "offense_route_key",
    "seal", "unseal", "new_kek", "is_sealed", "SealError",
    "RotationError", "rewrap", "rewrap_or_seal", "verify_opens_to",
    "TargetClass", "DeploymentMode", "AUTHORIZED_CLASSES", "RegisteredAsset", "RegisteredAssetStore",
    "ClassificationResult", "normalize_target", "classify_target", "is_authorized",
    "Vault", "VaultLocked",
    "IdentityAttestation", "Capability", "Attenuation", "EffectiveCapability", "WielderProof",
    "CapabilityError", "sign_identity_attestation", "verify_identity_attestation", "identity_digest",
    "identity_matches", "sign_capability", "attenuate", "verify_capability", "authorize_reverification",
    "prove_wielder", "verify_wielder_proof",
    "EscrowBundle", "EscrowError", "EscrowRequest", "Share", "escrow_passphrase", "maybe_escrow",
    "parse_public_metadata", "recover_passphrase", "recover_secret", "split_secret",
    # AS-2b — base data contracts (aegis_schemas.py):
    "EVENT_V2_SCHEMA", "HEALTH_V1_SCHEMA", "RESPONSE_MANIFEST_SCHEMA",
    "ALL_OUTCOME_CLASSES", "BASELINE_REACHABLE_OUTCOMES", "clean_aegis_token", "CanonicalModel",
    "OutcomeClass", "EffectVerification", "EngineHealthState", "PlacementState", "Criticality",
    "AssetRef", "AdapterCapability", "EngineHealth", "ResponseDeadlines", "ResponseManifest",
    "baseline_response_manifest", "AegisEventV2",
    # AS-9c — two-anchor tamper-evidence contract (aegis_anchors.py):
    "ANCHOR1_SCHEME", "AegisAnchorError", "AnchorVerification", "ProducerAnchor", "connector_secret_ref",
    "open_and_verify_producer_anchor", "produce_producer_anchor", "record_cert_digest", "require_trustworthy",
    "verify_anchored_record", "verify_anchored_record_sealed", "verify_owner_anchor", "verify_producer_anchor",
    # AS-2b — protection contract + provider registry (protection_contract.py):
    "PROTECTION_CONTRACT_SCHEMA", "PROVIDER_REGISTRY_SCHEMA",
    "Headline", "PostureDimension", "LicensingMode", "BindingState", "LockState", "CertState",
    "RevocationState", "ReleaseState", "SignerRole", "FailureBasis",
    "ViewerTls", "EdgeBlock", "OriginBinding", "OriginLock", "OriginBlock", "RequiredSensor",
    "LeaseProjection", "RevocationProjection", "AuthorizedActions", "EnforceReleaseProjection",
    "EnforcementTerms", "FailurePolicy", "CustomerPrerequisites", "TrustAssumptions",
    "Dimensions", "Budgets", "ProtectionContract",
    "ProviderDescriptor", "ProviderRegistry", "DuplicateProviderError",
    "BASELINE_SIGIL_PROVIDER", "baseline_provider_registry",
    # AS-4b — protection-contract evaluator + enforce/observe preview (contract_eval.py):
    "HEADLINE_LADDER", "NOT_OBSERVED_BASELINE", "HostProtectionPreview",
    "headline_floor", "grade_headline", "enforcement_reasons", "grade_enforcement", "grade_contract",
    "preview_host",
    # AS-27b — defense-control (manage_defense) posture + stand-down preview (defense_control.py):
    "STANDDOWN_NOT_ENFORCING", "STANDDOWN_ALREADY_STOOD_DOWN", "HostDefenseControl", "defense_control_host",
    # AS-6d — customer tenant onboarding-journey evaluator (onboarding.py):
    "STEP_PROVE_HOST", "STEP_PLAN", "STEP_TURN_ON", "ONBOARDING_STEPS",
    "STATUS_DONE", "STATUS_CURRENT", "STATUS_TODO",
    "OnboardingStep", "OnboardingJourney", "onboarding_journey",
]
