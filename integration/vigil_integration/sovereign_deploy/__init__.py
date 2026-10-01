"""
vigil_integration.sovereign_deploy — the sovereign / air-gapped DEPLOYMENT facade (W13-8, #501).

Four properties a customer can operate a VIGIL deployment on THEIR terms, each a thin facade over an
already-reviewed mechanism (never a second policy engine — the W13-2 ``sovereign_bridge`` rule applied to
deployment):

  1. :mod:`.bundle`    — offline, signed deployment bundles that INSTALL + VERIFY with NO network
                          (facade over ``vigil_core.signed_build_manifest``; ``no_network`` enforces it).
  2. :mod:`.trust`     — the trust anchor is CUSTOMER-controlled; NO vendor-held anchor can disable a
                          deployment (facade over the customer ``TrustRoot``; no vendor kill switch exists).
  3. :mod:`.attest`    — challenge-response attestation that REJECTS a replayed challenge, and whose failure
                          NEVER blocks an individual operation (no per-operation dependency on a vendor
                          service).
  4. :mod:`.telemetry` — schema-ALLOWLISTED telemetry with an explicit NO-COLLECT list, stated and tested.
  5. :mod:`.eval_profile` — the per-org investor-EVALUATION deployment config (INV3): the single source of
                          truth for the product-path "production-on" switches (family re-drive FACT-mint +
                          AEGIS enforce) and the capabilities (AEGIS_RESPOND) a control plane must provision.
                          Declares + honestly reports config; verifies nothing (the entitlement decision
                          stays engine-side).

Import-clean (FATAL-2): stdlib + ``vigil_core`` + the framework-free ``live.oracle_families`` only; nothing
from ``framework`` / ``strix`` / ``sigil``, so the whole package loads in the sovereign process.
"""

from __future__ import annotations

from .attest import (
    AttestationChallenge,
    AttestationOutcome,
    AttestationResponse,
    OperationResult,
    ReplayGuard,
    issue_challenge,
    respond,
    run_operation,
    verify_attestation,
)
from .bundle import (
    BundleInstallResult,
    NetworkAccessError,
    assemble_bundle,
    install_bundle,
    no_network,
)
from .eval_profile import (
    REQUIRED_CAPABILITIES,
    EvalReadiness,
    aegis_enforce_requested,
    assess_readiness,
    engage_fact_mint_flags,
    fact_mint_enabled,
    production_env,
)
from .telemetry import (
    NO_COLLECT_FIELDS,
    TELEMETRY_SCHEMA_ALLOWLIST,
    build_telemetry_payload,
    no_collect_fields,
    schema_allowlist,
    scrub_snapshot_for_export,
)
from .trust import (
    SOLE_OPERATIONAL_AUTHORITY,
    OperationalStatus,
    deployment_operational,
    operational_authorities,
    vendor_key_is_powerless,
)

__all__ = [
    # bundle (property 1)
    "assemble_bundle", "install_bundle", "BundleInstallResult", "no_network", "NetworkAccessError",
    # trust (property 2)
    "deployment_operational", "OperationalStatus", "SOLE_OPERATIONAL_AUTHORITY",
    "operational_authorities", "vendor_key_is_powerless",
    # attest (property 3)
    "issue_challenge", "respond", "verify_attestation", "run_operation", "ReplayGuard",
    "AttestationChallenge", "AttestationResponse", "AttestationOutcome", "OperationResult",
    # telemetry (property 4)
    "build_telemetry_payload", "scrub_snapshot_for_export", "schema_allowlist", "no_collect_fields",
    "TELEMETRY_SCHEMA_ALLOWLIST", "NO_COLLECT_FIELDS",
    # eval deployment config (INV3): the product-path "production-on" switches + required grants
    "production_env", "engage_fact_mint_flags", "fact_mint_enabled", "aegis_enforce_requested",
    "assess_readiness", "EvalReadiness", "REQUIRED_CAPABILITIES",
]
