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

Import-clean (FATAL-2): stdlib + ``vigil_core`` only; nothing from ``framework`` / ``strix`` / ``sigil``, so
the whole package loads in the sovereign process.
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
]
