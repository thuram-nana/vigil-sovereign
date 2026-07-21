"""
vigil_integration.detection — the AEGIS Detection Mirror edge-plane oracles (WS4-detection).

The defensive dual of the offensive engine: for every offensive tool, a DETERMINISTIC detection oracle
that PROVES its use against telemetry the systems you protect actually produced, as a re-runnable PCF
certificate — not an alert. The Sentinels recognise attacks; they wield no tool and perform no egress.

The sovereign invariant this module upholds (the red-pen attacks exactly this):

  * A detection is a **FACT** only when the deterministic oracle FIRES over retained telemetry AND a
    signed :class:`DetectionCertificate` RE-VERIFIES offline (signature + evidence digest + a live oracle
    RE-RUN over the embedded evidence — proof by re-execution, not string trust). Anything softer — a
    LEAD-grade signature (``waf_probe``, scanner-path bursts, the telemetry stubs), no signer wired, or a
    certificate that fails to re-verify — is a **LEAD**, never a silent block.
  * Every oracle ships a **benign twin** (a legitimate look-alike) that MUST NOT fire — the false-
    positive control. A benign twin that fires is a BLOCK.
  * Oracles are pure/deterministic (windows come from the records' own ts/seq — no clock/RNG), total on
    malformed telemetry (degrade to no signal), and secret-free (evidence scrubbed through the F3
    redactor before it enters a signed certificate).

Planes covered here: EDGE (recon + injection over access/flow logs) and AUTH TELEMETRY (credential over
auth.log). The egress + directory + cloud + session planes are honest LEAD-only stubs — no ingested
telemetry, no proof, stated plainly (``detection.telemetry``).
"""

from __future__ import annotations

from .base import (
    Detection,
    DetectionOracle,
    Grade,
    OracleHit,
    group_by,
    reverify_certificate,
    windowed,
)
from .certificate import (
    DetectionCertificate,
    build_certificate,
    evidence_digest,
    redact_evidence,
    sign_certificate,
    verify_certificate_signature,
)
from .credential import BruteForceOracle, PasswordSprayOracle
from .injection import (
    ATTACK_DETECTORS,
    CmdInjectionOracle,
    CrlfInjectionOracle,
    PathTraversalOracle,
    SqliStructureOracle,
    XssStructureOracle,
    detect_cmd,
    detect_crlf,
    detect_sqli,
    detect_traversal,
    detect_xss,
)
from .logs import (
    AccessRecord,
    AuthRecord,
    ConnRecord,
    parse_access_log,
    parse_auth_log,
    parse_clf_time,
    parse_conn_log,
)
from .recon import (
    CmsEnumerationOracle,
    ForcedBrowsingOracle,
    PortScanOracle,
    ScannerFingerprintOracle,
    WafProbeOracle,
)
from .registry import (
    ACCESS_ORACLE_NAMES,
    AUTH_ORACLE_NAMES,
    CONN_ORACLE_NAMES,
    ORACLE_CLASSES,
    facts,
    leads,
    resolve_oracle,
    run_access_detections,
    run_all_detections,
    run_auth_detections,
    run_conn_detections,
)
from .telemetry import (
    C2_STUB,
    CLOUD_STUB,
    IDENTITY_GRAPH_STUB,
    SESSION_STUB,
    TELEMETRY_STUBS,
    TelemetryStub,
    telemetry_stub,
)

__all__ = [
    # logs
    "AccessRecord", "AuthRecord", "ConnRecord",
    "parse_access_log", "parse_auth_log", "parse_conn_log", "parse_clf_time",
    # certificate
    "DetectionCertificate", "build_certificate", "sign_certificate",
    "verify_certificate_signature", "evidence_digest", "redact_evidence",
    # base
    "Grade", "OracleHit", "Detection", "DetectionOracle", "reverify_certificate",
    "group_by", "windowed",
    # recon
    "PortScanOracle", "ForcedBrowsingOracle", "ScannerFingerprintOracle", "CmsEnumerationOracle",
    "WafProbeOracle",
    # injection
    "SqliStructureOracle", "XssStructureOracle", "PathTraversalOracle", "CrlfInjectionOracle",
    "CmdInjectionOracle",
    "detect_sqli", "detect_xss", "detect_traversal", "detect_crlf", "detect_cmd", "ATTACK_DETECTORS",
    # credential
    "BruteForceOracle", "PasswordSprayOracle",
    # telemetry stubs
    "TelemetryStub", "telemetry_stub", "TELEMETRY_STUBS",
    "C2_STUB", "IDENTITY_GRAPH_STUB", "CLOUD_STUB", "SESSION_STUB",
    # registry / operating surface
    "ORACLE_CLASSES", "resolve_oracle",
    "ACCESS_ORACLE_NAMES", "CONN_ORACLE_NAMES", "AUTH_ORACLE_NAMES",
    "run_access_detections", "run_conn_detections", "run_auth_detections", "run_all_detections",
    "facts", "leads",
]
