"""vigil_integration.posture — the Proof-of-Posture trust protocol.

A ``PostureCertificate`` turns VIGIL's coverage oracle into the security industry's first
machine-verifiable, third-party-offline-re-verifiable **Certificate of Non-Exploitability**:
a signed, deterministic projection of a coverage scan into a posture vocabulary —

  * CLOSED    — an applicable deterministic oracle had a LIVE channel to the real target and did
                NOT fire (coverage verdict ``clean``; the class was provably-exercised-clean).
  * OPEN      — an oracle FIRED (a confirmed finding).
  * UNPROVEN  — the payload was sent but no oracle adjudicated (``inconclusive``), or the surface
                was never reached (out of the denominator).

bound to a specific target (an owner-signed ``IdentityAttestation``), carrying its own coverage
DENOMINATOR + honest RESIDUAL verbatim in the signed bytes. Freshness (an external RFC3161 time
anchor) and independent attestation (a witness quorum) are applied to the certificate's digest as
SIDECARS at the bundle layer, so the certificate core stays byte-deterministic.

FATAL-2: this package imports only ``vigil_core`` + stdlib; the m-of-n signing envelope is reused
from ``eval.benchmark_run`` via a FUNCTION-LOCAL import inside the sign/verify helpers (mirroring
``remediation.reprove``), so importing this package co-loads ZERO framework modules.
"""

from .certificate import (  # noqa: F401
    POSTURE_SCHEMA,
    POSTURE_RESIDUAL,
    PostureError,
    build_posture_certificate,
    canonical_posture_bytes,
    project_posture_claims,
    sign_posture_certificate,
    verify_posture_certificate,
    write_posture_certificate,
)

__all__ = [
    "POSTURE_SCHEMA",
    "POSTURE_RESIDUAL",
    "PostureError",
    "build_posture_certificate",
    "canonical_posture_bytes",
    "project_posture_claims",
    "sign_posture_certificate",
    "verify_posture_certificate",
    "write_posture_certificate",
]
