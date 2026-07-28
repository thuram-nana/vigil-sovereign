"""attest — attestation interface + software/TPM fallback (X1).

[BUILT] SoftwareAttestationProvider signs an integrity+origin quote today (no hardware).
[hardware-gated] SEV-SNP / TDX backends are stubs that raise until the platform lands.
The software quote does NOT prove hardware confidentiality — see ``attest/provider.py``.
"""

from __future__ import annotations

from .provider import (
    AttestationProvider,
    AttestationQuote,
    SevSnpAttestationProvider,
    SoftwareAttestationProvider,
    TdxAttestationProvider,
)

__all__ = [
    "AttestationProvider",
    "AttestationQuote",
    "SoftwareAttestationProvider",
    "SevSnpAttestationProvider",
    "TdxAttestationProvider",
]
