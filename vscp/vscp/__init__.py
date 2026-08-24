"""VSCP — the Vigil Sovereign Control Plane (W13-7 / #500).

A SIBLING application to the VIGIL assessment product, with its OWN runtime, deps,
migrations and CI, and CI-ENFORCED ISOLATION from that product: a separate database,
separate credentials / signing material, and NO import or network path to assessment
findings. VSCP reuses the shared, offense-free integrity substrate ``vigil_core``
(Ed25519 crypto, the signed hash-chain, the RBAC-of-record) and references the existing
gate-of-record primitives; it reimplements no policy.

The package deliberately performs NO heavy work at import time (keeps the isolation
surface small and the import graph auditable). Import the submodules you need.
"""
from __future__ import annotations

__all__ = ["__version__"]

__version__ = "0.1.0"
