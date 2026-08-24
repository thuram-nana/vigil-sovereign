"""VSCP core registries: deployment, trust authorities, authorization issuance.

Each registry gates its WRITES through the shared RBAC-of-record (a reviewer is refused),
persists to VSCP's OWN store, and holds no assessment-product data. These are the
skeleton registries the spec names as load-bearing; the fuller feature set
(policy/build registries, attestation, revocation workflows, fleet monitoring, event
ingestion, reviewer console) is staged — see ``vscp/ROADMAP.md``.
"""
from __future__ import annotations

from .deployment import Deployment, DeploymentRegistry
from .trust_authorities import TrustAuthority, TrustAuthorityRegistry

__all__ = [
    "Deployment",
    "DeploymentRegistry",
    "TrustAuthority",
    "TrustAuthorityRegistry",
]
