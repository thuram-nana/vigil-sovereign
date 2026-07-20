"""
entitlement — Pillar 2: controlled distribution and capability gating.

The framework's most dangerous capabilities do not run merely because
the code is present on disk. They run only against a threshold-signed,
host-bound, unexpired, unrevoked *entitlement* issued by a governance
authoriser set. Possession of the code without a matching entitlement
yields only the safe baseline core.

Public surface (import from here, not from submodules):

    from framework.v2.entitlement import (
        Capability, CapabilityTier,
        require_capability, is_capability_available,
        current_policy, set_policy, EntitlementPolicy,
    )

`require_capability(cap)` is the load-bearing gate. It raises an
`EntitlementViolation` subclass on denial (never silently caught) and
returns an `EntitlementDecision` on grant. Call it at the entry point
of every gated subsystem.

Design notes:

- Enforcement activates when a trust root is provisioned (or
  CRUCIBLE_ENTITLEMENT_ENFORCED=1). With no trust root the deployment
  is "ungoverned" — baseline runs, gated capabilities are permitted but
  every grant is logged at WARNING and `explain()` says so. This mirrors
  the sovereignty layer's PERMISSIVE default and keeps development
  checkouts working without provisioning. Production deployments
  provision a trust root and enforcement is automatic.
- Verification is m-of-n Ed25519 over a deterministic canonical form
  (`canonical.py`). It is forward-compatible with a single aggregated
  FROST-Ed25519 group signature: a trust root with one authoriser and
  threshold 1 verifies a group signature with no code change.
- All decisions are emitted to the engagement audit log.
"""

from __future__ import annotations

from .models import (
    Capability,
    CapabilityTier,
    EntitlementDecision,
    EntitlementDocument,
    EntitlementSubject,
    HardwareBinding,
    SignedEntitlement,
    SignedRevocation,
    TrustRoot,
)
from .policy import (
    EntitlementPolicy,
    current_policy,
    is_capability_available,
    require_capability,
    reset_policy,
    set_policy,
)

__all__ = [
    "Capability",
    "CapabilityTier",
    "EntitlementDecision",
    "EntitlementDocument",
    "EntitlementSubject",
    "HardwareBinding",
    "SignedEntitlement",
    "SignedRevocation",
    "TrustRoot",
    "EntitlementPolicy",
    "current_policy",
    "set_policy",
    "reset_policy",
    "require_capability",
    "is_capability_available",
]
