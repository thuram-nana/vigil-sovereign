"""
entitlement.models — Pydantic schemas for the entitlement layer.

Three documents matter:

  TrustRoot          the authoriser set + threshold a deployment trusts.
                     Provisioned once, out of band. The root of trust.
  SignedEntitlement  a capability grant for one institution, bound to
                     host identifiers, time-boxed, signed by m-of-n of
                     the trust root's authorisers.
  SignedRevocation   a signed list of entitlement ids that are revoked.

The unsigned cores (EntitlementDocument, RevocationDocument) are what
get canonicalised and signed; the signatures sit alongside the core in
the Signed* wrappers so the exact bytes that were signed are
reconstructable at verification time (see canonical.py).

Nothing here performs crypto or makes a trust decision. These are pure,
validated data shapes. Verification lives in crypto.py / policy.py.
"""

from __future__ import annotations

import enum
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field, model_validator
from vigil_core import AuthorizerKey, Signature, TrustRoot


# ---------------------------------------------------------------------------
# Capabilities and tiers
# ---------------------------------------------------------------------------


class Capability(str, enum.Enum):
    """A gated unit of framework power. The set is deliberately coarse:
    one capability per meaningful escalation in potential impact. Adding
    a capability is an entitlement-schema change and must be matched by
    an entry in `registry.REQUIRED_TIER`."""

    # --- baseline: always available, even with no entitlement ----------
    CORE_REASONING = "core_reasoning"          # URK cognitive bindings
    PASSIVE_INTAKE = "passive_intake"          # UTI passive fingerprint

    # --- standard ------------------------------------------------------
    ACTIVE_RECON = "active_recon"              # active probing within scope
    AUTONOMOUS_PLANNING = "autonomous_planning"  # ACP goal-tree planning

    # --- offensive -----------------------------------------------------
    EXPLOIT_EXECUTION = "exploit_execution"    # single-hypothesis exploit
    DEEP_STATIC_ANALYSIS = "deep_static_analysis"  # DAA white-box arsenal
    DEFENDER_TELEMETRY = "defender_telemetry"  # DEL self-detection scoring

    # --- defensive (AEGIS runtime protection) --------------------------
    AEGIS_RESPOND = "aegis_respond"            # AEGIS Gateway ACTIVE enforcement (block a proven attack)

    # --- advanced (most dangerous; entitlement-locked) -----------------
    FULL_CHAIN_EXPLOITATION = "full_chain_exploitation"  # multi-bug chaining
    DEFENDER_EVASION = "defender_evasion"      # DEL evasion (human-authored)
    SELF_IMPROVEMENT_MERGE = "self_improvement_merge"    # SIL merge authority


class CapabilityTier(str, enum.Enum):
    """A clearance level. Tiers are a monotone ladder: a higher tier
    permits every capability a lower tier permits, plus more. The
    ordering and the capability->tier map live in `registry.py`."""

    BASELINE = "baseline"
    STANDARD = "standard"
    OFFENSIVE = "offensive"
    ADVANCED = "advanced"


# ---------------------------------------------------------------------------
# Trust root
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# Entitlement
# ---------------------------------------------------------------------------


class EntitlementSubject(BaseModel):
    """Who an entitlement is for."""

    model_config = ConfigDict(extra="forbid")

    institution_id: str = Field(min_length=1)
    institution_name: str = Field(min_length=1)
    operator_constraint: str | None = Field(
        default=None,
        description="Optional operator-identity constraint (e.g. a SPIFFE id "
        "prefix). None means any operator at the institution.",
    )


class HardwareBinding(BaseModel):
    """Binds an entitlement to attested infrastructure. With
    binding_type='none' the entitlement runs anywhere (development /
    low-assurance). With 'host_attestation' the running host must
    present at least one of `bound_identifiers` (see binding.py)."""

    model_config = ConfigDict(extra="forbid")

    binding_type: str = Field(default="none", pattern=r"^(none|host_attestation)$")
    bound_identifiers: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def _check(self) -> "HardwareBinding":
        if self.binding_type == "host_attestation" and not self.bound_identifiers:
            raise ValueError("host_attestation binding requires bound_identifiers")
        return self


class EntitlementDocument(BaseModel):
    """The unsigned core that is canonicalised and signed. Every field
    here is covered by the signature; changing any byte invalidates it."""

    model_config = ConfigDict(extra="forbid")

    schema_version: int = Field(default=1, ge=1)
    entitlement_id: str = Field(min_length=1, description="Stable unique id (uuid).")
    issuer: str = Field(min_length=1, description="Issuing authority name.")
    subject: EntitlementSubject
    capability_tier: CapabilityTier
    granted_capabilities: list[Capability] = Field(
        default_factory=list,
        description="Explicit least-privilege allowlist within the tier. "
        "Empty means 'all capabilities the tier permits'.",
    )
    binding: HardwareBinding = Field(default_factory=HardwareBinding)
    revocation_required: bool = Field(
        default=False,
        description="When true, a validly-signed revocation list MUST be present "
        "and readable at evaluation time; an absent or unreadable list fails "
        "CLOSED (deny). This closes the 'rm revocation.json' bypass for grants "
        "that expect a revocation source. Default false preserves legacy "
        "behaviour — an entitlement that never expected a revocation list is "
        "not denied merely because none is present. This field is inside the "
        "signed core, so it cannot be flipped off without invalidating the "
        "signature.",
    )
    issued_at: datetime
    not_before: datetime
    not_after: datetime

    @model_validator(mode="after")
    def _check_window(self) -> "EntitlementDocument":
        if self.not_after <= self.not_before:
            raise ValueError("not_after must be strictly after not_before")
        return self


class SignedEntitlement(BaseModel):
    """An entitlement document plus the authoriser signatures over its
    canonical form."""

    model_config = ConfigDict(extra="forbid")

    document: EntitlementDocument
    signatures: list[Signature] = Field(min_length=1)


# ---------------------------------------------------------------------------
# Revocation
# ---------------------------------------------------------------------------


class RevocationDocument(BaseModel):
    """The unsigned core of a revocation list. `serial` increases with
    each reissue so a stale list cannot be replayed over a newer one."""

    model_config = ConfigDict(extra="forbid")

    schema_version: int = Field(default=1, ge=1)
    serial: int = Field(ge=0)
    issued_at: datetime
    revoked_entitlement_ids: list[str] = Field(default_factory=list)


class SignedRevocation(BaseModel):
    """A revocation document plus authoriser signatures. Signed by the
    same trust root that signs entitlements; threshold applies."""

    model_config = ConfigDict(extra="forbid")

    document: RevocationDocument
    signatures: list[Signature] = Field(min_length=1)


# ---------------------------------------------------------------------------
# Decision (audit record)
# ---------------------------------------------------------------------------


class EntitlementDecision(BaseModel):
    """The outcome of a capability check. Emitted to the audit log on
    every call to the gate, allow or deny."""

    model_config = ConfigDict(extra="forbid")

    allowed: bool
    capability: Capability
    reason: str
    enforced: bool = Field(description="False when no trust root is provisioned.")
    entitlement_id: str | None = None
    institution: str | None = None
    evaluated_at: datetime
