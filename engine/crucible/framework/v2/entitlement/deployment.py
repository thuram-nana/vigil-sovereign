"""
entitlement.deployment — deployment class + lifecycle (W13-3 #496).

The issue asks the engagement authorization's *deployment* leg to be
formalised alongside the engagement leg. The deployment authorization already
exists as a signed object — the :class:`SignedEntitlement` (Pillar 2). This
module EXTENDS that layer with the two facets a signed entitlement did not
carry, and adds **no policy of its own**:

  * a **deployment class** — WHERE the deployment runs. This REUSES the ONE
    deployment taxonomy of record, :class:`vigil_core.target_classification.DeploymentMode`
    (``LOCAL_OFFLINE`` / ``LOCAL_LAB`` / ``STAGING`` / ``PRODUCTION`` / ``REVIEWER``),
    re-exported here as :data:`DeploymentClass` — not a second enum; and
  * a **lifecycle** — WHETHER the deployment is operable right now
    (:class:`DeploymentLifecycle`: ``DRAFT`` → ``ACTIVE`` → ``SUSPENDED`` →
    ``EXPIRED`` / ``REVOKED``), plus the **customer** the deployment is for.

CRITICAL — NO DUPLICATED POLICY. This module does NOT decide which
capabilities a deployment may run. That decision lives in ONE place,
:func:`entitlement.policy.require_capability`, and stays there. A
:class:`DeploymentProfile` references the entitlement it governs by
``entitlement_id`` and adds a **lifecycle gate** on top:
:func:`require_operable_deployment` refuses any action from a deployment that
is not ``ACTIVE`` — but the capability grant itself is still the entitlement
policy's call. Composed, not duplicated: lifecycle ∧ (entitlement capability
policy).

The profile is a signed object with its own domain-separated canonical form,
verified against the SAME governance ``TrustRoot`` that signs entitlements — so
a deployment's class, customer, and lifecycle are as tamper-evident as its
capability grant.
"""

from __future__ import annotations

import enum
import json
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field
from vigil_core.target_classification import DeploymentMode

from ..common.errors import DeploymentNotOperable
from .models import Signature, TrustRoot

# Reuse the ONE deployment taxonomy of record — do not mint a second enum.
DeploymentClass = DeploymentMode


class DeploymentLifecycle(str, enum.Enum):
    """The operability state of a deployment. Only ``ACTIVE`` is operable; the
    others each fail the lifecycle gate for a distinct, auditable reason."""

    DRAFT = "draft"          # provisioned but not yet activated
    ACTIVE = "active"        # operable
    SUSPENDED = "suspended"  # temporarily halted by governance
    EXPIRED = "expired"      # validity elapsed
    REVOKED = "revoked"      # permanently withdrawn


# The single membership predicate for "operable". A deployment is operable iff
# its lifecycle is exactly ACTIVE — every other state is refused.
_OPERABLE: frozenset[DeploymentLifecycle] = frozenset({DeploymentLifecycle.ACTIVE})


class DeploymentProfileDocument(BaseModel):
    """The unsigned core that is canonicalised and signed. Carries the
    deployment class, customer, and lifecycle, and references the entitlement
    (by id) whose capability policy governs this deployment. It carries NO
    capability fields — those live in the referenced entitlement."""

    model_config = ConfigDict(extra="forbid")

    schema_version: int = Field(default=1, ge=1)
    profile_id: str = Field(min_length=1, description="Stable unique id (uuid).")
    entitlement_id: str = Field(
        min_length=1,
        description="The SignedEntitlement whose capability policy governs this "
        "deployment. The capability decision is NOT re-implemented here — it is "
        "made by entitlement.require_capability() against this entitlement.",
    )
    customer: str = Field(min_length=1, description="The customer this deployment is for.")
    deployment_class: DeploymentClass
    lifecycle: DeploymentLifecycle
    issued_at: datetime


class SignedDeploymentProfile(BaseModel):
    """A deployment profile plus governance signatures over its canonical
    form, verified against the entitlement layer's TrustRoot."""

    model_config = ConfigDict(extra="forbid")

    document: DeploymentProfileDocument
    signatures: list[Signature] = Field(min_length=1)


# ---------------------------------------------------------------------------
# Canonical signing bytes — a domain distinct from every other signed artifact
# ---------------------------------------------------------------------------

_DEPLOYMENT_PROFILE_DOMAIN = b"crucible-deployment-profile-v1\x00"


def deployment_profile_signing_bytes(document: DeploymentProfileDocument) -> bytes:
    """The exact bytes an authoriser signs / a verifier checks."""
    body = json.dumps(
        document.model_dump(mode="json"),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    return _DEPLOYMENT_PROFILE_DOMAIN + body


def sign_deployment_profile(
    document: DeploymentProfileDocument, signers: dict[str, str]
) -> SignedDeploymentProfile:
    """Sign a deployment profile with each (key_id -> private_key_b64)."""
    from .crypto import sign

    msg = deployment_profile_signing_bytes(document)
    signatures = [
        Signature(key_id=key_id, signature_b64=sign(priv_b64, msg))
        for key_id, priv_b64 in signers.items()
    ]
    return SignedDeploymentProfile(document=document, signatures=signatures)


def verify_deployment_profile(
    signed: SignedDeploymentProfile, trust_root: TrustRoot
) -> tuple[bool, str]:
    """Return (ok, reason). True iff at least the threshold of distinct
    trust-root authorisers validly signed the profile's canonical form."""
    from .crypto import verify_threshold

    result = verify_threshold(
        deployment_profile_signing_bytes(signed.document), signed.signatures, trust_root
    )
    return result.satisfied, result.reason


# ---------------------------------------------------------------------------
# The lifecycle gate — composed with, never replacing, the capability policy
# ---------------------------------------------------------------------------


def is_operable(document: DeploymentProfileDocument) -> bool:
    """True iff the deployment's lifecycle permits it to act at all. This is the
    lifecycle facet ONLY; whether a specific capability is granted remains the
    entitlement policy's decision."""
    return document.lifecycle in _OPERABLE


def require_operable_deployment(document: DeploymentProfileDocument) -> None:
    """Raise :class:`DeploymentNotOperable` unless the deployment is in an
    operable lifecycle state. Compose this with
    :func:`entitlement.require_capability` (lifecycle ∧ capability); it does NOT
    replace it. A DRAFT / SUSPENDED / EXPIRED / REVOKED deployment takes no
    action regardless of the capabilities its entitlement would confer."""
    if not is_operable(document):
        raise DeploymentNotOperable(
            f"deployment {document.profile_id!r} for customer {document.customer!r} is "
            f"{document.lifecycle.value!r}, not 'active'; no engagement action permitted "
            f"until it is activated (capability policy still governs which actions once active)"
        )
