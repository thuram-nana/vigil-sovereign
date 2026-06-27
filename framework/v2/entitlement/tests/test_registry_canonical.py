"""Tests for entitlement.registry (capability ladder) and
entitlement.canonical (deterministic signing bytes)."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from .. import canonical, registry
from ..models import (
    Capability,
    CapabilityTier,
    EntitlementDocument,
    EntitlementSubject,
    RevocationDocument,
)


# ---- registry -------------------------------------------------------------


def test_every_capability_has_required_tier() -> None:
    for cap in Capability:
        assert cap in registry.REQUIRED_TIER


def test_baseline_capabilities_need_no_entitlement() -> None:
    assert Capability.CORE_REASONING in registry.BASELINE_CAPABILITIES
    assert Capability.PASSIVE_INTAKE in registry.BASELINE_CAPABILITIES
    assert Capability.EXPLOIT_EXECUTION not in registry.BASELINE_CAPABILITIES


def test_tier_ladder_is_monotone() -> None:
    # OFFENSIVE permits EXPLOIT_EXECUTION; STANDARD does not.
    assert registry.tier_permits(CapabilityTier.OFFENSIVE, Capability.EXPLOIT_EXECUTION)
    assert not registry.tier_permits(CapabilityTier.STANDARD, Capability.EXPLOIT_EXECUTION)
    # ADVANCED permits everything OFFENSIVE permits, plus full-chain.
    assert registry.tier_permits(CapabilityTier.ADVANCED, Capability.EXPLOIT_EXECUTION)
    assert registry.tier_permits(CapabilityTier.ADVANCED, Capability.FULL_CHAIN_EXPLOITATION)
    assert not registry.tier_permits(CapabilityTier.OFFENSIVE, Capability.FULL_CHAIN_EXPLOITATION)


def test_effective_capabilities_empty_allowlist_is_whole_tier() -> None:
    caps = registry.effective_capabilities(CapabilityTier.OFFENSIVE, [])
    assert Capability.EXPLOIT_EXECUTION in caps
    assert Capability.CORE_REASONING in caps          # lower tiers included
    assert Capability.FULL_CHAIN_EXPLOITATION not in caps  # above tier excluded


def test_effective_capabilities_allowlist_restricts_within_tier() -> None:
    caps = registry.effective_capabilities(
        CapabilityTier.ADVANCED, [Capability.EXPLOIT_EXECUTION]
    )
    assert caps == frozenset({Capability.EXPLOIT_EXECUTION})


def test_allowlist_cannot_elevate_above_tier() -> None:
    # A STANDARD grant listing an ADVANCED capability must NOT confer it.
    caps = registry.effective_capabilities(
        CapabilityTier.STANDARD, [Capability.FULL_CHAIN_EXPLOITATION]
    )
    assert Capability.FULL_CHAIN_EXPLOITATION not in caps


# ---- canonical ------------------------------------------------------------


def _doc() -> EntitlementDocument:
    now = datetime(2026, 1, 1, tzinfo=timezone.utc)
    return EntitlementDocument(
        entitlement_id="ent-x",
        issuer="panel",
        subject=EntitlementSubject(institution_id="i", institution_name="n"),
        capability_tier=CapabilityTier.OFFENSIVE,
        issued_at=now,
        not_before=now - timedelta(hours=1),
        not_after=now + timedelta(hours=1),
    )


def test_entitlement_canonical_bytes_are_deterministic() -> None:
    doc = _doc()
    # Re-validate through a JSON round-trip; canonical bytes must match.
    reparsed = EntitlementDocument.model_validate(doc.model_dump(mode="json"))
    assert canonical.entitlement_signing_bytes(doc) == canonical.entitlement_signing_bytes(reparsed)


def test_entitlement_canonical_is_domain_separated() -> None:
    doc = _doc()
    rev = RevocationDocument(
        serial=1, issued_at=datetime(2026, 1, 1, tzinfo=timezone.utc), revoked_entitlement_ids=[]
    )
    eb = canonical.entitlement_signing_bytes(doc)
    rb = canonical.revocation_signing_bytes(rev)
    assert eb.startswith(b"crucible-entitlement-v1\x00")
    assert rb.startswith(b"crucible-revocation-v1\x00")
    assert eb != rb


def test_canonical_changes_when_a_field_changes() -> None:
    doc = _doc()
    mutated = doc.model_copy(update={"entitlement_id": "ent-y"})
    assert canonical.entitlement_signing_bytes(doc) != canonical.entitlement_signing_bytes(mutated)
