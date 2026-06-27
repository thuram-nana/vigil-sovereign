"""End-to-end tests for the entitlement gate (policy.py).

Each test provisions material into an isolated entitlement dir (via the
`mint` fixture), resets the cached policy, and exercises
`require_capability` / `is_capability_available`.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

import pytest

from ...common import paths
from ...common.errors import (
    CapabilityNotGranted,
    EntitlementBindingMismatch,
    EntitlementExpired,
    EntitlementInvalid,
    EntitlementMissing,
    EntitlementRevoked,
)
from .. import policy
from ..models import Capability, CapabilityTier, HardwareBinding
from .conftest import Mint


# ---------------------------------------------------------------------------
# Ungoverned (no trust root) — baseline runs, gated permitted-with-warning
# ---------------------------------------------------------------------------


def test_ungoverned_baseline_available() -> None:
    p = policy.EntitlementPolicy.from_provisioned()
    assert p.enforced is False
    d = p.assert_capability(Capability.CORE_REASONING)
    assert d.allowed is True


def test_ungoverned_permits_gated_capability() -> None:
    p = policy.EntitlementPolicy.from_provisioned()
    assert p.is_capability_available(Capability.EXPLOIT_EXECUTION) is True
    d = p.assert_capability(Capability.EXPLOIT_EXECUTION)
    assert d.allowed is True
    assert d.enforced is False


# ---------------------------------------------------------------------------
# Enforcement forced by env with no trust root — fail closed
# ---------------------------------------------------------------------------


def test_enforced_env_without_trust_root_denies_gated(enforced: object) -> None:
    enforced()  # type: ignore[operator]
    p = policy.EntitlementPolicy.from_provisioned()
    assert p.enforced is True
    # Baseline still runs.
    assert p.assert_capability(Capability.PASSIVE_INTAKE).allowed is True
    # Gated capability is denied.
    with pytest.raises(EntitlementInvalid):
        p.assert_capability(Capability.EXPLOIT_EXECUTION)


# ---------------------------------------------------------------------------
# Trust root present but no entitlement — EntitlementMissing
# ---------------------------------------------------------------------------


def test_trust_root_without_entitlement_is_missing(mint: Mint) -> None:
    mint.authority(n=1, threshold=1)  # writes trust-root.json only
    p = policy.EntitlementPolicy.from_provisioned()
    assert p.enforced is True
    with pytest.raises(EntitlementMissing):
        p.assert_capability(Capability.EXPLOIT_EXECUTION)
    # Baseline unaffected.
    assert p.assert_capability(Capability.CORE_REASONING).allowed is True


# ---------------------------------------------------------------------------
# Valid entitlement — capability granted / not granted by tier
# ---------------------------------------------------------------------------


def test_valid_offensive_entitlement_grants_exploit(mint: Mint) -> None:
    auth = mint.authority(n=1, threshold=1)
    mint.entitle(auth, auth.all_signers(), tier=CapabilityTier.OFFENSIVE)
    p = policy.EntitlementPolicy.from_provisioned()
    assert p.granted_tier is CapabilityTier.OFFENSIVE
    assert p.assert_capability(Capability.EXPLOIT_EXECUTION).allowed is True


def test_offensive_entitlement_denies_advanced(mint: Mint) -> None:
    auth = mint.authority(n=1, threshold=1)
    mint.entitle(auth, auth.all_signers(), tier=CapabilityTier.OFFENSIVE)
    p = policy.EntitlementPolicy.from_provisioned()
    with pytest.raises(CapabilityNotGranted):
        p.assert_capability(Capability.FULL_CHAIN_EXPLOITATION)


def test_least_privilege_allowlist(mint: Mint) -> None:
    auth = mint.authority(n=1, threshold=1)
    mint.entitle(
        auth,
        auth.all_signers(),
        tier=CapabilityTier.ADVANCED,
        granted=[Capability.EXPLOIT_EXECUTION],
    )
    p = policy.EntitlementPolicy.from_provisioned()
    assert p.assert_capability(Capability.EXPLOIT_EXECUTION).allowed is True
    # Tier would permit it, but the allowlist does not.
    with pytest.raises(CapabilityNotGranted):
        p.assert_capability(Capability.FULL_CHAIN_EXPLOITATION)


# ---------------------------------------------------------------------------
# Threshold
# ---------------------------------------------------------------------------


def test_threshold_met_two_of_three(mint: Mint) -> None:
    auth = mint.authority(n=3, threshold=2)
    mint.entitle(auth, auth.signers("auth-0", "auth-1"), tier=CapabilityTier.OFFENSIVE)
    p = policy.EntitlementPolicy.from_provisioned()
    assert p.assert_capability(Capability.EXPLOIT_EXECUTION).allowed is True


def test_threshold_not_met_one_of_two(mint: Mint) -> None:
    auth = mint.authority(n=2, threshold=2)
    mint.entitle(auth, auth.signers("auth-0"), tier=CapabilityTier.OFFENSIVE)
    p = policy.EntitlementPolicy.from_provisioned()
    with pytest.raises(EntitlementInvalid):
        p.assert_capability(Capability.EXPLOIT_EXECUTION)


# ---------------------------------------------------------------------------
# Tamper
# ---------------------------------------------------------------------------


def test_tampered_document_fails_signature(mint: Mint) -> None:
    auth = mint.authority(n=1, threshold=1)
    mint.entitle(auth, auth.all_signers(), tier=CapabilityTier.OFFENSIVE)
    # Escalate the tier on disk after signing.
    ep = paths.entitlement_path()
    blob = json.loads(ep.read_text(encoding="utf-8"))
    blob["document"]["capability_tier"] = "advanced"
    ep.write_text(json.dumps(blob), encoding="utf-8")
    p = policy.EntitlementPolicy.from_provisioned()
    with pytest.raises(EntitlementInvalid):
        p.assert_capability(Capability.FULL_CHAIN_EXPLOITATION)


# ---------------------------------------------------------------------------
# Validity window
# ---------------------------------------------------------------------------


def test_expired_entitlement(mint: Mint) -> None:
    auth = mint.authority(n=1, threshold=1)
    now = datetime.now(timezone.utc)
    mint.entitle(
        auth,
        auth.all_signers(),
        tier=CapabilityTier.OFFENSIVE,
        not_before=now - timedelta(hours=2),
        not_after=now - timedelta(hours=1),
    )
    p = policy.EntitlementPolicy.from_provisioned()
    with pytest.raises(EntitlementExpired):
        p.assert_capability(Capability.EXPLOIT_EXECUTION)


def test_not_yet_valid_entitlement(mint: Mint) -> None:
    auth = mint.authority(n=1, threshold=1)
    now = datetime.now(timezone.utc)
    mint.entitle(
        auth,
        auth.all_signers(),
        tier=CapabilityTier.OFFENSIVE,
        not_before=now + timedelta(hours=1),
        not_after=now + timedelta(hours=2),
    )
    p = policy.EntitlementPolicy.from_provisioned()
    with pytest.raises(EntitlementExpired):
        p.assert_capability(Capability.EXPLOIT_EXECUTION)


# ---------------------------------------------------------------------------
# Host binding
# ---------------------------------------------------------------------------


def test_binding_mismatch_denies(mint: Mint) -> None:
    auth = mint.authority(n=1, threshold=1)
    binding = HardwareBinding(
        binding_type="host_attestation",
        bound_identifiers=["spiffe://institution/red-team/never-matches-this-host"],
    )
    mint.entitle(auth, auth.all_signers(), tier=CapabilityTier.OFFENSIVE, binding=binding)
    p = policy.EntitlementPolicy.from_provisioned()
    with pytest.raises(EntitlementBindingMismatch):
        p.assert_capability(Capability.EXPLOIT_EXECUTION)


def test_binding_satisfied_by_attested_identity(
    mint: Mint, monkeypatch: pytest.MonkeyPatch
) -> None:
    attested = "spiffe://institution/red-team/host-7"
    monkeypatch.setenv("CRUCIBLE_ATTESTED_IDENTITY", attested)
    auth = mint.authority(n=1, threshold=1)
    binding = HardwareBinding(binding_type="host_attestation", bound_identifiers=[attested])
    mint.entitle(auth, auth.all_signers(), tier=CapabilityTier.OFFENSIVE, binding=binding)
    policy.reset_policy()
    p = policy.EntitlementPolicy.from_provisioned()
    assert p.assert_capability(Capability.EXPLOIT_EXECUTION).allowed is True


# ---------------------------------------------------------------------------
# Revocation
# ---------------------------------------------------------------------------


def test_revocation_blocks_listed_entitlement(mint: Mint) -> None:
    auth = mint.authority(n=1, threshold=1)
    mint.entitle(
        auth, auth.all_signers(), tier=CapabilityTier.OFFENSIVE, entitlement_id="ent-revoke-me"
    )
    mint.revoke(auth, auth.all_signers(), revoked_ids=["ent-revoke-me"])
    p = policy.EntitlementPolicy.from_provisioned()
    with pytest.raises(EntitlementRevoked):
        p.assert_capability(Capability.EXPLOIT_EXECUTION)


def test_revocation_not_listing_entitlement_is_fine(mint: Mint) -> None:
    auth = mint.authority(n=1, threshold=1)
    mint.entitle(
        auth, auth.all_signers(), tier=CapabilityTier.OFFENSIVE, entitlement_id="ent-keep"
    )
    mint.revoke(auth, auth.all_signers(), revoked_ids=["some-other-id"])
    p = policy.EntitlementPolicy.from_provisioned()
    assert p.assert_capability(Capability.EXPLOIT_EXECUTION).allowed is True


def test_invalidly_signed_revocation_fails_closed(mint: Mint) -> None:
    auth = mint.authority(n=1, threshold=1)
    mint.entitle(auth, auth.all_signers(), tier=CapabilityTier.OFFENSIVE, entitlement_id="ent-x")
    # Write a revocation list and then corrupt its signature on disk.
    mint.revoke(auth, auth.all_signers(), revoked_ids=["unrelated"])
    rp = paths.revocation_path()
    blob = json.loads(rp.read_text(encoding="utf-8"))
    # Flip the signature to a structurally-valid but wrong value.
    import base64

    blob["signatures"][0]["signature_b64"] = base64.b64encode(b"\x00" * 64).decode()
    rp.write_text(json.dumps(blob), encoding="utf-8")
    p = policy.EntitlementPolicy.from_provisioned()
    with pytest.raises(EntitlementInvalid):
        p.assert_capability(Capability.EXPLOIT_EXECUTION)


# ---------------------------------------------------------------------------
# Audit decision shape + module-level helpers
# ---------------------------------------------------------------------------


def test_decision_record_is_populated(mint: Mint) -> None:
    auth = mint.authority(n=1, threshold=1)
    mint.entitle(
        auth, auth.all_signers(), tier=CapabilityTier.OFFENSIVE, entitlement_id="ent-audit"
    )
    p = policy.EntitlementPolicy.from_provisioned()
    d = p.assert_capability(Capability.EXPLOIT_EXECUTION)
    assert d.capability is Capability.EXPLOIT_EXECUTION
    assert d.entitlement_id == "ent-audit"
    assert d.institution == "Authorised Red Team Alpha"
    assert d.evaluated_at.tzinfo is not None


def test_module_level_require_and_set_policy(mint: Mint) -> None:
    auth = mint.authority(n=1, threshold=1)
    mint.entitle(auth, auth.all_signers(), tier=CapabilityTier.OFFENSIVE)
    # Fresh build via module-level helper.
    policy.reset_policy()
    assert policy.require_capability(Capability.EXPLOIT_EXECUTION).allowed is True
    assert policy.is_capability_available(Capability.FULL_CHAIN_EXPLOITATION) is False
