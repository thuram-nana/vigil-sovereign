"""Tests for the three post-audit entitlement hardening fixes:

  1. Revocation fail-OPEN by deletion — a `revocation_required` grant
     denies when its revocation list is absent (rm revocation.json no
     longer un-gates a revocable entitlement).
  2. Serial anti-rollback — a validly-signed revocation list whose serial
     is below the last-accepted high-water mark is refused as a replay.
  3. operator_constraint — a grant carrying an operator_constraint binds
     to the presented operator identity (CRUCIBLE_OPERATOR_IDENTITY).

Each provisions material into an isolated entitlement dir (via `mint`),
resets the cached policy, and exercises the gate.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from ...common import paths
from ...common.errors import (
    EntitlementBindingMismatch,
    EntitlementInvalid,
    EntitlementRevoked,
)
from .. import policy, store
from ..models import (
    Capability,
    CapabilityTier,
    EntitlementDocument,
    EntitlementSubject,
    HardwareBinding,
)
from .conftest import Mint


def _doc(
    *,
    entitlement_id: str = "ent-hard",
    revocation_required: bool = False,
    operator_constraint: str | None = None,
) -> EntitlementDocument:
    now = datetime.now(timezone.utc)
    return EntitlementDocument(
        entitlement_id=entitlement_id,
        issuer="ANTIC Governance Panel",
        subject=EntitlementSubject(
            institution_id="inst-0001",
            institution_name="Authorised Red Team Alpha",
            operator_constraint=operator_constraint,
        ),
        capability_tier=CapabilityTier.OFFENSIVE,
        binding=HardwareBinding(),
        revocation_required=revocation_required,
        issued_at=now,
        not_before=now - timedelta(hours=1),
        not_after=now + timedelta(hours=1),
    )


# ---------------------------------------------------------------------------
# Fix 1 — revocation fail-OPEN by deletion
# ---------------------------------------------------------------------------


def test_revocation_required_denies_when_list_absent(mint: Mint) -> None:
    """A revocable grant with no revocation list on disk fails CLOSED.
    This is the 'rm revocation.json' bypass being closed."""
    auth = mint.authority(n=1, threshold=1)
    mint.entitle(
        auth,
        auth.all_signers(),
        document=_doc(entitlement_id="ent-req", revocation_required=True),
    )
    # No revocation.json written at all.
    assert not paths.revocation_path().is_file()
    p = policy.EntitlementPolicy.from_provisioned()
    with pytest.raises(EntitlementRevoked):
        p.assert_capability(Capability.EXPLOIT_EXECUTION)


def test_revocation_required_denies_after_deletion(mint: Mint) -> None:
    """Provision a valid list, then delete it: the grant must now deny."""
    auth = mint.authority(n=1, threshold=1)
    mint.entitle(
        auth,
        auth.all_signers(),
        document=_doc(entitlement_id="ent-del", revocation_required=True),
    )
    mint.revoke(auth, auth.all_signers(), revoked_ids=["unrelated"], serial=1)
    # With the list present the grant is fine.
    policy.reset_policy()
    assert (
        policy.EntitlementPolicy.from_provisioned()
        .assert_capability(Capability.EXPLOIT_EXECUTION)
        .allowed
        is True
    )
    # Delete the list — the only post-issuance kill — and re-evaluate.
    paths.revocation_path().unlink()
    policy.reset_policy()
    with pytest.raises(EntitlementRevoked):
        policy.EntitlementPolicy.from_provisioned().assert_capability(
            Capability.EXPLOIT_EXECUTION
        )


def test_revocation_required_allows_with_present_valid_list(mint: Mint) -> None:
    auth = mint.authority(n=1, threshold=1)
    mint.entitle(
        auth,
        auth.all_signers(),
        document=_doc(entitlement_id="ent-ok", revocation_required=True),
    )
    mint.revoke(auth, auth.all_signers(), revoked_ids=["someone-else"], serial=1)
    p = policy.EntitlementPolicy.from_provisioned()
    assert p.assert_capability(Capability.EXPLOIT_EXECUTION).allowed is True


def test_legacy_grant_without_revocation_source_still_allows(mint: Mint) -> None:
    """revocation_required defaults to False: an absent list is not a
    denial for a grant that never expected one (fixture compatibility)."""
    auth = mint.authority(n=1, threshold=1)
    mint.entitle(
        auth,
        auth.all_signers(),
        document=_doc(entitlement_id="ent-legacy", revocation_required=False),
    )
    assert not paths.revocation_path().is_file()
    p = policy.EntitlementPolicy.from_provisioned()
    assert p.assert_capability(Capability.EXPLOIT_EXECUTION).allowed is True


# ---------------------------------------------------------------------------
# Fix 2 — serial anti-rollback
# ---------------------------------------------------------------------------


def test_revocation_rollback_is_refused(mint: Mint) -> None:
    auth = mint.authority(n=1, threshold=1)
    mint.entitle(
        auth, auth.all_signers(), document=_doc(entitlement_id="ent-roll")
    )
    # Accept a high serial first; this advances the persisted high-water mark.
    mint.revoke(auth, auth.all_signers(), revoked_ids=["nobody"], serial=5)
    policy.reset_policy()
    assert (
        policy.EntitlementPolicy.from_provisioned()
        .assert_capability(Capability.EXPLOIT_EXECUTION)
        .allowed
        is True
    )
    assert store.load_revocation_highwater() == 5

    # Replay an older, still-validly-signed list. Must be refused.
    mint.revoke(auth, auth.all_signers(), revoked_ids=["nobody"], serial=3)
    policy.reset_policy()
    with pytest.raises(EntitlementInvalid):
        policy.EntitlementPolicy.from_provisioned().assert_capability(
            Capability.EXPLOIT_EXECUTION
        )


def test_revocation_same_serial_is_accepted(mint: Mint) -> None:
    auth = mint.authority(n=1, threshold=1)
    mint.entitle(
        auth, auth.all_signers(), document=_doc(entitlement_id="ent-same")
    )
    mint.revoke(auth, auth.all_signers(), revoked_ids=["nobody"], serial=4)
    policy.reset_policy()
    assert (
        policy.EntitlementPolicy.from_provisioned()
        .assert_capability(Capability.EXPLOIT_EXECUTION)
        .allowed
        is True
    )
    # Re-presenting the same serial (not a rollback) is fine.
    policy.reset_policy()
    assert (
        policy.EntitlementPolicy.from_provisioned()
        .assert_capability(Capability.EXPLOIT_EXECUTION)
        .allowed
        is True
    )


def test_revocation_higher_serial_advances_mark(mint: Mint) -> None:
    auth = mint.authority(n=1, threshold=1)
    mint.entitle(
        auth, auth.all_signers(), document=_doc(entitlement_id="ent-adv")
    )
    mint.revoke(auth, auth.all_signers(), revoked_ids=["nobody"], serial=2)
    policy.reset_policy()
    policy.EntitlementPolicy.from_provisioned().assert_capability(
        Capability.EXPLOIT_EXECUTION
    )
    assert store.load_revocation_highwater() == 2
    # A newer list advances the mark and still applies.
    mint.revoke(auth, auth.all_signers(), revoked_ids=["ent-adv"], serial=9)
    policy.reset_policy()
    with pytest.raises(EntitlementRevoked):
        policy.EntitlementPolicy.from_provisioned().assert_capability(
            Capability.EXPLOIT_EXECUTION
        )
    assert store.load_revocation_highwater() == 9


def test_corrupt_highwater_mark_fails_closed(mint: Mint) -> None:
    auth = mint.authority(n=1, threshold=1)
    mint.entitle(
        auth, auth.all_signers(), document=_doc(entitlement_id="ent-corrupt")
    )
    mint.revoke(auth, auth.all_signers(), revoked_ids=["nobody"], serial=1)
    store.revocation_highwater_path().write_text("not json", encoding="utf-8")
    policy.reset_policy()
    with pytest.raises(EntitlementInvalid):
        policy.EntitlementPolicy.from_provisioned().assert_capability(
            Capability.EXPLOIT_EXECUTION
        )


# ---------------------------------------------------------------------------
# Fix 3 — operator_constraint
# ---------------------------------------------------------------------------


def test_operator_constraint_denies_without_identity(mint: Mint) -> None:
    auth = mint.authority(n=1, threshold=1)
    mint.entitle(
        auth,
        auth.all_signers(),
        document=_doc(
            entitlement_id="ent-op",
            operator_constraint="spiffe://institution/operator/alice",
        ),
    )
    # CRUCIBLE_OPERATOR_IDENTITY is cleared by the autouse fixture.
    p = policy.EntitlementPolicy.from_provisioned()
    with pytest.raises(EntitlementBindingMismatch):
        p.assert_capability(Capability.EXPLOIT_EXECUTION)


def test_operator_constraint_exact_match_allows(
    mint: Mint, monkeypatch: pytest.MonkeyPatch
) -> None:
    ident = "spiffe://institution/operator/alice"
    monkeypatch.setenv("CRUCIBLE_OPERATOR_IDENTITY", ident)
    auth = mint.authority(n=1, threshold=1)
    mint.entitle(
        auth,
        auth.all_signers(),
        document=_doc(entitlement_id="ent-op2", operator_constraint=ident),
    )
    policy.reset_policy()
    p = policy.EntitlementPolicy.from_provisioned()
    assert p.assert_capability(Capability.EXPLOIT_EXECUTION).allowed is True


def test_operator_constraint_prefix_match_allows(
    mint: Mint, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv(
        "CRUCIBLE_OPERATOR_IDENTITY", "spiffe://institution/operator/alice/laptop"
    )
    auth = mint.authority(n=1, threshold=1)
    mint.entitle(
        auth,
        auth.all_signers(),
        document=_doc(
            entitlement_id="ent-op3",
            operator_constraint="spiffe://institution/operator/",
        ),
    )
    policy.reset_policy()
    p = policy.EntitlementPolicy.from_provisioned()
    assert p.assert_capability(Capability.EXPLOIT_EXECUTION).allowed is True


def test_operator_constraint_wrong_identity_denies(
    mint: Mint, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv(
        "CRUCIBLE_OPERATOR_IDENTITY", "spiffe://institution/operator/mallory"
    )
    auth = mint.authority(n=1, threshold=1)
    mint.entitle(
        auth,
        auth.all_signers(),
        document=_doc(
            entitlement_id="ent-op4",
            operator_constraint="spiffe://institution/operator/alice",
        ),
    )
    policy.reset_policy()
    p = policy.EntitlementPolicy.from_provisioned()
    with pytest.raises(EntitlementBindingMismatch):
        p.assert_capability(Capability.EXPLOIT_EXECUTION)


def test_no_operator_constraint_ignores_identity_env(
    mint: Mint, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A grant with no operator_constraint is unaffected by the env var."""
    monkeypatch.setenv("CRUCIBLE_OPERATOR_IDENTITY", "spiffe://whatever")
    auth = mint.authority(n=1, threshold=1)
    mint.entitle(
        auth,
        auth.all_signers(),
        document=_doc(entitlement_id="ent-op5", operator_constraint=None),
    )
    policy.reset_policy()
    p = policy.EntitlementPolicy.from_provisioned()
    assert p.assert_capability(Capability.EXPLOIT_EXECUTION).allowed is True
