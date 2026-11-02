"""K4-5d(A) — provision the per-launch owner-signed OFFENSE_GOVERNANCE_ROLE delegation.

``provision_launch_governance`` is the sovereign (owner-keyed) half of the completion seam: at launch it mints
an owner-signed delegation over the STABLE offense-governance key, scoped to the launch's ``cust_`` slug, which
the keyless worker's crossing + completion signals then verify against. These pin: the minted delegation
VERIFIES under the owner key + OFFENSE_GOVERNANCE_ROLE + the exact slug scope; it delegates to the SAME gov key
the worker signs with (so the two halves compose); an unsafe slug is refused (fail-closed); re-provisioning is
idempotent; the delegation does NOT verify under a different scope (the cross-tenant bound).

Sovereign leg: PYTHONPATH=apps/sigil:integration (imports the vigil_core-only governance_identity seam).
"""
from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path

import pytest

from sigil.governor.identity import ensure_owner_keypair, owner_pubkey
from sigil.ui.launch_governance import (
    LAUNCH_GOVERNANCE_DELEG_FILE, provision_launch_governance,
)
from vigil_core.delegation import OFFENSE_GOVERNANCE_ROLE, verify_delegation
from vigil_integration.live.governance_identity import (
    DEFAULT_GOVERNANCE_KEY_FILE, GOVERNANCE_KEY_ID, load_or_create_governance_keypair,
)

SLUG = "cust_" + "a" * 24
NOT_AFTER = 9_000_000_000


@pytest.fixture(autouse=True)
def _iso(monkeypatch):
    monkeypatch.setenv("VIGIL_BASE_DIR", tempfile.mkdtemp())
    monkeypatch.setenv("SIGIL_SPINE_DIR", tempfile.mkdtemp())
    monkeypatch.setenv("SIGIL_HOME", tempfile.mkdtemp())


def _cert(path):
    from vigil_core.delegation import DelegationCert
    return DelegationCert.model_validate_json(Path(path).read_text(encoding="utf-8"))


def test_provisions_a_delegation_that_verifies_under_owner_role_and_scope():
    ensure_owner_keypair()
    base = os.environ["VIGIL_BASE_DIR"]
    path = provision_launch_governance(slug=SLUG, not_after=NOT_AFTER, base_dir=base)
    assert path == str(Path(base) / SLUG / LAUNCH_GOVERNANCE_DELEG_FILE)
    cert = _cert(path)
    # verifies under THIS owner, the OFFENSE_GOVERNANCE_ROLE, and the exact cust_ slug scope
    root = verify_delegation(cert, trusted_owner_pubkey=owner_pubkey(), now=1000,
                             role=OFFENSE_GOVERNANCE_ROLE, scope=SLUG)
    assert root is not None


def test_delegates_to_the_same_gov_key_the_worker_signs_with():
    # the delegation's authorizer pubkey MUST be the base's stable gov key (key_id GOVERNANCE_KEY_ID), so the
    # keyless worker — which loads the SAME key under the SAME base — signs completions the delegation covers.
    ensure_owner_keypair()
    base = os.environ["VIGIL_BASE_DIR"]
    provision_launch_governance(slug=SLUG, not_after=NOT_AFTER, base_dir=base)
    cert = _cert(str(Path(base) / SLUG / LAUNCH_GOVERNANCE_DELEG_FILE))
    gov_kp = load_or_create_governance_keypair(path=str(Path(base) / DEFAULT_GOVERNANCE_KEY_FILE))
    auths = {a.key_id: a.public_key_b64 for a in cert.authorizers}
    assert auths == {GOVERNANCE_KEY_ID: gov_kp.public_key_b64}


def test_does_not_verify_under_a_different_scope():
    ensure_owner_keypair()
    base = os.environ["VIGIL_BASE_DIR"]
    path = provision_launch_governance(slug=SLUG, not_after=NOT_AFTER, base_dir=base)
    cert = _cert(path)
    from vigil_core.delegation import DelegationError
    with pytest.raises(DelegationError):               # scoped to SLUG — a different cust_ slug is NOT covered
        verify_delegation(cert, trusted_owner_pubkey=owner_pubkey(), now=1000,
                          role=OFFENSE_GOVERNANCE_ROLE, scope="cust_" + "b" * 24)


def test_unsafe_slug_is_refused():
    ensure_owner_keypair()
    base = os.environ["VIGIL_BASE_DIR"]
    for bad in ("../evil", "cust_../x", "notcust", "cust_" + "Z" * 10, "cust_" + "a" * 200):
        with pytest.raises(ValueError):
            provision_launch_governance(slug=bad, not_after=NOT_AFTER, base_dir=base)


def test_idempotent_reprovision():
    ensure_owner_keypair()
    base = os.environ["VIGIL_BASE_DIR"]
    p1 = provision_launch_governance(slug=SLUG, not_after=NOT_AFTER, base_dir=base)
    p2 = provision_launch_governance(slug=SLUG, not_after=NOT_AFTER + 1000, base_dir=base)
    assert p1 == p2
    assert len(list((Path(base) / SLUG).glob("*.deleg.json"))) == 1   # one delegation, overwritten in place
    root = verify_delegation(_cert(p2), trusted_owner_pubkey=owner_pubkey(), now=1000,
                             role=OFFENSE_GOVERNANCE_ROLE, scope=SLUG)
    assert root is not None


def test_not_after_is_honored():
    ensure_owner_keypair()
    base = os.environ["VIGIL_BASE_DIR"]
    path = provision_launch_governance(slug=SLUG, not_after=5000, base_dir=base)
    cert = _cert(path)
    from vigil_core.delegation import DelegationError
    verify_delegation(cert, trusted_owner_pubkey=owner_pubkey(), now=4000,
                      role=OFFENSE_GOVERNANCE_ROLE, scope=SLUG)        # valid before not_after
    with pytest.raises(DelegationError):
        verify_delegation(cert, trusted_owner_pubkey=owner_pubkey(), now=6000,
                          role=OFFENSE_GOVERNANCE_ROLE, scope=SLUG)    # expired after not_after
