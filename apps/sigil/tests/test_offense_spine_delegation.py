"""S5 — the owner-side issuer for the stable offense-spine identity delegation.

`delegate_offense_spine` lets the owner (holder of the sovereign key) mint a DelegationCert authorizing the
stable offense-spine pubkey under OFFENSE_SPINE_ROLE, so a verifier can chain an offense spine head back to
the owner. Proves the wrapper wires the right role and produces a cert that verifies for the spine role and
refuses under the governance role.

Run: pytest apps/sigil/tests/test_offense_spine_delegation.py -q
"""
import pytest

from sigil.governor.identity import delegate_offense_governance, delegate_offense_spine
from vigil_core import AuthorizerKey, generate_keypair
from vigil_core.delegation import (
    OFFENSE_GOVERNANCE_ROLE,
    OFFENSE_SPINE_ROLE,
    DelegationError,
    verify_delegation,
)

OWNER = generate_keypair()
SPINE = generate_keypair()
SPINE_AUTH = AuthorizerKey(key_id="offense-spine-0", name="offense-spine-0",
                           public_key_b64=SPINE.public_key_b64)
NOW, NOT_AFTER = 1000, 2000


def test_owner_delegates_the_spine_identity_and_it_verifies():
    cert = delegate_offense_spine(OWNER, authorizers=[SPINE_AUTH], scope="loopback", not_after=NOT_AFTER)
    root = verify_delegation(cert, trusted_owner_pubkey=OWNER.public_key_b64, now=NOW,
                             role=OFFENSE_SPINE_ROLE, scope="loopback")
    assert root.threshold == 1
    assert root.authorizers[0].public_key_b64 == SPINE.public_key_b64


def test_a_spine_delegation_does_not_authorize_governance():
    spine_cert = delegate_offense_spine(OWNER, authorizers=[SPINE_AUTH], scope="loopback", not_after=NOT_AFTER)
    with pytest.raises(DelegationError, match="role"):
        verify_delegation(spine_cert, trusted_owner_pubkey=OWNER.public_key_b64, now=NOW,
                          role=OFFENSE_GOVERNANCE_ROLE, scope="loopback")


def test_a_governance_delegation_does_not_authorize_the_spine():
    gov_cert = delegate_offense_governance(OWNER, authorizers=[SPINE_AUTH], threshold=1,
                                           scope="loopback", not_after=NOT_AFTER)
    with pytest.raises(DelegationError, match="role"):
        verify_delegation(gov_cert, trusted_owner_pubkey=OWNER.public_key_b64, now=NOW,
                          role=OFFENSE_SPINE_ROLE, scope="loopback")
