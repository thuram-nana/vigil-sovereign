"""The stable offense GOVERNANCE identity (unification S7).

The CRUCIBLE governance/authority key is the anchor-1 signer: it signs the engagement authority and the
oracle-path finding evidence certificates (the Detection-Mirror PCFs are signed by the separate offense-SPINE
key, S5a), and it is the key an owner delegation (S4, ``OFFENSE_GOVERNANCE_ROLE``) authorizes so the sovereign
receiver can chain a finding back to the owner. Before S7 it was minted FRESH per
run (``generate_keypair()`` in ``provision_authority``), so an owner delegation for it would have to be
re-issued every run and the finding anchor-1 owner tie could never hold across restarts. This retires that:
a STABLE governance keypair, generated once and persisted ``0600`` under the offense worker's own vault
(AEAD-sealed at rest when the vault is provisioned), so ONE owner-signed delegation covers it durably.

It is the governance analogue of ``spine_identity.load_or_create_spine_keypair`` and shares the same reviewed
implementation (``vigil_core.keystore``), differing only in its AEAD purpose-binding context so a
governance-key blob can never be opened as the spine key or the operator key (or vice-versa). Plaintext at
rest until the vault is provisioned — the same documented posture as the operator and spine keys; provision
the vault to seal it."""
from __future__ import annotations

from vigil_core.crypto import KeyPair
from vigil_core.keystore import load_or_create_sealed_keypair

# AEAD purpose-binding for the sealed governance keypair — DISTINCT from the operator key
# (``b"vigil/operator.key"``) and the spine key (``b"vigil/offense-spine.key"``) so the three offense
# identities are cryptographically non-interchangeable.
GOVERNANCE_KEYPAIR_CONTEXT = b"vigil/offense-governance.key"

# Default persisted governance keypair filename under the offense engagement base_dir.
DEFAULT_GOVERNANCE_KEY_FILE = "offense-governance.key"


def load_or_create_governance_keypair(*, path: str, vault: object = None) -> KeyPair:
    """Load the persisted stable offense-governance keypair, or generate + persist one (``0600``) on first
    use, sealed at rest under ``vault`` when it is provisioned. Fail-closed on a sealed-but-unopenable file
    (``VaultLocked``) — never mints a NEW divergent governance identity that would orphan an existing
    owner delegation. See :func:`vigil_core.keystore.load_or_create_sealed_keypair`."""
    return load_or_create_sealed_keypair(path=path, context=GOVERNANCE_KEYPAIR_CONTEXT, vault=vault)
