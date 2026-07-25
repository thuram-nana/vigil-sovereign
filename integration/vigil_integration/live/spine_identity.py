"""The stable offense engagement-spine identity (unification S5).

Before S5 the offense live engine signed its checkpoint spine, executor ExecRecords, and detection
certificates with a keypair minted FRESH per run (``generate_keypair()`` in wiring) and persisted nowhere —
so once the process exited nothing could verify the prior run's spine, and a restart against the same
``{slug}.spine`` file produced a new key that rejected every earlier line. This retires that ephemeral key:
a STABLE offense-spine keypair, generated once and persisted ``0600`` under the offense worker's own vault
(AEAD-sealed at rest when the vault is provisioned), so the offense spine is verifiable across runs and can
be owner-DELEGATED (``OFFENSE_SPINE_ROLE``) exactly like the operator key — the offense side holds only its
OWN stable key, never the owner private key, so the two-env boundary is untouched.

It is the offense-SPINE analogue of ``attestation.identity.load_or_create_operator_keypair`` and shares the
same reviewed implementation (``vigil_core.keystore``), differing only in its AEAD purpose-binding context
so a spine-key blob can never be opened as the operator key (or vice-versa).

At-rest posture (state it plainly): the DEFAULT is PLAINTEXT at rest (``0600``) until the offense worker's
vault is provisioned — the same posture the operator key already has, and a deliberate trade-off for a
STABLE cross-run identity (an ephemeral key never touched disk but could not be verified across runs).
Provision the vault to AEAD-seal it; ``vault.status()`` reports the unsealed state loudly."""
from __future__ import annotations

from vigil_core.crypto import KeyPair
from vigil_core.keystore import load_or_create_sealed_keypair

# AEAD purpose-binding for the sealed offense-spine keypair — DISTINCT from the operator key's context
# (``b"vigil/operator.key"``) so the two sealed identities are cryptographically non-interchangeable.
SPINE_KEYPAIR_CONTEXT = b"vigil/offense-spine.key"

# Default persisted spine keypair filename under the offense engagement base_dir.
DEFAULT_SPINE_KEY_FILE = "offense-spine.key"


def load_or_create_spine_keypair(*, path: str, vault: object = None) -> KeyPair:
    """Load the persisted stable offense-spine keypair, or generate + persist one (``0600``) on first use,
    sealed at rest under ``vault`` when it is provisioned. Fail-closed on a sealed-but-unopenable file
    (``VaultLocked``) — never mints a NEW divergent spine identity that would orphan the existing spine.
    See :func:`vigil_core.keystore.load_or_create_sealed_keypair`."""
    return load_or_create_sealed_keypair(path=path, context=SPINE_KEYPAIR_CONTEXT, vault=vault)
