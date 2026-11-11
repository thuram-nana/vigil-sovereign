"""A signed core that cannot be canonicalised to UTF-8 fails with the module's OWN typed error.

Inert signed data crosses process and plane boundaries as JSON, and JSON can carry a lone surrogate
(``"\\ud800"``) that no signer could have produced. Encoding it to UTF-8 raises ``UnicodeEncodeError`` (a
``ValueError``). Every verifier documents a fail-closed contract — raise ``CapabilityError`` /
``DelegationError`` on ANY failure — so callers catch exactly that type; an untyped error would escape them.
"""
from __future__ import annotations

import pytest

from vigil_core import AuthorizerKey, generate_keypair
from vigil_core.capability import (
    CapabilityError,
    attenuate,
    identity_digest,
    prove_wielder,
    sign_capability,
    sign_identity_attestation,
    verify_capability,
    verify_identity_attestation,
    verify_wielder_proof,
)
from vigil_core.delegation import OFFENSE_GOVERNANCE_ROLE, DelegationError, sign_delegation, verify_delegation

OWNER = generate_keypair()
HOLDER = generate_keypair()
ENG, NOW = "acme", 1_000
BAD = "\ud800"   # a lone surrogate: valid in a JSON string, impossible to encode as UTF-8


def _cap(audience="*"):
    ident = sign_identity_attestation(OWNER, engagement=ENG, policy={"host": ["shop.acme.test"]}, not_after=2_000)
    return sign_capability(OWNER, engagement=ENG, identity_digest=identity_digest(ident),
                           class_allowlist=["reflected_xss"], not_before=0, not_after=2_000, rate_limit=5,
                           revocation_id="rev-1", audience=audience)


def test_identity_attestation_with_an_unencodable_core_raises_capability_error():
    att = sign_identity_attestation(OWNER, engagement=ENG, policy={"host": ["shop.acme.test"]}, not_after=2_000)
    bad = att.model_copy(update={"policy": {"host": [BAD]}})
    with pytest.raises(CapabilityError, match="malformed"):
        verify_identity_attestation(bad, trusted_owner_pubkey=OWNER.public_key_b64, now=NOW, engagement=ENG)


def test_capability_with_an_unencodable_core_raises_capability_error():
    bad = _cap().model_copy(update={"revocation_id": f"rev-{BAD}"})
    with pytest.raises(CapabilityError, match="malformed"):
        verify_capability(bad, trusted_owner_pubkey=OWNER.public_key_b64, now=NOW, engagement=ENG)


def test_attenuation_with_an_unencodable_core_raises_capability_error():
    cap = _cap()
    att = attenuate(HOLDER, prev=cap, class_subset=["reflected_xss"])
    bad = att.model_copy(update={"class_subset": [BAD]})
    with pytest.raises(CapabilityError, match="attenuation #0 signature is malformed"):
        verify_capability(cap, trusted_owner_pubkey=OWNER.public_key_b64, now=NOW, engagement=ENG,
                          attenuations=[bad])


def test_wielder_proof_with_an_unencodable_core_raises_capability_error():
    cap = _cap(audience=HOLDER.public_key_b64)
    proof = prove_wielder(HOLDER, challenge="nonce-1", capability=cap).model_copy(update={"challenge": BAD})
    with pytest.raises(CapabilityError, match="wielder proof signature is malformed"):
        verify_wielder_proof(proof, expected_audience=HOLDER.public_key_b64, challenge=BAD, capability=cap)


def test_delegation_with_an_unencodable_core_raises_delegation_error():
    gov = generate_keypair()
    cert = sign_delegation(OWNER, role=OFFENSE_GOVERNANCE_ROLE, scope="loopback",
                           authorizers=[AuthorizerKey(key_id="root0", name="root0", public_key_b64=gov.public_key_b64)],
                           threshold=1, not_after=2_000)
    bad = cert.model_copy(update={"scope": BAD})
    with pytest.raises(DelegationError, match="malformed"):
        verify_delegation(bad, trusted_owner_pubkey=OWNER.public_key_b64, now=NOW, role=OFFENSE_GOVERNANCE_ROLE,
                          scope=BAD)
