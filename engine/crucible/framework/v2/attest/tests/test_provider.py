"""X1 — the software attestation fallback signs+verifies; the TEE backends are honest stubs."""

from __future__ import annotations

import pytest

from framework.v2.attest.provider import (
    AttestationQuote,
    SevSnpAttestationProvider,
    SoftwareAttestationProvider,
    TdxAttestationProvider,
)
from vigil_core.crypto import generate_keypair


def test_software_quote_signs_and_verifies() -> None:
    p = SoftwareAttestationProvider()
    q = p.attest(b"the-payload-bytes")
    assert p.verify(q) is True
    assert q.backend == "software-tpm-fallback"
    assert q.payload_sha256.startswith("sha256:")


def test_software_quote_is_not_hardware_backed() -> None:
    """Honesty: the software fallback never claims hardware confidentiality."""
    q = SoftwareAttestationProvider().attest(b"x")
    assert q.hardware_backed is False


def test_tampered_payload_digest_fails_verify() -> None:
    p = SoftwareAttestationProvider()
    q = p.attest(b"original")
    forged = q.model_copy(update={"payload_sha256": "sha256:" + "0" * 64})
    assert p.verify(forged) is False        # signature no longer covers the (changed) body


def test_tampered_backend_field_fails_verify() -> None:
    p = SoftwareAttestationProvider()
    q = p.attest(b"original")
    forged = q.model_copy(update={"backend": "sev-snp"})   # can't relabel a software quote as hardware
    assert p.verify(forged) is False


def test_signature_does_not_verify_under_a_different_key() -> None:
    q = SoftwareAttestationProvider().attest(b"payload")
    other_pub = generate_keypair().public_key_b64
    forged = q.model_copy(update={"signer_public_key_b64": other_pub})
    assert SoftwareAttestationProvider().verify(forged) is False


def test_fixed_key_makes_the_quote_deterministic() -> None:
    kp = generate_keypair()
    a = SoftwareAttestationProvider(kp).attest(b"same-bytes")
    b = SoftwareAttestationProvider(kp).attest(b"same-bytes")
    assert a.signature_b64 == b.signature_b64   # Ed25519 is deterministic (RFC 8032)


def test_verify_fails_closed_on_empty_or_malformed_signature() -> None:
    p = SoftwareAttestationProvider()
    q = p.attest(b"x")
    assert p.verify(q.model_copy(update={"signature_b64": ""})) is False
    assert p.verify(q.model_copy(update={"signature_b64": "!!!not-base64!!!"})) is False


def test_non_bytes_payload_is_rejected() -> None:
    with pytest.raises(TypeError):
        SoftwareAttestationProvider().attest("a string, not bytes")  # type: ignore[arg-type]


def test_quote_round_trips_through_json() -> None:
    p = SoftwareAttestationProvider()
    q = p.attest(b"payload")
    q2 = AttestationQuote.model_validate_json(q.model_dump_json())
    assert p.verify(q2) is True


@pytest.mark.parametrize("cls", [SevSnpAttestationProvider, TdxAttestationProvider])
def test_tee_backends_are_hardware_gated_stubs(cls: type) -> None:
    with pytest.raises(NotImplementedError, match="hardware-gated"):
        cls()
