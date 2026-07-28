"""X1 — the software attestation fallback signs+verifies; the TEE backends are honest stubs."""

from __future__ import annotations

import pytest

from framework.v2.attest import provider as prov
from framework.v2.attest.provider import (
    AttestationQuote,
    SevSnpAttestationProvider,
    SoftwareAttestationProvider,
    TdxAttestationProvider,
    detect_tee,
    open_attestation_provider,
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


# ---- auto-detect selector: pick the TEE backend if present, else the software fallback ----------


def test_detect_tee_none_on_a_plain_linux_pc(monkeypatch) -> None:
    # RUNS ON ANY LINUX PC: with no confidential-computing device, detection is None (→ software fallback).
    monkeypatch.delenv("VIGIL_TEE_BACKEND", raising=False)
    monkeypatch.setattr(prov, "_TEE_DEVICES", (("sev-snp", "/no/such/dev-sev"), ("tdx", "/no/such/dev-tdx")))
    assert detect_tee() is None


def test_detect_tee_finds_a_present_device(monkeypatch, tmp_path) -> None:
    dev = tmp_path / "sev-guest"; dev.write_text("")
    monkeypatch.delenv("VIGIL_TEE_BACKEND", raising=False)
    monkeypatch.setattr(prov, "_TEE_DEVICES", (("sev-snp", str(dev)),))
    assert detect_tee() == "sev-snp"


def test_env_override_forces_software_even_with_a_device(monkeypatch, tmp_path) -> None:
    dev = tmp_path / "sev-guest"; dev.write_text("")
    monkeypatch.setattr(prov, "_TEE_DEVICES", (("sev-snp", str(dev)),))
    monkeypatch.setenv("VIGIL_TEE_BACKEND", "software")
    assert detect_tee() is None


def test_open_provider_falls_back_to_software_on_a_plain_pc(monkeypatch) -> None:
    # The "runs anywhere" property: no device → a working software provider, honestly labelled, never raises.
    monkeypatch.delenv("VIGIL_TEE_BACKEND", raising=False)
    monkeypatch.setattr(prov, "_TEE_DEVICES", ())
    p, note = open_attestation_provider()
    assert isinstance(p, SoftwareAttestationProvider)
    assert "software" in note.lower() and "no confidential-computing device" in note
    assert p.verify(p.attest(b"x")) is True


def test_open_provider_detects_device_but_falls_back_until_backend_implemented(monkeypatch, tmp_path) -> None:
    # The AUTO-DETECT seam: a device IS present, but the SEV-SNP backend is still a hardware-gated stub that
    # raises on construction → honest fall back to software, with a note pointing at the activation runbook.
    dev = tmp_path / "sev-guest"; dev.write_text("")
    monkeypatch.delenv("VIGIL_TEE_BACKEND", raising=False)
    monkeypatch.setattr(prov, "_TEE_DEVICES", (("sev-snp", str(dev)),))
    p, note = open_attestation_provider()
    assert isinstance(p, SoftwareAttestationProvider)
    assert "sev-snp device detected" in note and "not yet implemented" in note
    assert "DEFERRED-INFRA" in note                      # points at how to activate it on this hardware


def test_open_provider_activates_hardware_when_a_backend_is_implemented(monkeypatch, tmp_path) -> None:
    # Prove the seam: the DAY a hardware backend stops raising, detection auto-selects it — no other change.
    dev = tmp_path / "sev-guest"; dev.write_text("")
    monkeypatch.delenv("VIGIL_TEE_BACKEND", raising=False)
    monkeypatch.setattr(prov, "_TEE_DEVICES", (("sev-snp", str(dev)),))

    class _FakeHw(SoftwareAttestationProvider):     # a stand-in "implemented" backend (does not raise)
        backend_name = "sev-snp"

    monkeypatch.setattr(prov, "_TEE_PROVIDERS", {"sev-snp": _FakeHw})
    p, note = open_attestation_provider()
    assert isinstance(p, _FakeHw) and "sev-snp hardware attestation active" in note


def test_open_provider_prefer_hardware_false_uses_software(monkeypatch, tmp_path) -> None:
    dev = tmp_path / "sev-guest"; dev.write_text("")
    monkeypatch.setattr(prov, "_TEE_DEVICES", (("sev-snp", str(dev)),))
    p, _ = open_attestation_provider(prefer_hardware=False)
    assert isinstance(p, SoftwareAttestationProvider)
