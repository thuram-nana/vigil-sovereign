"""VF-1a — the portable RemediationCertificate: the negative proof-carrying artifact.

Earned-by-silence (a still-firing patched build is refused), offline-verifiable by re-execution, and rejects
every tamper. Needs framework (reverify + the oracle) → PYTHONPATH=integration:engine/crucible:gateway.
"""
from __future__ import annotations

import pytest

from vigil_core import generate_keypair
from vigil_integration.remediation.remediation_cert import (
    mint_remediation_certificate,
    verify_remediation_certificate,
)

SIGNER = generate_keypair()
SIGNERS = [("root0", SIGNER.private_key_b64)]
PUBKEYS = {"root0": SIGNER.public_key_b64}

_SQL_ERROR = b"HTTP/1.1 500\r\n\r\nYou have an error in your SQL syntax near ''"
_BENIGN = b"HTTP/1.1 200\r\n\r\n{\"results\": []}"


def _context(body: bytes) -> dict:
    """Build an error_signature oracle_context from a captured response — the same translator the mint uses."""
    from framework.v2.evidence.poc import CapturedExchange
    from framework.v2.verify.poc_translate import context_from_exchanges
    ex = CapturedExchange(channel="error_signature", role="mutated", response_bytes_ref="resp")
    ctx = context_from_exchanges([ex], bug_class="error_based_sqli", resolve=lambda r: body)
    assert ctx is not None
    return ctx.model_dump(mode="json")


def test_silent_patched_build_mints_a_verifiable_remediation_cert():
    cert = mint_remediation_certificate(
        finding_ref="errsqli-1", bug_class="error_based_sqli",
        patched_oracle_context=_context(_BENIGN), engagement_slug="acme", signers=SIGNERS,
        original_finding_cert_digest="sha256:deadbeef")
    assert cert["schema"] == "vigil-remediation-cert-v1"
    assert cert["verdict"] == "oracle-silent"
    assert cert["original_finding_cert_digest"] == "sha256:deadbeef"  # pairs the positive proof
    v = verify_remediation_certificate(cert, signer_pubkeys=PUBKEYS)
    assert v.ok and v.silent and v.bound and v.authentic, v.reason


def test_still_vulnerable_build_cannot_be_certified():
    # earned-by-silence: a patched build where the exploit STILL fires must be refused, never minted.
    with pytest.raises(ValueError, match="STILL fires"):
        mint_remediation_certificate(
            finding_ref="errsqli-1", bug_class="error_based_sqli",
            patched_oracle_context=_context(_SQL_ERROR), engagement_slug="acme", signers=SIGNERS)


def test_wrong_pinned_key_fails_authenticity():
    cert = mint_remediation_certificate(
        finding_ref="errsqli-1", bug_class="error_based_sqli",
        patched_oracle_context=_context(_BENIGN), engagement_slug="acme", signers=SIGNERS)
    attacker = generate_keypair()
    v = verify_remediation_certificate(cert, signer_pubkeys={"root0": attacker.public_key_b64})
    assert not v.ok and not v.authentic


def test_tampered_context_breaks_binding():
    cert = mint_remediation_certificate(
        finding_ref="errsqli-1", bug_class="error_based_sqli",
        patched_oracle_context=_context(_BENIGN), engagement_slug="acme", signers=SIGNERS)
    # flip a byte in the retained context AFTER minting → the recomputed digest no longer matches the signed one.
    cert["patched_oracle_context"]["_tamper"] = "x"
    v = verify_remediation_certificate(cert, signer_pubkeys=PUBKEYS)
    assert not v.ok and not v.bound


def test_forged_signature_ref_is_rejected():
    cert = mint_remediation_certificate(
        finding_ref="errsqli-1", bug_class="error_based_sqli",
        patched_oracle_context=_context(_BENIGN), engagement_slug="acme", signers=SIGNERS)
    cert["signature_ref"] = "remediation:deadbeefdeadbeefdeadbeef:root0:" + "A" * 86
    v = verify_remediation_certificate(cert, signer_pubkeys=PUBKEYS)
    assert not v.ok and not v.authentic
