"""VF-1a — the CONTROLLED RemediationCertificate (negative proof with negative-proof controls).

A remediation is proven only when "silent" is distinguished from "didn't reach": the SAME oracle must still
FIRE on a positive-control twin (the harness is capable of firing), the patched build must be SILENT, and the
target must have ANSWERED (liveness). All controls are signed into the whole cert, so none can be stripped.
Needs framework (reverify + the oracle) → PYTHONPATH=integration:engine/crucible:gateway.
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
    """An error_signature oracle_context from a captured response — the translator the mint/verify use."""
    from framework.v2.evidence.poc import CapturedExchange
    from framework.v2.verify.poc_translate import context_from_exchanges
    ex = CapturedExchange(channel="error_signature", role="mutated", response_bytes_ref="resp")
    ctx = context_from_exchanges([ex], bug_class="error_based_sqli", resolve=lambda r: body)
    assert ctx is not None
    return ctx.model_dump(mode="json")


def _mint(patched: dict, control: dict) -> dict:
    return mint_remediation_certificate(
        finding_ref="errsqli-1", bug_class="error_based_sqli",
        patched_oracle_context=patched, positive_control_context=control,
        engagement_slug="acme", signers=SIGNERS, surface="GET /search?q=",
        original_finding_cert_digest="sha256:deadbeef")


def test_controlled_remediation_mints_and_verifies():
    cert = _mint(patched=_context(_BENIGN), control=_context(_SQL_ERROR))
    assert cert["schema"] == "vigil-remediation-cert-v2"
    assert cert["controls"]["positive_control"] and cert["controls"]["liveness"]
    assert "positive_control_context" in cert and "signature" in cert
    v = verify_remediation_certificate(cert, signer_pubkeys=PUBKEYS)
    assert v.ok and v.silent and v.control_fires and v.live and v.bound and v.authentic, v.reason


def test_still_vulnerable_build_cannot_be_certified():
    with pytest.raises(ValueError, match="STILL fires"):
        _mint(patched=_context(_SQL_ERROR), control=_context(_SQL_ERROR))


def test_positive_control_that_does_not_fire_is_refused():
    # the twin must FIRE — else "silent" on the patched build could just be a broken/blocked probe.
    with pytest.raises(ValueError, match="positive control does NOT fire"):
        _mint(patched=_context(_BENIGN), control=_context(_BENIGN))


def test_unreachable_patched_build_is_indeterminate_not_fixed():
    # a context with no captured response → silence is indistinguishable from "unreachable" → refused.
    with pytest.raises(ValueError, match="no captured response"):
        _mint(patched={"bug_class": "error_based_sqli"}, control=_context(_SQL_ERROR))


def test_wrong_pinned_key_fails_authenticity():
    cert = _mint(patched=_context(_BENIGN), control=_context(_SQL_ERROR))
    attacker = generate_keypair()
    v = verify_remediation_certificate(cert, signer_pubkeys={"root0": attacker.public_key_b64})
    assert not v.ok and not v.authentic


def test_tampered_context_breaks_binding_and_signature():
    cert = _mint(patched=_context(_BENIGN), control=_context(_SQL_ERROR))
    cert["patched_oracle_context"]["_tamper"] = "x"   # edit the retained context after signing
    v = verify_remediation_certificate(cert, signer_pubkeys=PUBKEYS)
    assert not v.ok and (not v.bound or not v.authentic)


def test_stripped_control_breaks_the_whole_cert_signature():
    # flipping a control claim after signing must break authenticity (the controls are signed into the cert).
    cert = _mint(patched=_context(_BENIGN), control=_context(_SQL_ERROR))
    cert["controls"]["positive_control"] = False
    v = verify_remediation_certificate(cert, signer_pubkeys=PUBKEYS)
    assert not v.ok and not v.authentic
