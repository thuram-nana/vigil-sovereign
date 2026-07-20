"""P9 — the OracleConfirmationAdapter: only an oracle-confirmed, oracle-mapped finding becomes a
signed FACT; everything else is a labelled lead. Drives CRUCIBLE's real confirm_finding + certify
(a stub verifier supplies the oracle verdict so we don't have to craft a live-firing context).

MUST run in its OWN pytest process (it loads framework.* = offense): sigil.governor's
assert_no_offense() refuses to co-load framework with a SIGIL module, so this file cannot share a
process with the sigil-importing tests. CI runs it separately (see the integration job)."""

from __future__ import annotations

import pytest

# needs CRUCIBLE (framework) importable — the offense venv.
pytest.importorskip("framework.v2.verify.confirmation", reason="CRUCIBLE not importable here")

from vigil_core import (  # noqa: E402
    AuthorizerKey,
    TrustRoot,
    evidence_signing_bytes,
    generate_keypair,
    verify_threshold,
)
from vigil_integration.oracle_adapter import confirm_and_certify  # noqa: E402

SIGNER = generate_keypair()
SIGNERS = [("root0", SIGNER.private_key_b64)]
TRUST = TrustRoot(threshold=1, authorizers=[
    AuthorizerKey(key_id="root0", name="root0", public_key_b64=SIGNER.public_key_b64)])


def _stub_verifier(*, confirmed: bool, bug_class: str):
    from framework.v2.verify.models import OracleKind, OracleSignal, VerificationResult

    signals = [OracleSignal(
        kind=OracleKind.BOOLEAN_INFERENCE, fired=confirmed,
        confidence=0.95 if confirmed else 0.0, evidence="stub", observed={})]
    result = VerificationResult(
        confirmed=confirmed, bug_class=bug_class, signals=signals,
        combine_policy="any_high_confidence_fired", dissent=[], rationale="stub")

    class _V:
        high_confidence = 0.7  # confirm_finding filters signals by verifier.high_confidence

        def confirm(self, finding_context):
            return result

    return _V()


def _finding(bug_class="sqli"):
    return {
        "check_id": "sqli-001",
        "bug_class": bug_class,
        "insertion_point": "id",
        "oracle_context": {"bug_class": bug_class, "note": "retained evidence"},
    }


def test_unconfirmed_finding_is_a_lead_not_a_fact():
    res = confirm_and_certify(
        _finding("sqli"), engagement_slug="acme", signers=SIGNERS,
        verifier=_stub_verifier(confirmed=False, bug_class="sqli"))
    assert res.status == "lead" and not res.is_fact and res.signed is None
    assert "did not fire" in res.reason


def test_confirmed_oracle_mapped_finding_becomes_a_signed_fact():
    res = confirm_and_certify(
        _finding("sqli"), engagement_slug="acme", signers=SIGNERS,
        verifier=_stub_verifier(confirmed=True, bug_class="sqli"))
    assert res.status == "fact" and res.is_fact
    assert res.signed is not None and res.confirmed_by  # an oracle kind fired
    # the signed certificate's m-of-n signature verifies against the governance trust root
    cert = res.signed.certificate
    msg = evidence_signing_bytes(cert.model_dump(mode="json"))
    assert verify_threshold(msg, res.signed.signatures, TRUST).satisfied is True
    # and it binds the exact retained oracle_context
    from framework.v2.evidence.canonical import digest_payload
    assert cert.oracle_context_digest == digest_payload({"bug_class": "sqli", "note": "retained evidence"})


def test_confirmed_but_unmapped_class_stays_a_lead_honesty_invariant():
    # even though the (stub) oracle "fired", a class with no deterministic oracle mapping is NOT
    # promoted to a signed fact — the invariant that keeps the system honest.
    res = confirm_and_certify(
        _finding("totally-made-up-class"), engagement_slug="acme", signers=SIGNERS,
        verifier=_stub_verifier(confirmed=True, bug_class="totally-made-up-class"))
    assert res.status == "lead" and res.signed is None
    assert "no deterministic oracle mapping" in res.reason


def test_tampering_a_signed_fact_breaks_its_signature():
    res = confirm_and_certify(
        _finding("sqli"), engagement_slug="acme", signers=SIGNERS,
        verifier=_stub_verifier(confirmed=True, bug_class="sqli"))
    forged = res.signed.certificate.model_copy(update={"bug_class": "rce"})  # relabel after signing
    msg = evidence_signing_bytes(forged.model_dump(mode="json"))
    assert verify_threshold(msg, res.signed.signatures, TRUST).satisfied is False
