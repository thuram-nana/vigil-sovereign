"""offense_worker — the offense trust domain is keyless: it cannot hold an owner key, cannot
produce a verifiable governance event, and crosses findings only as inert signed data."""

from __future__ import annotations

import pathlib
import sys

import pytest

from vigil_integration.inert_finding import validate_inert_finding
from vigil_integration.offense_worker import KeylessOffenseWorker


# --- duck-typed stand-in for a CRUCIBLE SignedEvidence (no framework import needed) -----------

class _Dumpable:
    def __init__(self, d):
        self._d = dict(d)

    def model_dump(self, mode="json"):
        return dict(self._d)


class _FakeSignedEvidence:
    def __init__(self, cert: dict, sigs: list[dict]):
        self.certificate = _Dumpable(cert)
        self.signatures = [_Dumpable(s) for s in sigs]


def test_worker_is_keyless():
    w = KeylessOffenseWorker(engagement_slug="acme")
    assert w.has_owner_key is False
    assert w.can_sign_governance() is False
    assert w.identity.ceiling == "A2"


def test_construction_refuses_an_owner_key():
    with pytest.raises(ValueError, match="KEYLESS"):
        KeylessOffenseWorker(engagement_slug="acme", owner_key=object())


def test_requires_engagement_slug():
    with pytest.raises(ValueError, match="engagement"):
        KeylessOffenseWorker(engagement_slug="")


def test_emits_inert_envelope_that_the_receiver_accepts():
    w = KeylessOffenseWorker(engagement_slug="acme")
    signed = _FakeSignedEvidence(
        {"schema_version": 1, "finding_ref": "xss-007", "oracle_context_digest": "b" * 64},
        [{"key_id": "root0", "signature_b64": "Zm9v"}],
    )
    envelope = w.emit_finding_envelope(signed)
    vf = validate_inert_finding(envelope)  # a str → parsed as inert JSON
    assert vf.finding_ref == "xss-007"
    assert vf.signatures == ({"key_id": "root0", "signature_b64": "Zm9v"},)


def test_refuses_to_emit_an_unsigned_finding():
    w = KeylessOffenseWorker(engagement_slug="acme")
    unsigned = _FakeSignedEvidence({"finding_ref": "x", "oracle_context_digest": "c" * 64}, [])
    with pytest.raises(ValueError, match="UNSIGNED"):
        w.emit_finding_envelope(unsigned)


def test_keyless_actor_cannot_forge_a_verifiable_governance_event():
    # The real guarantee: SIGIL's governance auth is fail-closed, so an event a keyless actor
    # builds (owner_key=None → sig=None) never verifies. Proven against the actual sigil module.
    sigil_root = pathlib.Path(__file__).resolve().parents[2] / "apps" / "sigil"
    if str(sigil_root) not in sys.path:
        sys.path.insert(0, str(sigil_root))
    authn = pytest.importorskip("sigil.governor.authn", reason="sigil not importable here")

    core = {"action": "kill_release", "engagement": "acme", "nonce": "1"}
    forged = authn.signed_payload(core, owner_key=None)   # keyless → sig/pubkey are None
    assert forged["sig"] is None and forged["pubkey"] is None
    # even against a real trusted pubkey, the keyless event is not authentic
    assert authn.verify_signed(forged, tuple(core), trusted_pubkey="any-real-owner-pubkey") is False
