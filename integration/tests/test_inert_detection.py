"""S7c — a DETECTION FACT crosses the ONE inert seam (offense-side seam validation).

The Detection Mirror's offense-spine-signed certificate rides the SAME inert JSON seam as a CRUCIBLE
finding: build_detection_envelope → validate_inert_detection → verify_signature against the owner-delegated
offense-spine trust root. Only the required identity fields differ (oracle+evidence_digest_hex vs a finding's
finding_ref+oracle_context_digest); the anchor-1 verify (verify_threshold over evidence_signing_bytes) is
identical. Back-compat: a plain finding envelope still validates as a finding.

Run: PYTHONPATH=integration:gateway pytest integration/tests/test_inert_detection.py -q
"""
from __future__ import annotations

import pytest

from vigil_core import AuthorizerKey, TrustRoot, generate_keypair, sign
from vigil_integration.detection.certificate import build_certificate, sign_certificate
from vigil_integration.inert_finding import (
    InertFindingError,
    build_detection_envelope,
    build_envelope,
    validate_inert_detection,
    validate_inert_finding,
)
from vigil_integration.live.spine_identity import SPINE_KEY_ID

SPINE = generate_keypair()
SPINE_TRUST = TrustRoot(threshold=1, authorizers=[
    AuthorizerKey(key_id=SPINE_KEY_ID, name=SPINE_KEY_ID, public_key_b64=SPINE.public_key_b64)])


def _signed_detection(kp=SPINE, key_id=SPINE_KEY_ID):
    cert = build_certificate(oracle="recon.port_scan", signature_kind="port-sweep",
                             bug_class="recon.port_scan", severity="medium", evidence_kind="conn_log",
                             evidence_lines=["10.0.0.9 -> :22", "10.0.0.9 -> :80"], summary="port sweep", seq=0)
    return sign_certificate(cert, lambda b: sign(kp.private_key_b64, b), key_id=key_id)


def _envelope(signed):
    return build_detection_envelope(signed.signing_payload(),
                                    [{"key_id": signed.key_id, "signature_b64": signed.signature}])


def test_detection_fact_round_trips_and_verifies_under_the_spine_root():
    signed = _signed_detection()
    vd = validate_inert_detection(_envelope(signed))
    assert vd.oracle == "recon.port_scan" and vd.bug_class == "recon.port_scan"
    assert vd.evidence_digest_hex == signed.evidence_digest_hex
    assert vd.verify_signature(SPINE_TRUST) is True


def test_detection_fact_refused_under_a_wrong_key():
    signed = _signed_detection(kp=generate_keypair())   # signed by a NON-delegated spine key
    vd = validate_inert_detection(_envelope(signed))
    assert vd.verify_signature(SPINE_TRUST) is False     # anchor-1 fails against the trusted spine root


def test_tampered_detection_cert_breaks_the_signature():
    signed = _signed_detection()
    payload = signed.signing_payload()
    payload["bug_class"] = "sqli"                          # tamper a signed field
    vd = validate_inert_detection(build_detection_envelope(
        payload, [{"key_id": signed.key_id, "signature_b64": signed.signature}]))
    assert vd.verify_signature(SPINE_TRUST) is False


def test_detection_envelope_carries_kind_detection():
    import json
    env = json.loads(_envelope(_signed_detection()))
    assert env["kind"] == "detection"


def test_a_finding_envelope_is_refused_as_detection_at_the_kind_gate():
    # a plain FINDING envelope (no "kind") is refused by the DETECTION profile at the KIND gate — "kind" is
    # authoritative, so a finding can never be mis-parsed as a detection (NIT-1 fix).
    import json
    cert = {"schema_version": 1, "finding_ref": "sqli-001", "oracle_context_digest": "a" * 64}
    with pytest.raises(InertFindingError, match="kind"):
        validate_inert_detection(build_envelope(cert, [{"key_id": "root0", "signature_b64": "x"}]))
    # and a detection-KIND envelope whose cert lacks the detection fields is refused at the FIELDS gate
    d = json.loads(build_detection_envelope(cert, [{"key_id": "root0", "signature_b64": "x"}]))
    with pytest.raises(InertFindingError, match="oracle"):
        validate_inert_detection(json.dumps(d))


def test_back_compat_finding_profile_unchanged():
    # the refactor is behavior-preserving for findings: a finding envelope still validates as a finding
    cert = {"schema_version": 1, "finding_ref": "sqli-001", "oracle_context_digest": "a" * 64}
    vf = validate_inert_finding(build_envelope(cert, [{"key_id": "root0", "signature_b64": "x"}]))
    assert vf.finding_ref == "sqli-001"
