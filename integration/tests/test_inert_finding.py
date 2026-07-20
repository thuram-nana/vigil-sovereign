"""inert_finding — the seam refuses everything that is not a valid, inert, signed finding, and
verifies the CRUCIBLE m-of-n anchor with vigil_core alone (no framework import)."""

from __future__ import annotations

import json
import pickle

import pytest

from vigil_core import (
    AuthorizerKey,
    Signature,
    TrustRoot,
    evidence_signing_bytes,
    generate_keypair,
    sign,
)
from vigil_integration import inert_finding
from vigil_integration.inert_finding import (
    InertFindingError,
    build_envelope,
    validate_inert_finding,
)


def _cert(**over) -> dict:
    base = {
        "schema_version": 1,
        "engagement_slug": "acme",
        "finding_ref": "sqli-001",
        "bug_class": "sqli",
        "oracle_context_digest": "a" * 64,
        "confidence": 0.9,
    }
    base.update(over)
    return base


def _signed_envelope(cert: dict, *, threshold: int = 1, n: int = 1):
    keys = [generate_keypair() for _ in range(n)]
    authorizers = [AuthorizerKey(key_id=f"root{i}", name=f"root{i}", public_key_b64=k.public_key_b64)
                   for i, k in enumerate(keys)]
    tr = TrustRoot(threshold=threshold, authorizers=authorizers)
    msg = evidence_signing_bytes(cert)
    sigs = [{"key_id": f"root{i}", "signature_b64": sign(k.private_key_b64, msg)}
            for i, k in enumerate(keys)]
    return build_envelope(cert, sigs), tr


def test_valid_envelope_validates_and_exposes_identity():
    env, _ = _signed_envelope(_cert())
    vf = validate_inert_finding(env)
    assert vf.finding_ref == "sqli-001"
    assert vf.oracle_context_digest == "a" * 64
    payload = vf.to_spine_payload()
    assert payload["schema"] == inert_finding.SCHEMA
    # inert: only JSON types survive
    json.dumps(payload)


def test_signature_verifies_against_trust_root():
    env, tr = _signed_envelope(_cert())
    vf = validate_inert_finding(env)
    assert vf.verify_signature(tr) is True


def test_tampered_certificate_fails_signature():
    env, tr = _signed_envelope(_cert())
    vf = validate_inert_finding(env)
    # flip a certificate field AFTER signing → signature no longer matches
    forged = dict(vf.raw)
    forged_cert = dict(vf.certificate)
    forged_cert["bug_class"] = "rce"   # relabelled finding
    forged["certificate"] = forged_cert
    vf2 = validate_inert_finding(json.dumps(forged))
    assert vf2.verify_signature(tr) is False


def test_threshold_not_met_fails():
    # 2-of-2 required but only 1 signer present in the envelope.
    cert = _cert()
    k0, k1 = generate_keypair(), generate_keypair()
    tr = TrustRoot(threshold=2, authorizers=[
        AuthorizerKey(key_id="r0", name="r0", public_key_b64=k0.public_key_b64),
        AuthorizerKey(key_id="r1", name="r1", public_key_b64=k1.public_key_b64),
    ])
    msg = evidence_signing_bytes(cert)
    env = build_envelope(cert, [{"key_id": "r0", "signature_b64": sign(k0.private_key_b64, msg)}])
    assert validate_inert_finding(env).verify_signature(tr) is False


def test_rejects_pickle_and_nonjson():
    # a pickled object is the classic "smuggle code across the boundary" attempt
    with pytest.raises(InertFindingError):
        validate_inert_finding(pickle.dumps({"schema": inert_finding.SCHEMA}))
    with pytest.raises(InertFindingError):
        validate_inert_finding(b"\x80\x04\x95not-json")
    with pytest.raises(InertFindingError):
        validate_inert_finding("{not valid json")


def test_rejects_live_object_input():
    # not str/bytes → someone passed a live/pickled object, not a serialized envelope
    with pytest.raises(InertFindingError):
        validate_inert_finding({"schema": inert_finding.SCHEMA})  # type: ignore[arg-type]


def test_rejects_oversized_envelope():
    huge = _cert(engagement_slug="x" * (inert_finding.MAX_ENVELOPE_BYTES))
    env, _ = _signed_envelope(huge)
    with pytest.raises(InertFindingError, match="exceeds"):
        validate_inert_finding(env)


def test_rejects_wrong_schema_and_extra_keys():
    env, _ = _signed_envelope(_cert())
    d = json.loads(env)
    with pytest.raises(InertFindingError, match="schema"):
        validate_inert_finding(json.dumps({**d, "schema": "evil.v9"}))
    with pytest.raises(InertFindingError, match="unexpected top-level"):
        validate_inert_finding(json.dumps({**d, "extra": 1}))


def test_rejects_missing_cert_fields_and_bad_signatures():
    env, _ = _signed_envelope(_cert())
    d = json.loads(env)
    bad_cert = {k: v for k, v in d["certificate"].items() if k != "finding_ref"}
    with pytest.raises(InertFindingError, match="finding_ref"):
        validate_inert_finding(json.dumps({**d, "certificate": bad_cert}))
    with pytest.raises(InertFindingError, match="signatures must be a non-empty list"):
        validate_inert_finding(json.dumps({**d, "signatures": []}))
    with pytest.raises(InertFindingError, match="unexpected keys"):
        validate_inert_finding(json.dumps({**d, "signatures": [{"key_id": "r", "signature_b64": "x", "evil": 1}]}))


def test_rejects_json_array_top_level():
    with pytest.raises(InertFindingError, match="must be a JSON object"):
        validate_inert_finding("[1, 2, 3]")


def test_rejects_deeply_nested_json_without_crashing():
    # a JSON "bomb" (deep nesting) must fail closed as InertFindingError, never escape as an
    # uncaught RecursionError.
    bomb = "[" * 20000 + "]" * 20000
    with pytest.raises(InertFindingError):
        validate_inert_finding(bomb)
