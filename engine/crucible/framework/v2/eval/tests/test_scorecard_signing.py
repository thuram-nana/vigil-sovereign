"""P1 — the benchmark scorecard is TAMPER-EVIDENT + independently verifiable: an m-of-n Ed25519 signature
over the canonical scorecard bytes, checkable offline. A flipped number breaks it; a non-authorized signer
does not count toward the threshold."""
from __future__ import annotations

import json

from vigil_core import generate_keypair

from framework.v2.eval.benchmark_run import sign_scorecard, verify_scorecard


def _write(p, doc):
    p.write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")


def test_signed_scorecard_verifies_and_rejects_a_flipped_number(tmp_path):
    sc = tmp_path / "benchmark-results.json"
    _write(sc, {"tool": "CRUCIBLE", "results": [{"tool": "crucible", "tp": 9, "fp": 0, "fn": 0, "precision": 1.0}]})
    kp = generate_keypair()
    sig = sign_scorecard(sc, signers=[("owner", kp.private_key_b64)],
                         authorizers=[{"key_id": "owner", "public_key_b64": kp.public_key_b64}], threshold=1)
    assert verify_scorecard(sc, sig) is True
    assert sc.with_suffix(".sig.json").exists() and sc.with_suffix(".fingerprint.txt").exists()

    # flip a reported number → canonical digest changes → the signature no longer verifies.
    d = json.loads(sc.read_text()); d["results"][0]["fp"] = 5; _write(sc, d)
    assert verify_scorecard(sc, sig) is False


def test_a_non_authorized_signer_does_not_satisfy_the_threshold(tmp_path):
    sc = tmp_path / "benchmark-results.json"
    _write(sc, {"tool": "CRUCIBLE", "results": [{"tool": "crucible", "tp": 9, "fp": 0}]})
    owner = generate_keypair()
    attacker = generate_keypair()
    # signed by 'attacker', but the trust root pins 'owner' → the attacker's signature is not counted.
    sig = sign_scorecard(sc, signers=[("attacker", attacker.private_key_b64)],
                         authorizers=[{"key_id": "owner", "public_key_b64": owner.public_key_b64}], threshold=1)
    assert verify_scorecard(sc, sig) is False


def test_keyless_zero_threshold_forgery_is_rejected_even_with_pin(tmp_path):
    """Red-pen BLOCK-1 regression (escalated to the merged web spine): an attacker with NO key tampers the
    body, recomputes the digest, and forges a threshold=0 + empty-signatures envelope keeping the pinned
    authorizer set. It must fail closed even with the correct pin (pre-fix it verified TRUE)."""
    import hashlib

    from vigil_core import canonical_json

    from framework.v2.eval.benchmark_run import _scorecard_fingerprint
    sc = tmp_path / "benchmark-results.json"
    _write(sc, {"tool": "CRUCIBLE", "results": [{"tool": "crucible", "tp": 9, "fp": 0}]})
    kp = generate_keypair()
    authorizers = [{"key_id": "owner", "public_key_b64": kp.public_key_b64}]
    sign_scorecard(sc, signers=[("owner", kp.private_key_b64)], authorizers=authorizers, threshold=1)
    pin = _scorecard_fingerprint(authorizers)
    d = json.loads(sc.read_text()); d["results"][0]["tp"] = 999; _write(sc, d)
    digest = "sha256:" + hashlib.sha256(canonical_json(json.loads(sc.read_text()))).hexdigest()
    for bad_threshold in (0, -1):
        forged = {"scorecard_digest": digest,
                  "trust_root": {"threshold": bad_threshold, "authorizers": authorizers}, "signatures": []}
        assert verify_scorecard(sc, forged, trust_root_fingerprint=pin) is False


def test_threshold_downgrade_is_rejected_by_expected_threshold(tmp_path):
    """Red-pen BLOCK-2 regression: a 2-of-2 scorecard re-signed by an insider with one key at threshold=1 is
    rejected when the caller pins expected_threshold=2."""
    sc = tmp_path / "benchmark-results.json"
    _write(sc, {"tool": "CRUCIBLE", "results": [{"tool": "crucible", "tp": 9, "fp": 0}]})
    k0, k1 = generate_keypair(), generate_keypair()
    authz = [{"key_id": "g0", "public_key_b64": k0.public_key_b64},
             {"key_id": "g1", "public_key_b64": k1.public_key_b64}]
    ok = sign_scorecard(sc, signers=[("g0", k0.private_key_b64), ("g1", k1.private_key_b64)],
                        authorizers=authz, threshold=2)
    assert verify_scorecard(sc, ok, expected_threshold=2) is True
    down = sign_scorecard(sc, signers=[("g0", k0.private_key_b64)], authorizers=authz, threshold=1)
    assert verify_scorecard(sc, down, expected_threshold=None) is True    # weak mode accepts thr=1
    assert verify_scorecard(sc, down, expected_threshold=2) is False      # pinned quorum rejects the downgrade
