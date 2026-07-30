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
