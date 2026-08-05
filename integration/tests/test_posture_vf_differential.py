"""P1 — DIFFERENTIAL: the STANDALONE ``verify_vf.verify_posture`` agrees with the in-tree
``posture.certificate.verify_posture_certificate``, byte-for-byte, on a valid PostureCertificate AND on
every tamper. This is what makes the Certificate of Non-Exploitability third-party-offline-re-verifiable:
a distrusting party re-checks it with stdlib + one Ed25519 lib, no VIGIL installed, and gets the SAME
verdict VIGIL does.
"""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path

from vigil_core.crypto import generate_keypair
from vigil_core.capability import sign_identity_attestation
from vigil_integration.posture.certificate import (
    PostureError,
    build_posture_certificate,
    sign_posture_certificate,
    verify_posture_certificate,
)

_VERIFIER = Path(__file__).resolve().parents[2] / "docs" / "proof-carrying-finding" / "verify_vf.py"


def _load_standalone():
    spec = importlib.util.spec_from_file_location("standalone_verify_vf_posture", _VERIFIER)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


VF = _load_standalone()


def _coverage_cert() -> dict:
    return {
        "schema": "vigil-coverage-certificate/1",
        "scope": "reached-surface coverage",
        "target_host": "127.0.0.1",
        "denominator": {"surfaces_reached": 3, "insertion_points_probed": 3, "distinct_classes_probed": 3,
                        "frontier_truncated": 0, "max_pages": 25, "max_depth": 4, "budget_exhausted": False},
        "probes": [
            {"surface": "/item", "insertion_point": "query", "param": "id", "check_id": "e",
             "class": "error_based_sqli", "verdict": "finding", "oracle_kinds_run": []},
            {"surface": "/search", "insertion_point": "query", "param": "q", "check_id": "x",
             "class": "reflected_xss", "verdict": "clean", "oracle_kinds_run": ["reflection"]},
            {"surface": "/dl", "insertion_point": "query", "param": "f", "check_id": "s",
             "class": "ssrf", "verdict": "inconclusive", "oracle_kinds_run": []},
        ],
        "summary": {"n_finding": 1, "n_clean": 1, "n_inconclusive": 1},
    }


def _mint(tmp_path: Path, *, sample=None):
    owner = generate_keypair()
    gov = generate_keypair()
    att = sign_identity_attestation(owner, engagement="demo", policy={"host": ["127.0.0.1"]},
                                    not_after=9999999999)
    cert = build_posture_certificate(_coverage_cert(), target_identity=att,
                                     target_sample=sample or {"host": "127.0.0.1"})
    p = tmp_path / "posture.json"
    sig = sign_posture_certificate(cert, p, signers=[("gov", gov.private_key_b64)],
                                   authorizers=[{"key_id": "gov", "public_key_b64": gov.public_key_b64}],
                                   threshold=1)
    fp = p.with_suffix(".fingerprint.txt").read_text().strip()
    return owner, gov, p, sig, fp


def _intree(p, sig, fp, owner, now=1):
    try:
        return verify_posture_certificate(p, sig, trust_root_fingerprint=fp,
                                          owner_pubkey=owner.public_key_b64, engagement="demo", now=now)
    except PostureError:
        return False


def _standalone(p, sig, fp, owner, now=1):
    cert_doc = json.loads(p.read_text())
    ok, _ = VF.verify_posture({"certificate": cert_doc, "signature": sig}, pin=fp,
                              owner_pubkey=owner.public_key_b64, engagement="demo", now=now)
    return ok


def test_valid_posture_verifies_in_both(tmp_path: Path):
    owner, gov, p, sig, fp = _mint(tmp_path)
    assert _intree(p, sig, fp, owner) is True
    assert _standalone(p, sig, fp, owner) is True
    # and through the full standalone bundle dispatch
    cert_doc = json.loads(p.read_text())
    sound, log = VF.verify_bundle({"posture": {"certificate": cert_doc, "signature": sig}},
                                  posture_pin=fp, posture_owner_pubkey=owner.public_key_b64,
                                  posture_engagement="demo", posture_now=1)
    assert sound is True, log


def test_flipped_byte_rejected_in_both(tmp_path: Path):
    owner, gov, p, sig, fp = _mint(tmp_path)
    doc = json.loads(p.read_text())
    doc["summary"]["n_closed"] = 99
    p.write_text(json.dumps(doc))
    assert _intree(p, sig, fp, owner) is False
    assert _standalone(p, sig, fp, owner) is False


def test_forged_claim_rejected_in_both(tmp_path: Path):
    owner, gov, p, sig, fp = _mint(tmp_path)
    doc = json.loads(p.read_text())
    for c in doc["posture_claims"]:
        if c["class"] == "error_based_sqli":
            c["status"] = "CLOSED"
            c["evidence_oracle_kinds"] = ["error_signature"]
    # re-sign under the SAME gov key so the signature is valid but the claim is detached from coverage
    from framework.v2.eval.benchmark_run import sign_scorecard
    from vigil_core import canonical_json
    p.write_bytes(canonical_json(doc))
    sig2 = sign_scorecard(p, signers=[("gov", gov.private_key_b64)],
                          authorizers=[{"key_id": "gov", "public_key_b64": gov.public_key_b64}], threshold=1)
    assert _intree(p, sig2, fp, owner) is False
    assert _standalone(p, sig2, fp, owner) is False


def test_target_swap_rejected_in_both(tmp_path: Path):
    owner, gov, p, sig, fp = _mint(tmp_path, sample={"host": "10.0.0.5"})
    assert _intree(p, sig, fp, owner) is False
    assert _standalone(p, sig, fp, owner) is False


def test_wrong_pin_and_wrong_owner_rejected_in_both(tmp_path: Path):
    owner, gov, p, sig, fp = _mint(tmp_path)
    bad_pin = "sha256:" + "0" * 64
    assert _intree(p, sig, bad_pin, owner) is False
    assert _standalone(p, sig, bad_pin, owner) is False
    other = generate_keypair()
    assert _intree(p, sig, fp, other) is False
    assert _standalone(p, sig, fp, other) is False
