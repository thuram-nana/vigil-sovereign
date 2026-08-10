"""Phase 3 — the signed cloud benchmark harness (cloud_benchmark).

VIGIL's cloud_live_verify is scored against a labelled cloud ground-truth manifest, matched on
(bug_class, resource_id), alongside any supplied incumbent report; the scorecard is signed and re-verifies
OFFLINE with an out-of-band trust-root pin. Fixture-tested (a native inventory + a sample prowler report
stand in for a live capture / live tool run).

The VIGIL-scoring + sign/verify paths importorskip framework (they run in the offense leg); the pure
scoring/normalization math is sovereign-safe.
"""
from __future__ import annotations

import json

import pytest

from vigil_integration.live.cloud_benchmark import (
    CloudGroundTruth,
    normalize_prowler,
    run_cloud_benchmark,
    score_pairs,
    sign_cloud_scorecard,
    verify_cloud_scorecard,
    _trust_root_fingerprint,
)


def _signers_and_authorizers():
    from vigil_core import generate_keypair
    kp = generate_keypair()
    return [("gov0", kp.private_key_b64)], [{"key_id": "gov0", "public_key_b64": kp.public_key_b64}]


# A native inventory with two insecure resources (a public bucket -> cloud_misconfiguration + an anon grant
# path -> privilege_path; an unencrypted sensitive db -> cloud_misconfiguration) and one SAFE resource.
_CAPTURE = {"format": "native", "export": {"resources": [
    {"id": "arn:aws:s3:::acme-public", "kind": "datastore",
     "grants": [{"principal": "*", "access": "s3:GetObject"}]},
    {"id": "arn:aws:rds:::acme-db", "kind": "datastore", "encrypted": False, "sensitive": True},
    {"id": "arn:aws:s3:::acme-private", "kind": "datastore"}]}}

_TRUTH = CloudGroundTruth(
    vulns=[("arn:aws:s3:::acme-public", "cloud_misconfiguration"),
           ("arn:aws:s3:::acme-public", "privilege_path"),
           ("arn:aws:rds:::acme-db", "cloud_misconfiguration")],
    safe=["arn:aws:s3:::acme-private"])


# ---- pure scoring / normalization (sovereign-safe) -----------------------------------------------

def test_score_pairs_confusion_matrix():
    # a tool that finds the two cloud_misconfiguration vulns but misses the privilege_path and false-flags a
    # safe resource
    pairs = {("cloud_misconfiguration", "arn:aws:s3:::acme-public"),
             ("cloud_misconfiguration", "arn:aws:rds:::acme-db"),
             ("cloud_misconfiguration", "arn:aws:s3:::acme-private")}  # FP on the safe resource
    s = score_pairs("t", pairs, _TRUTH)
    assert s.true_positives == 2 and s.false_negatives == 1 and s.false_positives == 1
    assert s.safe_hits == 1
    assert 0.66 < s.precision < 0.67 and 0.66 < s.recall < 0.67


def test_prowler_normalizer_maps_to_vigil_classes():
    report = {"findings": [
        {"check_id": "s3_bucket_public_access", "resource_arn": "arn:aws:s3:::acme-public"},
        {"check_id": "rds_instance_storage_encrypted", "resource_id": "arn:aws:rds:::acme-db"},
        {"check_id": "some_unmapped_check", "resource_arn": "arn:aws:s3:::acme-other"},  # dropped (unmapped)
    ]}
    pairs = normalize_prowler(report)
    assert ("cloud_misconfiguration", "arn:aws:s3:::acme-public") in pairs
    assert ("cloud_misconfiguration", "arn:aws:rds:::acme-db") in pairs
    assert all("acme-other" not in rid for _bc, rid in pairs)   # unmapped check contributes nothing


def test_normalizer_is_total_on_malformed_report():
    assert normalize_prowler("not a report") == set()
    assert normalize_prowler({"findings": [None, 3, {"no_check": 1}]}) == set()


# ---- VIGIL scored + a signed scorecard that re-verifies offline (framework leg) ------------------

def test_vigil_scores_perfect_on_its_detectable_classes_and_signs():
    pytest.importorskip("framework.v2.verify", reason="CRUCIBLE not importable here")
    signers, authorizers = _signers_and_authorizers()
    prowler = {"findings": [
        {"check_id": "s3_bucket_public_access", "resource_arn": "arn:aws:s3:::acme-public"},
        {"check_id": "rds_instance_storage_encrypted", "resource_id": "arn:aws:rds:::acme-db"}]}
    card = run_cloud_benchmark(_CAPTURE, _TRUTH, provider="aws", account="111122223333",
                              signers=signers, incumbent_reports={"prowler": prowler})
    rows = {r["tool"]: r for r in card["results"]}
    # VIGIL confirms all three planted pairs (2 cloud_misconfiguration + 1 privilege_path), zero FP/safe-hit
    assert rows["vigil"]["tp"] == 3 and rows["vigil"]["fp"] == 0 and rows["vigil"]["fn"] == 0
    assert rows["vigil"]["safe_hits"] == 0 and rows["vigil"]["precision"] == 1.0 and rows["vigil"]["recall"] == 1.0
    # prowler (posture-only) got the two cloud_misconfiguration, missed the privilege_path
    assert rows["prowler"]["tp"] == 2 and rows["prowler"]["fn"] == 1
    # the incumbents not supplied are honestly listed as skipped, never scored 0
    assert set(card["incumbents_skipped"]) == {"checkov", "scout-suite"}
    assert "vigil" in card["tools_scored"] and "checkov" not in card["tools_scored"]


def test_signed_scorecard_reverifies_offline_and_fails_on_tamper(tmp_path):
    pytest.importorskip("framework.v2.verify", reason="CRUCIBLE not importable here")
    signers, authorizers = _signers_and_authorizers()
    card = run_cloud_benchmark(_CAPTURE, _TRUTH, provider="aws", account="111122223333", signers=signers)
    out = tmp_path / "cloud-scorecard.json"
    sig = sign_cloud_scorecard(card, out, signers=signers, authorizers=authorizers, threshold=1)
    pin = _trust_root_fingerprint(authorizers)
    # honest signed artifact re-verifies offline with the out-of-band pin
    assert verify_cloud_scorecard(out, sig, trust_root_fingerprint=pin) is True
    # a flipped number breaks the digest -> fail closed
    doc = json.loads(out.read_text())
    doc["results"][0]["tp"] += 1
    out.write_text(json.dumps(doc))
    assert verify_cloud_scorecard(out, sig, trust_root_fingerprint=pin) is False


def test_keyless_forgery_with_zero_threshold_is_rejected_even_with_correct_pin(tmp_path):
    """BLOCK-1 regression: an attacker holding NO key recomputes the digest over a tampered body and supplies
    threshold=0 + zero signatures, keeping the pinned authorizer set. Pre-fix this verified TRUE even with the
    correct out-of-band pin (total defeat of tamper-evidence). It must now fail closed."""
    pytest.importorskip("framework.v2.verify", reason="CRUCIBLE not importable here")
    import hashlib as _h

    from vigil_core import canonical_json
    signers, authorizers = _signers_and_authorizers()
    card = run_cloud_benchmark(_CAPTURE, _TRUTH, provider="aws", account="111122223333", signers=signers)
    out = tmp_path / "cloud-scorecard.json"
    sign_cloud_scorecard(card, out, signers=signers, authorizers=authorizers, threshold=1)
    pin = _trust_root_fingerprint(authorizers)
    # tamper the body, then RECOMPUTE the digest over it (so the digest check passes) and forge a keyless
    # zero-threshold sig envelope, keeping the pinned authorizer set unchanged.
    doc = json.loads(out.read_text())
    doc["results"][0]["tp"] = 999
    out.write_text(json.dumps(doc))
    digest = "sha256:" + _h.sha256(canonical_json(json.loads(out.read_text()))).hexdigest()
    forged = {"scorecard_digest": digest,
              "trust_root": {"threshold": 0, "authorizers": authorizers}, "signatures": []}
    assert verify_cloud_scorecard(out, forged, trust_root_fingerprint=pin) is False   # keyless -> rejected
    forged["trust_root"]["threshold"] = -1                                            # negative too
    assert verify_cloud_scorecard(out, forged, trust_root_fingerprint=pin) is False


def test_threshold_downgrade_is_rejected_by_expected_threshold(tmp_path):
    """BLOCK-2 regression: a 2-of-2 scorecard, re-signed by an insider holding ONE key with threshold lowered
    to 1, is rejected when the caller pins expected_threshold=2 (the governance quorum)."""
    pytest.importorskip("framework.v2.verify", reason="CRUCIBLE not importable here")
    from vigil_core import generate_keypair
    k0, k1 = generate_keypair(), generate_keypair()
    signers = [("g0", k0.private_key_b64), ("g1", k1.private_key_b64)]
    authz = [{"key_id": "g0", "public_key_b64": k0.public_key_b64},
             {"key_id": "g1", "public_key_b64": k1.public_key_b64}]
    card = run_cloud_benchmark(_CAPTURE, _TRUTH, provider="aws", account="111122223333", signers=signers)
    out = tmp_path / "cloud-scorecard.json"
    sig = sign_cloud_scorecard(card, out, signers=signers, authorizers=authz, threshold=2)
    # honest 2-of-2 verifies when the caller pins expected_threshold=2
    assert verify_cloud_scorecard(out, sig, expected_threshold=2) is True
    # insider with only g0 lowers threshold to 1 and signs alone
    downgraded = sign_cloud_scorecard(card, out, signers=[("g0", k0.private_key_b64)], authorizers=authz,
                                     threshold=1)
    assert verify_cloud_scorecard(out, downgraded, expected_threshold=None) is True   # weak mode accepts thr=1
    assert verify_cloud_scorecard(out, downgraded, expected_threshold=2) is False     # pinned quorum rejects it


def test_forged_trust_root_is_rejected_by_the_pin(tmp_path):
    pytest.importorskip("framework.v2.verify", reason="CRUCIBLE not importable here")
    from vigil_core import generate_keypair
    signers, authorizers = _signers_and_authorizers()
    card = run_cloud_benchmark(_CAPTURE, _TRUTH, provider="aws", account="111122223333", signers=signers)
    out = tmp_path / "cloud-scorecard.json"
    sig = sign_cloud_scorecard(card, out, signers=signers, authorizers=authorizers, threshold=1)
    real_pin = _trust_root_fingerprint(authorizers)
    # a forger re-signs the SAME bytes with a FRESH key and swaps the embedded trust root
    forge = generate_keypair()
    fsig = sign_cloud_scorecard(card, out, signers=[("evil", forge.private_key_b64)],
                               authorizers=[{"key_id": "evil", "public_key_b64": forge.public_key_b64}],
                               threshold=1)
    # without the pin, the forged bundle is internally self-consistent (weak mode)
    assert verify_cloud_scorecard(out, fsig, trust_root_fingerprint=None) is True
    # WITH the out-of-band pin, the forged trust root is rejected before any signature check
    assert verify_cloud_scorecard(out, fsig, trust_root_fingerprint=real_pin) is False
