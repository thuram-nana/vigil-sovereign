"""P0 — the signed PostureCertificate (Certificate of Non-Exploitability).

Proves: the coverage->posture projection (CLOSED/OPEN/UNPROVEN); a sign+verify round-trip; and that
every forgery axis fails closed — a flipped byte, a forged claim detached from its coverage evidence, a
false CLOSED (a 'clean' probe with no conclusive oracle), a target-swap, a wrong owner key, an expired
identity, and a wrong out-of-band pin. Plus FATAL-2: importing the posture package co-loads no framework.
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from vigil_core.crypto import generate_keypair
from vigil_core.capability import sign_identity_attestation
from vigil_integration.posture.certificate import (
    PostureError,
    build_posture_certificate,
    project_posture_claims,
    sign_posture_certificate,
    verify_posture_certificate,
)


def _coverage_cert() -> dict:
    """A synthetic coverage certificate (the schema of verify.coverage_oracle) with one probe of each
    verdict, so the projection has an OPEN, two CLOSED, and an UNPROVEN claim."""
    probes = [
        {"surface": "/item", "insertion_point": "query", "param": "id", "check_id": "err_sqli",
         "class": "error_based_sqli", "verdict": "finding", "oracle_kinds_run": []},
        {"surface": "/search", "insertion_point": "query", "param": "q", "check_id": "xss",
         "class": "reflected_xss", "verdict": "clean", "oracle_kinds_run": ["reflection"]},
        {"surface": "/profile", "insertion_point": "query", "param": "name", "check_id": "bsqli",
         "class": "boolean_sqli", "verdict": "clean", "oracle_kinds_run": ["boolean_inference"]},
        {"surface": "/download", "insertion_point": "query", "param": "f", "check_id": "ssrf",
         "class": "ssrf", "verdict": "inconclusive", "oracle_kinds_run": []},
    ]
    return {
        "schema": "vigil-coverage-certificate/1",
        "scope": "reached-surface coverage; not a completeness proof",
        "target_host": "127.0.0.1",
        "denominator": {"surfaces_reached": 4, "insertion_points_probed": 4,
                        "distinct_classes_probed": 4, "frontier_truncated": 0,
                        "max_pages": 25, "max_depth": 4, "budget_exhausted": False},
        "probes": probes,
        "summary": {"n_finding": 1, "n_clean": 2, "n_inconclusive": 1},
    }


def _owner_and_identity():
    owner = generate_keypair()
    att = sign_identity_attestation(owner, engagement="demo", policy={"host": ["127.0.0.1"]},
                                    not_after=9999999999)
    return owner, att


def _signers(cert_gov=None):
    gov = cert_gov or generate_keypair()
    signers = [("posture-owner", gov.private_key_b64)]
    authorizers = [{"key_id": "posture-owner", "public_key_b64": gov.public_key_b64}]
    return signers, authorizers


def test_projection_maps_verdicts_to_posture_status():
    claims = project_posture_claims(_coverage_cert())
    by_class = {c["class"]: c for c in claims}
    assert by_class["error_based_sqli"]["status"] == "OPEN"
    assert by_class["reflected_xss"]["status"] == "CLOSED"
    assert by_class["reflected_xss"]["evidence_oracle_kinds"] == ["reflection"]
    assert by_class["boolean_sqli"]["status"] == "CLOSED"
    assert by_class["ssrf"]["status"] == "UNPROVEN"
    # every CLOSED names a conclusive oracle; the base tier is honestly "binding"
    for c in claims:
        if c["status"] == "CLOSED":
            assert c["evidence_oracle_kinds"] and c["verification"] == "binding"


def test_sign_and_verify_roundtrip(tmp_path: Path):
    owner, att = _owner_and_identity()
    cert = build_posture_certificate(_coverage_cert(), target_identity=att,
                                     target_sample={"host": "127.0.0.1"})
    assert cert["summary"] == {"n_closed": 2, "n_open": 1, "n_unproven": 1,
                               "n_closed_re_executable": 0, "n_closed_binding_only": 2}
    signers, authorizers = _signers()
    p = tmp_path / "posture.json"
    sig = sign_posture_certificate(cert, p, signers=signers, authorizers=authorizers, threshold=1)
    fp = (p.with_suffix(".fingerprint.txt")).read_text().strip()
    assert verify_posture_certificate(p, sig, trust_root_fingerprint=fp,
                                      owner_pubkey=owner.public_key_b64, engagement="demo", now=1) is True


def test_flipped_byte_breaks_signature(tmp_path: Path):
    owner, att = _owner_and_identity()
    cert = build_posture_certificate(_coverage_cert(), target_identity=att, target_sample={"host": "127.0.0.1"})
    signers, authorizers = _signers()
    p = tmp_path / "posture.json"
    sig = sign_posture_certificate(cert, p, signers=signers, authorizers=authorizers, threshold=1)
    fp = (p.with_suffix(".fingerprint.txt")).read_text().strip()
    doc = json.loads(p.read_text())
    doc["summary"]["n_closed"] = 99  # tamper a number
    p.write_text(json.dumps(doc))
    assert verify_posture_certificate(p, sig, trust_root_fingerprint=fp,
                                      owner_pubkey=owner.public_key_b64, engagement="demo", now=1) is False


def test_forged_claim_detached_from_coverage_is_refused(tmp_path: Path):
    owner, att = _owner_and_identity()
    cert = build_posture_certificate(_coverage_cert(), target_identity=att, target_sample={"host": "127.0.0.1"})
    # forge: flip an OPEN finding to a CLOSED claim without touching the coverage evidence
    for c in cert["posture_claims"]:
        if c["class"] == "error_based_sqli":
            c["status"] = "CLOSED"
            c["evidence_oracle_kinds"] = ["error_signature"]
    signers, authorizers = _signers()
    p = tmp_path / "posture.json"
    sig = sign_posture_certificate(cert, p, signers=signers, authorizers=authorizers, threshold=1)
    fp = (p.with_suffix(".fingerprint.txt")).read_text().strip()
    with pytest.raises(PostureError):
        verify_posture_certificate(p, sig, trust_root_fingerprint=fp,
                                   owner_pubkey=owner.public_key_b64, engagement="demo", now=1)


def test_false_closed_clean_without_oracle_is_refused():
    cov = _coverage_cert()
    # a 'clean' probe that names NO conclusive oracle is a tampered coverage cert
    cov["probes"].append({"surface": "/x", "insertion_point": "query", "param": "p", "check_id": "c",
                          "class": "path_traversal", "verdict": "clean", "oracle_kinds_run": []})
    with pytest.raises(PostureError):
        project_posture_claims(cov)


def test_target_swap_is_refused(tmp_path: Path):
    owner, att = _owner_and_identity()
    # the scanned target claims a host the owner's identity policy does not allow
    cert = build_posture_certificate(_coverage_cert(), target_identity=att, target_sample={"host": "10.0.0.5"})
    signers, authorizers = _signers()
    p = tmp_path / "posture.json"
    sig = sign_posture_certificate(cert, p, signers=signers, authorizers=authorizers, threshold=1)
    fp = (p.with_suffix(".fingerprint.txt")).read_text().strip()
    with pytest.raises(PostureError):
        verify_posture_certificate(p, sig, trust_root_fingerprint=fp,
                                   owner_pubkey=owner.public_key_b64, engagement="demo", now=1)


def test_wrong_owner_key_and_wrong_pin_fail_closed(tmp_path: Path):
    owner, att = _owner_and_identity()
    cert = build_posture_certificate(_coverage_cert(), target_identity=att, target_sample={"host": "127.0.0.1"})
    signers, authorizers = _signers()
    p = tmp_path / "posture.json"
    sig = sign_posture_certificate(cert, p, signers=signers, authorizers=authorizers, threshold=1)
    fp = (p.with_suffix(".fingerprint.txt")).read_text().strip()
    # wrong owner pubkey → target binding fails closed
    with pytest.raises(PostureError):
        verify_posture_certificate(p, sig, trust_root_fingerprint=fp,
                                   owner_pubkey=generate_keypair().public_key_b64, engagement="demo", now=1)
    # wrong out-of-band pin → authenticity fails closed (before binding)
    assert verify_posture_certificate(p, sig, trust_root_fingerprint="sha256:" + "0" * 64,
                                      owner_pubkey=owner.public_key_b64, engagement="demo", now=1) is False


def test_expired_identity_is_refused(tmp_path: Path):
    owner = generate_keypair()
    att = sign_identity_attestation(owner, engagement="demo", policy={"host": ["127.0.0.1"]}, not_after=100)
    cert = build_posture_certificate(_coverage_cert(), target_identity=att, target_sample={"host": "127.0.0.1"})
    signers, authorizers = _signers()
    p = tmp_path / "posture.json"
    sig = sign_posture_certificate(cert, p, signers=signers, authorizers=authorizers, threshold=1)
    fp = (p.with_suffix(".fingerprint.txt")).read_text().strip()
    with pytest.raises(PostureError):
        verify_posture_certificate(p, sig, trust_root_fingerprint=fp,
                                   owner_pubkey=owner.public_key_b64, engagement="demo", now=10_000_000_000)


def test_fatal2_importing_posture_coloads_no_framework():
    # importing the posture package must pull ZERO framework modules (FATAL-2). The sign/verify path
    # imports framework function-locally, so a plain import stays clean.
    code = (
        "import sys; import vigil_integration.posture.certificate as m; "
        "bad=[k for k in sys.modules if k=='framework' or k.startswith('framework.')]; "
        "assert not bad, bad; print('clean')"
    )
    repo = Path(__file__).resolve().parents[1].parent  # /home/kali/vigil
    r = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True,
                       cwd=str(repo), env={"PYTHONPATH": "integration", "PATH": "/usr/bin:/bin"})
    assert r.returncode == 0, r.stdout + r.stderr
    assert "clean" in r.stdout
