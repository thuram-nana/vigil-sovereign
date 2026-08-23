"""
S9c — the PostureCertificate discloses a coverage-incomplete run and downgrades its overall verdict.

The posture certificate projects CLOSED/OPEN/UNPROVEN purely from the coverage cert's per-probe verdicts —
the REACHED WEB surface. A run may ALSO have a DECLARED cloud/K8s surface a fusion sensor could NOT assess
(INCONCLUSIVE). Left unsaid, an all-CLEAN web cert reads as a clean whole-target close while silent about
that unassessed surface — the silent-CLEAN a sound-negative a government acts on must never make.

Proven here:
  * a coverage-incomplete build CARRIES the unassessed surfaces + a downgraded ``overall`` verdict + a
    residual clause naming them, and NEVER fabricates a CLOSED/OPEN claim about the unassessed surface;
  * a clean/no-disclosure build is BYTE-IDENTICAL to the pre-S9c certificate (no new fields);
  * sign+verify round-trips, and the fail-closed enforcement REFUSES a cert whose overall was tampered to a
    clean whole-target CLOSED while still declaring an unassessed surface (both in-tree and standalone);
  * the standalone VIGIL-free verifier agrees and surfaces the COVERAGE INCOMPLETE note.
"""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

from vigil_core.capability import sign_identity_attestation
from vigil_core.crypto import generate_keypair
from vigil_integration.posture.certificate import (
    PostureError,
    build_posture_certificate,
    canonical_posture_bytes,
    posture_overall_verdict,
    project_posture_claims,
    sign_posture_certificate,
    verify_posture_certificate,
)

_VERIFIER = Path(__file__).resolve().parents[2] / "docs" / "proof-carrying-finding" / "verify_vf.py"


def _load_standalone():
    spec = importlib.util.spec_from_file_location("standalone_vf_incov", _VERIFIER)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


VF = _load_standalone()


def _all_clean_coverage() -> dict:
    """A coverage cert whose every probe is CLEAN with a conclusive oracle — so WITHOUT any disclosure the
    posture projection is all-CLOSED and the overall would read as a clean whole-target CLOSE."""
    return {
        "schema": "vigil-coverage-certificate/1",
        "scope": "reached-surface coverage; not a completeness proof",
        "target_host": "127.0.0.1",
        "denominator": {"surfaces_reached": 2, "insertion_points_probed": 2, "distinct_classes_probed": 2,
                        "frontier_truncated": 0, "max_pages": 25, "max_depth": 4, "budget_exhausted": False},
        "probes": [
            {"surface": "/search", "insertion_point": "query", "param": "q", "check_id": "xss",
             "class": "reflected_xss", "verdict": "clean", "oracle_kinds_run": ["reflection"]},
            {"surface": "/profile", "insertion_point": "query", "param": "name", "check_id": "bsqli",
             "class": "boolean_sqli", "verdict": "clean", "oracle_kinds_run": ["boolean_inference"]},
        ],
        "summary": {"n_finding": 0, "n_clean": 2, "n_inconclusive": 0},
    }


def _identity():
    owner = generate_keypair()
    att = sign_identity_attestation(owner, engagement="demo", policy={"host": ["127.0.0.1"]},
                                    not_after=9999999999)
    return owner, att


_UNASSESSED = [{"sensor": "cloud_live", "missing_prerequisite": "no ambient aws credentials"},
               {"sensor": "k8s_live", "missing_prerequisite": "no kubeconfig"}]


# ---------------------------------------------------------------------------
# the overall-verdict projection
# ---------------------------------------------------------------------------


def test_overall_downgrades_a_clean_close_when_incomplete():
    claims = project_posture_claims(_all_clean_coverage())
    assert all(c["status"] == "CLOSED" for c in claims)
    assert posture_overall_verdict(claims, []) == "CLOSED"                      # clean whole-target close
    assert posture_overall_verdict(claims, _UNASSESSED) == "COVERAGE_INCOMPLETE"  # downgraded
    # an OPEN finding still dominates an incomplete disclosure.
    open_claims = claims + [{"status": "OPEN"}]
    assert posture_overall_verdict(open_claims, _UNASSESSED) == "OPEN"


# ---------------------------------------------------------------------------
# the certificate disclosure
# ---------------------------------------------------------------------------


def test_incomplete_cert_carries_disclosure_and_names_no_fabricated_claim():
    _, att = _identity()
    cert = build_posture_certificate(_all_clean_coverage(), target_identity=att,
                                     target_sample={"host": "127.0.0.1"}, coverage_incomplete=_UNASSESSED)
    assert cert["coverage_incomplete"]["incomplete"] is True
    assert [u["sensor"] for u in cert["coverage_incomplete"]["unassessed_surfaces"]] == ["cloud_live", "k8s_live"]
    assert cert["summary"]["overall"] == "COVERAGE_INCOMPLETE"
    # the residual (in the SIGNED bytes) NAMES the unassessed surface + its missing prerequisite.
    assert "COVERAGE INCOMPLETE" in cert["residual"] and "cloud_live" in cert["residual"]
    assert "no ambient aws credentials" in cert["residual"]
    # NEVER a fabricated CLOSED/OPEN claim about the unassessed surface — the projection is web-only.
    assert all(c["class"] in ("reflected_xss", "boolean_sqli") for c in cert["posture_claims"])
    assert not any(c["class"] in ("cloud_live", "k8s_live") for c in cert["posture_claims"])


def test_clean_build_is_byte_identical_without_disclosure():
    _, att = _identity()
    cov = _all_clean_coverage()
    base = build_posture_certificate(cov, target_identity=att, target_sample={"host": "127.0.0.1"})
    for empty in (None, [], ()):
        again = build_posture_certificate(cov, target_identity=att, target_sample={"host": "127.0.0.1"},
                                          coverage_incomplete=empty)
        assert canonical_posture_bytes(again) == canonical_posture_bytes(base)
        assert "coverage_incomplete" not in again and "overall" not in again["summary"]


# ---------------------------------------------------------------------------
# sign + verify: round-trip and the fail-closed enforcement
# ---------------------------------------------------------------------------


def _sign(cert, tmp_path):
    gov = generate_keypair()
    p = tmp_path / "posture.json"
    sig = sign_posture_certificate(cert, p, signers=[("gov", gov.private_key_b64)],
                                   authorizers=[{"key_id": "gov", "public_key_b64": gov.public_key_b64}],
                                   threshold=1)
    fp = p.with_suffix(".fingerprint.txt").read_text().strip()
    return gov, p, sig, fp


def test_incomplete_cert_round_trips_in_both_verifiers(tmp_path: Path):
    owner, att = _identity()
    cert = build_posture_certificate(_all_clean_coverage(), target_identity=att,
                                     target_sample={"host": "127.0.0.1"}, coverage_incomplete=_UNASSESSED)
    _, p, sig, fp = _sign(cert, tmp_path)
    assert verify_posture_certificate(p, sig, trust_root_fingerprint=fp,
                                      owner_pubkey=owner.public_key_b64, engagement="demo", now=1) is True
    ok, log = VF.verify_posture({"certificate": json.loads(p.read_text()), "signature": sig},
                                pin=fp, owner_pubkey=owner.public_key_b64, engagement="demo", now=1)
    assert ok is True and "COVERAGE INCOMPLETE" in log and "cloud_live" in log


def test_tampered_overall_to_closed_is_refused(tmp_path: Path):
    """A producer that keeps the coverage-incomplete disclosure but flips ``overall`` back to a clean
    whole-target CLOSED (and re-signs, so the signature itself is valid) is REFUSED by the downgrade
    enforcement — in-tree AND standalone."""
    owner, att = _identity()
    cert = build_posture_certificate(_all_clean_coverage(), target_identity=att,
                                     target_sample={"host": "127.0.0.1"}, coverage_incomplete=_UNASSESSED)
    cert["summary"]["overall"] = "CLOSED"                 # the forgery: hide the incompleteness in the verdict
    _, p, sig, fp = _sign(cert, tmp_path)                 # re-signed => the signature check passes
    with pytest.raises(PostureError):
        verify_posture_certificate(p, sig, trust_root_fingerprint=fp,
                                   owner_pubkey=owner.public_key_b64, engagement="demo", now=1)
    ok, reason = VF.verify_posture({"certificate": json.loads(p.read_text()), "signature": sig},
                                   pin=fp, owner_pubkey=owner.public_key_b64, engagement="demo", now=1)
    assert ok is False and ("CLOSED" in reason or "disagrees" in reason)
