"""P5 — the Authority-Envelope certificate (the accountability twin): prove an autonomous agent took
only actions its owner-signed authority permitted. A conformant run verifies; any executed action that
left the envelope, a forged conformance verdict, or a tampered envelope is refused fail-closed.
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from vigil_core.crypto import generate_keypair
from vigil_integration.posture.authority import (
    AuthorityError,
    build_authority_certificate,
    sign_authority_certificate,
    sign_authority_envelope,
    verify_authority_certificate,
)

OWNER = generate_keypair()
GOV = generate_keypair()
SIGNERS = [("gov", GOV.private_key_b64)]
AUTHZ = [{"key_id": "gov", "public_key_b64": GOV.public_key_b64}]


def _envelope():
    return sign_authority_envelope(OWNER, engagement="demo", scope_hosts=["127.0.0.1"],
                                   action_allowlist=["nmap", "httpx"], not_before=0, not_after=9_999_999_999)


def _sign(cert, tmp_path):
    p = tmp_path / "authority.json"
    sig = sign_authority_certificate(cert, p, signers=SIGNERS, authorizers=AUTHZ, threshold=1)
    fp = p.with_suffix(".fingerprint.txt").read_text().strip()
    return p, sig, fp


def test_conformant_run_verifies(tmp_path: Path):
    actions = [
        {"seq": 1, "action_kind": "nmap", "target": "http://127.0.0.1/", "at": 100, "gate_outcome": "allow", "executed": True},
        {"seq": 2, "action_kind": "httpx", "target": "127.0.0.1", "at": 200, "gate_outcome": "allow", "executed": True},
        {"seq": 3, "action_kind": "sqlmap", "target": "127.0.0.1", "at": 300, "gate_outcome": "queue", "executed": False},
    ]
    cert = build_authority_certificate(_envelope(), actions)
    assert cert["conformance"]["conformant"] is True and cert["conformance"]["n_executed"] == 2
    p, sig, fp = _sign(cert, tmp_path)
    assert verify_authority_certificate(p, sig, trust_root_fingerprint=fp,
                                        owner_pubkey=OWNER.public_key_b64, engagement="demo") is True


def test_executed_out_of_scope_action_is_non_conformant(tmp_path: Path):
    actions = [{"seq": 1, "action_kind": "nmap", "target": "10.0.0.5", "at": 100,
                "gate_outcome": "allow", "executed": True}]  # out-of-scope host, EXECUTED
    cert = build_authority_certificate(_envelope(), actions)
    assert cert["conformance"]["conformant"] is False
    p, sig, fp = _sign(cert, tmp_path)
    with pytest.raises(AuthorityError):
        verify_authority_certificate(p, sig, trust_root_fingerprint=fp,
                                     owner_pubkey=OWNER.public_key_b64, engagement="demo")


def test_disallowed_action_kind_is_non_conformant(tmp_path: Path):
    actions = [{"seq": 1, "action_kind": "responder", "target": "127.0.0.1", "at": 100,
                "gate_outcome": "allow", "executed": True}]  # kind not in the allowlist
    cert = build_authority_certificate(_envelope(), actions)
    p, sig, fp = _sign(cert, tmp_path)
    with pytest.raises(AuthorityError):
        verify_authority_certificate(p, sig, trust_root_fingerprint=fp,
                                     owner_pubkey=OWNER.public_key_b64, engagement="demo")


def test_forged_conformance_is_refused(tmp_path: Path):
    actions = [{"seq": 1, "action_kind": "nmap", "target": "10.0.0.5", "at": 100,
                "gate_outcome": "allow", "executed": True}]  # a real violation
    cert = build_authority_certificate(_envelope(), actions)
    cert["conformance"] = {"conformant": True, "violations": [], "n_actions": 1, "n_executed": 1}  # LIE
    p, sig, fp = _sign(cert, tmp_path)  # re-signed with the lie
    with pytest.raises(AuthorityError):  # re-derivation exposes the mismatch
        verify_authority_certificate(p, sig, trust_root_fingerprint=fp,
                                     owner_pubkey=OWNER.public_key_b64, engagement="demo")


def test_tampered_envelope_is_refused(tmp_path: Path):
    cert = build_authority_certificate(_envelope(), [])
    cert["envelope"]["scope_hosts"] = ["evil.example.com"]  # widen scope AFTER the owner signed
    p, sig, fp = _sign(cert, tmp_path)
    with pytest.raises(AuthorityError):
        verify_authority_certificate(p, sig, trust_root_fingerprint=fp,
                                     owner_pubkey=OWNER.public_key_b64, engagement="demo")


def test_wrong_pin_fails_closed(tmp_path: Path):
    cert = build_authority_certificate(_envelope(), [])
    p, sig, fp = _sign(cert, tmp_path)
    assert verify_authority_certificate(p, sig, trust_root_fingerprint="sha256:" + "0" * 64,
                                        owner_pubkey=OWNER.public_key_b64, engagement="demo") is False


import importlib.util  # noqa: E402

_VF = Path(__file__).resolve().parents[2] / "docs" / "proof-carrying-finding" / "verify_vf.py"


def _load_vf():
    spec = importlib.util.spec_from_file_location("standalone_vf_authority", _VF)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _standalone(p, sig, fp, *, owner=None, eng="demo"):
    VF = _load_vf()
    cert = json.loads(Path(p).read_text())
    ok, _ = VF.verify_authority({"certificate": cert, "signature": sig}, pin=fp,
                                owner_pubkey=(owner or OWNER.public_key_b64), engagement=eng)
    return ok


def test_differential_conformant_verifies_in_both(tmp_path: Path):
    cert = build_authority_certificate(_envelope(), [
        {"seq": 1, "action_kind": "nmap", "target": "127.0.0.1", "at": 5, "gate_outcome": "allow", "executed": True}])
    p, sig, fp = _sign(cert, tmp_path)
    assert verify_authority_certificate(p, sig, trust_root_fingerprint=fp,
                                        owner_pubkey=OWNER.public_key_b64, engagement="demo") is True
    assert _standalone(p, sig, fp) is True


def test_differential_violation_refused_in_both(tmp_path: Path):
    cert = build_authority_certificate(_envelope(), [
        {"seq": 1, "action_kind": "nmap", "target": "10.0.0.5", "at": 5, "gate_outcome": "allow", "executed": True}])
    p, sig, fp = _sign(cert, tmp_path)
    with pytest.raises(AuthorityError):
        verify_authority_certificate(p, sig, trust_root_fingerprint=fp,
                                     owner_pubkey=OWNER.public_key_b64, engagement="demo")
    assert _standalone(p, sig, fp) is False


def test_differential_wrong_pin_refused_in_both(tmp_path: Path):
    cert = build_authority_certificate(_envelope(), [])
    p, sig, fp = _sign(cert, tmp_path)
    bad = "sha256:" + "0" * 64
    assert verify_authority_certificate(p, sig, trust_root_fingerprint=bad,
                                        owner_pubkey=OWNER.public_key_b64, engagement="demo") is False
    assert _standalone(p, sig, bad) is False


def test_fatal2_authority_imports_no_framework():
    code = ("import sys; import vigil_integration.posture.authority as m; "
            "bad=[k for k in sys.modules if k.split('.')[0] in {'framework','flask','selenium'}]; "
            "assert not bad, bad; print('clean')")
    repo = Path(__file__).resolve().parents[1].parent
    r = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, cwd=str(repo),
                       env={"PYTHONPATH": "integration", "PATH": "/usr/bin:/bin"})
    assert r.returncode == 0 and "clean" in r.stdout, r.stdout + r.stderr
