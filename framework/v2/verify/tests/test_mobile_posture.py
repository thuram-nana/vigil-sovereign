"""verify.mobile_posture — the mobile-posture oracle (embedded private-key FACT; Phase-2 coverage).

The adversarial soundness map ruled nearly every mobile signal a LEAD (an Android precedence/gating chain
a MobSF descriptor omits). This slice proves the ONE offline-re-derivable FACT: an embedded PEM private
key that the oracle RE-DERIVES by actually LOADING (never a label-match). These tests pin that it fires on
a real unencrypted key, REFUSES on an encrypted/public/masked/garbage blob, and is held OUT of the frozen
fallback so the gate stays byte-identical.
"""

from __future__ import annotations

import pytest

from framework.v2.verify.mobile_posture import confirm_mobile_controls, confirm_mobile_posture
from framework.v2.verify.models import OracleKind
from framework.v2.verify.verifier import _ALL_ORACLES

cryptography = pytest.importorskip("cryptography")
from cryptography.hazmat.primitives import serialization as _ser  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec as _ec, rsa as _rsa  # noqa: E402


def _rsa_pem(fmt=_ser.PrivateFormat.PKCS8, enc=_ser.NoEncryption()) -> str:
    return _rsa.generate_private_key(65537, 2048).private_bytes(_ser.Encoding.PEM, fmt, enc).decode()


def _ec_pem() -> str:
    return _ec.generate_private_key(_ec.SECP256R1()).private_bytes(
        _ser.Encoding.PEM, _ser.PrivateFormat.TraditionalOpenSSL, _ser.NoEncryption()).decode()


def _ctl(pem: str, rule: str = "private_key_material") -> dict:
    return {"rule": rule, "check_id": "secret:0", "pem": pem}


# ---- FIRES: a real, unencrypted, structurally-valid private key is a FACT ----

def test_unencrypted_rsa_key_is_a_fact():
    r = confirm_mobile_posture(_ctl(_rsa_pem()))
    assert r.confirmed
    assert any(s.kind == OracleKind.MOBILE_POSTURE and s.fired for s in r.signals)


def test_unencrypted_ec_key_is_a_fact():
    assert confirm_mobile_posture(_ctl(_ec_pem())).confirmed


def test_pkcs1_traditional_rsa_key_is_a_fact():
    # the SEC1/PKCS#1 "-----BEGIN RSA PRIVATE KEY-----" spelling also loads + fires
    pem = _rsa.generate_private_key(65537, 2048).private_bytes(
        _ser.Encoding.PEM, _ser.PrivateFormat.TraditionalOpenSSL, _ser.NoEncryption()).decode()
    assert "RSA PRIVATE KEY" in pem
    assert confirm_mobile_posture(_ctl(pem)).confirmed


def test_openssh_format_key_is_a_fact():
    # review defect [MEDIUM]: ssh-keygen's DEFAULT format since OpenSSH 7.8. load_pem_private_key cannot
    # parse the OpenSSH container; the oracle falls back to load_ssh_private_key (still a real re-load).
    from cryptography.hazmat.primitives.asymmetric import ed25519
    pem = ed25519.Ed25519PrivateKey.generate().private_bytes(
        _ser.Encoding.PEM, _ser.PrivateFormat.OpenSSH, _ser.NoEncryption()).decode()
    assert "OPENSSH PRIVATE KEY" in pem
    assert confirm_mobile_posture(_ctl(pem)).confirmed


# ---- REFUSES: everything the oracle cannot reconstruct as a usable key ----

def test_encrypted_key_stays_a_lead():
    # an encrypted (passphrase-protected) key is real key material but its usability is unproven → LEAD
    enc = _rsa_pem(enc=_ser.BestAvailableEncryption(b"hunter2"))
    assert not confirm_mobile_posture(_ctl(enc)).confirmed


def test_public_key_does_not_fire():
    pub = _rsa.generate_private_key(65537, 2048).public_key().public_bytes(
        _ser.Encoding.PEM, _ser.PublicFormat.SubjectPublicKeyInfo).decode()
    assert not confirm_mobile_posture(_ctl(pub)).confirmed


def test_masked_or_partial_pem_refuses():
    masked = "-----BEGIN PRIVATE KEY-----\nMIIEvQ****REDACTED****\n-----END PRIVATE KEY-----"
    assert not confirm_mobile_posture(_ctl(masked)).confirmed


def test_non_pem_secret_refuses():
    assert not confirm_mobile_posture(_ctl("AKIAIOSFODNN7EXAMPLE")).confirmed


def test_no_pem_field_refuses():
    assert not confirm_mobile_posture({"rule": "private_key_material", "check_id": "secret:0"}).confirmed


def test_lead_only_rule_does_not_fire():
    # a general mobile lead (exported component, cleartext, allowBackup, secret-string) is NOT promoted
    for rule in ("exported_activity", "clear_text", "allow_backup", "secret", "unknown"):
        assert not confirm_mobile_posture({"rule": rule, "check_id": "x", "pem": ""}).confirmed


def test_non_mapping_and_empty_are_safe():
    assert not confirm_mobile_posture({}).confirmed
    assert confirm_mobile_controls(None) == []
    assert confirm_mobile_controls("nope") == []


def test_confirm_mobile_controls_filters_to_facts():
    facts = confirm_mobile_controls([
        _ctl(_rsa_pem()),                                    # FACT
        {"rule": "clear_text", "check_id": "manifest:1"},    # lead
        _ctl(_rsa_pem(enc=_ser.BestAvailableEncryption(b"pw"))),  # encrypted → lead
    ])
    assert len(facts) == 1 and facts[0]["rule"] == "private_key_material"


# ---- byte-identical gate discipline: held OUT of the frozen fallback ----

def test_mobile_posture_is_not_in_the_frozen_fallback():
    assert OracleKind.MOBILE_POSTURE not in _ALL_ORACLES
    assert len(_ALL_ORACLES) == 15
