"""
Tests for Wave 3.1 — the TLS-weakness oracle.

A "weak TLS" claim is an OBSERVATION; it becomes a FACT only when a real handshake negotiates a
deprecated protocol or a weak cipher. These cover the pure oracle, the FindingContext carrier + offline
re-verification, and the gated, bounded active capture (injected connector + a real loopback TLS
handshake + fail-closed refusals). The active gate is the SAME audited one as verify.reachability.
"""

from __future__ import annotations

import socket
import ssl
import threading
from pathlib import Path

import pytest

from framework.v2.verify import (
    OracleVerifier,
    capture_tls_handshake,
    confirm_weak_tls,
    tls_weakness_oracle,
    weak_tls_context,
)
from framework.v2.verify.adapter import FindingContext
from framework.v2.verify.reverify import reverify_context


# ---- the pure oracle -------------------------------------------------------


@pytest.mark.parametrize("version", ["TLSv1", "TLSv1.1", "SSLv3", "sslv2"])
def test_oracle_fires_on_a_deprecated_protocol(version: str) -> None:
    sig = tls_weakness_oracle(
        {"connected": True, "host": "h", "port": 443, "tls_version": version,
         "cipher": "ECDHE-RSA-AES128-GCM-SHA256"})
    assert sig.fired and sig.confidence >= 0.7 and "deprecated" in sig.evidence


@pytest.mark.parametrize("cipher", [
    "ECDHE-RSA-RC4-SHA", "DES-CBC3-SHA", "EXP-RC2-CBC-MD5", "NULL-SHA", "ADH-AES256-SHA", "RSA-3DES-EDE"])
def test_oracle_fires_on_a_weak_cipher(cipher: str) -> None:
    sig = tls_weakness_oracle(
        {"connected": True, "host": "h", "port": 443, "tls_version": "TLSv1.2", "cipher": cipher})
    assert sig.fired and sig.confidence >= 0.7 and "weak cipher" in sig.evidence


def test_oracle_does_not_fire_on_strong_modern_tls() -> None:
    sig = tls_weakness_oracle(
        {"connected": True, "host": "h", "port": 443, "tls_version": "TLSv1.3",
         "cipher": "TLS_AES_256_GCM_SHA384"})
    assert sig.fired is False   # good posture is not a finding


@pytest.mark.parametrize("tls", [
    {"connected": False, "host": "h", "port": 443, "error": "handshake failed"},
    {"connected": True, "host": "h", "port": 443, "tls_version": "TLSv1.2",
     "cipher": "ECDHE-RSA-AES128-GCM-SHA256"},   # strong -> no weakness
    "not a mapping",
    {},
])
def test_oracle_does_not_fire_without_a_real_weak_handshake(tls) -> None:
    assert tls_weakness_oracle(tls).fired is False


def test_deprecated_protocol_outranks_cipher_check() -> None:
    # a deprecated protocol fires at 0.95 even if the cipher would also match
    sig = tls_weakness_oracle(
        {"connected": True, "host": "h", "port": 443, "tls_version": "TLSv1", "cipher": "RC4-SHA"})
    assert sig.fired and sig.confidence == 0.95 and sig.observed["reason"] == "deprecated_protocol"


# ---- verifier routing + carrier + offline re-verify ------------------------


def test_weak_tls_routes_and_reverifies_offline() -> None:
    tls = {"connected": True, "host": "10.0.0.5", "port": 443, "tls_version": "TLSv1.1",
           "cipher": "AES128-SHA"}
    res = OracleVerifier().confirm(weak_tls_context(tls))
    assert res.confirmed and res.bug_class == "weak_tls"
    # re-run the pure oracle over the retained JSON-safe context — no network
    r = reverify_context(weak_tls_context(tls), bug_class="weak_tls")
    assert r.reproduced and r.ok
    import json
    json.dumps(weak_tls_context(tls))


def test_from_tls_handshake_carrier_and_a_strong_endpoint_does_not_confirm() -> None:
    ctx = FindingContext.from_tls_handshake(
        {"connected": True, "host": "h", "port": 443, "tls_version": "TLSv1.3", "cipher": "TLS_AES_128_GCM_SHA256"})
    assert ctx.to_verifier_context()["tls"]["tls_version"] == "TLSv1.3"
    assert not OracleVerifier().confirm(ctx.to_verifier_context()).confirmed


# ---- the gated, bounded active capture -------------------------------------


@pytest.fixture(autouse=True)
def _isolate(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    from framework.v2.common import paths
    monkeypatch.setattr(paths, "killswitch_path", lambda slug: tmp_path / f"{slug}.halt")
    monkeypatch.setattr(paths, "target_dir", lambda slug: tmp_path / slug)
    monkeypatch.setattr(paths, "charter_path", lambda slug: tmp_path / slug / "charter.md")


def _grant(monkeypatch: pytest.MonkeyPatch) -> None:
    from framework.v2 import entitlement
    monkeypatch.setattr(entitlement, "require_capability", lambda cap: None)


def _charter(tmp_path: Path, host: str) -> None:
    d = tmp_path / "alpha"
    d.mkdir(parents=True, exist_ok=True)
    (d / "charter.md").write_text(
        f"# Engagement charter — `alpha`\n\n**Status:** Final\n\n## 1. Operator attestation\n\n"
        f"Signed: `tester`     Date: `2026-05-04`\n\n## 2. In-scope systems\n\n"
        f"| Host | Notes | Auth |\n|---|---|---|\n| `{host}` | Host | Yes |\n\n"
        f"## 7. Posture\n\n- [x] **TEST**\n", encoding="utf-8")


def test_capture_tls_with_an_injected_connector_confirms_weakness(monkeypatch, tmp_path) -> None:
    _grant(monkeypatch)
    _charter(tmp_path, "10.0.0.5")
    tls = capture_tls_handshake("10.0.0.5", 443, slug="alpha",
                                connect=lambda h, p, t: ("TLSv1", "RC4-SHA", 128))
    assert tls["connected"] is True and tls["tls_version"] == "TLSv1"
    assert confirm_weak_tls(tls).confirmed


def test_capture_tls_handshake_failure_is_a_clean_negative(monkeypatch, tmp_path) -> None:
    _grant(monkeypatch)
    _charter(tmp_path, "10.0.0.5")

    def _fail(h, p, t):
        raise ssl.SSLError("handshake failure")

    tls = capture_tls_handshake("10.0.0.5", 443, slug="alpha", connect=_fail)
    assert tls["connected"] is False and "SSLError" in tls["error"]
    assert not confirm_weak_tls(tls).confirmed


def test_capture_tls_over_a_real_loopback_tls_server(monkeypatch, tmp_path) -> None:
    _grant(monkeypatch)
    _charter(tmp_path, "127.0.0.1")
    # a real self-signed TLS server on loopback — a genuine handshake, no mocks
    cert = _self_signed_cert(tmp_path)
    if cert is None:
        pytest.skip("cryptography not available to mint a self-signed cert")
    srv_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    srv_ctx.load_cert_chain(cert)
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    port = srv.getsockname()[1]

    def _serve():
        try:
            conn, _ = srv.accept()
            with srv_ctx.wrap_socket(conn, server_side=True):
                pass
        except OSError:
            pass

    t = threading.Thread(target=_serve, daemon=True)
    t.start()
    try:
        tls = capture_tls_handshake("127.0.0.1", port, slug="alpha", timeout=5.0)
    finally:
        srv.close()
        t.join(timeout=2.0)
    assert tls["connected"] is True and tls["tls_version"].startswith("TLS")
    # a modern default handshake should NOT be flagged weak
    assert not confirm_weak_tls(tls).confirmed


def test_capture_tls_no_slug_refused_never_connects(monkeypatch) -> None:
    _grant(monkeypatch)
    called = {"n": 0}
    tls = capture_tls_handshake("10.0.0.5", 443, connect=lambda *a: (called.update(n=1) or ("TLSv1.3", "x", 256)))
    assert tls["connected"] is False and "slug" in tls["error"] and called["n"] == 0


def test_capture_tls_out_of_scope_refused(monkeypatch, tmp_path) -> None:
    _grant(monkeypatch)
    _charter(tmp_path, "10.0.0.5")
    tls = capture_tls_handshake("8.8.8.8", 443, slug="alpha", connect=lambda *a: ("TLSv1.3", "x", 256))
    assert tls["connected"] is False and "scope" in tls["error"]


def test_capture_tls_requires_active_recon_entitlement(monkeypatch) -> None:
    from framework.v2 import entitlement
    monkeypatch.setattr(entitlement, "require_capability",
                        lambda cap: (_ for _ in ()).throw(RuntimeError("not entitled")))
    tls = capture_tls_handshake("10.0.0.5", 443, slug="alpha", connect=lambda *a: ("TLSv1.3", "x", 256))
    assert tls["connected"] is False and "not entitled" in tls["error"]


def _self_signed_cert(tmp_path: Path):
    """Mint a throwaway self-signed cert+key PEM for the loopback TLS server, or None if unavailable."""
    try:
        import datetime

        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import NameOID
    except Exception:
        return None
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = datetime.datetime(2026, 1, 1)
    cert = (x509.CertificateBuilder()
            .subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now).not_valid_after(datetime.datetime(2030, 1, 1))
            .sign(key, hashes.SHA256()))
    p = tmp_path / "srv.pem"
    p.write_bytes(cert.public_bytes(serialization.Encoding.PEM)
                  + key.private_bytes(serialization.Encoding.PEM,
                                      serialization.PrivateFormat.TraditionalOpenSSL,
                                      serialization.NoEncryption()))
    return str(p)
