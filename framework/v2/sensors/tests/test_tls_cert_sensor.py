"""
Tests for the TLS/cert posture sensor (X.509 certificate offline ingest).

A certificate file/dir is ingested (offline) as a gated sensor → weak-crypto CONTROL LEADS
(``GROUNDING_INTEL``), never facts. The sensor STOPS at leads; the weak-crypto-artifact oracle
(``verify.weak_crypto``) re-verifies a lead to a FACT only for a BROKEN-hash signature (MD5/SHA-1) —
wired through ``engage_fusion`` (``test_engage_fusion.py``). A modern SHA-256+ cert stays a lead. Mirrors
``test_cicd_sensor``.
"""

from __future__ import annotations

from pathlib import Path

import pytest

pytest.importorskip("cryptography")

from framework.v2.agents.tools import ToolContext  # noqa: E402
from framework.v2.sensors import (  # noqa: E402
    CertScanSensor,
    cert_control_observations,
    default_registry,
    parse_certs,
)
from framework.v2.verify.tests.test_weak_crypto import _SHA1_CERT_PEM, _cert  # noqa: E402


def _sha256_pem() -> str:
    from cryptography.hazmat.primitives.hashes import SHA256
    return _cert(SHA256()).decode()


def test_parse_a_sha1_cert_file(tmp_path: Path) -> None:
    p = tmp_path / "weak.pem"
    p.write_text(_SHA1_CERT_PEM, encoding="utf-8")
    controls = parse_certs(str(p))
    assert len(controls) == 1
    assert controls[0]["signature_algorithm"] == "sha1WithRSAEncryption"
    assert controls[0]["check_id"] == "weak.pem:0"       # stable, source-namespaced


def test_parse_a_der_cert_file(tmp_path: Path) -> None:
    from cryptography import x509
    from cryptography.hazmat.primitives.serialization import Encoding
    der = x509.load_pem_x509_certificate(_SHA1_CERT_PEM.encode()).public_bytes(Encoding.DER)
    p = tmp_path / "weak.der"
    p.write_bytes(der)
    controls = parse_certs(str(p))
    assert len(controls) == 1 and controls[0]["signature_algorithm"] == "sha1WithRSAEncryption"


def test_parse_directory_and_pem_chain(tmp_path: Path) -> None:
    d = tmp_path / "certs"
    d.mkdir()
    (d / "a.pem").write_text(_sha256_pem() + "\n" + _SHA1_CERT_PEM, encoding="utf-8")  # a 2-cert bundle
    (d / "b.crt").write_text(_sha256_pem(), encoding="utf-8")
    (d / "notes.txt").write_text("ignored", encoding="utf-8")   # non-cert extension skipped
    controls = parse_certs(str(d))
    # a.pem yields 2 descriptors (modern leaf + SHA-1), b.crt yields 1
    assert len(controls) == 3
    assert any(c["signature_algorithm"] == "sha1WithRSAEncryption" for c in controls)
    assert len({c["check_id"] for c in controls}) == 3      # unique per cert


def test_parse_is_total_on_garbage(tmp_path: Path) -> None:
    p = tmp_path / "junk.pem"
    p.write_text("not a certificate", encoding="utf-8")
    assert parse_certs(str(p)) == []
    assert parse_certs(str(tmp_path / "nope.pem")) == []


def test_observations_are_leads_not_facts(tmp_path: Path) -> None:
    p = tmp_path / "weak.pem"
    p.write_text(_SHA1_CERT_PEM, encoding="utf-8")
    obs = cert_control_observations(parse_certs(str(p)), seq=1)
    assert len(obs) == 1
    o = obs[0]
    assert o.source == "tls_cert"
    assert o.source_kind.value == "operator_ingest"
    assert 0.0 < o.confidence < 1.0
    assert o.relation is None and o.object is None
    assert o.subject.node_id.startswith("control:crypto:")
    assert o.attrs.get("signature_algorithm") == "sha1WithRSAEncryption"
    assert o.attrs.get("lead") is True and o.attrs.get("unverified") is True


def test_obs_ids_are_claim_keyed_and_reingest_is_idempotent(tmp_path: Path) -> None:
    p = tmp_path / "weak.pem"
    p.write_text(_SHA1_CERT_PEM, encoding="utf-8")
    controls = parse_certs(str(p))
    ids1 = [o.obs_id for o in cert_control_observations(controls, seq=1)]
    ids2 = [o.obs_id for o in cert_control_observations(controls, seq=1)]
    assert ids1 == ids2
    dup = cert_control_observations(controls + controls, seq=1)
    assert [o.obs_id for o in dup] == ids1                  # intra-batch duplicate collapses


def test_sensor_ingests_cert_and_mints_control_leads(tmp_path: Path) -> None:
    p = tmp_path / "weak.pem"
    p.write_text(_SHA1_CERT_PEM, encoding="utf-8")
    s = CertScanSensor()
    ctx = ToolContext(slug="alpha")
    res = s.run({"cert": str(p)}, ctx)
    assert res.ok and res.summary == "tls_cert: 1 certificate(s)"
    obs = s.normalize(res, ctx, seq=1)
    assert obs and all(o.subject.node_id.startswith("control:crypto:") for o in obs)


def test_sensor_missing_and_absent_cert_degrade_cleanly(tmp_path: Path) -> None:
    ctx = ToolContext(slug="alpha")
    assert not CertScanSensor().run({}, ctx).ok
    assert not CertScanSensor().run({"cert": "/no/such/cert.pem"}, ctx).ok
    p = tmp_path / "junk.pem"
    p.write_text("not a cert", encoding="utf-8")
    res = CertScanSensor().run({"cert": str(p)}, ctx)
    assert res.ok and CertScanSensor().normalize(res, ctx, seq=1) == []


def test_registered_in_default_registry() -> None:
    assert "tls_cert" in default_registry()
