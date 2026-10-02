"""M1.3 — the deterministic certificate-VALIDITY oracle (OracleKind.CERTIFICATE_VALIDITY).

The oracle re-derives the presented LEAF's validity defects — expired / not_yet_valid (against a RETAINED
capture instant) / hostname_mismatch / self_signed (structural) — from the RETAINED DER at the RETAINED
instant, so a FACT re-verifies OFFLINE. These tests plant each defect (positive), present a valid CA-issued
leaf whose SAN matches the host at an in-window instant (the SAFE TWIN — no fire), prove the oracle REFUSES
when the instant carries no provenance (the wiring trap), and prove the verdict re-derives byte-identically
over the retained context (offline re-verification).
"""
from __future__ import annotations

import base64
import datetime

import pytest

cryptography = pytest.importorskip("cryptography")
from cryptography import x509  # noqa: E402
from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import rsa  # noqa: E402
from cryptography.x509.oid import NameOID  # noqa: E402

from framework.v2.verify import OracleVerifier  # noqa: E402
from framework.v2.verify.models import OracleKind  # noqa: E402
from framework.v2.verify.oracles import certificate_validity_oracle  # noqa: E402


def _now() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc)


def _ca():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "VIGIL M1.3 Test CA")])
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(_now() - datetime.timedelta(days=1))
            .not_valid_after(_now() + datetime.timedelta(days=365))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .sign(key, hashes.SHA256()))
    return cert, key


def _leaf(*, cn="vigil-cert-validity.test", sans=None, not_before_days=-1, not_after_days=365, issuer=None):
    """A 2048-bit RSA leaf. ``issuer=(ca_cert, ca_key)`` makes it CA-issued (issuer != subject, so NOT
    self-signed); omitted => self-signed."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    issuer_name = issuer[0].subject if issuer else subject
    signing_key = issuer[1] if issuer else key
    b = (x509.CertificateBuilder()
         .subject_name(subject).issuer_name(issuer_name)
         .public_key(key.public_key()).serial_number(x509.random_serial_number())
         .not_valid_before(_now() + datetime.timedelta(days=not_before_days))
         .not_valid_after(_now() + datetime.timedelta(days=not_after_days)))
    if sans:
        b = b.add_extension(x509.SubjectAlternativeName(sans), critical=False)
    return b.sign(signing_key, hashes.SHA256()), key


def _der_b64(cert) -> str:
    return base64.b64encode(cert.public_bytes(serialization.Encoding.DER)).decode("ascii")


def _record(cert, *, host="127.0.0.1", at_epoch=None, source="runner_clock"):
    rec = {"host": host, "cert_der_b64": _der_b64(cert),
           "captured_at_epoch": int(at_epoch if at_epoch is not None else _now().timestamp())}
    if source is not None:
        rec["capture_time_source"] = source
    return rec


# -- POSITIVES: each defect, planted ---------------------------------------------------------------------
def test_an_expired_leaf_fires_against_the_retained_instant():
    ca = _ca()
    import ipaddress
    cert, _ = _leaf(not_before_days=-40, not_after_days=-10,
                    sans=[x509.IPAddress(ipaddress.ip_address("127.0.0.1"))], issuer=ca)
    sig = certificate_validity_oracle(_record(cert))
    assert sig.kind is OracleKind.CERTIFICATE_VALIDITY
    assert sig.fired and sig.confidence >= 0.95
    assert sig.observed["defects"] == ["expired"], sig.observed["defects"]


def test_a_not_yet_valid_leaf_fires():
    ca = _ca()
    import ipaddress
    cert, _ = _leaf(not_before_days=10, not_after_days=400,
                    sans=[x509.IPAddress(ipaddress.ip_address("127.0.0.1"))], issuer=ca)
    sig = certificate_validity_oracle(_record(cert))
    assert sig.fired and "not_yet_valid" in sig.observed["defects"]


def test_a_hostname_mismatch_leaf_fires():
    ca = _ca()
    cert, _ = _leaf(cn="not-the-host.example", sans=[x509.DNSName("other.example")], issuer=ca)
    sig = certificate_validity_oracle(_record(cert, host="127.0.0.1"))
    assert sig.fired and "hostname_mismatch" in sig.observed["defects"]


def test_a_self_signed_leaf_fires_structurally():
    import ipaddress
    cert, _ = _leaf(sans=[x509.IPAddress(ipaddress.ip_address("127.0.0.1"))])  # no issuer -> self-signed
    sig = certificate_validity_oracle(_record(cert))
    assert sig.fired and "self_signed" in sig.observed["defects"]


# -- SAFE TWIN: a valid CA-issued leaf whose SAN matches the host, in-window -> NO fire -------------------
def test_a_valid_matching_leaf_does_not_fire():
    ca = _ca()
    import ipaddress
    cert, _ = _leaf(cn="127.0.0.1", sans=[x509.IPAddress(ipaddress.ip_address("127.0.0.1"))],
                    not_before_days=-1, not_after_days=365, issuer=ca)
    sig = certificate_validity_oracle(_record(cert, host="127.0.0.1"))
    assert not sig.fired, sig.evidence
    assert sig.observed["defects"] == []


# -- REFUSAL: the wiring trap — an instant with no provenance may not be assumed -------------------------
def test_an_instant_without_provenance_is_refused_not_assumed():
    ca = _ca()
    import ipaddress
    # EXPIRED cert, but the record carries NO capture_time_source: the oracle must REFUSE rather than
    # label the instant 'runner_clock' and fire. Refusal is a non-fire with an explicit reason.
    cert, _ = _leaf(not_before_days=-40, not_after_days=-10,
                    sans=[x509.IPAddress(ipaddress.ip_address("127.0.0.1"))], issuer=ca)
    sig = certificate_validity_oracle(_record(cert, source=None))
    assert not sig.fired
    assert "REFUSED" in sig.evidence and "provenance" in sig.evidence.lower()
    # positive control: the SAME expired cert WITH provenance DOES fire, so the refusal above is the
    # missing provenance, not a broken call shape.
    assert certificate_validity_oracle(_record(cert, source="runner_clock")).fired


def test_missing_or_unparseable_inputs_do_not_fire():
    assert not certificate_validity_oracle(None).fired
    assert not certificate_validity_oracle({}).fired
    assert not certificate_validity_oracle({"cert_der_b64": "zzz-not-base64!!"}).fired
    ca = _ca()
    cert, _ = _leaf(issuer=ca)
    # no instant -> nothing to judge
    rec = {"host": "127.0.0.1", "cert_der_b64": _der_b64(cert), "capture_time_source": "runner_clock"}
    assert not certificate_validity_oracle(rec).fired


# -- OFFLINE RE-DERIVATION: the FACT re-verifies byte-identically over the retained context --------------
def test_the_verdict_re_derives_identically_over_the_retained_context():
    import ipaddress
    cert, _ = _leaf(not_before_days=-40, not_after_days=-10,
                    sans=[x509.IPAddress(ipaddress.ip_address("127.0.0.1"))])
    rec = _record(cert)  # self-signed AND expired
    a = certificate_validity_oracle(rec)
    b = certificate_validity_oracle(dict(rec))
    assert a.fired and b.fired
    assert a.observed["defects"] == b.observed["defects"] == ["expired", "self_signed"]


# -- ROUTING: the verifier selects CERTIFICATE_VALIDITY only via the fresh ctx key -----------------------
def test_the_verifier_confirms_only_via_the_cert_validity_ctx_key():
    import ipaddress
    cert, _ = _leaf(not_before_days=-40, not_after_days=-10,
                    sans=[x509.IPAddress(ipaddress.ip_address("127.0.0.1"))])
    rec = _record(cert)
    v = OracleVerifier()
    # bug_class certificate_validity + the cert_validity key -> CONFIRMED
    good = v.confirm({"bug_class": "certificate_validity", "cert_validity": rec})
    assert good.confirmed, good.rationale
    # the SAME record under the TLS_WEAKNESS class's keys draws no cert-validity oracle (wrong key) ...
    assert not v.confirm({"bug_class": "weak_tls", "cert_validity": rec}).confirmed
    # ... and the cert_validity key with NO declared class is an unknown-class fail-closed (never a FACT).
    assert not v.confirm({"cert_validity": rec, "bug_class": "not_a_known_class"}).confirmed
