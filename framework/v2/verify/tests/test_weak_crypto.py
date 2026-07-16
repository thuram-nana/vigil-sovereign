"""verify.weak_crypto — a cert signed with a BROKEN hash (MD5/SHA1) as a weak-crypto FACT.

Pins the sound, unconditional proof: a real SHA-1-signed cert fires; a modern SHA-256/384/512 cert does
NOT; the classification (name + OID fallback) is exhaustive; and `sha1` never false-matches SHA-2.
Reuses TLS_WEAKNESS — no new OracleKind.
"""

from __future__ import annotations

import datetime

import pytest

from framework.v2.verify import (
    confirm_weak_crypto_artifact,
    signature_descriptor,
    signature_descriptors,
    weak_crypto_context,
)
from framework.v2.verify.oracles import weak_crypto_artifact_oracle
from framework.v2.verify.models import OracleKind
from framework.v2.verify.reverify import reverify_context
from framework.v2.verify.verifier import _ALL_ORACLES

pytest.importorskip("cryptography")

# A REAL self-signed cert signed with SHA-1 (openssl req -x509 -sha1). Modern `cryptography` refuses to
# SIGN with SHA-1, so this is a captured fixture — the end-to-end proof that a broken-hash cert fires.
_SHA1_CERT_PEM = """-----BEGIN CERTIFICATE-----
MIIDFzCCAf+gAwIBAgIUOuV7fFl6dUjBXrvBNWqSHuPufzAwDQYJKoZIhvcNAQEF
BQAwGzEZMBcGA1UEAwwQd2Vhay5leGFtcGxlLmNvbTAeFw0yNjA3MTQxNzAyMDla
Fw0zNjA3MTExNzAyMDlaMBsxGTAXBgNVBAMMEHdlYWsuZXhhbXBsZS5jb20wggEi
MA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDL9LKf2i5rVjkf+1E42DCe8D3N
2mQrEsyfOgsl5OV6iQubZGMiyV1Byvm0clPPc5H+PH2Hda2SkoDs6BTKyMj9Ig48
WspW2ZCRTSnA9Gu6z2JbT2Z9BrvKQgKtO65vJfkGjTsXMRh03XJBIWVvvdB9VzkT
x1KBw8TLZ0aUyzFJ2AJ2V8eHew2fbI+oV5JfCEXbD2QJc7hGT9H8n/epNEj1sVkE
q7+eRaMc6qoQnV4/Q4ALREDV/6qgTN55g0D7foDa1zqzv2PLfyy/1zhZwzO8sNHq
jatVN5x3YGRioY0+XvJTpN7g6ogFTGwVHCd0tgAEhkh+FQwIwOWYJsTSK5vZAgMB
AAGjUzBRMB0GA1UdDgQWBBQWAeyzgdLeZ6nxZIz/2qR2f32v2zAfBgNVHSMEGDAW
gBQWAeyzgdLeZ6nxZIz/2qR2f32v2zAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3
DQEBBQUAA4IBAQAr4H7xeMhHH6hxqNVeaEmC64Yu5eO2WpB73ctIIEOrS2RN8a6k
QLjVhdT39LJCtHmxTqBi9MopTYNRNXHm+XYBEVomRZLEayAq/iY7d2GdkoDGwJvk
79yuh9TwTsfc9uoxRBE4AXTuWjqBCVXTuspXwCOjpv6fiUdmJ8Pxw3oMizLhX1aJ
S8UVIabE3N131qiu57YtDchhxnCFDyEtCkOLgSLf8pe8hEO6lhMD3Sk4Ev27+ME6
ff/HwDHrGTOpgVPsogD6pkCx/L3NCOSoMZzJw4NId6j7MYrNTc7qbS82O7GlfTkc
sfF59b+k2bpuIhdt+8BBymCPKTdp4Z00xbOo
-----END CERTIFICATE-----"""


def _cert(hash_algo) -> bytes:
    """A fresh self-signed cert signed with ``hash_algo`` (PEM). Used for the SHA-2 non-fire cases."""
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID
    k = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    n = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "good.example.com")])
    c = (x509.CertificateBuilder().subject_name(n).issuer_name(n).public_key(k.public_key())
         .serial_number(1).not_valid_before(datetime.datetime(2020, 1, 1))
         .not_valid_after(datetime.datetime(2030, 1, 1)).sign(k, hash_algo))
    return c.public_bytes(serialization.Encoding.PEM)


# ---------------------------------------------------------------------------
# FIRES — a real broken-hash (SHA-1) cert
# ---------------------------------------------------------------------------


def test_fires_on_real_sha1_signed_cert():
    r = confirm_weak_crypto_artifact(_SHA1_CERT_PEM)
    assert r is not None
    assert r.confirmed_by == OracleKind.TLS_WEAKNESS.value
    desc = signature_descriptor(_SHA1_CERT_PEM)
    assert desc["signature_algorithm"] == "sha1WithRSAEncryption"
    assert desc["oid"] == "1.2.840.113549.1.1.5"


def test_fires_on_real_sha1_cert_as_der_bytes():
    from cryptography import x509
    from cryptography.hazmat.primitives.serialization import Encoding
    der = x509.load_pem_x509_certificate(_SHA1_CERT_PEM.encode()).public_bytes(Encoding.DER)
    assert confirm_weak_crypto_artifact(der) is not None   # DER input path


# ---------------------------------------------------------------------------
# NON-FIRE — modern strong hashes
# ---------------------------------------------------------------------------


def test_no_fire_on_sha256_384_512_certs():
    from cryptography.hazmat.primitives import hashes
    for algo in (hashes.SHA256(), hashes.SHA384(), hashes.SHA512()):
        assert confirm_weak_crypto_artifact(_cert(algo)) is None


def test_unparseable_cert_is_dormant():
    assert weak_crypto_context(b"not a cert") is None
    assert confirm_weak_crypto_artifact("garbage") is None


# ---------------------------------------------------------------------------
# CHAIN — a weak-hash INTERMEDIATE (not just the leaf) is judged (review w277ihd5a LOW)
# ---------------------------------------------------------------------------


def test_fires_on_weak_intermediate_in_a_chain():
    from cryptography.hazmat.primitives import hashes
    modern_leaf = _cert(hashes.SHA256()).decode()
    chain = modern_leaf + "\n" + _SHA1_CERT_PEM   # modern leaf + SHA-1 "intermediate"
    r = confirm_weak_crypto_artifact(chain)
    assert r is not None, "a SHA-1 cert later in the chain must still fire"
    # the certified evidence is the WEAK cert's subject, not the modern leaf's
    ctx = weak_crypto_context(chain)
    assert ctx.crypto_artifact["signature_algorithm"] == "sha1WithRSAEncryption"
    assert "weak.example.com" in ctx.crypto_artifact["subject"]


def test_all_modern_chain_does_not_fire():
    from cryptography.hazmat.primitives import hashes
    chain = _cert(hashes.SHA256()).decode() + "\n" + _cert(hashes.SHA384()).decode()
    assert confirm_weak_crypto_artifact(chain) is None


def test_private_key_pem_is_dormant_not_raising():
    key_pem = ("-----BEGIN PRIVATE KEY-----\nMIIBVQ==\n-----END PRIVATE KEY-----")  # not a cert
    assert signature_descriptors(key_pem) == []
    assert weak_crypto_context(key_pem) is None


# ---------------------------------------------------------------------------
# oracle classification — name + OID fallback, and sha1 must not match SHA-2
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("name", [
    "md5WithRSAEncryption", "md4WithRSAEncryption", "md2WithRSAEncryption",
    "sha1WithRSAEncryption", "ecdsa-with-SHA1", "dsa-with-sha1",
])
def test_oracle_fires_on_broken_hash_names(name):
    assert weak_crypto_artifact_oracle({"signature_algorithm": name}).fired


@pytest.mark.parametrize("name", [
    "sha256WithRSAEncryption", "sha384WithRSAEncryption", "sha512WithRSAEncryption",
    "ecdsa-with-SHA256", "ed25519", "sha224WithRSAEncryption",
])
def test_oracle_does_not_fire_on_strong_names(name):
    # the sha1 negative-lookahead must NOT let sha224/256/384/512 through.
    assert not weak_crypto_artifact_oracle({"signature_algorithm": name}).fired


def test_oid_fallback_fires_when_name_absent():
    assert weak_crypto_artifact_oracle({"signature_algorithm": "", "oid": "1.2.840.113549.1.1.5"}).fired
    assert not weak_crypto_artifact_oracle({"signature_algorithm": "", "oid": "1.2.840.113549.1.1.11"}).fired  # sha256WithRSA


def test_oracle_non_mapping_is_safe():
    assert not weak_crypto_artifact_oracle(None).fired
    assert not weak_crypto_artifact_oracle("x").fired


# ---------------------------------------------------------------------------
# undersized public key (a second weak-crypto rule over the SAME cert descriptor)
# ---------------------------------------------------------------------------


def _cert_with_key(key) -> bytes:
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519
    from cryptography.hazmat.primitives.hashes import SHA256
    from cryptography.x509.oid import NameOID
    n = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "t.example.com")])
    b = (x509.CertificateBuilder().subject_name(n).issuer_name(n).public_key(key.public_key())
         .serial_number(1).not_valid_before(datetime.datetime(2020, 1, 1))
         .not_valid_after(datetime.datetime(2030, 1, 1)))
    hsh = None if isinstance(key, ed25519.Ed25519PrivateKey) else SHA256()
    return b.sign(key, hsh).public_bytes(serialization.Encoding.PEM)


def test_descriptor_carries_key_type_and_bits():
    from cryptography.hazmat.primitives.asymmetric import rsa
    d = signature_descriptor(_cert_with_key(rsa.generate_private_key(65537, 2048)))
    assert d["key_type"] == "rsa" and d["key_bits"] == 2048


@pytest.mark.parametrize("key_type,bits", [("rsa", 512), ("rsa", 1024), ("dsa", 1024), ("ec", 160), ("ec", 192)])
def test_oracle_fires_on_an_undersized_key(key_type, bits):
    sig = weak_crypto_artifact_oracle(
        {"signature_algorithm": "sha256WithRSAEncryption", "key_type": key_type, "key_bits": bits})
    assert sig.fired and sig.observed["reason"] == "short_key"


@pytest.mark.parametrize("key_type,bits", [("rsa", 2048), ("rsa", 4096), ("dsa", 2048), ("ec", 224), ("ec", 256), ("ec", 384)])
def test_oracle_does_not_fire_on_an_adequate_key(key_type, bits):
    assert not weak_crypto_artifact_oracle(
        {"signature_algorithm": "sha256WithRSAEncryption", "key_type": key_type, "key_bits": bits}).fired


def test_short_key_fires_end_to_end_over_a_real_cert():
    from cryptography.hazmat.primitives.asymmetric import ec, rsa
    assert confirm_weak_crypto_artifact(_cert_with_key(rsa.generate_private_key(65537, 1024))) is not None
    assert confirm_weak_crypto_artifact(_cert_with_key(ec.generate_private_key(ec.SECP192R1()))) is not None
    # a strong 2048-bit RSA / P-256 / Ed25519 cert does NOT fire (near-zero-FP)
    from cryptography.hazmat.primitives.asymmetric import ed25519
    assert confirm_weak_crypto_artifact(_cert_with_key(rsa.generate_private_key(65537, 2048))) is None
    assert confirm_weak_crypto_artifact(_cert_with_key(ec.generate_private_key(ec.SECP256R1()))) is None
    assert confirm_weak_crypto_artifact(_cert_with_key(ed25519.Ed25519PrivateKey.generate())) is None


def test_no_key_bits_field_never_fires_on_key_size():
    # an absent/unknown key size must never be judged short (only a hash rule could fire here)
    assert not weak_crypto_artifact_oracle({"signature_algorithm": "sha256WithRSAEncryption", "key_type": "rsa"}).fired
    assert not weak_crypto_artifact_oracle({"key_type": "ed25519publickey", "key_bits": None}).fired


# ---------------------------------------------------------------------------
# offline re-verification + gate safety
# ---------------------------------------------------------------------------


def test_fact_reverifies_offline():
    ctx = weak_crypto_context(_SHA1_CERT_PEM)
    r = reverify_context(ctx, bug_class="weak_crypto_artifact")
    assert r.reproduced and r.ok
    assert r.confirmed_by == OracleKind.TLS_WEAKNESS.value


def test_reuses_tls_weakness_no_new_kind():
    # weak-crypto adds NO new kind: it reuses TLS_WEAKNESS (a frozen fallback member) and there is no
    # WEAK_CRYPTO* member. (The absolute OracleKind count is pinned by the gate-invariant test, not here.)
    assert OracleKind.TLS_WEAKNESS in _ALL_ORACLES
    assert not any(k.name.startswith("WEAK_CRYPTO") for k in OracleKind)
