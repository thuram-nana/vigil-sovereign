"""
The OPT-IN cryptographic XML-DSig escalation of the SAML structural-forgery oracle (the `saml` extra).

A captured SAML Response whose ds:Signature structurally COVERS the consumed assertion looks "properly
signed" to the structural oracle — but "covers by URI" is not "valid crypto". When the operator supplies
a TRUSTED IdP cert AND `signxml` is importable, this escalation runs a REAL XML-DSig verification and
promotes the finding to a FACT (proof=``invalid_signature``) ONLY when the signature is DEFINITIVELY
cryptographically invalid against that trusted anchor — a wrong-signer forgery (InvalidSignature) or a
tampered-content assertion (InvalidDigest).

THE TWO HARD FP LINES this module pins:

  1. NEVER trust the EMBEDDED cert. A SAML assertion carries its own ds:X509Certificate in KeyInfo — the
     ATTACKER controls it, so a self-signed forgery "verifies" against its OWN embedded cert. This oracle
     verifies ONLY against the operator-supplied trusted cert(s) via signxml's ``x509_cert=`` (which
     overrides the document's embedded KeyInfo). With NO trusted cert the branch is DORMANT — a
     self-signed forgery embedding its own cert does NOT fire (the cardinal test below).
  2. REFUSE-TO-ADJUDICATE on can't-verify. c14n / unsupported-transform / cert-trust failures are NOT
     "forged" — they are "couldn't verify". The oracle fires ONLY on signxml's DEFINITIVE
     InvalidSignature/InvalidDigest exceptions; an unsupported algorithm/transform (InvalidInput), a cert
     trust/expiry failure (InvalidCertificate), a parse/config error, or any other outcome REFUSES
     (stays the structural verdict).

These tests build REAL RSA keypairs and sign with signxml, so the crypto is genuinely exercised. They
``importorskip('signxml')`` / ``importorskip('cryptography')`` so the suite still passes in an env that
lacks the opt-in extra (there, the crypto branch is dormant and the structural oracle is byte-identical).
"""

from __future__ import annotations

import datetime
import sys

import pytest

pytest.importorskip("signxml")
pytest.importorskip("cryptography")
pytest.importorskip("lxml")

from cryptography import x509  # noqa: E402
from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import rsa  # noqa: E402
from cryptography.x509.oid import NameOID  # noqa: E402
from lxml import etree  # noqa: E402
from signxml import XMLSigner  # noqa: E402

from framework.v2.verify import (  # noqa: E402
    confirm_saml_forgery,
    saml_forgery_context,
    saml_forgery_oracle,
)
from framework.v2.verify.adapter import FindingContext  # noqa: E402
from framework.v2.verify.models import OracleKind  # noqa: E402
from framework.v2.verify.oracles import _saml_crypto_verdict  # noqa: E402
from framework.v2.verify.reverify import reverify_context  # noqa: E402
from framework.v2.verify.verifier import _ALL_ORACLES, OracleVerifier  # noqa: E402

_NS_A = "urn:oasis:names:tc:SAML:2.0:assertion"
_NS_P = "urn:oasis:names:tc:SAML:2.0:protocol"


# ---------------------------------------------------------------------------
# real-keypair + real-signature fixtures (module-scoped: keygen is done once)
# ---------------------------------------------------------------------------


def _make_key_cert(
    cn: str,
    *,
    not_before: datetime.datetime = datetime.datetime(2020, 1, 1),
    not_after: datetime.datetime = datetime.datetime(2035, 1, 1),
):
    """A fresh RSA-2048 keypair + a self-signed X.509 cert (PEM) with the given validity window."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subj = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subj)
        .issuer_name(subj)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .sign(key, hashes.SHA256())
    )
    return key, cert.public_bytes(serialization.Encoding.PEM).decode()


# key A is the "real IdP"; key B is a DIFFERENT signer; expired-A is A's key under an expired cert.
_KEY_A, _PEM_A = _make_key_cert("idpA")
_KEY_B, _PEM_B = _make_key_cert("idpB")
_, _PEM_A_EXPIRED = _make_key_cert(
    "idpA-expired",
    not_before=datetime.datetime(2000, 1, 1),
    not_after=datetime.datetime(2001, 1, 1),
)
# reuse A's private key under the expired cert so the SIGNATURE would be valid but the CERT is not.
_PEM_A_EXPIRED = (
    x509.CertificateBuilder()
    .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "idpA-expired")]))
    .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "idpA-expired")]))
    .public_key(_KEY_A.public_key())
    .serial_number(x509.random_serial_number())
    .not_valid_before(datetime.datetime(2000, 1, 1))
    .not_valid_after(datetime.datetime(2001, 1, 1))
    .sign(_KEY_A, hashes.SHA256())
).public_bytes(serialization.Encoding.PEM).decode()


def _signed_response(
    signer_key,
    embed_pem: str,
    *,
    nameid: str = "alice@corp.test",
    aid: str = "_a1",
    rid: str = "_r1",
) -> str:
    """A samlp:Response whose saml:Assertion is signed IN PLACE (enveloped) by ``signer_key``, embedding
    ``embed_pem`` in ds:KeyInfo — how a REAL IdP signs. The signature's canonicalization is computed over
    the assertion as it sits in the Response, so it verifies against the correct signer's cert. (Signing a
    standalone assertion then transplanting it would break inclusive-c14n; that is a test artifact, not a
    forgery, so we sign in place.)"""
    full = etree.fromstring(
        f'<samlp:Response xmlns:samlp="{_NS_P}" xmlns:saml="{_NS_A}" ID="{rid}" Version="2.0">'
        f"<saml:Issuer>idp</saml:Issuer>"
        f'<saml:Assertion ID="{aid}"><saml:Subject><saml:NameID>{nameid}</saml:NameID></saml:Subject>'
        f"<saml:Conditions/></saml:Assertion></samlp:Response>".encode()
    )
    assertion_el = full.find(f"{{{_NS_A}}}Assertion")
    signed_el = XMLSigner(signature_algorithm="rsa-sha256", digest_algorithm="sha256").sign(
        assertion_el, key=signer_key, cert=embed_pem
    )
    idx = list(full).index(assertion_el)
    full.remove(assertion_el)
    full.insert(idx, signed_el)
    return etree.tostring(full).decode()


# ---------------------------------------------------------------------------
# FIRES — a signature DEFINITIVELY invalid against the operator's TRUSTED cert
# ---------------------------------------------------------------------------


def test_fires_on_wrong_signer_vs_trusted_cert() -> None:
    # signed by key A (embeds A's own cert), but the operator's TRUSTED anchor is key B: the RSA
    # signature over SignedInfo does not verify against B -> InvalidSignature -> definitive forgery.
    doc = _signed_response(_KEY_A, _PEM_A)  # a real, self-consistent signature by A
    sig = saml_forgery_oracle(doc, candidate_certs=[_PEM_B])
    assert sig.fired and sig.kind is OracleKind.SAML_STRUCTURAL_FORGERY
    assert sig.observed["proof"] == "invalid_signature"
    assert sig.observed["crypto_outcome"] == "invalid_signature"
    assert sig.confidence >= 0.9
    assert "InvalidSignature" in sig.observed.get("signxml_error", "")


def test_fires_on_tampered_content_vs_trusted_cert() -> None:
    # signed by A over alice@corp.test; the attacker swaps the NameID AFTER signing. The SignedInfo still
    # verifies against A (signer is A), but the referenced assertion's digest no longer matches ->
    # InvalidDigest -> definitive content-tampering forgery against the trusted cert A.
    doc = _signed_response(_KEY_A, _PEM_A, nameid="alice@corp.test")
    tampered = doc.replace("alice@corp.test", "attacker@evil.test")
    sig = saml_forgery_oracle(tampered, candidate_certs=[_PEM_A])
    assert sig.fired
    assert sig.observed["proof"] == "invalid_signature"
    assert "InvalidDigest" in sig.observed.get("signxml_error", "")


# ---------------------------------------------------------------------------
# NON-FIRE — the CARDINAL embedded-cert guard + a genuinely valid signature
# ---------------------------------------------------------------------------


def test_cardinal_embedded_self_signed_cert_with_no_trusted_cert_does_not_fire() -> None:
    # THE CARDINAL FP TEST. The assertion embeds its OWN (attacker-controllable) ds:X509Certificate, and
    # the signature verifies against that embedded cert. With NO operator-supplied trusted anchor the
    # crypto branch is DORMANT — this is exactly the JWT embedded-key/x5c FP that got rejected. It must
    # stay a structural non-fire (the reference structurally covers the consumed assertion), NEVER a
    # crypto fire, no matter that it "self-verifies".
    doc = _signed_response(_KEY_A, _PEM_A)  # self-signed forgery: embeds its own cert
    sig = saml_forgery_oracle(doc)  # no candidate_certs -> dormant
    assert not sig.fired
    assert sig.observed.get("proof") != "invalid_signature"
    assert "crypto_outcome" not in sig.observed
    # and _saml_crypto_verdict itself reports 'unavailable' (never consults the embedded cert)
    assert _saml_crypto_verdict(doc, [])[0] == "unavailable"


def test_does_not_fire_when_signature_verifies_against_the_trusted_cert() -> None:
    # a genuinely valid IdP signature: signed by A, the operator's trusted anchor IS A. It verifies ->
    # NOT a forgery -> non-fire (degrades to the structural verdict).
    doc = _signed_response(_KEY_A, _PEM_A)
    sig = saml_forgery_oracle(doc, candidate_certs=[_PEM_A])
    assert not sig.fired
    assert _saml_crypto_verdict(doc, [_PEM_A])[0] == "verified"


def test_embedded_cert_only_never_promotes_but_a_mismatched_trusted_cert_does() -> None:
    # the three-way contrast that isolates the cardinal line: the SAME self-signed doc is
    #   - NON-FIRE with no trusted cert (embedded cert is never a trust anchor),
    #   - NON-FIRE with the CORRECT trusted cert (it validly verifies),
    #   - FIRE only with a MISMATCHED operator-supplied trusted cert.
    doc = _signed_response(_KEY_A, _PEM_A)
    assert not saml_forgery_oracle(doc).fired
    assert not saml_forgery_oracle(doc, candidate_certs=[_PEM_A]).fired
    assert saml_forgery_oracle(doc, candidate_certs=[_PEM_B]).fired


# ---------------------------------------------------------------------------
# REFUSE — can't-verify is NOT forged (the c14n / unsupported-transform trap)
# ---------------------------------------------------------------------------


def test_refuses_on_unsupported_signature_algorithm() -> None:
    # mangle the SignatureMethod Algorithm to an unrecognized URI: signxml raises InvalidInput (a
    # ValueError, NOT an InvalidSignature) BEFORE it can verify. "Couldn't verify" != "forged" -> refuse.
    doc = _signed_response(_KEY_A, _PEM_A)
    mangled = doc.replace("rsa-sha256", "rsa-BOGUS-unsupported")  # -> Unrecognized SignatureMethod
    sig = saml_forgery_oracle(mangled, candidate_certs=[_PEM_A])
    assert not sig.fired
    assert _saml_crypto_verdict(mangled, [_PEM_A])[0] == "refuse"


def test_refuses_on_expired_trusted_cert_right_key() -> None:
    # the trusted cert carries A's RIGHT public key but is EXPIRED -> InvalidCertificate (a subclass of
    # InvalidSignature that we catch FIRST). A cert trust/expiry failure is NOT a bad signature -> refuse.
    doc = _signed_response(_KEY_A, _PEM_A)
    assert _saml_crypto_verdict(doc, [_PEM_A_EXPIRED])[0] == "refuse"
    assert not saml_forgery_oracle(doc, candidate_certs=[_PEM_A_EXPIRED]).fired


def test_refuses_on_mixed_definitive_invalid_plus_indeterminate() -> None:
    # rotation set where one cert is a definitive wrong-signer (B) and the other is indeterminate
    # (expired A). A single indeterminate outcome (a cert we could not evaluate — it MIGHT be the real
    # signer) forces a refuse: we fire only when EVERY cert conclusively rejects the signature.
    doc = _signed_response(_KEY_A, _PEM_A)
    assert _saml_crypto_verdict(doc, [_PEM_B, _PEM_A_EXPIRED])[0] == "refuse"
    assert not saml_forgery_oracle(doc, candidate_certs=[_PEM_B, _PEM_A_EXPIRED]).fired


def test_rotation_set_verified_by_any_cert_short_circuits_to_non_fire() -> None:
    # key rotation: the operator supplies both the OLD (B) and NEW (A) certs. The signature verifies
    # against A, so it is a valid signature under the trusted set -> non-fire (never fire just because
    # ONE cert in the set rejects it).
    doc = _signed_response(_KEY_A, _PEM_A)
    assert _saml_crypto_verdict(doc, [_PEM_B, _PEM_A])[0] == "verified"
    assert not saml_forgery_oracle(doc, candidate_certs=[_PEM_B, _PEM_A]).fired


# ---------------------------------------------------------------------------
# graceful degradation — the extra ABSENT is byte-identical to structural-only
# ---------------------------------------------------------------------------


def test_extra_absent_degrades_to_structural_only(monkeypatch: pytest.MonkeyPatch) -> None:
    # simulate a future env WITHOUT signxml: the lazy `from signxml import ...` inside the helper raises
    # ImportError -> crypto branch 'unavailable' -> the structural verdict stands. A wrong-signer doc that
    # WOULD crypto-fire must instead be a structural non-fire (it is structurally "covered").
    monkeypatch.setitem(sys.modules, "signxml", None)
    doc = _signed_response(_KEY_A, _PEM_A)
    assert _saml_crypto_verdict(doc, [_PEM_B])[0] == "unavailable"
    sig = saml_forgery_oracle(doc, candidate_certs=[_PEM_B])
    assert not sig.fired
    assert sig.observed.get("proof") != "invalid_signature"


def test_structural_path_byte_identical_with_and_without_empty_certs() -> None:
    # with no / empty candidate_certs the crypto branch is dormant and the oracle output must be
    # byte-identical to the pre-existing structural oracle, for BOTH a structural fire and a non-fire.
    unsigned = (
        f'<samlp:Response xmlns:samlp="{_NS_P}" xmlns:saml="{_NS_A}" ID="_r1" Version="2.0">'
        f'<saml:Assertion ID="_a1"><saml:Subject><saml:NameID>alice@corp.test</saml:NameID>'
        f"</saml:Subject><saml:Conditions/></saml:Assertion></samlp:Response>"
    )
    covered = _signed_response(_KEY_A, _PEM_A)
    for doc in (unsigned, covered):
        a = saml_forgery_oracle(doc)
        b = saml_forgery_oracle(doc, candidate_certs=[])
        assert (a.fired, a.confidence, a.evidence, a.observed) == (b.fired, b.confidence, b.evidence, b.observed)


# ---------------------------------------------------------------------------
# gate safety — no new OracleKind, frozen fallback unchanged
# ---------------------------------------------------------------------------


def test_no_new_oracle_kind_and_frozen_fallback_unchanged() -> None:
    assert len(OracleKind) == 27
    assert len(_ALL_ORACLES) == 15
    assert OracleKind.SAML_STRUCTURAL_FORGERY not in _ALL_ORACLES


# ---------------------------------------------------------------------------
# routing via the seam + verifier, and offline re-verification
# ---------------------------------------------------------------------------


def test_confirm_via_seam_and_verifier_with_trusted_cert() -> None:
    forged = _signed_response(_KEY_A, _PEM_A)
    # wrong-signer trusted cert -> crypto forgery confirmed
    assert confirm_saml_forgery(forged, [_PEM_B]).confirmed
    assert OracleVerifier().confirm(saml_forgery_context(forged, [_PEM_B])).confirmed
    # verifies against the correct trusted cert -> NOT confirmed
    assert not confirm_saml_forgery(forged, [_PEM_A]).confirmed
    # no trusted cert -> structural non-fire (covered) -> NOT confirmed (cardinal)
    assert not confirm_saml_forgery(forged).confirmed


def test_crypto_forgery_reverifies_offline_from_retained_context() -> None:
    forged = _signed_response(_KEY_A, _PEM_A)
    oracle_context = saml_forgery_context(forged, [_PEM_B])
    # no target, no forged traffic — re-run the oracle over the retained XML + trusted cert
    r = reverify_context(oracle_context, bug_class="saml_structural_forgery")
    assert r.reproduced and r.ok
    assert r.confirmed_by == OracleKind.SAML_STRUCTURAL_FORGERY.value


def test_adapter_builder_emits_saml_candidate_certs() -> None:
    forged = _signed_response(_KEY_A, _PEM_A)
    emitted = FindingContext.from_saml_structure(forged, candidate_certs=[_PEM_B]).to_verifier_context()
    assert emitted["bug_class"] == "saml_structural_forgery"
    assert emitted["saml_xml"] == forged
    assert emitted["saml_candidate_certs"] == [_PEM_B]
    # no certs supplied -> the field is absent from the ctx (dormant, byte-identical)
    assert "saml_candidate_certs" not in FindingContext.from_saml_structure(forged).to_verifier_context()
