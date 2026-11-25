"""PR-H Area 7 (keystone) — the REAL signxml XML-DSig round-trip through `verify_saml_response`.

Everything in test_saml.py injects a `sig_verifier` STUB that merely *attests* which element ids are
"signed", so the structural / XSW / temporal / audience / replay logic is exercised without a vetted
XML-DSig backend. That is the right split for those tests, but it leaves the one thing that turns all of
it into real security — "a genuine enveloped RSA-SHA256 signature over this exact assertion verifies, and
a tampered or wrong-key one does not" — resting on `signxml_sig_verifier`'s `# pragma: no cover` path.

This file closes that gap with NO stub: it builds a real RSA key + self-signed X.509 cert (the IdP
signing cert), signs a SAML assertion (and, in one case, the enveloping Response) with signxml's
`XMLSigner`, and drives it through the SHIPPED default verifier (`sig_verifier=None` →
`signxml_sig_verifier`). The accept path proves the happy case; the refuse paths prove the signature is
load-bearing — flip one payload byte, or configure a different cert, and the exact same document is
refused. A direct `signxml_sig_verifier` unit test pins the backend's id-extraction contract.

PROVISIONING: `signxml` (+ its `lxml` transitive) is a direct sovereign runtime dependency
(apps/sigil/requirements.txt → infra/supply-chain/sovereign.lock.txt), so the sovereign CI leg installs
it with `--require-hashes` and these tests RUN there. Where it is absent (a lighter leg / a bare
checkout) they `importorskip`-skip, exactly like every other sovereign-lock-only test in this suite.
`cryptography` is likewise a sovereign-lock dep, so the keygen below is always available where signxml is.
"""
from __future__ import annotations

import datetime
import tempfile

import pytest

signxml = pytest.importorskip("signxml")  # sovereign-lock dep; see module docstring
from lxml import etree  # ships with signxml  # noqa: E402
from signxml import XMLSigner  # noqa: E402

from cryptography import x509  # noqa: E402  (sovereign-lock dep)
from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import rsa  # noqa: E402
from cryptography.x509.oid import NameOID  # noqa: E402

from sigil.governor.sso_config import SsoConfig  # noqa: E402
from sigil.ui import saml  # noqa: E402
from sigil.ui.saml import SamlError  # noqa: E402

# NOW sits inside the assertion validity window (the year-2001 epoch test_saml.py also uses).
NOW = 1_000_400_000.0

_SAML = "urn:oasis:names:tc:SAML:2.0:assertion"
_P = "urn:oasis:names:tc:SAML:2.0:protocol"
_SUCCESS = "urn:oasis:names:tc:SAML:2.0:status:Success"


def _make_idp_cert() -> "tuple[bytes, bytes]":
    """A fresh RSA-2048 key + self-signed cert standing in for an IdP's SAML signing certificate.
    Returns (key_pem, cert_pem). Validity 2000-2035 so the year-2001 assertion window is covered."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "idp.example")])
    cert = (x509.CertificateBuilder()
            .subject_name(name).issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime(2000, 1, 1))
            .not_valid_after(datetime.datetime(2035, 1, 1))
            .sign(key, hashes.SHA256()))
    key_pem = key.private_bytes(serialization.Encoding.PEM,
                                serialization.PrivateFormat.TraditionalOpenSSL,
                                serialization.NoEncryption())
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    return key_pem, cert_pem


# One signing identity for the whole module (keygen is the slow part); a SECOND, unrelated cert is
# generated lazily for the wrong-key refusal. Module scope keeps the suite fast without sharing state
# a test could mutate — SsoConfig is rebuilt per call and the documents are immutable bytes.
_KEY_PEM, _CERT_PEM = _make_idp_cert()


def _config(cert_pem: bytes = _CERT_PEM) -> SsoConfig:
    return SsoConfig(org_id="acme", protocol="saml", issued_at=1.0, state="active",
                     idp_entity_id="https://idp.example", idp_certs_pem=(cert_pem.decode(),),
                     sp_entity_id="https://sp.vigil/acme", acs_url="https://app.vigil/acs/acme",
                     clock_skew_seconds=60)


def _unsigned_response(aid: str = "a1", rid: str = "r1", nameid: str = "user@acme",
                       groups: "tuple[str, ...]" = ("admins",)) -> str:
    grp = "".join(f'<saml:AttributeValue>{g}</saml:AttributeValue>' for g in groups)
    assertion = (
        f'<saml:Assertion xmlns:saml="{_SAML}" ID="{aid}">'
        '<saml:Issuer>https://idp.example</saml:Issuer>'
        f'<saml:Subject><saml:NameID>{nameid}</saml:NameID>'
        '<saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">'
        '<saml:SubjectConfirmationData Recipient="https://app.vigil/acs/acme" '
        'NotOnOrAfter="2001-09-14T00:00:00Z"/></saml:SubjectConfirmation></saml:Subject>'
        '<saml:Conditions NotBefore="2001-09-13T00:00:00Z" NotOnOrAfter="2001-09-14T00:00:00Z">'
        '<saml:AudienceRestriction><saml:Audience>https://sp.vigil/acme</saml:Audience>'
        '</saml:AudienceRestriction></saml:Conditions>'
        f'<saml:AttributeStatement><saml:Attribute Name="groups">{grp}</saml:Attribute>'
        '</saml:AttributeStatement></saml:Assertion>')
    return (
        f'<samlp:Response xmlns:samlp="{_P}" ID="{rid}" Destination="https://app.vigil/acs/acme">'
        f'<samlp:Status><samlp:StatusCode Value="{_SUCCESS}"/></samlp:Status>'
        f'{assertion}</samlp:Response>')


def _signer() -> XMLSigner:
    return XMLSigner(method=signxml.methods.enveloped,
                     signature_algorithm="rsa-sha256",
                     digest_algorithm="sha256",
                     c14n_algorithm="http://www.w3.org/2001/10/xml-exc-c14n#")


def _sign_assertion(xml_text: str, key_pem: bytes = _KEY_PEM, cert_pem: bytes = _CERT_PEM,
                    aid: str = "a1") -> bytes:
    """Enveloped-sign the single assertion (by its ID) in place, return the whole Response bytes."""
    resp = etree.fromstring(xml_text.encode())
    assertion = resp.find(f"{{{_SAML}}}Assertion")
    signed = _signer().sign(assertion, key=key_pem, cert=cert_pem, reference_uri=aid)
    resp.replace(assertion, signed)
    return etree.tostring(resp)


def _sign_response_root(xml_text: str, key_pem: bytes = _KEY_PEM, cert_pem: bytes = _CERT_PEM,
                        rid: str = "r1") -> bytes:
    """Enveloped-sign the whole Response (by its ID), return the signed Response bytes."""
    root = etree.fromstring(xml_text.encode())
    signed = _signer().sign(root, key=key_pem, cert=cert_pem, reference_uri=rid)
    return etree.tostring(signed)


def _led() -> "saml.SamlReplayLedger":
    return saml.SamlReplayLedger(tempfile.mktemp())


# --- accept paths (the shipped verifier, NO stub) ---------------------------------------------------

def test_real_signxml_signed_assertion_accepts():
    """A genuine enveloped RSA-SHA256 signature over the assertion verifies through the default backend."""
    signed = _sign_assertion(_unsigned_response())
    idn = saml.verify_saml_response(signed, config=_config(), now=NOW, replay_ledger=_led())
    assert idn.name_id == "user@acme"
    assert idn.assertion_id == "a1"
    assert idn.groups == ("admins",)


def test_real_signxml_signature_over_response_root_accepts():
    """Signing the enveloping Response (one assertion inside ⇒ no wrapping gap) also binds and accepts."""
    signed = _sign_response_root(_unsigned_response())
    idn = saml.verify_saml_response(signed, config=_config(), now=NOW, replay_ledger=_led())
    assert idn.name_id == "user@acme"


# --- refuse paths (the signature is load-bearing) ---------------------------------------------------

def test_real_signxml_tampered_payload_refused():
    """Flip one byte of the signed payload (user@acme → evil@acme): the signature no longer validates."""
    signed = _sign_assertion(_unsigned_response())
    tampered = signed.replace(b"user@acme", b"evil@acme")
    assert tampered != signed
    with pytest.raises(SamlError):
        saml.verify_saml_response(tampered, config=_config(), now=NOW, replay_ledger=_led())


def test_real_signxml_wrong_signing_cert_refused():
    """A document signed by key A, but the org config trusts an unrelated cert B ⇒ no valid signature."""
    signed = _sign_assertion(_unsigned_response())
    _, other_cert = _make_idp_cert()
    with pytest.raises(SamlError):
        saml.verify_saml_response(signed, config=_config(other_cert), now=NOW, replay_ledger=_led())


def test_real_signxml_unsigned_document_refused():
    """With the real backend and no <ds:Signature> at all, nothing is bound ⇒ refused (fail closed)."""
    with pytest.raises(SamlError):
        saml.verify_saml_response(_unsigned_response().encode(), config=_config(), now=NOW,
                                  replay_ledger=_led())


def test_real_signxml_signed_assertion_is_single_use():
    """The real signature accepts once; the same signed bytes are refused on replay (single-use id)."""
    signed = _sign_assertion(_unsigned_response())
    ledger = _led()
    assert saml.verify_saml_response(signed, config=_config(), now=NOW, replay_ledger=ledger).name_id
    with pytest.raises(SamlError):
        saml.verify_saml_response(signed, config=_config(), now=NOW, replay_ledger=ledger)


# --- the backend contract itself --------------------------------------------------------------------

def test_signxml_sig_verifier_returns_the_signed_element_id():
    """`signxml_sig_verifier(xml, (cert,))` returns the frozenset of ids whose signature validly verifies —
    the exact `# pragma: no cover` path the stub tests never reach. Here the signed assertion id is 'a1'."""
    signed = _sign_assertion(_unsigned_response())
    ids = saml.signxml_sig_verifier(signed, (_CERT_PEM.decode(),))
    assert isinstance(ids, frozenset)
    assert "a1" in ids


def test_signxml_sig_verifier_rejects_an_unrelated_cert():
    """The backend contributes NO id for a cert that does not verify the document (⇒ empty set, fail closed)."""
    signed = _sign_assertion(_unsigned_response())
    _, other_cert = _make_idp_cert()
    ids = saml.signxml_sig_verifier(signed, (other_cert.decode(),))
    assert ids == frozenset()
