"""
T4b — the OFFLINE structural-forgery PRODUCERS wired at the live JWT/SAML scanner sites.

``verify.jwt_forgery.confirm_jwt_forgery`` and ``verify.saml_forgery.confirm_saml_forgery`` had complete
confirm/_run plumbing but no pipeline caller fed them a captured token/xml. These tests exercise the two
producers that close that gap — ``scanner.jwt.JwtForgeryCheck`` and ``scanner.sso.SamlForgeryCheck`` — which
re-use the RAW token / SAML XML already in hand at the live-scan site and hand it to the deterministic
forgery oracle. They send ZERO traffic (the injected ``send`` here raises if called), fire ONLY over the
captured bytes, and stay fail-closed on a hardened token/assertion.
"""

from __future__ import annotations

from framework.v2.scanner import jwt, sso
from framework.v2.scanner.campaign import DEFAULT_REQUEST_CHECKS
from framework.v2.scanner.engine import AuditEngine
from framework.v2.scanner.insertion import HttpRequest

# ---------------------------------------------------------------------------
# a send that PROVES zero forged traffic — the forgery oracle judges bytes alone
# ---------------------------------------------------------------------------


def _no_send(_req: HttpRequest) -> dict:
    raise AssertionError("forgery producers must send NO traffic — the oracle judges captured bytes alone")


# ---------------------------------------------------------------------------
# JWT forgery producer (DEFAULT roster)
# ---------------------------------------------------------------------------

_STRONG_SECRET = b"aX9k2Pq7Z_not-in-any-weak-list-4f8e1c6b0d3a55"


def _jwt_req(token: str) -> HttpRequest:
    return HttpRequest(method="GET", url="http://127.0.0.1:9/me",
                       headers=[("Authorization", f"Bearer {token}")])


def test_jwt_forgery_check_is_in_the_default_roster() -> None:
    ids = {getattr(c, "id", None) for c in DEFAULT_REQUEST_CHECKS}
    assert "jwt-forgeable" in ids


def test_alg_none_token_fires_forgery_offline() -> None:
    tok = jwt.encode_none({"typ": "JWT"}, {"sub": "alice"})
    findings = AuditEngine(_no_send).audit(
        _jwt_req(tok), checks=(), request_checks=(jwt.JwtForgeryCheck(),))
    forge = [f for f in findings if f.bug_class == "jwt_forgeable"]
    assert forge, "an alg=none token is structurally forgeable and must be confirmed offline"
    assert forge[0].confirmed_by == "sso_assertion_forgery"
    assert forge[0].oracle_context   # carries a re-verifiable certificate


def test_weak_hmac_secret_token_fires_forgery_offline() -> None:
    tok = jwt.encode_hs256({"typ": "JWT"}, {"sub": "alice"}, b"secret")   # a known-weak secret
    findings = AuditEngine(_no_send).audit(
        _jwt_req(tok), checks=(), request_checks=(jwt.JwtForgeryCheck(),))
    assert [f for f in findings if f.bug_class == "jwt_forgeable"]


def test_strong_hmac_secret_token_does_not_fire() -> None:
    tok = jwt.encode_hs256({"typ": "JWT"}, {"sub": "alice"}, _STRONG_SECRET)
    findings = AuditEngine(_no_send).audit(
        _jwt_req(tok), checks=(), request_checks=(jwt.JwtForgeryCheck(),))
    assert findings == [], "a strongly-signed HS256 token is not recoverable — must not be flagged"


def test_rs256_token_does_not_fire() -> None:
    # a normal asymmetric token: forging it needs the private key, unreachable from the token alone
    seg = lambda o: jwt.b64url_encode(__import__("json").dumps(o).encode())
    tok = f"{seg({'alg': 'RS256'})}.{seg({'sub': 'alice'})}.{jwt.b64url_encode(b'not-a-real-sig')}"
    findings = AuditEngine(_no_send).audit(
        _jwt_req(tok), checks=(), request_checks=(jwt.JwtForgeryCheck(),))
    assert findings == []


def test_request_without_a_jwt_produces_nothing() -> None:
    req = HttpRequest(method="GET", url="http://127.0.0.1:9/x", headers=[])
    findings = AuditEngine(_no_send).audit(req, checks=(), request_checks=(jwt.JwtForgeryCheck(),))
    assert findings == []


# ---------------------------------------------------------------------------
# SAML forgery producer (OPT-IN SSO roster)
# ---------------------------------------------------------------------------

_NS_P = "urn:oasis:names:tc:SAML:2.0:protocol"
_NS_A = "urn:oasis:names:tc:SAML:2.0:assertion"
_NS_D = "http://www.w3.org/2000/09/xmldsig#"


def _assertion(aid: str, nameid: str, *, sig_ref: str | None = None) -> str:
    sig = ""
    if sig_ref is not None:
        sig = (f'<ds:Signature><ds:SignedInfo><ds:Reference URI="#{sig_ref}"></ds:Reference>'
               f"</ds:SignedInfo><ds:SignatureValue>QUFB</ds:SignatureValue></ds:Signature>")
    return (f'<saml:Assertion ID="{aid}"><saml:Subject><saml:NameID>{nameid}</saml:NameID>'
            f"</saml:Subject>{sig}<saml:Conditions/></saml:Assertion>")


def _response(inner: str) -> str:
    return (f'<samlp:Response xmlns:samlp="{_NS_P}" xmlns:saml="{_NS_A}" xmlns:ds="{_NS_D}" '
            f'ID="_r1" Version="2.0"><saml:Issuer>idp</saml:Issuer>{inner}</samlp:Response>')


def _acs_request(xml: str) -> HttpRequest:
    # use the module's own SAML encoder + form placement so extract_form_field/decode_saml round-trip
    return sso.with_form_field(
        HttpRequest(method="POST", url="https://sp.example.test/acs",
                    headers=[("Content-Type", "application/x-www-form-urlencoded")], body=""),
        "SAMLResponse", sso.encode_saml(xml))


def test_saml_forgery_check_is_opt_in_not_default() -> None:
    default_ids = {getattr(c, "id", None) for c in DEFAULT_REQUEST_CHECKS}
    sso_ids = {c.id for c in sso.SSO_REQUEST_CHECKS}
    assert "saml-structural-forgery" in sso_ids
    assert "saml-structural-forgery" not in default_ids   # never runs on the default benchmark


def test_unsigned_assertion_fires_forgery_offline() -> None:
    xml = _response(_assertion("_a1", "alice@corp.test"))   # no ds:Signature anywhere -> forgeable
    findings = AuditEngine(_no_send).audit(
        _acs_request(xml), checks=(), request_checks=(sso.SamlForgeryCheck(),))
    forge = [f for f in findings if f.bug_class == "saml_structural_forgery"]
    assert forge, "an unsigned consumed assertion is structurally forgeable and must confirm offline"
    assert forge[0].confirmed_by == "saml_structural_forgery"
    assert forge[0].oracle_context


def test_properly_signed_assertion_does_not_fire() -> None:
    xml = _response(_assertion("_a1", "alice@corp.test", sig_ref="_a1"))   # Reference covers it
    findings = AuditEngine(_no_send).audit(
        _acs_request(xml), checks=(), request_checks=(sso.SamlForgeryCheck(),))
    assert findings == [], "a properly-signed single assertion is not structurally forgeable"


def test_request_without_a_saml_response_produces_nothing() -> None:
    req = HttpRequest(method="POST", url="https://sp.example.test/acs",
                      headers=[("Content-Type", "application/x-www-form-urlencoded")], body="foo=bar")
    findings = AuditEngine(_no_send).audit(req, checks=(), request_checks=(sso.SamlForgeryCheck(),))
    assert findings == []
