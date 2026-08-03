"""
scanner.sso — SAML / OIDC (SSO) security checks for the operator's OWN integration.

Federated login is its own attack surface, and one CRUCIBLE only *detected* (the
fingerprint layer notes an OIDC discovery doc or a SAML namespace) rather than
*tested*. Detection is not proof: an operator's SAML Service Provider (SP) that
accepts an assertion whose signature does not cover the consumed assertion (an XML
Signature Wrapping bug), or that never validates the signature at all (assertion
tampering), or an OIDC Relying Party (RP) that honours an unsigned/forged
``id_token``, or an authorization endpoint that redirects to an attacker-chosen
``redirect_uri`` — none of these are reachable by parameter fuzzing. They need the
SSO artifact decomposed, forged, and re-submitted, and the *acceptance* observed.

This module does that with **stdlib only**. Confirmation stays honest and follows
the ``jwt``/``graphql`` precedent: a check emits a :class:`FindingContext`; the
deterministic oracle layer — never this code — decides. Where a deterministic
achieved-state signal exists (a forged/tampered assertion ACCEPTED while a
structurally-invalid control is REJECTED; an authorization endpoint redirecting to
the attacker host) the predicate oracle confirms a FACT. Everything softer (a
missing ``state``/``nonce``, an unsigned assertion) is surfaced as a LEAD
(:class:`SsoLead`), never minted into a confirmed finding.

Doctrine (constitution §II, §VI):
  * **Own integration only.** The SAML checks target the operator's ACS; the OIDC
    checks target the operator's authorization/callback endpoints. This module
    never attacks a third-party IdP — and every request rides the injected, gated
    ``send`` (charter / scope / kill-switch / egress), so an off-scope IdP is
    refused before a byte leaves the box.
  * **Correlatable.** Forged identities and canary hosts use fixed, greppable
    ``crucible-*`` / ``*.sso-test.invalid`` markers — the operator finds this
    traffic in their logs; it is not evasion.
  * **Opt-in.** None of these checks are in the default scan roster
    (``DEFAULT_REQUEST_CHECKS``); they run only when a caller passes
    :data:`SSO_REQUEST_CHECKS` (or ``WebScanCampaign(..., enable_sso=True)``), so
    the default benchmark sends zero SSO requests.

Untrusted XML is parsed through :func:`safe_parse_xml`, which is **XXE-safe**: it
rejects any DTD/entity declaration outright (the precondition for every external-
entity and billion-laughs attack) and bounds the input size, so a malicious-entity
document never resolves.
"""

from __future__ import annotations

import base64
import binascii
import copy
import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from ..verify.adapter import FindingContext
from . import jwt as _jwt
from .checks import Send
from .insertion import HttpRequest, RequestTemplate

# SAML / XML-DSig namespaces.
_NS_PROTO = "urn:oasis:names:tc:SAML:2.0:protocol"
_NS_ASSERT = "urn:oasis:names:tc:SAML:2.0:assertion"
_NS_DS = "http://www.w3.org/2000/09/xmldsig#"

# Register canonical prefixes so a re-serialised tree stays readable/stable
# (deterministic global state — set once at import).
ET.register_namespace("samlp", _NS_PROTO)
ET.register_namespace("saml", _NS_ASSERT)
ET.register_namespace("ds", _NS_DS)

# A status a minimally-correct endpoint returns when it REJECTS an artifact. Used
# as the discriminating control set: a finding fires only when a forged/tampered
# artifact is NOT rejected while a structurally-invalid one IS (mirrors the
# jwt.JwtNoneCheck "unsigned accepted AND garbage rejected" precedent).
_REJECTED = [0, 400, 401, 403, 404, 500, 502, 503]


# ---------------------------------------------------------------------------
# XXE-safe, bounded XML parsing
# ---------------------------------------------------------------------------


class XxeBlocked(ValueError):
    """Raised when input XML is refused by the XXE-safe guard (a DTD/entity
    declaration, an oversize document, or an otherwise-unparseable body). The
    refusal is the safety property: the document is never handed to a parser that
    could resolve an external entity or expand an entity bomb."""


# Every XXE / entity-expansion (billion-laughs, quadratic-blowup) attack requires a
# DTD (`<!DOCTYPE`) and/or an entity declaration (`<!ENTITY`). A legitimate SAML
# assertion carries neither, so refusing them outright loses no real coverage and
# is a hard, parser-independent guarantee.
_DOCTYPE_RE = re.compile(rb"<!DOCTYPE", re.IGNORECASE)
_ENTITY_RE = re.compile(rb"<!ENTITY", re.IGNORECASE)

# 5 MiB is far larger than any real SAML message and small enough to bound memory.
_MAX_XML_BYTES = 5 * 1024 * 1024


def _forbid_doctype(*_args: object) -> None:  # expat StartDoctypeDeclHandler
    raise XxeBlocked("DTD declaration forbidden (XXE-safe parse)")


def safe_parse_xml(data: str | bytes, *, max_bytes: int = _MAX_XML_BYTES) -> ET.Element:
    """Parse untrusted XML with XXE and entity-expansion defused.

    Two independent guards, so safety does not rest on one mechanism:
      1. A byte-level pre-scan rejects any ``<!DOCTYPE`` or ``<!ENTITY`` and any
         document over ``max_bytes`` — the necessary precondition for external-
         entity XXE and for entity bombs, blocked before the parser ever runs.
      2. Belt-and-suspenders, the expat parser is told to hard-fail on a DOCTYPE
         via ``StartDoctypeDeclHandler``, and (as always in ElementTree) external
         general entities are not resolved.

    Returns the parsed root :class:`~xml.etree.ElementTree.Element`. Raises
    :class:`XxeBlocked` if the document is oversize, declares a DTD/entity, or is
    otherwise unparseable — a malicious-entity document therefore never resolves."""
    raw = data.encode("utf-8") if isinstance(data, str) else bytes(data)
    if len(raw) > max_bytes:
        raise XxeBlocked(f"XML exceeds {max_bytes}-byte bound ({len(raw)} bytes)")
    if _DOCTYPE_RE.search(raw) or _ENTITY_RE.search(raw):
        raise XxeBlocked("DTD/ENTITY declaration rejected (XXE-safe parse)")
    parser = ET.XMLParser()
    # Hardening: hard-fail on a DTD even if one slipped past the byte scan. The
    # attribute path is a CPython implementation detail, so guard it — the
    # pre-scan is the primary, portable guarantee.
    try:  # pragma: no branch - defensive
        parser.parser.StartDoctypeDeclHandler = _forbid_doctype  # type: ignore[attr-defined]
    except AttributeError:  # pragma: no cover - non-expat backend
        pass
    try:
        return ET.fromstring(raw, parser=parser)
    except XxeBlocked:
        raise
    except ET.ParseError as exc:
        raise XxeBlocked(f"unparseable/unsafe XML: {exc}") from exc


# ---------------------------------------------------------------------------
# SAML message codec + tree helpers (pure, deterministic — no traffic)
# ---------------------------------------------------------------------------


def decode_saml(value: str) -> str | None:
    """Base64-decode a SAML POST-binding ``SAMLResponse``/``SAMLRequest`` field to
    its XML text, or None if it is not valid base64 / not UTF-8-ish. (POST binding
    uses standard base64, which may contain whitespace/newlines.)"""
    try:
        return base64.b64decode(value.strip(), validate=False).decode("utf-8", "replace")
    except (binascii.Error, ValueError):
        return None


def encode_saml(xml_text: str) -> str:
    """Base64-encode SAML XML for a POST-binding form field."""
    return base64.b64encode(xml_text.encode("utf-8")).decode("ascii")


def _serialize(root: ET.Element) -> str:
    return ET.tostring(root, encoding="unicode")


def _parent_map(root: ET.Element) -> dict[ET.Element, ET.Element]:
    return {child: parent for parent in root.iter() for child in parent}


def saml_nameid(root: ET.Element) -> str | None:
    """The first ``saml:NameID`` text in the tree (the asserted identity), or None."""
    for el in root.iter(f"{{{_NS_ASSERT}}}NameID"):
        if el.text:
            return el.text
    return None


def _strip_signatures(element: ET.Element) -> None:
    """Remove every ``ds:Signature`` under ``element`` (used to leave a forged
    assertion unsigned)."""
    pmap = _parent_map(element)
    for sig in list(element.iter(f"{{{_NS_DS}}}Signature")):
        parent = pmap.get(sig)
        if parent is not None:
            parent.remove(sig)


def tamper_assertion(xml_text: str, new_nameid: str) -> str:
    """Return the SAML XML with every ``NameID`` rewritten to ``new_nameid`` and the
    signature LEFT UNCHANGED (so it no longer matches the content). Submitting this
    tests whether the SP validates the signature at all: a correct SP rejects it
    (signature mismatch); a broken SP honours the forged identity."""
    root = safe_parse_xml(xml_text)
    changed = False
    for el in root.iter(f"{{{_NS_ASSERT}}}NameID"):
        el.text = new_nameid
        changed = True
    if not changed:
        raise ValueError("no saml:NameID present to tamper")
    return _serialize(root)


def wrap_assertion_xsw(xml_text: str, new_nameid: str) -> str:
    """Return an XML-Signature-Wrapping (XSW) variant of the SAML message.

    The original signed assertion is kept verbatim (so a naive signature check over
    it still passes) and an UNSIGNED forged copy — new ``ID``, attacker ``NameID``,
    no ``Signature`` — is inserted *before* it. An SP that verifies the first valid
    signature it finds but then consumes the first ``Assertion`` element processes
    the attacker's identity: the canonical XSW class. A hardened SP (which requires
    the signature to cover the assertion it consumes) rejects it, so this does not
    false-positive on a correctly-configured SP."""
    root = safe_parse_xml(xml_text)
    assertions = list(root.iter(f"{{{_NS_ASSERT}}}Assertion"))
    if not assertions:
        raise ValueError("no saml:Assertion present to wrap")
    original = assertions[0]
    pmap = _parent_map(root)
    parent = pmap.get(original)
    if parent is None:
        raise ValueError("assertion has no parent element to wrap within")
    index = list(parent).index(original)

    forged = copy.deepcopy(original)
    forged.set("ID", "_crucible_xsw_forged")
    _strip_signatures(forged)
    for nid in forged.iter(f"{{{_NS_ASSERT}}}NameID"):
        nid.text = new_nameid
    # Insert the forged, unsigned assertion ahead of the original signed one.
    parent.insert(index, forged)
    return _serialize(root)


# ---------------------------------------------------------------------------
# Request field helpers (form + query), and a JWT-in-a-field placer
# ---------------------------------------------------------------------------


def extract_form_field(req: HttpRequest, name: str) -> str | None:
    """The value of urlencoded body field ``name`` (falling back to the query
    string), or None. Used to pull ``SAMLResponse`` / ``id_token`` out of a request."""
    for k, v in parse_qsl(req.body or "", keep_blank_values=True):
        if k == name:
            return v
    for k, v in parse_qsl(urlsplit(req.url).query, keep_blank_values=True):
        if k == name:
            return v
    return None


def with_form_field(req: HttpRequest, name: str, value: str) -> HttpRequest:
    """Return a copy of ``req`` with urlencoded body field ``name`` set to ``value``
    (appended if absent), and a corrected ``Content-Length``."""
    pairs = parse_qsl(req.body or "", keep_blank_values=True)
    out: list[tuple[str, str]] = []
    replaced = False
    for k, v in pairs:
        if k == name:
            out.append((k, value))
            replaced = True
        else:
            out.append((k, v))
    if not replaced:
        out.append((name, value))
    new_body = urlencode(out)
    headers = [(k, v) for k, v in req.headers if k.lower() != "content-length"]
    headers.append(("Content-Length", str(len(new_body.encode("utf-8")))))
    return req.model_copy(update={"body": new_body, "headers": headers})


def with_query_param(req: HttpRequest, name: str, value: str) -> HttpRequest:
    """Return a copy of ``req`` with URL query parameter ``name`` set to ``value``."""
    sp = urlsplit(req.url)
    pairs = parse_qsl(sp.query, keep_blank_values=True)
    out: list[tuple[str, str]] = []
    replaced = False
    for k, v in pairs:
        if k == name:
            out.append((k, value))
            replaced = True
        else:
            out.append((k, v))
    if not replaced:
        out.append((name, value))
    new_url = urlunsplit((sp.scheme, sp.netloc, sp.path, urlencode(out), sp.fragment))
    return req.model_copy(update={"url": new_url})


def _param_present(req: HttpRequest, name: str) -> str | None:
    """The value of ``name`` in the query or the urlencoded body, or None."""
    q = dict(parse_qsl(urlsplit(req.url).query, keep_blank_values=True))
    if name in q:
        return q[name]
    b = dict(parse_qsl(req.body or "", keep_blank_values=True))
    return b.get(name)


def _replace_param(req: HttpRequest, name: str, value: str) -> HttpRequest:
    """Replace ``name`` wherever it currently lives (query or body); default to the
    query if it is present in neither."""
    if name in dict(parse_qsl(urlsplit(req.url).query, keep_blank_values=True)):
        return with_query_param(req, name, value)
    if req.body and name in dict(parse_qsl(req.body, keep_blank_values=True)):
        return with_form_field(req, name, value)
    return with_query_param(req, name, value)


def _extract_jwt(req: HttpRequest, location: str) -> str | None:
    """Pull a JWT from ``location``: ``header:<Name>`` (an ``authorization`` header
    strips a ``Bearer`` prefix) or a urlencoded field name."""
    if location.startswith("header:"):
        header = location.split(":", 1)[1]
        value = req.header(header) or ""
        if value.lower().startswith("bearer "):
            value = value[7:].strip()
        return value if _jwt._looks_like_jwt(value) else None
    value = extract_form_field(req, location) or ""
    return value if _jwt._looks_like_jwt(value) else None


def _place_jwt(req: HttpRequest, location: str, token: str) -> HttpRequest:
    """Place ``token`` at ``location`` (mirror of :func:`_extract_jwt`)."""
    if location.startswith("header:"):
        header = location.split(":", 1)[1]
        prefix = "Bearer " if header.lower() == "authorization" else ""
        headers = [(k, v) for k, v in req.headers if k.lower() != header.lower()]
        headers.append((header, f"{prefix}{token}"))
        return req.model_copy(update={"headers": headers})
    return with_form_field(req, location, token)


# ---------------------------------------------------------------------------
# Response accessors
# ---------------------------------------------------------------------------


def _status(resp: object) -> int:
    return int(resp.get("status", 0)) if isinstance(resp, dict) else 0


def _body(resp: object) -> str:
    return str(resp.get("body", "")) if isinstance(resp, dict) else str(resp)


def _location(resp: object) -> str:
    if not isinstance(resp, dict):
        return ""
    for k, v in resp.get("headers", []) or []:
        if str(k).lower() == "location":
            return str(v)
    return ""


def _host(url: str) -> str:
    return urlsplit(url).netloc.lower()


# ---------------------------------------------------------------------------
# LEADs — config observations, never oracle-confirmed
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class SsoLead:
    """A soft SSO observation (an unsigned assertion, a missing ``state``/``nonce``,
    an implicit flow). A LEAD, never a confirmed finding — it records a
    configuration weakness, not an oracle-proven exploit. Kept strictly separate
    from ``AuditFinding`` so prove-don't-guess is not diluted."""

    kind: str
    detail: str
    severity: str = "info"


def analyze_authorize_request(url: str) -> list[SsoLead]:
    """Config LEADs from an OIDC/OAuth authorization request URL: a missing
    ``state`` (CSRF / login-CSRF), a missing ``nonce`` on a flow that returns an
    ``id_token`` (replay), and any front-channel token exposure (implicit flow).
    Pure; sends nothing. These are leads because none is an oracle-provable fact on
    its own."""
    q = dict(parse_qsl(urlsplit(url).query, keep_blank_values=True))
    if not ({"response_type", "client_id", "scope"} & set(q)):
        return []  # not obviously an authorize request
    response_type = q.get("response_type", "")
    tokens_in_type = set(response_type.replace("+", " ").split())
    leads: list[SsoLead] = []
    if not q.get("state"):
        leads.append(SsoLead(
            "oidc_missing_state",
            "authorization request omits 'state' — no CSRF / login-CSRF protection",
            "medium"))
    if "id_token" in tokens_in_type and not q.get("nonce"):
        leads.append(SsoLead(
            "oidc_missing_nonce",
            "implicit/hybrid flow returns an id_token but omits 'nonce' — replay risk",
            "medium"))
    if "token" in tokens_in_type or "id_token" in tokens_in_type:
        leads.append(SsoLead(
            "oidc_front_channel_tokens",
            f"response_type={response_type!r} exposes tokens in the front channel "
            "(implicit flow) — prefer the authorization-code flow with PKCE",
            "low"))
    return leads


def analyze_saml_response(xml_text: str) -> list[SsoLead]:
    """Config LEADs from a decoded SAML Response: an entirely unsigned message, and
    an assertion with no ``Conditions``/``NotOnOrAfter`` window (no expiry / replay
    bound). XXE-safe parsing; a malicious-entity document yields no leads (it is
    refused). Pure; sends nothing."""
    try:
        root = safe_parse_xml(xml_text)
    except XxeBlocked:
        return []
    leads: list[SsoLead] = []
    if not any(True for _ in root.iter(f"{{{_NS_DS}}}Signature")):
        leads.append(SsoLead(
            "saml_unsigned",
            "SAML message carries no ds:Signature — the SP cannot verify integrity",
            "high"))
    has_assertion = any(True for _ in root.iter(f"{{{_NS_ASSERT}}}Assertion"))
    has_conditions = any(True for _ in root.iter(f"{{{_NS_ASSERT}}}Conditions"))
    if has_assertion and not has_conditions:
        leads.append(SsoLead(
            "saml_no_conditions",
            "assertion has no <Conditions> (no NotOnOrAfter/Audience) — no expiry or "
            "audience binding",
            "medium"))
    return leads


# ---------------------------------------------------------------------------
# Checks — request-level (RequestCheck protocol: probe(template, send))
# ---------------------------------------------------------------------------

# A structurally-valid SAML Response that carries NO assertion — the discriminating
# control every SP must reject (nothing to authenticate). Its rejection is what
# distinguishes a signature-ignoring SP from one that "accepts everything".
_CONTROL_SAML = (
    f'<samlp:Response xmlns:samlp="{_NS_PROTO}" xmlns:saml="{_NS_ASSERT}" '
    'ID="_crucible_control" Version="2.0">'
    "<saml:Issuer>crucible-control</saml:Issuer>"
    '<samlp:Status><samlp:StatusCode '
    'Value="urn:oasis:names:tc:SAML:2.0:status:Requester"/></samlp:Status>'
    "</samlp:Response>"
)

_ATTACKER_NAMEID = "crucible-attacker@sso-test.invalid"


@dataclass(frozen=True)
class SamlAssertionTamperingCheck:
    """Confirm the SP does not validate the assertion signature: rewrite the
    ``NameID`` to a UNIQUE attacker marker WITHOUT re-signing, submit it, and (as a
    control) submit an assertion-less SAML Response every SP must reject. Vulnerable
    iff the SP granted the attacker identity — the forged marker is reflected into a
    NON-rejection response AND the control is rejected. A status-only signal is
    insufficient (a hardened SP that still accepts a message as the LEGIT identity
    would false-positive); requiring the *forged marker* in the response anchors the
    proof to the attacker identity actually being honoured. A correct SP rejects the
    tampered message (signature mismatch), so it does not fire."""

    id: str = "saml-assertion-tampering"
    bug_class: str = "saml_assertion_tampering"
    field_name: str = "SAMLResponse"
    forged_nameid: str = _ATTACKER_NAMEID

    def probe(self, template: RequestTemplate, send: Send) -> FindingContext | None:
        req = template.request
        raw = extract_form_field(req, self.field_name)
        if not raw:
            return None
        xml_text = decode_saml(raw)
        if not xml_text:
            return None
        try:
            tampered = tamper_assertion(xml_text, self.forged_nameid)
        except (XxeBlocked, ValueError, ET.ParseError):
            return None

        forged_resp = send(with_form_field(req, self.field_name, encode_saml(tampered)))
        control_resp = send(with_form_field(req, self.field_name, encode_saml(_CONTROL_SAML)))
        # The ORACLE decides: the forged attacker marker was reflected into a
        # non-rejection response (the SP honoured the forged identity) while the
        # assertion-less control was rejected (so the SP is not accepting anything).
        return FindingContext.from_predicate(
            {"forged_status": _status(forged_resp), "forged_body": _body(forged_resp),
             "control_status": _status(control_resp), "forged_nameid": self.forged_nameid,
             "rejected": _REJECTED},
            {"all": [
                {"contains": [{"var": "forged_body"}, {"var": "forged_nameid"}]},
                {"not": {"in": [{"var": "forged_status"}, {"var": "rejected"}]}},
                {"in": [{"var": "control_status"}, {"var": "rejected"}]},
            ]},
            bug_class=self.bug_class)


@dataclass(frozen=True)
class SamlSignatureWrappingCheck:
    """Confirm an XML Signature Wrapping (XSW) bug: submit an XSW variant (an
    unsigned forged assertion carrying a UNIQUE attacker marker inserted ahead of
    the original signed one) and, as a control, an assertion-less Response.
    Vulnerable iff the SP verified the original signature but consumed the forged
    assertion — the attacker marker is reflected into a NON-rejection response AND
    the control is rejected. Requiring the *forged marker* (not just a 2xx/3xx) is
    what separates a genuine XSW from a hardened SP that accepts the message as the
    LEGIT signed identity (which must NOT be flagged). A hardened SP (signature must
    cover the consumed assertion) rejects the XSW message outright, so it does not
    fire either way."""

    id: str = "saml-signature-wrapping"
    bug_class: str = "saml_signature_wrapping"
    field_name: str = "SAMLResponse"
    forged_nameid: str = _ATTACKER_NAMEID

    def probe(self, template: RequestTemplate, send: Send) -> FindingContext | None:
        req = template.request
        raw = extract_form_field(req, self.field_name)
        if not raw:
            return None
        xml_text = decode_saml(raw)
        if not xml_text:
            return None
        try:
            wrapped = wrap_assertion_xsw(xml_text, self.forged_nameid)
        except (XxeBlocked, ValueError, ET.ParseError):
            return None

        xsw_resp = send(with_form_field(req, self.field_name, encode_saml(wrapped)))
        control_resp = send(with_form_field(req, self.field_name, encode_saml(_CONTROL_SAML)))
        return FindingContext.from_predicate(
            {"xsw_status": _status(xsw_resp), "xsw_body": _body(xsw_resp),
             "control_status": _status(control_resp), "forged_nameid": self.forged_nameid,
             "rejected": _REJECTED},
            {"all": [
                {"contains": [{"var": "xsw_body"}, {"var": "forged_nameid"}]},
                {"not": {"in": [{"var": "xsw_status"}, {"var": "rejected"}]}},
                {"in": [{"var": "control_status"}, {"var": "rejected"}]},
            ]},
            bug_class=self.bug_class)


@dataclass(frozen=True)
class OidcRedirectUriCheck:
    """Confirm broken ``redirect_uri`` validation at the operator's authorization
    endpoint: substitute an attacker-controlled ``redirect_uri`` and confirm via
    achieved-state ONLY when the endpoint actually redirects to the attacker host
    (a 30x ``Location`` to it, or a meta/JS redirect resolving to it) — which leaks
    the authorization code / token. An endpoint that rejects the unregistered URI,
    or keeps the redirect on its own host, does NOT fire. Runs through the gated
    ``send``, so an off-scope IdP is refused before any traffic."""

    id: str = "oidc-redirect-uri"
    bug_class: str = "oidc_redirect_uri"
    param: str = "redirect_uri"
    canary: str = "https://crucible-oidc-attacker.test/callback"

    def probe(self, template: RequestTemplate, send: Send) -> FindingContext | None:
        req = template.request
        if _param_present(req, self.param) is None:
            return None
        resp = send(_replace_param(req, self.param, self.canary))
        if not isinstance(resp, dict):
            return None
        return FindingContext.from_predicate(
            {"status": _status(resp), "location_host": _host(_location(resp)),
             "canary_host": _host(self.canary), "body": _body(resp)},
            {"any": [
                {"all": [
                    {"in": [{"var": "status"}, [301, 302, 303, 307, 308]]},
                    {"eq": [{"var": "location_host"}, {"var": "canary_host"}]},
                ]},
                {"all": [
                    {"min_len": [{"var": "canary_host"}, 1]},
                    {"contains": [{"var": "body"}, {"var": "canary_host"}]},
                    {"any": [
                        {"icontains": [{"var": "body"}, "http-equiv"]},
                        {"icontains": [{"var": "body"}, "location.href"]},
                        {"icontains": [{"var": "body"}, "location.replace"]},
                    ]},
                ]},
            ]},
            bug_class=self.bug_class)


@dataclass(frozen=True)
class OidcIdTokenCheck:
    """Confirm the operator's RP honours a forged ``id_token``: forge a well-formed
    UNSIGNED (``alg:none``) copy of the request's ``id_token`` carrying an attacker
    ``sub``/``email``, submit it, and (as a control) submit a structurally-invalid
    token. Vulnerable iff the forged token is ACCEPTED while the garbage token is
    REJECTED — the RP specifically trusts an unsigned/forged id_token, not that it
    ignores auth entirely. Reuses the stdlib ``jwt`` codec; a correct RP (which
    verifies the IdP signature) rejects the forged token, so it does not fire."""

    id: str = "oidc-idtoken-forgery"
    bug_class: str = "oidc_idtoken_forgery"
    location: str = "id_token"  # a urlencoded field name, or "header:<Name>"
    forged_sub: str = "crucible-attacker"

    def probe(self, template: RequestTemplate, send: Send) -> FindingContext | None:
        req = template.request
        token = _extract_jwt(req, self.location)
        if token is None:
            return None
        try:
            header, payload, _ = _jwt.decode(token)
        except Exception:
            return None
        forged_payload = {**payload, "sub": self.forged_sub,
                          "email": _ATTACKER_NAMEID}
        forged = _jwt.encode_none(header, forged_payload)

        forged_resp = send(_place_jwt(req, self.location, forged))
        garbage_resp = send(_place_jwt(req, self.location, "aaa.bbb.ccc"))
        return FindingContext.from_predicate(
            {"forged_status": _status(forged_resp), "garbage_status": _status(garbage_resp),
             "rejected": _REJECTED},
            {"all": [
                {"not": {"in": [{"var": "forged_status"}, {"var": "rejected"}]}},
                {"in": [{"var": "garbage_status"}, {"var": "rejected"}]},
            ]},
            bug_class=self.bug_class)


@dataclass(frozen=True)
class SamlForgeryCheck:
    """The OFFLINE, ZERO-TRAFFIC structural complement to the LIVE XSW/tampering checks: judge the
    CAPTURED ``SAMLResponse`` XML *itself* for structural forgeability, sending NOTHING. A captured SAML
    Response the request already carries is decoded and handed to the deterministic ``saml_forgery_oracle``
    (via ``FindingContext.from_saml_structure``), which fires ONLY on a coarse, c14n-free STRUCTURAL
    invariant a validly signed assertion cannot exhibit — an UNSIGNED consumed assertion, a
    ds:Reference/@URI that does not cover the consumed element, or the signature-wrapping shape (the dual of
    :func:`wrap_assertion_xsw`). A properly signed single assertion whose Reference covers it, a doc with no
    consumed NameID, and malformed/XXE-refused XML do NOT fire (near-zero-FP).

    This is the missing PRODUCER for ``verify.saml_forgery.confirm_saml_forgery`` — the plumbing existed but
    no pipeline caller fed it a captured assertion. It re-uses the RAW SAMLResponse ALREADY in hand at this
    site (``extract_form_field`` -> ``decode_saml``), so it needs no re-fetch and no LLM extraction: the
    oracle judges the captured bytes ALONE, offline, fail-closed. Opt-in (SSO roster), so it never runs on
    the default benchmark. Complementary to — never a replacement for — the LIVE acceptance checks: those
    prove the SP ACCEPTED a forged assertion; this proves the captured assertion is itself FORGEABLE."""

    id: str = "saml-structural-forgery"
    bug_class: str = "saml_structural_forgery"
    field_name: str = "SAMLResponse"

    def probe(self, template: RequestTemplate, send: Send) -> FindingContext | None:
        req = template.request
        raw = extract_form_field(req, self.field_name)
        if not raw:
            return None
        xml_text = decode_saml(raw)
        if not xml_text:
            return None
        # No traffic: the oracle judges the CAPTURED XML alone (XXE-safe parse, fail-closed).
        return FindingContext.from_saml_structure(xml_text, bug_class=self.bug_class)


# The opt-in SSO arsenal. NOT part of DEFAULT_REQUEST_CHECKS — a caller enables it
# explicitly (request_checks=... + SSO_REQUEST_CHECKS, or WebScanCampaign(enable_sso=True)),
# so the default scan roster and the benchmark are byte-for-byte unchanged. Every
# check returns None (sending nothing) on a request that carries no SSO artifact.
SSO_REQUEST_CHECKS: tuple[object, ...] = (
    SamlSignatureWrappingCheck(),
    SamlAssertionTamperingCheck(),
    SamlForgeryCheck(),
    OidcRedirectUriCheck(),
    OidcIdTokenCheck(),
)
