"""
Wave 3.4 — SSO forgery-ACCEPTANCE achieved-state duals (scanner.forgery_acceptance), ROUND 6.

ROOT CAUSE six rounds proved: an achieved authenticated/accepted state CANNOT be proven from response CONTENT.
Round 5 gated the grant-differential on a difflib same-shape SIMILARITY SCORE (>= 0.5); the sixth variant
defeats it — a benign NON-granting app that renders an identity-echoing soft-200 in the site shell scores
~0.95 similar to its own deny control yet is not a grant, minting a durable/offline false FACT.

THE SOUND REDUCTION round-6 ships (reusing the Wave-3.1 IDOR/BOLA differential that PASSED review): prove the
achieved state ONLY by an ACHIEVED READ OF A VICTIM-PRIVATE DATUM D. The FORGED token confirms acceptance ONLY
when a genuine operator-supplied victim-PRIVATE discriminator D is (a) PRESENT in the forged-token read AND
(b) PRESENT in a legit-VALID-token POSITIVE reference AND (c) ABSENT from a SUBSTANTIVE SAME-SHAPE invalid-token
NEGATIVE control (a substantive 2xx rendering the same resource — a denial/empty/error/different-shape is
REFUSED) AND (d) D is a valid, non-reflected discriminator. The difflib similarity SCORE is DROPPED as the
proof (kept only as a weak advisory); same-shape-ness is established SOUNDLY by the negative control being a
substantive-2xx rendering of the SAME replayed resource, exactly as Wave-3.1's substantive-2xx peer control.

WHY IT IS SOUND. D must be SERVER-SIDE victim-private content that is ABSENT from the forged token. Chrome the
operator might mistake for private content is rendered on the substantive same-shape control too, so its
absence-in-control (clause c) fails.

THE ROUND-6 BLOCK (clause d, forged-token-claim guard). Clause (a) alone is NOT enough: a benign app that REJECTS
the forge can still ECHO a value it DECODED FROM THE FORGED TOKEN — a JWT ``email``/``name`` claim, a SAML ``mail``
attribute — on its (non-granting) reject page. That echo is REFLECTION of attacker-controlled token data (the
attacker owns the ``alg:none`` / NameID-tampered unsigned token), NOT a leak of server-side private content, yet it
would satisfy clause (a) with D present in the forged read, clause (b) in a positive reference for the same real
identity, and clause (c) absent from a control that does not echo it — minting a FALSE ``achieved_state`` on
jwt/oidc/saml (``D=email`` is the canonical example). The fix parses the forged JWT payload / SAML assertion the
runner minted and REFUSES any D present in / derivable from its own decoded claim values (combined with the
pre-existing request-reflection guard, and re-derived in the predicate AST so an offline re-verify refuses a
token-claim-echo certificate). What survives is a SERVER-SIDE, token-ABSENT private datum a benign app cannot
supply. The class stays a rigorous LEAD (``fact_capable:false``); the sound forge-as-real-victim server-side-
private-read design is the ``blocking_work``.

HONEST OUTCOME (a LEAD-downgrade). A bad-signature control auto-derived from the legit token is NOT guaranteed
to be a substantive same-shape deny — a correct app rejects it with a terse 401 — so for the wired input the
class DOWNGRADES to a LEAD (fact_capable:false + blocking_work). The genuinely-sound sub-case (a substantive
same-shape control lacking a genuine private D) still mints the FACT; the offline jwt_forgeable /
saml_structural_forgery FACT is INDEPENDENT and unaffected.

The BENCHMARK for this opt-in, gated-workflow class lives here as deterministic injected-``send`` fixtures
(this class mints nothing on the default GET corpus, so the ``make gate`` is byte-identical). The apps model:

  * a FACT app that GRANTS the forge access to the victim-PRIVATE datum AND answers the bad-signature control
    with a SUBSTANTIVE SAME-SHAPE deny that lacks that datum ⇒ with a genuine private D the oracle mints a FACT;
  * the SIXTH-VARIANT benign app: a NON-granting app whose forge and control are both substantive soft-200s in
    the site shell (HIGH shape-similarity) but carry NO private D ⇒ MUST NOT fire (the score is now advisory);
  * a benign app whose forge/control render the same chrome shell, probed with CHROME markers ⇒ MUST NOT fire
    (chrome is present in the substantive control, so it is not access-gated);
  * twin (a) — a 200 "Login failed … Access denied." page that lacks the private datum ⇒ MUST NOT fire;
  * twin (b) — an app that GRANTS the datum to EVERYTHING incl. the control (D present in control) ⇒ MUST NOT fire;
  * twin (c) — a hardened app that verifies the signature and REJECTS the forgery ⇒ MUST NOT fire;
  * a GENUINELY vulnerable app whose bad-signature control is a TERSE 401 (not a substantive same-shape read) ⇒
    a LEAD, not a FACT (the honest downgrade).

Plus: no minted context (LEAD) without the private-datum baseline OR without the positive reference; the
offline re-verify re-fires the retained predicate and every tamper is rejected; the forged marker is a FRESH
per-probe random nonce (FIX #2); the reflected nonce is excised (FIX #3); the embedded-key path is never taken
(refusal #7); the classes route to ACHIEVED_STATE and are NOT in the default roster; and the INDEPENDENT
offline jwt_forgeable / saml_structural_forgery FACTs still mint.
"""

from __future__ import annotations

import base64
from urllib.parse import urlencode

from framework.v2.scanner import forgery_acceptance as fa
from framework.v2.scanner import jwt as _jwt
from framework.v2.scanner import sso as _sso
from framework.v2.scanner.campaign import DEFAULT_REQUEST_CHECKS
from framework.v2.scanner.engine import AuditEngine
from framework.v2.scanner.insertion import HttpRequest, RequestTemplate
from framework.v2.verify.models import OracleKind
from framework.v2.verify.reverify import reverify_context
from framework.v2.verify.verifier import (
    BUG_CLASS_ORACLES,
    OracleVerifier,
    is_known_bug_class,
    normalize_bug_class,
)

_SECRET = b"server-strong-secret-not-weak-xyz"

# The operator-supplied victim-PRIVATE datum D: an account number the authenticated resource renders ONLY on a
# genuine grant — not chrome, not reflected from the request. This is what a SOUND acceptance FACT rests on.
_PRIVATE = ("acct-88213-7741",)
# Shared-nav CHROME (NOT private): present on many pages incl. the same-shape deny. Must NEVER mint a FACT.
_CHROME = ("Dashboard", "Sign out")

_NS_P = "urn:oasis:names:tc:SAML:2.0:protocol"
_NS_A = "urn:oasis:names:tc:SAML:2.0:assertion"
_NS_D = "http://www.w3.org/2000/09/xmldsig#"
# A signed SAML Response. The SignatureValue stands in for the content the signature commits to: a hardened SP
# grants only when the consumed NameID equals it, and a realistic NameID-tamper-vulnerable SP grants when the
# SignatureValue is a valid signature (== the signed value) regardless of the consumed NameID.
_SIGNED_SAML = (
    f'<samlp:Response xmlns:samlp="{_NS_P}" xmlns:saml="{_NS_A}" xmlns:ds="{_NS_D}" ID="R1" Version="2.0">'
    "<saml:Issuer>https://idp.example.test</saml:Issuer>"
    '<samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>'
    '<saml:Assertion ID="A1" Version="2.0">'
    "<ds:Signature><ds:SignatureValue>alice@example.test</ds:SignatureValue></ds:Signature>"
    "<saml:Subject><saml:NameID>alice@example.test</saml:NameID></saml:Subject>"
    '<saml:Conditions NotOnOrAfter="2035-01-01T00:00:00Z"/>'
    "</saml:Assertion></samlp:Response>"
)
_SIGNED_SAML_B64 = base64.b64encode(_SIGNED_SAML.encode()).decode()


def _grant(sub: str) -> str:
    # The authenticated PRIVATE resource: the site shell (chrome) PLUS the victim-private datum D.
    return (f"<h1>Dashboard</h1><p>Welcome back {sub}. Your private account acct-88213-7741 "
            f"balance is ready to review.</p><nav><a href='/logout'>Sign out</a></nav>")


def _sameshape_deny() -> str:
    # A SUBSTANTIVE SAME-SHAPE deny: the SAME site shell as ``_grant`` (chrome "Dashboard" + "Sign out")
    # rendered on a DENY — but it does NOT carry the victim-private datum. Substantive (2xx, no bare-error
    # phrase). This is the reference a SOUND acceptance FACT needs; chrome present here is disqualified, only a
    # genuine private D survives.
    return ("<h1>Dashboard</h1><p>Your session has expired. Head to the entry page to review your account."
            "</p><nav><a href='/logout'>Sign out</a></nav>")


def _identity_echo_shell(sub: str) -> str:
    # SIXTH-VARIANT forge/deny body: an identity-echoing SOFT-200 in the site shell (chrome). NOT authenticated
    # — it echoes the (attacker) identity and renders chrome but carries NO victim-private datum.
    return (f"<h1>Dashboard</h1><p>Hello guest {sub}. Head to the entry page to review your account."
            f"</p><nav><a href='/logout'>Sign out</a></nav>")


def _softdeny_with_nav() -> str:
    # A benign SOFT-200 in the site shell: chrome, no private datum, no denylisted phrase.
    return ("<h1>Dashboard</h1><p>We could not complete your request. Head to the entry page.</p>"
            "<nav><a href='/logout'>Sign out</a></nav>")


def _legit_jwt() -> str:
    return _jwt.encode_hs256({"typ": "JWT"}, {"sub": "alice"}, _SECRET)


def _jwt_req() -> HttpRequest:
    return HttpRequest(method="GET", url="http://127.0.0.1:9/me",
                       headers=[("Authorization", f"Bearer {_legit_jwt()}")])


def _oidc_req() -> HttpRequest:
    return HttpRequest(method="POST", url="http://127.0.0.1:9/callback",
                       headers=[("Content-Type", "application/x-www-form-urlencoded")],
                       body=f"id_token={_legit_jwt()}&state=x")


def _saml_req() -> HttpRequest:
    return HttpRequest(method="POST", url="http://127.0.0.1:9/acs",
                       headers=[("Content-Type", "application/x-www-form-urlencoded")],
                       body=urlencode({"SAMLResponse": _SIGNED_SAML_B64}))


def _jwt_check(**kw):
    return fa.JwtForgeryAcceptanceCheck(success_markers=kw.pop("markers", _PRIVATE),
                                        legit_token=kw.pop("legit", _legit_jwt()), **kw)


def _oidc_check(**kw):
    return fa.OidcForgeryAcceptanceCheck(success_markers=kw.pop("markers", _PRIVATE),
                                         legit_token=kw.pop("legit", _legit_jwt()), **kw)


def _saml_check(**kw):
    return fa.SamlForgeryAcceptanceCheck(success_markers=kw.pop("markers", _PRIVATE),
                                         legit_saml=kw.pop("legit", _SIGNED_SAML_B64), **kw)


# ---------------------------------------------------------------------------
# JWT/OIDC app fixtures — read the token the check placed, branch on it
# ---------------------------------------------------------------------------


def _jwt_token_of(req: HttpRequest, location: str) -> "str | None":
    if location == "authorization":
        return _jwt.extract_token(req, location)
    return _sso._extract_jwt(req, location)


def _decoded_alg_and_sub(token: "str | None") -> "tuple[str | None, str]":
    if token is None:
        return None, ""
    try:
        header, payload, _ = _jwt.decode(token)
    except Exception:
        return None, ""
    return str(header.get("alg", "")), str(payload.get("sub", ""))


def _jwt_fact_app(location: str):
    """The alg:none-confusion RP whose deny view is a SUBSTANTIVE SAME-SHAPE page (round-6): it VERIFIES the
    HMAC signature for a signed token but TRUSTS an ``alg:none`` token without a signature (the vuln), leaking
    the victim-PRIVATE datum into the response. A legit signed token grants (renders D); the forged alg:none
    grants (renders D — the achieved private read); a well-formed bad-signature control is DENIED with the app's
    own same-shell deny view (``_sameshape_deny`` — chrome present, private datum absent), so the private D is
    the access-gated discriminator ⇒ a SOUND acceptance FACT. (An app whose bad-signature control is a TERSE 401
    instead — the realistic case — is ``_jwt_vuln_terse_control_app``, which round-6 downgrades to a LEAD.)"""
    def send(req: HttpRequest) -> dict:
        token = _jwt_token_of(req, location)
        alg, sub = _decoded_alg_and_sub(token)
        if alg is None:
            return {"status": 401, "body": "Unauthorized"}
        if alg == "none":
            return {"status": 200, "body": _grant(sub)}              # VULN: trusts the unsigned token (leaks D)
        if _jwt.crack_hs256(token, [_SECRET]) is None:
            return {"status": 200, "body": _sameshape_deny()}        # bad sig ⇒ SUBSTANTIVE SAME-SHAPE deny (no D)
        return {"status": 200, "body": _grant(sub)}
    return send


def _jwt_benign_highsim_app(location: str):
    """THE SIXTH-VARIANT BLOCK. A BENIGN NON-granting app: it soft-200-DENIES the alg:none forge AND the
    bad-signature control in the identity-echoing site shell — two SUBSTANTIVE soft-200s that are HIGHLY
    shape-similar (~0.9+), the exact configuration that satisfied round-5's >= 0.5 similarity gate. Neither
    carries the victim-PRIVATE datum (it is not a grant). A correctly-signed token IS granted (the positive
    reference). Round-5 could mint here off a chrome differential; round-6 requires a genuine private D in the
    forged read, which a benign app never leaks ⇒ MUST NOT fire (and mints no context)."""
    def send(req: HttpRequest) -> dict:
        token = _jwt_token_of(req, location)
        alg, sub = _decoded_alg_and_sub(token)
        if alg is None:
            return {"status": 401, "body": "Unauthorized"}
        if alg == "none":
            return {"status": 200, "body": _identity_echo_shell(sub)}   # soft-200 DENY in the shell (no D)
        if _jwt.crack_hs256(token, [_SECRET]) is None:
            return {"status": 200, "body": _sameshape_deny()}           # bad sig ⇒ SUBSTANTIVE soft-200 (no D), high-sim
        return {"status": 200, "body": _grant(sub)}                     # a correctly-signed token IS granted
    return send


def _jwt_benign_terse_control_app(location: str):
    """FIFTH-VARIANT residue. A BENIGN app that soft-200-denies the alg:none forge in the site shell but rejects
    the bad-signature control with a TERSE 401 (a different shape). The forge is NOT a grant (no private datum),
    and the terse control is not a substantive same-shape read ⇒ MUST NOT fire on either ground."""
    def send(req: HttpRequest) -> dict:
        token = _jwt_token_of(req, location)
        alg, sub = _decoded_alg_and_sub(token)
        if alg is None:
            return {"status": 401, "body": "Unauthorized"}
        if alg == "none":
            return {"status": 200, "body": _identity_echo_shell(sub)}   # soft-200 DENY in the site shell (no D)
        if _jwt.crack_hs256(token, [_SECRET]) is None:
            return {"status": 401, "body": "Unauthorized"}              # bad sig ⇒ TERSE 401 (not same-shape)
        return {"status": 200, "body": _grant(sub)}
    return send


def _jwt_vuln_terse_control_app(location: str):
    """HONEST LEAD-DOWNGRADE. A GENUINELY vulnerable alg:none-confusion RP that DOES grant the forged unsigned
    token (leaking D) — BUT rejects the bad-signature control with a TERSE 401, a DIFFERENT shape than the rich
    grant. Because the control is not a substantive same-shape read (clause c), the private-read differential
    cannot be soundly established and the class DOWNGRADES to a LEAD (mints nothing) rather than a FACT. (The
    offline jwt_forgeable structural FACT still stands; a substantive same-shape deny reference would promote
    this to a FACT.)"""
    def send(req: HttpRequest) -> dict:
        token = _jwt_token_of(req, location)
        alg, sub = _decoded_alg_and_sub(token)
        if alg is None:
            return {"status": 401, "body": "Unauthorized"}
        if alg == "none":
            return {"status": 200, "body": _grant(sub)}                 # VULN: trusts the unsigned token (real grant, leaks D)
        if _jwt.crack_hs256(token, [_SECRET]) is None:
            return {"status": 401, "body": "Unauthorized"}              # bad sig ⇒ TERSE 401 (NOT a same-shape deny)
        return {"status": 200, "body": _grant(sub)}
    return send


def _jwt_reflect_deny_app(location: str):
    """Twin (a): reflects the sub on a 200 'Access denied' page but grants nothing (no private datum)."""
    def send(req: HttpRequest) -> dict:
        alg, sub = _decoded_alg_and_sub(_jwt_token_of(req, location))
        if alg is None:
            return {"status": 401, "body": "Unauthorized"}
        return {"status": 200, "body": f"Your workspace shows nothing for user {sub}. Return to the entry page."}
    return send


def _jwt_accept_everything_app(location: str):
    """Twin (b): grants the private datum to EVERYTHING, including the control (D present in the control)."""
    def send(_req: HttpRequest) -> dict:
        return {"status": 200, "body": _grant("whoever")}
    return send


def _jwt_hardened_app(location: str):
    """Twin (c): verifies HS256 against the real secret; rejects alg:none and bad-sig alike."""
    def send(req: HttpRequest) -> dict:
        token = _jwt_token_of(req, location)
        if token is None or _jwt.crack_hs256(token, [_SECRET]) is None:
            return {"status": 401, "body": "Unauthorized"}
        _, sub = _decoded_alg_and_sub(token)
        return {"status": 200, "body": _grant(sub)}
    return send


def _jwt_chrome_consistent_app(location: str):
    """A benign app whose forge AND bad-signature control both render the SAME chrome shell (a substantive
    soft-200) and only a correctly-signed token is granted. Probed with CHROME markers, the chrome is present in
    the substantive same-shape control too, so it is NOT access-gated ⇒ MUST NOT fire (chrome-disqualification
    via clause c)."""
    def send(req: HttpRequest) -> dict:
        token = _jwt_token_of(req, location)
        alg, sub = _decoded_alg_and_sub(token)
        if alg is None:
            return {"status": 400, "body": "Bad token"}
        if alg == "none" or _jwt.crack_hs256(token, [_SECRET]) is None:
            return {"status": 200, "body": _softdeny_with_nav()}        # forge + control ⇒ same chrome shell (no D)
        return {"status": 200, "body": _grant(sub)}
    return send


# ---------------------------------------------------------------------------
# SAML app fixtures — read the SAMLResponse the check placed
# ---------------------------------------------------------------------------


def _saml_parse(req: HttpRequest) -> "tuple[str | None, str, str]":
    raw = _sso.extract_form_field(req, "SAMLResponse")
    if not raw:
        return None, "", ""
    xml = _sso.decode_saml(raw)
    if not xml:
        return None, "", ""
    try:
        root = _sso.safe_parse_xml(xml)
    except Exception:
        return None, "", ""
    if not list(root.iter(f"{{{_NS_A}}}Assertion")):
        return "no-assertion", "", ""
    nameid = _sso.saml_nameid(root) or ""
    sigval = ""
    for sv in root.iter(f"{{{_NS_D}}}SignatureValue"):
        sigval = sv.text or ""
        break
    return "assertion", nameid, sigval


def _saml_fact_app():
    """The NameID-tamper-vulnerable SP whose deny view is a SUBSTANTIVE SAME-SHAPE page (round-6): the signature
    must be VALID (SignatureValue == the signed value) but the SP consumes the possibly-tampered NameID and
    renders the victim-PRIVATE datum. The forge keeps the valid SignatureValue while rewriting the NameID ⇒
    granted (leaks D). The bad-signature control fails the signature check ⇒ DENIED with the SP's own same-shell
    deny view (``_sameshape_deny`` — chrome present, private datum absent) ⇒ a SOUND acceptance FACT with a
    genuine private D."""
    def send(req: HttpRequest) -> dict:
        kind, nameid, sigval = _saml_parse(req)
        if kind != "assertion":
            return {"status": 403, "body": "Forbidden"}
        if sigval != "alice@example.test":
            return {"status": 200, "body": _sameshape_deny()}   # signature invalid ⇒ SUBSTANTIVE SAME-SHAPE deny (no D)
        return {"status": 200, "body": _grant(nameid)}          # VULN: consumes the tampered NameID (leaks D)
    return send


def _saml_benign_highsim_app():
    """THE SIXTH-VARIANT BLOCK (SAML). A BENIGN SP: it soft-200-DENIES the NameID-tampered assertion AND the
    bad-signature control in the site shell — two substantive soft-200s that are highly shape-similar — carrying
    NO private datum. A fully-valid assertion is granted (the positive reference). Round-6: no private D in the
    forged read ⇒ MUST NOT fire."""
    def send(req: HttpRequest) -> dict:
        kind, nameid, sigval = _saml_parse(req)
        if kind != "assertion":
            return {"status": 400, "body": "Bad request"}
        if sigval != "alice@example.test":
            return {"status": 200, "body": _sameshape_deny()}              # invalidated-sig control ⇒ soft-200 (no D)
        if nameid != "alice@example.test":
            return {"status": 200, "body": _identity_echo_shell(nameid)}   # tampered NameID ⇒ soft-200 DENY (no D)
        return {"status": 200, "body": _grant(nameid)}                     # untampered valid ⇒ grant (D)
    return send


def _saml_benign_terse_control_app():
    """FIFTH-VARIANT residue (SAML). A BENIGN SP that soft-200-denies the tampered assertion in the shell but
    rejects the invalidated-signature control with a TERSE 401 (a different shape). No private datum in the
    forged read and a non-same-shape control ⇒ MUST NOT fire."""
    def send(req: HttpRequest) -> dict:
        kind, nameid, sigval = _saml_parse(req)
        if kind != "assertion":
            return {"status": 400, "body": "Bad request"}
        if sigval != "alice@example.test":
            return {"status": 401, "body": "Unauthorized"}                 # invalidated-sig control ⇒ TERSE 401
        if nameid != "alice@example.test":
            return {"status": 200, "body": _identity_echo_shell(nameid)}   # tampered NameID ⇒ soft-200 DENY (no D)
        return {"status": 200, "body": _grant(nameid)}
    return send


def _saml_reflect_deny_app():
    def send(req: HttpRequest) -> dict:
        kind, nameid, sigval = _saml_parse(req)
        if kind != "assertion":
            return {"status": 403, "body": "Forbidden"}
        return {"status": 200, "body": f"Your workspace shows nothing for user {nameid}. Return to the entry page."}
    return send


def _saml_accept_everything_app():
    def send(_req: HttpRequest) -> dict:
        return {"status": 200, "body": _grant("whoever")}
    return send


def _saml_hardened_app():
    """Rejects any assertion whose consumed NameID != the signed value (signature covers the NameID)."""
    def send(req: HttpRequest) -> dict:
        kind, nameid, sigval = _saml_parse(req)
        if kind != "assertion" or nameid != sigval or sigval != "alice@example.test":
            return {"status": 403, "body": "Forbidden"}
        return {"status": 200, "body": _grant(nameid)}
    return send


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


def _run(req: HttpRequest, check, send) -> list:
    return AuditEngine(send).audit(req, checks=(), request_checks=(check,))


def _confirmed(findings, bug_class: str) -> bool:
    return any(f.bug_class == bug_class and f.confirmed_by == "achieved_state" for f in findings)


# ---------------------------------------------------------------------------
# FACT on the vulnerable app (the three surfaces) — an achieved read of a victim-PRIVATE datum
# ---------------------------------------------------------------------------


def test_jwt_forgery_accepted_fires_on_private_read() -> None:
    # The FACT needs a genuine victim-PRIVATE datum D present in the forged read + the legit positive reference
    # and absent from the substantive same-shape deny control.
    findings = _run(_jwt_req(), _jwt_check(markers=_PRIVATE), _jwt_fact_app("authorization"))
    assert _confirmed(findings, "jwt_forgery_accepted"), "an app that leaks a private datum to an alg:none forge is a FACT"
    f = next(x for x in findings if x.bug_class == "jwt_forgery_accepted")
    assert f.oracle_context, "the FACT carries a re-verifiable certificate"


def test_oidc_forgery_accepted_fires_on_private_read() -> None:
    findings = _run(_oidc_req(), _oidc_check(markers=_PRIVATE, location="id_token"), _jwt_fact_app("id_token"))
    assert _confirmed(findings, "oidc_forgery_accepted")


def test_saml_forgery_accepted_fires_on_private_read() -> None:
    findings = _run(_saml_req(), _saml_check(markers=_PRIVATE), _saml_fact_app())
    assert _confirmed(findings, "saml_forgery_accepted")


# ---------------------------------------------------------------------------
# THE SIXTH VARIANT — a benign identity-echoing soft-200 with HIGH shape-similarity but NO private D ⇒ LEAD
# ---------------------------------------------------------------------------


def test_sixth_variant_highsim_benign_no_private_datum_does_not_fire() -> None:
    """THE SIXTH-VARIANT BLOCK. A benign NON-granting app whose forge and control are both substantive soft-200s
    in the same shell (HIGH difflib similarity — the round-5 gate would have passed) mints NOTHING under round-6,
    because with a genuine victim-PRIVATE datum baseline the forged soft-deny carries no D (clause a fails). On
    all three surfaces, with the private-datum baseline: NO fire AND NO minted context (nothing durable to
    re-fire). The similarity is high yet irrelevant — it is only an advisory now."""
    for surface, req, chk, app in (
        ("jwt", _jwt_req(), _jwt_check(markers=_PRIVATE), _jwt_benign_highsim_app("authorization")),
        ("oidc", _oidc_req(), _oidc_check(markers=_PRIVATE, location="id_token"), _jwt_benign_highsim_app("id_token")),
        ("saml", _saml_req(), _saml_check(markers=_PRIVATE), _saml_benign_highsim_app()),
    ):
        assert not _confirmed(_run(req, chk, app), chk.bug_class), f"{surface}: benign high-sim app must not fire"
        assert chk.probe(RequestTemplate(req), app) is None, (
            f"{surface}: no private datum in the forged read ⇒ NO context (a LEAD), whatever the similarity")
    # The similarity between the forge and control IS high on this benign app — proving the score no longer
    # decides the fire (it is demoted to an advisory): a high score does NOT mint.
    assert fa._shape_similarity(_identity_echo_shell("guest"), _sameshape_deny()) >= 0.5


def test_benign_chrome_markers_disqualified_by_substantive_control() -> None:
    """Chrome is not access-gated. A benign app whose forge and control render the SAME chrome shell, probed with
    CHROME markers, mints NOTHING: the chrome is present in the substantive same-shape control, so clause (c)
    (absent-in-control) fails and no chrome survives as a discriminator. On all three surfaces."""
    for surface, req, chk, app in (
        ("jwt", _jwt_req(), _jwt_check(markers=_CHROME), _jwt_chrome_consistent_app("authorization")),
        ("oidc", _oidc_req(), _oidc_check(markers=_CHROME, location="id_token"), _jwt_chrome_consistent_app("id_token")),
    ):
        assert not _confirmed(_run(req, chk, app), chk.bug_class), f"{surface}: chrome markers must not mint"
        assert chk.probe(RequestTemplate(req), app) is None, f"{surface}: chrome present in the substantive control ⇒ no context"
    # Even against the genuinely-granting FACT app, CHROME markers do not fire: the same-shape deny renders the
    # chrome too, so only the genuine private datum is access-gated.
    assert not _confirmed(_run(_jwt_req(), _jwt_check(markers=_CHROME), _jwt_fact_app("authorization")), "jwt_forgery_accepted")


def test_terse_control_downgrades_to_lead() -> None:
    """A terse-401 control (not a substantive same-shape read) DOWNGRADES to a LEAD on clause (c), on both a
    benign app (which also lacks the private datum in the forge) and a GENUINELY vulnerable app (a real grant,
    but the non-same-shape control cannot soundly establish the differential). Mints nothing either way."""
    for surface, req, chk, app in (
        ("jwt-benign", _jwt_req(), _jwt_check(markers=_PRIVATE), _jwt_benign_terse_control_app("authorization")),
        ("oidc-benign", _oidc_req(), _oidc_check(markers=_PRIVATE, location="id_token"), _jwt_benign_terse_control_app("id_token")),
        ("saml-benign", _saml_req(), _saml_check(markers=_PRIVATE), _saml_benign_terse_control_app()),
        ("jwt-vuln", _jwt_req(), _jwt_check(markers=_PRIVATE), _jwt_vuln_terse_control_app("authorization")),
        ("oidc-vuln", _oidc_req(), _oidc_check(markers=_PRIVATE, location="id_token"), _jwt_vuln_terse_control_app("id_token")),
    ):
        assert not _confirmed(_run(req, chk, app), chk.bug_class), f"{surface}: terse control must downgrade to a LEAD"
        assert chk.probe(RequestTemplate(req), app) is None, f"{surface}: honest LEAD — no context minted"


# ---------------------------------------------------------------------------
# SILENT on all three twins (the FP fixtures)
# ---------------------------------------------------------------------------


def test_jwt_twins_do_not_fire() -> None:
    assert not _confirmed(_run(_jwt_req(), _jwt_check(), _jwt_reflect_deny_app("authorization")), "jwt_forgery_accepted")
    assert not _confirmed(_run(_jwt_req(), _jwt_check(), _jwt_accept_everything_app("authorization")), "jwt_forgery_accepted")
    assert not _confirmed(_run(_jwt_req(), _jwt_check(), _jwt_hardened_app("authorization")), "jwt_forgery_accepted")


def test_oidc_twins_do_not_fire() -> None:
    for app in (_jwt_reflect_deny_app, _jwt_accept_everything_app, _jwt_hardened_app):
        assert not _confirmed(_run(_oidc_req(), _oidc_check(location="id_token"), app("id_token")), "oidc_forgery_accepted")


def test_saml_twins_do_not_fire() -> None:
    for app in (_saml_reflect_deny_app, _saml_accept_everything_app, _saml_hardened_app):
        assert not _confirmed(_run(_saml_req(), _saml_check(), app()), "saml_forgery_accepted")


# ---------------------------------------------------------------------------
# positive reference / private-datum baseline REQUIRED — else a rigorous LEAD (no context, no traffic)
# ---------------------------------------------------------------------------


def test_missing_positive_reference_downgrades_to_lead() -> None:
    """No legitimate-valid-token positive reference ⇒ the class DOWNGRADES to a LEAD: it mints nothing AND
    sends no traffic (it does not even probe), on all three surfaces."""
    sent: list = []

    def spy(req: HttpRequest) -> dict:
        sent.append(req)
        return {"status": 200, "body": _grant("x")}

    for check, req in ((fa.JwtForgeryAcceptanceCheck(success_markers=_PRIVATE), _jwt_req()),
                       (fa.OidcForgeryAcceptanceCheck(success_markers=_PRIVATE, location="id_token"), _oidc_req()),
                       (fa.SamlForgeryAcceptanceCheck(success_markers=_PRIVATE), _saml_req())):
        assert _run(req, check, spy) == [], f"{check.bug_class}: no positive reference must mint nothing"
        assert check.probe(RequestTemplate(req), spy) is None
    assert sent == [], "with no positive reference the check must send NO traffic (a rigorous LEAD, not a probe)"


def test_no_private_datum_baseline_mints_nothing() -> None:
    sent: list = []

    def spy(req: HttpRequest) -> dict:
        sent.append(req)
        return {"status": 200, "body": _grant("x")}

    for check, req in ((fa.JwtForgeryAcceptanceCheck(legit_token=_legit_jwt()), _jwt_req()),
                       (fa.OidcForgeryAcceptanceCheck(legit_token=_legit_jwt(), location="id_token"), _oidc_req()),
                       (fa.SamlForgeryAcceptanceCheck(legit_saml=_SIGNED_SAML_B64), _saml_req())):
        assert _run(req, check, spy) == [], f"{check.bug_class}: no baseline must mint nothing"
    assert sent == [], "with no baseline the check must send NO forged traffic (a rigorous LEAD, not a probe)"


def test_vacuous_discriminators_do_not_fire() -> None:
    """Even against the genuinely-vulnerable FACT app, an empty / whitespace / too-short (< 3 char) discriminator
    mints NOTHING — it is not a valid_discriminator, so no discriminator survives to become an access-gated
    private datum. (The clause-(d) request-reflection guard and the nonce-overlap guard are exercised at the
    unit level in test_shared_guard_helpers / test_nonce_excision_and_marker_validation_helpers.)"""
    for vacuous in (("",), ("   ",), ("\t\n",), ("ab",), ("x",), ("", "  ", "yz")):
        for req, chk, app in (
            (_jwt_req(), _jwt_check(markers=vacuous), _jwt_fact_app("authorization")),
            (_oidc_req(), _oidc_check(markers=vacuous, location="id_token"), _jwt_fact_app("id_token")),
            (_saml_req(), _saml_check(markers=vacuous), _saml_fact_app()),
        ):
            assert not _confirmed(_run(req, chk, app), chk.bug_class), (
                f"a vacuous discriminator {vacuous!r} must never mint a FACT, even on a granting app")


# ---------------------------------------------------------------------------
# FIX #3 — a discriminator satisfied ONLY by the reflected attacker nonce must NOT fire
# ---------------------------------------------------------------------------


def test_marker_collision_with_reflected_nonce_does_not_fire(monkeypatch) -> None:
    """A marker that is a substring of the reflected forged nonce ('crucible-forged', a short hex slice) would
    be satisfied by PURE REFLECTION. After FIX #3 the nonce is excised from every searched body AND overlapping
    markers are dropped, so none of the three surfaces fire even on the granting FACT app (the collision markers
    never become discriminators)."""
    fixed = "crucible-forged-deadbeefcafebabefeedface0badc0de"
    monkeypatch.setattr(fa, "_new_marker", lambda: fixed)
    collision = ("crucible-forged", "cafebabe")
    assert not _confirmed(_run(_jwt_req(), _jwt_check(markers=collision), _jwt_fact_app("authorization")), "jwt_forgery_accepted")
    assert not _confirmed(_run(_oidc_req(), _oidc_check(markers=collision, location="id_token"), _jwt_fact_app("id_token")), "oidc_forgery_accepted")
    assert not _confirmed(_run(_saml_req(), _saml_check(markers=collision), _saml_fact_app()), "saml_forgery_accepted")
    # And a genuine private datum OUTSIDE the reflected nonce still fires (excision must not remove genuine text).
    assert _confirmed(_run(_jwt_req(), _jwt_check(markers=_PRIVATE), _jwt_fact_app("authorization")), "jwt_forgery_accepted"), (
        "excision must remove ONLY the reflected nonce, never the genuine private datum")


def test_nonce_excision_and_marker_validation_helpers() -> None:
    marker = "crucible-forged-deadbeefcafebabefeedface0badc0de"
    kept = fa._sound_markers(("crucible-forged", "cafebabe", marker, "acct-88213-7741", "private note"), marker)
    assert kept == ["acct-88213-7741", "private note"], "markers overlapping the forged nonce must be dropped"
    assert fa._sound_markers(("crucible-forged",), marker) == [], "an all-collision baseline drops to empty"
    # clause (d) — a discriminator reflected from the request is dropped.
    assert fa._sound_markers(("acct-88213-7741", "req-echoed-value"), marker,
                             reflectable="GET /x\nBearer req-echoed-value") == ["acct-88213-7741"]
    email = f"{marker}@sso-test.invalid"
    body = f"Welcome. acct-88213-7741 for user {marker}. Contact {email} for help."
    excised = fa._excise(body, fa._reflected_forged_values(marker, (email,)))
    assert marker not in excised and "sso-test.invalid" not in excised and "crucible-forged" not in excised
    assert "Welcome." in excised and "acct-88213-7741" in excised, "genuine text on both sides must survive"


def test_shared_guard_helpers() -> None:
    """Unit-level proof of the round-6 SHARED GUARDs, independent of the predicate oracle."""
    # is_substantive_success: 2xx + >=16 stripped chars + NOT a bare soft-deny phrase (a fail-closed gate).
    assert fa.is_substantive_success(200, "<h1>Dashboard</h1> welcome home now") is True
    assert fa.is_substantive_success(302, "<h1>Dashboard</h1> welcome home now") is False, "3xx is not success"
    assert fa.is_substantive_success(401, "<h1>Dashboard</h1> welcome home now") is False
    assert fa.is_substantive_success(200, "   short   ") is False, "trivial body is not substantive"
    assert fa.is_substantive_success(200, "You are not authorized to view this page at all.") is False, (
        "a soft-deny phrase is treated as non-substantive (fail-closed) ⇒ its absent marker cannot be vacuous")
    assert fa.is_substantive_success(200, _sameshape_deny()) is True, "the same-shape deny is a substantive rendered page"
    # _deny_signature_hits is a WEAK ADVISORY only.
    assert "access denied" in fa._deny_signature_hits("Access Denied here")
    assert fa._deny_signature_hits("<h1>Dashboard</h1> welcome home") == []
    # valid_discriminator: non-empty, >=3 stripped chars, nonce-disjoint, non-reflected.
    nonce = "crucible-forged-deadbeefcafebabefeedface0badc0de"
    assert fa.valid_discriminator("acct-88213-7741", nonce) is True
    for bad in ("", "  ", "\t", "ab", None):
        assert fa.valid_discriminator(bad, nonce) is False, f"{bad!r} is not a valid discriminator"
    assert fa.valid_discriminator("crucible-forged", nonce) is False, "a nonce substring is reflection-only"
    assert fa.valid_discriminator("cafebabe", nonce) is False, "a hex-tail slice collides with the nonce"
    assert fa.valid_discriminator("req-echoed", nonce, reflectable="Bearer req-echoed-token") is False, (
        "clause (d): a value reflected from the request is not a valid discriminator")
    # _shape_similarity is an ADVISORY ONLY (round-6): no is_same_shape_deny gate remains.
    assert not hasattr(fa, "is_same_shape_deny"), "the round-5 similarity admission gate must be removed"
    assert fa._shape_similarity(_grant("alice"), _sameshape_deny()) > 0.0
    assert fa._shape_similarity("", "anything") == 0.0 and fa._shape_similarity("anything", "") == 0.0


# ---------------------------------------------------------------------------
# offline re-verify + tamper reject (the differential must re-fire, and every doctoring must fail)
# ---------------------------------------------------------------------------


def _probe_jwt_ctx():
    return _jwt_check(markers=_PRIVATE).probe(RequestTemplate(_jwt_req()), _jwt_fact_app("authorization"))


def test_offline_reverify_reproduces_and_tamper_is_rejected() -> None:
    ctx = _probe_jwt_ctx()
    assert ctx is not None
    oc = ctx.to_verifier_context()
    assert OracleVerifier().confirm(oc).confirmed

    r = reverify_context(oc, bug_class="jwt_forgery_accepted", claimed_confirmed_by="achieved_state")
    assert r.reproduced and r.matches_claim is not False, "the retained predicate must re-fire offline"

    G = oc["observed_evidence"]["grant_discriminators"]
    assert G, "the certificate must carry the derived access-gated private discriminators"

    def _tamper(**over):
        t = dict(oc)
        ev = dict(t["observed_evidence"])
        ev.update(over)
        t["observed_evidence"] = ev
        return t

    # TAMPER 1: rewrite the RAW forged body ⇒ the per-probe nonce is no longer reflected (token-processed check).
    assert not OracleVerifier().confirm(_tamper(forged_body="totally different body with no markers here")).confirmed, (
        "a tampered forged_body (nonce not reflected) must NOT re-confirm")
    # TAMPER 2: strip the private datum out of the forged content ⇒ no achieved private read.
    assert not OracleVerifier().confirm(_tamper(forged_content="an authenticated-looking body with none of the private data present")).confirmed, (
        "removing the private datum from forged_content must NOT re-confirm")
    # TAMPER 3: inject the private datum INTO the control content ⇒ it is no longer access-gated (absent-in-control fails).
    assert not OracleVerifier().confirm(_tamper(control_content=" ".join(G) + " now present in the control body too")).confirmed, (
        "a control that also carries the private datum must NOT re-confirm (it is not access-gated)")
    # TAMPER 4: strip the private datum out of the positive reference ⇒ no established private-read baseline.
    assert not OracleVerifier().confirm(_tamper(legit_content="a positive reference body missing the private data entirely")).confirmed, (
        "removing the private datum from the positive reference must NOT re-confirm")
    # TAMPER 5: replace the substantive same-shape control with a TERSE deny ⇒ clause (c) not substantive ⇒ reject.
    assert not OracleVerifier().confirm(_tamper(control_status=401, control_content="Unauthorized")).confirmed, (
        "a terse / non-substantive control must NOT re-confirm (clause c requires a substantive same-shape read)")
    # TAMPER 6 (round-6 clause d): inject a discriminator VALUE into the forged token's own decoded claims ⇒ it is
    # a token-claim echo (attacker-controlled reflection), so clause (8) fails and the certificate is refused.
    assert oc["observed_evidence"].get("forged_token_claims") is not None, (
        "the certificate must carry the forged token's decoded claim values (clause d)")
    assert not OracleVerifier().confirm(_tamper(forged_token_claims=" ".join(G) + " echoed from the forged token")).confirmed, (
        "a D present in the forged token's own claims (a decoded-token-claim echo) must NOT re-confirm (clause d)")


# ---------------------------------------------------------------------------
# ROUND-6 BLOCK fix — clause (d) forged-token-claim guard. A benign app that REJECTS the forge but ECHOES a value
# it DECODED FROM THE FORGED TOKEN (a JWT email / OIDC name / SAML mail attribute) on its reject page is
# REFLECTING attacker-controlled token content, NOT leaking a server-side private datum ⇒ MUST NOT mint.
# ---------------------------------------------------------------------------

_CLAIM_EMAIL = "victim-echo@corp.test"   # a JWT email claim the alg:none forge PRESERVES (D = this)
_CLAIM_NAME = "Victim Q Echo Name"       # an OIDC name claim the forge preserves (email is overridden by the nonce)
_CLAIM_MAIL = "mailattr-echo@corp.test"  # a SAML mail AttributeValue the NameID-tamper keeps


def _rich_jwt() -> str:
    # A captured/legit token carrying email + name identity CLAIMS (the same real identity is the positive ref).
    return _jwt.encode_hs256({"typ": "JWT"}, {"sub": "alice", "email": _CLAIM_EMAIL, "name": _CLAIM_NAME}, _SECRET)


def _rich_jwt_req() -> HttpRequest:
    return HttpRequest(method="GET", url="http://127.0.0.1:9/me", headers=[("Authorization", f"Bearer {_rich_jwt()}")])


def _rich_oidc_req() -> HttpRequest:
    return HttpRequest(method="POST", url="http://127.0.0.1:9/callback",
                       headers=[("Content-Type", "application/x-www-form-urlencoded")],
                       body=f"id_token={_rich_jwt()}&state=x")


_SIGNED_SAML_MAIL = (
    f'<samlp:Response xmlns:samlp="{_NS_P}" xmlns:saml="{_NS_A}" xmlns:ds="{_NS_D}" ID="R1" Version="2.0">'
    "<saml:Issuer>https://idp.example.test</saml:Issuer>"
    '<samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>'
    '<saml:Assertion ID="A1" Version="2.0">'
    "<ds:Signature><ds:SignatureValue>alice@example.test</ds:SignatureValue></ds:Signature>"
    "<saml:Subject><saml:NameID>alice@example.test</saml:NameID></saml:Subject>"
    '<saml:AttributeStatement><saml:Attribute Name="mail">'
    f"<saml:AttributeValue>{_CLAIM_MAIL}</saml:AttributeValue></saml:Attribute></saml:AttributeStatement>"
    '<saml:Conditions NotOnOrAfter="2035-01-01T00:00:00Z"/>'
    "</saml:Assertion></samlp:Response>"
)
_SIGNED_SAML_MAIL_B64 = base64.b64encode(_SIGNED_SAML_MAIL.encode()).decode()


def _rich_saml_req() -> HttpRequest:
    return HttpRequest(method="POST", url="http://127.0.0.1:9/acs",
                       headers=[("Content-Type", "application/x-www-form-urlencoded")],
                       body=urlencode({"SAMLResponse": _SIGNED_SAML_MAIL_B64}))


def _decoded_claim(token: "str | None", claim: str) -> str:
    if token is None:
        return ""
    try:
        _, payload, _ = _jwt.decode(token)
    except Exception:
        return ""
    return str(payload.get(claim, ""))


def _jwt_claim_echo_app(location: str, claim: str):
    """A BENIGN NON-granting RP that REJECTS the alg:none forge but ECHOES the token's decoded ``claim`` on a
    SUBSTANTIVE soft-200 reject page; answers the bad-signature control with a generic substantive deny that does
    NOT echo it (``_sameshape_deny``); and GRANTS a correctly-signed token (the positive reference, which echoes
    the real claim). It leaks NO server-side private datum — the ONLY thing carrying D is the echoed token claim,
    which is attacker-controlled REFLECTION. All of clauses (a)/(b)/(c) are satisfied; ONLY clause (d) (the
    forged-token-claim guard) stops the fire ⇒ MUST NOT mint (round-6 BLOCK)."""
    def send(req: HttpRequest) -> dict:
        token = _jwt_token_of(req, location)
        alg, _sub = _decoded_alg_and_sub(token)
        val = _decoded_claim(token, claim)
        if alg is None:
            return {"status": 401, "body": "Unauthorized"}
        if alg == "none":
            return {"status": 200, "body": (f"<h1>Dashboard</h1><p>Profile lookup for {val} is unavailable here. "
                                            f"Head to the entry page.</p><nav><a href='/logout'>Sign out</a></nav>")}
        if _jwt.crack_hs256(token, [_SECRET]) is None:
            return {"status": 200, "body": _sameshape_deny()}   # bad-sig control: generic substantive deny, NO echo (no D)
        return {"status": 200, "body": (f"<h1>Dashboard</h1><p>Welcome back. Your profile {val} is confirmed. "
                                        f"Balance is ready to review.</p><nav><a href='/logout'>Sign out</a></nav>")}
    return send


def _saml_claim_echo_app():
    """The SAML dual: a BENIGN SP that REJECTS the NameID-tampered assertion but ECHOES its ``mail`` AttributeValue
    on a substantive soft-200 reject page; answers the invalidated-signature control with a generic substantive
    deny that does NOT echo it; and GRANTS a fully-valid assertion. The tampered assertion is un-re-signed, so the
    echoed mail attribute is attacker-controlled REFLECTION ⇒ clause (d) stops the fire ⇒ MUST NOT mint."""
    def send(req: HttpRequest) -> dict:
        kind, nameid, sigval = _saml_parse(req)
        mail = ""
        raw = _sso.extract_form_field(req, "SAMLResponse")
        xml = _sso.decode_saml(raw) if raw else ""
        if xml:
            try:
                for av in _sso.safe_parse_xml(xml).iter(f"{{{_NS_A}}}AttributeValue"):
                    if av.text:
                        mail = av.text
                        break
            except Exception:
                pass
        if kind != "assertion":
            return {"status": 400, "body": "Bad request"}
        if sigval != "alice@example.test":
            return {"status": 200, "body": _sameshape_deny()}          # invalidated-sig control: generic deny (no D)
        if nameid != "alice@example.test":
            return {"status": 200, "body": (f"<h1>Dashboard</h1><p>Directory entry for {mail} is unavailable. "
                                            f"Head to the entry page.</p><nav><a href='/logout'>Sign out</a></nav>")}
        return {"status": 200, "body": (f"<h1>Dashboard</h1><p>Welcome. Directory {mail} confirmed. "
                                        f"Balance ready.</p><nav><a href='/logout'>Sign out</a></nav>")}
    return send


def test_decoded_token_claim_echo_does_not_fire() -> None:
    """THE ROUND-6 BLOCK. On all three surfaces, a benign app that echoes a DECODED TOKEN CLAIM (JWT email /
    OIDC name / SAML mail attribute) on its reject page — with that claim supplied as the operator's D and present
    in the forged read AND the positive reference AND absent from a substantive same-shape control — mints NOTHING
    (a LEAD): the echo is REFLECTION of attacker-controlled token content, refused by clause (d)."""
    for surface, req, chk, app in (
        ("jwt", _rich_jwt_req(), _jwt_check(markers=(_CLAIM_EMAIL,), legit=_rich_jwt()),
         _jwt_claim_echo_app("authorization", "email")),
        ("oidc", _rich_oidc_req(), _oidc_check(markers=(_CLAIM_NAME,), legit=_rich_jwt(), location="id_token"),
         _jwt_claim_echo_app("id_token", "name")),
        ("saml", _rich_saml_req(), _saml_check(markers=(_CLAIM_MAIL,), legit=_SIGNED_SAML_MAIL_B64),
         _saml_claim_echo_app()),
    ):
        assert not _confirmed(_run(req, chk, app), chk.bug_class), (
            f"{surface}: a decoded-token-claim echo must NOT mint a FACT (clause d)")
        assert chk.probe(RequestTemplate(req), app) is None, (
            f"{surface}: a decoded-token-claim echo ⇒ NO context (a rigorous LEAD)")


def test_forged_token_claim_guard_is_the_load_bearing_addition() -> None:
    """Prove the forged-token-claim guard — not the pre-existing request-reflection guard — is what refuses the
    token-claim echo: the echoed claim is base64-encoded inside the request token, so it is NOT a substring of the
    request-reflectable content (the old clause (d) would ADMIT it), while the forged-token-claim guard DROPS it."""
    nonce = "crucible-forged-deadbeefcafebabefeedface0badc0de"
    reflectable = fa._request_reflectable(_rich_jwt_req())     # URL + headers (the base64 token) + body
    assert _CLAIM_EMAIL not in reflectable, "the email claim is base64-encoded in the token, not reflected verbatim"
    assert fa.valid_discriminator(_CLAIM_EMAIL, nonce, reflectable=reflectable) is True, (
        "the request-reflection guard alone does NOT catch a base64-embedded token claim")
    assert fa.valid_discriminator(_CLAIM_EMAIL, nonce, token_claims=f"alice\n{_CLAIM_EMAIL}\n{_CLAIM_NAME}") is False, (
        "clause (d): a value present in the forged token's own decoded claims is refused")
    # _sound_markers drops the token-claim value up front; a genuine server-side datum survives.
    kept = fa._sound_markers((_CLAIM_EMAIL, "acct-88213-7741"), nonce, token_claims=f"sub\n{_CLAIM_EMAIL}\nnone")
    assert kept == ["acct-88213-7741"], "the forged-token-claim value is dropped; the server-side datum survives"


def test_claim_value_extractors() -> None:
    """Unit-level proof of the claim-value extractors that seed clause (d)."""
    # JWT: values (not keys) are collected recursively; None/bool skipped.
    vals = fa._claim_values({"sub": "alice", "email": _CLAIM_EMAIL, "roles": ["admin", "user"],
                             "verified": True, "nested": {"k": "deep-value"}, "nothing": None})
    assert "alice" in vals and _CLAIM_EMAIL in vals and "admin" in vals and "deep-value" in vals
    assert "sub" not in vals and "True" not in vals and "email" not in vals, "keys and bools are not collected"
    # the actual forged alg:none token decodes to exactly its claim values.
    marker = "crucible-forged-abc123"
    forged = _jwt.encode_none({"typ": "JWT"}, {"sub": marker, "email": _CLAIM_EMAIL})
    fclaims = fa._forged_jwt_claims(forged, {"typ": "JWT"}, {"sub": marker, "email": _CLAIM_EMAIL})
    assert _CLAIM_EMAIL in fclaims and marker in fclaims
    # SAML: the tampered assertion's NameID + AttributeValue + other text/attrs are all attacker-controlled.
    tampered = _sso.tamper_assertion(_SIGNED_SAML_MAIL, marker)
    sclaims = fa._saml_claim_values(tampered)
    assert marker in sclaims and _CLAIM_MAIL in sclaims, "the tampered NameID and kept mail attribute are claim values"
    assert fa._saml_claim_values("<<<not xml") == [], "a parse failure yields no claims (total/defensive)"


def test_server_side_private_datum_still_fires_with_rich_token_claims() -> None:
    """The guard is PRECISE, not blunt: a genuine SERVER-SIDE private datum (token-ABSENT) still mints the FACT
    even when the forged token is rich with other claims (email/name). Only token-present values are excluded."""
    findings = _run(_rich_jwt_req(), _jwt_check(markers=_PRIVATE, legit=_rich_jwt()), _jwt_fact_app("authorization"))
    assert _confirmed(findings, "jwt_forgery_accepted"), (
        "a server-side private datum absent from the forged token still fires despite rich token claims")
    ctx = _jwt_check(markers=_PRIVATE, legit=_rich_jwt()).probe(RequestTemplate(_rich_jwt_req()), _jwt_fact_app("authorization"))
    claims = ctx.to_verifier_context()["observed_evidence"]["forged_token_claims"]
    assert _CLAIM_EMAIL in claims and _PRIVATE[0] not in claims, (
        "the forged token's email claim is recorded, and the surviving server-side D is not one of its claims")


# ---------------------------------------------------------------------------
# FIX #2 — a fresh RANDOM per-probe nonce (not a frozen constant)
# ---------------------------------------------------------------------------


def test_forged_marker_is_a_fresh_random_per_probe_nonce() -> None:
    m1 = _probe_jwt_ctx().to_verifier_context()
    m2 = _probe_jwt_ctx().to_verifier_context()
    n1 = m1["observed_evidence"]["forged_marker"]
    n2 = m2["observed_evidence"]["forged_marker"]
    assert n1.startswith("crucible-forged-") and n2.startswith("crucible-forged-")
    assert n1 != n2, "the forged marker must be unique per probe (FIX #2), not a frozen constant"
    assert any("forged_marker" in str(node) for node in m1["predicate"]["all"])


# ---------------------------------------------------------------------------
# refusal #7 — the forge is alg:none only; no embedded-key path
# ---------------------------------------------------------------------------


def _jwt_req_with_embedded_key_header() -> HttpRequest:
    header = {"typ": "JWT", "alg": "HS256",
              "jku": "https://attacker.test/jwks.json",
              "x5u": "https://attacker.test/cert.pem",
              "jwk": {"kty": "oct", "k": "YWJj"},
              "x5c": ["MIIB...attacker-cert..."]}
    tok = _jwt.encode_hs256(header, {"sub": "alice"}, _SECRET)
    return HttpRequest(method="GET", url="http://127.0.0.1:9/me",
                       headers=[("Authorization", f"Bearer {tok}")])


def test_forge_is_alg_none_no_embedded_key() -> None:
    seen: list = []

    def capture(req: HttpRequest) -> dict:
        tok = _jwt.extract_token(req, "authorization")
        if tok:
            try:
                header, _, _ = _jwt.decode(tok)
                seen.append(header)
            except Exception:
                seen.append({"garbage": True})
        return {"status": 200, "body": _grant("x")}

    fa.JwtForgeryAcceptanceCheck(success_markers=_PRIVATE, legit_token=_legit_jwt()).probe(
        RequestTemplate(_jwt_req_with_embedded_key_header()), capture)
    # The alg:none forged header is the one carrying no signature-key material and alg none.
    forged_none = [h for h in seen if "garbage" not in h and h.get("alg") == "none"]
    assert forged_none, "the check must have forged an alg:none token"
    for h in forged_none:
        for banned in ("jwk", "x5c", "jku", "x5u"):
            assert banned not in h, (
                f"refusal #7: the forged alg:none header must not carry an embedded-key field {banned!r}")


# ---------------------------------------------------------------------------
# the INDEPENDENT offline forgeability FACTs (jwt_forgeable / saml_structural_forgery) still mint
# ---------------------------------------------------------------------------


def test_offline_forgeability_facts_are_independent_and_still_fire() -> None:
    """The offline structural-forgery FACTs are a SEPARATE class from acceptance and are unaffected by the
    round-6 acceptance redesign: an alg:none JWT still mints ``jwt_forgeable``, and the SAML structural-forgery
    producer still mints ``saml_structural_forgery`` — with no live traffic."""
    none_tok = _jwt.encode_none({"typ": "JWT", "alg": "none"}, {"sub": "alice"})
    none_req = HttpRequest(method="GET", url="http://127.0.0.1:9/me",
                           headers=[("Authorization", f"Bearer {none_tok}")])
    jf = _jwt.JwtForgeryCheck().probe(RequestTemplate(none_req), lambda r: {"status": 200, "body": ""})
    assert jf is not None and OracleVerifier().confirm(jf.to_verifier_context()).confirmed, (
        "the offline jwt_forgeable FACT must still mint on an alg:none token")
    assert jf.bug_class == "jwt_forgeable"
    # An UNSIGNED consumed assertion (no ds:Signature) is structurally forgeable — the offline FACT invariant.
    unsigned = (
        f'<samlp:Response xmlns:samlp="{_NS_P}" xmlns:saml="{_NS_A}" ID="R2" Version="2.0">'
        "<saml:Issuer>https://idp.example.test</saml:Issuer>"
        '<samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>'
        '<saml:Assertion ID="A2" Version="2.0"><saml:Subject><saml:NameID>alice@example.test</saml:NameID>'
        '</saml:Subject><saml:Conditions NotOnOrAfter="2035-01-01T00:00:00Z"/></saml:Assertion></samlp:Response>'
    )
    unsigned_req = HttpRequest(method="POST", url="http://127.0.0.1:9/acs",
                               headers=[("Content-Type", "application/x-www-form-urlencoded")],
                               body=urlencode({"SAMLResponse": base64.b64encode(unsigned.encode()).decode()}))
    sf = _sso.SamlForgeryCheck().probe(RequestTemplate(unsigned_req), lambda r: {"status": 200, "body": ""})
    assert sf is not None and OracleVerifier().confirm(sf.to_verifier_context()).confirmed, (
        "the offline saml_structural_forgery FACT must still mint on an unsigned consumed assertion")
    assert sf.bug_class == "saml_structural_forgery"


# ---------------------------------------------------------------------------
# wiring invariants
# ---------------------------------------------------------------------------


def test_classes_route_to_achieved_state_and_are_known() -> None:
    for bc in ("jwt_forgery_accepted", "oidc_forgery_accepted", "saml_forgery_accepted"):
        assert is_known_bug_class(bc)
        assert BUG_CLASS_ORACLES[bc] == (OracleKind.ACHIEVED_STATE,)
        assert normalize_bug_class(bc) == bc


def test_not_in_the_default_roster() -> None:
    ids = {getattr(c, "id", None) for c in DEFAULT_REQUEST_CHECKS}
    assert "jwt-forgery-accepted" not in ids
    assert "oidc-forgery-accepted" not in ids
    assert "saml-forgery-accepted" not in ids


def test_the_class_to_branch_map_resolves() -> None:
    import sys
    from pathlib import Path
    root = Path(__file__).resolve().parents[6]
    integ = str(root / "integration")
    if integ not in sys.path:
        sys.path.insert(0, integ)
    from vigil_integration.live.wiring import _redrive_branch_for
    assert _redrive_branch_for("jwt_forgery_accepted") == "jwt_forgery_accepted.grant_differential"
    assert _redrive_branch_for("oidc_forgery_accepted") == "oidc_forgery_accepted.grant_differential"
    assert _redrive_branch_for("saml_forgery_accepted") == "saml_forgery_accepted.grant_differential"


def test_factory_passes_positive_reference() -> None:
    # A private-datum baseline — the FACT app's same-shape deny control disqualifies chrome, only D is gated.
    checks = fa.forgery_acceptance_checks(_PRIVATE, legit_token=_legit_jwt(), legit_saml=_SIGNED_SAML_B64)
    assert _confirmed(_run(_jwt_req(), checks[0], _jwt_fact_app("authorization")), "jwt_forgery_accepted")
    # empty baseline / no reference ⇒ the factory's checks mint nothing (default roster is byte-identical).
    for c in fa.forgery_acceptance_checks(()):
        assert c.success_markers == ()
