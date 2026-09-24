"""
Session-fixation confirmation (Wave 3.2, gated-workflow) — end-to-end over the in-process benchmark app,
without a browser: VIGIL fixes a high-entropy sentinel session id BEFORE authenticating, runs the operator
login sequence through a direct send, captures S0's read of the protected URL PLUS a POSITIVE reference (the
owner's authoritative read), a DECISIVE SAME-SHAPE negative reference (an OTHER unauthorized identity's read)
and a no-session baseline; the deterministic ``session_fixation_oracle`` adjudicates by the PRIVATE-READ
REDUCTION over the RAW retained bytes.

SIXTH-VARIANT principle (round-5 BLOCK): an achieved authenticated state CANNOT be proven from response
CONTENT. A ``success_marker`` PRESENT-with-cookie / ABSENT-without proves only that the COOKIE changed the
response, not that S0 authenticated — a benign app that renders the marker whenever ANY cookie is present
defeats it. So the marker differential is NO LONGER a minting path. Fixation is confirmed ONLY when a genuine
victim-PRIVATE discriminator D is PRESENT in S0's read AND in the owner's authoritative read yet PROVABLY
ABSENT from a SUBSTANTIVE SAME-SHAPE read by an OTHER unauthorized identity (the DECISIVE clause — cosmetic
chrome shown for any credential appears there too) and a valid no-session baseline.

Proves:
  * a FACT on the PLANTED vulnerable login flow (``/sessfix/login`` keeps the client-fixed id across login,
    so the fixed id becomes the VICTIM's session and reads the victim's PRIVATE datum — present in S0's read
    and the owner's, absent from the attacker's same-shape read);
  * SILENCE on the BENIGN TWIN (``/sessfix/rotate/login`` rotates the id at login — the correct defense);
  * the SIXTH-VARIANT is CLOSED: a benign cookie-varying app (a chrome marker present-with-cookie /
    absent-without, D not private) mints NOTHING — live AND under offline re-verification;
  * a reflected-sentinel D (a cookie echo), no private D, or a D present in the same-shape other-identity
    reference all DOWNGRADE to a LEAD;
  * the oracle NEVER trusts a pre-computed bool nor a bare success-marker differential;
  * the default GET-only crawl never touches the login POST routes (the fixture is deep-only), so
    ``make gate`` is unaffected.
"""

from __future__ import annotations

import re
import urllib.error
import urllib.request

from framework.v2.eval.benchmark_app import _SESSFIX_SUCCESS_MARKER, _sessfix_private, serve
from framework.v2.scanner.insertion import HttpRequest
from framework.v2.scanner.session import (
    CookieJar,
    LoginSequence,
    confirm_session_fixation,
    is_substantive_success,
    mint_session_sentinel,
    valid_discriminator,
)
from framework.v2.verify.adapter import FindingContext
from framework.v2.verify.models import OracleKind
from framework.v2.verify.verifier import OracleVerifier

_SENTINEL_RE = re.compile(r"^sfx_[0-9a-f]{32}$")
_D = _sessfix_private("admin")   # the victim (admin) PRIVATE datum the private-read differential requires


def _send(req: HttpRequest) -> dict:
    """A direct (test-only) send that faithfully carries the Cookie header and captures Set-Cookie —
    stands in for the gated CRUCIBLE executor for this deterministic in-process test."""
    body = req.body.encode("utf-8") if req.body is not None else None
    r = urllib.request.Request(req.url, data=body, method=req.method)
    for k, v in req.headers:
        r.add_header(k, v)
    try:
        with urllib.request.urlopen(r, timeout=10) as resp:   # noqa: S310 (loopback benchmark app)
            raw = resp.read().decode("utf-8", "replace")
            headers = [(k, v) for k, v in resp.getheaders()]
            status = resp.status
    except urllib.error.HTTPError as e:                       # pragma: no cover - benchmark never 4xx/5xx here
        raw = e.read().decode("utf-8", "replace")
        headers = list(e.headers.items())
        status = e.code
    return {"status": status, "headers": headers, "body": raw}


def _login(url_login: str, user: str = "admin") -> LoginSequence:
    return LoginSequence(url=url_login, method="POST", body=f"user={user}&password=x",
                         success_marker=_SESSFIX_SUCCESS_MARKER)


def _authed_send(base: str, user: str):
    """A ``send`` authenticated as ``user``: log in via the ROTATE route (a fresh server-issued session bound
    to that user), capture the SESSION cookie, and carry it on every request. The owner (victim) and the
    OTHER unauthorized identity are built this way — each reads the protected page as its own identity."""
    resp = _send(HttpRequest(method="POST", url=f"{base}/sessfix/rotate/login",
                             headers=[("Content-Type", "application/x-www-form-urlencoded")],
                             body=f"user={user}&password=x"))
    jar = CookieJar()
    jar.update_from_headers([(str(k), str(v)) for k, v in resp["headers"]])
    sid = jar.get("SESSION")

    def send(req: HttpRequest) -> dict:
        headers = [(k, v) for k, v in req.headers if k.lower() != "cookie"] + [("Cookie", f"SESSION={sid}")]
        return _send(req.model_copy(update={"headers": headers}))

    return send


def _with_cookie(send, sid: str):
    """Wrap a benign (non-benchmark) send so every request carries ``SESSION=<sid>`` — used to build the
    owner / other-identity references for the custom benign-app tests."""
    def s(req: HttpRequest) -> dict:
        headers = [(k, v) for k, v in req.headers if k.lower() != "cookie"] + [("Cookie", f"SESSION={sid}")]
        return send(req.model_copy(update={"headers": headers}))
    return s


def _has_cookie(req: HttpRequest, cookie: str = "SESSION") -> bool:
    return any(k.lower() == "cookie" and f"{cookie}=" in v for k, v in req.headers)


def _confirm(ctx: FindingContext) -> bool:
    return OracleVerifier().confirm(ctx.to_verifier_context()).confirmed


def _confirm_offline(ctx: FindingContext) -> bool:
    """Re-verify from the SERIALIZED retained record — the durable-certificate path."""
    rebuilt = FindingContext.model_validate(ctx.model_dump())
    return OracleVerifier().confirm(rebuilt.to_verifier_context()).confirmed


def test_mint_sentinel_shape() -> None:
    assert _SENTINEL_RE.fullmatch(mint_session_sentinel())


def test_shared_discriminator_and_substance_guards() -> None:
    # The shared Wave-3 guards (names/semantics must stay identical across the slices) — a marker below 3
    # stripped chars discriminates nothing; a substantive success is a real 2xx with a non-trivial,
    # non-error body. valid_discriminator ALSO refuses a marker that is a substring of the per-probe nonce.
    assert valid_discriminator("") is False
    assert valid_discriminator("   ") is False
    assert valid_discriminator("ab") is False
    assert valid_discriminator("abc") is True
    assert valid_discriminator(_D) is True
    assert valid_discriminator(None) is False
    assert valid_discriminator("cafebabe", nonce="sfx_cafebabe0000") is False   # a substring of the nonce
    assert is_substantive_success(200, f"<h1>{_SESSFIX_SUCCESS_MARKER}</h1><p>{_D}</p>") is True
    assert is_substantive_success(200, "") is False
    assert is_substantive_success(200, "short") is False
    assert is_substantive_success(302, "<h1>plenty of real body content here</h1>") is False
    assert is_substantive_success(200, "Internal Server Error occurred, please retry later") is False
    assert is_substantive_success(200, "<h1>Please log in</h1><p>You are logged out.</p>") is True


def test_planted_fixation_flow_confirms_a_fact() -> None:
    with serve() as base:
        owner = _authed_send(base, "admin")        # the victim's own authoritative session (POSITIVE ref)
        other = _authed_send(base, "attacker")     # a DIFFERENT unauthorized identity (SAME-SHAPE negative)
        ctx = confirm_session_fixation(
            _send,
            login=_login(f"{base}/sessfix/login", "admin"),
            session_cookie="SESSION",
            protected_url=f"{base}/sessfix/account",
            private_discriminator=_D,
            owner_send=owner,
            unauth_send=other,
        )
    assert ctx is not None and ctx.bug_class == "session_fixation"
    rec = ctx.session_fixation
    assert rec is not None
    assert _SENTINEL_RE.fullmatch(rec["sentinel_id"])
    assert rec["post_auth_id"] == rec["sentinel_id"]     # the fixed id SURVIVED login (no rotation)
    # the PRIVATE-READ differential raw material: D present in S0's read AND the owner's, absent from the
    # OTHER identity's same-shape read AND the no-session baseline.
    assert _D in rec["authorized_view"]["body"]
    assert _D in rec["owner_view"]["body"]
    assert _D not in rec["unauth_ref"]["body"]
    assert _SESSFIX_SUCCESS_MARKER in rec["unauth_ref"]["body"]   # chrome IS present for the other identity
    assert _D not in rec["logged_out_ref"]["body"]
    outcome = OracleVerifier().confirm(ctx.to_verifier_context())
    assert outcome.confirmed
    assert any(s.kind is OracleKind.SESSION_FIXATION and s.fired for s in outcome.signals)
    # round-trip: the retained context re-fires (a re-verifiable certificate) from the SAME raw bytes.
    assert _confirm_offline(ctx)


def test_benign_twin_that_rotates_the_id_never_fires() -> None:
    with serve() as base:
        owner = _authed_send(base, "admin")
        other = _authed_send(base, "attacker")
        ctx = confirm_session_fixation(
            _send,
            login=_login(f"{base}/sessfix/rotate/login", "admin"),
            session_cookie="SESSION",
            protected_url=f"{base}/sessfix/account",
            private_discriminator=_D,
            owner_send=owner,
            unauth_send=other,
        )
    assert ctx is not None
    rec = ctx.session_fixation
    assert rec["post_auth_id"] != rec["sentinel_id"]      # the app ROTATED at login (the correct defense)
    # the fixed id S0 is not bound ⇒ its read is the logged-out body (no private datum) ⇒ rotated + dead ⇒ clean.
    assert _D not in rec["authorized_view"]["body"]
    assert not _confirm(ctx)
    assert not _confirm_offline(ctx)


def test_a_tampered_post_auth_id_no_longer_confirms() -> None:
    with serve() as base:
        owner = _authed_send(base, "admin")
        other = _authed_send(base, "attacker")
        ctx = confirm_session_fixation(
            _send, login=_login(f"{base}/sessfix/login", "admin"), session_cookie="SESSION",
            protected_url=f"{base}/sessfix/account", private_discriminator=_D,
            owner_send=owner, unauth_send=other,
        )
    assert _confirm(ctx)   # the untampered record IS a FACT
    d = ctx.model_dump()
    d["session_fixation"]["post_auth_id"] = "rot_deadbeefdeadbeefdeadbeefdeadbeef"  # forge a rotation
    tampered = FindingContext.model_validate(d)
    assert not OracleVerifier().confirm(tampered.to_verifier_context()).confirmed


def test_no_private_discriminator_downgrades_to_lead_even_against_the_vulnerable_flow() -> None:
    # Against the genuinely-vulnerable planted flow, WITHOUT a private discriminator D there is no
    # achieved-state proof (a bare success-marker differential proves only that a credential changed the
    # response) ⇒ the oracle FAILS CLOSED to a LEAD — an honest downgrade beats a FACT it cannot prove.
    with serve() as base:
        owner = _authed_send(base, "admin")
        other = _authed_send(base, "attacker")
        ctx = confirm_session_fixation(
            _send, login=_login(f"{base}/sessfix/login", "admin"), session_cookie="SESSION",
            protected_url=f"{base}/sessfix/account", owner_send=owner, unauth_send=other,
        )
    assert ctx is not None
    assert ctx.session_fixation["private_discriminator"] is None
    assert not _confirm(ctx)
    assert not _confirm_offline(ctx)


def test_no_references_supplied_downgrades_to_lead() -> None:
    # No owner/other-identity references at all (the operator pointed the probe but supplied no positive /
    # same-shape references) ⇒ the private-read differential is unestablished ⇒ LEAD, never a FACT.
    with serve() as base:
        ctx = confirm_session_fixation(
            _send, login=_login(f"{base}/sessfix/login", "admin"), session_cookie="SESSION",
            protected_url=f"{base}/sessfix/account", private_discriminator=_D,
        )
    assert ctx is not None
    assert ctx.session_fixation["owner_view"] is None and ctx.session_fixation["unauth_ref"] is None
    assert not _confirm(ctx)
    assert not _confirm_offline(ctx)


# ---------------------------------------------------------------------------
# SIXTH-VARIANT: a benign app whose response merely VARIES by credential presence must NOT mint.
# ---------------------------------------------------------------------------

def _cookie_varying_send(marker: str = "WELCOME-BACK-VALUED-USER"):
    """A BENIGN app: login sets NO Set-Cookie (S1 == S0), and the protected GET renders ``marker`` whenever
    ANY SESSION cookie is present, omitting it without one ('present-with-cookie / absent-without'), with NO
    per-identity private content. The exact sixth-variant a marker/credential-presence differential false-fires
    on — but the chrome marker appears for EVERY identity, so an other-identity same-shape read carries it too."""
    def send(req: HttpRequest) -> dict:
        if req.method == "POST":
            return {"status": 200, "headers": [], "body": "<html>ok, processed</html>"}
        if _has_cookie(req):
            return {"status": 200, "headers": [], "body": f"<h1>{marker}</h1><p>Welcome to the portal.</p>"}
        return {"status": 200, "headers": [], "body": "<h1>Portal</h1><p>Please sign in.</p>"}
    return send


def test_benign_cookie_varying_app_yields_no_fact_live_and_offline() -> None:
    marker = "WELCOME-BACK-VALUED-USER"
    benign = _cookie_varying_send(marker)
    ctx = confirm_session_fixation(
        benign,
        login=LoginSequence(url="http://app/login", method="POST", body="user=a&password=b",
                            success_marker=marker),
        session_cookie="SESSION", protected_url="http://app/account",
        private_discriminator=marker,                       # the operator mistakes the chrome for private
        owner_send=_with_cookie(benign, "owner_sess"),      # any cookie shows the chrome marker
        unauth_send=_with_cookie(benign, "attacker_sess"),  # SAME-SHAPE read ALSO shows the chrome marker
    )
    assert ctx is not None
    rec = ctx.session_fixation
    assert rec["post_auth_id"] == rec["sentinel_id"]                 # S1 == S0 (fixed id not rotated)
    assert marker in rec["authorized_view"]["body"]                 # present WITH the cookie
    assert marker not in rec["logged_out_ref"]["body"]              # absent WITHOUT — the old false differential
    assert marker in rec["unauth_ref"]["body"]                      # but present for the OTHER identity (chrome)
    assert not _confirm(ctx), "a benign cookie-varying app minted a FACT"
    assert not _confirm_offline(ctx), "a benign cookie-varying app minted a DURABLE FACT offline"


def test_no_substantive_same_shape_other_identity_reference_downgrades_to_lead() -> None:
    # A no-session-ONLY differential (present-with-cookie / absent-without) is defeated by a credential-
    # presence-varying app, so it can NEVER mint: the DECISIVE same-shape other-identity reference is missing.
    marker = "WELCOME-BACK-VALUED-USER"
    benign = _cookie_varying_send(marker)
    ctx = confirm_session_fixation(
        benign,
        login=LoginSequence(url="http://app/login", method="POST", body="user=a&password=b",
                            success_marker=marker),
        session_cookie="SESSION", protected_url="http://app/account",
        private_discriminator=marker, owner_send=_with_cookie(benign, "owner_sess"),
        # unauth_send omitted → no same-shape negative reference
    )
    assert ctx is not None
    assert ctx.session_fixation["unauth_ref"] is None
    assert not _confirm(ctx)
    assert not _confirm_offline(ctx)


# ---------------------------------------------------------------------------
# Reflected-sentinel D: a benign app that ECHOES the session cookie into the body cannot mint.
# ---------------------------------------------------------------------------

def _cookie_echo_send():
    """A BENIGN app that sets NO Set-Cookie at login (S1 == S0) and ECHOES the presented SESSION cookie value
    verbatim into every GET body. It performs NO authentication: S0's read differs from a no-cookie read ONLY
    by the reflected VIGIL sentinel."""
    def send(req: HttpRequest) -> dict:
        if req.method == "POST":
            return {"status": 200, "headers": [], "body": "<html>ok, processed</html>"}
        val = ""
        for k, v in req.headers:
            if k.lower() == "cookie":
                for part in v.split(";"):
                    kk, _, vv = part.strip().partition("=")
                    if kk == "SESSION":
                        val = vv
        return {"status": 200, "headers": [],
                "body": f"<html><body><p>Session token: {val}</p><p>Home page content here.</p></body></html>"}
    return send


def test_cookie_echo_sentinel_substring_discriminator_yields_no_fact() -> None:
    # A D that is a SUBSTRING of the VIGIL sentinel is a reflected cookie-echo artifact, not private content.
    s0 = "sfx_" + "0123456789abcdef" * 2   # 32 hex chars → valid sentinel shape
    hex_tail = s0[-12:]                      # a 12-char hex substring of S0
    echo = _cookie_echo_send()
    ctx = confirm_session_fixation(
        echo,
        login=LoginSequence(url="http://app/login", method="POST", body="user=a&password=b"),
        session_cookie="SESSION", protected_url="http://app/account",
        private_discriminator=hex_tail, sentinel_id=s0,
        owner_send=_with_cookie(echo, "owner_sess"), unauth_send=_with_cookie(echo, "attacker_sess"),
    )
    assert ctx is not None
    rec = ctx.session_fixation
    assert rec["sentinel_id"] == s0 and rec["post_auth_id"] == s0
    assert hex_tail in rec["authorized_view"]["body"]           # echoed sentinel makes the substring present
    assert not _confirm(ctx), "a sentinel-substring D minted a FACT off a benign cookie echo"
    assert not _confirm_offline(ctx), "a sentinel-substring D minted a DURABLE FACT offline"


def test_oracle_ignores_a_bare_authenticated_bool_no_raw_bytes_no_fact() -> None:
    # DURABLE soundness: the oracle re-derives from RAW bytes and NEVER trusts a pre-computed bool. A
    # hand-forged legacy-shaped record carrying only authenticated_after_login=True cannot construct a FACT.
    s0 = mint_session_sentinel()
    forged = FindingContext.model_validate({
        "bug_class": "session_fixation",
        "session_fixation": {
            "sentinel_id": s0, "post_auth_id": s0, "cookie_name": "SESSION",
            "authenticated_after_login": True,   # the old bare bool — must be IGNORED
        },
    })
    assert not OracleVerifier().confirm(forged.to_verifier_context()).confirmed
