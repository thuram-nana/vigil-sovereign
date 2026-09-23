"""
Session-fixation confirmation (Wave 3.2, gated-workflow) — end-to-end over the in-process benchmark app,
without a browser: VIGIL fixes a high-entropy sentinel session id BEFORE authenticating, runs the operator
login sequence through a direct send, captures the fixed-session view AND a same-URL LOGGED-OUT reference,
and the deterministic ``session_fixation_oracle`` adjudicates by a DIFFERENTIAL over the RAW retained bytes.

ROUND-4 principle: a single response body CANNOT be classified authenticated-vs-benign by content
heuristics. The operator ``success_marker`` qualifies as an authenticated-state discriminator ONLY when it
is PRESENT in the fixed-session view of the protected URL AND PROVABLY ABSENT from a SUBSTANTIVE same-URL
logged-out (no-cookie) reference. A marker present in BOTH views (a common HTML token, page chrome, a benign
soft-200 body both share) is DISQUALIFIED ⇒ no FACT. No substantive logged-out reference ⇒ a LEAD.

Proves:
  * a FACT on the PLANTED vulnerable login flow (``/sessfix/login`` keeps the client-fixed id across login,
    so the fixed id still authenticates ``/sessfix/account`` — marker present in the fixed-session view,
    absent from the logged-out reference);
  * SILENCE on the BENIGN TWIN (``/sessfix/rotate/login`` rotates the session id at login — the correct
    defense — so the fixed id never authenticates);
  * the ROUND-4 4th-variant is CLOSED: a benign soft-200 (the same body, or a common token like ``<p>`` /
    ``div``, shared by both the fixed-session and logged-out views) mints NOTHING — live AND under offline
    re-verification of the retained record;
  * the oracle NEVER trusts a pre-computed bool — a hand-forged record carrying only ``authenticated_after_
    login`` (no raw bodies) does not confirm;
  * the retained ``oracle_context`` re-fires (a re-verifiable certificate) and a tampered post-auth id no
    longer confirms;
  * the default GET-only crawl never touches the login POST routes (the fixture is deep-only), so
    ``make gate`` is unaffected — asserted by the ground-truth manifest test elsewhere.
"""

from __future__ import annotations

import re
import urllib.request

from framework.v2.eval.benchmark_app import _SESSFIX_SUCCESS_MARKER, serve
from framework.v2.scanner.insertion import HttpRequest
from framework.v2.scanner.session import (
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


def _login(url_login: str) -> LoginSequence:
    return LoginSequence(url=url_login, method="POST", body="user=admin&password=admin",
                         success_marker=_SESSFIX_SUCCESS_MARKER)


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
    # non-error body. (The differential itself lives in the oracle; these are the cheap pre-guards.)
    assert valid_discriminator("") is False
    assert valid_discriminator("   ") is False
    assert valid_discriminator("ab") is False
    assert valid_discriminator("abc") is True
    assert valid_discriminator("SESSFIX-AUTHENTICATED") is True
    assert valid_discriminator(None) is False
    assert is_substantive_success(200, "<h1>SESSFIX-AUTHENTICATED</h1><p>Welcome back.</p>") is True
    assert is_substantive_success(200, "") is False
    assert is_substantive_success(200, "short") is False
    assert is_substantive_success(302, "<h1>plenty of real body content here</h1>") is False
    assert is_substantive_success(200, "Internal Server Error occurred, please retry later") is False
    # a normal logged-out page is a substantive success too (so it is a usable negative reference).
    assert is_substantive_success(200, "<h1>Please log in</h1><p>You are logged out.</p>") is True


def test_planted_fixation_flow_confirms_a_fact() -> None:
    with serve() as base:
        ctx = confirm_session_fixation(
            _send,
            login=_login(f"{base}/sessfix/login"),
            session_cookie="SESSION",
            protected_url=f"{base}/sessfix/account",
        )
    assert ctx is not None and ctx.bug_class == "session_fixation"
    rec = ctx.session_fixation
    assert rec is not None
    assert _SENTINEL_RE.fullmatch(rec["sentinel_id"])
    assert rec["post_auth_id"] == rec["sentinel_id"]     # the fixed id SURVIVED login (no rotation)
    # the DIFFERENTIAL raw material: marker PRESENT in the fixed-session view, ABSENT from the logged-out ref.
    assert _SESSFIX_SUCCESS_MARKER in rec["authorized_view"]["body"]
    assert _SESSFIX_SUCCESS_MARKER not in rec["logged_out_ref"]["body"]
    assert rec["logged_out_ref"]["body"].strip()          # a substantive negative reference
    outcome = OracleVerifier().confirm(ctx.to_verifier_context())
    assert outcome.confirmed
    assert any(s.kind is OracleKind.SESSION_FIXATION and s.fired for s in outcome.signals)
    # round-trip: the retained context re-fires (a re-verifiable certificate) from the SAME raw bytes.
    assert _confirm_offline(ctx)


def test_benign_twin_that_rotates_the_id_never_fires() -> None:
    with serve() as base:
        ctx = confirm_session_fixation(
            _send,
            login=_login(f"{base}/sessfix/rotate/login"),
            session_cookie="SESSION",
            protected_url=f"{base}/sessfix/account",
        )
    assert ctx is not None
    rec = ctx.session_fixation
    assert rec["post_auth_id"] != rec["sentinel_id"]      # the app ROTATED at login (the correct defense)
    # the fixed id S0 is not blessed ⇒ its view is the logged-out body (no marker) ⇒ rotated + dead ⇒ clean.
    assert _SESSFIX_SUCCESS_MARKER not in rec["authorized_view"]["body"]
    assert not _confirm(ctx)
    assert not _confirm_offline(ctx)


def test_a_tampered_post_auth_id_no_longer_confirms() -> None:
    with serve() as base:
        ctx = confirm_session_fixation(
            _send,
            login=_login(f"{base}/sessfix/login"),
            session_cookie="SESSION",
            protected_url=f"{base}/sessfix/account",
        )
    d = ctx.model_dump()
    d["session_fixation"]["post_auth_id"] = "rot_deadbeefdeadbeefdeadbeefdeadbeef"  # forge a rotation
    tampered = FindingContext.model_validate(d)
    assert not OracleVerifier().confirm(tampered.to_verifier_context()).confirmed


def test_marker_absent_downgrades_to_lead_even_against_the_vulnerable_flow() -> None:
    # Against the genuinely-vulnerable planted flow, dropping the success_marker removes the positive
    # authenticated-state discriminator, so the differential is undecidable and VIGIL cannot soundly mint —
    # an honest LEAD/INCONCLUSIVE beats a FACT it cannot prove.
    with serve() as base:
        ctx = confirm_session_fixation(
            _send,
            login=LoginSequence(url=f"{base}/sessfix/login", method="POST", body="user=admin&password=admin"),
            session_cookie="SESSION",
            protected_url=f"{base}/sessfix/account",
        )
    assert ctx is not None
    assert ctx.session_fixation["success_marker"] is None
    assert not _confirm(ctx)
    assert not _confirm_offline(ctx)


# ---------------------------------------------------------------------------
# ROUND-4 core: a benign soft-200 that RESEMBLES success cannot mint — the differential closes it.
# ---------------------------------------------------------------------------

def _soft200_send(body_both: str, marker: str = _SESSFIX_SUCCESS_MARKER):
    """A benign app that never touches the VIGIL-fixed SESSION cookie (login sets NO Set-Cookie ⇒ S1 == S0)
    and returns the SAME soft-200 ``body_both`` for the protected URL REGARDLESS of the cookie — so the
    fixed-session view and the logged-out (no-cookie) reference are IDENTICAL. Any operator marker present in
    that shared body is present in BOTH views ⇒ disqualified ⇒ no FACT."""
    def send(req: HttpRequest) -> dict:
        if req.method == "POST":
            return {"status": 200, "headers": [], "body": "<html>ok, processed</html>"}
        return {"status": 200, "headers": [], "body": body_both}
    return send


def test_soft_200_shared_body_marker_in_both_views_yields_no_fact() -> None:
    # A benign soft-200 whose body contains the operator success_marker but is returned for BOTH the
    # fixed-session view and the logged-out reference. The marker is present in BOTH ⇒ NOT access-gated ⇒
    # the oracle refuses (LEAD), live AND under offline re-verification. This is the exact class that
    # defeated three prior rounds of content heuristics.
    body = f"<html><body><h1>{_SESSFIX_SUCCESS_MARKER}</h1><p>Welcome to the portal.</p></body></html>"
    ctx = confirm_session_fixation(_soft200_send(body), login=LoginSequence(
        url="http://app/login", method="POST", body="user=a&password=b",
        success_marker=_SESSFIX_SUCCESS_MARKER), session_cookie="SESSION", protected_url="http://app/account")
    assert ctx is not None
    rec = ctx.session_fixation
    assert rec["post_auth_id"] == rec["sentinel_id"]      # S1 == S0 (fixed id not rotated)
    assert _SESSFIX_SUCCESS_MARKER in rec["authorized_view"]["body"]
    assert _SESSFIX_SUCCESS_MARKER in rec["logged_out_ref"]["body"]   # present in BOTH ⇒ disqualified
    assert not _confirm(ctx)
    assert not _confirm_offline(ctx)


def test_round3_fourth_variant_common_html_token_marker_yields_no_durable_fact() -> None:
    # THE ROUND-3 4th-variant, CLOSED: a 3-char common HTML token ('<p>' / 'div') that valid_discriminator
    # admits (>= 3 stripped chars) but which is trivially present in ANY HTML body — including the logged-out
    # reference. The differential DISQUALIFIES it (present in both views), so no durable CWE-384 FACT is
    # minted against a logged-out page with S1 == S0 — the precise defect that BLOCKED round 3.
    for token in ("<p>", "div"):
        body = "<html><body><div><p>Some page content here for length.</p></div></body></html>"
        ctx = confirm_session_fixation(_soft200_send(body, marker=token), login=LoginSequence(
            url="http://app/login", method="POST", body="user=a&password=b", success_marker=token),
            session_cookie="SESSION", protected_url="http://app/account")
        assert ctx is not None
        rec = ctx.session_fixation
        assert rec["post_auth_id"] == rec["sentinel_id"]  # S1 == S0
        assert token in rec["authorized_view"]["body"] and token in rec["logged_out_ref"]["body"]
        assert not _confirm(ctx), f"common token {token!r} minted a FACT against a logged-out soft-200"
        assert not _confirm_offline(ctx), f"common token {token!r} minted a DURABLE FACT offline"


def test_no_substantive_logged_out_reference_downgrades_to_lead() -> None:
    # The differential cannot be established without a SUBSTANTIVE logged-out reference. Here the no-cookie
    # view is empty (non-substantive) while the fixed-session view is a real authenticated page — a
    # fixation-shaped app, but with no negative reference the oracle FAILS CLOSED to a LEAD (never a FACT),
    # the honest downgrade. (A benchmark-style app that DOES serve a substantive logged-out page FACTs;
    # test_planted_fixation_flow_confirms_a_fact covers that.)
    def send(req: HttpRequest) -> dict:
        if req.method == "POST":
            return {"status": 200, "headers": [], "body": "<html>ok</html>"}
        if _has_cookie(req):
            return {"status": 200, "headers": [],
                    "body": f"<h1>{_SESSFIX_SUCCESS_MARKER}</h1><p>Welcome back, admin.</p>"}
        return {"status": 200, "headers": [], "body": ""}   # non-substantive negative reference
    ctx = confirm_session_fixation(send, login=LoginSequence(
        url="http://app/login", method="POST", body="user=a&password=b",
        success_marker=_SESSFIX_SUCCESS_MARKER), session_cookie="SESSION", protected_url="http://app/account")
    assert ctx is not None
    rec = ctx.session_fixation
    assert rec["post_auth_id"] == rec["sentinel_id"]
    assert _SESSFIX_SUCCESS_MARKER in rec["authorized_view"]["body"]
    assert not rec["logged_out_ref"]["body"].strip()      # no substantive negative reference
    assert not _confirm(ctx)                              # LEAD, never a FACT
    assert not _confirm_offline(ctx)


def test_error_body_at_the_protected_page_yields_no_fact() -> None:
    # The fixed id survives login unrotated (S1 == S0) but the fixed-session read is an ERROR 200 that
    # COINCIDENTALLY echoes the marker; the logged-out reference is a normal page. The authorized view is not
    # a substantive success ⇒ undecidable ⇒ LEAD, live and offline.
    def send(req: HttpRequest) -> dict:
        if req.method == "POST":
            return {"status": 200, "headers": [], "body": "<html>ok, logged in</html>"}
        if _has_cookie(req):
            return {"status": 200, "headers": [],
                    "body": f"Internal Server Error rendering {_SESSFIX_SUCCESS_MARKER} account"}
        return {"status": 200, "headers": [], "body": "<h1>Please log in</h1><p>Logged out.</p>"}
    ctx = confirm_session_fixation(send, login=LoginSequence(
        url="http://app/login", method="POST", body="user=a&password=b",
        success_marker=_SESSFIX_SUCCESS_MARKER), session_cookie="SESSION", protected_url="http://app/account")
    assert ctx is not None
    assert ctx.session_fixation["post_auth_id"] == ctx.session_fixation["sentinel_id"]
    assert not _confirm(ctx)
    assert not _confirm_offline(ctx)


def test_oracle_ignores_a_bare_authenticated_bool_no_raw_bytes_no_fact() -> None:
    # DURABLE soundness: the oracle re-derives auth from RAW bytes and NEVER trusts a pre-computed bool. A
    # hand-forged legacy-shaped record carrying only authenticated_after_login=True (no authorized_view / no
    # logged_out_ref) cannot construct a FACT — it fails closed to a LEAD.
    s0 = mint_session_sentinel()
    forged = FindingContext.model_validate({
        "bug_class": "session_fixation",
        "session_fixation": {
            "sentinel_id": s0, "post_auth_id": s0, "cookie_name": "SESSION",
            "authenticated_after_login": True,   # the old bare bool — must be IGNORED
        },
    })
    assert not OracleVerifier().confirm(forged.to_verifier_context()).confirmed
