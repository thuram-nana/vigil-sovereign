"""
Session-fixation confirmation (Wave 3.2, gated-workflow) — end-to-end over the in-process benchmark app,
without a browser: VIGIL fixes a high-entropy sentinel session id BEFORE authenticating, runs the operator
login sequence through a direct send, and the deterministic ``session_fixation_oracle`` adjudicates.

Proves:
  * a FACT on the PLANTED vulnerable login flow (``/sessfix/login`` keeps the client-fixed id across login,
    so the fixed id still authenticates ``/sessfix/account``);
  * SILENCE on the BENIGN TWIN (``/sessfix/rotate/login`` rotates the session id at login — the correct
    defense — so the fixed id never authenticates);
  * the retained ``oracle_context`` re-fires (a re-verifiable certificate) and a tampered post-auth id no
    longer confirms;
  * the default GET-only crawl of the benchmark app never touches the login POST routes (the fixture is
    deep-only), so ``make gate`` is unaffected — asserted by the ground-truth manifest test elsewhere.
"""

from __future__ import annotations

import re
import urllib.request

from framework.v2.eval.benchmark_app import _SESSFIX_SUCCESS_MARKER, serve
from framework.v2.scanner.insertion import HttpRequest
from framework.v2.scanner.session import (
    LoginSequence,
    _is_authenticated,
    confirm_session_fixation,
    mint_session_sentinel,
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


def test_mint_sentinel_shape() -> None:
    assert _SENTINEL_RE.fullmatch(mint_session_sentinel())


def test_is_authenticated_tri_state_contract() -> None:
    # The producer's tri-state contract, exercised directly and adversarially. Only a POSITIVE discriminator
    # (success_marker PRESENT) can score authenticated; logged_out_markers can ONLY disprove.
    ok200 = {"status": 200, "headers": [], "body": "<h1>Welcome back, admin</h1>"}
    plain200 = {"status": 200, "headers": [], "body": "<h1>Dashboard</h1>"}
    login401 = {"status": 401, "headers": [], "body": "nope"}

    # success_marker present ⇒ True; absent ⇒ False.
    sm = LoginSequence(url="http://app/login", success_marker="Welcome back")
    assert _is_authenticated(ok200, sm) is True
    assert _is_authenticated(plain200, sm) is False
    # a logged-out status overrides even a would-be marker match ⇒ False.
    assert _is_authenticated(login401, sm) is False

    # success_marker present AND a logged_out_marker also present ⇒ NOT authenticated (the "and no
    # logged_out_marker" clause): the absence discriminator negates the positive one.
    sm_and_lo = LoginSequence(url="http://app/login", success_marker="Welcome back",
                              logged_out_markers=("Sign in",))
    assert _is_authenticated({"status": 200, "headers": [],
                              "body": "Welcome back … Sign in"}, sm_and_lo) is False

    # logged_out_markers ONLY (no success_marker): can never PROVE auth ⇒ None regardless of the body. Without
    # a positive discriminator the check is indeterminate (the task's "regardless of logged_out_markers ⇒
    # None"); the absence discriminator cannot turn a bare 200 into a proven authenticated session, and the
    # oracle degrades to INCONCLUSIVE (never a FACT) either way.
    lo_only = LoginSequence(url="http://app/login", logged_out_markers=("Sign in",))
    assert _is_authenticated(plain200, lo_only) is None
    assert _is_authenticated({"status": 200, "headers": [], "body": "Please Sign in"}, lo_only) is None

    # No discriminator at all ⇒ None; a non-dict response ⇒ None even with a marker.
    assert _is_authenticated(plain200, LoginSequence(url="http://app/login")) is None
    assert _is_authenticated("not-a-dict", sm) is None


def test_vacuous_success_marker_never_scores_authenticated() -> None:
    # SLICE 3.2 round-3 regression (VACUOUS PREDICATE SATISFACTION): a success_marker that is empty,
    # pure whitespace, or too short is trivially `in` almost any body — the old `is None` guard let it
    # through and `marker in body` scored 'authenticated', minting a false CWE-384 FACT. Such a marker is NO
    # discriminator at all, so _is_authenticated must FAIL CLOSED to None regardless of the body.
    body_with_everything = {"status": 200, "headers": [],
                            "body": "<h1>Welcome back, admin</h1><p>SESSFIX-AUTHENTICATED</p>"}
    for vacuous in ("", "   ", "\t\n ", "a", "ab", " x "):   # '' / whitespace / 1-2 stripped chars
        sm = LoginSequence(url="http://app/login", success_marker=vacuous)
        assert _is_authenticated(body_with_everything, sm) is None, f"vacuous marker {vacuous!r} scored auth"
    # the shared guard states the contract directly.
    from framework.v2.scanner.session import valid_discriminator
    assert valid_discriminator("") is False
    assert valid_discriminator("   ") is False
    assert valid_discriminator("a") is False
    assert valid_discriminator("ab") is False
    assert valid_discriminator("abc") is True                 # >= 3 stripped chars
    assert valid_discriminator("SESSFIX-AUTHENTICATED") is True
    assert valid_discriminator(None) is False


def test_authenticated_state_requires_a_substantive_success_body() -> None:
    # SLICE 3.2 round-3 regression: even a VALID marker must not score 'authenticated' off a NON-substantive
    # read — an empty / too-short / error-or-deny 200. Such a body proves neither a live session NOR a clean,
    # so _is_authenticated fails closed to None (the oracle then stays INCONCLUSIVE, never a FACT/CLEAN).
    from framework.v2.scanner.session import is_substantive_success
    sm = LoginSequence(url="http://app/login", success_marker="SESSFIX-AUTHENTICATED")
    # empty and too-short bodies ⇒ None even at 200.
    assert _is_authenticated({"status": 200, "headers": [], "body": ""}, sm) is None
    assert _is_authenticated({"status": 200, "headers": [], "body": "   "}, sm) is None
    assert _is_authenticated({"status": 200, "headers": [], "body": "SESSFIX-A"}, sm) is None  # < 16 stripped
    # an ERROR/DENY 200 that COINCIDENTALLY contains the marker string ⇒ None (not scored authenticated).
    assert _is_authenticated(
        {"status": 200, "headers": [],
         "body": "Internal Server Error while rendering SESSFIX-AUTHENTICATED dashboard"}, sm) is None
    assert _is_authenticated(
        {"status": 200, "headers": [],
         "body": "Error: SESSFIX-AUTHENTICATED page temporarily unavailable"}, sm) is None
    # a 5xx that echoes the marker ⇒ None (not a 2xx at all).
    assert _is_authenticated(
        {"status": 500, "headers": [], "body": "<h1>SESSFIX-AUTHENTICATED</h1><p>server crashed</p>"}, sm) is None
    # the shared guard contract, directly.
    assert is_substantive_success(200, "<h1>SESSFIX-AUTHENTICATED</h1><p>Welcome back.</p>") is True
    assert is_substantive_success(200, "") is False
    assert is_substantive_success(200, "short") is False
    assert is_substantive_success(302, "<h1>SESSFIX-AUTHENTICATED</h1> plenty of body here") is False
    assert is_substantive_success(200, "Internal Server Error occurred, please retry later") is False
    # a genuine authenticated page AND a normal logged-out page are BOTH substantive successes (no FP).
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
    assert rec["authenticated_after_login"] is True
    outcome = OracleVerifier().confirm(ctx.to_verifier_context())
    assert outcome.confirmed
    assert any(s.kind is OracleKind.ACHIEVED_STATE and s.fired for s in outcome.signals)
    # round-trip: the retained context re-fires (a re-verifiable certificate)
    rebuilt = FindingContext.model_validate(ctx.model_dump())
    assert OracleVerifier().confirm(rebuilt.to_verifier_context()).confirmed


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
    assert not OracleVerifier().confirm(ctx.to_verifier_context()).confirmed


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


def test_no_fact_when_no_positive_auth_discriminator_is_supplied() -> None:
    # SLICE 3.2 regression (marker-absent degeneration — the path the other tests never exercise): when the
    # operator omits BOTH success_marker AND logged_out_markers there is no positive authenticated-state
    # discriminator, so a bare 200 protected page is NOT evidence of an authenticated session. Against a
    # NON-fixation app that never touches the VIGIL-fixed SESSION cookie (S1 == S0) and serves the protected
    # URL as a 200 login form, the old code scored 'authenticated' and minted a false CWE-384 FACT. It must
    # now be INCONCLUSIVE — never confirmed.
    def non_fixation_send(req: HttpRequest) -> dict:
        # login: 200, sets NO SESSION cookie (auths via a different mechanism); never overwrites SESSION.
        # protected page: a 200 login form for the (unauthenticated) fixed id.
        if req.method == "POST":
            return {"status": 200, "headers": [], "body": "<html>ok</html>"}
        return {"status": 200, "headers": [], "body": "<html><h1>Please log in</h1></html>"}

    login = LoginSequence(url="http://app/login", method="POST", body="user=a&password=b")  # NO markers
    assert login.success_marker is None and login.logged_out_markers == ()
    ctx = confirm_session_fixation(non_fixation_send, login=login, session_cookie="SESSION",
                                   protected_url="http://app/account")
    assert ctx is not None
    rec = ctx.session_fixation
    assert rec["post_auth_id"] == rec["sentinel_id"]      # the fixed id was NOT rotated (S1 == S0)
    assert rec["authenticated_after_login"] is None       # undecidable — no positive discriminator
    assert not OracleVerifier().confirm(ctx.to_verifier_context()).confirmed   # NO false FACT
    # the retained record re-verifies to the SAME non-confirmation (a stable, honest INCONCLUSIVE)
    rebuilt = FindingContext.model_validate(ctx.model_dump())
    assert not OracleVerifier().confirm(rebuilt.to_verifier_context()).confirmed


def test_logged_out_markers_only_cannot_prove_auth_no_fact() -> None:
    # SLICE 3.2 round-2 regression (positive-by-absence hole): the operator supplies ONLY logged_out_markers
    # and NO success_marker. logged_out_markers is an ABSENCE discriminator — its PRESENCE can DISPROVE auth,
    # its ABSENCE proves nothing. Against a NON-fixation app that never touches the VIGIL-fixed SESSION cookie
    # (S1 == S0) and serves the protected URL as a plain 200 with NO logout marker, the old code took the
    # non-logged-out 2xx as 'authenticated' and minted a FALSE CWE-384 FACT. The REAL _is_authenticated
    # producer (exercised end-to-end through confirm_session_fixation, not a pre-computed bool) must now yield
    # `None` (undecidable) so the oracle returns INCONCLUSIVE — never a FACT.
    def non_fixation_send(req: HttpRequest) -> dict:
        # login: 200, sets NO SESSION cookie (never overwrites the fixed id ⇒ S1 == S0).
        # protected page: a 200 that does NOT carry the logout marker — a non-logged-out 2xx the OLD code
        # would have scored authenticated purely by ABSENCE.
        if req.method == "POST":
            return {"status": 200, "headers": [], "body": "<html>ok</html>"}
        return {"status": 200, "headers": [], "body": "<html><h1>Dashboard</h1></html>"}

    # ONLY an absence discriminator — no positive success_marker.
    login = LoginSequence(url="http://app/login", method="POST", body="user=a&password=b",
                          logged_out_markers=("logout",))
    assert login.success_marker is None and login.logged_out_markers == ("logout",)
    ctx = confirm_session_fixation(non_fixation_send, login=login, session_cookie="SESSION",
                                   protected_url="http://app/account")
    assert ctx is not None
    rec = ctx.session_fixation
    assert rec["post_auth_id"] == rec["sentinel_id"]      # the fixed id was NOT rotated (S1 == S0)
    assert rec["authenticated_after_login"] is None       # undecidable — no POSITIVE discriminator
    assert not OracleVerifier().confirm(ctx.to_verifier_context()).confirmed   # NO false FACT
    # a logout marker PRESENT would still DISPROVE (return False) — the absence discriminator only ever
    # negates; it can never turn a bare 200 into a proven authenticated session.
    rebuilt = FindingContext.model_validate(ctx.model_dump())
    assert not OracleVerifier().confirm(rebuilt.to_verifier_context()).confirmed


def test_vacuous_marker_yields_no_fact_even_against_the_vulnerable_flow() -> None:
    # SLICE 3.2 round-3 regression, END-TO-END + DURABLE: against the GENUINELY-vulnerable planted flow (the
    # fixed id survives login unrotated, S1 == S0, and the protected page WOULD authenticate), a VACUOUS
    # success_marker must still mint NOTHING. The old code let '' / whitespace / a 1-char marker satisfy
    # `marker in body` and minted a false CWE-384 FACT; now the S0 probe records None and the oracle is
    # INCONCLUSIVE. Critically, the retained record re-verifies OFFLINE to the SAME non-confirmation — there
    # is no durable certificate that re-fires.
    for vacuous in ("", "   ", "a"):
        with serve() as base:
            ctx = confirm_session_fixation(
                _send,
                login=LoginSequence(url=f"{base}/sessfix/login", method="POST",
                                    body="user=admin&password=admin", success_marker=vacuous),
                session_cookie="SESSION",
                protected_url=f"{base}/sessfix/account",
            )
        assert ctx is not None
        rec = ctx.session_fixation
        assert rec["post_auth_id"] == rec["sentinel_id"]      # the fixed id SURVIVED login (still vulnerable)
        assert rec["authenticated_after_login"] is None       # vacuous marker ⇒ no positive discriminator
        assert not OracleVerifier().confirm(ctx.to_verifier_context()).confirmed   # NO false FACT (live)
        rebuilt = FindingContext.model_validate(ctx.model_dump())
        assert not OracleVerifier().confirm(rebuilt.to_verifier_context()).confirmed   # NO false FACT (offline)


def test_error_body_at_the_protected_page_yields_no_fact() -> None:
    # SLICE 3.2 round-3 regression, END-TO-END: the fixed id survives login unrotated (S1 == S0) but the
    # protected-page read is an ERROR 200 that COINCIDENTALLY echoes the success marker. A contains-check
    # against a non-substantive body proves nothing, so the S0 probe is None ⇒ INCONCLUSIVE, never a FACT and
    # never a false CLEAN — live and under offline re-verification alike.
    def erroring_send(req: HttpRequest) -> dict:
        if req.method == "POST":
            return {"status": 200, "headers": [], "body": "<html>ok, logged in</html>"}   # no Set-Cookie ⇒ S1==S0
        # protected GET: a bare error page that happens to contain the marker string.
        return {"status": 200, "headers": [],
                "body": f"Internal Server Error rendering {_SESSFIX_SUCCESS_MARKER} account"}

    login = LoginSequence(url="http://app/login", method="POST", body="user=a&password=b",
                          success_marker=_SESSFIX_SUCCESS_MARKER)
    ctx = confirm_session_fixation(erroring_send, login=login, session_cookie="SESSION",
                                   protected_url="http://app/account")
    assert ctx is not None
    rec = ctx.session_fixation
    assert rec["post_auth_id"] == rec["sentinel_id"]          # the fixed id was NOT rotated (S1 == S0)
    assert rec["authenticated_after_login"] is None           # error body ⇒ not a substantive success
    assert not OracleVerifier().confirm(ctx.to_verifier_context()).confirmed
    rebuilt = FindingContext.model_validate(ctx.model_dump())
    assert not OracleVerifier().confirm(rebuilt.to_verifier_context()).confirmed


def test_marker_absent_yields_no_fact_even_against_the_vulnerable_flow() -> None:
    # Even against the genuinely-vulnerable planted flow, dropping the success_marker removes the positive
    # authenticated-state discriminator, so VIGIL cannot soundly mint — an honest INCONCLUSIVE (a safe false
    # negative) beats a FACT it cannot prove. (Compare test_planted_fixation_flow_confirms_a_fact, which
    # supplies the marker and DOES confirm.)
    with serve() as base:
        ctx = confirm_session_fixation(
            _send,
            login=LoginSequence(url=f"{base}/sessfix/login", method="POST", body="user=admin&password=admin"),
            session_cookie="SESSION",
            protected_url=f"{base}/sessfix/account",
        )
    assert ctx is not None
    assert ctx.session_fixation["authenticated_after_login"] is None
    assert not OracleVerifier().confirm(ctx.to_verifier_context()).confirmed
