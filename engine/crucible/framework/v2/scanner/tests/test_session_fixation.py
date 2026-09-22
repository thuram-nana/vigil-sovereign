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
from framework.v2.scanner.session import LoginSequence, confirm_session_fixation, mint_session_sentinel
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
