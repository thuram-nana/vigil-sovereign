"""
Wave-3.3 CSRF-achieved producer — a gated cross-site state change confirmed by the ACHIEVED
post-state, driven against the benchmark app's cookie-authenticated endpoints.

The state-changing write rides ONLY the ambient session cookie (no anti-CSRF token, no Origin
check); the driver issues the no-cookie control FIRST then the ambient-cookie treatment, and reads
the AUTHORITATIVE post-state after each. The FACT fires on ``/csrf/transfer`` (cookie-alone write
accepted); the benign twin ``/csrf/transfer-protected`` (an anti-CSRF token additionally required)
must NEVER fire. The retained ``oracle_context`` re-fires offline and a tampered readback no longer
confirms.

Deep-only: these endpoints are unlinked and POST-gated, so the default GET-only benchmark crawl
(``make gate``) never reaches them — the signed baseline stays byte-identical.
"""

from __future__ import annotations

import urllib.error
import urllib.parse
import urllib.request

from framework.v2.eval.benchmark_app import serve, _CSRF_SESSION_COOKIE_VALUE, _CSRF_TOKEN_VALUE
from framework.v2.scanner.csrf_achieved import (
    CsrfAchievedResult,
    confirm_csrf_achieved,
    csrf_achieved_finding,
)
from framework.v2.verify.adapter import FindingContext
from framework.v2.verify.models import OracleKind
from framework.v2.verify.verifier import BUG_CLASS_ORACLES, OracleVerifier, normalize_bug_class


def _drive(base: str, endpoint: str, *, csrf_token: str | None = None) -> CsrfAchievedResult:
    """Build submit / read_state callables against the benchmark app and run the differential.

    ``with_ambient_cookies`` attaches the ambient session cookie (a real browser sends it cross-site
    because the endpoint's cookie is SameSite=None); the no-cookie control omits it. ``csrf_token``,
    when set, is attached to BOTH writes — modelling an attacker who does NOT possess a valid token
    (the twin rejects the token-less write)."""
    write_url = base + endpoint
    read_url = base + ("/csrf/state-protected" if endpoint.endswith("protected") else "/csrf/state")

    def submit(*, with_ambient_cookies: bool, marker: str) -> None:
        form = {"marker": marker}
        if csrf_token is not None:
            form["csrf_token"] = csrf_token
        data = urllib.parse.urlencode(form).encode()
        req = urllib.request.Request(write_url, data=data, method="POST")
        req.add_header("Content-Type", "application/x-www-form-urlencoded")
        if with_ambient_cookies:
            req.add_header("Cookie", _CSRF_SESSION_COOKIE_VALUE)
        try:
            urllib.request.urlopen(req, timeout=5).read()
        except urllib.error.HTTPError:
            pass  # a 403 (control rejected / twin without token) is a legitimate no-state-change

    def read_state() -> str:
        return urllib.request.urlopen(read_url, timeout=5).read().decode("utf-8", "replace")

    return confirm_csrf_achieved(
        submit=submit, read_state=read_state, method="POST", endpoint=endpoint,
        # attaching an anti-CSRF token means the request is no longer ambient-cookie-ALONE, so the
        # driver honestly declares ambient_only=False (the oracle then refuses — not a CSRF).
        ambient_only=(csrf_token is None),
    )


# ---------------------------------------------------------------------------
# 1. Registration wiring
# ---------------------------------------------------------------------------


def test_csrf_achieved_is_registered_to_the_reused_achieved_state_kind() -> None:
    assert BUG_CLASS_ORACLES["csrf_achieved"] == (OracleKind.ACHIEVED_STATE,)
    assert normalize_bug_class("csrf_achieved") == "csrf_achieved"
    assert normalize_bug_class("achieved_csrf") == "csrf_achieved"
    assert normalize_bug_class("cross_site_state_change") == "csrf_achieved"
    # the achieved-state exploit is NOT folded onto the weaker `csrf` posture class
    assert normalize_bug_class("csrf") == "csrf"


# ---------------------------------------------------------------------------
# 2. FACT on the planted CSRF; SILENT on the token-protected twin
# ---------------------------------------------------------------------------


def test_planted_csrf_achieves_state_and_the_context_confirms() -> None:
    with serve() as base:
        r = _drive(base, "/csrf/transfer")
    assert isinstance(r, CsrfAchievedResult)
    assert r.channel_established and r.achieved
    assert r.marker in r.with_cookie_state and r.marker not in r.no_cookie_state
    outcome = OracleVerifier().confirm(r.context.to_verifier_context())
    assert outcome.confirmed
    assert any(s.kind is OracleKind.ACHIEVED_STATE and s.fired for s in outcome.signals)
    rebuilt = FindingContext.model_validate(r.context.model_dump())
    assert OracleVerifier().confirm(rebuilt.to_verifier_context()).confirmed


def test_token_protected_twin_never_fires() -> None:
    with serve() as base:
        # the attacker has ONLY the ambient cookie, no valid anti-CSRF token → write rejected
        r = _drive(base, "/csrf/transfer-protected")
    assert not r.achieved
    assert r.marker not in r.with_cookie_state
    assert not OracleVerifier().confirm(r.context.to_verifier_context()).confirmed


def test_twin_with_a_valid_token_still_is_not_csrf() -> None:
    # Even if the write lands with a valid token, the request is no longer ambient-cookie-ALONE, so
    # it is not a cross-site forgery — and here BOTH the control and treatment carry the token, so
    # the marker lands in both and the differential refuses.
    with serve() as base:
        r = _drive(base, "/csrf/transfer-protected", csrf_token=_CSRF_TOKEN_VALUE)
    assert not r.achieved
    assert not OracleVerifier().confirm(r.context.to_verifier_context()).confirmed


# ---------------------------------------------------------------------------
# 3. Tamper rejection + finding shape
# ---------------------------------------------------------------------------


def test_a_tampered_readback_no_longer_confirms() -> None:
    with serve() as base:
        r = _drive(base, "/csrf/transfer")
    ctx = r.context.model_dump()
    # strip the marker from the with-cookie readback → the achieved state no longer holds
    ctx["csrf_achieved"]["with_cookie_state"] = "<ul></ul>"
    tampered = FindingContext.model_validate(ctx)
    assert not OracleVerifier().confirm(tampered.to_verifier_context()).confirmed
    # or forge the control to also carry the marker → no longer attributable to the cookie
    ctx2 = r.context.model_dump()
    ctx2["csrf_achieved"]["no_cookie_state"] = ctx2["csrf_achieved"]["with_cookie_state"]
    assert not OracleVerifier().confirm(FindingContext.model_validate(ctx2).to_verifier_context()).confirmed


def test_csrf_achieved_finding_carries_the_retained_oracle_context() -> None:
    with serve() as base:
        r = _drive(base, "/csrf/transfer")
    finding = csrf_achieved_finding(r)
    assert finding["bug_class"] == "csrf_achieved"
    octx = finding["oracle_context"]
    assert octx.get("csrf_achieved")
    assert OracleVerifier().confirm(octx).confirmed
