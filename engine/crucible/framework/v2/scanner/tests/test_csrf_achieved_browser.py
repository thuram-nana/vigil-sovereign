"""
CSRF ACHIEVED — END-TO-END deep-profile assertion against a REAL SameSite-honoring headless browser and
the REAL benchmark app (Wave 3.3).

Skip-gated on a working headless Chromium (``scanner.cdp.cdp_available``), like the other live CDP tests,
so a browserless CI leg SKIPS this rather than failing (a browserless run yields no achieved-CSRF FACT —
never a false CLEAN; the deterministic derivation is covered by ``verify/tests/test_csrf_achieved_oracle.py``).

It drives the full path the plan specifies — from VIGIL's OWN attacker page on a GENUINELY different site
(``localhost`` vs the benchmark's ``127.0.0.1``), a top-level form POST to the target's state-changing
endpoint — and confirms the ``csrf_achieved`` oracle fires ONLY when the SameSite-honoring browser
ACTUALLY attaches the ambient session cookie cross-site:

  * ``/csrf/transfer`` with a ``SameSite=None`` session   => the browser sends the cookie => FACT;
  * ``/csrf/transfer`` with a ``SameSite=Strict`` session => the browser drops the cookie => NO fire
    (the SameSite dissolution the red-pen demanded — a urllib re-drive would falsely fire here);
  * ``/csrf/transfer-protected`` (anti-CSRF token required) => the token-less write is rejected => NO fire;
  * the same twin with a valid token attached => the observed request carries a token => NO fire
    (ambient_only is DERIVED from the observed request, not attested).

Plus offline re-verify and tamper-rejection on the DERIVED facts (a forged cross-origin origin or a
forged SameSite-block no longer confirms). Deliberately SEPARATE from the default benchmark corpus (the
routes are unlinked and need a browser + VIGIL's cross-site attacker), so ``make gate`` stays byte-identical.
"""

from __future__ import annotations

import pytest

from framework.v2.eval.benchmark_app import serve, _CSRF_SESSION_COOKIE_NAME, _CSRF_TOKEN_VALUE
from framework.v2.scanner.cdp import CdpBrowser, cdp_available
from framework.v2.scanner.csrf_achieved import confirm_csrf_achieved, csrf_achieved_finding
from framework.v2.verify.adapter import FindingContext
from framework.v2.verify.models import OracleKind
from framework.v2.verify.verifier import OracleVerifier

pytestmark = pytest.mark.skipif(not cdp_available(), reason="no usable headless Chromium for the CDP driver")


def _drive(base, browser, *, login_path, write_path, read_path, extra_form_fields=None):
    return confirm_csrf_achieved(
        target_base=base, login_path=login_path, write_path=write_path, read_path=read_path,
        ambient_cookie_name=_CSRF_SESSION_COOKIE_NAME, browser=browser,
        extra_form_fields=extra_form_fields, settle=1.2)


def test_samesite_none_target_achieves_cross_site_csrf_and_confirms() -> None:
    with serve() as base:
        browser = CdpBrowser().start()
        try:
            r = _drive(base, browser, login_path="/csrf/login",
                       write_path="/csrf/transfer", read_path="/csrf/state")
        finally:
            browser.stop()
    # the SameSite-honoring browser genuinely attached the ambient cookie to a cross-site write
    assert r.ambient_cookie_attached is True
    assert r.cross_site is True
    assert r.achieved is True
    assert r.marker in r.with_cookie_state and r.marker not in r.no_cookie_state
    # the initiator the browser attested is a genuinely different site than the target
    assert r.initiator_origin and r.initiator_origin != r.target_origin
    outcome = OracleVerifier().confirm(r.context.to_verifier_context())
    assert outcome.confirmed
    assert any(s.kind is OracleKind.ACHIEVED_STATE and s.fired for s in outcome.signals)
    # offline re-verify: rebuild the context from its serialized form and re-fire
    rebuilt = FindingContext.model_validate(r.context.model_dump())
    assert OracleVerifier().confirm(rebuilt.to_verifier_context()).confirmed


def test_samesite_strict_target_never_fires_the_dissolution() -> None:
    # A target defended by SameSite=Strict ALONE — impossible to CSRF in a real browser. The browser
    # refuses to attach the cookie cross-site, so NO state change is reached and the associated-cookie
    # observation carries a SameSite block. A urllib re-drive would falsely fire here; this must not.
    with serve() as base:
        browser = CdpBrowser().start()
        try:
            r = _drive(base, browser, login_path="/csrf/login?mode=strict",
                       write_path="/csrf/transfer", read_path="/csrf/state")
        finally:
            browser.stop()
    assert r.ambient_cookie_attached is False
    assert r.achieved is False
    assert r.marker not in r.with_cookie_state
    assert not OracleVerifier().confirm(r.context.to_verifier_context()).confirmed


def test_token_protected_twin_without_a_token_never_fires() -> None:
    # The attacker holds only the ambient cookie (SameSite=None, so it IS attached), but the endpoint
    # additionally requires a valid anti-CSRF token => the token-less write is rejected => no state change.
    with serve() as base:
        browser = CdpBrowser().start()
        try:
            r = _drive(base, browser, login_path="/csrf/login",
                       write_path="/csrf/transfer-protected", read_path="/csrf/state-protected")
        finally:
            browser.stop()
    assert r.achieved is False
    assert r.marker not in r.with_cookie_state
    assert not OracleVerifier().confirm(r.context.to_verifier_context()).confirmed


def test_write_carrying_a_token_is_not_ambient_cookie_only() -> None:
    # Even if a valid token lands the write, the OBSERVED request carries a token field => ambient_only is
    # DERIVED False => not a cross-site forgery => NO fire (the derivation, exercised end to end).
    with serve() as base:
        browser = CdpBrowser().start()
        try:
            r = _drive(base, browser, login_path="/csrf/login",
                       write_path="/csrf/transfer-protected", read_path="/csrf/state-protected",
                       extra_form_fields={"csrf_token": _CSRF_TOKEN_VALUE})
        finally:
            browser.stop()
    assert r.achieved is False
    assert not OracleVerifier().confirm(r.context.to_verifier_context()).confirmed


def test_tamper_on_the_derived_facts_no_longer_confirms() -> None:
    with serve() as base:
        browser = CdpBrowser().start()
        try:
            r = _drive(base, browser, login_path="/csrf/login",
                       write_path="/csrf/transfer", read_path="/csrf/state")
        finally:
            browser.stop()
    assert r.achieved is True  # baseline fires

    # (a) strip the marker from the with-cookie readback => no achieved state
    ctx = r.context.model_dump()
    ctx["csrf_achieved"]["with_cookie_state"] = "<ul></ul>"
    assert not OracleVerifier().confirm(FindingContext.model_validate(ctx).to_verifier_context()).confirmed

    # (b) forge the control to also carry the marker => not attributable to the cookie
    ctx = r.context.model_dump()
    ctx["csrf_achieved"]["no_cookie_state"] = ctx["csrf_achieved"]["with_cookie_state"]
    assert not OracleVerifier().confirm(FindingContext.model_validate(ctx).to_verifier_context()).confirmed

    # (c) forge the initiator origin to equal the target => the cross-origin topology is a lie
    ctx = r.context.model_dump()
    ctx["csrf_achieved"]["initiator_origin"] = ctx["csrf_achieved"]["target_origin"]
    assert not OracleVerifier().confirm(FindingContext.model_validate(ctx).to_verifier_context()).confirmed

    # (d) forge a SameSite block onto the observed associated cookie => browser did not attach it
    ctx = r.context.model_dump()
    ctx["csrf_achieved"]["associated_cookies"] = [
        {"name": _CSRF_SESSION_COOKIE_NAME, "blocked_reasons": ["SameSiteStrict"]}]
    assert not OracleVerifier().confirm(FindingContext.model_validate(ctx).to_verifier_context()).confirmed


def test_csrf_achieved_finding_carries_the_retained_oracle_context() -> None:
    with serve() as base:
        browser = CdpBrowser().start()
        try:
            r = _drive(base, browser, login_path="/csrf/login",
                       write_path="/csrf/transfer", read_path="/csrf/state")
        finally:
            browser.stop()
    finding = csrf_achieved_finding(r)
    assert finding["bug_class"] == "csrf_achieved"
    octx = finding["oracle_context"]
    assert octx.get("csrf_achieved")
    assert OracleVerifier().confirm(octx).confirmed


def test_producer_is_post_only() -> None:
    # The browser drive covers the classic top-level form POST vector; PUT/PATCH/DELETE cross-site
    # forgery is not browser-issuable and stays a LEAD — the producer refuses to pretend otherwise.
    with pytest.raises(ValueError):
        confirm_csrf_achieved(
            target_base="http://127.0.0.1:1", login_path="/csrf/login", write_path="/csrf/transfer",
            read_path="/csrf/state", ambient_cookie_name=_CSRF_SESSION_COOKIE_NAME, method="PUT")
