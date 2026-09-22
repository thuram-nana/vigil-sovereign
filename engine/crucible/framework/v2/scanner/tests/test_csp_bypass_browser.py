"""
Content-Security-Policy — END-TO-END deep-profile assertion against a REAL browser and the REAL
benchmark app (Wave 2.4).

Skip-gated on a working headless Chromium (``scanner.cdp.cdp_available``), like the other live CDP
tests, so a browserless leg SKIPS rather than fails (a browserless run yields no achieved-bypass
FACT — never a false CLEAN — which is covered deterministically by ``test_csp_bypass.py``). The
posture claim needs no browser, so it is asserted here against the real served headers too.

It drives the full path the plan specifies:
  * ACHIEVED BYPASS — ``/csp-bypass`` enforces a RESTRICTIVE policy (``script-src 'self'
    'nonce-<STATIC>'``) but the nonce is STATIC/reusable across responses, so VIGIL reads it and
    reflects a ``<script nonce=<STATIC>>`` back in; the browser sees a matching nonce and EXECUTES
    the canary. A genuine bypass of a restrictive policy → the guarded ``dom_execution`` oracle
    fires. Benign twins: ``/csp-strict`` (``script-src 'self'``, no nonce) BLOCKS every injected
    script (no execution, no FACT); ``/csp-none`` (NO CSP) lets the img-onerror EXECUTE but the
    guard adjudicates plain DOM-XSS, never a bypass.
  * POSTURE — ``/csp-permissive`` (``'unsafe-inline'`` with no nonce) FACTs the posture claim from
    the retained header; ``/csp-wellformed`` (nonce, no permissive token) and ``/csp-neutralized``
    (``'unsafe-inline'`` beside a nonce → browser ignores it per CSP3) must NOT.

These routes are deliberately UNLINKED from the index and need a browser (bypass) or a header parse
(posture), so the default GET-only benchmark crawl never runs them and ``make gate`` stays
byte-identical.
"""

from __future__ import annotations

import urllib.request

import pytest

from framework.v2.eval.benchmark_app import serve
from framework.v2.scanner.cdp import CdpBrowser, cdp_available
from framework.v2.scanner.csp_bypass import capture_csp_posture, confirm_csp_bypass
from framework.v2.verify.models import OracleKind
from framework.v2.verify.verifier import OracleVerifier

pytestmark = pytest.mark.skipif(not cdp_available(), reason="no usable headless Chromium for the CDP driver")


def _headers(url: str):
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with opener.open(url, timeout=8.0) as resp:  # noqa: S310 (loopback benchmark app)
        return resp.headers


# ---------------------------------------------------------------------------
# Achieved CSP bypass
# ---------------------------------------------------------------------------


def test_planted_static_nonce_bypass_facts_against_a_real_browser() -> None:
    with serve() as base:
        browser = CdpBrowser().start()
        try:
            results = confirm_csp_bypass(f"{base}/csp-bypass", params=("q",), browser=browser, settle=1.0)
            bypassed = [r for r in results if r.bypassed]
            assert bypassed, "the static-nonce script did not execute under the restrictive CSP — no bypass"
            r = bypassed[0]
            assert r.bug_class == "csp_bypass" and r.executed and r.csp_purported_to_block
            assert r.nonces_reused, "the bypass must have reused the target's static script-src nonce"
            outcome = OracleVerifier().confirm(r.context.to_verifier_context())
            assert outcome.confirmed
            assert any(s.kind is OracleKind.DOM_EXECUTION and s.fired for s in outcome.signals)
        finally:
            browser.stop()


def test_strict_blocking_policy_benign_twin_never_facts() -> None:
    with serve() as base:
        browser = CdpBrowser().start()
        try:
            results = confirm_csp_bypass(f"{base}/csp-strict", params=("q",), browser=browser, settle=1.0)
            assert results, "the strict route produced no attempts"
            assert not any(r.executed for r in results), (
                "script-src 'self' with no nonce must BLOCK every injected script")
            assert not any(r.bypassed for r in results)
            assert not OracleVerifier().confirm(results[0].context.to_verifier_context()).confirmed
        finally:
            browser.stop()


def test_execution_on_a_no_csp_page_is_plain_dom_xss_not_a_bypass() -> None:
    with serve() as base:
        browser = CdpBrowser().start()
        try:
            results = confirm_csp_bypass(f"{base}/csp-none", params=("q",), browser=browser, settle=1.0)
            assert any(r.executed for r in results), "an img-onerror should execute with no CSP"
            # executed, but NO enforced CSP purported to block it -> plain DOM-XSS, never a bypass
            assert not any(r.bypassed for r in results)
            for r in results:
                assert not OracleVerifier().confirm(r.context.to_verifier_context()).confirmed
        finally:
            browser.stop()


# ---------------------------------------------------------------------------
# Permissive-policy posture (no browser needed; asserted against the real headers)
# ---------------------------------------------------------------------------


def test_planted_permissive_header_facts_the_posture_claim() -> None:
    with serve() as base:
        url = f"{base}/csp-permissive"
        res = capture_csp_posture(url, response_headers=_headers(url))
        assert res.is_weak and res.weaknesses
        outcome = OracleVerifier().confirm(res.context.to_verifier_context())
        assert outcome.confirmed
        assert any(s.kind is OracleKind.CSP_POSTURE and s.fired for s in outcome.signals)


def test_wellformed_and_neutralized_headers_never_fact_the_posture_claim() -> None:
    with serve() as base:
        for route in ("/csp-wellformed", "/csp-neutralized"):
            url = f"{base}{route}"
            res = capture_csp_posture(url, response_headers=_headers(url))
            assert not res.is_weak, f"{route} must not be flagged permissive"
            assert not OracleVerifier().confirm(res.context.to_verifier_context()).confirmed
