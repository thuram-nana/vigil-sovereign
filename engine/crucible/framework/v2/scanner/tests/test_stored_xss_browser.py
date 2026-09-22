"""
Stored / second-order XSS — END-TO-END deep-profile assertion against a REAL browser
and the REAL benchmark app (Wave 2.1).

Skip-gated on a working headless Chromium (``scanner.cdp.cdp_available``), exactly
like the other live CDP tests, so a browserless CI leg SKIPS this rather than failing
(a browserless run yields no stored-XSS FACT — never a false CLEAN — which is covered
deterministically by ``test_stored_xss.py``).

It drives the full path the plan specifies: POST a unique execution canary at the
guestbook WRITE surface A through a gated write, then render the vulnerable render
surface B (``/guestbook/view``) in a real DOM and confirm the ``dom_execution`` oracle
fires — AND that the benign twin B' (``/guestbook/safe``, which HTML-escapes the same
persisted value) does NOT fire. This is deliberately SEPARATE from the default
benchmark corpus (the guestbook routes are unlinked and the store starts empty), so
``make gate`` stays byte-identical.
"""

from __future__ import annotations

import urllib.parse
import urllib.request

import pytest

from framework.v2.eval.benchmark_app import serve
from framework.v2.scanner.cdp import CdpBrowser, cdp_available
from framework.v2.scanner.stored_xss import confirm_stored_xss
from framework.v2.verify.models import OracleKind
from framework.v2.verify.verifier import OracleVerifier

pytestmark = pytest.mark.skipif(not cdp_available(), reason="no usable headless Chromium for the CDP driver")


def _gated_write_post(author: str):
    """A gated-write seam that performs the ONE state-changing POST at surface A.

    In a governed run this is where the Wave-0.3 owner-signed per-action approval is
    consumed before the write is issued; here (a test we own, loopback) it issues the
    approved POST directly. It stores the payload as ``comment`` under ``author`` so
    the render surface (``?name=<author>``) reads it back."""
    def gw(write_url: str, payload: str) -> bool:
        body = urllib.parse.urlencode({"name": author, "comment": payload}).encode("utf-8")
        req = urllib.request.Request(write_url, data=body, method="POST",
                                     headers={"Content-Type": "application/x-www-form-urlencoded"})
        with urllib.request.urlopen(req, timeout=10) as resp:  # noqa: S310 (loopback, owned target)
            return resp.status in (200, 201)
    return gw


def test_planted_stored_xss_facts_against_a_real_browser() -> None:
    with serve() as base:
        browser = CdpBrowser().start()
        try:
            results = confirm_stored_xss(
                f"{base}/guestbook",
                f"{base}/guestbook/view?name=victim",
                gated_write=_gated_write_post("victim"),
                browser=browser,
                settle=0.8,
            )
            executed = [r for r in results if r.executed]
            assert executed, "no payload executed on the render surface — stored-XSS not confirmed"
            r = executed[0]
            assert r.bug_class == "stored_xss" and r.written
            outcome = OracleVerifier().confirm(r.context.to_verifier_context())
            assert outcome.confirmed
            assert any(s.kind is OracleKind.DOM_EXECUTION and s.fired for s in outcome.signals)
        finally:
            browser.stop()


def test_benign_twin_escaped_render_never_facts_against_a_real_browser() -> None:
    with serve() as base:
        browser = CdpBrowser().start()
        try:
            results = confirm_stored_xss(
                f"{base}/guestbook",
                f"{base}/guestbook/safe?name=victim",   # B' HTML-escapes the persisted value → inert
                gated_write=_gated_write_post("victim"),
                browser=browser,
                settle=0.8,
            )
            assert results and all(r.written for r in results)
            assert not any(r.executed for r in results), "the escaped benign twin must NEVER execute"
            assert not OracleVerifier().confirm(results[0].context.to_verifier_context()).confirmed
        finally:
            browser.stop()
