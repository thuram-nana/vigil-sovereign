"""
The CDP driver primitives — launch, navigate, evaluate, and the execution binding
that survives a navigation. Skip-gated on a Chromium/Chrome binary. All URLs are
inline ``data:`` documents; nothing leaves the host.
"""

from __future__ import annotations

import urllib.parse

import pytest

from framework.v2.scanner.cdp import CdpBrowser, cdp_available

pytestmark = pytest.mark.skipif(not cdp_available(), reason="no Chromium/Chrome for the CDP driver")


def _data(html: str, frag: str = "") -> str:
    u = "data:text/html," + urllib.parse.quote(html)
    return u + ("#" + urllib.parse.quote(frag) if frag else "")


def test_launch_and_evaluate() -> None:
    with CdpBrowser() as br:
        sess = br.session()
        sess.navigate(_data("<p>hi</p>"))
        assert sess.evaluate("6*7") == 42
        assert sess.evaluate("document.readyState") == "complete"


def test_binding_survives_navigation_and_captures_execution() -> None:
    with CdpBrowser() as br:
        sess = br.session()
        sess.add_binding("__probe")
        # the binding is installed in the new document after navigation
        sess.navigate(_data("<p>x</p>"))
        assert sess.evaluate("typeof window.__probe") == "function"
        # a script that runs invokes it; the call surfaces as an event
        sess.evaluate("window.__probe('RAN-abc123'); 1")
        sess.drain_events(timeout=0.5)
        assert "RAN-abc123" in sess.binding_calls("__probe")


def test_init_script_runs_before_page_scripts() -> None:
    with CdpBrowser() as br:
        sess = br.session()
        sess.add_binding("__probe")
        sess.add_init_script("window.__probe('INIT-xyz')")
        sess.navigate(_data("<p>x</p>"))
        assert "INIT-xyz" in sess.binding_calls("__probe")
