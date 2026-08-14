"""Regression guard for the CDP page-target STARTUP RACE.

The CI flake: a CDP launch read the DevTools ``/json`` endpoint the instant the debugger port appeared,
BEFORE the initial ``about:blank`` page target was registered, and hard-failed with
``CdpError("no page target exposed by the browser")`` — even though the very same browser exposed a page
target a beat later (the capability smoke in ``cdp_available()`` won the race, a later real launch lost it).

``_page_ws_url`` now POLLS for the page target within the launch window. These tests drive that logic over a
MOCKED ``/json`` endpoint, so they are browser-independent and run everywhere (no ``cdp_available`` skip)."""
from __future__ import annotations

import json

import pytest

from framework.v2.scanner.cdp import CdpBrowser, CdpError


class _FakeResp:
    def __init__(self, payload: bytes) -> None:
        self._p = payload

    def read(self) -> bytes:
        return self._p


def _browser(launch_timeout: float = 1.0) -> CdpBrowser:
    # A non-empty browser_path constructs the object without a real binary; we never call start() — the
    # port is set by hand and every /json read is mocked, so no browser is launched.
    br = CdpBrowser(browser_path="/nonexistent/chrome", launch_timeout=launch_timeout)
    br._port = 9999
    return br


def test_page_ws_url_polls_until_page_target_appears(monkeypatch) -> None:
    calls = {"n": 0}
    page = [{"type": "page", "webSocketDebuggerUrl": "ws://127.0.0.1:9999/devtools/page/AB"}]

    def fake_urlopen(url, timeout=None):
        calls["n"] += 1
        body = [] if calls["n"] < 3 else page      # no page target for the first two reads, then it appears
        return _FakeResp(json.dumps(body).encode())
    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)

    br = _browser()
    assert br._page_ws_url() == "ws://127.0.0.1:9999/devtools/page/AB"
    assert calls["n"] >= 3                          # it POLLED rather than raising on the first empty read


def test_page_ws_url_survives_a_transient_list_error(monkeypatch) -> None:
    calls = {"n": 0}
    page = [{"type": "page", "webSocketDebuggerUrl": "ws://127.0.0.1:9999/devtools/page/CD"}]

    def fake_urlopen(url, timeout=None):
        calls["n"] += 1
        if calls["n"] == 1:
            raise OSError("connection refused while the debugger settles")   # transient, not permanent
        return _FakeResp(json.dumps(page).encode())
    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)

    br = _browser()
    assert br._page_ws_url() == "ws://127.0.0.1:9999/devtools/page/CD"


def test_page_ws_url_times_out_when_no_page_target_ever(monkeypatch) -> None:
    def fake_urlopen(url, timeout=None):
        return _FakeResp(json.dumps([]).encode())   # a genuinely target-less browser: never a page
    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)

    br = _browser(launch_timeout=0.3)
    with pytest.raises(CdpError, match="no page target exposed by the browser"):
        br._page_ws_url()
