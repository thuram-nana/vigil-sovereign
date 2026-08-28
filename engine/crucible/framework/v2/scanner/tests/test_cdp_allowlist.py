"""
The fail-closed CDP request allowlist (§8) — the headless browser's own egress gated
per request at the CDP layer, so a page cannot pull the browser off-scope.

These tests exercise the DECISION and the paused-request handling WITHOUT a live
browser: `_cdp_host_allowed` is pure, and `_handle_paused` is driven with a fake WS
connection that records the CDP command the driver would send (continue vs. fail).
The live-browser end-to-end (resolver rules + this gate together) is covered by
scanner/tests/test_browser_egress.py, which is skip-gated on Chromium.
"""

from __future__ import annotations

import json

from framework.v2.scanner.cdp import CdpBrowser, CdpSession, _cdp_host_allowed


def test_host_allow_decision_is_fail_closed() -> None:
    allow = {"in-scope.test"}
    # allowlisted host passes
    assert _cdp_host_allowed("http://in-scope.test/api", allow) is True
    # A6: loopback is NOT unconditionally allowed — with a REMOTE-only allowlist, a page-initiated request to
    # the operator's own 127.0.0.1 services is REFUSED (closes the browser SSRF-to-local-services hole).
    assert _cdp_host_allowed("http://127.0.0.1:8080/x", allow) is False
    assert _cdp_host_allowed("http://localhost/x", allow) is False
    # a NAMED off-allowlist host — and an IP-literal off-allowlist host — are refused
    assert _cdp_host_allowed("http://evil.example/x", allow) is False
    assert _cdp_host_allowed("http://10.0.0.5/x", allow) is False
    # same-document / non-network schemes carry no host → allowed (not egress)
    assert _cdp_host_allowed("data:text/html,<b>x</b>", allow) is True
    assert _cdp_host_allowed("about:blank", allow) is True
    # empty allowlist refuses EVERYTHING named, INCLUDING loopback (A6)
    assert _cdp_host_allowed("http://in-scope.test/x", set()) is False
    assert _cdp_host_allowed("http://127.0.0.1/x", set()) is False


def test_loopback_allowed_only_when_the_scan_targets_loopback() -> None:
    # A6: when the scan's OWN allowlist targets loopback (a loopback target), loopback page requests are
    # allowed — and any loopback alias unlocks all of them (they denote the same host).
    allow = {"127.0.0.1"}
    assert _cdp_host_allowed("http://127.0.0.1:9000/x", allow) is True
    assert _cdp_host_allowed("http://localhost/x", allow) is True     # alias of the allowlisted loopback
    assert _cdp_host_allowed("http://[::1]/x", allow) is True
    assert _cdp_host_allowed("http://evil.example/x", allow) is False  # a remote host is still refused


class _FakeConn:
    """Records the raw CDP command frames the session writes; never reads."""

    def __init__(self) -> None:
        self.sent: list[dict] = []

    def send_text(self, text: str) -> None:
        self.sent.append(json.loads(text))

    def recv_text(self, *, timeout: float = 0.0) -> str:
        return ""

    def close(self) -> None:
        return None


def _paused_event(request_id: str, url: str) -> dict:
    return {"method": "Fetch.requestPaused",
            "params": {"requestId": request_id, "request": {"url": url}}}


def test_paused_request_to_off_scope_host_is_failed() -> None:
    conn = _FakeConn()
    sess = CdpSession(conn)
    sess._allow_hosts = {"in-scope.test"}
    # ingesting a paused request rides the read loop and resolves it inline
    sess._ingest(_paused_event("r1", "http://evil.example/steal"))
    assert len(conn.sent) == 1
    cmd = conn.sent[0]
    assert cmd["method"] == "Fetch.failRequest"
    assert cmd["params"]["requestId"] == "r1"
    assert cmd["params"]["errorReason"] == "AccessDenied"


def test_paused_request_to_in_scope_host_is_continued() -> None:
    conn = _FakeConn()
    sess = CdpSession(conn)
    sess._allow_hosts = {"in-scope.test"}
    sess._ingest(_paused_event("r2", "http://in-scope.test/api/items"))
    assert len(conn.sent) == 1
    cmd = conn.sent[0]
    assert cmd["method"] == "Fetch.continueRequest"
    assert cmd["params"]["requestId"] == "r2"


def test_paused_loopback_request_is_refused_with_a_remote_allowlist() -> None:
    # A6: a page-initiated loopback request under a REMOTE-only allowlist is REFUSED (failRequest) — a remote
    # target's page cannot drive the operator browser toward the operator's own 127.0.0.1 services.
    conn = _FakeConn()
    sess = CdpSession(conn)
    sess._allow_hosts = {"in-scope.test"}
    sess._ingest(_paused_event("r3", "http://127.0.0.1:9000/app.js"))
    assert conn.sent[0]["method"] == "Fetch.failRequest"


def test_paused_loopback_request_is_continued_when_scan_targets_loopback() -> None:
    # ...but when the scan itself targets loopback (a loopback host on the allowlist), loopback is continued.
    conn = _FakeConn()
    sess = CdpSession(conn)
    sess._allow_hosts = {"127.0.0.1"}
    sess._ingest(_paused_event("r3", "http://127.0.0.1:9000/app.js"))
    assert conn.sent[0]["method"] == "Fetch.continueRequest"


def test_interception_off_by_default_no_command_emitted() -> None:
    # without enable_request_allowlist, _allow_hosts is None → a paused event (which
    # would not even arrive, since Fetch is not enabled) is buffered, never actioned.
    conn = _FakeConn()
    sess = CdpSession(conn)
    assert sess._allow_hosts is None
    sess._ingest(_paused_event("r4", "http://evil.example/x"))
    assert conn.sent == []  # no continue/fail issued when interception is off


def test_unrestricted_browser_installs_no_allowlist() -> None:
    # the loopback `scan` default: no allowed_hosts → no request-allowlist gate.
    # An injected browser_path short-circuits find_browser() so this hermetic assertion needs no real
    # Chromium (audit F-07); start() is never called, so nothing launches (mirrors _browser() in
    # test_cdp_page_target_polling.py).
    br = CdpBrowser(browser_path="/nonexistent/chrome")
    assert br._allowed_hosts is None
