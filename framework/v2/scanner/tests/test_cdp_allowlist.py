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
    # allowlisted + loopback pass
    assert _cdp_host_allowed("http://in-scope.test/api", allow) is True
    assert _cdp_host_allowed("http://127.0.0.1:8080/x", allow) is True
    assert _cdp_host_allowed("http://localhost/x", allow) is True
    # a NAMED off-allowlist host — and an IP-literal off-allowlist host — are refused
    assert _cdp_host_allowed("http://evil.example/x", allow) is False
    assert _cdp_host_allowed("http://10.0.0.5/x", allow) is False
    # same-document / non-network schemes carry no host → allowed (not egress)
    assert _cdp_host_allowed("data:text/html,<b>x</b>", allow) is True
    assert _cdp_host_allowed("about:blank", allow) is True
    # empty allowlist still admits loopback, refuses everything named
    assert _cdp_host_allowed("http://in-scope.test/x", set()) is False
    assert _cdp_host_allowed("http://127.0.0.1/x", set()) is True


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


def test_paused_loopback_request_is_continued() -> None:
    conn = _FakeConn()
    sess = CdpSession(conn)
    sess._allow_hosts = {"in-scope.test"}
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
    # the loopback `scan` default: no allowed_hosts → no request-allowlist gate
    br = CdpBrowser()
    assert br._allowed_hosts is None
