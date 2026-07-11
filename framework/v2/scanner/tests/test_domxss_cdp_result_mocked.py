"""
Mock-coverage for the CDP / browser DOM-XSS RESULT-handling — without a browser.

The live CDP tests (``test_cdp.py`` / ``test_browser_xss.py`` / ``test_spa_crawler.py``)
are skip-gated on a real Chromium, so the code that PARSES what the browser reports —
``CdpSession`` command results + event buffering, ``binding_calls`` (the DOM-XSS
execution signal), and ``confirm_dom_xss``'s executed/oracle-context handling — is not
verified by a normal run. Here we drive that logic with CANNED CDP frames (a fake WS
connection) and a STUB browser that "executes" a payload by echoing the injected
binding canary. The oracle then confirms over the resulting context, proving the
result-handling yields a re-verifiable DOM-XSS certificate. Chromium stays gated.

Complements ``test_cdp_allowlist.py`` (which fakes the WS conn for the egress
allowlist WRITE path); this file covers the READ / result path those tests do not.
"""

from __future__ import annotations

import json
import re
from collections import deque

import pytest

from framework.v2.scanner.cdp import CdpError, CdpSession
from framework.v2.scanner.browser_xss import (
    DomXssResult,
    _BINDING,
    _inject,
    confirm_dom_xss,
)
from framework.v2.verify.adapter import FindingContext
from framework.v2.verify.models import OracleKind
from framework.v2.verify.verifier import OracleVerifier

_CANARY_RE = re.compile(r"cxss[0-9]{2}[0-9a-f]{8}")


# ===========================================================================
# 1. CdpSession result-parsing driven by canned CDP frames (no browser)
# ===========================================================================


class _CannedConn:
    """A fake WS connection that hands back pre-queued CDP frames on ``recv_text``
    and records what the session ``send``s. ``auto_ack`` makes a command's result
    appear after any events queued before it, so interleaved-event buffering is
    exercised exactly as against a real browser."""

    def __init__(self) -> None:
        self.sent: list[dict] = []
        self._q: deque[str] = deque()
        self._auto: dict[str, dict] = {}

    def queue(self, *frames: dict) -> None:
        for f in frames:
            self._q.append(json.dumps(f))

    def auto_ack(self, method: str, result: dict) -> None:
        self._auto[method] = result

    def send_text(self, text: str) -> None:
        msg = json.loads(text)
        self.sent.append(msg)
        if msg["method"] in self._auto:
            self._q.append(json.dumps({"id": msg["id"], "result": self._auto[msg["method"]]}))

    def recv_text(self, *, timeout: float = 0.0) -> str:
        return self._q.popleft() if self._q else ""

    def close(self) -> None:
        return None


def test_send_returns_the_command_result_value() -> None:
    conn = _CannedConn()
    conn.auto_ack("Runtime.evaluate", {"result": {"value": 7}})
    sess = CdpSession(conn)
    assert sess.evaluate("3 + 4") == 7
    assert conn.sent[0]["method"] == "Runtime.evaluate"    # the command was actually issued


def test_send_raises_on_an_error_response() -> None:
    conn = _CannedConn()
    conn.queue({"id": 1, "error": {"code": -32000, "message": "eval blocked"}})
    sess = CdpSession(conn)
    with pytest.raises(CdpError):
        sess.send("Runtime.evaluate", {"expression": "x"})


def test_send_buffers_an_interleaved_event_while_awaiting_its_result() -> None:
    conn = _CannedConn()
    conn.auto_ack("Runtime.evaluate", {})
    # queued BEFORE the command runs -> recv returns it before the ack, so send() buffers it
    conn.queue({"method": "Runtime.bindingCalled", "params": {"name": _BINDING, "payload": "cxss00aabbccdd"}})
    sess = CdpSession(conn)
    sess.evaluate("noop")
    assert len(sess.events_of("Runtime.bindingCalled")) == 1


def test_binding_calls_extracts_only_the_named_binding_canaries() -> None:
    conn = _CannedConn()
    sess = CdpSession(conn)
    conn.queue(
        {"method": "Runtime.bindingCalled", "params": {"name": _BINDING, "payload": "cxss00deadbeef"}},
        {"method": "Runtime.bindingCalled", "params": {"name": _BINDING, "payload": "cxss01feedface"}},
        {"method": "Runtime.bindingCalled", "params": {"name": "some_other", "payload": "ignored"}},
        {"method": "Network.requestWillBeSent", "params": {}},   # unrelated event, buffered not returned
    )
    sess.drain_events(timeout=0.05)     # the read loop parses + buffers every frame
    assert sess.binding_calls(_BINDING) == ["cxss00deadbeef", "cxss01feedface"]


def test_wait_event_returns_the_first_matching_event() -> None:
    conn = _CannedConn()
    sess = CdpSession(conn)
    conn.queue({"method": "Page.loadEventFired", "params": {}})
    ev = sess.wait_event("Page.loadEventFired", timeout=0.1)
    assert ev is not None and ev["method"] == "Page.loadEventFired"
    # a canary event that never arrives -> None (no guess)
    assert sess.wait_event("Page.frameStoppedLoading", timeout=0.05) is None


def test_recv_of_a_non_json_frame_is_skipped_not_raised() -> None:
    conn = _CannedConn()
    sess = CdpSession(conn)
    conn._q.append("<<garbage not json>>")
    conn.queue({"method": "Runtime.bindingCalled", "params": {"name": _BINDING, "payload": "cxss00abcd1234"}})
    sess.drain_events(timeout=0.05)      # the garbled frame is skipped; the good one is buffered
    assert sess.binding_calls(_BINDING) == ["cxss00abcd1234"]


# ===========================================================================
# 2. confirm_dom_xss result-handling with a STUB browser that "executes"
# ===========================================================================


class _StubSession:
    """A stub CDP session that models a page: when ``vulnerable``, an injected payload
    'executes' — it echoes back the binding canary embedded in the navigated URL; when
    safe, no binding call happens (an inert/encoded reflection)."""

    def __init__(self, *, vulnerable: bool) -> None:
        self._vulnerable = vulnerable
        self._last_url = ""
        self.bound: list[str] = []

    def add_binding(self, name: str) -> None:
        self.bound.append(name)

    def navigate(self, url: str, *, settle: float = 0.4, timeout: float = 15.0) -> None:
        self._last_url = url

    def binding_calls(self, name: str) -> list[str]:
        if not self._vulnerable:
            return []
        m = _CANARY_RE.search(self._last_url)   # the payload put window.<name>('<canary>') into the URL
        return [m.group(0)] if m else []


class _StubBrowser:
    def __init__(self, *, vulnerable: bool) -> None:
        self._vulnerable = vulnerable

    def session(self) -> _StubSession:
        return _StubSession(vulnerable=self._vulnerable)


def test_inject_places_payload_in_query_param_and_fragment() -> None:
    q = _inject("http://127.0.0.1:9/p?a=1", "PAYLOAD", param="a", in_fragment=False)
    assert "a=PAYLOAD" in q and "a=1" not in q          # replaces the named param
    frag = _inject("http://127.0.0.1:9/p", "PAYLOAD", param=None, in_fragment=True)
    assert frag.endswith("#PAYLOAD")                    # fragment kept raw for hash sinks


def test_confirm_dom_xss_marks_execution_and_the_context_confirms_via_the_oracle() -> None:
    results = confirm_dom_xss("http://127.0.0.1:9/echo",
                              browser=_StubBrowser(vulnerable=True), settle=0.0)
    assert results and all(isinstance(r, DomXssResult) for r in results)
    assert all(r.executed for r in results)             # every payload 'executed' in the stub DOM
    r = results[0]
    assert r.bug_class == "dom_xss" and _CANARY_RE.fullmatch(r.canary)
    # the retained oracle context re-fires -> a real, re-verifiable DOM-execution certificate
    outcome = OracleVerifier().confirm(r.context.to_verifier_context())
    assert outcome.confirmed
    assert any(s.kind is OracleKind.DOM_EXECUTION and s.fired for s in outcome.signals)
    # and it round-trips through serialization (the certificate is portable)
    rebuilt = FindingContext.model_validate(r.context.model_dump())
    assert OracleVerifier().confirm(rebuilt.to_verifier_context()).confirmed


def test_confirm_dom_xss_on_a_safe_page_does_not_confirm() -> None:
    results = confirm_dom_xss("http://127.0.0.1:9/safe",
                              browser=_StubBrowser(vulnerable=False), settle=0.0)
    assert results and not any(r.executed for r in results)
    # no binding call -> the DOM-execution oracle correctly does NOT fire (no false positive)
    assert not OracleVerifier().confirm(results[0].context.to_verifier_context()).confirmed


def test_confirm_dom_xss_swallows_a_driver_error_as_no_execution() -> None:
    class _BoomSession(_StubSession):
        def navigate(self, url: str, *, settle: float = 0.4, timeout: float = 15.0) -> None:
            raise CdpError("navigation failed")

    class _BoomBrowser:
        def session(self) -> _BoomSession:
            return _BoomSession(vulnerable=True)

    results = confirm_dom_xss("http://127.0.0.1:9/x", browser=_BoomBrowser(), settle=0.0)
    # a driver failure yields no finding (a browser check never guesses), not a crash
    assert results and not any(r.executed for r in results)
