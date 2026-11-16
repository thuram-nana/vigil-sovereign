"""vigil_core.sdk_retry — an anthropic-SDK client never sleeps more than 60 s on a server's Retry-After.

SDK 2.x honours any positive Retry-After inside its own retry loop (SDK 0.x honoured only (0, 60] s), so one 429 with
``retry-after: 7200`` would stall a VIGIL call for two hours. ``cap_retry_after`` restores the 0.x rule as a response
hook on the client's HTTP layer: an out-of-bound or unreadable value is dropped and the SDK falls back to its own
bounded backoff.

Mutation-verify targets (each neuter reds a NAMED test here):
  * keep every Retry-After (no-op hook)              -> test_an_out_of_bound_or_unreadable_wait_is_dropped
  * raise the bound to 7200 s                        -> test_an_out_of_bound_or_unreadable_wait_is_dropped
  * drop an in-bound wait too                        -> test_an_in_bound_wait_is_kept
  * read retry-after-ms as seconds                   -> test_milliseconds_are_milliseconds
  * the client factory forgets the hook              -> test_the_real_sdk_never_sleeps_an_out_of_bound_retry_after
"""
from __future__ import annotations

import email.utils
import time

import pytest

from vigil_core import sdk_retry as sr


class _Resp:
    def __init__(self, **headers):
        self.headers = dict(headers)


def _future(seconds: float) -> str:
    return email.utils.formatdate(time.time() + seconds, usegmt=True)


@pytest.mark.parametrize("name,value", [
    ("retry-after", "7200"), ("retry-after", "60.5"), ("retry-after", "0"), ("retry-after", "-3"),
    ("retry-after", "soon"), ("retry-after", "nan"), ("retry-after", "inf"),
    ("retry-after-ms", "60001"), ("retry-after-ms", "0"), ("retry-after-ms", "x"),
])
def test_an_out_of_bound_or_unreadable_wait_is_dropped(name, value):
    r = _Resp(**{name: value})
    sr.cap_retry_after(r)
    assert name not in r.headers


@pytest.mark.parametrize("name,value", [
    ("retry-after", "1"), ("retry-after", "60"), ("retry-after", "2.5"), ("retry-after-ms", "500"),
    ("retry-after-ms", "60000"),
])
def test_an_in_bound_wait_is_kept(name, value):
    r = _Resp(**{name: value})
    sr.cap_retry_after(r)
    assert r.headers[name] == value


def test_milliseconds_are_milliseconds():
    r = _Resp(**{"retry-after-ms": "30000"})            # 30 s: in bound, kept
    sr.cap_retry_after(r)
    assert r.headers["retry-after-ms"] == "30000"
    r = _Resp(**{"retry-after-ms": "90000"})            # 90 s: dropped
    sr.cap_retry_after(r)
    assert "retry-after-ms" not in r.headers


def test_an_http_date_is_read_by_the_same_rule():
    near, far, past = _Resp(**{"retry-after": _future(20)}), _Resp(**{"retry-after": _future(3600)}), \
        _Resp(**{"retry-after": _future(-30)})
    for r in (near, far, past):
        sr.cap_retry_after(r)
    assert "retry-after" in near.headers
    assert "retry-after" not in far.headers and "retry-after" not in past.headers


def test_the_hook_never_raises_and_leaves_other_headers_alone():
    class _Weird:
        headers = None
    sr.cap_retry_after(_Weird())                         # no headers at all
    sr.cap_retry_after(object())
    r = _Resp(**{"retry-after": "7200", "request-id": "req_1", "x-should-retry": "true"})
    sr.cap_retry_after(r)
    assert r.headers == {"request-id": "req_1", "x-should-retry": "true"}


def test_the_real_sdk_never_sleeps_an_out_of_bound_retry_after(monkeypatch):
    """Through the REAL anthropic SDK (2.8+, offline): a 429 with retry-after 7200 is retried after the SDK's own short
    backoff, not after two hours; an in-bound retry-after 5 is honoured as asked. Skipped where the SDK (an opt-in
    extra no lock pins) is not installed."""
    anthropic = pytest.importorskip("anthropic", minversion="2.8.0")
    httpx2 = pytest.importorskip("httpx2")
    import anthropic._base_client as base

    slept: list = []
    monkeypatch.setattr(base.time, "sleep", lambda s: slept.append(s))
    for advised, expect in (("7200", lambda s: s <= 8.0), ("5", lambda s: s == 5.0)):
        calls = {"n": 0}
        slept.clear()

        def handler(req, advised=advised, calls=calls):
            calls["n"] += 1
            if calls["n"] == 1:
                return httpx2.Response(429, headers={"retry-after": advised},
                                       json={"type": "error", "error": {"type": "rate_limit_error", "message": "x"}})
            return httpx2.Response(200, json={
                "id": "msg_1", "type": "message", "role": "assistant", "model": "claude-opus-4-8",
                "content": [{"type": "text", "text": "ok"}], "stop_reason": "end_turn", "stop_sequence": None,
                "usage": {"input_tokens": 1, "output_tokens": 1}})

        client = anthropic.Anthropic(api_key="sk-test-offline", base_url="http://127.0.0.1:9",
                                     http_client=sr.bounded_http_client(transport=httpx2.MockTransport(handler)))
        client.messages.create(model="claude-opus-4-8", max_tokens=8, messages=[{"role": "user", "content": "x"}])
        assert calls["n"] == 2 and len(slept) == 1 and expect(slept[0]), (advised, slept)
