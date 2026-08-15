"""Chat auto-heal (W2): a TRANSIENT backend blip (a 429, an overload/5xx, a dropped connection or a
timeout) is retried with bounded backoff so the operator's message self-recovers instead of a hard
"could not be reached". A PERMANENT error (bad request / auth) is NOT retried.
"""
from __future__ import annotations

import pytest

from framework.v2.console import chat


# --- classification --------------------------------------------------------------------------------
def test_retryable_classification():
    class RateLimitError(Exception):
        pass

    class Boom(Exception):
        status_code = 503

    class Perm(Exception):
        status_code = 400

    assert chat._chat_retryable(RateLimitError())     # by SDK exception name
    assert chat._chat_retryable(Boom())               # by retryable HTTP status
    assert not chat._chat_retryable(Perm())           # a permanent 4xx is not retried
    assert not chat._chat_retryable(ValueError("nope"))


# --- the backoff wrapper ---------------------------------------------------------------------------
def test_retries_a_transient_error_then_succeeds(monkeypatch):
    monkeypatch.setattr(chat.time, "sleep", lambda *_a: None)   # no real waiting

    class RateLimitError(Exception):
        pass

    calls = {"n": 0}

    def call(_blocks):
        calls["n"] += 1
        if calls["n"] < 3:
            raise RateLimitError()
        return "OK"

    assert chat._chat_call_with_backoff(call, ["x"]) == "OK"
    assert calls["n"] == 3                             # two transient failures, then success


def test_gives_up_after_max_attempts(monkeypatch):
    monkeypatch.setattr(chat.time, "sleep", lambda *_a: None)

    class RateLimitError(Exception):
        pass

    calls = {"n": 0}

    def call(_blocks):
        calls["n"] += 1
        raise RateLimitError()

    with pytest.raises(RateLimitError):
        chat._chat_call_with_backoff(call, ["x"])
    assert calls["n"] == chat._CHAT_MAX_ATTEMPTS       # bounded — never an unbounded retry loop


def test_a_permanent_error_is_not_retried(monkeypatch):
    monkeypatch.setattr(chat.time, "sleep", lambda *_a: None)

    class BadRequestError(Exception):
        status_code = 400

    calls = {"n": 0}

    def call(_blocks):
        calls["n"] += 1
        raise BadRequestError()

    with pytest.raises(BadRequestError):
        chat._chat_call_with_backoff(call, ["x"])
    assert calls["n"] == 1                             # gave up immediately — no wasted retries


def test_honours_retry_after_header(monkeypatch):
    slept: list[float] = []
    monkeypatch.setattr(chat.time, "sleep", lambda s: slept.append(s))

    class RateLimitError(Exception):
        def __init__(self):
            super().__init__("rate limited")
            self.response = type("R", (), {"headers": {"retry-after": "2"}})()

    calls = {"n": 0}

    def call(_blocks):
        calls["n"] += 1
        if calls["n"] < 2:
            raise RateLimitError()
        return "OK"

    assert chat._chat_call_with_backoff(call, ["x"]) == "OK"
    assert slept and slept[0] >= 2.0                   # waited at least the server-requested Retry-After


def test_backoff_is_bounded(monkeypatch):
    slept: list[float] = []
    monkeypatch.setattr(chat.time, "sleep", lambda s: slept.append(s))

    class OverloadedError(Exception):
        pass

    def call(_blocks):
        raise OverloadedError()

    with pytest.raises(OverloadedError):
        chat._chat_call_with_backoff(call, ["x"])
    assert all(s <= chat._CHAT_MAX_BACKOFF_S for s in slept)   # every wait capped
