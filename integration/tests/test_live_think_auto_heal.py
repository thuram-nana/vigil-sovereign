"""Live-think auto-heal (W2b): a TRANSIENT backend blip on the OODA loop's think call is retried with
bounded backoff instead of fail-closing to ASK_USER and ending the engagement. A PERMANENT error is not
retried.
"""
from __future__ import annotations

from types import SimpleNamespace

import pytest

from vigil_integration.live import think_claude as tc


@pytest.fixture(autouse=True)
def _within_gateway_egress():
    """M4.1: think_claude._invoke asserts it runs INSIDE the gateway egress chokepoint (fail-closed).
    In production the retry loop runs inside ai_gateway.egress(); these UNIT tests drive
    _invoke_with_backoff directly, so enter the egress depth-context to mirror the real caller. This is
    test-local (the private depth contextvar) — NOT a public bypass API (which would defeat the gateway);
    it only sets in_egress()=True, exactly as the real egress() wrapper does around the same call."""
    from vigil_core import ai_gateway
    tok = ai_gateway._EGRESS_DEPTH.set(ai_gateway._EGRESS_DEPTH.get() + 1)
    try:
        yield
    finally:
        ai_gateway._EGRESS_DEPTH.reset(tok)


def test_retryable_classification():
    class RateLimitError(Exception):
        pass

    class Boom(Exception):
        status_code = 503

    class Perm(Exception):
        status_code = 400

    assert tc._think_retryable(RateLimitError())          # by SDK exception name
    assert tc._think_retryable(Boom())                    # by retryable HTTP status
    assert not tc._think_retryable(Perm())                # permanent 4xx
    assert not tc._think_retryable(ValueError("x"))


def _client(create):
    # a client whose messages has ONLY .create (no .stream) → _invoke falls back to messages.create.
    return SimpleNamespace(messages=SimpleNamespace(create=create))


def test_retries_a_transient_blip_then_succeeds(monkeypatch):
    monkeypatch.setattr(tc.time, "sleep", lambda *_a: None)

    class RateLimitError(Exception):
        pass

    calls = {"n": 0}

    def create(**_kw):
        calls["n"] += 1
        if calls["n"] < 2:
            raise RateLimitError()
        return "OK"

    assert tc._invoke_with_backoff(_client(create), {}) == "OK"
    assert calls["n"] == 2


def test_gives_up_after_bounded_attempts(monkeypatch):
    monkeypatch.setattr(tc.time, "sleep", lambda *_a: None)

    class OverloadedError(Exception):
        pass

    calls = {"n": 0}

    def create(**_kw):
        calls["n"] += 1
        raise OverloadedError()

    with pytest.raises(OverloadedError):
        tc._invoke_with_backoff(_client(create), {})
    assert calls["n"] == tc._THINK_MAX_ATTEMPTS


def test_a_permanent_error_is_not_retried(monkeypatch):
    monkeypatch.setattr(tc.time, "sleep", lambda *_a: None)

    class BadRequestError(Exception):
        status_code = 400

    calls = {"n": 0}

    def create(**_kw):
        calls["n"] += 1
        raise BadRequestError()

    with pytest.raises(BadRequestError):
        tc._invoke_with_backoff(_client(create), {})
    assert calls["n"] == 1                                # gave up immediately


def test_backoff_is_bounded(monkeypatch):
    slept: list[float] = []
    monkeypatch.setattr(tc.time, "sleep", lambda s: slept.append(s))

    class OverloadedError(Exception):
        pass

    def create(**_kw):
        raise OverloadedError()

    with pytest.raises(OverloadedError):
        tc._invoke_with_backoff(_client(create), {})
    assert all(s <= tc._THINK_MAX_BACKOFF_S for s in slept)
