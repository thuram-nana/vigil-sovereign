"""Live-think auto-heal (W2b): a TRANSIENT backend blip on the OODA loop's think call is retried with
bounded backoff instead of fail-closing to ASK_USER and ending the engagement. A PERMANENT error is not
retried.
"""
from __future__ import annotations

from types import SimpleNamespace

import pytest

from vigil_integration.live import think_claude as tc


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
