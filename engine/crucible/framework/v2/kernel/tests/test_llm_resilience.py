"""
Speed X4 — LLM resilience + load-balancing.

Three properties, each additive + default-safe:
  * the anthropic backend classifies transient failures (429 / overload / 5xx / connection),
    backs off honouring Retry-After, and raises BackendOverloaded when they persist;
  * the dispatch layer FAILS OVER to the next permitted backend in-tier on BackendOverloaded,
    but NOT on a permanent BackendError — and records the answering backend in the trace;
  * self-consistency runs its N samples through a bounded pool, gathering in submission order so
    the result is byte-identical to the serial run, with an opt-in rate limiter.
"""

from __future__ import annotations

import threading
from itertools import count
from types import SimpleNamespace

import pytest

from framework.v2.common.errors import BackendError, BackendOverloaded, BackendUnavailable
from framework.v2.kernel import llm
from framework.v2.kernel.backends import anthropic as A
from framework.v2.kernel.consistency import RateLimiter, run_consistent


# --------------------------------------------------------------- transient classifier


def _exc(status=None, name="Exception"):
    cls = type(name, (Exception,), {})
    e = cls()
    if status is not None:
        e.status_code = status
    return e


def test_classify_transient_by_status_and_class() -> None:
    for s in (408, 409, 429, 500, 502, 503, 504, 529):
        assert A._classify_transient(_exc(s))[0] is True
    for s in (400, 401, 403, 404, 422):
        assert A._classify_transient(_exc(s))[0] is False
    for nm in ("APIConnectionError", "APITimeoutError", "RateLimitError", "OverloadedError"):
        assert A._classify_transient(_exc(name=nm))[0] is True
    assert A._classify_transient(_exc(name="ValidationError"))[0] is False


def test_retry_after_seconds_numeric_only() -> None:
    e = _exc(429)
    e.response = SimpleNamespace(headers={"retry-after": "3"})
    assert A._retry_after_seconds(e) == 3.0
    # an HTTP-date Retry-After is ignored (we fall back to computed backoff), never raises.
    e.response = SimpleNamespace(headers={"retry-after": "Wed, 21 Oct 2015 07:28:00 GMT"})
    assert A._retry_after_seconds(e) is None
    assert A._retry_after_seconds(_exc(429)) is None            # no response attr


def test_retry_after_is_capped_no_unbounded_sleep() -> None:
    # Review MEDIUM: a hostile/misconfigured server sending an enormous Retry-After must NOT
    # cause a multi-day time.sleep — the honoured value is capped to the backoff ceiling.
    e = _exc(429)
    e.response = SimpleNamespace(headers={"retry-after": "999999"})
    assert A._retry_after_seconds(e) == A._MAX_RETRY_AFTER_S     # capped, not 999999


def test_backoff_wait_is_bounded_even_with_hostile_retry_after(monkeypatch) -> None:
    slept: list = []
    monkeypatch.setattr(A.time, "sleep", lambda s: slept.append(s))
    calls = count(1)

    class _Client:
        class messages:
            @staticmethod
            def create(**kw):
                if next(calls) == 1:
                    e = _exc(429)
                    e.response = SimpleNamespace(headers={"retry-after": "999999"})
                    raise e
                return "OK"

    _bare_anthropic()._create_with_backoff(
        _Client(), "s", "u", SimpleNamespace(temperature=0.2, max_tokens=8))
    assert slept == [A._MAX_RETRY_AFTER_S]                       # bounded, never 999999


# --------------------------------------------------------------- backend backoff loop


def _bare_anthropic():
    be = A.AnthropicBackend.__new__(A.AnthropicBackend)   # bypass __init__ (no SDK/key needed)
    be.model = "test-model"
    return be


def test_create_with_backoff_retries_transient_then_succeeds(monkeypatch) -> None:
    monkeypatch.setattr(A.time, "sleep", lambda s: sleeps.append(s))
    sleeps: list = []
    calls = count(1)

    class _Client:
        class messages:
            @staticmethod
            def create(**kw):
                if next(calls) < 3:
                    raise _exc(429)          # transient twice
                return "OK"

    prompt = SimpleNamespace(temperature=0.2, max_tokens=64)
    assert _bare_anthropic()._create_with_backoff(_Client(), "sys", "user", prompt) == "OK"
    assert len(sleeps) == 2                   # backed off before each of the 2 retries


def test_create_with_backoff_raises_overloaded_when_exhausted(monkeypatch) -> None:
    monkeypatch.setattr(A.time, "sleep", lambda s: None)

    class _Client:
        class messages:
            @staticmethod
            def create(**kw):
                raise _exc(503)

    with pytest.raises(BackendOverloaded):
        _bare_anthropic()._create_with_backoff(
            _Client(), "s", "u", SimpleNamespace(temperature=0.2, max_tokens=8))


def test_create_with_backoff_permanent_error_is_not_retried(monkeypatch) -> None:
    slept: list = []
    monkeypatch.setattr(A.time, "sleep", lambda s: slept.append(s))

    class _Client:
        class messages:
            @staticmethod
            def create(**kw):
                raise _exc(400)              # permanent

    with pytest.raises(BackendError) as ei:
        _bare_anthropic()._create_with_backoff(
            _Client(), "s", "u", SimpleNamespace(temperature=0.2, max_tokens=8))
    assert not isinstance(ei.value, BackendOverloaded)     # a plain BackendError, not overloaded
    assert slept == []                                     # never backed off a permanent failure


def test_honours_retry_after_over_computed_backoff(monkeypatch) -> None:
    slept: list = []
    monkeypatch.setattr(A.time, "sleep", lambda s: slept.append(s))
    calls = count(1)

    class _Client:
        class messages:
            @staticmethod
            def create(**kw):
                if next(calls) == 1:
                    e = _exc(429)
                    e.response = SimpleNamespace(headers={"retry-after": "7"})
                    raise e
                return "OK"

    _bare_anthropic()._create_with_backoff(
        _Client(), "s", "u", SimpleNamespace(temperature=0.2, max_tokens=8))
    assert slept == [7.0]                    # server-advised delay used verbatim


# --------------------------------------------------------------- dispatch failover


def _fake_backend(name, *, overloaded=False, permanent=False):
    class _B:
        pass
    b = _B()
    b.name = name
    b.is_available = lambda: (True, "ready")
    if overloaded:
        def _c(prompt):
            raise BackendOverloaded(f"{name} overloaded")
    elif permanent:
        def _c(prompt):
            raise BackendError(f"{name} bad request")
    else:
        def _c(prompt):
            return SimpleNamespace(parsed=f"answer-from-{name}",
                                   trace=SimpleNamespace(backend=name))
    b.complete = _c
    return b


def _wire(monkeypatch, order, backends):
    monkeypatch.delenv(llm._ENV_OVERRIDE, raising=False)
    monkeypatch.setattr(llm, "get_backend", lambda: backends[order[0]])
    monkeypatch.setattr(llm, "_construct", lambda nm: backends[nm])
    monkeypatch.setattr(llm.sovereignty, "current",
                        lambda: SimpleNamespace(permitted_preference=lambda: tuple(order)))


def test_failover_switches_to_next_permitted_on_overload(monkeypatch) -> None:
    backends = {"primary": _fake_backend("primary", overloaded=True),
                "secondary": _fake_backend("secondary")}
    _wire(monkeypatch, ["primary", "secondary"], backends)
    res = llm.complete_with_failover(prompt=SimpleNamespace())
    assert res.parsed == "answer-from-secondary"
    assert res.trace.backend == "secondary"          # the answering backend is recorded


def test_failover_does_not_trigger_on_permanent_error(monkeypatch) -> None:
    backends = {"primary": _fake_backend("primary", permanent=True),
                "secondary": _fake_backend("secondary")}
    _wire(monkeypatch, ["primary", "secondary"], backends)
    # a permanent BackendError is NOT failed over (another backend would not fix a 400).
    with pytest.raises(BackendError) as ei:
        llm.complete_with_failover(prompt=SimpleNamespace())
    assert not isinstance(ei.value, BackendOverloaded)


def test_failover_raises_overload_when_all_overloaded(monkeypatch) -> None:
    backends = {"primary": _fake_backend("primary", overloaded=True),
                "secondary": _fake_backend("secondary", overloaded=True)}
    _wire(monkeypatch, ["primary", "secondary"], backends)
    with pytest.raises(BackendOverloaded):
        llm.complete_with_failover(prompt=SimpleNamespace())


def test_env_override_is_honoured_without_failover(monkeypatch) -> None:
    chosen = _fake_backend("forced")
    monkeypatch.setenv(llm._ENV_OVERRIDE, "forced")
    monkeypatch.setattr(llm, "get_backend", lambda: chosen)
    res = llm.complete_with_failover(prompt=SimpleNamespace())
    assert res.trace.backend == "forced"             # explicit operator choice, used directly


# --------------------------------------------------------------- parallel self-consistency


def test_parallel_matches_serial_for_identical_samples() -> None:
    rf = lambda: ({"d": "sqli"}, {"t": 1})
    serial = run_consistent(rf, samples=5, key_fn=lambda v: v["d"], max_workers=1)
    par = run_consistent(rf, samples=5, key_fn=lambda v: v["d"], max_workers=4)
    assert serial.modal == par.modal == {"d": "sqli"}
    assert serial.n_samples == par.n_samples == 5
    assert serial.agreement == par.agreement == 1.0
    assert serial.entropy == par.entropy == 0.0


def test_parallel_clusters_a_majority_thread_safely() -> None:
    lock, ctr = threading.Lock(), count()
    values = ["a", "a", "a", "b", "c"]

    def rf():
        with lock:
            i = next(ctr)
        return ({"d": values[i]}, {"t": i})

    r = run_consistent(rf, samples=5, agreement_gate=0.5, key_fn=lambda v: v["d"], max_workers=4)
    assert r.n_samples == 5
    assert sorted(r.clusters.values()) == [1, 1, 3]      # same multiset regardless of order
    assert r.modal == {"d": "a"} and r.agreement == 0.6 and not r.abstained


def test_rate_limiter_is_invoked_once_per_sample() -> None:
    n = {"calls": 0}
    limiter_lock = threading.Lock()

    def limiter():
        with limiter_lock:
            n["calls"] += 1

    run_consistent(lambda: ({"d": "x"}, None), samples=3, max_workers=2,
                   rate_limiter=limiter, key_fn=lambda v: v["d"])
    assert n["calls"] == 3


def test_rate_limiter_min_interval_is_noop_when_zero() -> None:
    RateLimiter(0.0)()          # returns immediately, no sleep
    RateLimiter(-1.0)()
