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
        _Client(), "s", "u", SimpleNamespace(temperature=0.2, max_tokens=8, effort=None))
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

    prompt = SimpleNamespace(temperature=0.2, max_tokens=64, effort=None)
    assert _bare_anthropic()._create_with_backoff(_Client(), "sys", "user", prompt) == "OK"
    assert len(sleeps) == 2                   # backed off before each of the 2 retries


def test_temperature_only_sent_to_models_that_accept_it(monkeypatch) -> None:
    # A CURRENT model (opus-5/sonnet-5/opus-4.8/4.7/fable) 400s if `temperature` is sent; a legacy model
    # accepts it. The backend must attach temperature ONLY for a sampling-capable model — else the picker's
    # own default (claude-opus-5) hard-fails every call.
    monkeypatch.setattr(A.time, "sleep", lambda s: None)
    captured: dict = {}

    class _Client:
        class messages:
            @staticmethod
            def create(**kw):
                captured.clear()
                captured.update(kw)
                return "OK"

    prompt = SimpleNamespace(temperature=0.2, max_tokens=64, effort=None)

    be = _bare_anthropic()
    be.model = "claude-opus-5"
    be._create_with_backoff(_Client(), "sys", "user", prompt)
    assert "temperature" not in captured and captured["model"] == "claude-opus-5"

    be = _bare_anthropic()
    be.model = "claude-sonnet-4-6"
    be._create_with_backoff(_Client(), "sys", "user", prompt)
    assert captured["extra_body"]["temperature"] == 0.2   # legacy model still gets it (in the body: SDK v1+ has no
    assert "temperature" not in captured                  # `temperature` keyword, and 2026-10-21 refuses it)

    assert A._supports_sampling("claude-sonnet-5") is False
    assert A._supports_sampling("claude-opus-4-8") is False
    assert A._supports_sampling("claude-haiku-4-5") is True


# --------------------------------------------------------------- reasoning effort (A3)


def test_sampling_create_kwargs_effort_vs_temperature(monkeypatch) -> None:
    monkeypatch.delenv("CRUCIBLE_EFFORT", raising=False)
    # older model → its temperature ONLY (in the body, on the legacy API version that still takes it — the anthropic
    # SDK v1+ has no `temperature` keyword), never output_config.effort
    assert llm.sampling_create_kwargs("claude-haiku-4-5", 0.2, "high") == {
        "extra_headers": {"anthropic-version": "2023-06-01"}, "extra_body": {"temperature": 0.2}}
    # current model + no effort (no env) → {} (the model's own default; NEVER temperature/budget_tokens)
    assert llm.sampling_create_kwargs("claude-opus-5", 0.2, None) == {}
    # current model + explicit effort → output_config.effort, no temperature
    assert llm.sampling_create_kwargs("claude-opus-5", 0.2, "high") == {"output_config": {"effort": "high"}}
    # env default applies when no explicit; explicit overrides env; unknown value is ignored (model default)
    monkeypatch.setenv("CRUCIBLE_EFFORT", "max")
    assert llm.sampling_create_kwargs("claude-opus-5", 0.2, None) == {"output_config": {"effort": "max"}}
    assert llm.sampling_create_kwargs("claude-opus-5", 0.2, "low") == {"output_config": {"effort": "low"}}
    monkeypatch.setenv("CRUCIBLE_EFFORT", "bogus")
    assert llm.sampling_create_kwargs("claude-opus-5", 0.2, None) == {}
    assert set(llm.EFFORT_LEVELS) == {"low", "medium", "high", "xhigh", "max"}


def test_effort_threaded_into_anthropic_create_kwargs(monkeypatch) -> None:
    monkeypatch.setattr(A.time, "sleep", lambda s: None)
    monkeypatch.delenv("CRUCIBLE_EFFORT", raising=False)
    captured: dict = {}

    class _Client:
        class messages:
            @staticmethod
            def create(**kw):
                captured.clear()
                captured.update(kw)
                return "OK"

    be = _bare_anthropic()
    be.model = "claude-opus-5"
    be._create_with_backoff(_Client(), "s", "u", SimpleNamespace(temperature=0.2, max_tokens=8, effort="xhigh"))
    assert captured.get("output_config") == {"effort": "xhigh"} and "temperature" not in captured
    assert "budget_tokens" not in captured                     # never sent (deprecated / 400 on current models)
    # no effort + no env on a current model → neither knob
    be._create_with_backoff(_Client(), "s", "u", SimpleNamespace(temperature=0.2, max_tokens=8, effort=None))
    assert "output_config" not in captured and "temperature" not in captured


def test_create_with_backoff_raises_overloaded_when_exhausted(monkeypatch) -> None:
    monkeypatch.setattr(A.time, "sleep", lambda s: None)

    class _Client:
        class messages:
            @staticmethod
            def create(**kw):
                raise _exc(503)

    with pytest.raises(BackendOverloaded):
        _bare_anthropic()._create_with_backoff(
            _Client(), "s", "u", SimpleNamespace(temperature=0.2, max_tokens=8, effort=None))


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
            _Client(), "s", "u", SimpleNamespace(temperature=0.2, max_tokens=8, effort=None))
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
        _Client(), "s", "u", SimpleNamespace(temperature=0.2, max_tokens=8, effort=None))
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



# --------------------------------------------------------------- anthropic SDK v1/v2 (Dependabot #1122 / #1125)
# The SDK v1 removed `temperature` / `top_p` / `top_k` from `messages.create()` (a TypeError), and API version
# 2026-10-21 — the v2 default — refuses them (a 400). An older model keeps its temperature on the legacy API version.
# Mutation-verify targets:
#   * send a top-level `temperature` again                    -> test_an_older_model_never_gets_a_temperature_keyword
#   * pin every platform's legacy version in a header          -> test_each_platform_pins_its_own_legacy_version
#   * read a Bedrock inference-profile id as an older model     -> test_a_platform_prefixed_current_model_is_current
#   * an unknown platform falls back to the first-party version -> test_an_unknown_platform_is_a_caller_bug


@pytest.mark.parametrize("platform", ["anthropic", "bedrock", "vertex"])
@pytest.mark.parametrize("model", ["claude-haiku-4-5", "claude-sonnet-4-6", "anthropic.claude-3-5-sonnet-20241022-v2:0"])
def test_an_older_model_never_gets_a_temperature_keyword(model, platform) -> None:
    kw = llm.sampling_create_kwargs(model, 0.3, "high", platform=platform)
    assert not {"temperature", "top_p", "top_k"} & set(kw), kw        # never a keyword the SDK no longer has
    assert kw["extra_body"]["temperature"] == 0.3 and "output_config" not in kw


def test_each_platform_pins_its_own_legacy_version() -> None:
    assert llm.sampling_create_kwargs("claude-haiku-4-5", 0.2, None, platform="anthropic") == {
        "extra_headers": {"anthropic-version": "2023-06-01"}, "extra_body": {"temperature": 0.2}}
    assert llm.sampling_create_kwargs("claude-haiku-4-5", 0.2, None, platform="bedrock") == {
        "extra_body": {"anthropic_version": "bedrock-2023-05-31", "temperature": 0.2}}
    assert llm.sampling_create_kwargs("claude-haiku-4-5", 0.2, None, platform="vertex") == {
        "extra_body": {"anthropic_version": "vertex-2023-10-16", "temperature": 0.2}}


@pytest.mark.parametrize("model", ["anthropic.claude-opus-4-8-v1:0", "us.anthropic.claude-opus-4-7-v1:0",
                                   "eu.anthropic.claude-sonnet-5-v1:0", "claude-opus-4-8"])
def test_a_platform_prefixed_current_model_is_current(model, monkeypatch) -> None:
    monkeypatch.delenv("CRUCIBLE_EFFORT", raising=False)
    assert llm.is_current_model(model) is True
    assert llm.sampling_create_kwargs(model, 0.2, "high", platform="bedrock") == {"output_config": {"effort": "high"}}
    assert llm.is_current_model("xclaude-opus-4-8") is False          # only a dotted platform prefix is stripped


@pytest.mark.parametrize("model", ["claude-haiku-4-5", "claude-opus-4-8"])
def test_an_unknown_platform_is_a_caller_bug(model, monkeypatch) -> None:
    # for an older AND a current model: the platform is checked before the model-family split (never a silent default)
    monkeypatch.setenv("CRUCIBLE_EFFORT", "high")
    with pytest.raises(KeyError):
        llm.sampling_create_kwargs(model, 0.2, None, platform="azure")


@pytest.mark.parametrize("model", ["claude-haiku-5-5", "claude-opus-5-5", "claude-sonnet-5-5", "claude-fable-5-1",
                                   "us.anthropic.claude-haiku-5-5-v1:0"])
def test_every_claude_5_model_is_current(model, monkeypatch) -> None:
    """Claude Haiku 5.5 was missing from the current-model list, so it went down the older route (a temperature on the
    legacy API version) and a current model rejects a temperature. Every Claude 5 model takes effort, never sampling."""
    monkeypatch.delenv("CRUCIBLE_EFFORT", raising=False)
    assert llm.is_current_model(model) is True
    assert llm.sampling_create_kwargs(model, 0.2, "high") == {"output_config": {"effort": "high"}}


def test_the_first_party_backend_keeps_an_older_model_on_its_legacy_version(monkeypatch) -> None:
    """The first-party backend passes the helper's kwargs straight to messages.create: an older model goes out with the
    legacy anthropic-version header and its temperature in the body; a current model with neither (red-pen B-EV-02)."""
    monkeypatch.delenv("CRUCIBLE_EFFORT", raising=False)
    captured: dict = {}

    class _Client:
        class messages:
            @staticmethod
            def create(**kw):
                captured.clear()
                captured.update(kw)
                return "OK"

    prompt = SimpleNamespace(temperature=0.2, max_tokens=64, effort="high")
    be = _bare_anthropic()
    be.model = "claude-sonnet-4-6"
    be._create_with_backoff(_Client(), "sys", "user", prompt)
    assert captured["extra_headers"] == {"anthropic-version": "2023-06-01"}
    assert captured["extra_body"] == {"temperature": 0.2} and "output_config" not in captured
    be.model = "claude-opus-4-8"
    be._create_with_backoff(_Client(), "sys", "user", prompt)
    assert "extra_headers" not in captured and "extra_body" not in captured
    assert captured["output_config"] == {"effort": "high"}


def test_the_real_sdk_sends_what_the_helper_builds(monkeypatch) -> None:
    """Against the REAL anthropic SDK (v1+), offline: an older model goes out on 2023-06-01 with its temperature in the
    body; a current model on the SDK's default version with its effort and no temperature. Skipped where the SDK (an
    opt-in extra no lock pins) is not installed."""
    anthropic = pytest.importorskip("anthropic", minversion="2.8.0")
    httpx2 = pytest.importorskip("httpx2")
    import json
    monkeypatch.delenv("CRUCIBLE_EFFORT", raising=False)
    seen: dict = {}

    def handler(req):
        seen["version"] = req.headers.get("anthropic-version")
        seen["body"] = json.loads(req.content)
        return httpx2.Response(200, json={
            "id": "msg_1", "type": "message", "role": "assistant", "model": seen["body"]["model"],
            "content": [{"type": "text", "text": "ok"}], "stop_reason": "end_turn", "stop_sequence": None,
            "usage": {"input_tokens": 1, "output_tokens": 1}})

    client = anthropic.Anthropic(api_key="sk-test-offline", base_url="http://127.0.0.1:9", max_retries=0,
                                 http_client=anthropic.DefaultHttpxClient(transport=httpx2.MockTransport(handler)))
    base = {"max_tokens": 8, "messages": [{"role": "user", "content": "x"}]}
    client.messages.create(model="claude-haiku-4-5", **base,
                           **llm.sampling_create_kwargs("claude-haiku-4-5", 0.2, "high"))
    assert seen["version"] == "2023-06-01" and seen["body"]["temperature"] == 0.2
    assert "output_config" not in seen["body"]
    client.messages.create(model="claude-opus-4-8", **base, **llm.sampling_create_kwargs("claude-opus-4-8", 0.2, "high"))
    assert seen["version"] != "2023-06-01" and "temperature" not in seen["body"]
    assert seen["body"]["output_config"] == {"effort": "high"}


@pytest.mark.parametrize("platform,module", [("bedrock", "anthropic.lib.bedrock._client"),
                                             ("vertex", "anthropic.lib.vertex._client")])
def test_the_real_sdk_keeps_the_legacy_body_version_on_bedrock_and_vertex(platform, module) -> None:
    """The v2 SDK sets the body's anthropic_version with ``setdefault`` AFTER merging extra_body, so the legacy version
    the helper sends survives (an older model on Bedrock is not served 2026-10-21)."""
    pytest.importorskip("anthropic", minversion="2.8.0")
    import importlib
    from anthropic._models import FinalRequestOptions
    mod = importlib.import_module(module)
    kw = llm.sampling_create_kwargs("claude-haiku-4-5", 0.2, None, platform=platform)
    opts = FinalRequestOptions.construct(method="post", url="/v1/messages",
                                         json_data={"model": "claude-haiku-4-5", **kw["extra_body"]})
    if platform == "bedrock":
        out = mod._prepare_options(opts)
    else:
        out = mod._prepare_options(opts, project_id="p", region="europe-west4")
    assert out.json_data["anthropic_version"] == kw["extra_body"]["anthropic_version"]
    assert out.json_data["temperature"] == 0.2


@pytest.mark.parametrize("modname,cls,version", [("bedrock", "BedrockBackend", "bedrock-2023-05-31"),
                                                 ("vertex", "VertexBackend", "vertex-2023-10-16")])
def test_each_cloud_backend_sends_its_own_platform_legacy_version(modname, cls, version, monkeypatch) -> None:
    """The Bedrock / Vertex backends name their own platform, so an older model there is kept on THAT platform's
    legacy body version (never the first-party header), with its temperature in the body."""
    import importlib

    from pydantic import BaseModel

    from framework.v2.kernel.llm import Prompt
    monkeypatch.delenv("CRUCIBLE_EFFORT", raising=False)
    mod = importlib.import_module(f"framework.v2.kernel.backends.{modname}")
    seen: dict = {}

    class _Messages:
        @staticmethod
        def create(**kw):
            seen.update(kw)
            return SimpleNamespace(content=[SimpleNamespace(type="text", text='{"ok": true}')],
                                   usage=SimpleNamespace(input_tokens=1, output_tokens=1))

    be = getattr(mod, cls).__new__(getattr(mod, cls))          # bypass __init__ (no cloud SDK / credentials)
    be.model, be.zdr = "claude-haiku-4-5", False
    if modname == "bedrock":
        be.region = "eu-west-1"
    else:
        be.region, be.project = "europe-west4", "p"
    be._client_obj = lambda: SimpleNamespace(messages=_Messages())

    class _S(BaseModel):
        ok: bool

    be.complete(Prompt(system="s", user="u", schema=_S, schema_name="S", cognitive_doc="", temperature=0.2,
                       max_tokens=32))
    assert seen["extra_body"] == {"anthropic_version": version, "temperature": 0.2}
    assert "extra_headers" not in seen and "temperature" not in seen


def test_the_real_bedrock_client_sends_the_legacy_body_version_end_to_end() -> None:
    """End to end through the REAL ``AnthropicBedrock`` client (offline: a mock transport, dummy AWS keys), not the
    SDK-private request hook: VIGIL's default Bedrock model (an older one) goes out on bedrock-2023-05-31 with its
    temperature; a current Bedrock inference profile on the SDK's own version with its effort and no temperature.
    Skipped where the SDK (an opt-in extra) or botocore (its Bedrock signer) is not installed."""
    anthropic = pytest.importorskip("anthropic", minversion="2.8.0")
    httpx2 = pytest.importorskip("httpx2")
    pytest.importorskip("botocore")
    import json
    seen: dict = {}

    def handler(req):
        seen["body"] = json.loads(req.content)
        return httpx2.Response(200, json={
            "id": "msg_1", "type": "message", "role": "assistant", "model": "m",
            "content": [{"type": "text", "text": "ok"}], "stop_reason": "end_turn", "stop_sequence": None,
            "usage": {"input_tokens": 1, "output_tokens": 1}})

    client = anthropic.AnthropicBedrock(aws_region="eu-west-1", aws_access_key="AKIAEXAMPLE", aws_secret_key="x",
                                        http_client=anthropic.DefaultHttpxClient(
                                            transport=httpx2.MockTransport(handler)))
    base = {"max_tokens": 8, "messages": [{"role": "user", "content": "x"}]}
    older, current = "anthropic.claude-3-5-sonnet-20241022-v2:0", "us.anthropic.claude-opus-4-8-v1:0"
    client.messages.create(model=older, **base, **llm.sampling_create_kwargs(older, 0.2, "high", platform="bedrock"))
    assert seen["body"]["anthropic_version"] == "bedrock-2023-05-31" and seen["body"]["temperature"] == 0.2
    client.messages.create(model=current, **base,
                           **llm.sampling_create_kwargs(current, 0.2, "high", platform="bedrock"))
    assert seen["body"]["anthropic_version"] != "bedrock-2023-05-31" and "temperature" not in seen["body"]
    assert seen["body"]["output_config"] == {"effort": "high"}
