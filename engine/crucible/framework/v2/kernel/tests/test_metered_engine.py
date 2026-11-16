"""PRICING M1c-2 — a METERED customer run reaches a model through the sovereign model gateway, with its grant, or not
at all (``kernel.metered``; design §5.1, invariants I1 / I9).

While ``VIGIL_MODEL_GRANT`` is set:
  * the Anthropic backend builds its client for the grant and the LOOPBACK gateway only — never the persisted
    provider key (the key reload is a no-op), never another host (no gateway ⇒ no client);
  * the gateway's credit stop (``x-vigil-stop: credits_exhausted``) is a terminal ``CreditsExhausted`` — never
    retried, never failed over;
  * no backend but the gateway's Anthropic backend is selected, constructed, pinned or failed over to;
  * model-tier routing is off.
With it unset nothing changes (the existing kernel suites pin that; a few cases are repeated here).

Mutation-verify targets (each neuter reds a NAMED test here):
  * build the metered client without base_url / with the env key  -> test_a_metered_client_is_built_for_the_grant_and_the_gateway_only
  * do not re-key the client cache on the grant                    -> test_a_metered_client_is_built_for_the_grant_and_the_gateway_only
  * build a client when the gateway URL is missing / not loopback  -> test_a_metered_run_without_a_loopback_gateway_builds_no_client
  * let the key reload run under a grant                           -> test_the_key_reload_never_replaces_a_grant
  * classify the credit stop as a plain error / retry it           -> test_the_credit_stop_is_terminal_and_distinct
  * drop the metered refusal in _construct                         -> test_a_metered_run_selects_only_the_gateway_backend
  * fail over in a metered run                                     -> test_a_metered_run_never_fails_over
  * let complete_with_backend pin another backend                  -> test_a_metered_run_cannot_pin_another_backend
  * leave routing on in a metered run                              -> test_routing_is_off_for_a_metered_run
"""
from __future__ import annotations

import sys
import types
from types import SimpleNamespace

import pytest

from framework.v2.common import live_keys
from framework.v2.common.errors import BackendError, BackendOverloaded, BackendUnavailable, CreditsExhausted
from framework.v2.kernel import llm, metered, routing
from framework.v2.kernel.backends import anthropic as A

GATEWAY = "http://127.0.0.1:8742"


@pytest.fixture(autouse=True)
def _clean(monkeypatch, tmp_path):
    for k in ("VIGIL_MODEL_GRANT", "ANTHROPIC_BASE_URL", "ANTHROPIC_API_KEY", "VIGIL_LIVE_KEY_RELOAD",
              "CRUCIBLE_LLM_BACKEND", "CRUCIBLE_MODEL_ROUTING", "CRUCIBLE_SOVEREIGNTY_TIER", "CRUCIBLE_SOVEREIGN_MODE",
              "CRUCIBLE_ANTHROPIC_ZDR"):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("SIGIL_HOME", str(tmp_path))
    llm.reset_cache()
    yield
    llm.reset_cache()


@pytest.fixture
def fake_sdk(monkeypatch):
    """A stand-in ``anthropic`` module that records every client it is asked to build."""
    built: list = []

    class Anthropic:
        def __init__(self, **kw):
            built.append(kw)
            self.kw = kw

    mod = types.ModuleType("anthropic")
    mod.Anthropic = Anthropic
    monkeypatch.setitem(sys.modules, "anthropic", mod)
    return built


def _meter(monkeypatch, grant="vmg1.grant-one", base=GATEWAY):
    monkeypatch.setenv("VIGIL_MODEL_GRANT", grant)
    if base is not None:
        monkeypatch.setenv("ANTHROPIC_BASE_URL", base)


# ------------------------------------------------------------------------------------------------- the switch

def test_metered_mode_follows_the_grant(monkeypatch):
    assert metered.model_grant() is None and not metered.metered_mode()
    monkeypatch.setenv("VIGIL_MODEL_GRANT", "   ")
    assert not metered.metered_mode()                                   # blank is no grant
    monkeypatch.setenv("VIGIL_MODEL_GRANT", " vmg1.x ")
    assert metered.model_grant() == "vmg1.x" and metered.metered_mode()


@pytest.mark.parametrize("url,ok", [
    ("http://127.0.0.1:8742", True), ("http://127.0.0.1:8742/", True), ("http://[::1]:8742", True),
    ("http://localhost:8742", True), (" http://127.0.0.1:8742 ", True),
    ("https://api.anthropic.com", False), ("http://127.0.0.1.example.com:8742", False),
    ("http://user@127.0.0.1:8742", False), ("http://127.0.0.1:8742/v1", False), ("http://127.0.0.1:8742?x=1", False),
    ("http://127.0.0.1", False), ("http://127.0.0.1:0", False), ("http://127.0.0.1:70000", False),
    ("https://127.0.0.1:8742", False), ("http://10.0.0.1:8742", False), ("", False),
])
def test_the_gateway_is_a_loopback_url_or_nothing(monkeypatch, url, ok):
    monkeypatch.setenv("ANTHROPIC_BASE_URL", url)
    assert (metered.gateway_base() == url.strip()) if ok else (metered.gateway_base() is None)


def test_the_stop_constant_is_the_shared_one():
    from vigil_core.model_grant import STOP_CREDITS_EXHAUSTED, STOP_HEADER
    assert A._CREDITS_EXHAUSTED_STOP == STOP_CREDITS_EXHAUSTED and STOP_HEADER == "x-vigil-stop"


# ------------------------------------------------------------------------------------------------- the client

def test_a_metered_client_is_built_for_the_grant_and_the_gateway_only(monkeypatch, tmp_path, fake_sdk):
    (tmp_path / "sigil.env").write_text("ANTHROPIC_API_KEY=sk-provider-persisted\n")
    monkeypatch.setenv("VIGIL_LIVE_KEY_RELOAD", "1")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-provider-env")
    _meter(monkeypatch)
    be = A.AnthropicBackend()
    c1 = be._client_obj()
    assert fake_sdk == [{"max_retries": 0, "api_key": "vmg1.grant-one", "base_url": GATEWAY, "http_client": None}]
    assert be._client_obj() is c1 and len(fake_sdk) == 1                # cached for the same grant
    assert __import__("os").environ["ANTHROPIC_API_KEY"] == "sk-provider-env"   # the reload never ran
    monkeypatch.setenv("VIGIL_MODEL_GRANT", "vmg1.grant-two")           # the next run's grant: a new client
    c2 = be._client_obj()
    assert c2 is not c1 and fake_sdk[-1] == {"max_retries": 0, "api_key": "vmg1.grant-two", "base_url": GATEWAY,
                                             "http_client": None}
    monkeypatch.delenv("VIGIL_MODEL_GRANT")                             # the metered run is over: never reuse it
    monkeypatch.delenv("VIGIL_LIVE_KEY_RELOAD")
    c3 = be._client_obj()
    assert c3 is not c2 and fake_sdk[-1] == {"max_retries": 0}          # the unmetered client, exactly as before


def test_a_metered_client_never_reads_an_ambient_proxy(monkeypatch, fake_sdk):
    """The grant is a bearer token: its HTTP client is built with ``trust_env=False`` and every proxy pattern mounted
    to no proxy (SDK 2.x mounts the environment's proxies whatever ``trust_env`` says), so no ``HTTP(S)_PROXY`` /
    ``ALL_PROXY`` can sit between the run and the loopback gateway."""
    made: list = []
    sys.modules["anthropic"].DefaultHttpxClient = lambda **kw: made.append(kw) or ("http-client", kw)
    _meter(monkeypatch)
    A.AnthropicBackend()._client_obj()
    want = {"trust_env": False, "mounts": {"http://": None, "https://": None, "all://": None}}
    assert made == [want] and fake_sdk[-1]["http_client"] == ("http-client", want)


def test_a_metered_run_without_a_loopback_gateway_builds_no_client(monkeypatch, fake_sdk):
    for base in (None, "https://api.anthropic.com", "http://203.0.113.9:8742"):
        monkeypatch.delenv("ANTHROPIC_BASE_URL", raising=False)
        _meter(monkeypatch, base=base)
        be = A.AnthropicBackend()                       # constructible (a grant is its key), but never usable
        ok, note = be.is_available()
        assert not ok and "gateway" in note
        with pytest.raises(BackendUnavailable):
            be._client_obj()
    assert fake_sdk == []                               # the grant was never handed to any client


def test_the_key_reload_never_replaces_a_grant(monkeypatch, tmp_path):
    (tmp_path / "sigil.env").write_text("SIGIL_ANTHROPIC_API_KEY=sk-provider-persisted\n")
    monkeypatch.setenv("VIGIL_LIVE_KEY_RELOAD", "1")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "vmg1.grant-one")
    _meter(monkeypatch)
    assert live_keys.refresh_live_anthropic_key() is False
    assert __import__("os").environ["ANTHROPIC_API_KEY"] == "vmg1.grant-one"
    monkeypatch.delenv("VIGIL_MODEL_GRANT")                             # unmetered: the reload works as before
    assert live_keys.refresh_live_anthropic_key() is True
    assert __import__("os").environ["ANTHROPIC_API_KEY"] == "sk-provider-persisted"


# ------------------------------------------------------------------------------------------------- the credit stop

def _refusal(status, headers):
    e = type("PermissionDeniedError", (Exception,), {})("refused")
    e.status_code = status
    e.response = SimpleNamespace(headers=headers)
    return e


def _bare():
    be = A.AnthropicBackend.__new__(A.AnthropicBackend)
    be.model = "claude-opus-4-8"
    return be


def test_the_credit_stop_is_terminal_and_distinct(monkeypatch):
    slept: list = []
    monkeypatch.setattr(A.time, "sleep", lambda s: slept.append(s))
    calls: list = []

    def client_raising(exc):
        class _Client:
            class messages:
                @staticmethod
                def create(**kw):
                    calls.append(kw)
                    raise exc
        return _Client()

    prompt = SimpleNamespace(temperature=0.2, max_tokens=8, effort=None)
    with pytest.raises(CreditsExhausted):
        _bare()._create_with_backoff(client_raising(_refusal(403, {"x-vigil-stop": "credits_exhausted"})),
                                     "s", "u", prompt)
    assert len(calls) == 1 and slept == []                              # the first answer stands: no retry
    calls.clear()
    with pytest.raises(BackendError) as ei:                             # any other 403 stays a plain failure
        _bare()._create_with_backoff(client_raising(_refusal(403, {})), "s", "u", prompt)
    assert not isinstance(ei.value, (CreditsExhausted, BackendOverloaded)) and len(calls) == 1
    assert issubclass(CreditsExhausted, BackendError) and not issubclass(CreditsExhausted, BackendOverloaded)
    assert metered.stop_reason(_refusal(403, {"x-vigil-stop": " credits_exhausted "})) == "credits_exhausted"
    assert metered.stop_reason(ValueError("no response")) is None


# ------------------------------------------------------------------------------------------------- selection

def test_a_metered_run_selects_only_the_gateway_backend(monkeypatch, fake_sdk):
    _meter(monkeypatch)
    for name in ("ollama", "dryrun", "claude-code", "bedrock", "self-hosted"):
        monkeypatch.setenv("CRUCIBLE_LLM_BACKEND", name)
        llm.reset_cache()
        with pytest.raises(BackendUnavailable):
            llm.get_backend()
        with pytest.raises(BackendUnavailable):
            llm.get_backend(force=name)
    monkeypatch.delenv("CRUCIBLE_LLM_BACKEND")
    llm.reset_cache()
    b = llm.get_backend()
    assert isinstance(b, A.AnthropicBackend) and b.name == "anthropic"
    assert llm.get_backend() is b                                       # cached for this grant


def test_a_metered_run_never_reuses_the_unmetered_selection(monkeypatch, fake_sdk):
    monkeypatch.setenv("CRUCIBLE_LLM_BACKEND", "dryrun")
    flat = llm.get_backend()                                            # an operator run selected dry-run
    assert flat.name == "dryrun"
    monkeypatch.delenv("CRUCIBLE_LLM_BACKEND")
    _meter(monkeypatch)
    assert isinstance(llm.get_backend(), A.AnthropicBackend)            # never the cached dry-run
    monkeypatch.delenv("VIGIL_MODEL_GRANT")
    assert llm.get_backend() is flat                                    # and the operator's selection is intact


def test_a_metered_run_with_no_usable_gateway_backend_is_refused(monkeypatch, fake_sdk):
    _meter(monkeypatch, base=None)                                      # no gateway URL
    with pytest.raises(BackendUnavailable):
        llm.get_backend()
    monkeypatch.setenv("ANTHROPIC_BASE_URL", GATEWAY)
    monkeypatch.setenv("CRUCIBLE_SOVEREIGNTY_TIER", "AIR_GAPPED")       # the tier permits no cloud backend at all
    llm.reset_cache()
    with pytest.raises(BackendUnavailable):
        llm.get_backend()


def _fake(name, *, overloaded=False):
    b = SimpleNamespace(name=name, is_available=lambda: (True, "ready"))
    if overloaded:
        def _c(prompt):
            raise BackendOverloaded(f"{name} overloaded")
    else:
        def _c(prompt):
            return SimpleNamespace(trace=SimpleNamespace(backend=name))
    b.complete = _c
    return b


def test_a_metered_run_never_fails_over(monkeypatch):
    primary, other = _fake("anthropic", overloaded=True), _fake("ollama")
    constructed: list = []
    monkeypatch.setattr(llm, "get_backend", lambda: primary)
    monkeypatch.setattr(llm, "_construct", lambda nm: constructed.append(nm) or other)
    monkeypatch.setattr(llm.sovereignty, "current",
                        lambda: SimpleNamespace(permitted_preference=lambda: ("anthropic", "ollama")))
    _meter(monkeypatch)
    with pytest.raises(BackendOverloaded):
        llm.complete_with_failover(prompt=SimpleNamespace())
    assert constructed == []                                            # no other backend was even built
    monkeypatch.delenv("VIGIL_MODEL_GRANT")                             # unmetered: the X4 failover as before
    assert llm.complete_with_failover(prompt=SimpleNamespace()).trace.backend == "ollama"


def test_a_metered_run_cannot_pin_another_backend(monkeypatch):
    _meter(monkeypatch)
    with pytest.raises(BackendUnavailable):
        llm.complete_with_backend(_fake("dryrun"), SimpleNamespace(system="s", user="u"))


# ------------------------------------------------------------------------------------------------- routing

def test_routing_is_off_for_a_metered_run(monkeypatch):
    monkeypatch.setenv("CRUCIBLE_MODEL_ROUTING", "1")
    monkeypatch.setenv("CRUCIBLE_MODEL_TIER_STANDARD", "claude-cheaper-model")
    assert routing.routing_enabled() and routing.resolve_model("standard", "claude-opus-4-8") == "claude-cheaper-model"
    _meter(monkeypatch)
    assert not routing.routing_enabled()
    assert routing.resolve_model("standard", "claude-opus-4-8") == "claude-opus-4-8"


# ------------------------------------------------------------------------------------------------- the wire (item 5)

def test_the_real_sdk_sends_the_grant_to_the_gateway_at_the_grants_effort(monkeypatch):
    """Through the REAL anthropic SDK (2.8+) against a loopback stand-in gateway: a metered call goes to the gateway
    with the grant as its bearer key, the run's model and ``output_config.effort`` (no sampling parameters), and the
    gateway's credit stop comes back as ``CreditsExhausted`` on the first answer. Skipped where the SDK (an opt-in
    extra no lock pins) is not installed."""
    pytest.importorskip("anthropic", minversion="2.8.0")
    import json
    import threading
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    seen: list = []
    answers = [(200, {}, {"id": "msg_1", "type": "message", "role": "assistant", "model": "claude-opus-4-8",
                          "content": [{"type": "text", "text": "{}"}], "stop_reason": "end_turn",
                          "stop_sequence": None, "usage": {"input_tokens": 1, "output_tokens": 1}}),
               (403, {"x-vigil-stop": "credits_exhausted"},
                {"type": "error", "error": {"type": "permission_error", "message": "exhausted"}})]

    class _Gateway(BaseHTTPRequestHandler):
        def do_POST(self):  # noqa: N802
            n = int(self.headers.get("content-length") or 0)
            seen.append({"path": self.path, "headers": {k.lower(): v for k, v in self.headers.items()},
                         "body": json.loads(self.rfile.read(n))})
            status, headers, doc = answers[len(seen) - 1]
            raw = json.dumps(doc).encode()
            self.send_response(status)
            self.send_header("content-type", "application/json")
            self.send_header("content-length", str(len(raw)))
            for k, v in headers.items():
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(raw)

        def log_message(self, *a):  # noqa: D102
            pass

    srv = ThreadingHTTPServer(("127.0.0.1", 0), _Gateway)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        _meter(monkeypatch, base=f"http://127.0.0.1:{srv.server_address[1]}")
        monkeypatch.setenv("CRUCIBLE_ANTHROPIC_MODEL", "claude-opus-4-8")
        for proxy in ("HTTP_PROXY", "http_proxy", "ALL_PROXY", "all_proxy"):     # an ambient proxy is never used
            monkeypatch.setenv(proxy, "http://127.0.0.1:9")
        for no_proxy in ("NO_PROXY", "no_proxy"):
            monkeypatch.delenv(no_proxy, raising=False)
        be = A.AnthropicBackend()
        prompt = SimpleNamespace(temperature=0.2, max_tokens=16, effort="xhigh")
        be._create_with_backoff(be._client_obj(), "sys", "user", prompt, "claude-opus-4-8")
        sent = seen[0]
        assert sent["path"] == "/v1/messages"
        assert sent["headers"].get("authorization") == "Bearer vmg1.grant-one" or \
            sent["headers"].get("x-api-key") == "vmg1.grant-one"
        assert sent["body"]["model"] == "claude-opus-4-8" and sent["body"]["output_config"] == {"effort": "xhigh"}
        assert not {"temperature", "top_p", "top_k"} & set(sent["body"])
        with pytest.raises(CreditsExhausted):
            be._create_with_backoff(be._client_obj(), "sys", "user", prompt, "claude-opus-4-8")
        assert len(seen) == 2                                           # the stop was not retried
    finally:
        srv.shutdown()
        srv.server_close()
