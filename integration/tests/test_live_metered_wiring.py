"""M1c-2b — the LIVE think / codefix / loop paths spend a metered run's grant through the gateway.

Pins the offense-plane LIVE wiring under a metered run (a model grant in scope):
  * ``think_claude._resolve_key`` PREFERS the grant over every provider-key source (FATAL-2: a metered live
    think never reaches for the provider key);
  * ``think_claude._build_live_client`` points the SDK client at the LOOPBACK gateway (``base_url``) with the
    grant (the WIRE test asserts the request bytes: base_url, the bearer grant, the model, ``output_config.effort``
    = the grant's effort, and NO temperature);
  * the gateway's terminal credit stop surfaces as ``CreditsExhausted`` (a PAUSE), not an ASK_USER degrade —
    ``_think_via_client_raw`` raises it and ``engine.VigilEngine._think`` propagates it to the engage seam;
  * ``codefix_runner`` uses the grant's model in metered mode (its own default would 400 at the gateway).

DEFAULT-OFF: with no grant every path is byte-identical.

Mutation-verify targets (each neuter reds a NAMED test here):
  * _resolve_key stops preferring the grant                                   -> test_resolve_key_prefers_the_grant_over_the_provider_key
  * _build_live_client stops passing base_url when metered                    -> test_the_metered_client_wires_the_grant_to_the_gateway
  * _think_via_client_raw degrades a credit stop to ASK_USER (not raise)       -> test_a_credit_stop_raises_credits_exhausted_not_ask_user
  * engine._think swallows CreditsExhausted into ASK_USER                      -> test_engine_think_propagates_a_credit_stop
  * codefix ignores the grant model when metered                              -> test_codefix_uses_the_grant_model_when_metered
"""
from __future__ import annotations

from types import SimpleNamespace

import pytest

pytest.importorskip("framework.v2.kernel.metered", reason="framework (offense) not importable in the sovereign leg")

from vigil_integration.agent.state import ActionType  # noqa: E402
from vigil_integration.live import codefix_runner as cf  # noqa: E402
from vigil_integration.live import think_claude as tc  # noqa: E402
from vigil_integration.live.engine import EngineSeams, VigilEngine  # noqa: E402

GATEWAY = "http://127.0.0.1:8742"
GRANT = "vmg1.grant-one"
MODEL = "claude-opus-4-8"


def _metered(monkeypatch, *, base=GATEWAY):
    monkeypatch.setenv("VIGIL_MODEL_GRANT", GRANT)
    monkeypatch.setenv("ANTHROPIC_BASE_URL", base)


class _Stop(Exception):
    """A gateway credit-stop exception: carries the ``x-vigil-stop: credits_exhausted`` response header."""
    def __init__(self, status_code=None):
        self.response = SimpleNamespace(headers={"x-vigil-stop": "credits_exhausted"})
        if status_code is not None:
            self.status_code = status_code


# ----------------------------------------------------------------------------------- _resolve_key / build client
def test_resolve_key_prefers_the_grant_over_the_provider_key(monkeypatch):
    _metered(monkeypatch)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-provider")
    monkeypatch.setenv("VIGIL_LIVE_KEY_RELOAD", "1")
    # the grant wins over the explicit arg, the env key and the hot-reload
    assert tc._resolve_key("sk-explicit") == GRANT
    assert tc._resolve_key(None) == GRANT


def test_resolve_key_unmetered_is_unchanged(monkeypatch):
    monkeypatch.delenv("VIGIL_MODEL_GRANT", raising=False)
    monkeypatch.delenv("VIGIL_LIVE_KEY_RELOAD", raising=False)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-env")
    assert tc._resolve_key("sk-explicit") == "sk-explicit"          # the explicit arg still wins
    assert tc._resolve_key(None) == "sk-env"                        # else the env key (byte-identical)


def test_metered_gateway_base_reads_the_gateway(monkeypatch):
    _metered(monkeypatch)
    assert tc._metered_gateway_base() == GATEWAY
    monkeypatch.delenv("VIGIL_MODEL_GRANT", raising=False)
    assert tc._metered_gateway_base() is None                       # unmetered ⇒ no base_url (byte-identical)


def test_the_metered_client_wires_the_grant_to_the_gateway(monkeypatch):
    anthropic = pytest.importorskip("anthropic")
    import httpx
    import json

    seen: list = []

    def _handler(req):
        seen.append({"url": str(req.url),
                     "auth": req.headers.get("authorization"), "xapi": req.headers.get("x-api-key"),
                     "body": json.loads(req.content)})
        return httpx.Response(200, json={"id": "m", "type": "message", "role": "assistant", "model": MODEL,
                                         "content": [{"type": "text", "text": "{}"}], "stop_reason": "end_turn",
                                         "stop_sequence": None, "usage": {"input_tokens": 1, "output_tokens": 1}})

    _metered(monkeypatch)
    monkeypatch.setenv("CRUCIBLE_EFFORT", "xhigh")
    monkeypatch.setattr(tc, "_metered_http_client",
                        lambda mod: httpx.Client(transport=httpx.MockTransport(_handler)))
    client = tc._build_live_client(tc._resolve_key(None))           # metered: the grant key + base_url=gateway
    assert client is not None
    # the request params the think step builds (model + output_config.effort; NEVER temperature)
    params = dict(model=MODEL, max_tokens=16, system="s", messages=[{"role": "user", "content": "u"}],
                  **tc._effort_kwargs(MODEL))
    client.messages.create(**params)
    assert len(seen) == 1
    req = seen[0]
    assert req["url"] == f"{GATEWAY}/v1/messages"                   # the client dialed the loopback gateway
    assert req["auth"] == f"Bearer {GRANT}" or req["xapi"] == GRANT # the grant is the bearer credential
    assert req["body"]["model"] == MODEL
    assert req["body"].get("output_config") == {"effort": "xhigh"}  # the grant's effort reaches the API
    assert not {"temperature", "top_p", "top_k"} & set(req["body"])  # NO sampling parameters


# ----------------------------------------------------------------------------------- the credit stop → a pause
def test_a_credit_stop_raises_credits_exhausted_not_ask_user(monkeypatch):
    from framework.v2.common.errors import CreditsExhausted
    _metered(monkeypatch)
    monkeypatch.setattr(tc, "_gw", None)                            # unit-test the raw think path (no egress chokepoint)
    messages = SimpleNamespace(create=lambda **kw: (_ for _ in ()).throw(_Stop()))
    client = SimpleNamespace(messages=messages)
    with pytest.raises(CreditsExhausted):
        tc._think_via_client_raw(client, "sys", "user", model=MODEL, max_tokens=16)


def test_a_non_credit_error_still_degrades_to_ask_user(monkeypatch):
    # byte-identical: a NON-credit model error still fail-closes to the safest ASK_USER (never raises).
    _metered(monkeypatch)
    monkeypatch.setattr(tc, "_gw", None)
    messages = SimpleNamespace(create=lambda **kw: (_ for _ in ()).throw(ValueError("bad request")))
    client = SimpleNamespace(messages=messages)
    d = tc._think_via_client_raw(client, "sys", "user", model=MODEL, max_tokens=16)
    assert d.action == ActionType.ASK_USER


def test_think_retryable_never_retries_a_credit_stop(monkeypatch):
    _metered(monkeypatch)
    assert tc._think_retryable(_Stop()) is False                    # a credit stop is terminal (never a retry storm)
    # even a credit stop carrying a RETRYABLE status (503) is not retried — the terminal credit stop wins.
    assert tc._think_retryable(_Stop(status_code=503)) is False


def test_engine_think_propagates_a_credit_stop(monkeypatch):
    from framework.v2.common.errors import CreditsExhausted

    def _think_credit(_state):
        raise CreditsExhausted("credits exhausted")

    eng = VigilEngine(slug="loopback", seams=EngineSeams(think=_think_credit), max_iterations=3)
    with pytest.raises(CreditsExhausted):
        eng._think(SimpleNamespace())                               # propagates to the engage seam, not ASK_USER


def test_engine_think_still_asks_user_on_an_ordinary_error():
    def _think_boom(_state):
        raise RuntimeError("boom")

    eng = VigilEngine(slug="loopback", seams=EngineSeams(think=_think_boom), max_iterations=3)
    d = eng._think(SimpleNamespace())
    assert d.action == ActionType.ASK_USER                          # byte-identical for a non-credit error


# ----------------------------------------------------------------------------------- codefix model
def test_codefix_uses_the_grant_model_when_metered(monkeypatch):
    _metered(monkeypatch)
    monkeypatch.setenv("CRUCIBLE_ANTHROPIC_MODEL", MODEL)
    assert cf._metered_model("claude-opus-5") == MODEL              # the grant's model, never the coder's default


def test_codefix_model_unmetered_is_the_default(monkeypatch):
    monkeypatch.delenv("VIGIL_MODEL_GRANT", raising=False)
    monkeypatch.setenv("CRUCIBLE_ANTHROPIC_MODEL", MODEL)           # present, but unmetered ⇒ ignored
    assert cf._metered_model("claude-opus-5") == "claude-opus-5"


# ----------------------------------------------------------------------------------- open-question decisions
def test_anthropic_zdr_counts_as_a_metered_backend():
    # §15.5 open question (decided): a ZDR-attested deployment's metered run uses the anthropic-zdr backend —
    # the grant + gateway are identical; both anthropic variants serve a metered run (M1c-2a's _METERED_BACKENDS).
    from framework.v2.kernel.llm import _METERED_BACKENDS
    assert _METERED_BACKENDS == frozenset({"anthropic", "anthropic-zdr"})
