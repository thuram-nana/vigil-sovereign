"""F1 — llm_intake: transient classification, Claude-native retry + param self-heal, and the
fail-closed JSON→typed-proposal boundary."""

from __future__ import annotations

import asyncio

import pytest

from vigil_integration.safety.llm_intake import (
    ProposalParseError,
    extract_json,
    is_param_unsupported_error,
    is_transient_llm_error,
    parse_proposal,
    retry_call,
)


class RateLimitError(Exception):
    pass


class _RateLimitSubclass(RateLimitError):
    pass


def test_transient_classifier():
    assert is_transient_llm_error(RateLimitError("slow down")) is True       # name in set
    assert is_transient_llm_error(_RateLimitSubclass("x")) is True            # MRO match
    assert is_transient_llm_error(Exception("Connection reset by peer")) is True   # keyword
    assert is_transient_llm_error(Exception("HTTP 503 service unavailable")) is True  # keyword+status
    assert is_transient_llm_error(Exception("overloaded_error 529")) is True
    # a permanent error that merely CONTAINS a big number must NOT be transient (word boundary)
    assert is_transient_llm_error(Exception("max_tokens: 50000 exceeded")) is False
    assert is_transient_llm_error(Exception("invalid x-api-key")) is False
    assert is_transient_llm_error(ValueError("schema mismatch")) is False


def test_param_unsupported_detection():
    assert is_param_unsupported_error(Exception("`temperature` is deprecated for this model"), "temperature")
    assert is_param_unsupported_error(Exception('model does not support "thinking"'), "thinking")
    assert not is_param_unsupported_error(Exception("rate limit"), "temperature")


async def _fail_then_succeed(fails, exc):
    calls = {"n": 0}

    async def call():
        if calls["n"] < fails:
            calls["n"] += 1
            raise exc
        return "ok"
    return call, calls


def test_retry_retries_transient_then_succeeds():
    async def run():
        call, calls = await _fail_then_succeed(2, RateLimitError("529 overloaded"))
        noop = lambda *_a: asyncio.sleep(0)
        res = await retry_call(call, max_attempts=3, sleep=noop)
        return res, calls["n"]
    res, n = asyncio.run(run())
    assert res == "ok" and n == 2


def test_retry_reraises_permanent_immediately():
    async def run():
        async def call():
            raise ValueError("invalid api key")
        with pytest.raises(ValueError, match="invalid api key"):
            await retry_call(call, max_attempts=3, sleep=lambda *_a: asyncio.sleep(0))
    asyncio.run(run())


def test_retry_exhaustion_reraises_last():
    async def run():
        async def call():
            raise RateLimitError("still 503")
        with pytest.raises(RateLimitError):
            await retry_call(call, max_attempts=2, sleep=lambda *_a: asyncio.sleep(0))
    asyncio.run(run())


def test_param_self_heal_fires_once():
    async def run():
        state = {"healed": False}

        async def bad():
            raise Exception("`temperature` is not supported")

        async def good():
            return "healed-ok"

        def self_heal(exc):
            if is_param_unsupported_error(exc, "temperature") and not state["healed"]:
                state["healed"] = True
                return good
            return None
        return await retry_call(bad, max_attempts=3, param_self_heal=self_heal, sleep=lambda *_a: asyncio.sleep(0))
    assert asyncio.run(run()) == "healed-ok"


# --- JSON extraction + fail-closed proposal parse ----------------------------------------------

def test_extract_json_handles_fenced_bare_and_repair():
    assert extract_json('```json\n{"a": 1}\n```') == {"a": 1}
    assert extract_json('here is the plan: {"action": "use_tool"} thanks') == {"action": "use_tool"}
    assert extract_json('[1, 2, 3]') == [1, 2, 3]
    assert extract_json('{"a": 1, "b": [2, 3,],}') == {"a": 1, "b": [2, 3]}   # trailing commas repaired
    assert extract_json('{"a": 1, "b": {"c": 2') == {"a": 1, "b": {"c": 2}}    # unclosed braces repaired
    assert extract_json("no json here") is None
    assert extract_json("") is None and extract_json(None) is None  # type: ignore[arg-type]


class _Decision:
    def __init__(self, action):
        if action not in ("use_tool", "complete"):
            raise ValueError(f"bad action {action!r}")
        self.action = action

    @classmethod
    def validate(cls, obj):
        return cls(obj["action"])


def test_parse_proposal_valid_invalid_and_failclosed_default():
    ok = parse_proposal('{"action": "use_tool"}', _Decision.validate)
    assert ok.action == "use_tool"
    # invalid content + a fail-closed default → returns the default, never raises
    downgraded = parse_proposal('{"action": "deploy_fireteam"}', _Decision.validate,
                                default=_Decision("use_tool"))
    assert downgraded.action == "use_tool"
    # malformed JSON + a default → default
    assert parse_proposal("garbage", _Decision.validate, default=_Decision("complete")).action == "complete"


def test_parse_proposal_no_default_raises():
    with pytest.raises(ProposalParseError):
        parse_proposal("not json", _Decision.validate)
    with pytest.raises(ProposalParseError):
        parse_proposal('{"action": "invalid"}', _Decision.validate)
