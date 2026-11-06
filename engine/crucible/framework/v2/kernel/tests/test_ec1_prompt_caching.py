"""
EC-1a — Anthropic prompt-prefix caching (the first AI-cost economics slice).

The kernel's prompt is already prefix-stable: the stable doctrine/schema rides the `system`
turn, all volatile per-step content rides the `user` turn. So caching is enabled by ONE change —
passing `system` as a cache-control content block — plus the load-bearing correctness fold:
cached input tokens are added back into `tokens_in` so the per-tool budget ledger counts the
SAME total input it did before caching (cached bytes still consume context). Without that fold the
budget silently under-charges and throttles late.

Every assertion here is deterministic and OFFLINE (no key, no network). A stateful stub simulates
a cache hit so the hit/miss keying is exercised without a live model. One opt-in live test is
gated behind CRUCIBLE_LIVE_LLM.

Mutation-verify targets (each neuter reds a named test):
  * drop cache_control from the system block            -> test_system_is_a_cache_control_block
  * move cache_control onto the user message            -> test_user_turn_is_never_cache_controlled
  * tokens_in = raw input only (un-fold)                -> test_usage_folds_cache_tokens_into_tokens_in
  * _tb_record ignores the folded tokens_in             -> test_budget_charges_the_folded_total
  * hardcode the trace cache fields to 0                -> test_usage_folds_cache_tokens_into_tokens_in
"""

from __future__ import annotations

import os
from types import SimpleNamespace

import pytest
from pydantic import BaseModel

from framework.v2.kernel import llm
from framework.v2.kernel.backends import anthropic as A
from framework.v2.kernel.llm import Prompt, make_call_trace


# --------------------------------------------------------------------------- helpers


class _Tiny(BaseModel):
    ok: bool


_RAW = '{"ok": true}'


def _bare_anthropic(model: str = "claude-opus-4-8"):
    """An AnthropicBackend with no SDK/key (mirrors test_llm_resilience._bare_anthropic)."""
    be = A.AnthropicBackend.__new__(A.AnthropicBackend)
    be.model = model
    be.zdr = False
    return be


def _prompt(system: str = "STABLE-DOCTRINE", user: str = "volatile-step-observation") -> Prompt:
    return Prompt(
        system=system,
        user=user,
        schema=_Tiny,
        schema_name="Tiny",
        cognitive_doc="metacognition.md",
        cognitive_sections=["s1"],
        max_tokens=64,
        temperature=0.2,
        effort=None,
    )


def _usage(*, input_tokens=100, output_tokens=10, cache_creation=None, cache_read=None):
    ns = SimpleNamespace(input_tokens=input_tokens, output_tokens=output_tokens)
    if cache_creation is not None:
        ns.cache_creation_input_tokens = cache_creation
    if cache_read is not None:
        ns.cache_read_input_tokens = cache_read
    return ns


def _stub_client(captured: list, usage, raw: str = _RAW):
    """A fake anthropic client whose messages.create captures kwargs and returns a fixed usage."""
    def create(**kw):
        captured.append(kw)
        return SimpleNamespace(
            content=[SimpleNamespace(type="text", text=raw)],
            usage=usage,
        )
    return SimpleNamespace(messages=SimpleNamespace(create=create))


def _run(be, prompt, captured, usage):
    be._client_obj = lambda: _stub_client(captured, usage)   # bypass SDK/key/network
    return be.complete(prompt)


# --------------------------------------------------------------- request shape (the breakpoint)


def test_system_is_a_cache_control_block() -> None:
    """system is sent as a one-element content list whose LAST block carries an ephemeral
    cache_control breakpoint — the entire stable span is cached."""
    captured: list = []
    _run(_bare_anthropic(), _prompt(), captured, _usage(cache_creation=0, cache_read=0))
    assert len(captured) == 1
    system = captured[0]["system"]
    assert isinstance(system, list) and len(system) >= 1
    last = system[-1]
    assert last["type"] == "text"
    assert last["cache_control"] == {"type": "ephemeral"}
    # the built system text is the stable doctrine + the output-contract/schema tail
    assert "STABLE-DOCTRINE" in last["text"]
    assert "Output contract" in last["text"]


def test_user_turn_is_never_cache_controlled() -> None:
    """The volatile user turn (which carries any untrusted/target-derived data) is never cached."""
    captured: list = []
    _run(_bare_anthropic(), _prompt(user="volatile"), captured, _usage(cache_creation=0, cache_read=0))
    messages = captured[0]["messages"]
    assert messages == [{"role": "user", "content": "volatile"}]
    # no cache_control anywhere in the user turn
    assert all("cache_control" not in str(m) for m in messages)


def test_prefix_is_byte_stable_across_different_user_content() -> None:
    """Two calls that share a binding's system but differ in user content must send byte-identical
    cached system blocks (the cache key is the stable prefix, not the volatile turn). Guards against
    a silent invalidator (e.g. a timestamp/nonce injected into the system prompt)."""
    cap: list = []
    be = _bare_anthropic()
    _run(be, _prompt(user="step-1"), cap, _usage(cache_creation=0, cache_read=0))
    _run(be, _prompt(user="step-2-different"), cap, _usage(cache_creation=0, cache_read=0))
    assert cap[0]["system"][0]["text"] == cap[1]["system"][0]["text"]   # prefix identical
    assert cap[0]["messages"] != cap[1]["messages"]                     # user differs


# --------------------------------------------------------------- usage fold (the correctness point)


def test_usage_folds_cache_tokens_into_tokens_in() -> None:
    """tokens_in = raw_input + cache_creation + cache_read, so the ledger sees the SAME total input
    it did pre-caching; the two provenance fields record the breakdown."""
    captured: list = []
    res = _run(_bare_anthropic(), _prompt(), captured,
               _usage(input_tokens=100, output_tokens=10, cache_creation=800, cache_read=1200))
    tr = res.trace
    assert tr.cache_creation_input_tokens == 800
    assert tr.cache_read_input_tokens == 1200
    assert tr.tokens_out == 10
    assert tr.tokens_in == 2100          # 100 + 800 + 1200 — NOT the 100 uncached remainder


def test_budget_charges_the_folded_total(monkeypatch) -> None:
    """_tb_record charges tokens_in + tokens_out; with the fold that is the full input volume, so
    the per-tool budget counts exactly what it counted before caching (no silent under-charge)."""
    charged: list = []
    fake_budget = SimpleNamespace(record=lambda tool, spent: charged.append((tool, spent)))
    monkeypatch.setattr(llm, "_token_budget", fake_budget)
    trace = make_call_trace(
        backend="anthropic", is_dryrun=False, cognitive_doc="d", cognitive_sections=[],
        tokens_in=2100, tokens_out=10, cache_creation_input_tokens=800, cache_read_input_tokens=1200,
    )
    llm._tb_record("engine", trace)
    assert charged == [("engine", 2110)]          # 2100 in + 10 out — the full volume


def test_dryrun_trace_charges_nothing(monkeypatch) -> None:
    """A dry-run trace never touches the ledger (the is_dryrun short-circuit), regardless of fields."""
    charged: list = []
    fake_budget = SimpleNamespace(record=lambda tool, spent: charged.append((tool, spent)))
    monkeypatch.setattr(llm, "_token_budget", fake_budget)
    trace = make_call_trace(
        backend="dryrun", is_dryrun=True, cognitive_doc="d", cognitive_sections=[],
        tokens_in=999, tokens_out=9,
    )
    llm._tb_record("engine", trace)
    assert charged == []


# --------------------------------------------------------------- cache hit / miss (stateful stub)


def _stateful_client(captured: list, seen: set):
    """Simulates the provider cache: first time a given system prefix is seen -> cache CREATION;
    byte-identical prefix again -> cache READ (hit); a different prefix -> no read (miss)."""
    def create(**kw):
        captured.append(kw)
        sys_text = kw["system"][0]["text"]
        if sys_text in seen:
            usage = _usage(input_tokens=5, output_tokens=5, cache_creation=0, cache_read=1000)
        else:
            seen.add(sys_text)
            usage = _usage(input_tokens=5, output_tokens=5, cache_creation=1000, cache_read=0)
        return SimpleNamespace(content=[SimpleNamespace(type="text", text=_RAW)], usage=usage)
    return SimpleNamespace(messages=SimpleNamespace(create=create))


def test_simulated_cache_hit_then_miss_on_different_prefix() -> None:
    captured: list = []
    seen: set = set()
    be = _bare_anthropic()
    be._client_obj = lambda: _stateful_client(captured, seen)

    r1 = be.complete(_prompt(system="DOCTRINE-A", user="u1"))   # cold -> creation
    assert r1.trace.cache_creation_input_tokens > 0
    assert r1.trace.cache_read_input_tokens == 0

    r2 = be.complete(_prompt(system="DOCTRINE-A", user="u2-different"))   # HIT -> read
    assert r2.trace.cache_read_input_tokens > 0
    assert r2.trace.tokens_in == 1005          # folded total survives even on a hit

    r3 = be.complete(_prompt(system="DOCTRINE-B", user="u3"))   # different prefix -> MISS
    assert r3.trace.cache_read_input_tokens == 0


def test_caching_off_control_degrades_silently() -> None:
    """When the prefix is under the model minimum the provider returns no cache fields; the call
    still parses, tokens_in == raw input, nothing crashes."""
    captured: list = []
    res = _run(_bare_anthropic(), _prompt(), captured, _usage(input_tokens=42, output_tokens=7))
    assert res.parsed.ok is True
    assert res.trace.tokens_in == 42
    assert res.trace.cache_creation_input_tokens == 0
    assert res.trace.cache_read_input_tokens == 0


def test_cache_block_survives_a_parse_retry() -> None:
    """A first unparseable response then a valid one: the cached system block is byte-identical
    across both attempts (only the user message gets the retry hint appended)."""
    captured: list = []
    calls = {"n": 0}

    def create(**kw):
        captured.append(kw)
        calls["n"] += 1
        text = "not json" if calls["n"] == 1 else _RAW
        return SimpleNamespace(
            content=[SimpleNamespace(type="text", text=text)],
            usage=_usage(cache_creation=0, cache_read=0),
        )

    be = _bare_anthropic()
    be._client_obj = lambda: SimpleNamespace(messages=SimpleNamespace(create=create))
    res = be.complete(_prompt())
    assert res.parsed.ok is True
    assert len(captured) == 2                                   # one retry
    assert captured[0]["system"][0]["text"] == captured[1]["system"][0]["text"]   # prefix stable
    assert captured[0]["messages"] != captured[1]["messages"]  # user got the retry hint


# --------------------------------------------------------------- opt-in live assertion


_LIVE = os.environ.get("CRUCIBLE_LIVE_LLM") == "1" and bool(os.environ.get("ANTHROPIC_API_KEY"))
requires_live = pytest.mark.skipif(not _LIVE, reason="set CRUCIBLE_LIVE_LLM=1 + ANTHROPIC_API_KEY")


@requires_live
def test_live_cache_read_on_second_call() -> None:  # pragma: no cover - opt-in, needs a real key
    """Two real calls <5 min apart with an identical system prefix: the 2nd reports a cache read.
    All correctness is covered offline above; this only confirms the wire behaviour end-to-end."""
    from framework.v2.kernel.backends.anthropic import AnthropicBackend
    be = AnthropicBackend()
    p = _prompt(system="OBSIDIAN DOCTRINE " * 400, user="probe")   # clear the per-model minimum
    be.complete(p)
    r2 = be.complete(_prompt(system="OBSIDIAN DOCTRINE " * 400, user="probe-2"))
    assert r2.trace.cache_read_input_tokens > 0
