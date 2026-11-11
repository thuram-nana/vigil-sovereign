"""EC-2a — model-tier routing (the engine's biggest model-COST lever).

Every URK reasoning call runs on ONE model today. Routing lets an operator send the mechanical /
no-oracle bindings to a cheaper model while the finding-critical ones stay capable. It changes no
SOUNDNESS (a FACT is oracle-decided, never LLM-decided) — only recall/precision of leads, which the
benchmark eval gate measures (the A/B proof is EC-2b). Two safety rules are structural and locked
here: **default-OFF** (byte-identical until opted in) and **fail-toward-capable** (an unmapped /
unknown / empty tier always resolves to the backend's configured model — a cheaper model is used
ONLY where the operator explicitly mapped a recognised tier).

Every assertion is deterministic and OFFLINE (no key, no network).

Mutation-verify targets (each neuter reds a named test):
  * routing_enabled() default True (not False)            -> test_routing_disabled_by_default
  * resolve_model returns an override when DISABLED        -> test_disabled_resolves_default_for_every_tier
  * resolve_model returns override for an UNMAPPED tier     -> test_enabled_unmapped_tier_fails_toward_capable
  * resolve_model honours an UNKNOWN tier name             -> test_unknown_tier_resolves_to_default
  * flip the critique/hypothesize/decide assignment to a cheaper tier -> test_finding_critical_bindings_are_deep
  * tier_for_binding falls back to a cheaper tier for unknown -> test_unknown_binding_falls_back_to_capable
  * resolve_effective_model reads backend.model when routing on+mapped (ignores tier) -> test_effective_model_maps_when_enabled
  * drop resolve_effective_model's fail-safe try/except     -> test_effective_model_is_fail_safe
  * L2 seam keys on backend.model instead of the effective model -> test_l2_store_keys_on_effective_model /
                                                               test_l2_lookup_keys_on_effective_model
  * binding.run stops assigning the tier from the identity  -> test_binding_run_assigns_tier_from_identity
  * make_call_trace drops the model field                   -> test_make_call_trace_records_model
"""
from __future__ import annotations

import pytest
from pydantic import BaseModel

from framework.v2.kernel import binding, llm, routing
from framework.v2.kernel import response_cache as rc
from framework.v2.kernel.backends import anthropic as _anthropic
from framework.v2.kernel.llm import LLMBackend, LLMResult, Prompt, make_call_trace
from framework.v2.kernel.models import CritiqueResult

_OLD = "claude-3-5-sonnet-20241022"     # older family: L2-cacheable, takes temperature
_CURRENT = "claude-opus-4-8"            # current-gen: drops temperature for effort; never L2-cacheable
_CHEAP = "claude-haiku-4-5"             # a stand-in cheaper model an operator might map a tier to


@pytest.fixture(autouse=True)
def _clean_routing_env(monkeypatch):
    """Routing reads env at call time, so a leaked var would make tests order-dependent. Clear the
    enable flag + every per-tier mapping before each test; a test opts in explicitly."""
    monkeypatch.delenv(routing._ENABLE_ENV, raising=False)
    for t in routing.TIERS:
        monkeypatch.delenv(f"{routing._TIER_ENV_PREFIX}{t.upper()}", raising=False)


class S(BaseModel):
    x: int


def _p(**kw) -> Prompt:
    d = dict(system="SYS", user="USR", schema=S, schema_name="S", cognitive_doc="doc",
             temperature=0.0, samples=1, max_tokens=100)
    d.update(kw)
    return Prompt(**d)


class _FakeBackend:
    """A backend double: a fixed configured model + a name, is_dryrun False. (resolve_effective_model
    reads .model + .honors_routing; the L2 seam also reads .name/.is_dryrun.) honors_routing defaults
    True so the routing-ON assertions exercise the routed path; a test sets it False to exercise a
    non-wired backend (ollama/self_hosted/mistral/azure/claude_code)."""

    def __init__(self, model: str, name: str = "fake", honors_routing: bool = True) -> None:
        self.model = model
        self.name = name
        self.is_dryrun = False
        self.honors_routing = honors_routing


# ---- routing policy: default-OFF --------------------------------------------------------------------
def test_routing_disabled_by_default():
    assert routing.routing_enabled() is False


def test_disabled_resolves_default_for_every_tier(monkeypatch):
    # even with a mapping present, routing DISABLED must return the backend's own model for every tier.
    monkeypatch.setenv(f"{routing._TIER_ENV_PREFIX}STANDARD", _CHEAP)
    for tier in (*routing.TIERS, "", "bogus"):
        assert routing.resolve_model(tier, _CURRENT) == _CURRENT


# ---- routing policy: fail-toward-capable ------------------------------------------------------------
def test_enabled_maps_only_explicitly_mapped_tiers(monkeypatch):
    monkeypatch.setenv(routing._ENABLE_ENV, "1")
    monkeypatch.setenv(f"{routing._TIER_ENV_PREFIX}STANDARD", _CHEAP)
    assert routing.resolve_model("standard", _CURRENT) == _CHEAP     # the one mapped tier routes cheap


def test_enabled_unmapped_tier_fails_toward_capable(monkeypatch):
    monkeypatch.setenv(routing._ENABLE_ENV, "1")
    monkeypatch.setenv(f"{routing._TIER_ENV_PREFIX}STANDARD", _CHEAP)
    # deep + cheap are NOT mapped -> the capable default, never a silent downgrade.
    assert routing.resolve_model("deep", _CURRENT) == _CURRENT
    assert routing.resolve_model("cheap", _CURRENT) == _CURRENT


def test_enabled_but_nothing_mapped_is_byte_identical(monkeypatch):
    monkeypatch.setenv(routing._ENABLE_ENV, "1")
    for tier in routing.TIERS:
        assert routing.resolve_model(tier, _CURRENT) == _CURRENT


def test_unknown_tier_resolves_to_default(monkeypatch):
    monkeypatch.setenv(routing._ENABLE_ENV, "1")
    monkeypatch.setenv(f"{routing._TIER_ENV_PREFIX}STANDARD", _CHEAP)
    # Map the UNKNOWN names too: the fixed vocabulary, not a missing env var, must be what refuses them
    # (without these, dropping the `t not in TIERS` guard survives — the named-mutant corpus caught it).
    for name in ("", "BOGUS", "DEEPISH"):
        monkeypatch.setenv(f"{routing._TIER_ENV_PREFIX}{name}", _CHEAP)
    for bogus in ("", "   ", "bogus", "DEEPISH"):
        assert routing.resolve_model(bogus, _CURRENT) == _CURRENT


def test_tier_name_is_case_insensitive(monkeypatch):
    monkeypatch.setenv(routing._ENABLE_ENV, "1")
    monkeypatch.setenv(f"{routing._TIER_ENV_PREFIX}STANDARD", _CHEAP)
    assert routing.resolve_model("STANDARD", _CURRENT) == _CHEAP     # tier name case-folded
    assert routing.resolve_model("Standard", _CURRENT) == _CHEAP


def test_enable_flag_truthy_vocabulary(monkeypatch):
    monkeypatch.setenv(f"{routing._TIER_ENV_PREFIX}STANDARD", _CHEAP)
    for off in ("", "0", "no", "off", "false", "nope"):
        monkeypatch.setenv(routing._ENABLE_ENV, off)
        assert routing.resolve_model("standard", _CURRENT) == _CURRENT
    for on in ("1", "true", "yes", "on", "TRUE"):
        monkeypatch.setenv(routing._ENABLE_ENV, on)
        assert routing.resolve_model("standard", _CURRENT) == _CHEAP


# ---- the per-binding default-tier table -------------------------------------------------------------
def test_finding_critical_bindings_are_deep():
    # critique gates findings; hypothesize generates the leads oracles confirm; decide sets severity +
    # worth_reporting. All three must stay on the capable tier by default.
    assert routing.tier_for_binding("self-critique") == "deep"
    assert routing.tier_for_binding("hypothesis-driven") == "deep"
    assert routing.tier_for_binding("decision-frameworks") == "deep"


def test_mechanical_bindings_are_standard():
    assert routing.tier_for_binding("threat-modeling") == "standard"
    assert routing.tier_for_binding("pivot-protocols") == "standard"
    assert routing.tier_for_binding("opsec-discipline") == "standard"


def test_unknown_binding_falls_back_to_capable():
    # a new / unrecognised binding is never silently routed cheap.
    assert routing.tier_for_binding("brand-new-binding") == "deep"
    assert routing.tier_for_binding("") == "deep"
    assert routing._DEFAULT_TIER == "deep"


def test_no_binding_defaults_to_cheap():
    # "cheap" ships in the vocabulary (for an operator / EC-7) but NO binding defaults to it.
    assert "cheap" not in routing._BINDING_TIERS.values()


# ---- resolve_effective_model: the ONE source of truth -----------------------------------------------
def test_effective_model_off_is_backend_model():
    # a tier is declared, but routing is OFF -> the backend's own model (byte-identical).
    assert llm.resolve_effective_model(_p(model_tier="standard"), _FakeBackend(_CURRENT)) == _CURRENT


def test_effective_model_maps_when_enabled(monkeypatch):
    monkeypatch.setenv(routing._ENABLE_ENV, "1")
    monkeypatch.setenv(f"{routing._TIER_ENV_PREFIX}STANDARD", _CHEAP)
    assert llm.resolve_effective_model(_p(model_tier="standard"), _FakeBackend(_CURRENT)) == _CHEAP
    # an unmapped tier on the same call still fails toward capable.
    assert llm.resolve_effective_model(_p(model_tier="deep"), _FakeBackend(_CURRENT)) == _CURRENT


def test_effective_model_no_tier_is_backend_model(monkeypatch):
    monkeypatch.setenv(routing._ENABLE_ENV, "1")
    monkeypatch.setenv(f"{routing._TIER_ENV_PREFIX}STANDARD", _CHEAP)
    assert llm.resolve_effective_model(_p(), _FakeBackend(_CURRENT)) == _CURRENT   # tier "" -> default


def test_effective_model_backend_without_model_is_empty():
    class NoModel:
        name = "x"
    assert llm.resolve_effective_model(_p(model_tier="deep"), NoModel()) == ""     # never raises


def test_effective_model_is_fail_safe(monkeypatch):
    # a routing error must degrade to the backend's model, never crash a completion.
    def _boom(*a, **k):
        raise RuntimeError("boom")
    monkeypatch.setattr(routing, "resolve_model", _boom)
    assert llm.resolve_effective_model(_p(model_tier="standard"), _FakeBackend(_CURRENT)) == _CURRENT


def test_non_honoring_backend_keys_on_its_own_model(monkeypatch):
    # Red-pen fold: resolve_effective_model is the ONE source of truth only because a backend that does
    # NOT honor routing (honors_routing False — every backend outside the Anthropic-SDK family) always
    # resolves to its OWN configured model, even with routing on + the tier mapped. So the L2 cache key
    # and the determinism gate never label a routed model the backend never actually invoked.
    monkeypatch.setenv(routing._ENABLE_ENV, "1")
    monkeypatch.setenv(f"{routing._TIER_ENV_PREFIX}STANDARD", _OLD)
    nonwired = _FakeBackend(_CURRENT, honors_routing=False)
    assert llm.resolve_effective_model(_p(model_tier="standard"), nonwired) == _CURRENT   # NOT _OLD
    wired = _FakeBackend(_CURRENT, honors_routing=True)
    assert llm.resolve_effective_model(_p(model_tier="standard"), wired) == _OLD           # honors -> routed


# ---- the Anthropic backend applies the sampling regime of the EFFECTIVE model (CONFIRMED red-pen MED) --
class _CaptureClient:
    """Captures the kwargs of the single messages.create call; returns an opaque stub (the raw round-trip
    value _create_with_backoff returns unparsed)."""

    def __init__(self) -> None:
        self.kw: dict | None = None

    @property
    def messages(self):
        return self

    def create(self, **kw):
        self.kw = dict(kw)
        return "stub"


def _bare_anthropic(model: str):
    be = _anthropic.AnthropicBackend.__new__(_anthropic.AnthropicBackend)   # bypass __init__ (no SDK/key)
    be.model = model
    return be


def test_anthropic_sampling_regime_follows_effective_model(monkeypatch):
    # The bug 4 red-pen lenses confirmed: _create_with_backoff sent the request to the routed `model` but
    # computed sampling_create_kwargs(self.model) — so a cross-generation route sent the wrong family.
    # It must compute the regime from the EFFECTIVE model (matching bedrock/vertex).
    monkeypatch.delenv("CRUCIBLE_EFFORT", raising=False)
    prompt = _p(temperature=0.2, effort=None)

    # self.model CURRENT, routed to an OLDER model -> OLDER family: temperature present, no output_config.
    cli = _CaptureClient()
    _bare_anthropic(_CURRENT)._create_with_backoff(cli, "s", "u", prompt, _OLD)
    assert cli.kw["model"] == _OLD
    assert cli.kw.get("temperature") == 0.2          # from the EFFECTIVE (older) model, NOT self.model
    assert "output_config" not in cli.kw

    # self.model OLDER, routed to a CURRENT model -> CURRENT family: NO temperature (effort unset -> omitted).
    cli2 = _CaptureClient()
    _bare_anthropic(_OLD)._create_with_backoff(cli2, "s", "u", prompt, _CURRENT)
    assert cli2.kw["model"] == _CURRENT
    assert "temperature" not in cli2.kw              # current family rejects temperature; regime from EFFECTIVE


# ---- the L2 cache seam keys on the EFFECTIVE model ---------------------------------------------------
def test_l2_store_keys_on_effective_model(monkeypatch):
    """With routing on + STANDARD->older-model, a temp-0 single-shot call on a CURRENT-gen backend is
    L2-cacheable (the effective model is the older one). The old code keyed on backend.model (current)
    and is_deterministic would be False -> rc.store never called. So capturing rc.store's model kwarg
    distinguishes the two: the seam must store under the effective (older) model."""
    monkeypatch.setenv(routing._ENABLE_ENV, "1")
    monkeypatch.setenv(f"{routing._TIER_ENV_PREFIX}STANDARD", _OLD)
    for e in ("CRUCIBLE_CACHE_DISABLE", "CRUCIBLE_L2_DISABLED"):
        monkeypatch.delenv(e, raising=False)
    seen: list[str] = []
    monkeypatch.setattr(rc, "resolve_scope", lambda: (None, None))
    monkeypatch.setattr(rc, "store", lambda *a, **k: seen.append(k["model"]))
    backend = _FakeBackend(_CURRENT, name="fake")
    res = LLMResult(parsed=S(x=1),
                    trace=make_call_trace("fake", is_dryrun=False, cognitive_doc="d",
                                          cognitive_sections=[], tokens_in=1, tokens_out=1),
                    raw_response='{"x": 1}')
    llm._l2_store(_p(model_tier="standard"), res, backend)
    assert seen == [_OLD]        # stored under the EFFECTIVE model, not backend.model (_CURRENT)


def test_l2_lookup_keys_on_effective_model(monkeypatch):
    monkeypatch.setenv(routing._ENABLE_ENV, "1")
    monkeypatch.setenv(f"{routing._TIER_ENV_PREFIX}STANDARD", _OLD)
    for e in ("CRUCIBLE_CACHE_DISABLE", "CRUCIBLE_L2_DISABLED"):
        monkeypatch.delenv(e, raising=False)
    seen: list[str] = []
    monkeypatch.setattr(rc, "resolve_scope", lambda: (None, None))
    monkeypatch.setattr(rc, "lookup", lambda *a, **k: seen.append(k["model"]) or None)
    llm._l2_lookup(_p(model_tier="standard"), _FakeBackend(_CURRENT, name="fake"))
    assert seen == [_OLD]


def test_l2_off_keys_on_backend_model(monkeypatch):
    # routing OFF: the effective model == backend.model, so the L2 key is byte-identical to pre-EC-2a.
    for e in ("CRUCIBLE_CACHE_DISABLE", "CRUCIBLE_L2_DISABLED"):
        monkeypatch.delenv(e, raising=False)
    seen: list[str] = []
    monkeypatch.setattr(rc, "resolve_scope", lambda: (None, None))
    monkeypatch.setattr(rc, "lookup", lambda *a, **k: seen.append(k["model"]) or None)
    llm._l2_lookup(_p(model_tier="standard"), _FakeBackend(_OLD, name="fake"))
    assert seen == [_OLD]        # == backend.model (routing off), never an override


# ---- binding.run assigns the tier from the binding identity -----------------------------------------
def _capturing_backend(captured: dict) -> LLMBackend:
    class Cap(LLMBackend):
        name = "cap"
        model = _CURRENT

        def is_available(self):
            return (True, "ok")

        @property
        def is_dryrun(self):
            return True

        def complete(self, prompt):
            captured["tier"] = prompt.model_tier
            return LLMResult(
                parsed=CritiqueResult(claim="c", decision="confirm", deception_check="x"),
                trace=make_call_trace(self.name, is_dryrun=True, cognitive_doc="", cognitive_sections=[]),
                raw_response="")
    return Cap()


def test_binding_run_assigns_tier_from_identity():
    cap: dict = {}
    binding.run(schema=CritiqueResult, schema_name="CritiqueResult",
                cognitive_doc_stem="self-critique", section_anchors=[],
                task_directive="t", structured_input={"a": 1}, backend=_capturing_backend(cap))
    assert cap["tier"] == "deep"       # the finding-gate binding's identity -> deep


def test_binding_run_explicit_tier_wins():
    cap: dict = {}
    binding.run(schema=CritiqueResult, schema_name="CritiqueResult",
                cognitive_doc_stem="self-critique", section_anchors=[],
                task_directive="t", structured_input={"a": 1}, model_tier="cheap",
                backend=_capturing_backend(cap))
    assert cap["tier"] == "cheap"      # an explicit caller tier overrides the identity default


# ---- CallTrace records the model used ---------------------------------------------------------------
def test_make_call_trace_records_model():
    tr = make_call_trace("b", is_dryrun=False, cognitive_doc="d", cognitive_sections=[], model="m-1")
    assert tr.model == "m-1"


def test_call_trace_model_defaults_empty():
    tr = make_call_trace("b", is_dryrun=False, cognitive_doc="d", cognitive_sections=[])
    assert tr.model == ""           # backward compatible: a caller / persisted trace without it
