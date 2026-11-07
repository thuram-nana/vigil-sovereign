"""
kernel.llm — LLM backend abstraction used by every URK binding.

Three backends ship in this session:

    AnthropicBackend  — Anthropic API (live).      Activates when
                        ANTHROPIC_API_KEY is set and `anthropic` is
                        installed.
    OllamaBackend     — local Ollama daemon.       Activates when
                        http://localhost:11434/api/version answers.
    DryRunBackend     — default fallback.          Always available.
                        Writes the prompt to disk; returns a
                        deterministic structured stub built from the
                        per-binding fixture.

Selection order is anthropic > ollama > dryrun unless overridden by
CRUCIBLE_LLM_BACKEND (one of: anthropic, ollama, dryrun).

The contract is simple: a binding builds a Prompt, calls
`get_backend().complete(prompt)`, gets back an LLMResult with a
parsed Pydantic instance and a CallTrace.
"""

from __future__ import annotations

import abc
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel

from ..common import logging as v2log
from ..common.errors import (
    BackendError, BackendOverloaded, BackendUnavailable, SovereigntyViolation,
)
from . import sovereignty
from .models import CallTrace


_log = v2log.get_logger(__name__)

# Per-tool TOKEN BUDGETS (warn + throttle, never block). vigil_core is the shared substrate both planes
# import; guard the import so the kernel still runs if it is ever unavailable — metering is advisory
# back-pressure, never a gate, so its absence must NEVER stop a completion.
try:                                                       # pragma: no cover - import guard
    from vigil_core import token_budget as _token_budget
except Exception:                                          # noqa: BLE001
    _token_budget = None

# M4.1 — the ONE egress chokepoint both LLM paths route through. vigil_core is the shared leaf both the
# offense framework and the sovereign planes import, so composing the egress discipline (classify ->
# redact -> authorize -> route -> provenance -> output-verify -> audit) there crosses no FATAL-2 boundary.
# Guarded like the budget import so the kernel still completes a call if the shared core is ever absent;
# when present it is the egress path (it adds the symmetric secret-redaction the URK path lacked, and the
# unified audit record), with sovereignty still asserted at backend construction underneath.
try:                                                       # pragma: no cover - import guard
    from vigil_core import ai_gateway as _gw
except Exception:                                          # noqa: BLE001
    _gw = None


def _tb_tool() -> str:
    try:
        return _token_budget.current_tool() if _token_budget else "engine"
    except Exception:                                      # noqa: BLE001
        return "engine"


def _tb_throttle(tool: str) -> None:
    """Consult the tool's budget and SLEEP the bounded throttle delay if over. Never blocks, never raises."""
    if _token_budget is None:
        return
    try:
        _token_budget.throttle(tool)
    except Exception:                                      # noqa: BLE001
        pass


def _tb_clamp(tool: str, max_tokens: int) -> int:
    if _token_budget is None:
        return max_tokens
    try:
        return _token_budget.clamp_output(tool, max_tokens)
    except Exception:                                      # noqa: BLE001
        return max_tokens


def _tb_record(tool: str, trace: "CallTrace") -> None:
    """Charge the ACTUAL tokens a real (non-dry-run) call spent. Never raises."""
    if _token_budget is None or getattr(trace, "is_dryrun", False):
        return
    try:
        spent = int(getattr(trace, "tokens_in", 0) or 0) + int(getattr(trace, "tokens_out", 0) or 0)
        if spent > 0:
            _token_budget.record(tool, spent)
    except Exception:                                      # noqa: BLE001
        pass


@dataclass
class Prompt:
    """Everything one URK call sends to the LLM."""

    system: str
    user: str
    schema: type[BaseModel]
    schema_name: str
    cognitive_doc: str
    cognitive_sections: list[str] = field(default_factory=list)
    structured_input: dict[str, Any] = field(default_factory=dict)
    temperature: float = 0.2
    max_tokens: int = 4096
    # Reasoning effort for current-generation models (output_config.effort). None => the caller lets the
    # operator default (CRUCIBLE_EFFORT) or the model's own default decide; an explicit value overrides.
    # Resolved + applied per-backend via sampling_create_kwargs (older models ignore it and take temperature).
    effort: str | None = None
    # Self-consistency policy (anti-hallucination P5), for NO-ORACLE bindings only. samples>1
    # declares that the call site wants N-sample agreement clustering (see kernel.consistency);
    # agreement_gate is the modal-share threshold below which the site should ABSTAIN. Defaults
    # (samples=1) are single-shot — identical to pre-P5 behaviour. Oracle-backed sites leave
    # these at the default; an LLM vote must never dispose a claim an oracle settles.
    samples: int = 1
    agreement_gate: float = 0.6


@dataclass
class LLMResult:
    parsed: BaseModel
    trace: CallTrace
    raw_response: str = ""


# The operator-selectable reasoning-effort levels (the Settings picker allowlist + the chatbot's slider).
EFFORT_LEVELS = ("low", "medium", "high", "xhigh", "max")

# Current-generation models REMOVE the sampling params (temperature/top_p/top_k) — sending any is a 400 —
# and instead accept `output_config.effort`. Older models accept temperature and do not know effort. This
# is the SINGLE source of that model-family split; the anthropic backend + the Bedrock/Vertex wrappers
# (all first-party anthropic-SDK `messages.create`) share sampling_create_kwargs below.
_CURRENT_MODEL_PREFIXES = (
    "claude-fable-5", "claude-mythos-5", "claude-opus-5", "claude-sonnet-5",
    "claude-opus-4-8", "claude-opus-4-7",
)


def is_current_model(model: str) -> bool:
    """True if `model` is a current-generation Claude that takes output_config.effort and rejects sampling."""
    m = str(model or "")
    return any(m.startswith(p) for p in _CURRENT_MODEL_PREFIXES)


def resolve_effort(explicit: str | None) -> str | None:
    """The effort level for a call: an explicit choice wins, else the operator default (env CRUCIBLE_EFFORT),
    else None. An unset/unknown value returns None (the backend simply omits output_config) — never raises."""
    val = (explicit or os.environ.get("CRUCIBLE_EFFORT") or "").strip().lower()
    return val if val in EFFORT_LEVELS else None


def sampling_create_kwargs(model: str, temperature: float, effort: str | None) -> dict:
    """The model-appropriate reasoning knobs for a first-party anthropic-SDK `messages.create`:
      * OLDER model  → {"temperature": ...}          (current models 400 if temperature is sent)
      * CURRENT model→ {"output_config": {"effort"}}  only when an effort resolves; else {} (model default)
    Never sends budget_tokens (deprecated / 400 on current models). One helper so anthropic/bedrock/vertex
    stay consistent and a current-model selection on Bedrock/Vertex no longer sends a rejected temperature."""
    if not is_current_model(model):
        return {"temperature": temperature}
    eff = resolve_effort(effort)
    return {"output_config": {"effort": eff}} if eff else {}


# EC-1a prompt caching — the `system` param for a first-party anthropic-SDK messages.create.
# Caching is a COST optimization and must NEVER override the zero-data-retention sovereignty
# posture, so the ephemeral cache_control breakpoint is attached ONLY when caching is allowed;
# otherwise the plain pre-caching string is sent, so no vendor-side prompt retention is requested.
def prompt_cache_disabled() -> bool:
    """Operator opt-out (CRUCIBLE_PROMPT_CACHE_DISABLED) — an escape hatch for a model/region that
    rejects cache_control. Default OFF (caching ON)."""
    return os.environ.get("CRUCIBLE_PROMPT_CACHE_DISABLED", "").strip().lower() in ("1", "true", "yes", "on")


def _ephemeral_session_active() -> bool:
    """True while a --ephemeral / ZDR session is active (common.ephemeral). Lazy + guarded so a
    status query can never break a completion, and so importing llm never pulls in common.ephemeral."""
    try:
        from ..common import ephemeral
        return bool(ephemeral.is_active())
    except Exception:                                      # noqa: BLE001 — metering/posture query, never a gate
        return False


def system_param(sys_prompt: str, *, zdr: bool = False) -> "str | list[dict]":
    """Return a cache_control content block (one ephemeral breakpoint at the end of the stable
    system span) to enable Anthropic prompt caching — UNLESS caching must be off: a ZDR backend, an
    active --ephemeral session (common.ephemeral: 'leaves nothing behind / never route reasoning
    through a data-retaining vendor'), or the operator opt-out. In those cases the plain string is
    returned — the exact pre-EC-1a wire shape — so the vendor is never asked to retain the prefix."""
    if zdr or prompt_cache_disabled() or _ephemeral_session_active():
        return sys_prompt
    return [{"type": "text", "text": sys_prompt, "cache_control": {"type": "ephemeral"}}]


class LLMBackend(abc.ABC):
    """All backends implement this. Subclasses set `name`."""

    name: str = "abstract"

    @abc.abstractmethod
    def is_available(self) -> tuple[bool, str]:
        """(available, one-line note). Cheap; called by status / probe_all."""

    @abc.abstractmethod
    def complete(self, prompt: Prompt) -> LLMResult: ...

    @property
    def is_dryrun(self) -> bool:
        return False


# ---------------------------------------------------------------------------
# selection
# ---------------------------------------------------------------------------

_ENV_OVERRIDE = "CRUCIBLE_LLM_BACKEND"
_cached_backend: LLMBackend | None = None


def _construct(name: str) -> LLMBackend:
    """Import backends lazily so the module loads without optional deps.

    The sovereignty policy is checked *before* any import of a cloud
    backend's SDK — strict tiers never import `anthropic`, `boto3`,
    or `google-auth` even to probe availability.
    """
    sovereignty.current().assert_permitted(name)
    if name == "anthropic":
        from .backends.anthropic import AnthropicBackend
        return AnthropicBackend(zdr=False)
    if name == "anthropic-zdr":
        from .backends.anthropic import AnthropicBackend
        return AnthropicBackend(zdr=True)
    if name == "bedrock":
        from .backends.bedrock import BedrockBackend
        return BedrockBackend()
    if name == "vertex":
        from .backends.vertex import VertexBackend
        return VertexBackend()
    if name == "mistral":
        from .backends.mistral import MistralBackend
        return MistralBackend()
    if name == "azure_openai":
        from .backends.azure_openai import AzureOpenAIBackend
        return AzureOpenAIBackend()
    if name in ("self-hosted", "vllm", "llama-cpp", "tgi"):
        # one OpenAI-compatible backend serves all three declared self-hosted names (+ the generic alias)
        from .backends.self_hosted import SelfHostedOpenAIBackend
        return SelfHostedOpenAIBackend(backend_name=name)
    if name == "claude-code":
        from .backends.claude_code import ClaudeCodeBackend
        return ClaudeCodeBackend()
    if name == "ollama":
        from .backends.ollama import OllamaBackend
        return OllamaBackend()
    if name == "dryrun":
        from .backends.dryrun import DryRunBackend
        return DryRunBackend()
    raise BackendUnavailable(f"unknown backend {name!r}")


def get_backend(force: str | None = None, refresh: bool = False) -> LLMBackend:
    """Return the active backend.

    `force` overrides everything. `refresh` reprobes the registry —
    useful in tests after env changes.
    """
    global _cached_backend

    if force is not None:
        return _construct(force)

    if _cached_backend is not None and not refresh:
        return _cached_backend

    policy = sovereignty.current()

    override = os.environ.get(_ENV_OVERRIDE, "").strip().lower()
    if override:
        # `_construct` re-asserts the policy; an attempt to override
        # to a cloud backend in sovereign mode raises here, fail-closed.
        b = _construct(override)
        _cached_backend = b
        _log.info(
            "kernel.backend.selected",
            backend=b.name, reason="env-override",
            sovereign=policy.strict,
        )
        return b

    for name in policy.permitted_preference():
        try:
            cand = _construct(name)
        except (BackendUnavailable, SovereigntyViolation):
            # SovereigntyViolation should never appear here because
            # `permitted_preference()` already filters; catching it
            # is defence-in-depth in case a future policy variant
            # offers cloud names but rejects on construction.
            continue
        ok, note = cand.is_available()
        if ok:
            _cached_backend = cand
            _log.info(
                "kernel.backend.selected",
                backend=cand.name, reason="auto", note=note,
                sovereign=policy.strict,
            )
            return cand

    # DryRun is always available; this branch should be unreachable.
    raise BackendUnavailable("no backend available, not even DryRun (impossible)")


def reset_cache() -> None:
    global _cached_backend
    _cached_backend = None


# EC-1b — L2 deterministic response cache seam. A deterministic completion (single-shot, temperature 0, older
# model) is served from the per-tenant local store instead of re-calling the provider, at zero tokens. The
# cache sits OUTSIDE the egress chokepoint, so a HIT reaches no provider — and therefore skips NO security
# gate: a MISS runs the full gated path (throttle -> redact -> authorize -> route -> audit) unchanged, and only
# then stores. Fail-safe (any error -> the normal path) and OFF (byte-identical) for a non-deterministic /
# dry-run / ZDR-ephemeral call or when the cache kill-switch is set.
def _l2_backend_for_failover(prompt: "Prompt"):
    """The auto-selected backend to key the L2 cache on — resolved ONLY when the prompt is plausibly
    cacheable (cheap pre-gate: cache enabled, not ephemeral, samples==1, temperature==0.0), so a
    non-deterministic call never resolves a backend or opens the cache for L2's sake. None => skip L2."""
    try:
        from . import response_cache as _rc
        if (_ephemeral_session_active() or _rc.l2_disabled()
                or int(getattr(prompt, "samples", 1)) != 1
                or float(getattr(prompt, "temperature", 0.2)) != 0.0):
            return None
        return get_backend()
    except Exception:                                    # noqa: BLE001 — never let L2 break a completion
        return None


def _l2_tier() -> str:
    try:
        return str(getattr(sovereignty.current().tier, "value", "") or "")
    except Exception:                                    # noqa: BLE001
        return ""


def _l2_lookup(prompt: "Prompt", backend: "LLMBackend"):
    """A rebuilt LLMResult on a cache HIT, else None. Runs the FULL determinism gate (incl. the
    model-family check now that the backend is known) + ZDR/dry-run/kill-switch exclusions."""
    try:
        from . import response_cache as _rc
        model = str(getattr(backend, "model", "") or "")
        if (bool(getattr(backend, "is_dryrun", False)) or _ephemeral_session_active()
                or _rc.l2_disabled() or not _rc.is_deterministic(prompt, model)):
            return None
        org, slug = _rc.resolve_scope()
        return _rc.lookup(prompt, backend=str(getattr(backend, "name", "") or ""), model=model,
                          tier=_l2_tier(), org_id=org, slug=slug)
    except Exception:                                    # noqa: BLE001
        return None


def _l2_store(prompt: "Prompt", result: "LLMResult", backend: "LLMBackend") -> None:
    """Persist a fresh (MISS-path) deterministic completion. Never caches a dry-run or already-cached result,
    and never caches a result a DIFFERENT backend produced than the one the key is built from. The L2 key is
    built from the PRIMARY (``get_backend()``), but ``complete_with_failover`` may fail over IN-TIER to a
    secondary backend on a transient overload; caching that answer under the primary's key would MIS-PROVENANCE
    the store — a later lookup keyed on the primary would serve a value a different model actually produced, and
    a current-gen secondary (NOT determinism-guaranteed) could be cached under the older-model key. So the store
    is gated on the ANSWERING backend (``result.trace.backend``) matching ``backend.name``: a failover is a rare
    overload event, and skipping its store costs at most one re-call — never a cross-model or stale HIT."""
    try:
        from . import response_cache as _rc
        model = str(getattr(backend, "model", "") or "")
        if (bool(getattr(backend, "is_dryrun", False)) or _ephemeral_session_active()
                or _rc.l2_disabled() or not _rc.is_deterministic(prompt, model)):
            return
        tr = getattr(result, "trace", None)
        if tr is not None and (getattr(tr, "cached", False) or getattr(tr, "is_dryrun", False)):
            return
        if str(getattr(tr, "backend", "") or "") != str(getattr(backend, "name", "") or ""):
            return                                       # a failover/secondary backend answered: never cache it
        org, slug = _rc.resolve_scope()
        _rc.store(prompt, result, backend=str(getattr(backend, "name", "") or ""), model=model,
                  tier=_l2_tier(), org_id=org, slug=slug)
    except Exception:                                    # noqa: BLE001
        pass


def complete_with_failover(prompt: "Prompt") -> "LLMResult":
    """Complete ``prompt`` with failover (see ``_complete_with_failover_raw`` for the failover contract),
    wrapped in the per-tool TOKEN BUDGET: consult the current tool's budget and apply WARN + THROTTLE
    (a bounded delay, NEVER a block) before the call, clamp the per-call output ceiling, and charge the
    ACTUAL tokens the call spent afterwards. The tool is read from ``token_budget.current_tool()`` (a
    subsystem sets it with ``using_tool(...)``; the default is ``engine``). Metering never changes what
    the call does — it can only slow it and record it.

    EC-1b: a deterministic prompt is first looked up in the L2 response cache; a HIT returns with no
    provider call and no budget charge (0 tokens). A MISS runs the gated path below unchanged, then stores."""
    _b = _l2_backend_for_failover(prompt)
    if _b is not None:
        _hit = _l2_lookup(prompt, _b)
        if _hit is not None:
            return _hit                                  # served from cache: no throttle, no egress, no charge
    tool = _tb_tool()
    _tb_throttle(tool)                                   # warn + throttle (bounded), never blocks
    _mx = getattr(prompt, "max_tokens", None)            # defensive: a minimal prompt double may lack it
    if _mx is not None:
        try:
            prompt.max_tokens = _tb_clamp(tool, _mx)
        except (AttributeError, TypeError):
            pass
    result = _route_urk_egress(prompt)                   # M4.1: through the single egress chokepoint
    _tb_record(tool, getattr(result, "trace", None))     # None trace records nothing (spent == 0)
    if _b is not None:
        # Store under the ORIGINAL (pre-clamp) max_tokens. The budget clamp mutated prompt.max_tokens for the
        # provider call, but the L2 LOOKUP above keyed on the original, so the store must too — otherwise L2
        # would never hit under budget pressure (a silent cost-saving defeat). A HIT is free (0 tokens), so the
        # clamp (back-pressure) is a miss-path-only concern; the cache maps the caller's deterministic REQUEST
        # to its response. Leaving max_tokens at the original also undoes the clamp's in-place mutation of the
        # caller's prompt (cleaner; a reused prompt then re-keys on the original too).
        if _mx is not None:
            try:
                prompt.max_tokens = _mx
            except (AttributeError, TypeError):
                pass
        _l2_store(prompt, result, _b)                    # cache the fresh deterministic result (fail-safe)
    return result


# ---------------------------------------------------------------------------
# M4.1 — the URK adapter: route the in-tier failover through the shared egress chokepoint.
# ---------------------------------------------------------------------------


def _intended_backend_name() -> str:
    """The backend name the next URK call will use IF the operator pinned one via ``CRUCIBLE_LLM_BACKEND``;
    an empty string means auto-selection (the gateway then skips the pre-assert and lets the per-candidate
    sovereignty check inside construction decide). Reads env only — never constructs or probes a backend."""
    return os.environ.get(_ENV_OVERRIDE, "").strip().lower()


def _apply_redaction_to_prompt(prompt: "Prompt", redacted: dict) -> "Prompt":
    """Return a prompt whose ``system``/``user`` carry the gateway-redacted text, so the backend sends the
    masked payload. A prompt double with no such fields (the resilience tests pass ``SimpleNamespace()``)
    is returned unchanged. Never raises."""
    rs, ru = redacted.get("system"), redacted.get("user")
    if rs is None and ru is None:
        return prompt
    updates = {}
    if isinstance(rs, str):
        updates["system"] = rs
    if isinstance(ru, str):
        updates["user"] = ru
    if not updates:
        return prompt
    try:
        import dataclasses
        if dataclasses.is_dataclass(prompt):
            return dataclasses.replace(prompt, **updates)
    except Exception:  # noqa: BLE001 — fall through to a shallow-copy mutation
        pass
    try:
        import copy
        p = copy.copy(prompt)
        for k, v in updates.items():
            setattr(p, k, v)
        return p
    except Exception:  # noqa: BLE001 — last resort: send the original (unredacted) rather than crash
        return prompt


def _urk_provenance(result: "LLMResult") -> dict:
    """Extract the answering backend + token counts from the result's CallTrace for the unified record.
    The provider is NEVER a trust anchor; this is provenance, not authority. Never raises."""
    tr = getattr(result, "trace", None)
    if tr is None:
        return {}
    return {
        "answered_backend": getattr(tr, "backend", ""),
        "tokens_in": int(getattr(tr, "tokens_in", 0) or 0),
        "tokens_out": int(getattr(tr, "tokens_out", 0) or 0),
        "is_dryrun": bool(getattr(tr, "is_dryrun", False)),
    }


def _route_urk_egress(prompt: "Prompt") -> "LLMResult":
    """Route one URK completion through ``vigil_core.ai_gateway.egress`` (classify -> redact -> authorize
    -> route -> provenance -> output-verify -> audit). When the shared core is absent the call still
    completes via the in-tier failover, with sovereignty asserted at construction. A sovereignty refusal
    surfaces as :class:`SovereigntyViolation` (the URK contract)."""
    if _gw is None:
        return _complete_with_failover_raw(prompt)

    def _invoke(redacted: dict) -> "LLMResult":
        _gw.assert_in_egress("kernel.urk")               # a bypass of the chokepoint fails closed
        return _complete_with_failover_raw(_apply_redaction_to_prompt(prompt, redacted))

    case = _gw.EgressCase(
        path="urk",
        invoke=_invoke,
        backend=_intended_backend_name(),                # "" => auto (per-candidate assert inside invoke)
        assert_permitted=lambda name: sovereignty.current().assert_permitted(name),
        provenance=_urk_provenance,
        provider_identity=_intended_backend_name() or "urk-backend",
    )
    payload = {"system": getattr(prompt, "system", None), "user": getattr(prompt, "user", None)}
    res = _gw.egress(payload, case=case)
    if res.refused:
        if res.refusal_kind == "sovereignty":
            raise SovereigntyViolation(res.refusal_reason)
        raise BackendUnavailable(res.refusal_reason)
    return res.output


def _backend_complete_raw(backend: "LLMBackend", prompt: "Prompt") -> "LLMResult":
    """The raw round-trip for an EXPLICITLY-provided backend. Reached ONLY inside the egress context (asserts
    it first), so a direct call that skips the chokepoint fails closed."""
    if _gw is not None:
        _gw.assert_in_egress("kernel.urk.explicit")     # raw explicit-backend round-trip: only inside egress
    return backend.complete(prompt)


def complete_with_backend(backend: "LLMBackend", prompt: "Prompt") -> "LLMResult":
    """Complete ``prompt`` on an EXPLICITLY-provided backend (``binding.run(backend=...)`` — a pinned run or a
    test), routed through the ONE egress chokepoint — classify -> redact -> provenance -> audit — exactly like
    the auto-selected failover path, so there is no second un-redacted, un-audited egress. The explicit backend
    is the caller's choice, so there is NO failover and NO sovereignty pre-assert (the backend was already
    constructed, which asserts the policy); the gateway still masks every credential shape it recognises in the
    prompt, records the unified audit entry, and runs the call inside the egress context so a bypass fails
    closed. When the shared core is absent the call still completes via the raw round-trip.

    EC-1b: a deterministic prompt on this explicit backend is first looked up in the L2 response cache; a
    HIT returns with no provider round-trip; a MISS runs the gated path below unchanged, then stores."""
    _hit = _l2_lookup(prompt, backend)
    if _hit is not None:
        return _hit
    if _gw is None:
        _r = _backend_complete_raw(backend, prompt)
        _l2_store(prompt, _r, backend)
        return _r

    def _invoke(redacted: dict) -> "LLMResult":
        return _backend_complete_raw(backend, _apply_redaction_to_prompt(prompt, redacted))

    case = _gw.EgressCase(
        path="urk_explicit", invoke=_invoke, backend="",     # explicit backend: no failover, no pre-assert
        provenance=_urk_provenance,
        provider_identity=str(getattr(backend, "name", "") or "urk-backend"),
    )
    payload = {"system": getattr(prompt, "system", None), "user": getattr(prompt, "user", None)}
    res = _gw.egress(payload, case=case)
    if res.refused:
        raise BackendUnavailable(res.refusal_reason)
    _l2_store(prompt, res.output, backend)
    return res.output


def _complete_with_failover_raw(prompt: "Prompt") -> "LLMResult":
    """Complete ``prompt``, failing over across the permitted backends IN-TIER on a transient
    overload (Speed X4). Tries the auto-selected primary (the cached ``get_backend()``); a
    :class:`BackendOverloaded` — a rate-limit / overload / 5xx / connection failure that
    survived the backend's own backoff — advances to the NEXT available backend in the tier's
    ``permitted_preference()``. A plain :class:`BackendError` (a permanent / parse failure) is
    NOT failed over — another backend would not fix it. The answering backend is recorded in the
    returned trace. NEVER escapes the sovereignty tier: only ``permitted_preference()`` backends
    are tried, each re-asserting the policy on construction.

    An explicit env-override backend is honoured as the operator's choice (no failover). This is
    the auto-selection path binding._bind uses when no backend is passed; an explicitly-passed
    backend bypasses this entirely (the caller owns that choice).

    Every ``backend.complete`` below is a raw provider round-trip reached ONLY from inside the egress
    context (via :func:`_route_urk_egress`'s invoke closure), so this asserts that context first — a
    direct call that skips the chokepoint fails closed. The no-bypass guard depends on this self-assertion."""
    if _gw is not None:
        _gw.assert_in_egress("kernel.urk.raw")     # raw URK round-trips: reached only inside the gateway
    override = os.environ.get(_ENV_OVERRIDE, "").strip().lower()
    if override:
        return get_backend().complete(prompt)      # explicit operator choice: no failover

    primary = get_backend()                          # cached + logged selection (common path)
    last_overload: BackendOverloaded | None = None
    try:
        return primary.complete(prompt)
    except BackendOverloaded as e:
        last_overload = e
        _log.warning("kernel.backend.failover", from_backend=primary.name, error=str(e)[:200])

    tried = {primary.name}
    for name in sovereignty.current().permitted_preference():
        try:
            cand = _construct(name)                  # re-asserts sovereignty
        except (BackendUnavailable, SovereigntyViolation):
            continue
        if cand.name in tried:
            continue
        ok, _note = cand.is_available()
        if not ok:
            continue
        tried.add(cand.name)
        try:
            return cand.complete(prompt)
        except BackendOverloaded as e:
            last_overload = e
            _log.warning("kernel.backend.failover", from_backend=cand.name, error=str(e)[:200])
            continue
    # every in-tier candidate was overloaded — surface the overload (never silently drop).
    raise last_overload if last_overload is not None else BackendUnavailable(
        "no permitted backend available for failover")


# ---------------------------------------------------------------------------
# Helpers used by all live backends.
# ---------------------------------------------------------------------------


def make_call_trace(
    backend: str, *, is_dryrun: bool, cognitive_doc: str,
    cognitive_sections: list[str], tokens_in: int = 0, tokens_out: int = 0,
    cache_creation_input_tokens: int = 0, cache_read_input_tokens: int = 0,
    cached: bool = False, latency_ms: float = 0.0,
) -> CallTrace:
    return CallTrace(
        backend=backend,
        is_dryrun=is_dryrun,
        cognitive_doc=cognitive_doc,
        cognitive_sections=cognitive_sections,
        tokens_in=tokens_in,
        tokens_out=tokens_out,
        cache_creation_input_tokens=cache_creation_input_tokens,
        cache_read_input_tokens=cache_read_input_tokens,
        cached=cached,
        latency_ms=latency_ms,
        timestamp=datetime.now(timezone.utc).isoformat(timespec="seconds"),
    )


def parse_json_response(text: str, schema: type[BaseModel]) -> BaseModel:
    """Strip common markdown fences, then validate against schema.

    Raises BackendError with a useful message on validation failure.
    """
    import json
    import re

    # peel `​```json ... ​```` fences if the model wrapped its output
    fence = re.search(
        r"```(?:json)?\s*(.+?)\s*```", text, flags=re.DOTALL | re.IGNORECASE,
    )
    payload = fence.group(1) if fence else text
    payload = payload.strip()

    try:
        return schema.model_validate_json(payload)
    except Exception as e:
        # second chance: maybe the model returned a Python repr or extra prose
        try:
            obj = json.loads(payload)
            return schema.model_validate(obj)
        except Exception:
            pass
        raise BackendError(
            f"could not parse LLM response as {schema.__name__}: {e}\n"
            f"raw response (truncated): {payload[:500]!r}"
        )
