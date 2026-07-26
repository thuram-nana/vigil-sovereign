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


def complete_with_failover(prompt: "Prompt") -> "LLMResult":
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
    backend bypasses this entirely (the caller owns that choice)."""
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
    latency_ms: float = 0.0,
) -> CallTrace:
    return CallTrace(
        backend=backend,
        is_dryrun=is_dryrun,
        cognitive_doc=cognitive_doc,
        cognitive_sections=cognitive_sections,
        tokens_in=tokens_in,
        tokens_out=tokens_out,
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
