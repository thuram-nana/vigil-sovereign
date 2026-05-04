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
from ..common.errors import BackendError, BackendUnavailable
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


@dataclass
class LLMResult:
    parsed: BaseModel
    trace: CallTrace
    raw_response: str = ""


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
_PREFERENCE_ORDER = ("anthropic", "ollama", "dryrun")
_cached_backend: LLMBackend | None = None


def _construct(name: str) -> LLMBackend:
    """Import backends lazily so the module loads without optional deps."""
    if name == "anthropic":
        from .backends.anthropic import AnthropicBackend
        return AnthropicBackend()
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

    override = os.environ.get(_ENV_OVERRIDE, "").strip().lower()
    if override:
        b = _construct(override)
        _cached_backend = b
        _log.info("kernel.backend.selected", backend=b.name, reason="env-override")
        return b

    for name in _PREFERENCE_ORDER:
        try:
            cand = _construct(name)
        except BackendUnavailable:
            continue
        ok, note = cand.is_available()
        if ok:
            _cached_backend = cand
            _log.info(
                "kernel.backend.selected",
                backend=cand.name, reason="auto", note=note,
            )
            return cand

    # DryRun is always available; this branch should be unreachable.
    raise BackendUnavailable("no backend available, not even DryRun (impossible)")


def reset_cache() -> None:
    global _cached_backend
    _cached_backend = None


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
