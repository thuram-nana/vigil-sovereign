"""
LLM backends. Each implements the LLMBackend interface from kernel.llm.

The dispatch logic (selection, override, fallback) lives in kernel.llm.
This sub-package only exposes a `probe_all()` for the `status` CLI.
"""

from __future__ import annotations

from typing import Iterator

from ..llm import LLMBackend


_BACKEND_NAMES = (
    "anthropic", "anthropic-zdr",
    "bedrock", "vertex", "mistral", "azure_openai",
    "claude-code", "ollama", "self-hosted", "dryrun",
)


def probe_all() -> Iterator[tuple[str, bool, str]]:
    """Yield (name, available, note) for each backend. Cheap probes
    only — no API calls."""
    for name in _BACKEND_NAMES:
        try:
            cand = _construct(name)
        except Exception as e:
            yield name, False, f"construct failed: {e.__class__.__name__}: {e}"
            continue
        try:
            ok, note = cand.is_available()
        except Exception as e:
            ok, note = False, f"probe error: {e.__class__.__name__}: {e}"
        yield name, ok, note


def _construct(name: str) -> LLMBackend:
    # Defer to kernel.llm._construct so the sovereignty gate runs
    # before any cloud SDK is imported.
    from ..llm import _construct as llm_construct
    return llm_construct(name)
