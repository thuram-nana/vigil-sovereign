"""
kernel.binding — shared helpers for the six cognitive bindings.

Every binding in URK does roughly the same thing:

    1. Load the relevant cognitive doc via common.docs.
    2. Pull the sections that govern this call.
    3. Build a system prompt that quotes those sections verbatim.
    4. Build a user prompt from the structured input.
    5. Call the active backend.
    6. Return the parsed Pydantic instance plus a CallTrace.

This module factors out steps 3-6 so each binding is short and
prose-led. The system prompt deliberately quotes v1 prose rather than
paraphrasing — URK does not replace the cognitive layer, it cites it.
"""

from __future__ import annotations

import json
from typing import Any

from pydantic import BaseModel

from ..common import docs
from .llm import LLMBackend, Prompt, get_backend
from .models import CallTrace


def _format_section_excerpt(doc: docs.Document, anchor: str, max_chars: int = 1500) -> str:
    sec = doc.section(anchor)
    return f"### § {sec.heading}\n\n{sec.excerpt(max_chars)}"


def build_system_prompt(
    doc: docs.Document, section_anchors: list[str], task_directive: str,
) -> str:
    """Construct a system prompt by quoting the cognitive doc."""
    body_parts = []
    for a in section_anchors:
        try:
            body_parts.append(_format_section_excerpt(doc, a))
        except KeyError:
            # graceful: skip anchors not found.  The binding caller is
            # the source-of-truth for which sections exist.
            continue
    quoted = "\n\n".join(body_parts)
    return (
        "You are OBSIDIAN, the offensive-security agent. The framework "
        "you operate is CRUCIBLE.  The sections below are the v1 cognitive "
        "doctrine that governs this specific call. Reason from them.\n\n"
        f"--- Source: framework/cognitive/{doc.path.name} ---\n\n"
        f"{quoted}\n\n"
        "--- Task ---\n\n"
        f"{task_directive}"
    )


def build_user_prompt(structured_input: dict[str, Any]) -> str:
    """Render the structured input as a JSON block. Bindings can extend."""
    return (
        "Structured input:\n\n"
        f"```json\n{json.dumps(structured_input, indent=2, default=str)}\n```"
    )


def run(
    *,
    schema: type[BaseModel],
    schema_name: str,
    cognitive_doc_stem: str,
    section_anchors: list[str],
    task_directive: str,
    structured_input: dict[str, Any],
    backend: LLMBackend | None = None,
    extra_user: str = "",
    temperature: float = 0.2,
    max_tokens: int = 4096,
) -> tuple[BaseModel, CallTrace]:
    """Render the prompt, dispatch to the active backend, return (parsed, trace)."""
    doc = docs.cognitive(cognitive_doc_stem)
    system = build_system_prompt(doc, section_anchors, task_directive)
    user = build_user_prompt(structured_input)
    if extra_user:
        user += "\n\n" + extra_user

    prompt = Prompt(
        system=system,
        user=user,
        schema=schema,
        schema_name=schema_name,
        cognitive_doc=f"framework/cognitive/{doc.path.name}",
        cognitive_sections=section_anchors,
        structured_input=structured_input,
        temperature=temperature,
        max_tokens=max_tokens,
    )
    be = backend or get_backend()
    result = be.complete(prompt)
    return result.parsed, result.trace
