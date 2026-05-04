"""
threat_model() — wraps framework/cognitive/threat-modeling.md.

Given a target description (and optional fingerprint output), produce
a structured ThreatModel: assets, actors, trust boundaries, STRIDE
threats, and an attack tree decomposing top assets into testable
leaves.
"""

from __future__ import annotations

from typing import Any

from .binding import run
from .llm import LLMBackend
from .models import CallTrace, ThreatModel


def threat_model(
    target_name: str,
    *,
    business_context: str = "",
    archetype: str = "",
    fingerprint: dict[str, Any] | None = None,
    known_concerns: list[str] | None = None,
    backend: LLMBackend | None = None,
) -> tuple[ThreatModel, CallTrace]:
    """Generate a structured threat model.

    Args:
        target_name: short slug or hostname for the target.
        business_context: one-paragraph description of what the target
            does and who its users are.
        archetype: stack archetype label (e.g. "PHP-Smarty SMM panel"),
            usually supplied by UTI.
        fingerprint: structured fingerprint output (server, framework,
            CMS, payment processors, ...).
        known_concerns: operator-provided focus areas (e.g. "users
            reporting account takeovers").
        backend: override the active LLM backend.

    Returns:
        (ThreatModel, CallTrace).
    """
    structured = {
        "target_name": target_name,
        "business_context": business_context,
        "archetype": archetype,
        "fingerprint": fingerprint or {},
        "known_concerns": known_concerns or [],
    }
    parsed, trace = run(
        schema=ThreatModel,
        schema_name="ThreatModel",
        cognitive_doc_stem="threat-modeling",
        section_anchors=[
            "1-what-a-threat-model-contains",
            "2-assets-whats-worth-attacking",
            "3-actors-whos-actually-attacking",
            "4-trust-boundaries-where-you-focus",
            "5-stride-per-boundary",
            "6-attack-trees",
        ],
        task_directive=(
            "Build a threat model in the order from § 1: assets, actors, "
            "trust boundaries, STRIDE per boundary, attack tree. Rank "
            "assets by combined business impact (§ 2). Profile a "
            "REALISTIC adversary set for this product (§ 3) — do not "
            "list every theoretical actor. Find every privilege crossing "
            "(§ 4) and emit STRIDE threats only for those that are "
            "realistic on this target. Build the attack tree (§ 6) "
            "rooted at top adversary objectives, decomposed to testable "
            "leaves. Include catastrophic_outcomes (§ 5 ranked) and "
            "not_in_model (§ 6 explicit out-of-model)."
        ),
        structured_input=structured,
        backend=backend,
        max_tokens=8000,
    )
    assert isinstance(parsed, ThreatModel)
    return parsed, trace
