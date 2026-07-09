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
from .consistency import ConsistencyResult, run_consistent, sample_workers
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


def _threat_signature(tm: ThreatModel) -> tuple:
    """The decision-bearing STRUCTURAL skeleton of a threat model — CATEGORICAL only, never prose.
    The multiset of STRIDE classes (S/T/R/I/D/E), the multiset of asset priorities (P0..P3), and
    the structural cardinality (assets / actors / boundaries). Two threat models with the same
    structural assessment cluster together; a scattered one does not. Free-text (business_context,
    names, tree labels) is excluded, per the decision-not-prose contract."""
    return (
        tuple(sorted(str(t.stride_class) for t in tm.stride_threats)),
        tuple(sorted(str(a.priority) for a in tm.assets)),
        (len(tm.assets), len(tm.actors), len(tm.trust_boundaries)),
    )


def threat_model_consistent(
    target_name: str,
    *,
    business_context: str = "",
    archetype: str = "",
    fingerprint: dict[str, Any] | None = None,
    known_concerns: list[str] | None = None,
    samples: int = 3,
    agreement_gate: float = 0.6,
    backend: LLMBackend | None = None,
) -> ConsistencyResult:
    """Self-consistent threat model — a NO-ORACLE binding. Runs :func:`threat_model` ``samples``
    times and clusters by the STRUCTURAL skeleton (STRIDE classes / asset priorities / cardinality).
    ``abstained`` True flags an unstable structural assessment to RENDER as low-confidence rather
    than assert.

    ADVISORY only — never enters the oracle / SCE / calibration. ``samples`` defaults to 3 (a
    threat model is an expensive ~8k-token call). Byte-identical on the deterministic dry-run
    backend."""
    workers, limiter = sample_workers(backend)
    concerns = list(known_concerns) if known_concerns is not None else None
    return run_consistent(
        lambda: threat_model(target_name, business_context=business_context, archetype=archetype,
                             fingerprint=fingerprint, known_concerns=concerns, backend=backend),
        samples=samples, agreement_gate=agreement_gate, key_fn=_threat_signature,
        max_workers=workers, rate_limiter=limiter)
