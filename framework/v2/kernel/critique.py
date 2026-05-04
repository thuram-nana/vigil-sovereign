"""
critique() — wraps framework/cognitive/self-critique.md.

Adversarial review of a claim. Used by the (deferred) critique-agent
to gate findings before report. Returns a CritiqueResult that names
objections, drift, coverage gaps, and the deception-check question.
"""

from __future__ import annotations

from .binding import run
from .llm import LLMBackend
from .models import CallTrace, CritiqueResult


def critique(
    claim: str,
    *,
    evidence: str = "",
    context: str = "",
    backend: LLMBackend | None = None,
) -> tuple[CritiqueResult, CallTrace]:
    """Run a structured self-critique against a claim.

    Args:
        claim: the proposed finding text or hypothesis statement.
        evidence: a short summary of the evidence at hand
            (request/response excerpts, observed side-effects).
        context: anything the reviewer should know about the engagement
            posture or surrounding hypotheses.
        backend: override the active LLM backend.

    Returns:
        (CritiqueResult, CallTrace). decision is one of
        confirm / objections / more_evidence_needed.
    """
    structured = {
        "claim": claim,
        "evidence": evidence,
        "context": context,
    }
    parsed, trace = run(
        schema=CritiqueResult,
        schema_name="CritiqueResult",
        cognitive_doc_stem="self-critique",
        section_anchors=[
            "1-quick-critique-5-minutes-run-often",
            "21-coverage-check",
            "4-final-critique-before-declaring-done",
            "5-anti-patterns-the-routine-catches",
        ],
        task_directive=(
            "Critique the claim. Answer the five quick-critique questions "
            "from § 1 in your reasoning, then emit a structured result. "
            "Decision must be one of: confirm (claim stands; PoC reproduced; "
            "specificity isolated; impact walked), objections (concrete "
            "concerns must be addressed before promotion), or "
            "more_evidence_needed (claim is hedged / single-shot / not "
            "isolated). Always include a deception_check sentence — name "
            "where the operator might be reading the response generously. "
            "Always offer one_more_thread — what to test if you had one "
            "more hour."
        ),
        structured_input=structured,
        backend=backend,
    )
    assert isinstance(parsed, CritiqueResult)
    return parsed, trace
