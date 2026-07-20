"""
decide() — wraps framework/cognitive/decision-frameworks.md.

Score severity (CVSS 3.1 + contextual adjustment), assess likelihood
× impact, decide whether the finding is worth reporting at all, and
draft the regulator-readable impact paragraph.
"""

from __future__ import annotations

from .binding import run
from .consistency import ConsistencyResult, run_consistent, sample_workers
from .llm import LLMBackend
from .models import CallTrace, SeverityDecision


def decide(
    finding_summary: str,
    *,
    affected_endpoint: str = "",
    preconditions: str = "",
    impact_observed: str = "",
    chain_candidates: list[str] | None = None,
    backend: LLMBackend | None = None,
) -> tuple[SeverityDecision, CallTrace]:
    """Score a finding and decide whether to report.

    Args:
        finding_summary: one-paragraph plain-language description.
        affected_endpoint: the surface the bug lives on.
        preconditions: what an attacker needs to exploit.
        impact_observed: data exposed / privilege gained / dollars moved.
        chain_candidates: other findings that may compose with this one.
        backend: override the active LLM backend.

    Returns:
        (SeverityDecision, CallTrace).
    """
    structured = {
        "finding_summary": finding_summary,
        "affected_endpoint": affected_endpoint,
        "preconditions": preconditions,
        "impact_observed": impact_observed,
        "chain_candidates": chain_candidates or [],
    }
    parsed, trace = run(
        schema=SeverityDecision,
        schema_name="SeverityDecision",
        cognitive_doc_stem="decision-frameworks",
        section_anchors=[
            "1-severity-cvss-plus-contextual-adjustment",
            "11-when-to-override-cvss-up",
            "12-when-to-override-cvss-down",
            "13-severity-ladder-pragmatic-definitions",
            "5-the-explain-it-to-a-regulator-test",
            "6-when-to-surface-immediately-vs-hold",
        ],
        task_directive=(
            "Score the finding with CVSS 3.1 base, then apply a contextual "
            "adjustment per § 1.1 / 1.2. Justify the adjustment in "
            "contextual_note. Pick severity (Critical/High/Medium/Low/Info) "
            "from the pragmatic ladder § 1.3.  Decide worth_reporting per "
            "§ 3 (finding / engagement_log_only / skip). Set "
            "immediate_surface_to_operator if any criterion in § 6 is met. "
            "Write a regulator_paragraph per § 5 — non-technical, "
            "quantified, with a reference to a similar public incident "
            "if applicable."
        ),
        structured_input=structured,
        backend=backend,
    )
    assert isinstance(parsed, SeverityDecision)
    return parsed, trace


def _severity_signature(sd: SeverityDecision) -> tuple[str, str]:
    """The decision-bearing signature of a severity call: the ``(severity, worth_reporting)`` pair
    — both categorical DECISIONS, never the prose (contextual_note / regulator_paragraph). Two
    calls that reach the same verdict cluster together; an unstable one scatters."""
    return (str(sd.severity), str(sd.worth_reporting))


def decide_consistent(
    finding_summary: str,
    *,
    affected_endpoint: str = "",
    preconditions: str = "",
    impact_observed: str = "",
    chain_candidates: list[str] | None = None,
    samples: int = 5,
    agreement_gate: float = 0.6,
    backend: LLMBackend | None = None,
) -> ConsistencyResult:
    """Self-consistent severity decision (anti-hallucination) — a NO-ORACLE binding. Runs
    :func:`decide` ``samples`` times and clusters by the ``(severity, worth_reporting)`` decision.
    ``abstained`` is True when the samples disagree enough that the severity should be treated as
    LOW-CONFIDENCE (routed to needs_evidence) rather than asserted.

    ADVISORY only: it discounts the LLM's confidence in its OWN severity — it NEVER enters the
    deterministic oracle / SCE / calibration inputs (which score exploitability from real evidence,
    not the LLM's stability). Byte-identical on the deterministic dry-run backend (every sample is
    identical -> agreement 1.0, abstained False)."""
    workers, limiter = sample_workers(backend)
    chain = list(chain_candidates) if chain_candidates is not None else None
    return run_consistent(
        lambda: decide(finding_summary, affected_endpoint=affected_endpoint,
                       preconditions=preconditions, impact_observed=impact_observed,
                       chain_candidates=chain, backend=backend),
        samples=samples, agreement_gate=agreement_gate, key_fn=_severity_signature,
        max_workers=workers, rate_limiter=limiter)
