"""
pivot() — wraps framework/cognitive/pivot-protocols.md.

Generate lateral moves when a thread is stuck. Returns at least three
PivotKind-tagged moves with rationale and effort estimates.
"""

from __future__ import annotations

from typing import Iterable

from .binding import run
from .llm import LLMBackend
from .models import CallTrace, PivotProposal


def pivot(
    stuck_thread: str,
    *,
    last_observation: str = "",
    blockers: Iterable[str] = (),
    posture: str = "TEST",
    backend: LLMBackend | None = None,
) -> tuple[PivotProposal, CallTrace]:
    """Propose lateral moves when stuck.

    Args:
        stuck_thread: a one-paragraph description of what the operator
            was trying and why it stalled.
        last_observation: the most recent observation that did not fit
            any current hypothesis.
        blockers: specific things blocking progress (WAF, rate limit,
            lockout, refuted hypothesis, etc.).
        posture: TEST / AUDIT / EMULATE — affects which kinds of moves
            are realistic.
        backend: override the active LLM backend.

    Returns:
        (PivotProposal, CallTrace). proposal.recommended is the index
        of the highest-EV move per the LLM's judgement.
    """
    structured = {
        "stuck_thread": stuck_thread,
        "last_observation": last_observation,
        "blockers": list(blockers),
        "posture": posture,
    }
    parsed, trace = run(
        schema=PivotProposal,
        schema_name="PivotProposal",
        cognitive_doc_stem="pivot-protocols",
        section_anchors=[
            "1-the-two-minute-reset",
            "2-surface-pivot-same-class-different-surface",
            "3-class-pivot-same-surface-different-class",
            "4-adversary-pivot-what-would-x-do-here",
            "5-layer-pivot-go-up-or-go-down",
        ],
        task_directive=(
            "Generate at least three lateral moves to unstick this thread. "
            "Each move is tagged with a PivotKind (surface / class / "
            "adversary / layer / time / source / tool / constraint / "
            "operator). Diversify kinds. Each carries a rationale (why "
            "this is a credible next thread), an effort estimate "
            "(minutes / hours / session), and a confidence (0.0 - 1.0). "
            "Set 'recommended' to the index of the highest-EV move."
        ),
        structured_input=structured,
        backend=backend,
    )
    assert isinstance(parsed, PivotProposal)
    return parsed, trace
