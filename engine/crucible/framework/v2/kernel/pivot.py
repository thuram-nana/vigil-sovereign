"""
pivot() — wraps framework/cognitive/pivot-protocols.md.

Generate lateral moves when a thread is stuck. Returns at least three
PivotKind-tagged moves with rationale and effort estimates.
"""

from __future__ import annotations

from typing import Iterable

from .binding import run
from .consistency import ConsistencyResult, run_consistent, sample_workers
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


def _pivot_signature(pp: PivotProposal) -> list[str]:
    """The decision-bearing signature of a pivot proposal: the SORTED DISTINCT move KINDS it
    reaches for (mirroring hypothesize's bug-class signature). Two proposals that pivot along the
    same kinds cluster together; a scattered one does not. Prose (suggestion/rationale) is
    excluded."""
    return sorted({str(m.kind) for m in pp.moves})


def pivot_consistent(
    stuck_thread: str,
    *,
    last_observation: str = "",
    blockers: Iterable[str] = (),
    posture: str = "TEST",
    samples: int = 5,
    agreement_gate: float = 0.6,
    backend: LLMBackend | None = None,
) -> ConsistencyResult:
    """Self-consistent pivot / lateral-move proposal — a NO-ORACLE binding (the LLM's narrative
    over a stuck thread; the DETERMINISTIC attack-path search is a separate engine and is left
    untouched). Runs :func:`pivot` ``samples`` times and clusters by the set of move KINDS
    proposed. ``abstained`` True flags an unstable pivot to treat as low-confidence, not asserted.

    ADVISORY only — never enters the oracle / SCE / calibration. Byte-identical on the dry-run
    backend."""
    workers, limiter = sample_workers(backend)
    blockers = tuple(blockers)   # materialise once — the sample lambda re-reads it N times
    return run_consistent(
        lambda: pivot(stuck_thread, last_observation=last_observation, blockers=blockers,
                      posture=posture, backend=backend),
        samples=samples, agreement_gate=agreement_gate, key_fn=_pivot_signature,
        max_workers=workers, rate_limiter=limiter)
