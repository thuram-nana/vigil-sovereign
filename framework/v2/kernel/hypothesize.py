"""
hypothesize() — wraps framework/cognitive/hypothesis-driven.md.

Given an observation (and optional surface / context), generate at
least five falsifiable hypotheses in the four-part form (§ 1) — each
with a refute_on stop rule (§ 4) and a cheap-test design (§ 3).
"""

from __future__ import annotations

from typing import Iterable

from .binding import run
from .consistency import ConsistencyResult, run_consistent
from .llm import LLMBackend
from .models import CallTrace, HypothesisSet


def hypothesize(
    observation: str,
    *,
    surface: str = "",
    context: str = "",
    bug_classes: Iterable[str] = (),
    backend: LLMBackend | None = None,
) -> tuple[HypothesisSet, CallTrace]:
    """Generate >=5 falsifiable hypotheses for `observation`.

    Args:
        observation: what was observed at the surface (response shape,
            error pattern, side effect).
        surface: endpoint / feature / flow under test.
        context: any additional state the LLM should know.
        bug_classes: optional hint of bug classes to consider first.
        backend: override the active LLM backend (for tests).

    Returns:
        (HypothesisSet, CallTrace).  HypothesisSet.doctrine_compliant()
        returns True iff len(hypotheses) >= 5.
    """
    structured = {
        "observation": observation,
        "surface": surface,
        "context": context,
        "bug_classes_to_consider": list(bug_classes),
    }
    parsed, trace = run(
        schema=HypothesisSet,
        schema_name="HypothesisSet",
        cognitive_doc_stem="hypothesis-driven",
        section_anchors=[
            "1-the-hypothesis-form",
            "2-generating-hypotheses-forcing-breadth",
            "3-cheap-test-design",
            "4-falsifiability-what-evidence-would-change-my-mind",
        ],
        task_directive=(
            "Generate at least five falsifiable hypotheses for the "
            "observation in the structured input below. Each hypothesis "
            "must use the four-part form: given / if / then / because. "
            "Each must include a refute_on (the observation that would "
            "disprove it) and a cheap_test (the minimum experiment to "
            "run, ideally a single curl or single tool invocation). "
            "Diversify bug_class across the entries — do not return five "
            "of the same class."
        ),
        structured_input=structured,
        backend=backend,
    )
    assert isinstance(parsed, HypothesisSet)
    return parsed, trace


def _bug_class_signature(hs: HypothesisSet) -> list[str]:
    """The decision-bearing signature of a generation: the SORTED DISTINCT bug classes it
    proposed. Two generations that reach for the same attack surface cluster together; a
    fabrication that scatters across unrelated classes does not."""
    return sorted({h.bug_class for h in hs.hypotheses})


def hypothesize_consistent(
    observation: str,
    *,
    surface: str = "",
    context: str = "",
    bug_classes: Iterable[str] = (),
    samples: int = 5,
    agreement_gate: float = 0.6,
    backend: LLMBackend | None = None,
) -> ConsistencyResult:
    """Self-consistent hypothesis generation (anti-hallucination P5) — a NO-ORACLE binding.

    Runs :func:`hypothesize` ``samples`` times and clusters the generations by the set of
    bug classes they propose. Returns a :class:`ConsistencyResult`: ``modal`` is the most-
    agreed generation, and ``abstained`` is True when the runs disagree enough that the
    output should be routed to ``needs_evidence`` rather than acted on. With the deterministic
    dry-run backend every sample is identical, so it agrees trivially (agreement 1.0); the
    signal only bites against a live, temperature>0 backend."""
    return run_consistent(
        lambda: hypothesize(observation, surface=surface, context=context,
                            bug_classes=bug_classes, backend=backend),
        samples=samples, agreement_gate=agreement_gate, key_fn=_bug_class_signature)
