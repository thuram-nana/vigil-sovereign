"""
agents.executor_proto — pluggable execution layer for the exploit-agent.

The exploit-agent does not call tools directly. It accepts an
`Executor` whose `execute()` maps (hypothesis, plan) -> ExecutionOutcome.
Two implementations ship:

  - DeterministicExecutor    used by tests. Looks up a pre-canned
                             outcome by (bug_class, surface). Returns
                             a fixed result, no I/O.
  - HttpExecutor             real-engagement use. Issues bounded HTTP
                             requests via UTI's Fetcher. Out of scope
                             for the simulated acceptance, but the
                             interface is here so the path is open.

Real engagements will eventually plug in a richer Executor (one that
invokes framework/scripts/<class>/*.py per hypothesis). Until ACP
ships an executor router, DeterministicExecutor + HttpExecutor are
enough.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol, runtime_checkable

from .models import FindingPayload, HypothesisPayload, PlanPayload


@dataclass
class ExecutionOutcome:
    """What an exploit-agent step learns from running one plan."""

    success: bool
    status_code: int = 0
    elapsed_ms: float = 0.0
    body_excerpt: str = ""
    note: str = ""
    # If the outcome is a confirmed bug, the finding payload to post.
    # The exploit-agent will mark it critique_status='pending' regardless.
    finding: FindingPayload | None = None
    # Oracle-observable evidence backing the finding: a serialized
    # verify.adapter.FindingContext (baseline/mutated responses, OOB hits,
    # achieved-state pair, ...) collected while running the plan. When present,
    # the exploit-agent propagates it onto the posted Finding as
    # `oracle_context`, so the deterministic oracle — not the LLM critique —
    # becomes the confirmation authority for that finding.
    oracle_context: dict | None = None


@runtime_checkable
class Executor(Protocol):
    """Anything that can run a Plan against a target and return an outcome."""

    def execute(
        self,
        hypothesis: HypothesisPayload,
        plan: PlanPayload,
    ) -> ExecutionOutcome: ...


# ---------------------------------------------------------------------------
# DeterministicExecutor — used by the simulated acceptance test
# ---------------------------------------------------------------------------


@dataclass
class DeterministicExecutor:
    """Outcome lookup table keyed by `(bug_class, surface)`.

    Useful for the simulated 4-hour run: the harness pre-populates a
    fixture map of "what happens if you try X against Y" so the planner
    + agents can be exercised without a live target.
    """

    outcomes: dict[tuple[str, str], ExecutionOutcome] = field(default_factory=dict)
    default: ExecutionOutcome = field(default_factory=lambda: ExecutionOutcome(
        success=False, status_code=404,
        body_excerpt="",
        note="DeterministicExecutor: no fixture for this (class, surface)",
    ))

    def execute(
        self,
        hypothesis: HypothesisPayload,
        plan: PlanPayload,
    ) -> ExecutionOutcome:
        key = (hypothesis.bug_class, hypothesis.surface)
        return self.outcomes.get(key, self.default)


# ---------------------------------------------------------------------------
# HttpExecutor — bounded live-HTTP sketch (not exercised this session)
# ---------------------------------------------------------------------------


@dataclass
class HttpExecutor:
    """Live-HTTP executor sketch. Consumes UTI's Fetcher.

    NOT exercised in Session 2's acceptance test. The interface is in
    place so a future session can wire a real engagement without
    reshaping the exploit-agent. See V2-LIMITATIONS.md.
    """

    base_url: str
    fetcher: object | None = None  # injected; type-erased to avoid circular import

    def execute(
        self,
        hypothesis: HypothesisPayload,
        plan: PlanPayload,
    ) -> ExecutionOutcome:
        # Minimal viable: GET the surface and report status. A real
        # implementation would parse cheap_test into a request.
        if self.fetcher is None:
            return ExecutionOutcome(
                success=False, status_code=0,
                note="HttpExecutor has no Fetcher injected",
            )
        url = hypothesis.surface
        ex = self.fetcher.get(url)  # type: ignore[attr-defined]
        return ExecutionOutcome(
            success=False,  # naive: never claims success without explicit logic
            status_code=ex.status,
            elapsed_ms=ex.elapsed_ms,
            body_excerpt=ex.body_excerpt[:300],
            note="HttpExecutor: probed only; no exploit logic yet",
        )
