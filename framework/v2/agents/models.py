"""
agents.models — Pydantic types for the blackboard.

The blackboard is a typed event log. Eight event kinds, each with a
strongly-shaped payload, plus a wrapper that carries provenance:

    Observation   what an agent saw
    Hypothesis    a falsifiable claim posted for testing
    Plan          a concrete intent (which hypothesis, what action)
    Action        an action that was actually taken
    Result        the outcome of an action
    Finding       a confirmed bug, gated by Critique before promotion
    Critique      adversarial review of a finding/observation/plan
    Decision      a coordinator/planner choice with rationale

Per FORGE PROTOCOL § 3.4: events are append-only. To "edit" an event,
post a new one with `supersedes_id` referencing the old. The old row
is preserved; queries by default exclude superseded events.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


EventKind = Literal[
    "observation",
    "hypothesis",
    "plan",
    "action",
    "result",
    "finding",
    "critique",
    "decision",
]

ALL_EVENT_KINDS: tuple[EventKind, ...] = (
    "observation", "hypothesis", "plan", "action",
    "result", "finding", "critique", "decision",
)


# ---------------------------------------------------------------------------
# Per-kind payloads
# ---------------------------------------------------------------------------


class ObservationPayload(BaseModel):
    """Something observed at a surface — a recon hit, a probe response,
    a side-effect noticed during exploitation."""

    source: str = Field(description="Subsystem that observed it: recon / exploit / critique / ...")
    surface: str = Field(description="Endpoint / feature / flow.")
    summary: str = Field(description="Plain-language description.")
    raw_excerpt: str = Field(default="", description="Up to ~1KB of raw signal.")
    confidence: float = Field(ge=0.0, le=1.0, default=0.5)


class HypothesisPayload(BaseModel):
    """A falsifiable hypothesis. Mirrors kernel.models.Hypothesis but
    adds a status field tracked across the engagement."""

    handle: str = Field(description="Stable handle, e.g. H-007.")
    surface: str
    bug_class: str
    given: str
    if_action: str
    then_observation: str
    because_model: str
    refute_on: str
    cheap_test: str
    confidence: float = Field(ge=0.0, le=1.0, default=0.5)
    status: Literal[
        "open", "claimed", "tested", "confirmed", "refuted", "deferred"
    ] = "open"


class PlanPayload(BaseModel):
    """A concrete plan to test a hypothesis or explore a surface.
    Posted by the hypothesis-agent or planner."""

    plan_id: str
    targets_hypothesis: str | None = Field(
        default=None, description="Hypothesis handle this plan tests, if any.",
    )
    next_action: str = Field(description="Plain-language description of what to do.")
    estimated_requests: int = 1
    estimated_minutes: float = 1.0


class ActionPayload(BaseModel):
    """A concrete action taken by an exploit-agent."""

    action_id: str
    plan_id: str | None = None
    tool: str = Field(description="curl / race-balance.py / dalfox / ...")
    args_summary: str = Field(description="Human-readable command summary.")
    target_url: str = ""


class ResultPayload(BaseModel):
    """Outcome of an action."""

    action_id: str
    success: bool
    status_code: int = 0
    elapsed_ms: float = 0.0
    body_excerpt: str = ""
    evidence_path: str = ""
    note: str = ""


class FindingPayload(BaseModel):
    """A confirmed bug. Critique-agent must confirm before promotion to
    the report. The `critique_status` field records that gate."""

    finding_slug: str = Field(description="NNN-short-slug")
    title: str
    severity: Literal["Critical", "High", "Medium", "Low", "Info"]
    bug_class: str
    surface: str
    summary: str
    impact: str = ""
    cvss_vector: str = ""
    cvss_base: float | None = None
    derived_from_hypothesis: str | None = Field(
        default=None, description="Hypothesis handle this finding confirms.",
    )
    critique_status: Literal["pending", "confirmed", "objections"] = "pending"
    oracle_context: dict[str, Any] | None = Field(
        default=None,
        description=(
            "A serialized verify.adapter.FindingContext (its model_dump), or "
            "None. When present, the deterministic oracle layer — not the LLM "
            "critique — is the authority for promotion to 'confirmed'. When "
            "None, the finding takes the legacy LLM-advisory confirmation path."
        ),
    )
    verified_by_oracle: bool = Field(
        default=False,
        description=(
            "Provenance: True only when a deterministic oracle fired and "
            "carried this finding's confirmation. False for LLM-advisory "
            "confirmations and for every finding without oracle evidence."
        ),
    )


class CritiquePayload(BaseModel):
    """Critique-agent review of an event (typically a Finding)."""

    target_event_id: int = Field(description="ID of the event being critiqued.")
    decision: Literal["confirm", "objections", "more_evidence_needed"]
    objections: list[str] = Field(default_factory=list)
    deception_check: str = Field(
        default="",
        description="One sentence on where the claim might be self-deception.",
    )


class DecisionPayload(BaseModel):
    """A choice made by the coordinator or planner. URK decide()-backed."""

    question: str
    choice: str
    rationale: str = ""


# Map kind -> Pydantic class so the blackboard can validate generically.
PAYLOAD_BY_KIND: dict[EventKind, type[BaseModel]] = {
    "observation": ObservationPayload,
    "hypothesis":  HypothesisPayload,
    "plan":        PlanPayload,
    "action":      ActionPayload,
    "result":      ResultPayload,
    "finding":     FindingPayload,
    "critique":    CritiquePayload,
    "decision":    DecisionPayload,
}


# ---------------------------------------------------------------------------
# Event wrapper — what the storage layer round-trips
# ---------------------------------------------------------------------------


class BlackboardEvent(BaseModel):
    """One row in the blackboard. Append-only.

    The `payload` is a dict on the wire; agents construct it from the
    matching PAYLOAD_BY_KIND class and the blackboard validates on
    insert.
    """

    model_config = ConfigDict(populate_by_name=True)

    id: int = Field(default=0, description="Set by the store on insert.")
    engagement_id: int
    kind: EventKind
    agent_name: str
    posted_at: str = Field(description="ISO-8601 UTC.")
    payload: dict[str, Any]
    parent_id: int | None = Field(
        default=None,
        description="Event this one derives from (e.g. a Result derives from an Action).",
    )
    supersedes_id: int | None = Field(
        default=None,
        description="Event this one replaces. The replaced event remains in the log.",
    )


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")
