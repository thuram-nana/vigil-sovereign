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
    # --- Nervous-System spine kinds (additive; N0). The original 8 are untouched. ---
    "reward",         # a learning/credit signal (RL reward bus)
    "critic_verdict", # one critic's ADVISORY verdict (multi-critic panel)
    "reflection",     # an in-loop metacognitive reflection (re-rank/defer only)
    "refusal",        # a recorded refusal (a gate fired) — refusals are evidence
    # --- Agentic tool-use / sensor-driving spine kinds (additive; W1.4). ---
    "tool_call",      # the reasoning core invoked a gated tool/sensor (the request)
    "tool_result",    # that invocation's outcome (a PROVENANCE-labelled observation, not a fact)
    # --- Agent-to-agent coordination (additive; S5). A DIRECTED, addressed message between agents. It is
    #     COORDINATION ONLY, never promotable to a fact/finding — only a fired oracle mints a fact. ---
    "agent_message",
]

ALL_EVENT_KINDS: tuple[EventKind, ...] = (
    "observation", "hypothesis", "plan", "action",
    "result", "finding", "critique", "decision",
    "reward", "critic_verdict", "reflection", "refusal",
    "tool_call", "tool_result", "agent_message",
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
    # "confirmed" is RESERVED for a fired deterministic oracle — the sole authority.
    # An LLM-only advisory verdict (no oracle) can never reach "confirmed"; it is
    # "llm_advisory" (recorded + shown, but never promoted or reported as fact).
    critique_status: Literal["pending", "confirmed", "objections", "llm_advisory"] = "pending"
    critique_dryrun: bool = Field(
        default=False, description="The advisory critique came from a dry-run LLM call (not a real inference).")
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
    confidence: float | None = Field(
        default=None,
        ge=0.0,
        le=1.0,
        description=(
            "Calibrated exploitability probability set at the confirmation site "
            "when a deterministic oracle fired: the oracle's signal confidence "
            "mapped through calibration (PAV isotonic over the OutcomeLedger, or "
            "identity when data is sparse). NEVER the old hardcoded 1.0. None for "
            "unconfirmed findings and for the LLM-advisory path."
        ),
    )
    oracle_kind: str | None = Field(
        default=None,
        description=(
            "Which deterministic oracle fired to confirm this finding (e.g. "
            "'differential_response', 'oob_callback', 'sanitizer_signal'). None "
            "for LLM-advisory confirmations. Surfaced in the report so the proof "
            "is visible, not just asserted."
        ),
    )
    oracle_rationale: str = Field(
        default="",
        description=(
            "Plain-language rationale from the oracle layer (which signal fired "
            "and on what evidence). Empty for the LLM-advisory path."
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


# ---------------------------------------------------------------------------
# Nervous-System spine payloads (N0). These carry the learning / metacognition /
# refusal signals onto the SAME append-only event stream every subsystem shares.
# ---------------------------------------------------------------------------


class RewardPayload(BaseModel):
    """A learning reward/credit signal emitted once an outcome is known — the RL feedback
    on the spine. Reward derives from INDEPENDENT ground truth (never P(exploit|oracle));
    ``source`` names the learner it credits."""

    source: str = Field(description="Learner/subsystem: 'bandit' / 'ledger' / 'credit' / 'intel-yield'.")
    arm: str = Field(default="", description="The (context:arm) key the reward credits.")
    signal: str = Field(default="", description="What produced it: 'oracle_confirmed' / 'refuted' / 'disputed'.")
    reward: float = Field(ge=0.0, le=1.0, description="Normalised reward in [0,1].")
    target_event_id: int | None = Field(default=None, description="The finding/decision event credited, if any.")
    rationale: str = ""


class CriticVerdictPayload(BaseModel):
    """One critic's ADVISORY verdict on a target event (multi-critic panel). Deliberately has
    NO 'confirm' value — critics advise/object/abstain; only a fired deterministic oracle
    confirms. A verdict can never promote a finding to fact."""

    critic: str = Field(description="Critic role: 'soundness' / 'scope-safety' / 'calibration' / 'deception' / 'novelty'.")
    target_event_id: int = Field(description="The event under review (usually a finding).")
    verdict: Literal["endorse", "object", "abstain"] = Field(description="Advisory only — never 'confirm'.")
    severity: Literal["info", "minor", "major", "critical"] = "info"
    rationale: str = ""


class ReflectionPayload(BaseModel):
    """An in-loop metacognitive reflection over the reasoning trace: what it reveals (dead
    threads, refuted hypotheses, drift, wasted budget) and how to RE-ORIENT next. Re-orient =
    re-rank/defer only; it can never gate or skip an attack surface (coverage doctrine)."""

    trigger: str = Field(description="'phase-boundary' / 'stall' / 'surprise' / 'periodic'.")
    observations: list[str] = Field(default_factory=list, description="What the trace revealed.")
    reorientation: str = Field(default="", description="How to re-rank/defer next — never gates a surface.")
    rationale: str = ""


class RefusalPayload(BaseModel):
    """A refusal recorded as evidence: which gate fired, what was declined, and whether it
    halted the run. Refusals are NEVER silently dropped — every one lands on the spine."""

    gate: str = Field(description="'kill-switch' / 'scope' / 'sovereignty' / 'ethics' / 'entitlement' / 'epistemic'.")
    action_refused: str = Field(description="The target/action/conclusion that was declined.")
    reason: str = ""
    fatal: bool = Field(default=False, description="True if the refusal halted the engagement.")


class ToolCallPayload(BaseModel):
    """The reasoning core's REQUEST to run a gated tool/sensor — recorded BEFORE the tool runs,
    so the intent is on the immutable stream even if the run refuses or fails. Carries no raw
    wallclock (the spine digest is time-independent); ``args_summary`` is a short, redacted view
    of the arguments (never secrets, never full payloads)."""

    tool: str = Field(description="Registered tool/sensor name.")
    tier: str = Field(default="", description="Governance tier: 'T1'/'T2'/'T3' (passive/active/adversary-sim).")
    capability: str = Field(default="", description="Entitlement capability the tool requires ('' = none).")
    target: str = Field(default="", description="Target/host the tool acts on, if any (for scope/egress).")
    args_summary: str = Field(default="", description="Short redacted view of the arguments.")


class ToolResultPayload(BaseModel):
    """The outcome of a gated tool/sensor invocation — a PROVENANCE-LABELLED OBSERVATION, never a
    fact. A tool's output becomes a fact only if a deterministic oracle later re-verifies it; on
    the spine it is tagged with its source (the tool) and whether a gate refused it. Provenance-
    linked to its ``tool_call`` via ``parent_id`` (mirroring the Action->Result idiom)."""

    tool: str = Field(description="Registered tool/sensor name.")
    ok: bool = Field(description="True iff the tool ran and returned a result (not refused, not errored).")
    refused: bool = Field(default=False, description="True iff a fail-closed gate declined the invocation.")
    gate: str = Field(default="", description="Which gate refused ('' if not refused).")
    summary: str = Field(default="", description="Short summary of the observation the tool produced.")
    note: str = Field(default="", description="Error/refusal reason or an operator-facing note.")


class AgentMessagePayload(BaseModel):
    """A DIRECTED message from one agent to another (S5 agent-to-agent coordination). It is a COORDINATION
    signal ONLY — a hint the recipient MAY consider on its next tick — and is NEVER promotable to a fact, a
    finding, or an observation: only a fired deterministic oracle over real evidence mints a fact, and no
    fact-building path reads this kind. The blackboard enforces ``sender == the posting agent`` (anti-spoof),
    so a message can never forge its origin; a message that SUGGESTS an action does not authorize it (the
    recipient still routes any action through its own gate/oracle)."""

    sender: str = Field(description="The posting agent's name — blackboard-enforced to equal the poster.")
    recipient: str = Field(description="The addressed agent's name.")
    topic: str = Field(default="", description="A short subject line.")
    body: str = Field(default="", description="The coordination hint (advisory; never evidence/a fact).")
    intent: Literal["coordination"] = Field(
        default="coordination", description="Always 'coordination' — never a fact/finding/observation.")
    refs: list[int] = Field(default_factory=list, description="Referenced blackboard event ids (context only).")


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
    "reward":         RewardPayload,
    "critic_verdict": CriticVerdictPayload,
    "reflection":     ReflectionPayload,
    "refusal":        RefusalPayload,
    "tool_call":      ToolCallPayload,
    "tool_result":    ToolResultPayload,
    "agent_message":  AgentMessagePayload,
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
