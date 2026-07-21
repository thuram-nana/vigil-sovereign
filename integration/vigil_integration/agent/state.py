"""
agent.state — the typed ReAct agent state + the single structured LLM decision (VIGIL-FUSION F2).

Reimplements the SHAPE of redamon's agent state (a single structured ``LLMDecision`` routing a small
set of action types; an explicit offensive phase; an execution trace; separate finding stores) in
VIGIL's Python, but with the sovereign distinction baked into the TYPES:

  * ``OutputAnalysis`` holds the LLM's CLAIMS about a tool result — ``exploit_succeeded`` and friends.
    These are PROPOSALS, never facts. They flow into ``AgentState.leads`` only.
  * ``AgentState.facts`` holds ONLY oracle-confirmed, signed findings — nothing the LLM asserts lands
    here without the deterministic oracle re-firing (enforced by ``agent.react``, not by trust).

Everything the LLM emits is parsed fail-closed (via ``safety.llm_intake.parse_proposal``) into a
``LLMDecision`` and stamped a non-authoritative proposal. Nothing in this module makes anything true.

Import-clean: pydantic + stdlib only (no ``framework.*``/``strix.*``); the gate/oracle are injected in
``agent.react``.
"""

from __future__ import annotations

from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, Field


class Phase(str, Enum):
    """The offensive kill-chain phase. Escalation is monotone (never auto-downgrades) and each phase
    maps to a WARDEN authority tier in ``agent.phases`` — the deeper the phase, the higher the tier a
    tool call must clear."""

    INFORMATIONAL = "informational"   # passive/recon; low blast radius
    EXPLOITATION = "exploitation"     # active exploitation; needs A2
    POST_EXPLOITATION = "post_exploitation"  # lateral/persistence/impact; needs A3


class ActionType(str, Enum):
    """The 7 actions a single ``LLMDecision`` may propose. ``agent.react`` routes each through the
    sovereign gates; several are inert (no target contact) and several are action-bearing."""

    USE_TOOL = "use_tool"                 # run one tool (action-bearing → gated)
    PLAN_TOOLS = "plan_tools"             # propose a wave of tool calls (each gated at execution)
    TRANSITION_PHASE = "transition_phase"  # escalate the phase (needs signed approval at target tier)
    DEPLOY_FIRETEAM = "deploy_fireteam"   # spawn parallel specialists (gated; F6)
    SWITCH_SKILL = "switch_skill"         # change the active skill/playbook (inert)
    ASK_USER = "ask_user"                 # pause for a human answer (inert; HITL)
    COMPLETE = "complete"                 # end the engagement (inert)


class ToolCall(BaseModel):
    """One proposed tool invocation. ``destructive``/``blast_class`` drive the destruction gate (I4);
    they are the LLM's proposal and are re-derived server-side from the tool registry in F3, never
    trusted from the model alone."""

    tool_name: str
    tool_args: dict[str, Any] = Field(default_factory=dict)
    destructive: bool = False
    blast_class: str = ""   # "" | "destructive" | "high-blast"
    reason: str = ""


class OutputAnalysis(BaseModel):
    """The LLM's CLAIMS about the previous tool's output — inline observe/orient folded into the same
    think call. **Every field here is a PROPOSAL, never a fact.** ``exploit_succeeded`` in particular
    is the exact assertion the oracle exists to check; it may only produce a LEAD until a deterministic
    oracle re-fires over the retained raw output (see ``agent.react.intake_result``)."""

    exploit_succeeded: Optional[bool] = None
    new_information_gained: Optional[bool] = None
    verdict: str = ""            # new_info | confirmation | no_progress | blocked | duplicate | ...
    findings: list[dict[str, Any]] = Field(default_factory=list)   # proposed findings → LEADs
    extracted_info: dict[str, Any] = Field(default_factory=dict)
    notes: str = ""


class LLMDecision(BaseModel):
    """The single structured object a ``think`` step emits; ``action`` routes the whole ReAct cycle.
    Parsed fail-closed (malformed → downgraded to the safest action in ``agent.react``). It is stamped
    non-authoritative: it can PROPOSE an action, never authorize one — the gates decide."""

    action: ActionType
    reasoning: str = ""
    # use_tool
    tool: Optional[ToolCall] = None
    # plan_tools
    plan: list[ToolCall] = Field(default_factory=list)
    # transition_phase
    target_phase: Optional[Phase] = None
    # deploy_fireteam
    fireteam: list[dict[str, Any]] = Field(default_factory=list)
    # switch_skill
    skill: Optional[str] = None
    # ask_user / complete
    question: Optional[str] = None
    summary: Optional[str] = None
    # inline analysis of the PRIOR tool output (claims → leads)
    output_analysis: Optional[OutputAnalysis] = None


class Finding(BaseModel):
    """A finding record. ``status`` is the veracity: a LEAD is the LLM's proposal; a FACT is
    oracle-confirmed and carries a signed-evidence reference. Only ``agent.react`` may set FACT, and
    only after the deterministic oracle re-fires."""

    ref: str
    bug_class: str = ""
    title: str = ""
    severity: str = ""
    status: str = "lead"          # "lead" | "fact"
    evidence_ref: str = ""        # spine record hash / SCITT cert id when status == "fact"
    source: str = ""              # which tool/step proposed it


class AgentState(BaseModel):
    """The run state carried across ReAct turns. ``facts`` and ``leads`` are SEPARATE stores: the LLM
    and tools can only add to ``leads``; ``facts`` grows only through the oracle. Serialisable so
    ``agent.checkpoint`` can snapshot it into the append-only signed spine (a later F2 slice)."""

    engagement_slug: str = ""
    phase: Phase = Phase.INFORMATIONAL
    iteration: int = 0
    objective: str = ""
    facts: list[Finding] = Field(default_factory=list)     # oracle-confirmed only
    leads: list[Finding] = Field(default_factory=list)     # LLM/tool proposals
    execution_trace: list[dict[str, Any]] = Field(default_factory=list)
    awaiting_approval: bool = False
    awaiting_question: bool = False
    done: bool = False

    def record_lead(self, finding: Finding) -> None:
        finding.status = "lead"
        finding.evidence_ref = ""
        self.leads.append(finding)

    def record_fact(self, finding: Finding, *, evidence_ref: str) -> None:
        """Only the oracle-confirmation path in ``agent.react`` calls this; a FACT MUST carry a signed
        evidence reference."""
        if not evidence_ref:
            raise ValueError("a FACT requires a signed evidence reference (oracle-confirmed only)")
        finding.status = "fact"
        finding.evidence_ref = evidence_ref
        self.facts.append(finding)
