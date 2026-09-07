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

from pydantic import BaseModel, Field, field_validator, model_validator


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

    @field_validator("findings", mode="before")
    @classmethod
    def _coerce_findings(cls, v: Any) -> Any:
        """ROBUSTNESS: real models routinely emit ``findings`` as a list of STRINGS (or a bare string)
        instead of the documented list-of-dicts. Without this, that one malformed field raises a
        ValidationError that rejects the WHOLE ``LLMDecision`` — silently dropping ``exploit_succeeded`` /
        ``extracted_info`` and downgrading a genuine confirmation to the safest action (ask_user), so the
        live re-drive never fires. Coerce each non-dict element to ``{"summary": <text>}``. Findings are
        ADVISORY leads only — the FACT-minting re-drive reads ``exploit_succeeded`` + ``extracted_info``,
        never ``findings`` — so this loosening cannot affect oracle soundness."""
        if v is None:
            return []
        if isinstance(v, (str, bytes)):
            v = [v]
        if not isinstance(v, list):
            return v            # a truly unexpected shape → let pydantic raise its normal error
        out: list = []
        for item in v:
            if isinstance(item, dict):
                out.append(item)
            elif isinstance(item, bytes):
                out.append({"summary": item.decode("utf-8", "replace")})
            elif isinstance(item, str):
                out.append({"summary": item})
            else:
                out.append({"summary": str(item)})
        return out


class LLMDecision(BaseModel):
    """The single structured object a ``think`` step emits; ``action`` routes the whole ReAct cycle.
    Parsed fail-closed (malformed → downgraded to the safest action in ``agent.react``). It is stamped
    non-authoritative: it can PROPOSE an action, never authorize one — the gates decide."""

    action: ActionType
    reasoning: str = ""
    # W6b: a classified BACKEND-CALL failure the think seam fail-closed over (network / api_transient /
    # api); "" for every normal decision. CODE-ONLY — the think seam stamps it by DIRECT ASSIGNMENT after
    # a real backend-call failure (``live.think_claude``); it is STRIPPED from every validated/parsed
    # input by ``_strip_model_set_error_class`` below, so a prompt-injected model response can NEVER forge
    # a "backend error" event into the process box or the append-only spine. Advisory only — authorizes
    # nothing; the engine mirrors a stamped value to the spine as an observation so the operator sees WHY
    # a think stalled.
    error_class: str = ""
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
    # ask_user: OPTIONAL suggested answers, so the operator can pick one (or "Other → type your own"). ADVISORY
    # only — the chosen text is folded back as the resume answer exactly like a free-text reply; it authorises
    # nothing and relaxes no gate (a picked option still steers, never runs, on its own).
    question_options: list[str] = Field(default_factory=list)
    summary: Optional[str] = None
    # inline analysis of the PRIOR tool output (claims → leads)
    output_analysis: Optional[OutputAnalysis] = None

    @model_validator(mode="before")
    @classmethod
    def _strip_model_set_error_class(cls, data: Any) -> Any:
        """``error_class`` is a CODE-ONLY diagnostic: only the think seam may set it, and only by DIRECT
        attribute assignment after a real backend-call failure (``live.think_claude._think_via_client``).
        Strip it from every VALIDATED input — ``parse_decision`` / ``model_validate`` / ``__init__`` — so
        the model can never populate it from its own JSON. Without this, a prompt-injected in-scope target
        could elicit a *successful* decision carrying ``error_class`` + arbitrary ``reasoning`` and forge a
        fabricated 'backend network error' (with attacker-controlled prose) into the trusted W5 process box
        and the append-only spine. Direct assignment (the legitimate stamp) bypasses this — pydantic runs
        no validator on assignment (``validate_assignment`` is off on this model)."""
        if isinstance(data, dict):
            return {k: v for k, v in data.items() if k != "error_class"}
        return data


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
    target: str = ""              # where the finding lives — a URL, or "path:line" for a code finding (the
                                  # gated auto-patch reads this to locate the file to fix). Optional + default
                                  # "" so it round-trips old spines unchanged.

    @model_validator(mode="after")
    def _fact_needs_evidence(self) -> "Finding":
        """Enforce the sovereign invariant at the TYPE level: a FACT-status finding MUST carry a
        non-whitespace signed evidence reference. This closes the deserialization/checkpoint path —
        ``Finding.model_validate({"status": "fact", "evidence_ref": ""})`` is refused, so an untrusted
        or replayed record can never construct an evidence-less fact even without going through
        ``AgentState.record_fact``."""
        if self.status == "fact" and not (self.evidence_ref or "").strip():
            raise ValueError("a FACT finding requires a non-empty signed evidence reference")
        return self


class AgentState(BaseModel):
    """The run state carried across ReAct turns. ``facts`` and ``leads`` are SEPARATE stores: the LLM
    and tools can only add to ``leads``; ``facts`` grows only through the oracle. Serialisable so
    ``agent.checkpoint`` can snapshot it into the append-only signed spine (a later F2 slice)."""

    engagement_slug: str = ""
    phase: Phase = Phase.INFORMATIONAL
    iteration: int = 0
    objective: str = ""
    # The authoritative in-scope target the operator seeded the engagement with (the `vigil engage`
    # seed URL, e.g. "http://127.0.0.1:19010/records/search?q=test"). ADVISORY to the think step: it is
    # surfaced in the TRUSTED prompt header so the model aims tool calls at the real host:port instead
    # of fabricating one from the engagement name (the observed failure was the model targeting
    # "http://<slug>/..." → out-of-scope deny). It can NEVER relax scope: the executor's egress guard
    # and the conjunctive gate re-enforce the signed scope on the executor-resolved host regardless of
    # what the model proposes here.
    target: str = ""
    facts: list[Finding] = Field(default_factory=list)     # oracle-confirmed only
    leads: list[Finding] = Field(default_factory=list)     # LLM/tool proposals
    execution_trace: list[dict[str, Any]] = Field(default_factory=list)
    awaiting_approval: bool = False
    awaiting_question: bool = False
    done: bool = False
    # Mid-run operator guidance (A5), folded into the think step's UNTRUSTED context. ADVISORY only — it
    # steers reasoning like the objective does; every action it prompts still passes the gate + approval,
    # and every claimed exploit still needs the oracle. It can neither fire a tool nor relax scope.
    operator_instructions: list[str] = Field(default_factory=list)

    def record_lead(self, finding: Finding) -> None:
        finding.status = "lead"
        finding.evidence_ref = ""
        self.leads.append(finding)

    def record_fact(self, finding: Finding, *, evidence_ref: str) -> None:
        """Only the oracle-confirmation path in ``agent.react`` calls this; a FACT MUST carry a
        non-whitespace signed evidence reference."""
        if not (evidence_ref or "").strip():
            raise ValueError("a FACT requires a signed evidence reference (oracle-confirmed only)")
        finding.status = "fact"
        finding.evidence_ref = evidence_ref
        self.facts.append(finding)
