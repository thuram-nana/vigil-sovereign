"""
vigil_integration.agent — the sovereign ReAct agent core (VIGIL-FUSION F2, keystone).

Reimplements the SHAPE of redamon's LangGraph ReAct agent (a single structured decision, an explicit
offensive phase machine, an execution trace) in VIGIL's Python, but re-plumbed so nothing bypasses the
sovereign core: every action-bearing edge clears the conjunctive gate at the phase's WARDEN tier, every
phase escalation needs a signed operator approval, and every LLM claim is a LEAD until the deterministic
oracle mints a signed FACT. The gate and oracle are injected, so the keystone is fully testable without
the live kernel/framework.

Slice-1 (this module tree): state model + phase→tier machine + the fail-closed decision parse + the
action-edge authorization + the oracle interposition. Later slices wire the live Claude think-step,
spine-snapshot checkpointing, tool execution, and fireteam.
"""

from .cognition import (
    GovernanceVerdict,
    audit_productivity_claim,
    compute_productivity_score,
    deep_think_is_novel,
    detect_state_growth,
    detect_uniform_response_anomaly,
    downgrade_verdict_to_no_progress,
    extract_axis,
    axis_key,
    axis_unproductive_count,
    governance_decision,
    record_axis_attempt,
    tier_for_score,
    update_stall_counters,
)
from .phases import can_transition, is_escalation, phase_tier, tool_tier
from .react import (
    EdgeSpec,
    EdgeVerdict,
    IntakeResult,
    apply_intake,
    authorize_edge,
    classify_edge,
    intake_result,
    parse_decision,
)
from .state import (
    ActionType,
    AgentState,
    Finding,
    LLMDecision,
    OutputAnalysis,
    Phase,
    ToolCall,
)

__all__ = [
    "Phase", "ActionType", "ToolCall", "OutputAnalysis", "LLMDecision", "Finding", "AgentState",
    "phase_tier", "tool_tier", "can_transition", "is_escalation",
    "parse_decision", "classify_edge", "authorize_edge", "EdgeSpec", "EdgeVerdict",
    "intake_result", "apply_intake", "IntakeResult",
    # F5 — non-authoritative cognition governors (budget/scheduling only)
    "GovernanceVerdict", "governance_decision", "compute_productivity_score", "tier_for_score",
    "audit_productivity_claim", "downgrade_verdict_to_no_progress",
    "detect_uniform_response_anomaly", "detect_state_growth", "update_stall_counters",
    "extract_axis", "axis_key", "axis_unproductive_count", "record_axis_attempt",
    "deep_think_is_novel",
]
