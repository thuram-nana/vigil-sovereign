"""
live.engine — VIGIL-LIVE WS-2: the unified sovereign engine ("one single system").

A single **attestation-first OODA loop** that wires the F2 ReAct core through EVERY subsystem and the
sovereign core, with NO thunks in production:

    attest (WS-6, fail-closed: no attestation → no run)
      └► think (F2)                    — the LLM PROPOSES one structured decision
         └► parse fail-closed          — garbage → the safest ASK_USER, never an action from noise
            └► classify + authorize the edge (F2)  — the REAL conjunctive gate
               (WARDEN tier ∧ CRUCIBLE authority ∧ m-of-n for destructive; escalation → signed approval)
               └► execute live (F3/F9) — the governed, loopback-PINNED Kali executor; full output → a
                  │                       signed, redacted spine record
                  └► oracle re-fire (F2 intake) — the CRUCIBLE oracle re-examines the RAW output;
                     │                             an LLM "exploit_succeeded" is a LEAD until it fires
                     └► sign a FACT (else a labelled LEAD)
                        └► project to the graph (F4, FACT-only)
                           └► cognition governors re-rank (F5, advisory)
                              └► observability span (F11, emit-only)
                                 └► checkpoint the state into the signed spine (F2b)
                                    └► loop
    then, around the whole run:
      • the AEGIS Detection Mirror (WS-4) proves each attack's signature over the target's OWN logs
        (dual certs: an offense FACT paired with a detection FACT), and
      • the WS-3 auto-patch loop may remediate a confirmed FACT (gated; timeout → REJECT).

Sovereign invariant, enforced here by construction: the LLM/tools only PROPOSE; only the oracle mints a
signed FACT; only the gate authorizes an action; only the loopback egress pin lets a packet out. Every
seam is INJECTED, so the whole engine is unit-testable without the live kernel; :func:`build_engine`
wires the real live binders with HONEST graceful degradation — a missing sidecar degrades a seam to
fail-closed (deny / no-fact / refuse-to-run), NEVER to a fake pass.

Import-clean: pydantic + stdlib + the already-import-clean sibling modules; heavy live deps
(anthropic / neo4j / opentelemetry / framework) are reached only inside :func:`build_engine`.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Optional

from pydantic import BaseModel, Field

from ..agent.react import apply_intake, authorize_edge, intake_result
from ..agent.state import ActionType, AgentState, Finding, LLMDecision, Phase

# ---------------------------------------------------------------------------------------------------
# seam types — the fixed, simple callables the loop drives. build_engine adapts the real binders to
# these; tests inject fakes. Every seam is Optional and its absence is fail-closed (never a fake pass).
# ---------------------------------------------------------------------------------------------------

# think(state) -> a non-authoritative LLMDecision proposal.
ThinkFn = Callable[[AgentState], LLMDecision]
# gate(tool_name, target, destructive) -> a verdict object with .allowed/.outcome/.reason (the
# conjunctive gate). None-seam ⇒ no gate ⇒ every tool call is DENIED.
GateFn = Callable[[str, str, bool], Any]
# run_tool(tool, phase, seq, *, approved) -> an ExecResult (.ran/.outcome/.stdout RAW/.record signed).
# The executor is pre-wired with the gate + spine signer; it re-checks the gate itself (defence in
# depth). ``approved`` marks that the owner's signed approval satisfied the WARDEN human leg for an
# offense tool (>= A2) — CRUCIBLE scope is still enforced by the executor's gate regardless.
RunToolFn = Callable[..., Any]
# oracle(raw_output, analysis) -> a signed evidence ref on confirmation, else None (the CRUCIBLE oracle).
OracleFn = Callable[[str, Any], Optional[str]]
# attest(action, target, phase, seq, prev_hash) -> an AttestationVerdict (.allowed/.reason/.attestation).
AttestFn = Callable[..., Any]
# project(facts) -> None (F4 FACT-only graph projection); govern(state) -> a verdict (F5, advisory);
# emit(record) -> None (F11 span); checkpoint(state, seq) -> a snapshot record (F2b); detect() -> list.
ProjectFn = Callable[[list], None]
GovernFn = Callable[[AgentState], Any]
EmitFn = Callable[[Any], None]
CheckpointFn = Callable[[AgentState, int], Any]
DetectFn = Callable[[], list]
# approval(decision, state) -> True iff a valid SIGNED operator approval exists for this escalation
# (the human leg of the conjunctive gate). None-seam ⇒ False ⇒ an escalation stays queued (fail-closed).
ApprovalFn = Callable[[LLMDecision, AgentState], bool]
# operator_messages() -> the NEW mid-run operator instructions for this engagement, consumed once (A5).
# ADVISORY context only — folded into the think step; never a tool trigger or a scope change. None-seam ⇒
# no mid-run guidance (an ASK_USER pause simply ends the run, exactly as before A5).
OperatorMsgFn = Callable[[], list]

_GENESIS = "0" * 64


@dataclass(frozen=True)
class EngineSeams:
    """The injected seams. Any seam left None fails closed at its point of use (documented per-field)."""

    think: Optional[ThinkFn] = None            # None ⇒ the loop cannot propose ⇒ it completes immediately
    gate: Optional[GateFn] = None              # None ⇒ every target-touching tool call is DENIED
    run_tool: Optional[RunToolFn] = None       # None ⇒ an allowed tool call cannot run ⇒ recorded refusal
    oracle: Optional[OracleFn] = None          # None ⇒ nothing an LLM claims can ever become a FACT
    attest: Optional[AttestFn] = None          # None ⇒ (with require_attestation) the engagement is REFUSED
    project: Optional[ProjectFn] = None        # None ⇒ facts are simply not mirrored to the graph
    govern: Optional[GovernFn] = None          # None ⇒ no advisory re-rank (never gates truth anyway)
    emit: Optional[EmitFn] = None              # None ⇒ no telemetry span emitted
    checkpoint: Optional[CheckpointFn] = None  # None ⇒ no per-turn spine snapshot
    detect: Optional[DetectFn] = None          # None ⇒ the Detection Mirror is not run
    approval: Optional[ApprovalFn] = None      # None ⇒ a phase escalation / fireteam stays QUEUED
    operator_messages: Optional[OperatorMsgFn] = None  # None ⇒ no mid-run operator instructions (A5)


# ---------------------------------------------------------------------------------------------------
# the run report — a faithful, honest record of what the engine did (facts vs leads kept distinct)
# ---------------------------------------------------------------------------------------------------


class ToolCallRecord(BaseModel):
    tool: str = ""
    outcome: str = ""          # "ran" | "deny"
    tier: str = "A0"
    target: str = ""
    destructive: bool = False
    record_id: str = ""        # the signed ExecRecord id ("" if the call was denied / unsigned)


class RunReport(BaseModel):
    """Everything the engagement produced. ``facts`` are oracle-confirmed + signed; ``leads`` are
    proposals. ``refused`` with an empty run means the attestation gate denied the whole engagement."""

    slug: str = ""
    seed: str = ""
    objective: str = ""
    refused: bool = False
    refusal_reason: str = ""
    attestation_ref: str = ""              # the WS-6 usage-attestation record hash for this run
    iterations: int = 0
    decisions: list[str] = Field(default_factory=list)
    tool_calls: list[ToolCallRecord] = Field(default_factory=list)
    denied_edges: list[str] = Field(default_factory=list)
    queued_edges: list[str] = Field(default_factory=list)
    facts: list[Finding] = Field(default_factory=list)
    leads: list[Finding] = Field(default_factory=list)
    detection_facts: int = 0
    detection_leads: int = 0
    checkpoints: list[str] = Field(default_factory=list)
    paused: str = ""                       # "" | "ask_user" | "awaiting_approval"
    done: bool = False

    @property
    def fact_count(self) -> int:
        return len(self.facts)


# ---------------------------------------------------------------------------------------------------
# the engine
# ---------------------------------------------------------------------------------------------------


@dataclass
class VigilEngine:
    """The unified OODA engine. Holds the injected seams + policy; :meth:`engage` runs one engagement,
    attestation-first and fail-closed. Stateless between engagements (state lives in ``AgentState`` and
    the signed spine)."""

    slug: str
    seams: EngineSeams = field(default_factory=EngineSeams)
    require_attestation: bool = True       # the WS-6 deep-core rule: no attestation → no run
    max_iterations: int = 12

    # -- the loop -----------------------------------------------------------------------------------

    def engage(self, seed_url: str, *, objective: str = "", spine_head: str = _GENESIS) -> RunReport:
        """Run one authorized engagement against ``seed_url`` (loopback-pinned downstream). Mints a usage
        attestation FIRST and refuses the whole run if one cannot be minted+recorded; then drives the
        OODA loop, routing every action-bearing edge through the real gate and every claimed exploit
        through the real oracle. Never raises — every failure path is a recorded refusal, never a crash."""
        report = RunReport(slug=self.slug, seed=seed_url, objective=objective)

        # (0) ATTEST FIRST — the deep-core, always-on rule. No attestation → no engagement.
        ok, att_ref, why = self._attest_run(seed_url, seq=0, prev_hash=spine_head)
        if not ok:
            report.refused = True
            report.refusal_reason = why
            return report
        report.attestation_ref = att_ref

        state = AgentState(engagement_slug=self.slug, objective=objective, phase=Phase.INFORMATIONAL)
        seq = 1

        for it in range(self.max_iterations):
            state.iteration = it
            report.iterations = it + 1

            self._drain_operator(state)      # (A5) fold in any queued operator instructions BEFORE we think
            decision = self._think(state)
            report.decisions.append(str(decision.action.value))

            # inert terminal / pause actions first.
            if decision.action == ActionType.COMPLETE:
                state.done = True
                break
            if decision.action == ActionType.ASK_USER:
                # (A5) the ASK_USER dead-end is now resumable: if the operator queued an instruction
                # (possibly DURING this think), fold it in and continue instead of ending the run. Advisory
                # only — the resulting think's proposals still pass authorize_edge (gate + approval), so an
                # instruction can neither fire a tool nor relax scope.
                if self._drain_operator(state) > 0:
                    report.decisions[-1] = "ask_user->resumed"
                    continue
                state.awaiting_question = True
                report.paused = "ask_user"
                break

            verdict = authorize_edge(decision, state, gate=self.seams.gate)
            approved = False

            if verdict.outcome == "queue":
                # The conjunctive gate's HUMAN LEG. WARDEN queues an offense tool (>= A2), a phase
                # escalation, or a fireteam deploy — none auto-run on the LLM's word; each proceeds only
                # with a valid SIGNED operator approval. CRUCIBLE scope is ALREADY enforced (a queue is
                # "in-envelope but needs approval"; an out-of-scope target is a "deny", never a queue).
                if not self._approved(decision, state):
                    report.queued_edges.append(verdict.reason)
                    report.paused = "awaiting_approval"
                    state.awaiting_approval = True
                    break
                approved = True
                if decision.action != ActionType.USE_TOOL:
                    # phase escalation / fireteam: apply the approved escalation and loop.
                    self._apply_escalation(decision, state)
                    self._checkpoint(state, seq, report)
                    seq += 1
                    continue
                # an APPROVED tool call falls through to execution (with the owner-approval gate).

            elif verdict.outcome != "allow":
                # denied / structurally invalid → record the refusal and PIVOT (never give up the run).
                report.denied_edges.append(verdict.reason)
                state.execution_trace.append(
                    {"iteration": it, "action": str(decision.action.value), "outcome": "deny",
                     "reason": verdict.reason})
                continue

            # ALLOW (A0/A1 auto) or APPROVED (owner-signed) — execute through the governed live executor.
            exec_res = self._run_tool(decision.tool, state.phase, seq, approved=approved)
            seq += 1
            report.tool_calls.append(self._tool_record(exec_res))
            if not getattr(exec_res, "ran", False):
                report.denied_edges.append(getattr(exec_res, "reason", "tool call not run"))
                state.execution_trace.append(
                    {"iteration": it, "action": "use_tool", "tool": getattr(exec_res, "tool", ""),
                     "outcome": "deny", "reason": getattr(exec_res, "reason", "")})
                # observability + checkpoint still record the refused attempt.
                self._emit(getattr(exec_res, "record", None))
                self._checkpoint(state, seq, report)
                seq += 1
                continue

            # ORACLE INTAKE — the LLM's claims become LEADs; only the oracle re-firing over the RAW
            # output mints a signed FACT. This is the load-bearing anti-hallucination seam.
            raw = getattr(exec_res, "stdout", "") or ""
            intake = intake_result(raw, decision.output_analysis, oracle=self.seams.oracle,
                                   source=(decision.tool.tool_name if decision.tool else ""))
            apply_intake(state, intake)
            report.facts.extend(intake.facts)
            report.leads.extend(intake.leads)

            self._project(intake.facts)
            self._govern(state)
            self._emit(getattr(exec_res, "record", None))
            self._checkpoint(state, seq, report)
            seq += 1

            state.execution_trace.append(
                {"iteration": it, "action": "use_tool",
                 "tool": decision.tool.tool_name if decision.tool else "", "outcome": "ran",
                 "facts": len(intake.facts), "leads": len(intake.leads)})

        report.done = state.done

        # DETECTION MIRROR (WS-4) — prove each attack's signature over the target's own logs.
        self._run_detection(report)
        return report

    # -- seam adapters (each fail-closed / total) ---------------------------------------------------

    def _attest_run(self, seed_url: str, *, seq: int, prev_hash: str) -> tuple[bool, str, str]:
        """Mint + durably record the run's usage attestation. Returns (ok, attestation_ref, reason)."""
        if self.seams.attest is None:
            if self.require_attestation:
                return (False, "", "no attestation seam wired and attestation is MANDATORY "
                        "(deep-core rule: no attestation → no run) — fail-closed refusal")
            return (True, "", "attestation not required (explicitly disabled)")
        try:
            v = self.seams.attest(action="engage", target=seed_url, phase="informational",
                                  seq=seq, prev_hash=prev_hash)
        except Exception as exc:  # noqa: BLE001 — an attestation error is a REFUSAL, never a crash
            return (False, "", f"attestation gate error (fail-closed): {exc}")
        if getattr(v, "allowed", False) is not True:
            return (False, "", f"attestation denied: {getattr(v, 'reason', 'no reason')}")
        att = getattr(v, "attestation", None)
        return (True, str(getattr(att, "record_hash", "") or ""), "attested")

    def _think(self, state: AgentState) -> LLMDecision:
        if self.seams.think is None:
            return LLMDecision(action=ActionType.COMPLETE, reasoning="no think backend wired",
                               summary="engagement ended: nothing to propose")
        try:
            d = self.seams.think(state)
        except Exception as exc:  # noqa: BLE001 — a think error pauses for a human, never proceeds
            return LLMDecision(action=ActionType.ASK_USER,
                               reasoning=f"think backend error: {type(exc).__name__}",
                               question="the think backend errored — how should I proceed?")
        return d if isinstance(d, LLMDecision) else LLMDecision(
            action=ActionType.ASK_USER, reasoning="think returned a non-decision",
            question="the think backend returned no valid decision — how should I proceed?")

    def _run_tool(self, tool: Any, phase: Phase, seq: int, *, approved: bool = False) -> Any:
        if self.seams.run_tool is None or tool is None:
            return _DenyResult(getattr(tool, "tool_name", "") if tool is not None else "",
                               "no executor wired — a tool call cannot run (fail-closed)")
        try:
            return self.seams.run_tool(tool, phase, seq, approved=approved)
        except TypeError:
            # a seam that predates the approved kwarg — call it positionally (approval defaults off).
            try:
                return self.seams.run_tool(tool, phase, seq)
            except Exception as exc:  # noqa: BLE001
                return _DenyResult(getattr(tool, "tool_name", ""),
                                   f"executor error (fail-closed): {type(exc).__name__}: {exc}")
        except Exception as exc:  # noqa: BLE001 — an executor error is a DENY, never a crash
            return _DenyResult(getattr(tool, "tool_name", ""),
                               f"executor error (fail-closed): {type(exc).__name__}: {exc}")

    def _approved(self, decision: LLMDecision, state: AgentState) -> bool:
        if self.seams.approval is None:
            return False
        try:
            return self.seams.approval(decision, state) is True
        except Exception:  # noqa: BLE001 — an approval error denies the escalation
            return False

    def _drain_operator(self, state: AgentState) -> int:
        """Fold any NEW operator instructions into ``state`` so the next think sees them; return how many
        were new. ADVISORY only — this changes what the LLM reads, never what it may do (every proposed
        action still passes authorize_edge). Fail-closed + total: no seam, or any seam error, yields 0 and
        never raises into the loop."""
        if self.seams.operator_messages is None:
            return 0
        try:
            msgs = self.seams.operator_messages() or []
        except Exception:  # noqa: BLE001 — an instruction-source error never crashes the run
            return 0
        new = [str(m).strip() for m in msgs if str(m or "").strip()]
        state.operator_instructions.extend(new)
        return len(new)

    @staticmethod
    def _apply_escalation(decision: LLMDecision, state: AgentState) -> None:
        """Apply an APPROVED escalation (only reached after a valid signed operator approval)."""
        if decision.action == ActionType.TRANSITION_PHASE and decision.target_phase is not None:
            state.phase = decision.target_phase
            state.awaiting_approval = False

    def _project(self, facts: list) -> None:
        if self.seams.project is None or not facts:
            return
        try:
            self.seams.project(facts)
        except Exception:  # noqa: BLE001 — a graph projection failure never affects the run's truth
            pass

    def _govern(self, state: AgentState) -> None:
        if self.seams.govern is None:
            return
        try:
            self.seams.govern(state)  # advisory only — the return is not allowed to gate anything
        except Exception:  # noqa: BLE001
            pass

    def _emit(self, record: Any) -> None:
        if self.seams.emit is None or record is None:
            return
        try:
            self.seams.emit(record)
        except Exception:  # noqa: BLE001 — telemetry is emit-only; a sink error never affects the run
            pass

    def _checkpoint(self, state: AgentState, seq: int, report: RunReport) -> None:
        if self.seams.checkpoint is None:
            return
        try:
            rec = self.seams.checkpoint(state, seq)
        except Exception:  # noqa: BLE001 — a checkpoint failure is recorded, never fatal
            return
        ref = (getattr(rec, "hash", None) or getattr(rec, "record_hash", None)
               or getattr(rec, "record_id", None) or rec)
        if isinstance(ref, str) and ref:
            report.checkpoints.append(ref)

    def _run_detection(self, report: RunReport) -> None:
        if self.seams.detect is None:
            return
        try:
            dets = self.seams.detect() or []
        except Exception:  # noqa: BLE001 — the Detection Mirror is defensive/emit-only
            return
        report.detection_facts = sum(1 for d in dets if getattr(d, "is_fact", False))
        report.detection_leads = sum(1 for d in dets if not getattr(d, "is_fact", False))

    @staticmethod
    def _tool_record(exec_res: Any) -> ToolCallRecord:
        rec = getattr(exec_res, "record", None)
        return ToolCallRecord(
            tool=str(getattr(exec_res, "tool", "") or ""),
            outcome=str(getattr(exec_res, "outcome", "") or ""),
            tier=str(getattr(exec_res, "tier", "A0") or "A0"),
            target=str(getattr(exec_res, "target", "") or ""),
            destructive=bool(getattr(exec_res, "destructive", False)),
            record_id=str(getattr(rec, "record_id", "") or "") if rec is not None else "",
        )


@dataclass(frozen=True)
class _DenyResult:
    """The engine's own fail-closed ExecResult stand-in for when no executor could run (duck-typed to
    the executor's ExecResult surface the loop reads)."""

    tool: str
    reason: str
    ran: bool = False
    outcome: str = "deny"
    tier: str = "A0"
    target: str = ""
    destructive: bool = False
    stdout: str = ""
    record: Any = None
