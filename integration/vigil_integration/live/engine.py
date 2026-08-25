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
from urllib.parse import urlsplit

from pydantic import BaseModel, Field

from ..agent.react import apply_intake, authorize_edge, intake_result
from ..agent.state import ActionType, AgentState, Finding, LLMDecision, Phase
from ..agent.targets import extract_target
from .tool_intake import analysis_from_tool_output

# The governed LOCAL terminal tool name (mirrors executor._TERMINAL_TOOL — kept as a local literal so engine
# imports nothing from executor). A terminal command inspects HOST state; its output is advisory, never
# target-produced evidence, so the loop must NEVER feed it to oracle intake (it can never mint a FACT).
_TERMINAL_TOOL = "terminal.run"

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
# The production seam also accepts a keyword-only ``redrive`` request-spec (T2 live re-drive); the engine
# binds it in via ``_oracle_with_redrive`` and passes this 2-arg-shaped wrapper here, so react.py is unchanged.
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
# deploy_fireteam(decision, state, seq) -> a FireteamOutcome (A4c). Runs an APPROVED fan-out wave: N capped
# members (never A3) each independently gated + oracle-checked; returns oracle-confirmed facts + leads +
# queued escalations. Reached ONLY after authorize_edge queued the deploy and a signed operator approval
# satisfied it (approve-then-run). None-seam ⇒ an approved deploy is a recorded refusal (fail-closed).
DeployFireteamFn = Callable[[LLMDecision, AgentState, int], Any]
# persist_spine() -> None (T3): a best-effort, END-OF-RUN persist of the CRUCIBLE blackboard chain as inert,
# governance-signed bytes (spine-head.json + spine-chain.json) so a public-key-only offline reader can verify
# it. Emit-only / side-effecting; its return is ignored. None-seam ⇒ the chain is simply not persisted (the
# segment then reports honestly UNVERIFIABLE — never a fake pass). A persist error NEVER affects the run.
PersistSpineFn = Callable[[], None]
# spine_post(kind, payload, *, parent_id=None) -> Optional[int] (T3b): mirror ONE OODA hook point onto the
# CRUCIBLE blackboard event spine, so the END-OF-RUN persist_spine has real events to sign for EVERY engage
# run — making the offline-verifiable spine (O9) universal, not fireteam-only. ``kind`` is a plain blackboard
# event-kind string ("decision"/"hypothesis"/"observation"/"tool_call"/"tool_result"/"finding"/"refusal");
# ``payload`` a plain dict in the engine's own vocabulary (the wiring adapter reshapes it to the framework's
# validated schema — the engine imports NO framework). Returns the posted event id (for provenance
# parent-linking of tool_call→tool_result / finding) or None. EMIT-ONLY + best-effort: its exceptions are
# swallowed and NEVER affect the run's truth; a None return is fine. None-seam ⇒ NO-OP, byte-identical to
# today (no events ⇒ persist_spine writes nothing ⇒ the segment stays honestly UNVERIFIABLE, never a fake
# pass). engine.py stays FRAMEWORK-FREE: this is a plain callable and nothing here imports the framework.
SpinePostFn = Callable[..., Optional[int]]

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
    # W2b resume: ONE read → (restored_state, head_seq). One call so the state and its seq are always from
    # the same snapshot (no two-read race). None ⇒ --resume degrades to a fresh start.
    rebuild: Optional[Callable[[], Any]] = None
    detect: Optional[DetectFn] = None          # None ⇒ the Detection Mirror is not run
    approval: Optional[ApprovalFn] = None      # None ⇒ a phase escalation / fireteam stays QUEUED
    operator_messages: Optional[OperatorMsgFn] = None  # None ⇒ no mid-run operator instructions (A5)
    deploy_fireteam: Optional[DeployFireteamFn] = None  # None ⇒ an approved fireteam deploy is refused (A4c)
    persist_spine: Optional[PersistSpineFn] = None  # None ⇒ the blackboard chain is not persisted (T3)
    spine_post: Optional[SpinePostFn] = None  # None ⇒ OODA events are not mirrored to the blackboard spine (T3b)


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
    # G1 (Tier A) — the STRUCTURED record of fireteam member edges QUEUED for a signed operator approval (an
    # over-cap/dangerous member tool that was never run). Each entry carries the binding key
    # (wave_id/member_id/seq) + tool/target/requested_tier/reason (target/reason scrubbed at source), so the
    # operator can review exactly what is pending at END OF RUN. NB this report is IN-MEMORY (the run's return
    # value, not persisted); the DURABLE append-only ledger a separate-process resolve tier (B) reads is the
    # ConfirmationRegistry (`fireteam/confirmation.py`). Surfacing only: nothing here is executable, and a
    # member edge still never auto-runs.
    fireteam_escalations: list[dict] = Field(default_factory=list)
    facts: list[Finding] = Field(default_factory=list)
    leads: list[Finding] = Field(default_factory=list)
    detection_facts: int = 0
    detection_leads: int = 0
    checkpoints: list[str] = Field(default_factory=list)
    paused: str = ""                       # "" | "ask_user" | "awaiting_approval"
    done: bool = False
    resumed: bool = False                  # True iff this run CONTINUED a prior checkpointed state (W2b)

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

    def engage(self, seed_url: str, *, objective: str = "", spine_head: str = _GENESIS,
               resume: bool = False) -> RunReport:
        """Run one authorized engagement against ``seed_url`` (loopback-pinned downstream). Mints a usage
        attestation FIRST and refuses the whole run if one cannot be minted+recorded; then drives the
        OODA loop, routing every action-bearing edge through the real gate and every claimed exploit
        through the real oracle. Never raises — every failure path is a recorded refusal, never a crash.

        ``resume=True`` continues a prior run of this slug from its last SIGNED checkpoint instead of
        starting fresh — the network-failure / crash recovery path (W2b)."""
        report = RunReport(slug=self.slug, seed=seed_url, objective=objective)

        # (0) ATTEST FIRST — the deep-core, always-on rule. No attestation → no engagement.
        ok, att_ref, why = self._attest_run(seed_url, seq=0, prev_hash=spine_head)
        if not ok:
            report.refused = True
            report.refusal_reason = why
            return report
        report.attestation_ref = att_ref

        # (0b) RESUME (W2b): reconstruct the last signed AgentState for this slug (via ONE spine read that
        # returns the state AND its seq together) and continue the OODA loop from where it stopped. The
        # checkpoint spine already threads prev_hash from the file tail (a fresh binder resumes the SAME
        # chain), so all we seed here is (a) the state, (b) the monotonic seq at head_seq+1 so a resumed turn
        # never collides a seq with an already-persisted (and actually-restored) one, and (c) the loop index.
        #
        # FAIL-CLOSED, not fail-open: a resume proceeds ONLY when we have real restored progress AND a real
        # head_seq (>=1) to continue past. No prior state, no rebuild seam, an unreadable/forged spine, a
        # raising seam, or a restored-state-without-a-seq all degrade to a FRESH start — never a partial
        # resume that could reseed seq=1 and collide persisted turns, and never a crash. Gate/oracle/
        # attestation are unchanged: a resumed edge is authorized + oracle-confirmed exactly like a fresh one.
        #
        # AT-LEAST-ONCE re-execution: the per-turn checkpoint is written at the END of an iteration, so a
        # crash AFTER a tool ran but BEFORE its checkpoint resumes at that iteration and RE-RUNS its tool.
        # Every re-run still re-gates + re-confirms through the oracle (no auth bypass), but an offense tool
        # CAN re-fire on resume — resume is at-least-once, not exactly-once. A COMPLETED run is a no-op.
        state = AgentState(engagement_slug=self.slug, objective=objective, phase=Phase.INFORMATIONAL)
        seq = 1
        start_it = 0
        if resume and self.seams.rebuild is not None:
            prior, hs = None, 0
            try:
                out = self.seams.rebuild()                  # ONE read → (restored_state, head_seq)
                if isinstance(out, tuple) and len(out) == 2:
                    prior, hs = out[0], int(out[1] or 0)
                elif isinstance(out, AgentState):           # tolerate a bare-state seam (tests)
                    prior, hs = out, 0
            except Exception:  # noqa: BLE001 — an unreadable/forged spine → a fresh start, never a crash
                prior, hs = None, 0
            has_progress = isinstance(prior, AgentState) and bool(
                prior.iteration or prior.facts or prior.leads or prior.execution_trace or prior.done
                or prior.awaiting_approval or prior.awaiting_question)   # a paused-at-0 run resumes honestly
            if has_progress and hs >= 1:                    # real state AND a real seq to continue past
                state = prior
                state.engagement_slug = self.slug          # identity/objective stay authoritative
                if objective:
                    state.objective = objective
                report.resumed = True
                report.facts.extend(list(prior.facts))     # the report reflects TOTAL progress, honestly
                report.leads.extend(list(prior.leads))
                seq = int(hs) + 1                           # strictly past every persisted + restored turn
                if state.done:
                    start_it = self.max_iterations          # a COMPLETED run resumes to a no-op, never re-runs
                    report.iterations = int(getattr(prior, "iteration", 0) or 0)   # honest count, not max
                else:
                    start_it = int(getattr(prior, "iteration", 0) or 0) + 1
                    report.iterations = start_it

        for it in range(start_it, self.max_iterations):
            state.iteration = it
            report.iterations = it + 1

            self._drain_operator(state)      # (A5) fold in any queued operator instructions BEFORE we think
            decision = self._think(state)
            report.decisions.append(str(decision.action.value))

            # W6b — a classified BACKEND-CALL failure the think seam fail-closed over (network / api /
            # api_transient) is mirrored to the spine as an OBSERVATION so the operator's process box shows
            # WHY a think stalled (network vs API), not just a silent ASK_USER. Advisory only: it is
            # source-tagged 'backend-error', mints no finding, and never enters oracle intake.
            if getattr(decision, "error_class", ""):
                self._spine_post("observation", {
                    "source": "backend-error",
                    "error_class": str(decision.error_class),
                    "summary": decision.reasoning or f"backend {decision.error_class} error"})

            # T3b — mirror the OODA ORIENT/DECIDE step onto the blackboard spine (best-effort NO-OP without a
            # seam). The decision is the coordinator choice; a USE_TOOL proposal additionally posts the
            # falsifiable HYPOTHESIS it is testing. All payloads are deterministic (no wallclock/rng), so two
            # identical scripted engages produce identical spine digests.
            self._spine_post("decision", {
                "question": f"phase={state.phase.value} iteration={it}: what is the next action?",
                "choice": str(decision.action.value),
                "rationale": decision.reasoning or ""})
            if decision.action == ActionType.USE_TOOL and decision.tool is not None:
                _oa = decision.output_analysis
                _info = getattr(_oa, "extracted_info", {}) if _oa is not None else {}
                _tname = decision.tool.tool_name or ""
                _ttarget = extract_target(getattr(decision.tool, "tool_args", None)) or ""
                self._spine_post("hypothesis", {
                    "handle": f"H-it{it}",
                    "surface": _tname,
                    "bug_class": str((_info or {}).get("bug_class", "")),
                    "action": f"{_tname} vs {_ttarget}".strip(),
                    "rationale": decision.reasoning or ""})

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
                    # phase escalation / fireteam: apply the approved escalation and loop. (Reached ONLY
                    # after a signed operator approval satisfied the queued edge — approve-then-run.)
                    self._apply_escalation(decision, state)
                    if decision.action == ActionType.DEPLOY_FIRETEAM:
                        self._deploy_fireteam(decision, state, seq, report)
                    self._checkpoint(state, seq, report)
                    seq += 1
                    continue
                # an APPROVED tool call falls through to execution (with the owner-approval gate).

            elif verdict.outcome != "allow":
                # denied / structurally invalid → record the refusal and PIVOT (never give up the run).
                report.denied_edges.append(verdict.reason)
                self._spine_post("refusal", {                # T3b — a gate refusal IS evidence on the spine
                    "gate": "authorize_edge", "action_refused": str(decision.action.value),
                    "reason": verdict.reason or "", "fatal": False})
                state.execution_trace.append(
                    {"iteration": it, "action": str(decision.action.value), "outcome": "deny",
                     "reason": verdict.reason})
                continue

            # ALLOW (A0/A1 auto) or APPROVED (owner-signed) — execute through the governed live executor.
            # T3b — record the tool-run REQUEST on the spine BEFORE it runs (the intent is on the immutable
            # stream even if the run refuses/errors); its id links the tool_result below.
            _tc_id = self._spine_post("tool_call", {
                "tool": decision.tool.tool_name if decision.tool else "",
                "target": extract_target(getattr(decision.tool, "tool_args", None)) if decision.tool else "",
                "tier": str(getattr(verdict, "tier", "") or ""),
                "args_summary": "owner-approved" if approved else "auto"})
            exec_res = self._run_tool(decision.tool, state.phase, seq, approved=approved)
            seq += 1
            report.tool_calls.append(self._tool_record(exec_res))
            # T3b — record the tool OUTCOME (a provenance-labelled observation, never a fact), linked to its
            # tool_call. Covers BOTH the ran and the refused/errored branch below with one post point.
            _ran = bool(getattr(exec_res, "ran", False))
            self._spine_post("tool_result", {
                "tool": (getattr(exec_res, "tool", "") or (decision.tool.tool_name if decision.tool else "")),
                "ok": _ran, "refused": not _ran, "gate": "" if _ran else "executor",
                "summary": str(getattr(exec_res, "outcome", "") or ""),
                "note": "" if _ran else str(getattr(exec_res, "reason", "") or "")}, parent_id=_tc_id)
            if not getattr(exec_res, "ran", False):
                report.denied_edges.append(getattr(exec_res, "reason", "tool call not run"))
                self._spine_post("refusal", {                # T3b — the executor's fail-closed deny as evidence
                    "gate": "executor", "action_refused": (getattr(exec_res, "tool", "") or "tool"),
                    "reason": str(getattr(exec_res, "reason", "") or ""), "fatal": False})
                state.execution_trace.append(
                    {"iteration": it, "action": "use_tool", "tool": getattr(exec_res, "tool", ""),
                     "outcome": "deny", "reason": getattr(exec_res, "reason", "")})
                # observability + checkpoint still record the refused attempt.
                self._emit(getattr(exec_res, "record", None))
                self._checkpoint(state, seq, report)
                seq += 1
                continue

            # T3 — a governed LOCAL terminal command inspects HOST state (a file, a process, uname): its output
            # is NOT target-produced evidence, so it is ADVISORY ONLY and must NEVER enter oracle intake — a
            # terminal record can never mint a FACT (nor even a LEAD from output_analysis, which is meant for a
            # real tool's target output). The signed ExecRecord is still emitted + checkpointed for the audit
            # trail; the loop then continues to the next think. This is the load-bearing "autonomous terminal
            # never fabricates a finding" property.
            _ran_tool = decision.tool.tool_name if decision.tool else ""
            if isinstance(_ran_tool, str) and _ran_tool.strip().lower() == _TERMINAL_TOOL:
                self._emit(getattr(exec_res, "record", None))
                self._checkpoint(state, seq, report)
                seq += 1
                state.execution_trace.append(
                    {"iteration": it, "action": "use_tool", "tool": _ran_tool, "outcome": "ran",
                     "facts": 0, "leads": 0, "advisory": "terminal"})
                continue

            # H8f-b — a body-routed execution (--brain-execute-via-body with a provisioned runner) mints its
            # facts inside the RUNNER's OWN admit()+certify (over VIGIL's own gated re-drive, never the tool's
            # bytes), so this ExecResult carries ZERO stdout and the oracle-intake path below would mint
            # nothing. Surface the runner's ALREADY-oracle-confirmed, signed facts through the SAME
            # already-confirmed-fact path used for fireteam facts (a fact needs a signed evidence ref, else it
            # degrades to a LEAD). This never re-adjudicates tool output — the engine only counts what the
            # runner independently confirmed + signed. A normal executor ExecResult has no `body_facts`
            # attribute, so this branch is body-only.
            if getattr(exec_res, "body_facts", None) is not None:
                nf, nl = self._surface_body_facts(exec_res, state, report, parent_id=_tc_id)
                self._emit(getattr(exec_res, "record", None))
                self._checkpoint(state, seq, report)
                seq += 1
                state.execution_trace.append(
                    {"iteration": it, "action": "use_tool", "tool": getattr(exec_res, "tool", ""),
                     "outcome": "ran", "facts": nf, "leads": nl})
                continue

            # ORACLE INTAKE — the LLM's claims become LEADs; only the oracle re-firing over target-produced
            # bytes mints a signed FACT. This is the load-bearing anti-hallucination seam. T2: for an
            # error_based_sqli exploit claim the oracle ADDITIONALLY re-drives the proposed exploit through
            # the gated executor and mints a FACT from the TARGET's FRESH response bytes — the LLM's claimed
            # oracle_context is discarded for the fact (its proposed payload/param/endpoint is only "where to
            # look"). The request-spec is bound in via `_oracle_with_redrive`; react.py stays unchanged.
            raw = getattr(exec_res, "stdout", "") or ""
            # T3b — the recon/probe RAW output is a provenance-labelled observation on the spine (length only —
            # deterministic and secret-safe; the raw bytes stay in the signed ExecRecord, not the digest).
            _obs_id = self._spine_post("observation", {
                "source": "tool:" + (decision.tool.tool_name if decision.tool else ""),
                "surface": (extract_target(getattr(decision.tool, "tool_args", None)) if decision.tool else ""),
                "summary": f"tool output captured: {len(raw)} byte(s)"}, parent_id=_tc_id)
            oracle = self._oracle_with_redrive(decision, exec_res)
            # H8: a deterministic planner (BrainThink) sets no output_analysis — it has no LLM — so the
            # executed tool's bytes were parsed by nothing and every run reported 0 facts AND 0 leads.
            # When the decision carries no analysis, derive PROPOSALS from the tool's own structured
            # output. LEAD-only by construction: exploit_succeeded=False keeps the oracle unfired here, and
            # react._finding_from_claim hard-codes status="lead". An LLM-supplied analysis always wins.
            _analysis = decision.output_analysis
            if _analysis is None and decision.tool is not None:
                _analysis = analysis_from_tool_output(decision.tool.tool_name, raw)
            intake = intake_result(raw, _analysis, oracle=oracle,
                                   source=(decision.tool.tool_name if decision.tool else ""))
            apply_intake(state, intake)
            report.facts.extend(intake.facts)
            report.leads.extend(intake.leads)

            # T3b — the ORACLE INTAKE result on the spine: each oracle-confirmed FACT as a finding event
            # (linked to the raw observation), each LEAD as a labelled observation (never a finding — only a
            # fired oracle mints a fact, mirrored honestly here).
            for _f in intake.facts:
                self._spine_post("finding", {
                    "ref": getattr(_f, "ref", ""), "title": getattr(_f, "title", ""),
                    "severity": getattr(_f, "severity", ""), "bug_class": getattr(_f, "bug_class", ""),
                    "surface": getattr(_f, "source", ""), "summary": getattr(_f, "title", ""),
                    "status": "fact", "verified_by_oracle": True}, parent_id=_obs_id)
            for _ld in intake.leads:
                self._spine_post("observation", {
                    "source": "lead:" + (getattr(_ld, "source", "") or ""),
                    "surface": getattr(_ld, "bug_class", "") or "(lead)",
                    "summary": f"LEAD (unconfirmed): {getattr(_ld, 'title', '')}"}, parent_id=_obs_id)

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

        # W2b — persist the TERMINAL state so a later --resume sees the true end. The COMPLETE branch and
        # the pause branches (ask_user / awaiting_approval) BREAK without a per-turn checkpoint, so without
        # this the last persisted snapshot reads done=False and a finished run would RE-ENTER the loop on
        # resume and re-fire offense. Writing the final state (done / paused flags / final trace) makes the
        # resume done-guard reachable and lets a paused run resume its true pause. Fail-closed: a spine
        # outage is a recorded no-op (via _checkpoint), never fatal to the run. Skipped only for a pure
        # no-op resume (start_it == max_iterations: a completed/exhausted run this session did no work and
        # its terminal state is already persisted) — so a done-resume adds no redundant snapshot.
        if start_it < self.max_iterations:
            self._checkpoint(state, seq, report)

        # DETECTION MIRROR (WS-4) — prove each attack's signature over the target's own logs.
        self._run_detection(report)

        # T3 — PERSIST the CRUCIBLE blackboard chain as inert, governance-signed bytes so a public-key-only
        # offline reader can verify it (making overclaim O9 true for the last chain that wasn't file-backed).
        # Best-effort + fail-closed: a persist error is swallowed and never affects the run's truth.
        self._persist_spine()
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

    def _oracle_with_redrive(self, decision: LLMDecision, exec_res: Any) -> Optional[OracleFn]:
        """The oracle seam with the T2 live-re-drive request-spec bound in. For an ``error_based_sqli``
        ``exploit_succeeded`` candidate carrying a COMPLETE request-spec (derived from the TOOL ARGS + the
        LLM's analysis — its proposed "where to look"), wrap ``seams.oracle`` so it ALSO receives that spec
        and can re-drive the target. Otherwise return the seam unchanged. Fail-closed: no seam ⇒ None; an
        oracle that predates the ``redrive`` kwarg (a test fake / older seam) is called positionally, i.e.
        no re-drive — exactly today's LEAD-only behaviour."""
        oracle = self.seams.oracle
        if oracle is None:
            return None
        spec = self._redrive_spec(decision, exec_res)
        if spec is None:
            return oracle

        def _with_spec(raw_output: str, analysis: Any, _o: Any = oracle, _spec: dict = spec) -> Optional[str]:
            try:
                return _o(raw_output, analysis, redrive=_spec)
            except TypeError:
                # an oracle that does not accept the redrive kwarg ⇒ no re-drive (fail-closed, unchanged).
                return _o(raw_output, analysis)

        return _with_spec

    @staticmethod
    def _redrive_spec(decision: LLMDecision, exec_res: Any) -> Optional[dict]:
        """Derive the T2 live-re-drive request-spec (``base_url`` / ``endpoint_path`` / ``param`` /
        ``payload`` / ``nonce_param``) for an ``error_based_sqli`` ``exploit_succeeded`` candidate, from the
        candidate's TOOL ARGS (the target the tool call named) + the LLM's ``output_analysis`` (its proposed
        insertion point + payload — the "where to look", which the LLM is allowed to propose). Returns None
        unless it is an error_based_sqli exploit claim with a COMPLETE, reconstructable spec (fail-closed →
        the seam stays LEAD-only).

        The LLM's claimed ``oracle_context`` (the response bytes) is NEVER read for the fact — only the
        request-side "where to look" is sourced from the model here; the FACT is decided by the re-driven
        wire bytes. The gated re-drive re-enforces charter scope, so an out-of-scope proposed target is
        refused there (never a fact) — this derivation is proposal-triage only, not an authority."""
        tool = getattr(decision, "tool", None)
        analysis = getattr(decision, "output_analysis", None)
        if tool is None or analysis is None:
            return None
        if getattr(analysis, "exploit_succeeded", None) is not True:
            return None
        info = getattr(analysis, "extracted_info", None)
        if not isinstance(info, dict):
            return None
        octx = info.get("oracle_context") if isinstance(info.get("oracle_context"), dict) else {}
        # CLASS GATE (cheap; the seam re-normalizes authoritatively): only error_based_sqli re-drives.
        bug_class = str(info.get("bug_class") or octx.get("bug_class") or "")
        if bug_class.strip().lower().replace("-", "_").replace(" ", "_") != "error_based_sqli":
            return None
        target = extract_target(getattr(tool, "tool_args", None))   # the ONE shared tool-args target reader
        if not target:
            return None
        sp = urlsplit(target if "://" in target else "http://" + target)
        if not sp.hostname:
            return None
        base_url = f"{(sp.scheme or 'http')}://{sp.netloc}"
        endpoint_path = sp.path or "/"
        param = str(info.get("insertion_point") or octx.get("payload_param") or "").strip()
        payload = str(info.get("request_payload") or info.get("payload")
                      or octx.get("request_payload") or "").strip()
        nonce_param = str(info.get("nonce_param") or "rc").strip() or "rc"
        if not (param and payload):
            return None
        return {"base_url": base_url, "endpoint_path": endpoint_path, "param": param,
                "payload": payload, "nonce_param": nonce_param, "bug_class": "error_based_sqli"}

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

    def _deploy_fireteam(self, decision: LLMDecision, state: AgentState, seq: int, report: RunReport) -> None:
        """Run an APPROVED fireteam wave (reached ONLY after a signed operator approval satisfied the queued
        deploy edge). Folds the wave's oracle-confirmed FACTS + LEADS into the run and surfaces member
        escalations as queued edges. Fail-closed + total: no seam / a seam error / a refused (malformed /
        over-cap / mutex) plan spawns nothing and adds no fact. The wave's members are each independently
        capped (≤A2, never A3) + gated + oracle-checked — this NEVER bypasses the parent gate or the
        oracle: a wave 'fact' is admitted here ONLY if it carries a signed evidence ref, else it degrades
        to a lead (the same 'a FACT needs a signed evidence ref' invariant AgentState enforces)."""
        if self.seams.deploy_fireteam is None:
            report.denied_edges.append("fireteam deploy approved but no fireteam seam is wired (fail-closed)")
            return
        try:
            outcome = self.seams.deploy_fireteam(decision, state, seq)
        except Exception as exc:  # noqa: BLE001 — a wave error is a recorded refusal, never a crash
            report.denied_edges.append(f"fireteam wave error (fail-closed): {type(exc).__name__}")
            return
        if outcome is None or getattr(outcome, "refused", False):
            report.queued_edges.append(
                "fireteam plan refused (malformed / over-cap / mutex) — nothing spawned")
            return
        for f in getattr(outcome, "facts", []) or []:
            ref = str(getattr(f, "evidence_ref", "") or "").strip()
            if ref:
                state.record_fact(f, evidence_ref=ref)   # already oracle-confirmed by fireteam.collect
                report.facts.append(f)
            else:                                          # fail-closed: no signed ref ⇒ a LEAD, never a fact
                state.record_lead(f)
                report.leads.append(f)
        for ld in getattr(outcome, "leads", []) or []:
            state.record_lead(ld)
            report.leads.append(ld)
        self._project([f for f in getattr(outcome, "facts", []) or []
                       if str(getattr(f, "evidence_ref", "") or "").strip()])
        for esc in getattr(outcome, "escalations", []) or []:
            report.queued_edges.append(f"fireteam escalation (queued, never auto-run): "
                                       f"{getattr(esc, 'reason', '') or getattr(esc, 'tool_name', '')}")
            # G1 (Tier A): also record the STRUCTURED escalation so the operator can review exactly what is
            # pending (the binding key + tool/target/tier/reason) on the run report. This is genuinely TOTAL:
            # the whole row build is guarded, so a malformed escalation contributes nothing rather than
            # propagating out of engage() (which must never raise). `target`/`reason` are the only free-text
            # here, so they are SCRUBBED at source (the F3 value-redactor) — the row is secret-safe by
            # construction, so a later tier / UI that surfaces it cannot leak a credential in a target URL.
            try:
                from ..tools.governance import redact_tool_args
                _safe = redact_tool_args({"target": str(getattr(esc, "target", "") or ""),
                                          "reason": str(getattr(esc, "reason", "") or "")})
                report.fireteam_escalations.append({
                    "wave_id": str(getattr(esc, "wave_id", "") or ""),
                    "member_id": str(getattr(esc, "member_id", "") or ""),
                    "seq": int(getattr(esc, "seq", 0) or 0),
                    "tool": str(getattr(esc, "tool_name", "") or ""),
                    "target": str(_safe.get("target", "")),
                    "requested_tier": str(getattr(esc, "requested_tier", "") or ""),
                    "reason": str(_safe.get("reason", "")),
                    "status": "queued",   # queued for a signed operator approval; never auto-run (Tier B/C = sign/run)
                })
            except Exception:  # noqa: BLE001 — a malformed row is dropped; engage() never raises over telemetry
                pass
        for ref in getattr(outcome, "spine_refs", []) or []:
            report.checkpoints.append(str(ref))

    @staticmethod
    def _apply_escalation(decision: LLMDecision, state: AgentState) -> None:
        """Apply an APPROVED escalation (only reached after a valid signed operator approval)."""
        if decision.action == ActionType.TRANSITION_PHASE and decision.target_phase is not None:
            state.phase = decision.target_phase
            state.awaiting_approval = False

    def _surface_body_facts(self, exec_res: Any, state: AgentState, report: RunReport,
                            *, parent_id: Optional[int] = None) -> tuple[int, int]:
        """H8f-b — surface a body-routed execution's runner-minted results into the run report, honestly.

        The runner already ran the deterministic oracle over VIGIL's OWN gated re-drive and signed a
        certificate (``admit()`` + ``certify_admitted``); this does NOT re-adjudicate any tool bytes. Each
        carried ``AdapterResult`` is admitted as a FACT ONLY if it is a signed fact with a non-empty evidence
        ref — the SAME 'a FACT needs a signed evidence ref' invariant the fireteam path (and ``AgentState``)
        enforce; anything else degrades to a LEAD (fail-closed). Returns (n_facts, n_leads) surfaced.

        The evidence ref is the certificate's ``finding_ref`` — identical to how the engine's own intake facts
        are referenced (``oracle`` seam → ``_admit_and_mint`` returns ``finding_ref``); the fact is mirrored to
        the spine as a finding event, so a body FACT is as durable + provenance-linked as any other."""
        tool = str(getattr(exec_res, "tool", "") or "")
        n_facts = 0
        n_leads = 0
        for af in list(getattr(exec_res, "body_facts", ()) or ()):
            ref = str(getattr(af, "finding_ref", "") or "").strip()
            bug_class = str(getattr(af, "bug_class", "") or "")
            is_fact = bool(getattr(af, "is_fact", False)) and str(getattr(af, "status", "")) == "fact"
            signed = getattr(af, "signed", None)
            if is_fact and signed is not None and ref:
                title = f"{bug_class or tool} confirmed (runner re-drive)"
                f = Finding(ref=ref, bug_class=bug_class, title=title, severity="", status="fact",
                            evidence_ref=ref, source=tool)
                state.record_fact(f, evidence_ref=ref)     # already oracle-confirmed + signed by the runner
                report.facts.append(f)
                self._spine_post("finding", {
                    "ref": ref, "title": title, "bug_class": bug_class, "surface": tool,
                    "summary": title, "status": "fact", "verified_by_oracle": True}, parent_id=parent_id)
                self._project([f])
                n_facts += 1
            else:
                # fail-closed: a body result without a signed evidence ref is a LEAD, never a report FACT.
                ld = Finding(ref=ref or (tool or "body-lead"), bug_class=bug_class,
                             title=(bug_class or tool or "body lead"), status="lead", source=tool)
                state.record_lead(ld)
                report.leads.append(ld)
                n_leads += 1
        # The runner's OWN leads (a reachable-but-unconfirmed probe, a non-FACT-capable proposal) are recorded
        # as report leads too, so a body run that found only leads is not silently empty (never a fact — a lead
        # by construction, mirroring record_lead which strips any status/evidence_ref).
        for al in list(getattr(exec_res, "body_leads", ()) or ()):
            ld = Finding(ref=str(getattr(al, "finding_ref", "") or "").strip() or (tool or "body-lead"),
                         bug_class=str(getattr(al, "bug_class", "") or ""),
                         title=(str(getattr(al, "bug_class", "") or "") or tool or "body lead"),
                         status="lead", source=tool)
            state.record_lead(ld)
            report.leads.append(ld)
            n_leads += 1
        return n_facts, n_leads

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

    def _persist_spine(self) -> None:
        """T3 — best-effort, END-OF-RUN persist of the blackboard chain (see :data:`PersistSpineFn`). Total:
        no seam, or ANY seam error, is a silent no-op — a persistence failure is never fatal to a run whose
        truth is already sealed in the signed spine + attestation ledger."""
        if self.seams.persist_spine is None:
            return
        try:
            self.seams.persist_spine()
        except Exception:  # noqa: BLE001 — a persist error is a recorded no-op, never a crash
            return

    def _spine_post(self, kind: str, payload: dict, *, parent_id: Optional[int] = None) -> Optional[int]:
        """T3b — best-effort mirror of ONE OODA hook point onto the blackboard event spine (see
        :data:`SpinePostFn`). Total + emit-only: no seam, any seam error, or a non-int return yields None and
        NEVER raises into the loop, so mirroring can never perturb the run's truth. The returned id (when the
        seam gives one) lets the caller thread provenance edges (tool_call→tool_result, finding←tool_result)."""
        if self.seams.spine_post is None:
            return None
        try:
            rid = self.seams.spine_post(kind, payload, parent_id=parent_id)
        except TypeError:
            # a seam that predates the parent_id kwarg (a test fake / older seam) — call it positionally.
            try:
                rid = self.seams.spine_post(kind, payload)
            except Exception:  # noqa: BLE001 — a spine write is emit-only; never fatal to the run
                return None
        except Exception:  # noqa: BLE001 — a spine write is emit-only; never fatal to the run
            return None
        return rid if isinstance(rid, int) else None

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
