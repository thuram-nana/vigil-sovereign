"""hexstrike_body — a FULLY-WIRED, pluggable VIGIL agent body driven by the drift-free hexstrike brain.

`HexstrikeAgentBody` implements the `agent_body.AgentBody` contract (think -> propose -> gate -> execute
-> learn) and inherits `run_cycle`'s STRUCTURAL guarantee that `execute` is unreachable unless the gate
authorized the action. It turns the propose-only `HexstrikeBrain` into a gated actor with NO relaxed
invariant, wired end-to-end to the real gate + the R4 gated external-tool runner + the oracle.

H1 — THE CANONICAL BODY. This is now the PRODUCTION proposal source, not a parallel scaffold: the
`vigil engage --brain hexstrike` path drives the live engine through `engine_think.BrainThink`, a thin
think-seam adapter that delegates its profile+chain construction to this body's `plan` (see
`docs/BRAIN-SLOT-INTEGRATION.md` step 6). The profile-from-observations + ordered-chain logic lives in ONE
place — here — instead of being re-implemented at the engine seam. (Residual: this body's OWN
gate/execute/learn + runner-owned oracle re-drive remain a second, tested execution model; production
execution still flows through the live engine's governed executor + signed ExecRecord. Converging the two
EXECUTE paths onto a single gated executor is the remaining H1 work — this slice converges the PROPOSE
half.) The contract:

  * think    — build a TargetProfile from VIGIL OBSERVATIONS (sensor/oracle context), not URL guesses;
               resolve the scannable host from the charter-provided IPs/target. No network.
  * propose  — emit the next brain-proposed step as a ProposedAction (a LEAD; carries no authorized flag).
  * gate     — the WARDEN tier gate (default) or an injected gate-of-record. A2 FLOOR: on a live target
               NOTHING auto-fires — every tool QUEUEs for owner approval (authorized=False); a RECON tool
               is auto-eligible ONLY in a staging/twin posture (red-pen MEDIUM). Fail-closed: any raise =
               DENY. (Scope + egress are additionally enforced inside the runner at execute time.)
  * execute  — run an authorized action ONLY through `run_external_tool` (the R4 runner): ScopeGate
               (charter scope ∧ gateway egress denylist) -> gated backend -> an INDEPENDENT oracle re-drive
               that the RUNNER owns. The body supplies NO `provenance`/`oracle_context` — a scanner's
               say-so can never mint a FACT (red-pen HIGH-3). A tool with no oracle-mapped ToolSpec stays a
               LEAD.
  * learn    — re-rank/defer ONLY: record the outcome. Never mint a fact, promote a lead, grant a tier, or
               widen scope.

FATAL-2: only the lightweight `agent_body.interface` (ABC + dataclasses, no offense engine) is imported at
module scope; `run_external_tool` + its ToolSpec/backends are imported FUNCTION-LOCALLY, so importing this
module co-loads no scanner/agents/oracle engine.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Optional
from urllib.parse import urlsplit

from framework.v2.agent_body.interface import (
    ActionOutcome,
    AgentBody,
    GateDecision,
    Observation,
    ProposedAction,
    Thought,
)

from .hexstrike_brain import (
    AttackStep,
    HexstrikeBrain,
    TargetProfile,
    TargetType,
    ToolDanger,
    parse_objective,
)
# H7: FACT-capability is a property of the tool's SHARED ORACLE FAMILY, not a per-tool flat set. The family
# registry is pure stdlib (no framework import), so importing it at module scope is FATAL-2 safe.
from ..live.oracle_families import ToolObservation, family_for, fuse, oracle_mapped_tools

# brain tool name -> the runner-owned oracle-mapped ToolSpec builder. ONLY these can mint a FACT (via the
# runner's own independent re-drive); every other tool stays a LEAD. Adding a tool = adding a ToolSpec +
# a runner-owned per-class oracle re-drive — never a body-supplied provenance.
#   nmap / masscan / rustscan / naabu -> service_reachable  (the SAME gated TCP-handshake re-drive; H5)
#   sslscan                           -> weak_tls + weak_crypto_artifact (gated TLS handshake re-drive; slice 4)
# The three extra port scanners are the H5 SERVICE_REACHABILITY reuse: they carry NO redrives on their
# ToolSpec, so the runner re-proves every proposed port with its own gated handshake exactly as it does for
# nmap — a port scanner's row is only a PROPOSAL, and only VIGIL's independent handshake mints the FACT.
# The tools with a runner-owned ToolSpec builder in ``_spec_for_kind`` below — the ONLY tools whose FACT can
# be minted by VIGIL's own gated re-drive. Kept in lock-step with ``_spec_for_kind`` by
# ``test_oracle_mapped_tools_all_have_a_spec_builder_no_drift``.
_SPEC_BUILDER_TOOLS = frozenset({"nmap", "sslscan", "masscan", "rustscan", "naabu"})
# H7 — FACT-capability is derived from the SHARED ORACLE FAMILY, not hand-listed per tool: a spec-builder
# tool mints only if its family owns a re-drive that crosses ``verdict.admit()`` (network-discovery →
# SERVICE_REACHABILITY for the four port scanners; tls → TLS_WEAKNESS for sslscan). Adding a member to a
# FACT-capable family that also gains a spec builder makes it FACT-capable automatically — no edit here.
_ORACLE_MAPPED_TOOLS = oracle_mapped_tools(_SPEC_BUILDER_TOOLS)
# a provenance/context/authorization key must NEVER originate from the body/brain (red-pen HIGH-3 guard).
_FORBIDDEN_EXEC_KEYS = frozenset({"provenance", "oracle_context", "_authorized", "authorized"})


def _spec_for_kind(kind: str, params: "dict | None"):
    """Map an oracle-mapped brain tool name + its typed params to the runner-owned ToolSpec that mints its
    FACT. Returns ``None`` for a name this builder does not handle (kept in lock-step with
    ``_ORACLE_MAPPED_TOOLS`` by ``test_oracle_mapped_tools_all_have_a_spec_builder``). Only the typed
    ``ports``/``port`` VALUES are read — every flag is constructed server-side inside the ToolSpec, and an
    invalid ports value raises ``ValueError`` from the ToolSpec's strict schema (the caller keeps it a LEAD).

    FATAL-2: the offense-side ``external_tool`` import is function-local, so importing this module co-loads no
    offense engine into the sovereign env."""
    from ..live.external_tool import (  # noqa: PLC0415
        masscan_service_scan,
        naabu_service_scan,
        nmap_service_scan,
        rustscan_service_scan,
        tls_scan,
    )
    p = params or {}
    if kind == "sslscan":
        return tls_scan(port=int(p.get("port", 443)))
    if kind == "nmap":
        return nmap_service_scan(ports=str(p.get("ports", "1-1024")))
    if kind == "masscan":
        return masscan_service_scan(ports=str(p.get("ports", "1-1024")), rate=int(p.get("rate", 1000)))
    if kind == "rustscan":
        return rustscan_service_scan(ports=str(p.get("ports", "1-1024")))
    if kind == "naabu":
        return naabu_service_scan(ports=str(p.get("ports", "1-1024")))
    return None


@dataclass
class RunnerDeps:
    """The gated-runner dependencies the body needs to actually execute a tool through R4."""
    scope_gate: Any                       # vigil_gateway/live ScopeGate (charter scope ∧ egress denylist)
    backend: Any                          # LocalSubprocessBackend | DockerTopologyBackend
    engagement_slug: str
    signers: list                         # [(key_id, private_key_b64)] — m-of-n governance signers
    timeout: float = 60.0
    # H8f GATE PARITY (closes the H1x-1 red-pen prerequisite). A provisioned runner is a LIVE egress path,
    # so — unlike the runner-less planning body — it MUST re-enforce the executor's execution-time single-use
    # authorization. run_external_tool already re-checks scope + loopback + pre-flight (kill-switch / charter
    # slug / entitlement) + backend isolation UNCONDITIONALLY; the ONE control it applies only when threaded
    # is the single-use, action-bound CAPABILITY TOKEN (W13-5). This carries it (a
    # ``live.external_tool.CapabilityCheck``); ``_run_via_external_tool`` refuses BEFORE traffic if a runner
    # is provisioned without one, so a body-routed tool can never emit a packet on an unspent authorization.
    # Typed ``Any`` (not the offense-side CapabilityCheck) so this dataclass stays FATAL-2-safe at module scope.
    capability: Any = None


class HexstrikeAgentBody(AgentBody):
    def __init__(
        self,
        *,
        brain: Optional[HexstrikeBrain] = None,
        objective: str = "comprehensive",
        posture: str = "live",            # "live" (A2 floor: everything queues) | "staging"/"twin" (recon auto)
        runner: Optional[RunnerDeps] = None,
        gate_fn: Optional[Callable[[ProposedAction], GateDecision]] = None,
        executor: Optional[Callable[[ProposedAction, GateDecision], ActionOutcome]] = None,
    ) -> None:
        self._brain = brain or HexstrikeBrain()
        # Normalise ONCE, here: an unknown objective raises at construction rather than silently planning
        # something other than its label (parse_objective is stdlib — no framework/offense dependency). This
        # is the same guarantee the engine_think adapter used to own alone; carrying it into the canonical
        # body keeps the plan's label equal to the plan it built for EVERY caller of this one implementation.
        self._objective = parse_objective(objective).value
        self._posture = posture
        self._runner = runner
        self._gate_fn = gate_fn or self._warden_gate
        self._executor = executor
        self._profile = None
        self._host = ""
        self._queue: list = []
        self.history: list[dict] = []

    # ---- think -----------------------------------------------------------------------------------
    def think(self, observation: Observation) -> Thought:
        st = dict(observation.state or {})
        tt = st.get("target_type")
        self._profile = self._brain.analyze_target(
            st.get("target", ""),
            target_type=TargetType(tt) if tt else None,
            ip_addresses=st.get("ip_addresses"), open_ports=st.get("open_ports"),
            services=st.get("services"), technologies=st.get("technologies") or [],
            cms_type=st.get("cms_type"), cloud_provider=st.get("cloud_provider"),
        )
        # the scannable host for the runner: a charter-provided IP, else the target's hostname, else target.
        ips = self._profile.ip_addresses
        self._host = ips[0] if ips else (urlsplit(self._profile.target).hostname or self._profile.target)
        return Thought(intent="propose a gated recon/assessment chain",
                       detail={"target": self._profile.target, "host": self._host,
                               "risk": self._profile.risk_level})

    # ---- plan (the ONE canonical brain-driving step) ---------------------------------------------
    def _build_chain(self) -> list[AttackStep]:
        """The single place the ordered attack chain is built from the current profile (a list of LEADs).
        Both this body's own ``propose`` loop and the ``engine_think.BrainThink`` think-seam adapter that
        drives the production live engine consume it — so ONE implementation decides what the brain
        proposes and in what order (H1 convergence)."""
        if self._profile is None:
            return []
        return list(self._brain.create_attack_chain(self._profile, self._objective).steps)

    def plan(self, observation: Observation) -> tuple[TargetProfile, list[AttackStep]]:
        """Build the ``TargetProfile`` from the normalized VIGIL Observation and the ordered ``AttackStep``
        chain, and return both (steps carry NO authority — each is a LEAD the gate/oracle later adjudicate).

        This is the production entry point that makes ``HexstrikeAgentBody`` the canonical body: the
        ``vigil engage --brain hexstrike`` path drives the live engine through ``engine_think.BrainThink``,
        which now delegates its profile+chain construction here rather than re-implementing it. The chain is
        also cached into this body's ``propose`` queue, so a subsequent ``run_cycle`` reuses the exact plan."""
        self.think(observation)                 # sets self._profile / self._host (no network)
        self._queue = self._build_chain()
        return self._profile, list(self._queue)

    # ---- family votes (H7: agreement raises PRIORITY, never mints) -------------------------------
    def family_votes(self) -> list:
        """The current chain's tools fused BY SHARED ORACLE FAMILY into per-family LEADs, with priority
        raised on agreement. When several proposed tools belong to the SAME family against this host — the
        four network-discovery port scanners, say — their agreement is a stronger reason to LOOK, so the
        family's LEAD is prioritised. It is NEVER a fact: every returned ``FamilyVote`` is a LEAD by
        construction (``oracle_families.fuse``), no matter how many tools agree or whether the family is
        FACT-capable. Minting stays the runner-owned re-drive's job alone.

        Keyed on this host, so tools in one family voting about the same target fuse into one lead; a tool in
        no discovery family (an excluded offense binary the brain proposed) simply does not vote."""
        chain = self._queue or self._build_chain()
        host = self._host or (self._profile.target if self._profile is not None else "")
        obs = [ToolObservation(tool=s.tool, observation_key=host, base_priority=int(s.priority))
               for s in chain if family_for(s.tool) is not None]
        return fuse(obs)

    # ---- propose (one step per cycle; a LEAD) ----------------------------------------------------
    def propose(self, thought: Thought) -> Optional[ProposedAction]:
        if not self._queue and self._profile is not None:
            self._queue = self._build_chain()
        if not self._queue:
            return None
        step = self._queue.pop(0)
        return ProposedAction(kind=step.tool, target=self._host,
                              params={**dict(step.params), "danger": step.danger.value})

    # ---- gate (WARDEN tier; A2 floor on live; fail-closed) --------------------------------------
    def gate(self, action: ProposedAction) -> GateDecision:
        try:
            decision = self._gate_fn(action)
        except Exception as e:  # noqa: BLE001 — any gate error is a DENY (fail-closed)
            return GateDecision(authorized=False, reason=f"gate error (fail-closed): {e}")
        return decision if isinstance(decision, GateDecision) else \
            GateDecision(authorized=False, reason="gate returned a non-decision (fail-closed)")

    def _warden_gate(self, action: ProposedAction) -> GateDecision:
        danger = (action.params or {}).get("danger")
        if self._posture in ("staging", "twin") and danger == ToolDanger.RECON.value:
            return GateDecision(authorized=True, reason=f"recon tool auto-eligible in {self._posture} posture")
        # A2 floor on a live target: nothing auto-fires — queue for a signed owner approval.
        return GateDecision(authorized=False,
                            reason=f"{danger or 'tool'} queued for owner approval (A2 floor, posture={self._posture})")

    # ---- execute (only via the gated runner; body supplies NO provenance) -----------------------
    def execute(self, action: ProposedAction, decision: GateDecision) -> ActionOutcome:
        leaked = _FORBIDDEN_EXEC_KEYS & set(action.params or {})
        if leaked:
            return ActionOutcome(executed=False, ok=False,
                                 blocked_reason=f"refused: body-supplied forbidden key(s) {sorted(leaked)}")
        if self._executor is not None:
            return self._executor(action, decision)
        return self._run_via_external_tool(action, decision)

    def _run_via_external_tool(self, action: ProposedAction, decision: GateDecision) -> ActionOutcome:
        """Real executor: run ONLY through the R4 gated runner, which owns the per-bug-class re-drive +
        provenance + signing. A tool with no oracle-mapped ToolSpec, an unprovisioned runner, or a runner
        provisioned WITHOUT a single-use capability token (H8f gate parity), stays a LEAD (honest — never a
        fabricated fact, never a packet on an unspent authorization)."""
        if action.kind not in _ORACLE_MAPPED_TOOLS:
            return ActionOutcome(executed=False, ok=False,
                                 blocked_reason=f"{action.kind!r} has no oracle-mapped ToolSpec — stays a LEAD")
        if self._runner is None:
            return ActionOutcome(executed=False, ok=False,
                                 blocked_reason="runner not provisioned (no RunnerDeps) — stays a LEAD")
        # function-local (FATAL-2): building the spec co-loads no offense engine into the sovereign env.
        from ..live.external_tool import run_external_tool  # noqa: PLC0415

        params = action.params or {}
        # SERVER-SIDE spec construction: only the typed `ports`/`port` VALUES are read from params; every
        # flag is built inside the ToolSpec (no model/brain-supplied flags reach the tool). An invalid
        # server-side ports value fails the ToolSpec's STRICT schema → the body keeps it a LEAD (fail-closed),
        # never an un-validated argv.
        try:
            spec = _spec_for_kind(action.kind, params)
        except ValueError as e:
            return ActionOutcome(executed=False, ok=False,
                                 blocked_reason=f"{action.kind!r} params rejected by the ToolSpec schema — "
                                                f"stays a LEAD: {e}")
        if spec is None:
            # _ORACLE_MAPPED_TOOLS and _spec_for_kind agreed on membership above; a None here would be an
            # internal drift, so refuse to run (fail-closed) rather than fabricate.
            return ActionOutcome(executed=False, ok=False,
                                 blocked_reason=f"{action.kind!r} is oracle-mapped but has no spec builder "
                                                f"(internal) — stays a LEAD")
        # H8f GATE PARITY (H1x-1 red-pen prerequisite): reaching here means real traffic is about to flow, so
        # the body must re-enforce the executor's single-use, action-bound authorization. run_external_tool
        # re-checks scope + loopback + pre-flight + isolation for free; the capability token is the one control
        # it applies only when threaded. A provisioned runner with no capability would emit a packet on an
        # unspent authorization — refuse it BEFORE traffic (a LEAD), never diverge from the executor path. When
        # present, run_external_tool binds the token to the EXACT argv (operation_hash), burns its O_EXCL nonce,
        # and refuses a stale/replayed/different-operation token before the subprocess runs.
        if self._runner.capability is None:
            return ActionOutcome(executed=False, ok=False,
                                 blocked_reason="runner provisioned without a single-use capability token — "
                                                "refused before traffic (H8f gate parity)")
        res = run_external_tool(
            spec, action.target, scope_gate=self._runner.scope_gate, backend=self._runner.backend,
            engagement_slug=self._runner.engagement_slug, signers=self._runner.signers,
            timeout=self._runner.timeout, capability=self._runner.capability,
        )
        if getattr(res, "refused", False):
            return ActionOutcome(executed=False, ok=False,
                                 blocked_reason=f"runner refused (pre-traffic): {getattr(res, 'reason', '')}")
        facts = list(getattr(res, "facts", []) or [])
        leads = list(getattr(res, "leads", []) or [])
        return ActionOutcome(executed=True, ok=bool(facts),
                             detail={"n_facts": len(facts), "n_leads": len(leads),
                                     "reason": getattr(res, "reason", ""), "tool": action.kind})

    # ---- learn (re-rank/defer ONLY) ------------------------------------------------------------
    def learn(self, outcome: ActionOutcome) -> None:
        self.history.append({"executed": bool(outcome.executed), "ok": bool(outcome.ok),
                             "blocked_reason": outcome.blocked_reason, "detail": dict(outcome.detail or {})})
