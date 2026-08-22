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

# brain tool name -> the runner-owned oracle-mapped ToolSpec builder. ONLY these can mint a FACT (via the
# runner's own independent re-drive); every other tool stays a LEAD. Adding a tool = adding a ToolSpec +
# a runner-owned per-class oracle re-drive — never a body-supplied provenance.
#   nmap    -> service_reachable        (gated handshake re-drive)
#   sslscan -> weak_tls + weak_crypto_artifact (gated TLS handshake re-drive; slice 4)
_ORACLE_MAPPED_TOOLS = frozenset({"nmap", "sslscan"})
# a provenance/context/authorization key must NEVER originate from the body/brain (red-pen HIGH-3 guard).
_FORBIDDEN_EXEC_KEYS = frozenset({"provenance", "oracle_context", "_authorized", "authorized"})


@dataclass
class RunnerDeps:
    """The gated-runner dependencies the body needs to actually execute a tool through R4."""
    scope_gate: Any                       # vigil_gateway/live ScopeGate (charter scope ∧ egress denylist)
    backend: Any                          # LocalSubprocessBackend | DockerTopologyBackend
    engagement_slug: str
    signers: list                         # [(key_id, private_key_b64)] — m-of-n governance signers
    timeout: float = 60.0


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
        provenance + signing. A tool with no oracle-mapped ToolSpec, or an unprovisioned runner, stays a
        LEAD (honest — never a fabricated fact)."""
        if action.kind not in _ORACLE_MAPPED_TOOLS:
            return ActionOutcome(executed=False, ok=False,
                                 blocked_reason=f"{action.kind!r} has no oracle-mapped ToolSpec — stays a LEAD")
        if self._runner is None:
            return ActionOutcome(executed=False, ok=False,
                                 blocked_reason="runner not provisioned (no RunnerDeps) — stays a LEAD")
        from ..live.external_tool import nmap_service_scan, run_external_tool, tls_scan  # noqa: PLC0415 (FATAL-2)

        params = action.params or {}
        if action.kind == "sslscan":
            spec = tls_scan(port=int(params.get("port", 443)))
        else:  # nmap (the only other oracle-mapped tool)
            spec = nmap_service_scan(ports=str(params.get("ports", "1-1024")))
        res = run_external_tool(
            spec, action.target, scope_gate=self._runner.scope_gate, backend=self._runner.backend,
            engagement_slug=self._runner.engagement_slug, signers=self._runner.signers,
            timeout=self._runner.timeout,
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
