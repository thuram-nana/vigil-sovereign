"""engine_think — a THIN think-seam adapter that drives the production live engine with the ONE canonical
hexstrike agent body.

`BrainThink` is a `ThinkFn` (`Callable[[AgentState], LLMDecision]`) that adapts the pluggable
`HexstrikeAgentBody` (``brains.hexstrike_body``) — the single canonical body — to the live engine's
``think`` seam. It hands the body a normalized ``Observation`` and asks it to ``plan``: the body builds the
``TargetProfile`` and the ordered attack chain. BrainThink then emits ONE `USE_TOOL` LLMDecision per
proposed step (a non-authoritative proposal) and `COMPLETE` when every step of the current plan is emitted.

H9 — BOUNDED ADAPTIVE RE-PLANNING. BrainThink no longer builds its chain once and only advances an index.
On EVERY cycle it folds the current ``AgentState`` into a deterministic, propose-only
``planner_memory.PlannerMemory`` (tool-effectiveness statistics, failed-path memory, discovered
surfaces/technology profile, oracle-confirmed relationships), and RE-PLANS when a new observation has
materially changed that world — the profile is rebuilt from the augmented observations, a failed path is
deprioritized, and a tool already emitted is never re-proposed. When no new observation has arrived the world
digest is unchanged and the plan is NOT rebuilt, so a static run is byte-identical to the build-once
behaviour. Two load-bearing honesty properties hold: re-planning changes only WHAT is proposed and mints
ZERO facts (the brain carries no LLM claim, so the fact-minting seam is never fed — FP-0 stays green); and
**unverified model prose never enters durable knowledge as a FACT** — the memory's admission gate records a
lead/prose observation as a plan PRIOR (LEAD/ADVISORY), never as a FACT, exactly as the oracle-is-sole-
authority contract requires.

H1 CONVERGENCE. BrainThink no longer re-implements the profile+chain construction — that logic lives in
ONE place, ``HexstrikeAgentBody.plan``. This makes the body the PRODUCTION proposal source (it had zero
production callers before) while BrainThink keeps only the three responsibilities that belong to the
engine seam: (1) objective normalization at construction (fail-closed on an unknown label); (2)
``danger_floor`` — the raise-only classifier the engine's gate consults; and (3) proposal PERSISTENCE for
the console panel. The engine's gate + governed executor + oracle + signed ExecRecord + approval broker are
UNCHANGED — the brain proposes, the conjunctive gate authorizes (offense tools QUEUE for owner approval),
and the oracle confirms. Nothing self-authorizes; a proposal is a LEAD until the oracle fires.

Import-clean (FATAL-2): module scope imports only `agent.state` (pydantic models, no framework/strix) +
the stdlib brain, so importing this module pulls no offense engine and it loads in the sovereign leg. The
canonical body — which imports the lightweight ``framework.v2.agent_body.interface`` — is imported
FUNCTION-LOCALLY (only when a run actually drives the seam, which happens only in the offense leg where
framework is on the path). Constructing a BrainThink, reading ``danger_floor`` and the normalized objective
therefore need no framework.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Optional

from ..agent.state import ActionType, LLMDecision, ToolCall
from .hexstrike_brain import HexstrikeBrain, parse_objective, proposal_document
from .planner_memory import PlannerMemory


class BrainThink:
    """A stateful think seam. `target` is the engagement's scannable target (the caller wires it per
    engagement, since AgentState carries no seed field); `observations` optionally seeds the profile with
    charter/sensor facts (ip_addresses/open_ports/services/technologies/cms_type/cloud_provider).

    PROPOSAL PERSISTENCE (makes the console's Brain-decision panel REAL): when a run directory is
    configured — the explicit ``proposal_out`` arg, else the ``VIGIL_PROOF_RUN_DIR`` env the console sets
    for a spawned run — the ordered chain the brain proposes is written ONCE, at chain-build time, to
    ``<run_dir>/brain-proposal.json``. That is the exact file ``api.brain_decision`` reads, so a real
    ``vigil engage --brain hexstrike`` run now surfaces its chain in the panel instead of the panel reading
    a file nothing writes. Persistence is OPT-IN and fail-soft: no run dir ⇒ nothing is written (a plain
    ``vigil engage --brain hexstrike`` is byte-identical to before), and a write error never sinks the
    engine. What is persisted is EXACTLY the chain the engine drives — never a re-run or a fabrication."""

    def __init__(self, brain: Optional[HexstrikeBrain] = None, *, target: str = "",
                 objective: "str | None" = None, observations: Optional[dict[str, Any]] = None,
                 posture: str = "live", proposal_out: "str | os.PathLike | None" = None) -> None:
        self._brain = brain or HexstrikeBrain()
        self._target = target
        # Normalise ONCE, here: an unknown objective raises at construction rather than silently planning
        # something other than its label, and the persisted proposal records the objective actually used.
        # (parse_objective is stdlib — this keeps construction framework-free for the sovereign leg.)
        self._objective = parse_objective(objective).value
        self._obs = dict(observations or {})
        self._posture = posture
        # OPT-IN persistence: explicit arg wins; else the run dir the console already hands a spawned run.
        _out = proposal_out if proposal_out is not None else os.environ.get("VIGIL_PROOF_RUN_DIR")
        self._proposal_out: "str | None" = str(_out) if _out else None
        # The ONE canonical body this seam adapts — constructed LAZILY on first drive (it imports the
        # framework agent-body interface, available only in the offense leg; construction, danger_floor and
        # the normalized objective must stay framework-free for the sovereign leg).
        self._body: Optional[Any] = None
        # H9 — the deterministic, propose-only planner memory (stdlib-only ⇒ safe at module scope, sovereign
        # leg included). It accretes observations across cycles and drives re-planning; it mints nothing.
        self._memory = PlannerMemory()
        # The CURRENT plan (full ordered chain for the current world) + the world digest it was built at, the
        # set of tools already emitted as a USE_TOOL proposal, and the last profile the body returned.
        self._plan: Optional[list] = None
        self._planned_digest: Optional[str] = None
        self._emitted: set[str] = set()
        self._profile: Optional[Any] = None
        self._replan_count = 0
        # Capability annotations are STATIC for a run (which tools are executable does not change mid-run), so
        # they are probed at most once and reused across re-plans — a re-plan must not re-probe the host.
        self._capabilities: Optional[dict] = None
        self._capabilities_probed = False

    def danger_floor(self, base_classify):
        """Wrap the offense classifier so the PLANNER's danger class can only RAISE a tool's tier.

        H1 — the divergence this closes. The brain classifies every tool it may propose as RECON or ACTIVE,
        but that judgement was dropped at the engine seam: the tier is re-derived from the executor's own
        ``default_classify``, whose curated ``_RECON`` set contains ``nuclei`` — a tool the brain calls
        ACTIVE, and which sends attack templates rather than merely observing. So a brain-proposed ACTIVE
        step could classify A1 and become auto-eligible. Two VIGIL-owned tables disagreed and the weaker
        one won.

        RAISE-ONLY, and only on the brain path. An ACTIVE tool never lands below A2; a RECON tool is
        untouched; a name the brain does not know is untouched; and a tier the base classifier already put
        ABOVE A2 (a danger-token A3) is never lowered. Non-brain runs keep ``default_classify`` exactly as
        it was, so this changes no behaviour outside a ``--brain`` engagement.
        """
        from .hexstrike_brain import ToolDanger, _TOOL_DANGER

        order = {"A0": 0, "A1": 1, "A2": 2, "A3": 3}

        def _classify(tool_name: str) -> str:
            base = base_classify(tool_name)
            if _TOOL_DANGER.get(str(tool_name).strip()) is not ToolDanger.ACTIVE:
                return base
            # never lower: take the stricter of the base tier and the ACTIVE floor
            return base if order.get(base, 0) >= order["A2"] else "A2"

        return _classify

    def _ensure_body(self):
        """Construct the ONE canonical body lazily. Import is FUNCTION-LOCAL (FATAL-2): ``hexstrike_body``
        imports the framework agent-body interface, so touching it at module scope would break the sovereign
        leg — but a run is only ever driven in the offense leg, where framework is on the path."""
        if self._body is None:
            from .hexstrike_body import HexstrikeAgentBody  # noqa: PLC0415 (FATAL-2: framework at module scope)
            self._body = HexstrikeAgentBody(brain=self._brain, objective=self._objective,
                                            posture=self._posture)
        return self._body

    def _observation(self, state: Any):
        """Normalize the engine's AgentState + the caller's charter/sensor seeds into the body's read-only
        ``Observation``. Target resolution is unchanged: the explicit ``target``, else the engagement's
        free-text objective. Import is function-local for the same FATAL-2 reason as the body.

        H9 — the seed observations are AUGMENTED with the surfaces the planner has discovered during the run
        (``PlannerMemory.augment``): a new open port, technology or CMS fingerprint observed mid-run re-shapes
        the profile the next plan is built from. With no discovered surface the augmentation is a no-op, so
        the observation equals the seed and the plan is unchanged."""
        from framework.v2.agent_body.interface import Observation  # noqa: PLC0415 (FATAL-2)
        target = self._target or getattr(state, "objective", "") or ""
        # explicit target wins over any stray key in the (augmented) seed observations
        return Observation(state={**self._memory.augment(dict(self._obs)), "target": target})

    def _resolve_capabilities(self) -> Optional[dict]:
        """Probe capability annotations AT MOST ONCE per run and cache them — a re-plan reuses the result
        rather than re-probing the host (capabilities are static for a run). FAIL-SOFT: a resolve() failure
        caches ``None`` so the proposal persists UNANNOTATED (byte-identical to the no-capabilities path).
        Import is FUNCTION-LOCAL (FATAL-2): resolve co-loads the executor + a live host probe only in the
        offense leg where framework/gateway are on the path — engine_think module scope stays framework-free."""
        if not self._capabilities_probed:
            self._capabilities_probed = True
            try:
                from ..live.capability_join import resolve  # noqa: PLC0415 (FATAL-2 / fail-soft)
                rows = resolve(probe_host=True)
                self._capabilities = {r.name: {"status": r.status, "reason": r.reason} for r in rows}
            except Exception:
                self._capabilities = None
        return self._capabilities

    def _persist(self, profile: Any, steps: list) -> None:
        """Write the proposed chain to ``<run_dir>/brain-proposal.json`` (opt-in, atomic, fail-soft). This
        is the ONLY producer of the file the panel reads; it never runs the brain a second time — it
        serialises the profile + steps the engine is about to drive, so the panel matches the run exactly.

        H9 — re-callable: a re-plan re-persists the CURRENT full plan, plus a ``replanning`` block recording
        the deterministic planner-memory snapshot (re-plan count, world digest, deprioritized tools,
        discovered surfaces, tool stats) so the panel can show the adaptive history. The block is ADDITIVE —
        the ``{target,objective,posture,profile,steps}`` contract the reader depends on is unchanged."""
        out = self._proposal_out
        if not out:
            return
        try:
            # H4b-B — annotate each proposed step with its CAPABILITY status (EXECUTABLE / BLOCKED /
            # UNAVAILABLE + reason), so the panel shows WHY a proposed tool can or cannot run rather than
            # the plan silently listing a step that never executes.
            doc = proposal_document(profile, steps, objective=self._objective, posture=self._posture,
                                    capabilities=self._resolve_capabilities())
            doc["replanning"] = {"count": self._replan_count, **self._memory.snapshot()}
            d = Path(out)
            d.mkdir(parents=True, exist_ok=True)
            tmp = d / ".brain-proposal.json.tmp"
            tmp.write_text(json.dumps(doc, indent=2), encoding="utf-8")
            tmp.replace(d / "brain-proposal.json")   # atomic swap — a reader never sees a torn file
        except Exception:
            pass   # persistence is advisory: a write error must never sink the engagement

    def _replan(self, state: Any) -> None:
        """Rebuild the plan from the CURRENT (augmented) observations. Delegates profile + chain construction
        to the ONE canonical body (H1 — this seam does not re-implement it), then applies the planner
        memory's failed-path deprioritization. Persists the fresh plan. Mints nothing — the body returns
        LEADs; the gate authorizes; the oracle confirms."""
        profile, base_steps = self._ensure_body().plan(self._observation(state))
        self._profile = profile
        self._plan = self._memory.replan(base_steps)
        self._replan_count += 1
        # What is persisted is EXACTLY the plan the engine will drive from here.
        self._persist(profile, self._plan)

    def _next_step(self):
        """The next step of the current plan whose tool has not already been emitted, or ``None`` when every
        planned tool has been proposed. A tool that was deprioritized-and-already-tried is thus never
        re-proposed; a tool newly added by a re-plan (e.g. wpscan after a WordPress surface is discovered) is
        picked up here."""
        for step in (self._plan or []):
            if step.tool not in self._emitted:
                return step
        return None

    def __call__(self, state: Any) -> LLMDecision:
        # H9 — fold the current observations into the planner memory (deterministic, propose-only), then
        # RE-PLAN when a new observation has materially changed the world. When nothing new arrived the world
        # digest is unchanged and the plan is NOT rebuilt — a static run is byte-identical to build-once.
        self._memory.ingest_state(state, engagement_slug=str(getattr(state, "engagement_slug", "") or ""))
        digest = self._memory.world_digest()
        if self._plan is None or digest != self._planned_digest:
            self._replan(state)
            self._planned_digest = digest

        step = self._next_step()
        if step is None:
            return LLMDecision(action=ActionType.COMPLETE,
                               summary=f"hexstrike brain chain exhausted "
                                       f"({len(self._emitted)} steps proposed, {self._replan_count} plan(s))")
        self._emitted.add(step.tool)
        # a non-authoritative proposal: the gate decides, the oracle confirms. target rides in tool_args so
        # the executor scopes it; destructiveness is re-derived server-side from the tool registry (F3).
        # NOTE (FP-0): no ``output_analysis`` is ever set — the brain carries no LLM exploit claim, so the
        # engine's fact-minting seam is never fed. Re-planning changes WHAT is proposed, never mints a fact.
        return LLMDecision(
            action=ActionType.USE_TOOL,
            reasoning=f"hexstrike brain step {step.priority}/{len(self._plan or [])}: {step.tool} "
                      f"(danger={step.danger.value}, effectiveness={step.effectiveness})",
            tool=ToolCall(tool_name=step.tool, tool_args={"target": self._target, **dict(step.params)},
                          reason=f"brain-proposed {step.danger.value} step"),
        )
