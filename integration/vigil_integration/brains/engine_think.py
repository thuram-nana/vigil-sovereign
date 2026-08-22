"""engine_think — a THIN think-seam adapter that drives the production live engine with the ONE canonical
hexstrike agent body.

`BrainThink` is a `ThinkFn` (`Callable[[AgentState], LLMDecision]`) that adapts the pluggable
`HexstrikeAgentBody` (``brains.hexstrike_body``) — the single canonical body — to the live engine's
``think`` seam. On first call it hands the body a normalized ``Observation`` and asks it to ``plan``: the
body builds the ``TargetProfile`` and the ordered attack chain. BrainThink then emits ONE `USE_TOOL`
LLMDecision per proposed step (a non-authoritative proposal) and `COMPLETE` when the chain is exhausted.

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
        self._steps: Optional[list] = None
        self._i = 0

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
        free-text objective. Import is function-local for the same FATAL-2 reason as the body."""
        from framework.v2.agent_body.interface import Observation  # noqa: PLC0415 (FATAL-2)
        target = self._target or getattr(state, "objective", "") or ""
        # explicit target wins over any stray key in the seed observations
        return Observation(state={**self._obs, "target": target})

    def _persist(self, profile: Any, steps: list) -> None:
        """Write the proposed chain to ``<run_dir>/brain-proposal.json`` (opt-in, atomic, fail-soft). This
        is the ONLY producer of the file the panel reads; it never runs the brain a second time — it
        serialises the profile + steps the engine is about to drive, so the panel matches the run exactly."""
        out = self._proposal_out
        if not out:
            return
        try:
            doc = proposal_document(profile, steps, objective=self._objective, posture=self._posture)
            d = Path(out)
            d.mkdir(parents=True, exist_ok=True)
            tmp = d / ".brain-proposal.json.tmp"
            tmp.write_text(json.dumps(doc, indent=2), encoding="utf-8")
            tmp.replace(d / "brain-proposal.json")   # atomic swap — a reader never sees a torn file
        except Exception:
            pass   # persistence is advisory: a write error must never sink the engagement

    def __call__(self, state: Any) -> LLMDecision:
        if self._steps is None:
            # Delegate profile + chain construction to the ONE canonical body — this seam no longer
            # re-implements it (H1). What is persisted is EXACTLY the chain the body handed back.
            profile, self._steps = self._ensure_body().plan(self._observation(state))
            self._persist(profile, self._steps)
        if self._i >= len(self._steps):
            return LLMDecision(action=ActionType.COMPLETE,
                               summary=f"hexstrike brain chain exhausted ({len(self._steps)} steps proposed)")
        step = self._steps[self._i]
        self._i += 1
        # a non-authoritative proposal: the gate decides, the oracle confirms. target rides in tool_args so
        # the executor scopes it; destructiveness is re-derived server-side from the tool registry (F3).
        return LLMDecision(
            action=ActionType.USE_TOOL,
            reasoning=f"hexstrike brain step {step.priority}/{len(self._steps)}: {step.tool} "
                      f"(danger={step.danger.value}, effectiveness={step.effectiveness})",
            tool=ToolCall(tool_name=step.tool, tool_args={"target": self._target, **dict(step.params)},
                          reason=f"brain-proposed {step.danger.value} step"),
        )
