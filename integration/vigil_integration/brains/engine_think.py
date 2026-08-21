"""engine_think — drive the production live engine's `think` seam with the propose-only hexstrike brain.

`BrainThink` is a `ThinkFn` (`Callable[[AgentState], LLMDecision]`): on first call it builds a TargetProfile
and the brain's ordered attack chain, then emits ONE `USE_TOOL` LLMDecision per call (a non-authoritative
proposal), and `COMPLETE` when the chain is exhausted. Wire it via `EngineConfig.brain`; the engine's gate
+ governed executor + oracle are UNCHANGED, so this is the red-pen's "one gated executor" — the brain only
proposes, the conjunctive gate authorizes (offense tools QUEUE for owner approval), and the oracle confirms.
Nothing self-authorizes; a proposal is a LEAD until the oracle fires.

Import-clean: only `agent.state` (pydantic models, no framework/strix) + the stdlib brain — so wiring it
pulls no offense engine.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Optional

from ..agent.state import ActionType, LLMDecision, ToolCall
from .hexstrike_brain import HexstrikeBrain, TargetType, parse_objective, proposal_document


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
        self._objective = parse_objective(objective).value
        self._obs = dict(observations or {})
        self._posture = posture
        # OPT-IN persistence: explicit arg wins; else the run dir the console already hands a spawned run.
        _out = proposal_out if proposal_out is not None else os.environ.get("VIGIL_PROOF_RUN_DIR")
        self._proposal_out: "str | None" = str(_out) if _out else None
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

    def _profile(self, state: Any):
        target = self._target or getattr(state, "objective", "") or ""
        tt = self._obs.get("target_type")
        return self._brain.analyze_target(
            target, target_type=TargetType(tt) if tt else None,
            ip_addresses=self._obs.get("ip_addresses"), open_ports=self._obs.get("open_ports"),
            services=self._obs.get("services"), technologies=self._obs.get("technologies") or [],
            cms_type=self._obs.get("cms_type"), cloud_provider=self._obs.get("cloud_provider"))

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
            profile = self._profile(state)
            self._steps = list(self._brain.create_attack_chain(profile, self._objective).steps)
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
