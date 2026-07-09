"""
agents.spine_sink — bridge the flagship engage/scanner world onto the one event spine.

The blackboard is the append-only, typed, provenance-linked event stream. Historically only
the multi-agent (MAO) path wrote to it; the flagship ``engage``/scanner path kept its state in
parallel stores. ``SpineSink`` closes that gap ADDITIVELY: it implements the scanner's existing
``ProgressSink`` Protocol (so the scanner emits phase/finding/done onto the spine in real time
without importing anything from here) and adds typed helpers so ``engage`` can mirror its
high-fidelity findings, grounding verdicts, refusals, and rewards onto the SAME stream.

Every post is best-effort and fire-and-forget — a spine write can NEVER raise into the scan or
sink an engagement (the JsonlSink discipline). When no ``SpineSink`` is attached, behaviour is
byte-identical to before: the spine is opt-in.
"""

from __future__ import annotations

from typing import Any

from .blackboard import Blackboard
from .models import EventKind


class SpineSink:
    """Mirrors scanner/engage activity onto the blackboard event spine.

    Satisfies ``scanner.progress.ProgressSink`` (phase/finding/done) AND offers typed spine
    helpers (finding_event / decision / refusal / reward / reflection / critic_verdict). All
    emission is swallow-on-error so it never perturbs the run.
    """

    def __init__(self, bb: Blackboard, engagement: str, *, agent_name: str = "spine") -> None:
        self._bb = bb
        self._engagement = engagement
        self._agent = agent_name
        try:
            self._bb.engagement_id(engagement)   # ensure the engagement row exists (create=True)
        except Exception:
            pass

    def _post(self, kind: EventKind, payload: dict[str, Any], **kw: Any) -> int | None:
        try:
            return self._bb.post(engagement=self._engagement, kind=kind,
                                 agent_name=self._agent, payload=payload, **kw)
        except Exception:
            return None   # never let a spine write perturb the scan/engagement

    # ---- ProgressSink Protocol (real-time, progress-level → observation events) ----

    def phase(self, name: str, **fields: object) -> None:
        self._post("observation", {"source": "scanner:phase", "surface": str(name),
                                   "summary": f"phase: {name}"})

    def finding(self, bug_class: str, confirmed_by: str, param: str, endpoint: str,
                confidence: float) -> None:
        # A real-time PROGRESS signal (an observation), not the authoritative finding event —
        # engage posts the high-fidelity finding_event() below with the oracle_context.
        self._post("observation", {
            "source": "scanner:finding", "surface": f"{param} @ {endpoint}".strip(" @"),
            "summary": f"{bug_class} confirmed by {confirmed_by} (conf {round(confidence, 3)})"})

    def done(self, findings: int, requests_sent: int, elapsed_s: float) -> None:
        self._post("observation", {"source": "scanner:done", "surface": "(scan)",
                                   "summary": f"scan done: {findings} findings, {requests_sent} requests"})

    # ---- typed spine helpers (high-fidelity, for the engage post-scan mirror) ----

    def finding_event(self, payload: dict[str, Any], *, parent_id: int | None = None) -> int | None:
        """Post an authoritative FindingPayload-shaped finding event (carries the finding's
        oracle_context / verified_by_oracle / grounding so downstream can re-verify)."""
        return self._post("finding", payload, parent_id=parent_id)

    def decision(self, question: str, choice: str, rationale: str = "") -> int | None:
        return self._post("decision", {"question": question, "choice": choice, "rationale": rationale})

    def refusal(self, gate: str, action_refused: str, *, reason: str = "",
                fatal: bool = False) -> int | None:
        """Record a refusal AS EVIDENCE on the spine (a gate fired). Never dropped."""
        return self._post("refusal", {"gate": gate, "action_refused": action_refused,
                                      "reason": reason, "fatal": fatal})

    def reward(self, source: str, reward: float, *, arm: str = "", signal: str = "",
               target_event_id: int | None = None, rationale: str = "") -> int | None:
        return self._post("reward", {"source": source, "arm": arm, "signal": signal,
                                     "reward": max(0.0, min(1.0, float(reward))),
                                     "target_event_id": target_event_id, "rationale": rationale})

    def reflection(self, trigger: str, observations: list[str], *, reorientation: str = "",
                   rationale: str = "") -> int | None:
        return self._post("reflection", {"trigger": trigger, "observations": list(observations),
                                         "reorientation": reorientation, "rationale": rationale})

    def critic_verdict(self, critic: str, target_event_id: int, verdict: str, *,
                       severity: str = "info", rationale: str = "") -> int | None:
        # parent_id = the finding this verdict is ABOUT (the provenance edge), MIRRORING
        # MultiCriticAgent. Without it, the panel quorum's indexed parent_id read
        # (agents/critics.py::panel_verdict_for) would not see this spine-posted verdict —
        # only the payload target_event_id would, and that read now filters on parent_id.
        return self._post("critic_verdict", {"critic": critic, "target_event_id": target_event_id,
                                             "verdict": verdict, "severity": severity,
                                             "rationale": rationale}, parent_id=target_event_id)

    def tool_call(self, tool: str, *, tier: str = "", capability: str = "", target: str = "",
                  args_summary: str = "", parent_id: int | None = None) -> int | None:
        """Record the reasoning core's REQUEST to run a gated tool/sensor (W1.4), before it runs.
        ``parent_id`` links it to the driving event (a hypothesis/decision)."""
        return self._post("tool_call", {"tool": tool, "tier": tier, "capability": capability,
                                        "target": target, "args_summary": args_summary},
                          parent_id=parent_id)

    def tool_result(self, tool: str, *, ok: bool, refused: bool = False, gate: str = "",
                    summary: str = "", note: str = "", tool_call_id: int | None = None) -> int | None:
        """Record a gated tool/sensor invocation's outcome (a provenance-labelled observation, not
        a fact). ``parent_id = tool_call_id`` is the provenance edge back to the request."""
        return self._post("tool_result", {"tool": tool, "ok": bool(ok), "refused": bool(refused),
                                          "gate": gate, "summary": summary, "note": note},
                          parent_id=tool_call_id)
