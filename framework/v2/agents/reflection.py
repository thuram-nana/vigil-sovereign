"""
agents.reflection — an in-loop metacognitive reflection over the reasoning trace.

CRUCIBLE reviewed FINDINGS (critique) but never reflected on its own REASONING mid-run: which
threads went dead, which hypotheses were refuted, whether it is stalling. reasoning-loops.md §8
and self-critique.md prescribe exactly that cadence. This module reads the event spine and
posts ``reflection`` events that RE-ORIENT the next tick — strictly re-rank / defer, NEVER gate
or skip an attack surface (coverage doctrine) and never touch the oracle path.

Deterministic (no LLM, no wallclock/global-rng), replay-safe. ``reflect`` is a pure function of
the spine; ``ReflectionAgent`` posts only reflections not already on the stream (deduped), so a
long run does not accumulate repeats.
"""

from __future__ import annotations

from typing import Any


def _all_events(bb: Any, engagement: Any) -> list:
    """Every event for the engagement in id order, paged to exhaustion (the read default limit
    would silently truncate a large log — the N1/N3 lesson)."""
    out: list = []
    since = 0
    while True:
        batch = bb.read(engagement=engagement, since_id=since, limit=5000)
        if not batch:
            break
        out.extend(batch)
        since = batch[-1].id
        if len(batch) < 5000:
            break
    return out


def _dedup_key(payload: dict) -> str:
    return f"{payload.get('trigger', '')}::{payload.get('reorientation', '')}"


def reflect(bb: Any, engagement: Any, *, stall_actions: int = 5) -> list[dict]:
    """Read the spine and return the reflection payloads its current state warrants — pure,
    deterministic, read-only. Detects: DEAD THREADS (a hypothesis that produced no finding),
    and a STALL (many actions with zero findings). Each reflection RE-ORIENTS by re-rank/defer;
    none gates a surface."""
    events = _all_events(bb, engagement)
    reflections: list[dict] = []

    hyp_handles = [e.payload.get("handle") for e in events if e.kind == "hypothesis"]
    finding_handles = {e.payload.get("derived_from_hypothesis")
                       for e in events if e.kind == "finding"}
    for handle in dict.fromkeys(h for h in hyp_handles if h):        # stable order, unique
        if handle not in finding_handles:
            reflections.append({
                "trigger": "dead-thread",
                "observations": [f"hypothesis {handle} produced no finding"],
                "reorientation": f"defer {handle}; re-rank effort toward untested surfaces",
                "rationale": "a thread with no confirmed finding is low expected value to keep pursuing"})

    n_actions = sum(1 for e in events if e.kind == "action")
    n_findings = sum(1 for e in events if e.kind == "finding")
    if n_actions >= stall_actions and n_findings == 0:
        reflections.append({
            "trigger": "stall",
            "observations": [f"{n_actions} actions taken, 0 findings confirmed"],
            "reorientation": "pivot: re-rank to a different surface/technique (do not skip any)",
            "rationale": "sustained effort with no confirmation suggests the current thread is unproductive"})

    return reflections


class ReflectionAgent:
    """A schedulable agent (duck-typed to ``agents.base.Agent``) that posts NEW reflections
    from ``reflect`` — additive; addable to the Coordinator without touching any agent. It only
    posts advisory reflection events; a downstream planner MAY re-rank on them."""

    name = "reflection"

    def __init__(self, blackboard: Any, engagement_slug: str, *, stall_actions: int = 5) -> None:
        # mirror base.Agent's contract without importing it (keeps this module light)
        self.bb = blackboard
        self.slug = engagement_slug
        self.engagement_id = blackboard.engagement_id(engagement_slug)
        self._stall_actions = stall_actions

    def _already_posted(self) -> set[str]:
        return {_dedup_key(r.payload)
                for r in _all_events(self.bb, self.engagement_id) if r.kind == "reflection"}

    def _pending(self) -> list[dict]:
        posted = self._already_posted()
        return [r for r in reflect(self.bb, self.engagement_id, stall_actions=self._stall_actions)
                if _dedup_key(r) not in posted]

    def should_run(self) -> bool:
        return bool(self._pending())

    def step(self) -> int:
        posted = 0
        for r in self._pending():
            try:
                self.bb.post(engagement=self.engagement_id, kind="reflection",
                             agent_name=self.name, payload=r)
                posted += 1
            except Exception:
                pass
        return posted
