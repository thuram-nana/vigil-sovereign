"""
hypothesis_agent — reads Observations, generates Hypotheses via URK.

The hypothesis-agent watches the blackboard for new Observations and
posts at-least-one HypothesisPayload per Observation, derived from
URK.hypothesize().

Per the v1 doctrine in `framework/cognitive/hypothesis-driven.md`
§ 2, every observation should yield at least five candidate
hypotheses (the forcing function). The agent honours that by posting
all five returned by URK; downstream the exploit-agent claims them.

Each Hypothesis posted carries `parent_id` set to the originating
Observation, so provenance is queryable.
"""

from __future__ import annotations

import itertools

from ..kernel.hypothesize import hypothesize as urk_hypothesize
from .base import Agent
from .blackboard import Blackboard
from .models import HypothesisPayload, ObservationPayload


class HypothesisAgent(Agent):
    name = "hypothesis"

    def __init__(self, bb: Blackboard, engagement_slug: str) -> None:
        super().__init__(bb, engagement_slug)
        self._handle_counter = itertools.count(1)
        self._processed_observation_ids: set[int] = set()

    def should_run(self) -> bool:
        # Anything new on the blackboard since our cursor?
        latest = self.bb.latest_event_id(engagement=self.engagement_id)
        return latest > self._cursor

    def step(self) -> int:
        new_obs = self.bb.read(
            engagement=self.engagement_id,
            kinds=["observation"],
            since_id=self._cursor,
        )
        posted = 0
        for ev in new_obs:
            if ev.id in self._processed_observation_ids:
                continue
            try:
                obs = ObservationPayload.model_validate(ev.payload)
            except Exception:
                continue

            # Skip observations from this same agent or from agents that
            # post error observations (low confidence).
            if obs.confidence < 0.2:
                self._processed_observation_ids.add(ev.id)
                continue

            try:
                result, _trace = urk_hypothesize(
                    observation=f"{obs.summary}\n\n{obs.raw_excerpt[:500]}",
                    surface=obs.surface,
                    context=f"posted by {ev.agent_name}",
                )
            except Exception as e:
                self._log.warning(
                    "agent.hypothesis.urk_error",
                    error=str(e), parent_id=ev.id,
                )
                self._processed_observation_ids.add(ev.id)
                continue

            for h in result.hypotheses:
                handle = f"H-{next(self._handle_counter):03d}"
                payload = HypothesisPayload(
                    handle=handle,
                    surface=h.surface or obs.surface,
                    bug_class=h.bug_class,
                    given=h.given,
                    if_action=h.if_action,
                    then_observation=h.then_observation,
                    because_model=h.because_model,
                    refute_on=h.refute_on,
                    cheap_test=h.cheap_test,
                    confidence=h.confidence,
                    status="open",
                )
                self.bb.post(
                    engagement=self.engagement_id, kind="hypothesis",
                    agent_name=self.name, parent_id=ev.id,
                    payload=payload.model_dump(by_alias=True),
                )
                posted += 1

            self._processed_observation_ids.add(ev.id)

        self._advance_cursor()
        return posted
