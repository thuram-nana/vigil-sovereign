"""
recon_agent — probes paths, posts Observation events.

The recon-agent owns the recon path. It does not exploit. Other
agents read its Observations to drive hypothesis generation.

Implementation: it is given an iterable of paths to probe and a
Fetcher (UTI's `intake.http.Fetcher`, which honours the 50-request
budget and respects fixture-replay mode). One step probes one path
and posts one Observation.

Per FORGE PROTOCOL § 3.4 the agent stays in lane: recon does not
exploit, does not generate hypotheses, does not write findings.
"""

from __future__ import annotations

from typing import Iterable

from ..intake.http import Fetcher
from .base import Agent
from .blackboard import Blackboard
from .models import ObservationPayload


class ReconAgent(Agent):
    name = "recon"

    def __init__(
        self,
        bb: Blackboard,
        engagement_slug: str,
        *,
        fetcher: Fetcher,
        paths: Iterable[str],
    ) -> None:
        super().__init__(bb, engagement_slug)
        self._fetcher = fetcher
        self._queue: list[str] = list(paths)

    def should_run(self) -> bool:
        return bool(self._queue)

    def step(self) -> int:
        if not self._queue:
            return 0
        path = self._queue.pop(0)

        try:
            ex = self._fetcher.get(path)
        except Exception as e:
            # Budget exhaustion or HTTP error — record an observation noting
            # the failure rather than silently skipping. Append-only audit.
            self.bb.post(
                engagement=self.engagement_id, kind="observation",
                agent_name=self.name,
                payload=ObservationPayload(
                    source=self.name, surface=path,
                    summary=f"probe error: {type(e).__name__}: {e}",
                    confidence=0.1,
                ).model_dump(),
            )
            self._advance_cursor()
            return 1

        # Synthesize a one-line summary from the response shape.
        summary_bits = [f"GET {path} -> {ex.status}"]
        ct = ex.header("Content-Type")
        if ct:
            summary_bits.append(f"ct={ct[:30]}")
        if "Server" in ex.headers:
            summary_bits.append(f"server={ex.headers['Server'][:40]}")
        summary = "; ".join(summary_bits)

        body_for_obs = (ex.body_excerpt or "")[:1000]

        # Confidence reflects how informative the response is for downstream.
        if ex.status == 0:
            confidence = 0.1
        elif 200 <= ex.status < 400:
            confidence = 0.7
        else:
            confidence = 0.4

        self.bb.post(
            engagement=self.engagement_id, kind="observation",
            agent_name=self.name,
            payload=ObservationPayload(
                source=self.name, surface=path,
                summary=summary, raw_excerpt=body_for_obs,
                confidence=confidence,
            ).model_dump(),
        )
        self._advance_cursor()
        return 1
