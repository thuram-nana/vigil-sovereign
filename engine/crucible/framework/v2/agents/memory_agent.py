"""
memory_agent — bridge from blackboard event stream to MLS recorder.

Per FORGE PROTOCOL § 3.4 the memory-agent is the recorder for MLS.
The blackboard is the in-memory engagement state; MLS is the
cross-engagement learning substrate. This agent forwards each
blackboard event to the matching MLS recorder call so that:

  - Engagement starts / ends are visible in MLS engagements.
  - Hypotheses from the blackboard land in MLS hypotheses (with
    correct status).
  - Confirmed findings from the blackboard land in MLS findings.
  - Action / Result pairs become MLS payloads with outcome.
  - Refuted hypotheses become MLS dead_ends.

The agent maintains a per-event-id cursor so a re-run after a kill
does not double-write. Every MLS write is keyed by content; the
recorder layer is idempotent where the schema permits.
"""

from __future__ import annotations

from ..common import logging as v2log
from ..memory import recorder as mls_recorder
from ..memory.store import Store, open_store
from .base import Agent
from .blackboard import Blackboard, BlackboardEventRow
from .models import (
    ActionPayload, FindingPayload, HypothesisPayload, ResultPayload,
)


class MemoryAgent(Agent):
    name = "memory"

    def __init__(
        self,
        bb: Blackboard,
        engagement_slug: str,
        *,
        store: Store | None = None,
        archetype: str = "",
        target_url: str = "",
    ) -> None:
        super().__init__(bb, engagement_slug)
        self._owns_store = store is None
        self._store = store or open_store()
        # Make sure the engagement exists in MLS so finding/hypothesis writes
        # do not fail with "no engagement with slug ...".
        try:
            self._store.engagement_id(self.slug)
        except Exception:
            mls_recorder.record_engagement_start(
                self._store, slug=self.slug,
                target_url=target_url,
                archetype=archetype,
                business_context="Created by memory-agent on first event.",
                posture="TEST",
            )
        # Pending action/result pairs (action_id -> payload) so we can
        # write the payload to MLS once we see its result.
        self._pending_actions: dict[str, tuple[str, str]] = {}  # action_id -> (bug_class, surface)
        # action handles -> hypothesis handle, for connecting result to hypothesis
        self._action_to_hypothesis: dict[str, str] = {}

    def should_run(self) -> bool:
        latest = self.bb.latest_event_id(engagement=self.engagement_id)
        return latest > self._cursor

    def step(self) -> int:
        events = self.bb.read(
            engagement=self.engagement_id,
            since_id=self._cursor,
        )
        forwarded = 0
        for ev in events:
            try:
                forwarded += self._forward(ev)
            except Exception as e:
                self._log.warning(
                    "agent.memory.forward_error",
                    id=ev.id, kind=ev.kind, error=str(e),
                )
        self._advance_cursor()
        return forwarded

    def close(self) -> None:
        if self._owns_store:
            self._store.close()

    # ---- forwarding logic ----

    def _forward(self, ev: BlackboardEventRow) -> int:
        if ev.kind == "hypothesis":
            return self._forward_hypothesis(ev)
        if ev.kind == "action":
            return self._capture_action(ev)
        if ev.kind == "result":
            return self._forward_result(ev)
        if ev.kind == "finding":
            return self._forward_finding(ev)
        # Other kinds (observation/plan/critique/decision) are visible on the
        # blackboard but not currently mirrored to MLS schema. Recording them
        # would require schema additions that are out of session scope.
        return 0

    def _forward_hypothesis(self, ev: BlackboardEventRow) -> int:
        try:
            h = HypothesisPayload.model_validate(ev.payload)
        except Exception:
            return 0
        mls_recorder.record_hypothesis(
            self._store, self.slug,
            handle=h.handle, bug_class=h.bug_class, surface=h.surface,
            given=h.given, if_text=h.if_action,
            then_text=h.then_observation, because=h.because_model,
            refute_on=h.refute_on, cheap_test=h.cheap_test,
            status=h.status if h.status in ("open", "confirmed", "refuted", "deferred") else "open",
            confidence=h.confidence,
        )
        return 1

    def _capture_action(self, ev: BlackboardEventRow) -> int:
        try:
            a = ActionPayload.model_validate(ev.payload)
        except Exception:
            return 0
        # Look up the hypothesis the action's plan targets.
        # plan event is the parent of action.
        if ev.parent_id is None:
            return 0
        plan_event = self.bb.get(ev.parent_id)
        if plan_event is None or plan_event.parent_id is None:
            return 0
        hyp_event = self.bb.get(plan_event.parent_id)
        if hyp_event is None or hyp_event.kind != "hypothesis":
            return 0
        hyp_payload = hyp_event.payload
        self._pending_actions[a.action_id] = (
            hyp_payload.get("bug_class", ""),
            hyp_payload.get("surface", ""),
        )
        self._action_to_hypothesis[a.action_id] = hyp_payload.get("handle", "")
        return 0  # action itself is not a separate MLS write; result will pair

    def _forward_result(self, ev: BlackboardEventRow) -> int:
        try:
            r = ResultPayload.model_validate(ev.payload)
        except Exception:
            return 0
        bug_class, surface = self._pending_actions.pop(
            r.action_id, ("", ""),
        )
        if not bug_class:
            return 0
        outcome = "success" if r.success else "failure"
        mls_recorder.record_payload(
            self._store, self.slug,
            bug_class=bug_class,
            payload_text=f"action={r.action_id} surface={surface}",
            target_surface=surface,
            outcome=outcome,
            notes=r.note[:300],
        )
        if not r.success:
            mls_recorder.record_dead_end(
                self._store, self.slug,
                technique=bug_class, surface=surface,
                reason=r.note[:300] or "exploit-agent reported failure",
            )
        return 1

    def _forward_finding(self, ev: BlackboardEventRow) -> int:
        try:
            f = FindingPayload.model_validate(ev.payload)
        except Exception:
            return 0
        # Only forward to MLS once critique is signed off; pre-critique
        # findings are still being adjudicated.
        if f.critique_status != "confirmed":
            return 0
        mls_recorder.record_finding(
            self._store, self.slug,
            finding_slug=f.finding_slug, title=f.title,
            severity=f.severity, cvss_vector=f.cvss_vector,
            cvss_base=f.cvss_base, bug_class=f.bug_class,
            surface=f.surface, summary=f.summary, impact=f.impact,
        )
        return 1
