"""
critique_agent — adversarial review of every Finding before promotion.

Per FORGE PROTOCOL § 3.4 critical rules: the critique-agent is NOT
optional. Every Finding goes through it before the reporter promotes
it. This is the guard against confident hallucination — it forces a
"could this be wrong, and how?" pass on every claim.

For each Finding with `critique_status='pending'`:
  1. Read the related Result + Action + Hypothesis (provenance walk).
  2. Build evidence string from those.
  3. Call URK.critique(claim, evidence).
  4. Post a Critique event citing the Finding.
  5. Supersede the Finding with critique_status updated to
     'confirmed' or 'objections'.

The reporter watches for findings with critique_status='confirmed'.
"""

from __future__ import annotations

from typing import Iterator

from ..kernel.critique import critique as urk_critique
from .base import Agent
from .blackboard import Blackboard, BlackboardEventRow
from .models import CritiquePayload, FindingPayload


class CritiqueAgent(Agent):
    name = "critique"

    def __init__(self, bb: Blackboard, engagement_slug: str) -> None:
        super().__init__(bb, engagement_slug)
        self._reviewed_finding_ids: set[int] = set()

    def should_run(self) -> bool:
        # Any pending finding we haven't reviewed yet?
        for f in self._pending_findings():
            if f.id not in self._reviewed_finding_ids:
                return True
        return False

    def step(self) -> int:
        posted = 0
        for f in list(self._pending_findings()):
            if f.id in self._reviewed_finding_ids:
                continue
            posted += self._review(f)
            self._reviewed_finding_ids.add(f.id)
        self._advance_cursor()
        return posted

    # ---- helpers ----

    def _pending_findings(self) -> Iterator[BlackboardEventRow]:
        rows = self.bb.read(
            engagement=self.engagement_id, kinds=["finding"],
        )
        for r in rows:
            if r.payload.get("critique_status") == "pending":
                yield r

    def _review(self, f_event: BlackboardEventRow) -> int:
        try:
            finding = FindingPayload.model_validate(f_event.payload)
        except Exception as e:
            self._log.warning(
                "agent.critique.finding_invalid", id=f_event.id, error=str(e),
            )
            return 0

        # Gather evidence by walking parent_id chain: finding -> result -> action -> plan -> hypothesis
        evidence_parts: list[str] = []
        cur = self.bb.get(f_event.parent_id) if f_event.parent_id else None
        depth = 0
        while cur is not None and depth < 6:
            evidence_parts.append(f"{cur.kind}: {cur.payload}")
            cur = self.bb.get(cur.parent_id) if cur.parent_id else None
            depth += 1
        evidence = "\n\n".join(evidence_parts) or "(no provenance chain)"

        try:
            cr, _trace = urk_critique(
                claim=f"{finding.title}: {finding.summary}",
                evidence=evidence,
                context=f"finding_slug={finding.finding_slug}; severity={finding.severity}",
            )
        except Exception as e:
            self._log.warning(
                "agent.critique.urk_error", id=f_event.id, error=str(e),
            )
            return 0

        # 1. post the critique event
        crit_payload = CritiquePayload(
            target_event_id=f_event.id,
            decision=cr.decision,
            objections=[o.concern for o in cr.objections],
            deception_check=cr.deception_check,
        )
        self.bb.post(
            engagement=self.engagement_id, kind="critique",
            agent_name=self.name, parent_id=f_event.id,
            payload=crit_payload.model_dump(),
        )

        # 2. supersede the finding with the new critique_status
        new_status = "confirmed" if cr.decision == "confirm" else "objections"
        new_finding = finding.model_copy(update={"critique_status": new_status})
        self.bb.supersede(
            old_id=f_event.id, agent_name=self.name,
            new_payload=new_finding.model_dump(),
        )
        return 2
