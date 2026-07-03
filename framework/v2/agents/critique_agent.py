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

Oracle authority (CRUCIBLE Wave 3)
----------------------------------
When a Finding carries `oracle_context` (a serialized
`verify.adapter.FindingContext`), the deterministic oracle layer is the
AUTHORITY and the LLM critique is demoted to ADVISORY:

  * If an oracle FIRES over the observed data, the finding is stamped
    `confirmed` and `verified_by_oracle=True`. The URK critique is STILL
    run and its verdict STILL recorded as a Critique event — but that
    verdict does not override the fired signal.
  * If no oracle fires, the finding is NOT confirmed regardless of what
    the LLM says — a fired signal is required. The LLM cannot rubber-
    stamp a finding the oracle refused.

When `oracle_context` is None the legacy LLM-only path is unchanged and
`verified_by_oracle` stays False (advisory confirmation, as before).
"""

from __future__ import annotations

from typing import Any, Iterator

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

        # If the finding carries oracle evidence, the deterministic oracle is
        # the AUTHORITY: run it first and let its verdict decide promotion. The
        # URK critique below becomes advisory (still recorded, never overriding).
        oracle_confirmed = (
            self._oracle_confirm(finding, f_event.id)
            if finding.oracle_context is not None
            else None
        )
        oracle_present = finding.oracle_context is not None
        oracle_fired = oracle_confirmed is not None

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
            if not oracle_present:
                # Legacy LLM-only path: no critique means no decision. Leave the
                # finding pending exactly as before (unchanged behaviour).
                return 0
            # Oracle-authoritative path: the oracle already holds the verdict,
            # so a failed advisory critique does not block promotion. Proceed
            # without an advisory Critique event.
            cr = None

        posted = 0

        # 1. post the critique event (advisory when an oracle is the authority)
        if cr is not None:
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
            posted += 1

        # 2. supersede the finding with the new critique_status.
        if oracle_present:
            # The oracle is authoritative: a fired signal is required, and the
            # LLM's advisory verdict cannot override it in either direction.
            new_status = "confirmed" if oracle_fired else "objections"
            verified = oracle_fired
        else:
            # Legacy LLM-advisory path — unchanged.
            new_status = "confirmed" if cr.decision == "confirm" else "objections"
            verified = False

        new_finding = finding.model_copy(update={
            "critique_status": new_status,
            "verified_by_oracle": verified,
        })
        self.bb.supersede(
            old_id=f_event.id, agent_name=self.name,
            new_payload=new_finding.model_dump(),
        )
        posted += 1
        return posted

    def _oracle_confirm(self, finding: FindingPayload, finding_id: int) -> Any:
        """Run the deterministic oracle layer over `finding.oracle_context`.

        Returns the `ConfirmedFinding` when an oracle fired at/above the
        verifier threshold, else None. `verify` is imported lazily to avoid an
        import cycle (verify → agents.models via _finding_to_dict duck typing).
        Any failure to build the context or run the oracle is treated as
        "did not fire" — the authority never promotes on an error."""
        try:
            from ..verify.adapter import FindingContext
            from ..verify.confirmation import confirm_finding
        except Exception as e:  # pragma: no cover - defensive import guard
            self._log.warning(
                "agent.critique.verify_import_failed", id=finding_id, error=str(e),
            )
            return None

        try:
            context = FindingContext.model_validate(finding.oracle_context)
        except Exception as e:
            self._log.warning(
                "agent.critique.oracle_context_invalid", id=finding_id, error=str(e),
            )
            return None

        try:
            return confirm_finding(finding, context)
        except Exception as e:  # pragma: no cover - defensive
            self._log.warning(
                "agent.critique.oracle_error", id=finding_id, error=str(e),
            )
            return None
