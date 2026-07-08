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

import hashlib
from typing import TYPE_CHECKING, Any, Iterator

from ..kernel.critique import critique as urk_critique
from .base import Agent
from .blackboard import Blackboard, BlackboardEventRow
from .models import CritiquePayload, FindingPayload

if TYPE_CHECKING:
    from ..calibration import OutcomeLedger

# Version tag stamped on every ledger Prediction this agent writes, so a
# calibrator can segment by the scoring model that produced the record.
_MODEL_VERSION = "oracle-critique-v1"


def _feature_hash(finding: FindingPayload) -> str:
    """A stable, wallclock-free feature key for a finding's calibration record
    (bug class + surface). Deterministic so the ledger serialises byte-stably."""
    raw = f"{finding.bug_class}|{finding.surface}".encode("utf-8")
    return hashlib.sha256(raw).hexdigest()[:16]


# The confidence at/above which a signal is treated as a confirming one — mirrors
# verify.verifier.OracleVerifier.high_confidence (0.7). Kept local so this module
# does not import the verifier just to count corroborating kinds.
_CORROBORATION_THRESHOLD = 0.7


def _distinct_confirming_kinds(oracle_result: Any) -> int:
    """How many DISTINCT oracle kinds fired at/above the confirming threshold for
    one finding. Two or more is genuine cross-oracle corroboration — evidence
    independent enough of any single oracle to resolve an autonomous EXPLOITABLE
    label without the ledger certifying an oracle against itself."""
    signals = getattr(oracle_result, "signals", None) or []
    kinds: set[str] = set()
    for s in signals:
        if getattr(s, "fired", False) and float(getattr(s, "confidence", 0.0)) >= _CORROBORATION_THRESHOLD:
            k = getattr(s, "kind", None)
            kinds.add(getattr(k, "value", None) or str(k))
    return len(kinds)


class CritiqueAgent(Agent):
    name = "critique"

    def __init__(
        self,
        bb: Blackboard,
        engagement_slug: str,
        *,
        ledger: "OutcomeLedger | None" = None,
    ) -> None:
        super().__init__(bb, engagement_slug)
        self._reviewed_finding_ids: set[int] = set()
        # Optional calibration outcome ledger. When present, every
        # oracle-adjudicated finding appends a deterministic (prediction,
        # outcome) pair — the training signal for calibrated scoring and the
        # audit trail. Absent it, critique behaviour is unchanged.
        self._ledger = ledger

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

        cr_dryrun = False
        try:
            cr, trace = urk_critique(
                claim=f"{finding.title}: {finding.summary}",
                evidence=evidence,
                context=f"finding_slug={finding.finding_slug}; severity={finding.severity}",
            )
            cr_dryrun = bool(getattr(trace, "is_dryrun", False))
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
            # "confirmed" is now RESERVED for this path — a fired deterministic oracle.
            new_status = "confirmed" if oracle_fired else "objections"
            verified = oracle_fired
        else:
            # No oracle backs this finding. An LLM verdict — however confident, and
            # ESPECIALLY a dry-run canned one — can NEVER reach "confirmed" (that word
            # is oracle-only). It becomes "llm_advisory": recorded and shown, but never
            # promoted, memory-recorded, or reported as a confirmed fact. This is the
            # veracity invariant: the LLM layer may only advise, never confirm.
            wants_confirm = cr is not None and cr.decision == "confirm"
            new_status = "llm_advisory" if wants_confirm else "objections"
            verified = False

        update: dict[str, Any] = {
            "critique_status": new_status,
            "verified_by_oracle": verified,
            "critique_dryrun": cr_dryrun,
        }
        # Calibrated exploitability score at the confirmation site — the fired
        # oracle's signal confidence mapped through calibration (identity under
        # sparse data). This replaces the audit's hardcoded 1.0; it is never 1.0.
        if oracle_fired:
            update["confidence"] = self._calibrated_confidence(
                float(getattr(oracle_confirmed, "confidence", 0.0))
            )
            # Provenance for the report: which oracle fired + why (item 4.2).
            kind = getattr(oracle_confirmed, "confirmed_by", None)
            update["oracle_kind"] = getattr(kind, "value", None) or (
                str(kind) if kind is not None else None
            )
            update["oracle_rationale"] = str(
                getattr(oracle_confirmed, "rationale", "") or ""
            )
        new_finding = finding.model_copy(update=update)
        self.bb.supersede(
            old_id=f_event.id, agent_name=self.name,
            new_payload=new_finding.model_dump(),
        )
        posted += 1

        # 3. record the deterministic outcome for calibration + audit — oracle
        # path only (a fired/silent oracle is the ground truth; the LLM-advisory
        # path has no deterministic label worth recording).
        if oracle_present and self._ledger is not None:
            self._record_outcome(finding, f_event.id, oracle_fired, oracle_confirmed)

        return posted

    def _record_outcome(
        self,
        finding: FindingPayload,
        finding_event_id: int,
        oracle_fired: bool,
        oracle_result: Any,
    ) -> None:
        """Append the finding's (prediction, outcome) pair to the ledger.

        The prediction's raw_score is the fired oracle's confidence (0.0 when no
        oracle fired); the outcome is EXPLOITABLE when a signal fired, else
        FALSE_POSITIVE. `seq` is derived from the finding's blackboard event id
        (monotonic, wallclock-free): 2*id for the prediction, 2*id+1 for the
        outcome. Append-only violations (a re-reviewed id) are logged, not
        raised — the ledger never rewrites history."""
        try:
            from ..calibration.ledger import LedgerError
            from ..calibration.models import Outcome, OutcomeLabel, Prediction
        except Exception as e:  # pragma: no cover - defensive import guard
            self._log.warning(
                "agent.critique.calibration_import_failed",
                id=finding_event_id, error=str(e),
            )
            return

        fid = f"{finding.finding_slug}#{finding_event_id}"
        raw = float(getattr(oracle_result, "confidence", 0.0)) if oracle_fired else 0.0
        # Non-circular ground truth. The old code labelled EXPLOITABLE iff the
        # oracle fired and used that same oracle's confidence as the prediction —
        # so the calibrator learned P(exploitable | oracle) ~= 1.0 by construction,
        # certifying the oracle against itself. Here the label is resolved ONLY
        # from a signal independent of the confirming oracle: genuine cross-oracle
        # corroboration (>=2 distinct kinds firing on the same evidence) resolves
        # EXPLOITABLE; everything else is DISPUTED (target None -> excluded from
        # every fit). A silent oracle is NOT auto-labelled FALSE_POSITIVE — that
        # too would be the oracle judging itself. Real EXPLOITABLE/FALSE_POSITIVE
        # labels come from an INDEPENDENT adjudicator (the eval harness scoring
        # against a known corpus, or the operator) via record_outcome; until then
        # the calibrator honestly falls back to identity.
        if oracle_fired and _distinct_confirming_kinds(oracle_result) >= 2:
            label = OutcomeLabel.EXPLOITABLE
        else:
            label = OutcomeLabel.DISPUTED
        pred_seq = 2 * finding_event_id
        try:
            self._ledger.add_prediction(
                Prediction(
                    finding_id=fid,
                    raw_score=raw,
                    feature_hash=_feature_hash(finding),
                    model_version=_MODEL_VERSION,
                    oracle_confirmed=oracle_fired,
                ),
                seq=pred_seq,
            )
            self._ledger.record_outcome(
                Outcome(finding_id=fid, label=label), seq=pred_seq + 1,
            )
        except LedgerError as e:
            self._log.warning(
                "agent.critique.ledger_skip", id=finding_event_id, error=str(e),
            )

    def _calibrated_confidence(self, raw: float) -> float:
        """Map a fired oracle's raw signal confidence to a calibrated
        exploitability probability. Fits a PAV/isotonic calibrator over the
        ledger's resolved pairs when a ledger is present; falls back to identity
        (the raw score passed through) with no ledger or too few labels. Either
        way it is a real number in [0, 1) — never the old hardcoded 1.0."""
        raw = max(0.0, min(1.0, raw))
        if self._ledger is None:
            return raw
        try:
            from ..calibration.calibrate import fit
            calibrator = fit(self._ledger.pairs())
            return float(calibrator.calibrate(raw, oracle_confirmed=True))
        except Exception as e:  # pragma: no cover - defensive
            self._log.warning("agent.critique.calibrate_failed", error=str(e))
            return raw

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
