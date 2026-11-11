"""
jobs.completion_signal — K4-5b: the keyless "engagement complete" SETTLE signal (producer side).

When a customer run reaches a terminal state, the keyless offense worker emits a GOVERNANCE-SIGNED
``EngagementCompletion{engagement_slug, nonce, outcome}`` to the cross-plane SETTLE spool. The sovereign
settle-drain (``apps/sigil/sigil/inbound/completion_spool``) verifies it against the owner-signed
``OFFENSE_GOVERNANCE_ROLE`` delegation, derives the billable units from the OWNER-SIGNED lease's reserved
(flat-per-run — this signal carries NO amount), and calls the idempotent ``LaunchGate.settle_launch``. So
credits settle to actual billable consumption AFTER the run (reserve-before / settle-after), and settle stays
sovereign/owner-keyed — the keyless worker cannot mint a refund.

Consumption metric: FLAT-PER-RUN (the plan default, matching the fixed per-run price): COMPLETED ⇒ full
reserved units consumed (no refund); CANCELED/FAILED ⇒ 0 consumed (full refund). ``settle_launch`` CLAMPS
consumed to the owner-signed lease's reserved, so even a forged-but-somehow-signed signal can never
over-charge.

KEYLESS + FATAL-2: this holds NO owner key — ``signers`` are the owner-DELEGATED offense-governance
authorisers (``[(key_id, priv_b64)]``, e.g. from ``live.wiring.provision_authority``). Module scope is
stdlib + ``vigil_core`` (the shared integrity core, framework-free) + the import-clean ``finding_spool`` seam;
NO ``framework`` import, NO ``sigil`` import.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from vigil_core import EngagementCompletion, EngagementOutcome, sign_engagement_completion

from ..finding_spool import spool_envelope

#: The inert settle-spool envelope schema (public material only — document + signatures).
COMPLETION_SEAM_SCHEMA = "vigil-engagement-completion-seam-v1"


def consumed_flat_per_run(outcome: str, reserved: int) -> int:
    """FLAT-PER-RUN billable units: a ``completed`` run consumes the full ``reserved`` units; a
    ``canceled``/``failed`` run consumes 0 (full refund). Advisory only — the sovereign drain recomputes this
    from the owner-signed lease and ``settle_launch`` clamps to the signed reserved, so it can never
    over-charge."""
    return int(reserved) if str(outcome) == EngagementOutcome.COMPLETED.value else 0


def build_completion_envelope(signed) -> str:
    """Serialise a ``SignedEngagementCompletion`` into the inert JSON envelope that crosses to the sovereign
    settle-drain: schema + the document + the signatures (public material only). ``model_dump(mode="json")``
    so the sovereign side re-derives ``engagement_completion_signing_bytes`` byte-identically and verifies."""
    return json.dumps(
        {
            "schema": COMPLETION_SEAM_SCHEMA,
            "document": signed.document.model_dump(mode="json"),
            "signatures": [
                {"key_id": s.key_id, "signature_b64": s.signature_b64} for s in signed.signatures
            ],
        },
        ensure_ascii=False, sort_keys=True,
    )


def emit_completion_signal(
    *,
    engagement_slug: str,
    nonce: str,
    outcome: str,
    signers: "list[tuple[str, str]]",
    spool_dir: Any,
) -> Path:
    """Sign an engagement-completion signal with the owner-delegated offense-governance ``signers`` and spool
    it to the cross-plane settle spool. ``outcome`` is one of ``completed`` / ``canceled`` / ``failed``.
    Fail-closed: no signers ⇒ refuse (a LEAD/unsigned settle trigger can never cross)."""
    if not signers:
        raise ValueError(
            "emit_completion_signal requires owner-delegated offense-governance signers; it will not emit an "
            "unsigned settle signal (fail-closed — only a governance-signed completion may settle)")
    document = EngagementCompletion(
        engagement_slug=engagement_slug, nonce=str(nonce), outcome=EngagementOutcome(str(outcome)))
    signed = sign_engagement_completion(document, dict(signers))
    return spool_envelope(spool_dir, build_completion_envelope(signed))
