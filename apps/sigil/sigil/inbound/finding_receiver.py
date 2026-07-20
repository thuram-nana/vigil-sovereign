"""
finding_receiver — the sovereign side of the two-anchor finding seam (VIGIL P10).

An oracle-confirmed finding is minted + m-of-n signed on the offense side (P9), serialized to an
INERT JSON envelope (P5), and crosses the narrow data-only channel to here. This module is where
the personal core ingests it — and it does so WITHOUT importing any offense-engine module
(``framework.*`` / ``strix.*``), so the offense-free-by-construction guarantee holds: an incoming
finding is opaque signed DATA, never code.

Two anchors make an ingested finding trustworthy end-to-end:

  * Anchor 1 — the CRUCIBLE governance root's m-of-n signature over the finding's evidence
    certificate. Verified HERE, with ``vigil_core`` alone (``ValidatedFinding.verify_signature``),
    before the record is admitted. A finding whose governance signature does not satisfy the
    trust root is REFUSED — it is never written to the spine.
  * Anchor 2 — the owner's Ed25519 signature over the spine HEAD that chains the appended record.
    That is the existing SIGIL spine-head signing (``sigil sign`` / the checkpoint): once the
    finding is appended it is part of the hash-chain the owner head anchors, so tampering with a
    stored finding, or reordering it, breaks the owner-signed head.

Separation of authority: the offense side proves WHAT was found (anchor 1); the owner attests
WHEN it entered the personal record (anchor 2). Neither can forge the other's.
"""

from __future__ import annotations

from typing import Optional

from vigil_integration.inert_finding import InertFindingError, validate_inert_finding

from ..reuse import TrustRoot
from ..spine.store import SpineStore

# The finding record's provenance on the spine. ``kind="finding"`` already exists in the spine
# model (Phase 3). Source/actor mark it as arriving from the offense side via the oracle, not as a
# sovereign-authored event.
FINDING_KIND = "finding"
FINDING_SOURCE = "offense"
FINDING_ACTOR = "ORACLE"


class FindingReceiver:
    """Validate an inert finding envelope, verify anchor 1, and append it to the signed spine."""

    def __init__(self, store: SpineStore, *, crucible_trust_root: TrustRoot):
        self.store = store
        # The CRUCIBLE governance trust root (m-of-n). Held as a known trust anchor on the sovereign
        # side; it is DATA (public keys + threshold), never the offense engine.
        self.crucible_trust_root = crucible_trust_root

    def ingest(self, envelope: "str | bytes") -> int:
        """Ingest one inert finding envelope. Returns the appended spine seq.

        Fail-closed: raises ``InertFindingError`` if the envelope is not a valid inert finding, or
        if its CRUCIBLE governance signature (anchor 1) does not verify — in which case NOTHING is
        written to the spine. Only a structurally-valid, governance-signed finding is admitted.
        """
        vf = validate_inert_finding(envelope)  # inert-data validation (json-only, bounded, shaped)
        if not vf.verify_signature(self.crucible_trust_root):
            raise InertFindingError(
                f"finding {vf.finding_ref!r}: CRUCIBLE m-of-n governance signature does not satisfy "
                f"the trust root — refusing to spine-sign an unverified finding (anchor 1 failed)"
            )
        # Anchor 2: appended into the owner-signed hash-chain. append() is fsync-durable and returns
        # the assigned seq; the record is now covered by the owner-signed spine head.
        return self.store.append(
            kind=FINDING_KIND, source=FINDING_SOURCE, actor=FINDING_ACTOR,
            payload=vf.to_spine_payload(),
        )


def ingest_finding(
    store: SpineStore, envelope: "str | bytes", *, crucible_trust_root: TrustRoot
) -> int:
    """One-shot convenience: validate + verify anchor 1 + append. See :class:`FindingReceiver`."""
    return FindingReceiver(store, crucible_trust_root=crucible_trust_root).ingest(envelope)
