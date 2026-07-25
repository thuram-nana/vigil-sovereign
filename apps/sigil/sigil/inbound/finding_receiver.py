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

Owner tie + scope confinement (S4): the anchor-1 trust root is, in the low-level ``__init__`` /
``ingest_finding`` primitives, simply trusted as given — those do NOT check owner delegation and impose no
per-finding scope. The owner-tied path is :meth:`FindingReceiver.from_delegation`: it DERIVES the trust
root from an owner-signed ``DelegationCert`` (via ``vigil_core.delegation``) and carries the delegated
scope so ``ingest`` binds each finding's own signed ``engagement_slug`` to it — admitting a finding only if
its governance signer was owner-delegated AND it is labelled for the delegated engagement. Sovereign
daemon/CLI wiring MUST use ``from_delegation``; there is no production caller of the raw path today.
"""

from __future__ import annotations

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

    def __init__(self, store: SpineStore, *, crucible_trust_root: TrustRoot, scope: str = "*"):
        """LOW-LEVEL primitive: trusts ``crucible_trust_root`` AS GIVEN — it does NOT verify the owner
        delegated it. Production/daemon/CLI wiring MUST construct via :meth:`from_delegation`, which derives
        the root from an owner-signed delegation (the owner tie is a property of that path, not of this one).
        ``scope`` (default ``"*"`` = no per-finding confinement) binds every ingested finding's own signed
        ``engagement_slug``; :meth:`from_delegation` sets it to the delegated scope so a delegation for one
        engagement cannot admit findings labelled for another."""
        self.store = store
        # The CRUCIBLE governance trust root (m-of-n). Held as a known trust anchor on the sovereign
        # side; it is DATA (public keys + threshold), never the offense engine.
        self.crucible_trust_root = crucible_trust_root
        self._scope = str(scope)

    @classmethod
    def from_delegation(cls, store: SpineStore, *, owner_pubkey: str, delegation, now: int,
                        scope: str) -> "FindingReceiver":
        """Build a receiver whose governance trust root is DERIVED from an OWNER-SIGNED delegation (S4),
        not handed in blindly. The owner (the sovereign 1-of-1 root — a key this side already holds) must
        have signed ``delegation`` authorizing the offense-governance role for ``scope``, not expired at
        ``now``; the receiver then verifies each finding's anchor-1 against the DELEGATED root. Fail-closed:
        an absent/forged/expired/out-of-scope/wrong-owner delegation raises ``InertFindingError`` and NO
        receiver is built — so no finding is ever admitted under an un-owner-delegated governance key.
        Owner-side only; verified with ``vigil_core`` (no offense import)."""
        from vigil_core.delegation import (
            OFFENSE_GOVERNANCE_ROLE,
            DelegationError,
            verify_delegation,
        )
        try:
            root = verify_delegation(delegation, trusted_owner_pubkey=owner_pubkey, now=int(now),
                                     role=OFFENSE_GOVERNANCE_ROLE, scope=scope)
        except DelegationError as exc:
            raise InertFindingError(
                f"offense-governance delegation invalid — refusing all findings under it: {exc}"
            ) from exc
        # Carry the delegated scope through so ingest() binds each finding's OWN signed engagement_slug to it
        # (a non-wildcard scope confines findings; "*" delegations impose no per-finding confinement).
        return cls(store, crucible_trust_root=root, scope=scope)

    def ingest(self, envelope: "str | bytes") -> int:
        """Ingest one inert finding envelope. Returns the appended spine seq.

        Fail-closed: raises ``InertFindingError`` if the envelope is not a valid inert finding, or
        if its CRUCIBLE governance signature (anchor 1) does not verify — in which case NOTHING is
        written to the spine. Only a structurally-valid, governance-signed finding is admitted.
        """
        vf = validate_inert_finding(envelope)  # inert-data validation (json-only, bounded, shaped)
        try:
            verified = vf.verify_signature(self.crucible_trust_root)
        except Exception as exc:
            # malformed signature/key material (e.g. non-base64 sig, empty sig field) can raise
            # from the crypto/model layer — normalise to InertFindingError so ingest's contract holds
            # and a caller catching only InertFindingError still fails closed. Nothing is written.
            raise InertFindingError(
                f"finding {vf.finding_ref!r}: signature material is malformed — {exc} (anchor 1 failed)"
            ) from exc
        if not verified:
            raise InertFindingError(
                f"finding {vf.finding_ref!r}: CRUCIBLE m-of-n governance signature does not satisfy "
                f"the trust root — refusing to spine-sign an unverified finding (anchor 1 failed)"
            )
        # Scope binding (S4): a non-wildcard receiver admits ONLY findings whose OWN signed engagement_slug
        # matches the owner-delegated scope. The delegation's scope gates who signs; THIS gates what they
        # can label. Without it, a compromised offense worker holding any valid in-scope delegation could
        # launder authentic findings onto the spine under an arbitrary engagement label — and they would
        # propagate into per-engagement VEX/report attribution. Fail-closed: a missing/mismatched slug is
        # refused; nothing is written.
        if self._scope != "*" and vf.engagement_slug != self._scope:
            raise InertFindingError(
                f"finding {vf.finding_ref!r}: engagement_slug {vf.engagement_slug!r} is outside the "
                f"owner-delegated scope {self._scope!r} — refusing (cross-engagement finding)"
            )
        # Anchor 2: appended into the owner-signed hash-chain. append() is fsync-durable and returns
        # the assigned seq; the record is now covered by the owner-signed spine head.
        return self.store.append(
            kind=FINDING_KIND, source=FINDING_SOURCE, actor=FINDING_ACTOR,
            payload=vf.to_spine_payload(),
        )


def ingest_finding(
    store: SpineStore, envelope: "str | bytes", *, crucible_trust_root: TrustRoot, scope: str = "*"
) -> int:
    """One-shot convenience over the LOW-LEVEL primitive: validate + verify anchor 1 + (scope-bind) + append.
    Like :meth:`FindingReceiver.__init__`, this trusts ``crucible_trust_root`` AS GIVEN and does NOT verify
    owner delegation — daemon/CLI wiring must derive the receiver via :meth:`FindingReceiver.from_delegation`.
    See :class:`FindingReceiver`."""
    return FindingReceiver(store, crucible_trust_root=crucible_trust_root, scope=scope).ingest(envelope)
