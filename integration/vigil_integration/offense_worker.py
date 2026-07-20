"""
offense_worker — the keyless trust domain that runs offense (FATAL-2, confused-deputy fix).

The offense side runs in env-offense (where ``framework.*`` and ``strix.*`` ARE importable) as a
process holding an engagement-scoped store handle and an autonomy ceiling, but **no owner signing
key** — exactly like a SIGIL mesh agent. Without the owner key it cannot mint an authentic
sovereign governance event (killswitch release, promotion, approval): every such event is signed
over its canonical core by the owner Ed25519 key and verified fail-closed
(``sigil.governor.authn.verify_signed``), so an event the worker forges carries ``sig=None`` and
never verifies — it is ignored. This is what stops the powerful offense process from becoming a
confused deputy that escalates its own authority.

The worker crosses a CONFIRMED finding to the sovereign side only as inert signed DATA, via
``inert_finding.build_envelope`` — no code, no governance action. This module imports neither
``framework`` nor ``strix`` (it duck-types the ``SignedEvidence`` it is handed), so including it
does not by itself pull the offense engine into a process.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .inert_finding import build_envelope

# The offense executor floor (plan §6): offense exec is never auto-A0; A2 is the working ceiling
# for the keyless worker, with A3 transitions requiring an explicit owner-signed, spine-logged,
# auto-expiring authorisation the worker cannot self-issue.
DEFAULT_CEILING = "A2"


@dataclass(frozen=True)
class OffenseWorkerIdentity:
    """The offense worker's trust domain: engagement-scoped, keyless, ceiling-bounded."""

    engagement_slug: str
    ceiling: str = DEFAULT_CEILING


class KeylessOffenseWorker:
    """Runs an offense engagement without any owner authority.

    Construction refuses an owner key outright — the keylessness is enforced, not merely
    convention. The worker may be given an engagement-scoped store handle (to read its own
    engagement's records / write findings within its ceiling), but it can neither hold nor be
    handed the owner key that authenticates governance.
    """

    def __init__(
        self,
        *,
        engagement_slug: str,
        store: Any = None,
        ceiling: str = DEFAULT_CEILING,
        owner_key: Any = None,
    ):
        if owner_key is not None:
            raise ValueError(
                "the offense worker must be KEYLESS: it may not hold an owner signing key "
                "(that is what makes forging a sovereign governance event structurally impossible)"
            )
        if not engagement_slug:
            raise ValueError("an offense worker must be bound to an engagement slug")
        self.identity = OffenseWorkerIdentity(engagement_slug=engagement_slug, ceiling=ceiling)
        self._store = store  # engagement-scoped handle only; may be None

    @property
    def has_owner_key(self) -> bool:
        return False

    def can_sign_governance(self) -> bool:
        """Structurally False. Provided so callers can assert the property directly; the real
        guarantee is that ``sigil.governor.authn.verify_signed`` fails closed on any event this
        keyless worker could produce (``sig`` is ``None``)."""
        return False

    def emit_finding_envelope(self, signed_evidence: Any) -> str:
        """Serialise a CONFIRMED finding (a CRUCIBLE ``SignedEvidence``) into the inert JSON
        envelope that crosses to the sovereign side.

        Uses ``model_dump(mode="json")`` for the certificate so the sovereign receiver can
        re-derive ``evidence_signing_bytes`` byte-identically and verify the m-of-n signature.
        Only JSON data crosses — never code, never a live object.
        """
        certificate = signed_evidence.certificate.model_dump(mode="json")
        signatures = [s.model_dump() for s in signed_evidence.signatures]
        if not signatures:
            raise ValueError("refusing to emit an UNSIGNED finding across the sovereignty seam")
        return build_envelope(certificate, signatures)
