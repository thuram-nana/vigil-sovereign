"""
improve.canonical — deterministic signing bytes for a proposal.

Governance approvers sign over a proposal's *content digest* (the
merge-relevant fields: id, title, target, change type, patch hash, gap
ids — see ImprovementProposal.content_digest). Signing the digest, with
a domain-separation prefix distinct from the entitlement and revocation
domains, means an approval cannot be replayed onto a different proposal
or onto an entitlement, and a later status/timestamp change does not
invalidate it.
"""

from __future__ import annotations

from typing import Final

from .models import ImprovementProposal

_PROPOSAL_DOMAIN: Final[bytes] = b"crucible-proposal-v1\x00"


def proposal_signing_bytes(proposal: ImprovementProposal) -> bytes:
    """The exact bytes a governance approver signs to approve a merge."""
    return _PROPOSAL_DOMAIN + proposal.content_digest().encode("ascii")
