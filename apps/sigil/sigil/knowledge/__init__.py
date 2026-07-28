"""
sigil.knowledge — the SOVEREIGN half of the Knowledge Engine (K2b).

The offense plane DRAFTS proposals (ranked vulnerability leads); this plane is where the owner acts on
them. A proposal is enqueued as an ordinary awaiting-approval item on the append-only spine; ACCEPT is the
existing owner-signed ``ApprovalQueue.approve`` (never weakened here). Accepting AUTHORISES LEARNING (K3),
never fact-minting — and only a fired oracle ever mints a FACT. Enqueuing grants nothing; the owner-signed
approval is the sole trust operation.
"""

from .learn_grant import approved_learn_grants, export_approved_grants
from .proposals import LEARN_SIGNAL, enqueue_learn_proposal, pending_learn_proposals

__all__ = ["LEARN_SIGNAL", "enqueue_learn_proposal", "pending_learn_proposals",
           "approved_learn_grants", "export_approved_grants"]
