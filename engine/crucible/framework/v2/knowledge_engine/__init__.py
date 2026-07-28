"""
knowledge_engine — the OFFENSE half of the Knowledge Engine (K2+).

It reasons over the K1 vulnerability-intelligence LEADS and drafts owner-gated PROPOSALS. Doctrine:
a proposal is a ranked SUGGESTION and authorizes NOTHING — the owner must ACCEPT it (which authorizes
LEARNING, never fact-minting), and only a fired deterministic oracle ever mints a FACT. Nothing here
touches the graph, the gate, or an oracle; it is pure ranking over existing intel-tier leads.
"""

from .proposals import LearnProposal, draft_proposals

__all__ = ["LearnProposal", "draft_proposals"]
