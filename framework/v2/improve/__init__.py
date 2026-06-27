"""
improve — SIL, the Self-Improvement Loop (Pillar 3, Milestone M3).

The never-stop engine, built the only way a serious institution can
field it: **continuous discovery, gated deployment.** SIL runs
continuously to find what the framework missed and to author candidate
improvements; it never merges or deploys them to itself. A change
reaches the framework only through a human-governed gate:
eval-harness-green (M2) AND a threshold of governance approvals over the
proposal (reusing the Pillar-2 entitlement crypto) AND a deployment that
holds the SELF_IMPROVEMENT_MERGE capability.

Four moving parts:

    reviewer    mines an engagement (and MLS priors) for capability gaps
    horizon     ingests new CVEs / techniques as gaps
    patcher     turns gaps into reviewable ImprovementProposals (records +
                markdown) — never raw self-applied diffs
    merge_gate  authorises (does not apply) a proposal: eval-green +
                threshold approvals + capability

Public surface:

    from framework.v2.improve import (
        CapabilityGap, GapKind, EngagementSnapshot,
        ImprovementProposal, ProposalStatus, MergeDecision, HorizonItem,
        review_snapshot, ingest_horizon, draft_proposals, evaluate_merge,
    )

SIL acts on nothing by itself. It proposes; humans, holding keys,
dispose.
"""

from __future__ import annotations

from .horizon import ingest_horizon
from .merge_gate import evaluate_merge
from .models import (
    CapabilityGap,
    EngagementSnapshot,
    GapKind,
    HorizonItem,
    HypothesisRecord,
    ImprovementProposal,
    MergeDecision,
    ProposalStatus,
)
from .patcher import draft_proposals
from .reviewer import review_snapshot

__all__ = [
    "CapabilityGap",
    "GapKind",
    "EngagementSnapshot",
    "HypothesisRecord",
    "ImprovementProposal",
    "ProposalStatus",
    "MergeDecision",
    "HorizonItem",
    "review_snapshot",
    "ingest_horizon",
    "draft_proposals",
    "evaluate_merge",
]
