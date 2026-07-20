"""
improve.models — schemas for SIL.

Flow of data:

    EngagementSnapshot / HorizonItem  --reviewer/horizon-->  CapabilityGap
    CapabilityGap                     --patcher-->            ImprovementProposal
    ImprovementProposal + eval + approvals  --merge_gate-->   MergeDecision

Everything is pure validated data. The gate authorises; nothing here
mutates the framework.
"""

from __future__ import annotations

import enum
import hashlib
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field


# ---------------------------------------------------------------------------
# Gaps
# ---------------------------------------------------------------------------


class GapKind(str, enum.Enum):
    """What kind of shortfall a gap represents. Priority derives from
    kind in reviewer.py."""

    COVERAGE_GAP = "coverage_gap"            # a known bug class never hypothesised
    UNREACHED_SURFACE = "unreached_surface"  # a discovered surface never tested
    UNREACHED_HYPOTHESIS = "unreached_hypothesis"  # an open hypothesis never executed
    REFUTED_THREAD = "refuted_thread"        # a thread we could not confirm
    HORIZON = "horizon"                      # a newly disclosed CVE / technique


class CapabilityGap(BaseModel):
    """One identified shortfall in what the framework achieved or can
    achieve. The unit SIL turns into a proposal."""

    model_config = ConfigDict(extra="forbid")

    id: str = Field(min_length=1)
    kind: GapKind
    priority: int = Field(ge=0, le=100, description="Higher = more valuable to close.")
    title: str = Field(min_length=1)
    description: str = Field(default="")
    source: str = Field(min_length=1, description="Engagement slug or 'horizon:<feed>'.")
    bug_class: str = Field(default="")
    surface: str = Field(default="")
    evidence: list[str] = Field(
        default_factory=list, description="Provenance: blackboard event ids, CVE ids, etc."
    )
    discovered_at: datetime


# ---------------------------------------------------------------------------
# Reviewer input
# ---------------------------------------------------------------------------


class HypothesisRecord(BaseModel):
    """A flattened view of one hypothesis as the reviewer needs it.
    Adapters build these from blackboard rows."""

    model_config = ConfigDict(extra="forbid")

    handle: str = Field(min_length=1)
    bug_class: str = Field(default="")
    surface: str = Field(default="")
    status: str = Field(default="open", description="open | confirmed | refuted")
    executed: bool = Field(default=False, description="Did an executor run it?")
    event_id: str = Field(default="")


class EngagementSnapshot(BaseModel):
    """The read-only inputs the reviewer mines. An adapter assembles this
    from a Blackboard + MLS recall; tests build it directly."""

    model_config = ConfigDict(extra="forbid")

    slug: str = Field(min_length=1)
    archetype: str = Field(default="generic-web")
    hypotheses: list[HypothesisRecord] = Field(default_factory=list)
    discovered_surfaces: list[str] = Field(default_factory=list)
    known_archetype_bug_classes: list[str] = Field(
        default_factory=list,
        description="Bug classes MLS associates with this archetype — the "
        "coverage yardstick.",
    )


# ---------------------------------------------------------------------------
# Horizon
# ---------------------------------------------------------------------------


class HorizonItem(BaseModel):
    """A newly disclosed vulnerability or technique to consider folding
    into the framework's repertoire."""

    model_config = ConfigDict(extra="forbid")

    id: str = Field(min_length=1, description="CVE id or technique handle.")
    source: str = Field(min_length=1)
    summary: str = Field(min_length=1)
    bug_class: str = Field(default="")
    affected_archetypes: list[str] = Field(default_factory=list)
    severity: str = Field(default="medium", pattern=r"^(info|low|medium|high|critical)$")
    references: list[str] = Field(default_factory=list)
    published_at: datetime


# ---------------------------------------------------------------------------
# Proposals
# ---------------------------------------------------------------------------


class ProposalStatus(str, enum.Enum):
    DRAFT = "draft"
    EVAL_PENDING = "eval_pending"
    EVAL_PASSED = "eval_passed"
    EVAL_FAILED = "eval_failed"
    APPROVED = "approved"
    MERGED = "merged"
    REJECTED = "rejected"


class ProposedChange(BaseModel):
    """A precise, reviewable description of the change. `patch` is an
    optional unified diff; when absent the change is described for a
    human or an LLM binding to implement. SIL never self-applies either
    form."""

    model_config = ConfigDict(extra="forbid")

    target_artifact: str = Field(
        min_length=1,
        description="Path or logical artifact to change "
        "(e.g. 'signatures/idor-bola.yaml', 'playbooks/07-authorization.md').",
    )
    change_type: str = Field(
        min_length=1, description="add_signature | extend_playbook | add_technique | code_fix"
    )
    summary: str = Field(min_length=1)
    patch: str = Field(default="", description="Optional unified diff. Empty = described-only.")

    def patch_digest(self) -> str:
        return hashlib.sha256(self.patch.encode("utf-8")).hexdigest()


class ImprovementProposal(BaseModel):
    """A reviewable candidate improvement. Emitted by the patcher;
    authorised (not applied) by the merge gate."""

    model_config = ConfigDict(extra="forbid")

    id: str = Field(min_length=1)
    title: str = Field(min_length=1)
    rationale: str = Field(default="")
    gap_ids: list[str] = Field(default_factory=list)
    change: ProposedChange
    status: ProposalStatus = Field(default=ProposalStatus.DRAFT)
    created_at: datetime

    def content_digest(self) -> str:
        """A stable digest of the merge-relevant content (NOT status or
        timestamps). Approvers sign over this so later status changes do
        not invalidate their approval."""
        parts = [
            self.id,
            self.title,
            self.change.target_artifact,
            self.change.change_type,
            self.change.patch_digest(),
            "|".join(sorted(self.gap_ids)),
        ]
        return hashlib.sha256("\x1f".join(parts).encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# Merge decision
# ---------------------------------------------------------------------------


class MergeDecision(BaseModel):
    """The gate's verdict on whether a proposal MAY be merged. It does
    not perform the merge — a human applies an authorised proposal."""

    model_config = ConfigDict(extra="forbid")

    proposal_id: str
    approved: bool
    capability_present: bool
    eval_passed: bool
    threshold_met: bool
    valid_approvers: list[str] = Field(default_factory=list)
    reasons: list[str] = Field(default_factory=list)
    evaluated_at: datetime
