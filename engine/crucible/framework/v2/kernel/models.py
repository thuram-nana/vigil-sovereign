"""
kernel.models — Pydantic schemas for URK structured outputs.

Each schema mirrors the structured information one cognitive doc
produces. Schemas are how URK enforces consistency: type-checked at
parse time, queryable at use time, serializable to JSON for MLS.

The shapes here track the v1 prose. If a cognitive doc gains a new
section that warrants a new field, update the schema and the
corresponding binding together.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, computed_field

from ..verify.verifier import is_known_bug_class


# ---------------------------------------------------------------------------
# hypothesize.py  ←  framework/cognitive/hypothesis-driven.md
# ---------------------------------------------------------------------------


class Hypothesis(BaseModel):
    """One falsifiable hypothesis in the four-part form from § 1 of
    hypothesis-driven.md: given / if / then / because, plus a refute_on
    and a cheap_test. Required on every entry."""

    model_config = ConfigDict(populate_by_name=True)

    id: str = Field(description="Stable handle (e.g. H-007). Short.")
    surface: str = Field(description="Endpoint, feature, or flow under test.")
    # Value-membership (anti-hallucination P6): the raw label is preserved (downstream
    # exploit-scenario / planner keys match on its exact spelling), but ``oracle_provable``
    # (below) reports whether the class — after normalisation — is one an oracle can actually
    # confirm, so an exploratory lead is never mistaken for a provable fact.
    bug_class: str = Field(
        description="Single bug class label: SQLi, IDOR, SSRF, race, etc."
    )
    given: str = Field(description="Pre-condition / context.")
    if_action: str = Field(
        alias="if", description="The action that probes the hypothesis."
    )
    then_observation: str = Field(
        alias="then", description="Expected observation if hypothesis holds."
    )
    because_model: str = Field(
        alias="because",
        description="The internal model: WHY the observation should follow.",
    )
    refute_on: str = Field(description="Observation that would disprove this.")
    cheap_test: str = Field(
        description="The minimum test (curl one-liner is the goal)."
    )
    confidence: float = Field(
        ge=0.0, le=1.0, default=0.5,
        description="Tester's prior on this being a real bug.",
    )

    @computed_field  # type: ignore[prop-decorator]
    @property
    def oracle_provable(self) -> bool:
        """True iff this bug_class is in the CURATED oracle vocabulary — i.e. it maps to
        specific confirming oracle(s). False marks a class outside that set: an exploratory
        lead not known to be provable on the strength of its label. (It is NOT a guarantee
        that no oracle could ever fire — the verifier's fallback can still try generic
        oracles for an unknown class — so the deterministic oracle re-fire, not this flag,
        remains the authority for any FACT claim.) Surfaced in the serialized hypothesis so
        the planner can prefer provable leads."""
        return is_known_bug_class(self.bug_class)


class HypothesisSet(BaseModel):
    """Output of hypothesize(). Doctrine: at least five hypotheses per
    observation (hypothesis-driven.md § 2). Schema enforces three to
    survive partial-output backends; bindings extend to five."""

    observation: str
    hypotheses: list[Hypothesis] = Field(min_length=3)
    notes: str | None = Field(
        default=None, description="Free-form caveats or surprises."
    )

    def doctrine_compliant(self) -> bool:
        return len(self.hypotheses) >= 5


# ---------------------------------------------------------------------------
# critique.py  ←  framework/cognitive/self-critique.md
# ---------------------------------------------------------------------------


CritiqueDecision = Literal["confirm", "objections", "more_evidence_needed"]


class Objection(BaseModel):
    """A single concern raised during critique. Mirrors the shape of a
    senior reviewer's pushback: name the concern, name the evidence
    that would dispel it."""

    concern: str
    severity: Literal["fatal", "major", "minor"]
    evidence_request: str = Field(
        description="What would change this objection's status."
    )


class CritiqueResult(BaseModel):
    """Output of critique(). Used by the (future) critique-agent to gate
    findings before report. self-critique.md § 4 final critique is the
    template for fields here."""

    claim: str
    decision: CritiqueDecision
    drift_detected: bool = False
    drift_note: str | None = None
    coverage_gaps: list[str] = Field(default_factory=list)
    deception_check: str = Field(
        description="One sentence on where the agent might be deceiving itself."
    )
    objections: list[Objection] = Field(default_factory=list)
    one_more_thread: str | None = Field(
        default=None,
        description="If you had one more hour on this, what would you check?",
    )


# ---------------------------------------------------------------------------
# pivot.py  ←  framework/cognitive/pivot-protocols.md
# ---------------------------------------------------------------------------


PivotKind = Literal[
    "surface",       # same class, different surface (§ 2)
    "class",         # same surface, different class (§ 3)
    "adversary",     # what would X do here (§ 4)
    "layer",         # go up / down / sideways (§ 5)
    "time",          # historical / recent change (§ 6)
    "source",        # surgical white-box dip (§ 7)
    "tool",          # different lens (§ 8)
    "constraint",    # relax an assumption (§ 9)
    "operator",      # ask the operator (§ 10)
]


class LateralMove(BaseModel):
    kind: PivotKind
    suggestion: str
    rationale: str = Field(description="Why this is a credible next thread.")
    estimated_effort: Literal["minutes", "hours", "session"]
    confidence: float = Field(ge=0.0, le=1.0)


class PivotProposal(BaseModel):
    """Output of pivot(). Generated when a thread is stuck."""

    stuck_thread: str = Field(description="Where the operator was blocked.")
    last_observation: str
    moves: list[LateralMove] = Field(min_length=3)
    recommended: int = Field(
        ge=0, description="Index into `moves` of the highest-EV next step."
    )


# ---------------------------------------------------------------------------
# decide.py  ←  framework/cognitive/decision-frameworks.md
# ---------------------------------------------------------------------------


Severity = Literal["Critical", "High", "Medium", "Low", "Info"]
Likelihood = Literal["low", "medium", "high"]
Impact = Literal["low", "medium", "high"]
WorthReporting = Literal["finding", "engagement_log_only", "skip"]


class SeverityDecision(BaseModel):
    """Output of decide(). Wraps decision-frameworks.md § 1–3 + § 7."""

    finding_summary: str
    cvss_vector: str = Field(
        description="CVSS 3.1 vector, e.g. AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    )
    cvss_base: float = Field(ge=0.0, le=10.0)
    severity: Severity
    contextual_note: str = Field(
        description="One paragraph on why severity differs from the CVSS base."
    )
    likelihood: Likelihood
    impact: Impact
    worth_reporting: WorthReporting
    immediate_surface_to_operator: bool = Field(
        description="True if criteria from decision-frameworks.md § 6 are met."
    )
    chain_candidates: list[str] = Field(
        default_factory=list,
        description="Other findings that may chain with this one.",
    )
    regulator_paragraph: str = Field(
        description="The 'explain it to a regulator' paragraph, § 5."
    )


# ---------------------------------------------------------------------------
# opsec.py  ←  framework/cognitive/opsec-discipline.md
# ---------------------------------------------------------------------------


Posture = Literal["TEST", "AUDIT", "EMULATE"]


class OpsecGuidance(BaseModel):
    """Output of opsec(). Posture-aware guidance for a proposed action."""

    action_summary: str
    posture: Posture
    allowed: bool = Field(description="False means: do not perform this action.")
    pre_approval_required: bool
    pre_approval_reason: str | None = None
    user_agent_recommendation: str
    rate_limit_recommendation: str = Field(
        description="Concrete rate / concurrency to use."
    )
    cleanup_required: list[str] = Field(default_factory=list)
    log_to_command_log: bool = Field(default=True)
    notes: str | None = None


# ---------------------------------------------------------------------------
# threat_model.py  ←  framework/cognitive/threat-modeling.md
# ---------------------------------------------------------------------------


class Asset(BaseModel):
    """A single asset row — the §2 table of threat-modeling.md."""

    id: str = Field(description="Stable handle, A1..AN.")
    name: str
    rationale: str
    confidentiality: Literal["low", "medium", "high", "critical"]
    integrity: Literal["low", "medium", "high", "critical"]
    availability: Literal["low", "medium", "high", "critical"]
    priority: Literal["P0", "P1", "P2", "P3"]


class Actor(BaseModel):
    id: str = Field(description="Stable handle, T1..TN.")
    name: str
    goal: str
    skill: Literal["novice", "journeyman", "expert", "nation-state"]
    motivation: Literal["opportunistic", "motivated", "strategic"]
    notes: str = ""


class TrustBoundary(BaseModel):
    """A privilege crossing where bugs cluster (§ 4)."""

    name: str
    data_crossing: str
    auth_check: str
    failure_mode: str


class StrideThreat(BaseModel):
    """One STRIDE-class threat at one boundary."""

    boundary: str
    stride_class: Literal["S", "T", "R", "I", "D", "E"]
    threat: str
    realistic: bool = Field(
        description="True if a realistic adversary in scope would attempt this."
    )


class AttackTreeNode(BaseModel):
    """Recursive tree per § 6. Leaves are testable."""

    label: str
    is_leaf: bool = False
    status: Literal["?", "tested", "vulnerable", "blocked", "deferred"] = "?"
    children: list["AttackTreeNode"] = Field(default_factory=list)
    notes: str = ""


class ThreatModel(BaseModel):
    """Output of threat_model()."""

    business_context: str
    assets: list[Asset] = Field(min_length=1)
    actors: list[Actor] = Field(min_length=1)
    trust_boundaries: list[TrustBoundary] = Field(min_length=1)
    stride_threats: list[StrideThreat] = Field(default_factory=list)
    attack_tree: AttackTreeNode
    catastrophic_outcomes: list[str] = Field(
        default_factory=list,
        description="Ranked list, worst first (§ 5).",
    )
    not_in_model: list[str] = Field(
        default_factory=list,
        description="Explicit out-of-scope adversaries (§ 6).",
    )


# rebuild for forward references in AttackTreeNode
AttackTreeNode.model_rebuild()


# ---------------------------------------------------------------------------
# Common metadata returned with every URK call
# ---------------------------------------------------------------------------


class CallTrace(BaseModel):
    """Returned alongside every structured output. Provenance for MLS
    and audit; lets the operator (or a future SIL) see exactly which
    backend produced what, with which prompt size."""

    backend: str
    is_dryrun: bool
    cognitive_doc: str = Field(description="v1 source-of-truth doc cited.")
    cognitive_sections: list[str] = Field(
        default_factory=list, description="Anchors of doc sections used."
    )
    tokens_in: int = 0
    tokens_out: int = 0
    latency_ms: float = 0.0
    timestamp: str = ""
