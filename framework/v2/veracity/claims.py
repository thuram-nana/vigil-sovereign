"""
veracity.claims — the typed claim + the verdict of admitting it.

A `Claim` is any assertion the system might act on or show: an LLM critique verdict, a
world-model write, a report sentence, an SCE evidence datum. It carries the grounding
tokens that (may) back it and the entities it names. `admit()` turns it into an
`AdmittedClaim` whose verdict is one of four — GROUNDED (fact- or hypothesis-strength),
UNGROUNDED, CONTRADICTED, or ABSTAIN — and which NEVER silently becomes a fact: an
ungrounded claim is stamped, not dropped, so the operator loses framing, never information.

Distinct-by-design from ``evidence/claims.py`` (do NOT merge — different layer, same name):
that module owns no claim type at all — it decomposes a finding's report prose into
``ReportClaim`` objects (defined in ``evidence/models.py``) for binding into a signed
certificate. The dependency is one-directional: the evidence layer sits ON TOP of this one —
``evidence/certify.py::_claims_grounded`` builds a veracity ``Claim`` from each fact-labelled
``ReportClaim`` and re-admits it through ``admit()`` here. This module never imports evidence.
"""

from __future__ import annotations

import enum

from pydantic import BaseModel, ConfigDict, Field

from .tokens import Ground, GroundingToken


class VeracityVerdict(str, enum.Enum):
    GROUNDED = "grounded"         # at least one ground validated by re-execution
    UNGROUNDED = "ungrounded"     # no ground resolved — labelled commentary, never fact
    CONTRADICTED = "contradicted" # asserts against an established higher-belief fact
    ABSTAIN = "abstain"           # too uncertain to assert (e.g. high semantic entropy)


class Claim(BaseModel):
    """An assertion presented for admission."""

    model_config = ConfigDict(extra="forbid")

    text: str = ""
    source: str = ""                                   # e.g. "llm:critique", "scanner", "intel:infer"
    # the STRUCTURED subject the claim asserts — what a ground must be BOUND to. A ground
    # backs the claim only if it proves THIS subject: an oracle must re-fire for this
    # bug_class, a cert must certify it, a world-model node must be named in entity_refs.
    bug_class: str = ""
    tokens: list[GroundingToken] = Field(default_factory=list)
    entity_refs: list[str] = Field(default_factory=list)   # world-model node ids this claim names
    proposed_confidence: float | None = Field(default=None, ge=0.0, le=1.0)
    from_dryrun: bool = False                          # the whole claim originated in a dry-run call


class AdmittedClaim(BaseModel):
    """The firewall's verdict on one claim. ``is_fact`` is the single thing every
    downstream consumer keys on: only a fact-strength grounded claim may render as fact."""

    model_config = ConfigDict(extra="forbid")

    claim: Claim
    verdict: VeracityVerdict
    strength: Ground | None = None                     # the strongest ground that resolved
    calibrated_confidence: float | None = None
    grounded_by: list[str] = Field(default_factory=list)  # which grounds resolved (audit)
    reason: str = ""

    @property
    def is_fact(self) -> bool:
        """True only if the claim is grounded at FACT strength (oracle / cert / belief).
        A gated hypothesis is GROUNDED but NOT a fact; ungrounded/contradicted are never."""
        return (self.verdict is VeracityVerdict.GROUNDED
                and self.strength is not None and self.strength in
                (Ground.ORACLE, Ground.CERT, Ground.WORLDMODEL))

    @property
    def is_hypothesis(self) -> bool:
        return self.verdict is VeracityVerdict.GROUNDED and self.strength is Ground.HYPOTHESIS

    @property
    def render_as(self) -> str:
        """How a report should present it."""
        if self.is_fact:
            return "fact"
        if self.is_hypothesis:
            return "hypothesis"
        if self.verdict is VeracityVerdict.CONTRADICTED:
            return "contradicted"
        return "analyst-commentary"   # ungrounded / abstain — shown, labelled, never as fact
