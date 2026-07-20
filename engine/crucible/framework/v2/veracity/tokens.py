"""
veracity.tokens — the grounding token: the ONLY currency that lets a claim be real.

A `GroundingToken` names ONE of the four legitimate grounds a claim may cite, and — the
load-bearing property — it carries the DATA needed to RE-VALIDATE that ground by
re-execution, never a string to trust:

  * ORACLE     → the retained ``oracle_context`` (re-fired by verify.reverify)
  * CERT       → a serialized ``SignedEvidence`` (re-checked by evidence.verify_certificate)
  * WORLDMODEL → a node/edge id (looked up + belief-floored + its provenance must itself resolve)
  * HYPOTHESIS → a gated, prior-capped hypothesis (a LABELLED guess, never a fact)

Unforgeability is the whole point: because a token is validated by re-running the cited
proof, a ``provenance='llm-said-so'`` string cannot mint one. A token whose backing LLM
call was a dry-run carries ``from_dryrun=True`` and can never ground on its own.
"""

from __future__ import annotations

import enum

from pydantic import BaseModel, ConfigDict, Field


class Ground(str, enum.Enum):
    ORACLE = "oracle"           # re-fired oracle over a retained oracle_context
    CERT = "cert"               # signed, reproducing evidence certificate
    WORLDMODEL = "worldmodel"   # a graph node/edge whose belief traces to ORACLE/CERT
    HYPOTHESIS = "hypothesis"   # a gated, prior-capped labelled hypothesis (never a fact)


# The strength ordering: which grounds carry FACT strength vs merely labelled-hypothesis.
_FACT_GROUNDS = frozenset({Ground.ORACLE, Ground.CERT, Ground.WORLDMODEL})


class GroundingToken(BaseModel):
    """One citation, carrying the re-validation payload for its ground. Constructed via
    the classmethods so each ground gets exactly the fields its validator needs."""

    model_config = ConfigDict(extra="forbid")

    ground: Ground
    ref: str = ""                         # human-readable reference (for reasons/audit)
    from_dryrun: bool = False             # backing LLM call was a dry-run → cannot ground alone

    # ORACLE payload
    oracle_context: dict | None = None
    bug_class: str = ""
    claimed_confirmed_by: str | None = None
    claimed_confidence: float | None = None

    # CERT payload — a serialized evidence.SignedEvidence (+ the context it authenticates)
    signed_evidence: dict | None = None

    # WORLDMODEL payload
    node_id: str = ""

    # HYPOTHESIS payload
    gated: bool | None = None
    prior: float | None = Field(default=None, ge=0.0, le=1.0)

    @property
    def is_fact_ground(self) -> bool:
        return self.ground in _FACT_GROUNDS

    # -- constructors ---------------------------------------------------------

    @classmethod
    def oracle(cls, oracle_context: dict, *, bug_class: str,
               confirmed_by: str | None = None, confidence: float | None = None,
               from_dryrun: bool = False, ref: str = "") -> "GroundingToken":
        return cls(ground=Ground.ORACLE, oracle_context=oracle_context, bug_class=bug_class,
                   claimed_confirmed_by=confirmed_by, claimed_confidence=confidence,
                   from_dryrun=from_dryrun, ref=ref or bug_class)

    @classmethod
    def cert(cls, signed_evidence: dict, *, oracle_context: dict | None = None,
             ref: str = "") -> "GroundingToken":
        return cls(ground=Ground.CERT, signed_evidence=signed_evidence,
                   oracle_context=oracle_context, ref=ref)

    @classmethod
    def worldmodel(cls, node_id: str, *, ref: str = "") -> "GroundingToken":
        return cls(ground=Ground.WORLDMODEL, node_id=node_id, ref=ref or node_id)

    @classmethod
    def hypothesis(cls, *, gated: bool, prior: float, ref: str = "",
                   from_dryrun: bool = False) -> "GroundingToken":
        return cls(ground=Ground.HYPOTHESIS, gated=gated, prior=prior, ref=ref,
                   from_dryrun=from_dryrun)
