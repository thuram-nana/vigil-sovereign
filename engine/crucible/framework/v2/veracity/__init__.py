"""
framework.v2.veracity — the system-wide anti-hallucination firewall.

One invariant, enforced by re-execution: no claim reaches an operator, a report, the
world-model, or a decision unless it carries a `GroundingToken` that resolves — at
admission time, by re-running the cited proof — to a fired oracle, a signed+reproducing
evidence certificate, a belief-floored world-model fact, or a gated prior-capped
hypothesis. Anything else is stamped UNGROUNDED and rendered as labelled commentary,
never as fact. The layer only demotes or abstains; it can never promote a claim the
oracle refused. Tokens are unforgeable because a `provenance='llm-said-so'` string cannot
survive re-execution.

Reuses the platform's existing authorities as validators: `verify.reverify`,
`evidence.verify_certificate`, the world-model Beta belief (`belief_lcb`), and the gated
`intel.predict.AssetHypothesis`.
"""

from .tokens import Ground, GroundingToken
from .claims import AdmittedClaim, Claim, VeracityVerdict
from .consistency import contradicts
from .firewall import admit
from .adapters import admit_finding, claim_from_finding

__all__ = [
    "Ground", "GroundingToken",
    "Claim", "AdmittedClaim", "VeracityVerdict",
    "contradicts", "admit",
    "admit_finding", "claim_from_finding",
]
