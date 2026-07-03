"""
verify.models — Pydantic schemas for the deterministic verification layer.

Four shapes matter:

  OracleProbe          a passive description of what an oracle needs to
                       compare or observe. It names inputs abstractly
                       (references to already-collected responses/state,
                       a correlation token, a discriminator spec). It does
                       NOT generate payloads and it does NOT send traffic.
  OracleSignal         the verdict of one oracle over already-observed
                       data: did a real signal fire, how confident, and
                       the evidence that justifies it.
  VerificationResult   the aggregate: confirmed only when >=1 high-
                       confidence oracle fired, with every signal retained
                       for audit and a plain-language rationale.

Nothing here sends traffic or makes an LLM call. These are pure, validated
data shapes. The oracle logic lives in oracles.py; the out-of-band receiver
lives in oob.py; the dispatcher lives in verifier.py.
"""

from __future__ import annotations

import enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class OracleKind(str, enum.Enum):
    """The family of deterministic signal a finding can be confirmed by.

    Each kind maps to one pure oracle in oracles.py (plus the out-of-band
    receiver in oob.py for OOB_CALLBACK). A finding is confirmed by a real
    signal, never by an assertion."""

    DIFFERENTIAL_RESPONSE = "differential_response"  # boolean/time-based blind
    ACHIEVED_STATE = "achieved_state"                # unauthorized state reached
    SIDE_EFFECT = "side_effect"                       # unique marker reached a sink
    OOB_CALLBACK = "oob_callback"                     # blind out-of-band interaction
    SANITIZER_SIGNAL = "sanitizer_signal"             # ASAN/UBSAN/panic/traceback


class OracleProbe(BaseModel):
    """A passive, abstract description of what an oracle must compare.

    This is deliberately not a payload. It names *what to look at* — which
    already-collected responses, which expected state, which correlation
    token — so a caller can wire observed data into the right oracle. The
    verification layer is a judge of collected evidence, not a sender."""

    model_config = ConfigDict(extra="forbid")

    kind: OracleKind
    description: str = Field(
        default="",
        description="Human-readable statement of the signal being probed for.",
    )
    inputs: dict[str, Any] = Field(
        default_factory=dict,
        description="Abstract references to observed data the oracle consumes "
        "(e.g. {'baseline_ref': 'resp_A', 'mutated_ref': 'resp_B'}). Never a payload.",
    )
    discriminator: dict[str, Any] | None = Field(
        default=None,
        description="Optional comparison spec for the differential oracle "
        "(dimensions, thresholds, markers, expect).",
    )
    correlation_token: str | None = Field(
        default=None,
        description="For OOB_CALLBACK: the unique token minted by the oob receiver.",
    )


class OracleSignal(BaseModel):
    """The verdict of a single oracle over already-observed data."""

    model_config = ConfigDict(extra="forbid")

    kind: OracleKind
    fired: bool = Field(description="True iff a real signal was detected.")
    confidence: float = Field(
        ge=0.0,
        le=1.0,
        description="Calibrated strength of the signal. High-confidence "
        "(>= the verifier threshold) fired signals are what confirm a finding.",
    )
    evidence: str = Field(
        default="",
        description="The concrete artifact justifying the verdict — the "
        "matched marker, the diverging dimensions, the crash line, the hit.",
    )
    observed: dict[str, Any] = Field(
        default_factory=dict,
        description="Structured detail of what was observed, for the audit trail.",
    )


class VerificationResult(BaseModel):
    """The aggregate verdict for one finding.

    `confirmed` is True only when at least one oracle fired at or above the
    verifier's high-confidence threshold. Every signal — fired or not — is
    retained so the decision is reconstructable."""

    model_config = ConfigDict(extra="forbid")

    confirmed: bool
    bug_class: str = Field(default="", description="The class the finding claimed.")
    signals: list[OracleSignal] = Field(default_factory=list)
    combine_policy: str = Field(
        default="any_high_confidence_fired",
        description=(
            "How multiple applicable oracles were combined into `confirmed`. "
            "'any_high_confidence_fired' is safety-monotone: one deterministic "
            "oracle firing at/above the threshold is sufficient proof, and a "
            "non-firing oracle CANNOT veto a fired one (absence of a signal is "
            "not evidence of absence). A disagreeing oracle is recorded as "
            "dissent, never treated as a refutation."
        ),
    )
    dissent: list[str] = Field(
        default_factory=list,
        description=(
            "When the finding was confirmed, the applicable oracle kinds that "
            "RAN over observed data but did not confirm (did not fire, or fired "
            "below the threshold) — the recorded disagreement among oracles. "
            "Empty when a lone oracle confirmed or when nothing confirmed."
        ),
    )
    rationale: str = Field(
        default="",
        description="Plain-language account of why the finding was or was not confirmed.",
    )

    @property
    def confirming_signals(self) -> list[OracleSignal]:
        """The fired signals; the subset that carried the confirmation."""
        return [s for s in self.signals if s.fired]
