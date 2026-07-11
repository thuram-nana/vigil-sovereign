"""
aegis.models — the typed surface of the defensive dual.

Every shape here is pydantic ``extra="forbid"`` so a malformed or over-broad input is
rejected at parse, and the load-bearing honesty properties are enforced by construction:

  * ``Verdict.decision`` is a three-valued ``Literal`` — NEVER a bare boolean. "clear" is
    "no oracle fired and signals below band", NOT "safe".
  * ``Verdict.attack_class`` is a ``KnownBugClass`` (verify's value-membership validator), so
    a hallucinated class is parse-rejected — an AI-attack label can never be invented.
  * ``Verdict.certificate is not None`` IFF ``decision == "confirmed"`` (a model validator),
    and the certificate is the retained, offline-re-runnable oracle evidence.

These are pure data shapes; the detection logic lives in ``pipeline.py``.
"""

from __future__ import annotations

import enum
import hashlib
import json
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from ..verify.verifier import KnownBugClass


def _canonical_json(obj: Any) -> str:
    """Deterministic canonical JSON (sorted keys, compact) — the same discipline the
    evidence layer and the reverify cache key use. No wallclock, no rng."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


class Surface(str, enum.Enum):
    """Which telemetry surface an envelope carries. MVP ships LLM (class 1) and REQUEST
    (the honeypot tripwire, class 4-confirmed). AUTH/CONTENT are declared for the roadmap
    but carry no MVP oracle."""

    LLM = "llm"            # the app's own LLM I/O (prompt-injection / system-prompt disclosure)
    REQUEST = "request"    # in-request-path metadata (the honeypot tripwire)
    AUTH = "auth"          # auth-outcome telemetry (credential-stuffing / ATO — SPRT + Holm confirmed)
    CONTENT = "content"    # roadmap: stored/indirect injection (LEAD-only in the MVP)


class ActorRef(BaseModel):
    """A reference to the external actor an observation is ABOUT.

    UNTRUSTED / SPOOFABLE by construction (X-Forwarded-For, session fixation, a submitted
    username) — documented so no enforce action is ever keyed on it without a confirmed
    certificate (doctrine D1, roadmap). Identifiers here are pseudonymised at the ingest
    boundary (keyed HMAC + /24 IP coarsening, PR2) before they reach the world-model."""

    model_config = ConfigDict(extra="forbid")

    ip: str = Field(default="", description="Source IP (raw at the edge; HMAC'd /24 after boundary).")
    session: str = Field(default="", description="Session id (raw at the edge; HMAC'd after boundary).")
    principal: str = Field(default="", description="Authenticated principal (raw at edge; HMAC'd after boundary).")

    @property
    def stable_key(self) -> str:
        """A deterministic, order-stable actor key from the most-specific available id. Pure."""
        parts = [p for p in (self.principal, self.session, self.ip) if p]
        return ":".join(parts) if parts else "anon"

    @property
    def node_id(self) -> str:
        """The world-model node id (NodeKind.SESSION) this actor projects onto."""
        return f"session:{self.stable_key}"


class LLMInteraction(BaseModel):
    """One turn of the app's OWN LLM feature (class 1). The app controls both ends, so a
    planted canary + a control-vs-treatment behavior obs make injection provable."""

    model_config = ConfigDict(extra="forbid")

    system_prompt_id: str = ""
    canary: str | None = Field(default=None, description="The planted high-entropy sentinel (from the guard).")
    user_input: str = Field(default="", description="The untrusted user turn.")
    llm_output: str = Field(default="", description="The model's response (PII-redacted at the boundary).")
    # control-vs-treatment behavior observations (the ONLY path that earns `prompt_injection`).
    control_behavior: dict[str, Any] | None = None
    treatment_behavior: dict[str, Any] | None = None


class AuthEvent(BaseModel):
    """One auth-attempt outcome. Identifiers are RAW at the edge and keyed-HMAC pseudonymised at
    the ingest boundary (PR2) before they reach the world-model / a certificate — no raw
    username or IP ever survives into the retained oracle evidence."""

    model_config = ConfigDict(extra="forbid")

    account: str = Field(default="", description="Targeted account/username (raw at edge; HMAC'd after boundary).")
    source: str = Field(default="", description="Credential source / origin (raw at edge; coarsened+HMAC'd after boundary). Empty → the actor.")
    success: bool = Field(default=False, description="Whether the authentication attempt succeeded.")


class AuthActivity(BaseModel):
    """The AUTH-surface payload: an ORDERED window of the actor's recent auth outcomes (bounded at
    the boundary), plus the operator's known-good egress allowlist. Credential stuffing / ATO is
    confirmed only when a source's UNSEEN-(account, source) SUCCESSES cross the SPRT AND survive
    the Holm family-wise control; a failed-only burst (NAT/CGNAT bulk) confirms nothing."""

    model_config = ConfigDict(extra="forbid")

    events: list[AuthEvent] = Field(default_factory=list, description="Ordered auth-outcome window.")
    benign_sources: list[str] = Field(
        default_factory=list,
        description="Operator known-good egress identities (raw at edge; pseudonymised) whose successes REFUTE.")


class TelemetryEnvelope(BaseModel):
    """The bounded, safe-parsed unit the SDK/HTTP boundary ingests. ``extra='forbid'`` means
    an unknown key is a parse rejection (fail-closed)."""

    model_config = ConfigDict(extra="forbid")

    surface: Surface
    actor: ActorRef = Field(default_factory=ActorRef)
    seq: int = Field(ge=0, description="Caller-supplied MONOTONIC sequence — never wallclock.")
    requested_path: str | None = Field(default=None, description="REQUEST surface: the fetched path.")
    llm: LLMInteraction | None = Field(default=None, description="LLM surface: the interaction.")
    auth: AuthActivity | None = Field(default=None, description="AUTH surface: the auth-outcome window.")


class BeliefRef(BaseModel):
    """The per-actor Beta posterior — the thing a scalar risk score structurally cannot
    express. ``lcb`` (lower credible bound) keeps a thinly-evidenced actor below a proven one."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    mean: float
    lcb: float
    n_observations: int


class CertRef(BaseModel):
    """A confirmed detection's certificate: the retained oracle evidence, offline-re-runnable
    with no app and zero trust in AEGIS. ``cert_id`` is a deterministic content hash, so the
    same evidence always mints the same id (the determinism invariant).

    PR1 (honest retention): for class 1 the ``oracle_context`` retains the random sentinel and
    a bounded, boundary-redacted matched span in PLAINTEXT — because the reverify contract
    re-fires on verbatim substrings. This is a dedicated random token, never proprietary
    prompt text and never raw PII; the "only hashes survive" claim does NOT hold for class 1
    and we say so."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    cert_id: str
    bug_class: str
    confirmed_by: str
    confidence: float
    oracle_context: dict[str, Any]

    @classmethod
    def mint(cls, oracle_context: dict[str, Any], *, bug_class: str,
             confirmed_by: str, confidence: float) -> "CertRef":
        digest = hashlib.sha256(
            _canonical_json({"oracle_context": oracle_context, "bug_class": bug_class}).encode("utf-8")
        ).hexdigest()[:16]
        return cls(cert_id=f"aegis-cert:{digest}", bug_class=bug_class,
                   confirmed_by=confirmed_by, confidence=confidence, oracle_context=dict(oracle_context))

    def reverify(self) -> bool:
        """Re-run the deterministic oracle over the retained evidence with the DEFAULT verifier
        (no app) — the offline replay anyone can perform. True iff it re-confirms and matches."""
        from ..verify.reverify import reverify_context
        r = reverify_context(self.oracle_context, bug_class=self.bug_class,
                             claimed_confirmed_by=self.confirmed_by,
                             claimed_confidence=self.confidence)
        return r.ok


class RefuteChannel(BaseModel):
    """How an operator/end-user disputes a verdict — the refutation channel that feeds
    ``credit_outcome``. The ``dismiss_token`` is a deterministic function of the verdict, so
    the same evidence mints the same token."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    how_to_dispute: str
    dismiss_token: str


class Verdict(BaseModel):
    """The honest-by-construction output. Frozen; ``extra='forbid'``.

    Invariants (enforced below):
      * ``decision == "confirmed"``  ⇔  ``certificate is not None``.
      * a confirmed verdict's ``provenance`` is the ``grounded:`` tier (an oracle fired +
        was admitted by the veracity firewall); a lead's is the ``intel:`` tier.
    ``decision == "clear"`` is NOT "safe" — it is "no oracle fired and signals below band"."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    decision: Literal["confirmed", "lead", "clear"]
    attack_class: KnownBugClass
    confidence: float = 0.0
    belief: BeliefRef | None = None
    band: tuple[float, float] | None = None
    top_alternative: tuple[str, float] | None = None
    certificate: CertRef | None = None
    provenance: str = ""
    action: Literal["allow", "observe", "challenge", "throttle", "block"] = "observe"
    refutation: RefuteChannel | None = None
    contributing: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def _check_invariants(self) -> "Verdict":
        if self.decision == "confirmed" and self.certificate is None:
            raise ValueError("decision=='confirmed' requires a certificate (the offline-re-runnable proof)")
        if self.decision != "confirmed" and self.certificate is not None:
            raise ValueError("only a confirmed verdict may carry a certificate")
        return self


class AegisConfig(BaseModel):
    """Per-deployment configuration. ``deployment_secret`` keys the identifier HMAC (PR2)."""

    model_config = ConfigDict(extra="forbid")

    deployment_secret: str = Field(min_length=1, description="Per-deployment HMAC key for identifier pseudonymisation (PR2).")
    mode: Literal["observe", "enforce"] = "observe"       # default READ-ONLY
    max_envelope_bytes: int = Field(default=65536, gt=0)
    max_depth: int = Field(default=16, gt=0)
    max_field_chars: int = Field(default=8192, gt=0)
    max_auth_events: int = Field(default=4096, gt=0, description="Bounded AUTH-window size (DoS-safe replay).")
    honeypot_paths: list[str] = Field(default_factory=list)
    crawler_allowlist: list[str] = Field(default_factory=list, description="Known-good crawler/monitor tokens whose fetches REFUTE.")

    @classmethod
    def from_mapping(cls, data: dict[str, Any]) -> "AegisConfig":
        return cls.model_validate(dict(data or {}))
