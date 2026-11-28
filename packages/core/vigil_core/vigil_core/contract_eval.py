"""AEGIS AS-4b — the protection-contract EVALUATOR + the customer-facing enforce/observe PREVIEW.

AS-2b (:mod:`vigil_core.protection_contract`) ships the full, read-only protection-contract SCHEMA and
says, in its own docstring, that **AS-4b ships the evaluator that FILLS and GRADES it**: a consumer
"computes the headline as the floor of the dimensions" and "AS-4b/AS-29 compute ``effective``". This
module is that evaluator, plus the smallest coherent customer-facing increment the "contract + preview"
slice names — a READ-ONLY PREVIEW of what a defence/enforce contract WOULD do for a host, grounded only
in already-verified inputs, before anything is armed.

Doctrine (inherited from :mod:`vigil_core.protection_contract` / :mod:`vigil_core.aegis_schemas`):

  * READ-ONLY / NEVER AUTHORITY — every function here only READS and GRADES already-verified state. It
    signs nothing, mints nothing, arms nothing, and cannot raise anyone's authority. A preview is a
    snapshot a renderer reads; releasing a host into enforce stays behind the AS-29 owner-signed gate.
  * FAIL-CLOSED — the headline is the FLOOR of the six dimensions (the weakest axis caps the claim);
    ``effective`` enforcement is the AND of every term and defaults ``False``; a preview claims enforce
    is PERMITTED only when every precondition the sovereign would re-check holds, and names an honest
    blocker otherwise. A missing input reads as "less protection", never "more".
  * HONESTY — the preview states only what the inputs support. "What enforce would add" is derived from
    the provider registry's own declared outcome classes (never a hard-coded claim), so a provider slice
    that has not shipped cannot make the preview promise an outcome it cannot reach.
  * DETERMINISM — no wallclock, no RNG; set-valued outputs are sorted + de-duplicated.

FATAL-2: imports only ``vigil_core`` siblings + stdlib + pydantic. No ``framework``, no ``sigil``.
"""
from __future__ import annotations

from typing import Final, Iterable

from pydantic import ConfigDict, Field, field_validator

from .aegis_schemas import CanonicalModel, OutcomeClass
from .authority_v2 import check_dns_host
from .monitoring_authority import MonitoringMode
from .protection_contract import (
    Dimensions,
    EnforcementTerms,
    Headline,
    ProtectionContract,
    ProviderRegistry,
    ReleaseState,
    baseline_provider_registry,
)

# The Headline ladder, weakest → strongest (§4.5). The order is load-bearing: the headline is the FLOOR
# (the weakest rung reached by any of the six dimensions), so a single unsupported axis caps the claim.
HEADLINE_LADDER: Final[tuple[Headline, ...]] = (
    Headline.UNSUPPORTED,
    Headline.INACTIVE,
    Headline.DEGRADED,
    Headline.UNVERIFIED,
    Headline.OBSERVING,
    Headline.ENFORCING,
)
_RANK: Final[dict[Headline, int]] = {h: i for i, h in enumerate(HEADLINE_LADDER)}

# The fixed coverage limitation the gateway is honest about — what is NOT inspected (§4.5 ``not_observed``:
# "direct-to-origin, cache hits, chunked, >2 MiB, multipart, websocket, non-HTTP"). A preview surfaces it so
# the customer never reads "enforcing" as "everything is covered". Tokens (safe path components); the renderer
# maps them to copy.
NOT_OBSERVED_BASELINE: Final[tuple[str, ...]] = (
    "direct_to_origin",
    "cache_hits",
    "chunked",
    "over_2_mib",
    "multipart",
    "websocket",
    "non_http",
)

# The honest blocker vocabulary a preview names when enforce is NOT permitted. Closed set; fail-closed.
BLOCKER_RESPOND_NOT_IN_PLAN: Final[str] = "respond_not_in_plan"
BLOCKER_PROOF_LAPSED: Final[str] = "proof_lapsed"
BLOCKER_ALREADY_ENFORCING: Final[str] = "already_enforcing"
BLOCKER_NOT_ARMED: Final[str] = "not_armed"


# --- the general grading (what AS-2b's docstring names AS-4b) -------------------------------------------------
def headline_floor(levels: Iterable[Headline]) -> Headline:
    """The FLOOR of a set of :class:`Headline` levels on the ladder — the weakest rung any of them reached.
    An empty set is the fail-closed floor ``unsupported`` (claim nothing)."""
    ranks = [_RANK[h] for h in levels]
    if not ranks:
        return Headline.UNSUPPORTED
    return HEADLINE_LADDER[min(ranks)]


def grade_headline(dimensions: Dimensions) -> Headline:
    """The contract headline: the FLOOR of the six posture dimensions (§4.5 "the headline is their floor").
    A single ``unsupported`` axis caps the whole claim at ``unsupported`` (fail-closed)."""
    return headline_floor(
        (
            dimensions.asset_placement,
            dimensions.edge,
            dimensions.origin_lock,
            dimensions.telemetry,
            dimensions.detection_enforcement,
            dimensions.authority_release,
        )
    )


def enforcement_reasons(terms: EnforcementTerms) -> tuple[str, ...]:
    """The SORTED tokens naming every term that currently WITHHOLDS enforcement — fail-closed: enforcement
    is the AND of many terms, so any unmet term is a reason it is not effective. Empty iff every term holds."""
    out: list[str] = []
    if not terms.grant_block:
        out.append("grant_not_block")
    if terms.enforce_release.state is not ReleaseState.RELEASED:
        out.append("not_released")
    if not terms.flag:
        out.append("flag_off")
    if terms.mode is not MonitoringMode.BLOCK:
        out.append("mode_not_block")
    if not terms.entitlement:
        out.append("not_entitled")
    if terms.kill_switch_tripped:
        out.append("kill_switch_tripped")
    if terms.override_active:
        out.append("override_active")
    return tuple(sorted(out))


def grade_enforcement(terms: EnforcementTerms) -> EnforcementTerms:
    """Return a COPY of ``terms`` with ``effective`` and ``reasons`` COMPUTED (the §4.5 / AS-29 computation):
    ``effective`` is the fail-closed AND of every enforcement term, and ``reasons`` names what withholds it
    (empty iff effective). Read-only: the input is never mutated."""
    reasons = enforcement_reasons(terms)
    return terms.model_copy(update={"effective": not reasons, "reasons": list(reasons)})


def grade_contract(contract: ProtectionContract) -> ProtectionContract:
    """FILL + GRADE a protection contract (AS-2b docstring: "AS-4b ships the evaluator that FILLS and GRADES
    it"): return a COPY whose ``enforcement_terms`` is graded (``effective`` + ``reasons`` computed) and whose
    ``headline`` is the floor of its six dimensions. Read-only — the input contract is never mutated, and
    nothing here signs or arms anything."""
    return contract.model_copy(
        update={
            "enforcement_terms": grade_enforcement(contract.enforcement_terms),
            "headline": grade_headline(contract.dimensions),
        }
    )


# --- the customer-facing enforce/observe preview -------------------------------------------------------------
def _outcome_split(registry: ProviderRegistry) -> tuple[tuple[OutcomeClass, ...], tuple[OutcomeClass, ...]]:
    """From the provider registry, the (OBSERVE, ENFORCE-ADDS) outcome classes, DERIVED from the providers'
    OWN declared capabilities (never hard-coded): OBSERVE is what detect/alert reaches (class 5,
    ``detected_without_enforcement``); ENFORCE-ADDS is every other outcome class the registry reaches — what
    releasing to enforce would ADD beyond observe. Both sorted by value, de-duplicated (determinism). A later
    provider slice that appends a stronger capability extends the enforce set here without editing this file."""
    observe: set[OutcomeClass] = set()
    enforce: set[OutcomeClass] = set()
    for prov in registry.providers:
        for cap in prov.capabilities:
            if cap.outcome_class is OutcomeClass.DETECTED_WITHOUT_ENFORCEMENT:
                observe.add(cap.outcome_class)
            else:
                enforce.add(cap.outcome_class)
    observe_sorted = tuple(sorted(observe, key=lambda c: c.value))
    enforce_sorted = tuple(sorted(enforce - observe, key=lambda c: c.value))
    return observe_sorted, enforce_sorted


class HostProtectionPreview(CanonicalModel):
    """A READ-ONLY, per-host projection of what AEGIS does now (observe) and what releasing to enforce WOULD
    add — a protection-contract preview grounded only in already-verified inputs. It is NEVER authority:
    nothing here arms a host; ``enforce_permitted`` only states whether the AS-29 release gate WOULD admit a
    release right now, and ``enforce_blockers`` names, honestly, why not. Fail-closed: ``enforce_permitted``
    defaults ``False`` and the headline defaults to the floor.

    ``observe_outcomes`` is a LIVE claim — the detection AEGIS performs RIGHT NOW — so it is only non-empty for
    a host that is actually armed (a live monitoring grant). A proven-but-unarmed host is not monitored, so it
    claims NO live detection; what arming it WOULD make live is carried, honestly, in ``observe_adds_outcomes``
    (availability-first: "would be detected once monitoring is armed", never "is detected now")."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    host: str
    headline: Headline = Field(default=Headline.UNSUPPORTED)
    mode: MonitoringMode = Field(default=MonitoringMode.OBSERVE)
    armed: bool = Field(default=False)
    proof_current: bool = Field(default=False)
    respond_entitled: bool = Field(default=False)
    observe_outcomes: tuple[OutcomeClass, ...] = Field(default_factory=tuple)
    observe_adds_outcomes: tuple[OutcomeClass, ...] = Field(default_factory=tuple)
    enforce_adds_outcomes: tuple[OutcomeClass, ...] = Field(default_factory=tuple)
    enforce_permitted: bool = Field(default=False)
    enforce_blockers: tuple[str, ...] = Field(default_factory=tuple)
    not_observed: tuple[str, ...] = Field(default_factory=lambda: NOT_OBSERVED_BASELINE)

    @field_validator("host")
    @classmethod
    def _host(cls, v: str) -> str:
        return check_dns_host(v, label="preview.host")   # a bare DNS host (the same shape the grant declares); IP literals refused

    def customer_safe(self) -> dict:
        """The customer-plane projection the edge returns over the hop: enum values, booleans and token lists
        only — no secret, no internal id, nothing a host does not already see on the Monitoring screen."""
        return {
            "host": self.host,
            "headline": self.headline.value,
            "mode": self.mode.value,
            "armed": self.armed,
            "proof_current": self.proof_current,
            "respond_entitled": self.respond_entitled,
            "observe_outcomes": [c.value for c in self.observe_outcomes],
            "observe_adds_outcomes": [c.value for c in self.observe_adds_outcomes],
            "enforce_adds_outcomes": [c.value for c in self.enforce_adds_outcomes],
            "enforce_permitted": self.enforce_permitted,
            "enforce_blockers": list(self.enforce_blockers),
            "not_observed": list(self.not_observed),
        }


def preview_host(
    host: str,
    *,
    mode: MonitoringMode,
    armed: bool,
    proof_current: bool,
    respond_entitled: bool,
    registry: ProviderRegistry | None = None,
) -> HostProtectionPreview:
    """Grade, read-only, what AEGIS does for ``host`` now and what releasing it to enforce would add — from
    already-verified inputs (the host's armed mode, whether its ownership proof is current, whether the plan
    entitles Respond). ``registry`` defaults to the baseline SIGIL provider registry.

    The headline is honest and grounded: a host that is not armed reads ``inactive``; an armed host whose proof
    lapsed reads ``unverified`` (a tenant-side proof is missing — it caps the claim and blocks a release); an
    armed observe host reads ``observing``; an armed block host with a current proof reads ``enforcing``.

    ``enforce_permitted`` is the AS-29 release gate as a PREVIEW, never an action: a release would be admitted
    only for an armed, Respond-entitled host whose proof is current and that is still in the always-safe Observe
    base. ``enforce_blockers`` names, in a closed honest vocabulary, every reason it would not.

    HONESTY — live detection is a LIVE claim, not a capability advert: ``observe_outcomes`` (what AEGIS detects
    NOW) is non-empty ONLY for an armed host. A proven-but-unarmed host is not monitored, so it claims no live
    detection; the detection arming it WOULD make live is surfaced in ``observe_adds_outcomes`` instead (the
    renderer reads it as "would be detected once monitoring is armed")."""
    reg = registry if registry is not None else baseline_provider_registry()
    detect_outcomes, enforce_adds = _outcome_split(reg)
    # LIVE claim: detection is only in effect for a host that is actually armed (a live monitoring grant). An
    # unarmed host is not monitored — it claims NO live detection; arming it is what WOULD make detection live.
    observe_outcomes = detect_outcomes if armed else ()
    observe_adds = () if armed else detect_outcomes

    if not armed:
        headline = Headline.INACTIVE
    elif not proof_current:
        headline = Headline.UNVERIFIED
    elif mode is MonitoringMode.BLOCK:
        headline = Headline.ENFORCING
    else:
        headline = Headline.OBSERVING

    blockers: list[str] = []
    if not respond_entitled:
        blockers.append(BLOCKER_RESPOND_NOT_IN_PLAN)
    if not armed:
        blockers.append(BLOCKER_NOT_ARMED)
    elif not proof_current:
        blockers.append(BLOCKER_PROOF_LAPSED)
    elif mode is MonitoringMode.BLOCK:
        blockers.append(BLOCKER_ALREADY_ENFORCING)
    permitted = not blockers

    return HostProtectionPreview(
        host=host,
        headline=headline,
        mode=mode,
        armed=armed,
        proof_current=proof_current,
        respond_entitled=respond_entitled,
        observe_outcomes=observe_outcomes,
        observe_adds_outcomes=observe_adds,
        enforce_adds_outcomes=enforce_adds,
        enforce_permitted=permitted,
        enforce_blockers=tuple(sorted(blockers)),
        not_observed=NOT_OBSERVED_BASELINE,
    )


__all__ = [
    "HEADLINE_LADDER",
    "NOT_OBSERVED_BASELINE",
    "BLOCKER_RESPOND_NOT_IN_PLAN",
    "BLOCKER_PROOF_LAPSED",
    "BLOCKER_ALREADY_ENFORCING",
    "BLOCKER_NOT_ARMED",
    "headline_floor",
    "grade_headline",
    "enforcement_reasons",
    "grade_enforcement",
    "grade_contract",
    "HostProtectionPreview",
    "preview_host",
]
