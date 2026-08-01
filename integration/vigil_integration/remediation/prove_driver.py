"""remediation.prove_driver — the ``vigil remediate --prove`` orchestrator (VF-1a).

A NARROW protocol orchestrator (deliberately NOT a generalized agent loop) that turns "we patched it" into a
signed, FOUR-STATE statement about the FRESH behaviour of a real authorized target. It composes the merged VF
foundation — the RemediationCertificate + controls, the owner-attested identity, the capability chain + proof
of possession — into one gated flow and classifies the result into exactly one of:

    REMEDIATED · STILL_VULNERABLE · INCONCLUSIVE · REFUSED

The distinction that carries the weight: **REFUSED** = testing must not begin (authorization failed);
**INCONCLUSIVE** = testing occurred but the negative claim was not earned (a control failed, freshness was not
established, identity drifted, too few valid trials, …). Both still produce a **signed** certificate, so an
INCONCLUSIVE reason cannot be stripped and re-read as success.

The live side is behind :class:`LiveTargetAdapter`, so the entire protocol logic here is exercised offline
against a fake adapter that can produce each state; the real executor adapter (a live re-drive against a
loopback / chartered target) plugs in behind the same interface. Identity integration is present from the
start — a Mode-L "against S, now" claim is not strong without it.

Standing invariants: only ONE narrow path reaches REMEDIATED; the original ORACLE is the sole authority (this
orchestrator advises/sequences, it never promotes); FATAL-2 (every ``framework.v2`` import is function-local);
determinism (``now`` / ``run_id`` / nonces are INPUTS the caller supplies — never a wallclock/rng read in the
signed math). The first honest certificate claims only: *under the recorded authorization, identity, freshness,
control, execution and observation conditions, the original exploit oracle did not reproduce across the
protocol-required trials.*
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Optional, Protocol, runtime_checkable

from vigil_core import (
    Attenuation,
    Capability,
    CapabilityError,
    IdentityAttestation,
    WielderProof,
    authorize_reverification,
    canonical_json,
    digest_payload,
    identity_digest,
    identity_matches,
    sha256_hex,
    sign,
    verify_capability,
    verify_identity_attestation,
    verify_one,
)
from vigil_core.crypto import load_public_key

PROTOCOL_VERSION = "vigil-remediation-prove-v1"
_CERT_SCHEMA = "vigil-remediation-prove-cert-v1"
_CERT_DOMAIN = b"vigil-remediation-prove-cert-v1\x00"
_CHALLENGE_DOMAIN = b"vigil-remediation-freshness-challenge-v1\x00"


# --------------------------------------------------------------------------------------------------------
# Verdict states + reason codes (the four-state machine).
# --------------------------------------------------------------------------------------------------------
class State:
    REMEDIATED = "REMEDIATED"
    STILL_VULNERABLE = "STILL_VULNERABLE"
    INCONCLUSIVE = "INCONCLUSIVE"
    REFUSED = "REFUSED"


class Reason:
    # REMEDIATED
    ORACLE_SILENT_ACROSS_TRIALS = "oracle_silent_across_trials"
    # STILL_VULNERABLE
    ORACLE_FIRED = "oracle_fired_over_fresh_evidence"
    # REFUSED (testing must not begin)
    DOWNGRADE_REQUESTED = "downgrade_requested"
    INVALID_CAPABILITY = "invalid_capability"
    EXPIRED_CAPABILITY = "expired_capability"
    REVOKED_CAPABILITY = "revoked_capability"
    POP_FAILURE = "proof_of_possession_failure"
    IDENTITY_POLICY_MISMATCH = "identity_policy_mismatch"
    UNAUTHORIZED_BUG_CLASS = "unauthorized_bug_class"
    DESTRUCTIVE_UNDER_NONDESTRUCTIVE = "destructive_recipe_under_nondestructive_capability"
    SCOPE_MISMATCH = "scope_mismatch"
    BUDGET_EXHAUSTED = "action_budget_exhausted"
    UNPROVABLE_ORACLE_FAMILY = "oracle_family_has_no_deterministic_remediation_rule"
    # INCONCLUSIVE (testing occurred, claim not earned)
    CONTROL_FAILED = "positive_control_failed"
    TARGET_UNAVAILABLE = "target_unavailable"
    FRESHNESS_ECHO_MISSING = "freshness_echo_missing"
    INSUFFICIENT_FRESHNESS = "insufficient_freshness_level"
    IDENTITY_CHANGED = "identity_changed_during_run"
    RESPONSE_CHANNEL_DEGRADED = "response_channel_degraded"
    INSUFFICIENT_REPETITIONS = "insufficient_valid_repetitions"
    ORACLE_CONTEXT_UNREBUILDABLE = "oracle_context_unrebuildable"
    RATE_LIMIT_INTERRUPTED = "rate_limit_interrupted"
    COLLECTOR_FAILED = "evidence_collector_failed"
    DEPLOYMENT_CHANGED = "deployment_changed_during_run"
    STATISTICAL_RULE_UNIMPLEMENTED = "statistical_stopping_rule_not_yet_implemented"


# Freshness hierarchy (recorded on the cert; never assumed — the adapter reports what it can PROVE).
class Freshness:
    F0_NONCE_GENERATED = 0        # a fresh client challenge exists
    F1_TARGET_ECHOES = 1         # the target returned the challenge (responsive)
    F2_PATH_TRAVERSED = 2        # the challenge passed through the relevant application path
    F3_BOUND_TO_EVIDENCE = 3     # the challenge is bound into the exploit/control evidence
    F4_INDEPENDENT_SIGNED = 4    # an independent collector / the target key signed the nonce-bound observation


# --------------------------------------------------------------------------------------------------------
# Per-oracle-family repeat policy — protocol-defined, NOT chosen ad hoc by the CLI.
# --------------------------------------------------------------------------------------------------------
@dataclass(frozen=True)
class RepeatPolicy:
    family: str
    min_valid_trials: int             # valid treatment (+control) trials required before a verdict
    requires_significance: bool = False   # timing/race need a statistical rule (not yet implemented → INCONCLUSIVE)
    unique_token_per_trial: bool = False  # OOB families must not reuse a token across trials
    note: str = ""


REPEAT_POLICY: dict[str, RepeatPolicy] = {
    "deterministic_state_change": RepeatPolicy("deterministic_state_change", 1,
        note="one valid treatment + controls suffices for a deterministic effect"),
    "error_based_sqli": RepeatPolicy("error_based_sqli", 3, note="multiple treatment/control pairs"),
    "error_signature": RepeatPolicy("error_signature", 3),
    "reflected_xss": RepeatPolicy("reflected_xss", 3, note="repeated render-path pairs"),
    "differential_response": RepeatPolicy("differential_response", 3, note="repeated baseline/treatment pairing"),
    "boolean_sqli": RepeatPolicy("boolean_sqli", 3),
    "oob_callback": RepeatPolicy("oob_callback", 3, unique_token_per_trial=True,
        note="a unique / derivation-bound token per trial"),
    "ssrf": RepeatPolicy("ssrf", 3, unique_token_per_trial=True),
    "timing_sqli": RepeatPolicy("timing_sqli", 8, requires_significance=True,
        note="statistical sample floor + significance threshold — deterministic rule not yet implemented"),
    "race_condition": RepeatPolicy("race_condition", 8, requires_significance=True),
    "auth_flaw": RepeatPolicy("auth_flaw", 3, note="multiple independent sessions"),
}
_DEFAULT_POLICY = RepeatPolicy("_default", 3, note="conservative default for an unclassified oracle family")


def repeat_policy_for(family: str) -> RepeatPolicy:
    return REPEAT_POLICY.get(str(family or ""), _DEFAULT_POLICY)


# --------------------------------------------------------------------------------------------------------
# The freshness challenge — binds the WHOLE causal chain, not just a random nonce.
# --------------------------------------------------------------------------------------------------------
def build_freshness_challenge(*, run_id: str, finding_id: str, original_certificate_digest: str,
                              identity_policy_digest: str, capability_chain_digest: str,
                              target_identity_digest: str, sequence: int, nonce: str) -> str:
    """H(domain ‖ canonical(all causal digests + nonce)). A bare nonce echoed by a generic endpoint proves
    only responsiveness; binding the finding / original-cert / identity-policy / capability-chain / target
    identity means an echo of THIS challenge can only have come from a run authorized for THIS finding against
    THIS target. ``nonce`` MUST be a fresh, unpredictable value the caller supplies."""
    core = {
        "protocol_version": PROTOCOL_VERSION, "run_id": str(run_id), "finding_id": str(finding_id),
        "original_certificate_digest": str(original_certificate_digest),
        "identity_policy_digest": str(identity_policy_digest),
        "capability_chain_digest": str(capability_chain_digest),
        "target_identity_digest": str(target_identity_digest), "sequence": int(sequence), "nonce": str(nonce),
    }
    return sha256_hex(_CHALLENGE_DOMAIN + canonical_json(core))


def capability_chain_digest(cap: Capability, attenuations: "list[Attenuation] | None") -> str:
    """A stable digest over the base capability + its ordered attenuation chain (binds the whole delegation)."""
    return digest_payload({
        "capability": cap.model_dump(mode="json"),
        "attenuations": [a.model_dump(mode="json") for a in (attenuations or [])],
    })


def target_identity_digest_of(identity_sample: dict) -> str:
    return digest_payload({str(k): identity_sample[k] for k in sorted(identity_sample or {})})


# --------------------------------------------------------------------------------------------------------
# EffectiveAuthorization — an IMMUTABLE execution envelope derived from a VERIFIED capability. Every send
# consumes it; there is no path from raw arguments to the executor. Closes the validate→execute TOCTOU.
# --------------------------------------------------------------------------------------------------------
class BudgetExhausted(RuntimeError):
    """The action budget was consumed — raised by AtomicBudget.spend before any traffic is sent."""


@dataclass
class AtomicBudget:
    """Consume-BEFORE-send request budget. The core is serial, but ``spend`` decrements first and raises on
    overrun so a (future) concurrent executor cannot let two workers each observe remaining capacity and
    collectively exceed the authorized limit — the check and the decrement are one step."""
    remaining: int

    def spend(self, n: int = 1) -> None:
        if n <= 0:
            raise ValueError("budget spend must be positive")
        if self.remaining - n < 0:
            raise BudgetExhausted(f"action budget exhausted (need {n}, have {self.remaining})")
        self.remaining -= n


@dataclass(frozen=True)
class EffectiveAuthorization:
    """The frozen envelope handed to the executor. Derived ONCE from a verified EffectiveCapability +
    identity; nothing downstream may widen it."""
    target_identity_digest: str
    allowed_bug_classes: tuple[str, ...]
    maximum_requests: int
    not_before: int
    expires_at: int
    revocation_id: str
    capability_chain_digest: str
    destructive: bool = False

    def digest(self) -> str:
        return digest_payload({
            "target_identity_digest": self.target_identity_digest,
            "allowed_bug_classes": sorted(self.allowed_bug_classes),
            "maximum_requests": self.maximum_requests, "not_before": self.not_before,
            "expires_at": self.expires_at, "revocation_id": self.revocation_id,
            "capability_chain_digest": self.capability_chain_digest, "destructive": self.destructive,
        })


# --------------------------------------------------------------------------------------------------------
# The live-target adapter interface + its observation types. The real executor implements this; tests inject
# a fake. The core NEVER re-drives directly — it calls the adapter, which is the single egress point.
# --------------------------------------------------------------------------------------------------------
@dataclass(frozen=True)
class ControlObservation:
    """Result of the positive-control twin: proof the vuln-class observation CHANNEL is alive (not a recreation
    of the vuln). ``oracle_context`` is the twin context the SAME oracle must re-fire on."""
    reachable: bool
    channel_alive: bool
    oracle_context: dict
    freshness_level: int = Freshness.F0_NONCE_GENERATED
    definition_digest: str = ""
    detail: str = ""


@dataclass(frozen=True)
class TrialObservation:
    """One re-drive of the ORIGINAL exploit probe. ``valid`` marks a usable trial; an invalid trial (probe
    couldn't be sent, response malformed, token reused, …) is recorded but not counted toward the policy."""
    reachable: bool
    valid: bool
    oracle_context: Optional[dict]
    freshness_level: int = Freshness.F0_NONCE_GENERATED
    nonce_echoed: bool = False
    invalid_reason: str = ""
    detail: str = ""


@runtime_checkable
class LiveTargetAdapter(Protocol):
    """The single egress interface. Attributes describe the ORIGINAL exploit (bound into the cert so the
    re-drive is the original method, never a model-regenerated approximation)."""
    bug_class: str
    oracle_family: str
    oracle_id: str
    oracle_version: str
    original_probe_recipe_digest: str
    execution_profile_digest: str
    destructive: bool

    def identity_sample(self) -> dict: ...
    def run_positive_control(self, *, challenge: str, auth: EffectiveAuthorization,
                             budget: AtomicBudget) -> ControlObservation: ...
    def run_exploit_trial(self, *, challenge: str, trial_index: int, auth: EffectiveAuthorization,
                          budget: AtomicBudget) -> TrialObservation: ...


# --------------------------------------------------------------------------------------------------------
# Policy for the run (what the deployment REQUIRES — the downgrade floor).
# --------------------------------------------------------------------------------------------------------
@dataclass(frozen=True)
class ProvePolicy:
    """The required floor. A run that would deliver LESS than this is REFUSED (downgrade resistance) — there
    are deliberately no --skip-identity / --no-control / --allow-stale knobs in prove mode."""
    require_identity_match: bool = True
    require_positive_control: bool = True
    require_proof_of_possession: bool = True
    require_fresh_revocation: bool = True
    minimum_freshness_level: int = Freshness.F1_TARGET_ECHOES
    single_instance_scope: bool = True   # this cert speaks for the sampled instance, not a fleet (recorded)


# --------------------------------------------------------------------------------------------------------
# The outcome + the orchestrator.
# --------------------------------------------------------------------------------------------------------
@dataclass
class ProveOutcome:
    state: str
    reason_code: str
    certificate: dict
    detail: str = ""
    trials_attempted: int = 0
    trials_valid: int = 0
    achieved_freshness: int = Freshness.F0_NONCE_GENERATED


def _refused(reason: str, detail: str, cert: dict) -> ProveOutcome:
    return ProveOutcome(state=State.REFUSED, reason_code=reason, certificate=cert, detail=detail)


def prove_remediation(
    *,
    adapter: LiveTargetAdapter,
    identity: IdentityAttestation,
    capability: Capability,
    wielder_proof: Optional[WielderProof],
    trusted_owner_pubkey: str,
    engagement: str,
    finding_id: str,
    original_certificate_digest: str,
    signers: "list[tuple[str, str]]",
    now: int,
    run_id: str,
    pop_challenge: str,
    freshness_nonce: str,
    attenuations: "list[Attenuation] | None" = None,
    revoked_ids: "frozenset[str]" = frozenset(),
    policy: ProvePolicy = ProvePolicy(),
    requested_min_freshness: Optional[int] = None,
) -> ProveOutcome:
    """Run the gated remediation-proof flow and return a four-state, signed outcome. See the module docstring
    for the invariants. ``now`` / ``run_id`` / ``pop_challenge`` / ``freshness_nonce`` are caller-supplied
    (fresh, unpredictable) — determinism is preserved and the run is reproducible in tests."""
    if not signers:
        raise ValueError("prove_remediation: governance signers are required (never an unsigned certificate)")

    # ---- DOWNGRADE RESISTANCE (step 0): a request weaker than the policy floor never starts. ----
    if requested_min_freshness is not None and int(requested_min_freshness) < int(policy.minimum_freshness_level):
        return _refused(Reason.DOWNGRADE_REQUESTED,
                        f"requested freshness F{requested_min_freshness} < policy floor "
                        f"F{policy.minimum_freshness_level}",
                        _mint_cert(State.REFUSED, Reason.DOWNGRADE_REQUESTED, adapter=adapter, identity=identity,
                                   capability=capability, attenuations=attenuations, finding_id=finding_id,
                                   original_certificate_digest=original_certificate_digest, run_id=run_id,
                                   freshness_challenge="", policy=policy, signers=signers))
    if policy.require_proof_of_possession and wielder_proof is None and capability.audience != "*":
        return _refused(Reason.DOWNGRADE_REQUESTED, "policy requires proof of possession but none was supplied",
                        _mint_cert(State.REFUSED, Reason.DOWNGRADE_REQUESTED, adapter=adapter, identity=identity,
                                   capability=capability, attenuations=attenuations, finding_id=finding_id,
                                   original_certificate_digest=original_certificate_digest, run_id=run_id,
                                   freshness_challenge="", policy=policy, signers=signers))

    chain_digest = capability_chain_digest(capability, attenuations)

    def refuse(reason: str, detail: str) -> ProveOutcome:
        return _refused(reason, detail,
                        _mint_cert(State.REFUSED, reason, adapter=adapter, identity=identity,
                                   capability=capability, attenuations=attenuations, finding_id=finding_id,
                                   original_certificate_digest=original_certificate_digest, run_id=run_id,
                                   freshness_challenge="", policy=policy, signers=signers,
                                   capability_chain_digest=chain_digest))

    # ---- REFUSED gate (steps 1-9 pre-execution): authorization must fully hold before ANY traffic. ----
    if adapter.destructive:
        return refuse(Reason.DESTRUCTIVE_UNDER_NONDESTRUCTIVE,
                      "the original probe recipe is destructive; the capability is non-destructive")

    # (a) owner-attested identity is valid for this engagement.
    try:
        verify_identity_attestation(identity, trusted_owner_pubkey=trusted_owner_pubkey, now=now,
                                    engagement=engagement)
    except CapabilityError as e:
        return refuse(Reason.INVALID_CAPABILITY, f"identity attestation invalid: {e}")

    # (b) the capability verifies (structure/owner/window/revocation) — map the sub-reason by the failure.
    try:
        eff = verify_capability(capability, trusted_owner_pubkey=trusted_owner_pubkey, now=now,
                                engagement=engagement, attenuations=attenuations, revoked_ids=revoked_ids)
    except CapabilityError as e:
        msg = str(e)
        reason = (Reason.EXPIRED_CAPABILITY if "not valid at now" in msg or "expired" in msg
                  else Reason.REVOKED_CAPABILITY if "revoked" in msg
                  else Reason.INVALID_CAPABILITY)
        return refuse(reason, f"capability rejected: {e}")

    # (c) the bug class is in the (attenuated) allowlist.
    if adapter.bug_class not in set(eff.class_allowlist):
        return refuse(Reason.UNAUTHORIZED_BUG_CLASS,
                      f"bug_class {adapter.bug_class!r} not in {sorted(eff.class_allowlist)}")

    # (d) acquire the FIRST live identity sample and match it against the signed policy (before execution).
    try:
        sample1 = adapter.identity_sample()
    except Exception as e:  # noqa: BLE001 — a target we cannot even identify is unavailable, not authorized
        return refuse(Reason.TARGET_UNAVAILABLE, f"could not sample target identity: {e}")
    if policy.require_identity_match and not identity_matches(identity.policy, sample1):
        return refuse(Reason.IDENTITY_POLICY_MISMATCH,
                      "the live target's identity does not satisfy the attested policy")
    tid_digest = target_identity_digest_of(sample1)
    identity_samples = [tid_digest]

    # (e) the FULL authorization gate incl. proof-of-possession (the only thing (a)-(d) did not already cover).
    try:
        authorize_reverification(capability, identity, trusted_owner_pubkey=trusted_owner_pubkey, now=now,
                                 engagement=engagement, bug_class=adapter.bug_class, identity_sample=sample1,
                                 challenge=pop_challenge, wielder_proof=wielder_proof,
                                 attenuations=attenuations, revoked_ids=revoked_ids)
    except CapabilityError as e:
        # (a)-(d) already passed, so a failure here is the wielder proof of possession.
        return refuse(Reason.POP_FAILURE, f"wielder proof of possession failed: {e}")

    # ---- Repeat policy: some oracle families have no deterministic remediation rule yet → REFUSED honestly. ----
    rp = repeat_policy_for(adapter.oracle_family)

    # ---- Build the execution envelope + budget. Budget must cover control + the required trials. ----
    required_sends = 1 + rp.min_valid_trials      # 1 control + N trials (minimum; invalid trials cost budget too)
    auth = EffectiveAuthorization(
        target_identity_digest=tid_digest, allowed_bug_classes=tuple(sorted(eff.class_allowlist)),
        maximum_requests=int(eff.rate_limit), not_before=int(eff.not_before), expires_at=int(eff.not_after),
        revocation_id=eff.revocation_id, capability_chain_digest=chain_digest, destructive=False)
    if auth.maximum_requests < required_sends:
        return refuse(Reason.BUDGET_EXHAUSTED,
                      f"rate_limit {auth.maximum_requests} < required {required_sends} "
                      f"(1 control + {rp.min_valid_trials} trials)")
    budget = AtomicBudget(remaining=auth.maximum_requests)

    # From here testing has STARTED → failures are INCONCLUSIVE (never silently REMEDIATED), except a firing
    # oracle (STILL_VULNERABLE) or a clean silence across the required trials (REMEDIATED).
    def inconclusive(reason: str, detail: str, *, freshness: int = Freshness.F0_NONCE_GENERATED,
                     attempted: int = 0, valid: int = 0) -> ProveOutcome:
        cert = _mint_cert(State.INCONCLUSIVE, reason, adapter=adapter, identity=identity, capability=capability,
                          attenuations=attenuations, finding_id=finding_id,
                          original_certificate_digest=original_certificate_digest, run_id=run_id,
                          freshness_challenge=challenge, policy=policy, signers=signers,
                          capability_chain_digest=chain_digest, effective_authority_digest=auth.digest(),
                          identity_samples=identity_samples, trial_policy=_policy_dict(rp),
                          trial_results={"attempted": attempted, "valid": valid}, achieved_freshness=freshness)
        return ProveOutcome(state=State.INCONCLUSIVE, reason_code=reason, certificate=cert, detail=detail,
                            trials_attempted=attempted, trials_valid=valid, achieved_freshness=freshness)

    # ---- (step 10) mint the causal-chain-bound freshness challenge. ----
    challenge = build_freshness_challenge(
        run_id=run_id, finding_id=finding_id, original_certificate_digest=original_certificate_digest,
        identity_policy_digest=identity_digest(identity), capability_chain_digest=chain_digest,
        target_identity_digest=tid_digest, sequence=0, nonce=freshness_nonce)

    if rp.requires_significance:
        # timing/race remediation needs a statistical stopping rule we do not yet implement — refuse to fake it.
        return inconclusive(Reason.STATISTICAL_RULE_UNIMPLEMENTED,
                            f"oracle family {adapter.oracle_family!r} needs a significance rule (not implemented)")

    # ---- (step 11) positive-control twin: prove the observation channel is alive. ----
    try:
        control = adapter.run_positive_control(challenge=challenge, auth=auth, budget=budget)
    except BudgetExhausted as e:
        return inconclusive(Reason.RATE_LIMIT_INTERRUPTED, f"budget interrupted the control: {e}")
    except Exception as e:  # noqa: BLE001
        return inconclusive(Reason.COLLECTOR_FAILED, f"control execution failed: {e}")
    if not control.reachable:
        return inconclusive(Reason.TARGET_UNAVAILABLE, "target unreachable for the positive control")
    if policy.require_positive_control and not (control.channel_alive and _fires(control.oracle_context,
                                                                                 adapter.bug_class, finding_id)):
        return inconclusive(Reason.CONTROL_FAILED,
                            "the positive control did NOT fire — silence would be an artefact, not a fix")

    # ---- (step 12) identity continuity #2 (before exploit trials). ----
    if not _same_identity(adapter, identity, policy, tid_digest, identity_samples):
        return inconclusive(Reason.IDENTITY_CHANGED, "identity changed before the exploit trials")

    # ---- (steps 13-16) re-drive the ORIGINAL exploit under the repeat policy; re-fire the oracle. ----
    attempted = valid = 0
    achieved_freshness = Freshness.F0_NONCE_GENERATED
    seen_contexts: list[dict] = []
    while valid < rp.min_valid_trials:
        try:
            trial = adapter.run_exploit_trial(challenge=challenge, trial_index=attempted, auth=auth, budget=budget)
        except BudgetExhausted as e:
            return inconclusive(Reason.RATE_LIMIT_INTERRUPTED, f"budget interrupted the trials: {e}",
                                attempted=attempted, valid=valid, freshness=achieved_freshness)
        except Exception as e:  # noqa: BLE001
            return inconclusive(Reason.COLLECTOR_FAILED, f"trial execution failed: {e}",
                                attempted=attempted, valid=valid, freshness=achieved_freshness)
        attempted += 1
        if not trial.reachable:
            return inconclusive(Reason.TARGET_UNAVAILABLE, "target became unreachable mid-run",
                                attempted=attempted, valid=valid, freshness=achieved_freshness)
        if not trial.valid or trial.oracle_context is None:
            # an invalid trial is recorded but not counted; guard against an unbounded invalid streak by budget.
            continue
        # FRESHNESS: the trial must establish at least the policy floor (echo must be present & bound).
        if not trial.nonce_echoed:
            return inconclusive(Reason.FRESHNESS_ECHO_MISSING,
                                "the target did not echo the run challenge — cannot prove fresh (not replayed)",
                                attempted=attempted, valid=valid, freshness=achieved_freshness)
        if int(trial.freshness_level) < int(policy.minimum_freshness_level):
            return inconclusive(Reason.INSUFFICIENT_FRESHNESS,
                                f"achieved F{trial.freshness_level} < policy floor F{policy.minimum_freshness_level}",
                                attempted=attempted, valid=valid, freshness=int(trial.freshness_level))
        achieved_freshness = max(achieved_freshness, int(trial.freshness_level))
        # ORACLE AUTHORITY: re-fire the ORIGINAL oracle over this fresh evidence.
        if _fires(trial.oracle_context, adapter.bug_class, finding_id):
            cert = _mint_cert(State.STILL_VULNERABLE, Reason.ORACLE_FIRED, adapter=adapter, identity=identity,
                              capability=capability, attenuations=attenuations, finding_id=finding_id,
                              original_certificate_digest=original_certificate_digest, run_id=run_id,
                              freshness_challenge=challenge, policy=policy, signers=signers,
                              capability_chain_digest=chain_digest, effective_authority_digest=auth.digest(),
                              identity_samples=identity_samples, trial_policy=_policy_dict(rp),
                              trial_results={"attempted": attempted, "valid": valid + 1},
                              achieved_freshness=achieved_freshness, fresh_oracle_context=trial.oracle_context)
            return ProveOutcome(state=State.STILL_VULNERABLE, reason_code=Reason.ORACLE_FIRED, certificate=cert,
                                detail="the original exploit oracle fired over fresh evidence",
                                trials_attempted=attempted, trials_valid=valid + 1,
                                achieved_freshness=achieved_freshness)
        valid += 1
        seen_contexts.append(trial.oracle_context)

    # ---- (step 12 again) identity continuity #3 (after exploit trials). ----
    if not _same_identity(adapter, identity, policy, tid_digest, identity_samples):
        return inconclusive(Reason.IDENTITY_CHANGED, "identity changed after the exploit trials",
                            attempted=attempted, valid=valid, freshness=achieved_freshness)

    # ---- (steps 17-18) all required trials were valid, fresh, and SILENT → REMEDIATED. Mint the embedded
    #      controlled RemediationCertificate (re-fires the oracle: control fires, patched silent, live). ----
    if not _same_identity(adapter, identity, policy, tid_digest, identity_samples):   # #4 before mint
        return inconclusive(Reason.IDENTITY_CHANGED, "identity changed before minting",
                            attempted=attempted, valid=valid, freshness=achieved_freshness)

    from .remediation_cert import mint_remediation_certificate  # lazy — needs framework (FATAL-2)
    try:
        embedded = mint_remediation_certificate(
            finding_ref=finding_id, bug_class=adapter.bug_class, patched_oracle_context=seen_contexts[-1],
            positive_control_context=control.oracle_context, engagement_slug=engagement, signers=signers,
            surface="", original_finding_cert_digest=original_certificate_digest,
            freshness_nonce=challenge, repeats=valid)
    except ValueError as e:
        # the controlled mint enforces the same controls; a refusal here means the negative claim was not earned.
        return inconclusive(Reason.INSUFFICIENT_REPETITIONS, f"controlled remediation mint refused: {e}",
                            attempted=attempted, valid=valid, freshness=achieved_freshness)

    cert = _mint_cert(State.REMEDIATED, Reason.ORACLE_SILENT_ACROSS_TRIALS, adapter=adapter, identity=identity,
                      capability=capability, attenuations=attenuations, finding_id=finding_id,
                      original_certificate_digest=original_certificate_digest, run_id=run_id,
                      freshness_challenge=challenge, policy=policy, signers=signers,
                      capability_chain_digest=chain_digest, effective_authority_digest=auth.digest(),
                      identity_samples=identity_samples, trial_policy=_policy_dict(rp),
                      trial_results={"attempted": attempted, "valid": valid}, achieved_freshness=achieved_freshness,
                      fresh_oracle_context=seen_contexts[-1], embedded_remediation_cert=embedded,
                      control_context=control.oracle_context)
    return ProveOutcome(state=State.REMEDIATED, reason_code=Reason.ORACLE_SILENT_ACROSS_TRIALS, certificate=cert,
                        detail="the original exploit oracle did not reproduce across the protocol-required trials",
                        trials_attempted=attempted, trials_valid=valid, achieved_freshness=achieved_freshness)


# --------------------------------------------------------------------------------------------------------
# Helpers.
# --------------------------------------------------------------------------------------------------------
def _fires(context: dict, bug_class: str, ref: str) -> bool:
    """Re-fire the ORIGINAL oracle over ``context``; True iff it CONFIRMS. Any reverify error → not-firing
    (fail-closed). Lazy framework import (FATAL-2)."""
    from framework.v2.verify.reverify import reverify_context
    try:
        return bool(reverify_context(context, bug_class=bug_class, ref=ref).reproduced)
    except Exception:  # noqa: BLE001
        return False


def _same_identity(adapter: LiveTargetAdapter, identity: IdentityAttestation, policy: ProvePolicy,
                   expected_digest: str, samples: list[str]) -> bool:
    """Sample identity again; record it; True iff it still matches the policy AND equals the first sample's
    digest (no drift between patched/unpatched replicas, rotation, redeploy)."""
    if not policy.require_identity_match:
        return True
    try:
        s = adapter.identity_sample()
    except Exception:  # noqa: BLE001
        return False
    d = target_identity_digest_of(s)
    samples.append(d)
    return identity_matches(identity.policy, s) and d == expected_digest


def _policy_dict(rp: RepeatPolicy) -> dict:
    return {"family": rp.family, "min_valid_trials": rp.min_valid_trials,
            "requires_significance": rp.requires_significance,
            "unique_token_per_trial": rp.unique_token_per_trial, "stopping_rule": "all_required_trials_silent"}


def _cert_signing_bytes(cert_without_sig: dict) -> bytes:
    return _CERT_DOMAIN + canonical_json(cert_without_sig)


def _mint_cert(state: str, reason: str, *, adapter: LiveTargetAdapter, identity: IdentityAttestation,
               capability: Capability, attenuations: "list[Attenuation] | None", finding_id: str,
               original_certificate_digest: str, run_id: str, freshness_challenge: str, policy: ProvePolicy,
               signers: "list[tuple[str, str]]", capability_chain_digest: str = "",
               effective_authority_digest: str = "", identity_samples: "list[str] | None" = None,
               trial_policy: "dict | None" = None, trial_results: "dict | None" = None,
               achieved_freshness: int = Freshness.F0_NONCE_GENERATED, fresh_oracle_context: "dict | None" = None,
               embedded_remediation_cert: "dict | None" = None, control_context: "dict | None" = None) -> dict:
    """Assemble + SIGN the full causal-chain ProveCertificate for ANY state (so an INCONCLUSIVE/REFUSED reason
    is tamper-evident — no unsigned sidecar can change its interpretation)."""
    cert: dict[str, Any] = {
        "schema": _CERT_SCHEMA,
        "protocol_version": PROTOCOL_VERSION,
        "state": state,
        "original_finding": {
            "positive_certificate_digest": str(original_certificate_digest or ""),
            "finding_id": str(finding_id or ""),
            "bug_class": adapter.bug_class,
            "oracle_id": adapter.oracle_id,
            "oracle_version": adapter.oracle_version,
            "probe_digest": adapter.original_probe_recipe_digest,
        },
        "target": {
            "identity_policy_digest": identity_digest(identity),
            "observed_identity_samples": list(identity_samples or []),
            "target_identity_digest": (identity_samples[0] if identity_samples else ""),
            "scope": "single_instance" if policy.single_instance_scope else "fleet",
        },
        "authorization": {
            "capability_root_digest": digest_payload(capability.model_dump(mode="json")),
            "capability_chain_digest": str(capability_chain_digest or ""),
            "effective_authority_digest": str(effective_authority_digest or ""),
            "proof_of_possession": (capability.audience != "*"),
            "revocation_id": capability.revocation_id,
        },
        "execution": {
            "run_id": str(run_id or ""),
            "freshness_challenge": str(freshness_challenge or ""),
            "execution_profile_digest": adapter.execution_profile_digest,
            "trial_policy": trial_policy or {},
            "trial_results": trial_results or {},
        },
        "controls": {
            "positive_control_digest": (digest_payload(control_context) if control_context else ""),
            "liveness_result": bool(control_context is not None),
            "achieved_freshness_level": int(achieved_freshness),
            "minimum_freshness_level": int(policy.minimum_freshness_level),
        },
        "evidence": {
            "fresh_oracle_context_digest": (digest_payload(fresh_oracle_context) if fresh_oracle_context else ""),
            "embedded_remediation_cert": embedded_remediation_cert or None,
        },
        "verdict": {
            "oracle_fired": (state == State.STILL_VULNERABLE),
            "remediation_state": state,
            "reason_code": reason,
        },
    }
    key_id, priv = signers[0]
    cert["signer"] = {"key_id": str(key_id), "signature": sign(priv, _cert_signing_bytes(cert))}
    return cert


def verify_prove_certificate(cert: dict, *, signer_pubkeys: "dict[str, str]") -> tuple[bool, str]:
    """Offline verification of a ProveCertificate: (1) the whole-cert Ed25519 signature verifies against a
    pinned governance key (so the state, reason, and every bound digest are tamper-evident); (2) for a
    REMEDIATED cert, the embedded controlled RemediationCertificate independently RE-EXECUTES to ``ok`` (the
    oracle is silent on the patched context, the positive control fires, the target answered). Fail-closed.

    NOTE: authenticity + internal consistency are checkable with stdlib + Ed25519; re-executing the oracle
    (the REMEDIATED case) needs the framework (lazy import), exactly like the base RemediationCertificate."""
    if not isinstance(cert, dict) or cert.get("schema") != _CERT_SCHEMA:
        return False, "not a vigil-remediation-prove-cert-v1"
    state = str(cert.get("state") or "")
    if state not in (State.REMEDIATED, State.STILL_VULNERABLE, State.INCONCLUSIVE, State.REFUSED):
        return False, f"unknown state {state!r}"
    sigblk = cert.get("signer")
    if not (isinstance(sigblk, dict) and sigblk.get("key_id") and sigblk.get("signature")):
        return False, "missing/malformed signer block"
    key_id, sig = str(sigblk["key_id"]), str(sigblk["signature"])
    pub = signer_pubkeys.get(key_id) if isinstance(signer_pubkeys, dict) else None
    if not pub:
        return False, f"no pinned public key for signer {key_id!r}"
    msg = _cert_signing_bytes({k: v for k, v in cert.items() if k != "signer"})
    try:
        load_public_key(pub)
        if not verify_one(pub, msg, sig):
            return False, "signature invalid (forged/tampered/wrong key)"
    except Exception:  # noqa: BLE001
        return False, "malformed signature/key material — fail closed"

    # the verdict block must agree with the top-level state (no split-brain relabelling).
    verdict = cert.get("verdict") or {}
    if str(verdict.get("remediation_state")) != state:
        return False, "verdict.remediation_state disagrees with the certificate state"
    if bool(verdict.get("oracle_fired")) != (state == State.STILL_VULNERABLE):
        return False, "verdict.oracle_fired disagrees with the state"

    if state == State.REMEDIATED:
        embedded = ((cert.get("evidence") or {}).get("embedded_remediation_cert"))
        if not isinstance(embedded, dict):
            return False, "REMEDIATED cert has no embedded RemediationCertificate to re-execute"
        from .remediation_cert import verify_remediation_certificate   # lazy — FATAL-2
        v = verify_remediation_certificate(embedded, signer_pubkeys=signer_pubkeys)
        if not v.ok:
            return False, f"embedded remediation cert does not re-execute: {v.reason}"
        return True, "REMEDIATED: signed + embedded remediation re-executes (oracle silent, control fires, live)"
    return True, f"{state}: signed and internally consistent"
