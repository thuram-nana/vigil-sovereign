"""remediation.prove_driver — the ``vigil remediate --prove`` orchestrator (VF-1a).

A NARROW protocol orchestrator (deliberately NOT a generalized agent loop) that turns "we patched it" into a
signed, FOUR-STATE statement about the FRESH behaviour of a real authorized target. It composes the merged VF
foundation — the RemediationCertificate + controls, the owner-attested identity, the capability chain + proof
of possession — into one gated flow and classifies the result into exactly one of:

    REMEDIATED · STILL_VULNERABLE · INCONCLUSIVE · REFUSED

The distinction that carries the weight: **REFUSED** = testing must not begin (authorization failed, or this
mode cannot certify this oracle family); **INCONCLUSIVE** = testing occurred but the negative claim was not
earned (a control failed, freshness was not established, identity drifted, too few valid trials, …). Both still
produce a **signed** certificate, so an INCONCLUSIVE reason cannot be stripped and re-read as success.

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

import threading
from dataclasses import dataclass
from typing import Any, Optional, Protocol, runtime_checkable

from vigil_core import (
    Attenuation,
    Capability,
    CapabilityError,
    IdentityAttestation,
    WielderProof,
    canonical_json,
    digest_payload,
    identity_digest,
    identity_matches,
    sha256_hex,
    sign,
    verify_capability,
    verify_identity_attestation,
    verify_one,
    verify_wielder_proof,
)
from vigil_core.crypto import load_public_key

# The response-bearing (oracle-judged) fields — SAME set the liveness control uses (single source of truth).
# remediation_cert's module scope is stdlib + vigil_core only, so this import is FATAL-2 safe (no framework).
from .remediation_cert import _RESPONSE_KEYS

PROTOCOL_VERSION = "vigil-remediation-prove-v1"
_CERT_SCHEMA = "vigil-remediation-prove-cert-v1"
_CERT_DOMAIN = b"vigil-remediation-prove-cert-v1\x00"
_CHALLENGE_DOMAIN = b"vigil-remediation-freshness-challenge-v1\x00"
# The differential-channel oracle family (TRUTHENOVATION R1) — used as the cert's channel marker and to route
# ``verify_prove_certificate`` to the differential re-execution path.
_BOOLEAN_INFERENCE = "boolean_inference"

# The ATTRIBUTION discriminator for the REMEDIATED channel-closure check (red-pen BLOCK-B) — ZERO tolerance:
# ANY deterministic difference between ``true`` and ``false_a`` counts as the channel still OPEN. It is
# DELIBERATELY distinct from the SPRT's fuzzy ``bool_disc``: the fuzzy thresholds (lexical 0.10 / length 0.05)
# have a SAFE failure mode in the CONFIRM direction (a sub-threshold channel is a false-negative under-claim),
# but reusing them to assert CLOSURE flips that into a false ALL-CLEAR — a 1-byte deterministic leak in a large
# page (~99.85% similar) reads as "closed" while an attacker reads the DB bit-by-bit. To attribute a fix we
# require true and false_a INDISTINGUISHABLE at zero tolerance. A PROTOCOL constant (never cert-supplied), so a
# minted and a re-verified cert are judged by the identical rule (mint gate + ``_verify_differential_remediated``).
_ATTRIBUTION_DISC = {"dimensions": ["status", "length", "lexical"],
                     "length_threshold": 0.0, "lexical_threshold": 0.0}
# The SPRT boolean discriminator and the WAF-closure discriminator are ALSO protocol constants — NEVER
# cert-supplied at verify (red-pen re-check #2 hardening). The mint records them in the cert for audit, but
# ``_verify_differential_remediated`` re-executes with THESE fixed rules, so a re-verified cert is judged by the
# identical discriminators the mint used — a signed cert cannot carry a weakened ``closure_discriminator`` (e.g.
# dropping ``structural``) to make a blocked/interposed origin re-verify as REMEDIATED. Consistent with the
# re-execution-independence posture the attribution gate adopts.
_BOOL_DISC = {"dimensions": ["status", "length", "lexical"]}
_CLOSURE_DISC = {"dimensions": ["status", "structural"], "expect": "same"}


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
    UNPROVABLE_ORACLE_FAMILY = "oracle_family_not_certifiable_by_silence"
    STATISTICAL_RULE_UNIMPLEMENTED = "statistical_stopping_rule_not_yet_implemented"
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
    # INCONCLUSIVE (differential channel, TRUTHENOVATION R1) — a decisive SPRT refute did not translate to a
    # sound REMEDIATED because the metachar decoy was blocked/diverted (a blocking payload-discriminating WAF/
    # edge is interposing, DIFFERENTIAL-REMEDIATION §4.3), or the SPRT reached no boundary at all (§4.4 / HIGH-3:
    # absence of evidence is not evidence of a fix — REMEDIATED requires a DECISIVE refute, never a non-decision),
    # or the refute was UNATTRIBUTABLE — driven by the dynamic-page control tripping (false_a != false_b noise:
    # __VIEWSTATE / rotating banner / big reflected token) rather than genuine channel closure, so a still-firing
    # injection can hide behind the noise (red-pen: a false REMEDIATED over a live-vulnerable noisy origin).
    INTERPOSER_SUSPECTED = "interposer_suspected_waf_closure_failed"
    INSUFFICIENT_ROUNDS = "sprt_inconclusive_insufficient_rounds"
    CHANNEL_NOISE_UNATTRIBUTABLE = "sprt_refute_unattributable_dynamic_page_noise_not_channel_closure"
    # a probe body was captured at the truncation cap → closure CANNOT be attributed (a boolean leak past the
    # observation window would be invisible; red-pen R2 BLOCK — a >8 KB response with the leak in its tail).
    OBSERVATION_TRUNCATED = "closure_unattributable_response_body_truncated"


class Freshness:
    F0_NONCE_GENERATED = 0        # a fresh client challenge exists
    F1_TARGET_ECHOES = 1         # the target returned the challenge (responsive) — reflection, incl. into a
                                 #   SILENT response, never exceeds this (an echoer/edge can produce it)
    F2_PATH_TRAVERSED = 2        # the fresh challenge is reflected in the datastore-error LINE a FIRING trial
                                 #   matched — it came back through the SAME error channel the signal did, as
                                 #   attributable as the error_signature oracle's own firing (NOT byte-unforgeable;
                                 #   that is the OOB Tier-2 / zkTLS frontier). Sound only for STILL_VULNERABLE; a
                                 #   REMEDIATED (silent) verdict can NEVER reach F2 (fixed sink) — VF-1a.3.
    F3_BOUND_TO_EVIDENCE = 3     # the challenge is bound into the exploit/control evidence (structural)
    F4_INDEPENDENT_SIGNED = 4    # an independent collector / the target key signed the nonce-bound observation


# --------------------------------------------------------------------------------------------------------
# Per-oracle-CLASS repeat policy — protocol-defined, keyed on the AUTHORIZED bug_class (never a free field),
# and normalised through the canonical timing/race aliases so no real statistical class slips the gate.
# `certifiable_by_silence` is fail-CLOSED: only classes we KNOW silence-across-N soundly proves are certifiable;
# statistical families (timing/race) and any UNKNOWN class cannot reach REMEDIATED.
# --------------------------------------------------------------------------------------------------------
@dataclass(frozen=True)
class RepeatPolicy:
    bug_class: str
    min_valid_trials: int
    certifiable_by_silence: bool          # is oracle SILENCE a SOUND negative for THIS oracle (deterministic
                                          # per-observation)? — an oracle property, orthogonal to whether a
                                          # given run also establishes LIVENESS (that is a separate runtime gate).
    requires_significance: bool = False   # statistical/probabilistic family — silence needs an equivalence rule
    unique_token_per_trial: bool = False  # OOB families must not reuse a token across trials
    note: str = ""


# FAIL-CLOSED ALLOWLIST of oracle KINDS (by OracleKind.value) for which silence is a SOUND negative: a present
# vuln CERTAINLY re-fires a comparable honest re-drive because the oracle fires on a DETERMINISTIC per-observation
# signal over a RELIABLY-REPRODUCIBLE channel. A class is certifiable-by-silence ONLY if EVERY oracle in its set
# is here — so an unaudited/new/sampled/stochastic kind defaults to NON-certifiable (a blocklist fails unsafe;
# repeated red-pen rounds proved an allowlist is the only robust shape). Deliberately EXCLUDED and why:
#   TIMING, CREDENTIAL_STUFFING            — significance test over a sampled campaign (silence = no evidence)
#   PROMPT_INJECTION, SYSTEM_PROMPT_DISCLOSURE — deterministic GIVEN the obs, but the obs is a STOCHASTIC LLM output
#   SANITIZER_SIGNAL                        — TSAN data-race sub-case is non-deterministic (unaudited → excluded)
#   VERSION_RANGE, POLICY_PATH, *_POSTURE, SAML/SSO forgery, AUTOMATED_ACCESS — offline/posture, not a live
#     exploit re-drive with a freshness nonce (out of prove-mode scope; reconciles the certifiability↔mint gap)
#   SERVICE_REACHABILITY, ACTIVE_EXPOSURE, TLS_WEAKNESS — recon/handshake classes whose liveness is the
#     connection-dict problem; excluded until a sound `connected is True` liveness lands.
_CERTIFIABLE_ORACLE_KINDS = frozenset({
    "error_signature", "side_effect", "differential_response", "boolean_inference", "reflection_context",
    "dom_execution", "evaluation", "achieved_state", "predicate", "oob_callback",
    "sql_injection_breakout", "command_injection_breakout", "nosql_injection_breakout",
})
# LOAD-BEARING INVARIANTS these entries rest on (verified by round-5 adversarial audit; preserve them):
#  (1) differential_response is here only because NO certifiable class attaches a LATENCY discriminator — every
#      certifiable producer uses content dims (status/length/lexical); the two latency-mode producers hard-code
#      the guarded `request_smuggling` class. If a future producer attaches a latency discriminator to a
#      certifiable class, silence becomes unsound — exclude latency-mode differential then.
#  (2) boolean_inference & oob_callback silence is sound ONLY because the mandatory POSITIVE-CONTROL fire proves
#      the round/callback budget is adequate before any silence is credited. Do NOT relax the positive-control
#      gate for these families.

# Non-deterministically-REPRODUCIBLE phenomena: the oracle is deterministic given the observation, but a present
# vuln may not manifest on a given drive (connection-state desync / race window). Silence-across-N is unsound.
_PROBABILISTIC_CLASSES = frozenset({"request_race", "race_condition", "toctou", "request_smuggling",
                                    "response_smuggling", "http_request_smuggling", "http_desync"})
# Oracle kinds whose exclusion is a STATISTICAL/STOCHASTIC-rule gap (→ STATISTICAL_RULE_UNIMPLEMENTED reason),
# vs a merely-unaudited/unsupported kind (→ UNPROVABLE_ORACLE_FAMILY).
_STATISTICAL_KIND_NAMES = frozenset({"timing", "credential_stuffing", "prompt_injection",
                                     "system_prompt_disclosure"})


def repeat_policy_for(bug_class: str) -> RepeatPolicy:
    """The repeat policy for the AUTHORIZED ``bug_class``, DERIVED from the authoritative verifier taxonomy via a
    FAIL-CLOSED oracle-kind ALLOWLIST. ``certifiable_by_silence`` answers ONLY "is oracle silence a SOUND negative
    for this oracle?" (a present vuln CERTAINLY re-fires a comparable honest re-drive) — LIVENESS (did the target
    answer) is a SEPARATE runtime gate in the mint. A class is certifiable iff its canonical name is known, it is
    not a probabilistic-phenomenon (race/desync) class, AND EVERY oracle in its set is on the deterministic
    allowlist. Everything else — unknown class, oracle-KIND name, sampled/stochastic kind, unaudited kind,
    race/smuggling phenomenon — is NON-certifiable (fail-closed). Lazy framework import (FATAL-2)."""
    from framework.v2.verify.models import OracleKind                     # lazy — FATAL-2
    from framework.v2.verify.verifier import BUG_CLASS_ORACLES, canonical_bug_class

    canonical = canonical_bug_class(bug_class)
    if canonical is None:
        label = str(bug_class or "").strip().lower()
        return RepeatPolicy(label, min_valid_trials=3, certifiable_by_silence=False,
                            note="UNKNOWN to the oracle vocabulary — fail-closed: cannot certify by silence")
    kinds = frozenset(o.value for o in BUG_CLASS_ORACLES.get(canonical, ()))
    is_phenomenon = (canonical in _PROBABILISTIC_CLASSES
                     or any(t in canonical for t in ("race", "toctou", "smuggl", "desync")))
    all_deterministic = bool(kinds) and kinds.issubset(_CERTIFIABLE_ORACLE_KINDS)
    if is_phenomenon or not all_deterministic:
        requires_sig = is_phenomenon or bool(kinds & _STATISTICAL_KIND_NAMES)
        return RepeatPolicy(canonical, min_valid_trials=8, certifiable_by_silence=False,
                            requires_significance=requires_sig,
                            note="non-deterministic / sampled / stochastic / race / unaudited oracle — silence is "
                                 "not a sound negative (fail-closed)")
    return RepeatPolicy(canonical, min_valid_trials=3, certifiable_by_silence=True,
                        unique_token_per_trial=("oob_callback" in kinds),
                        note="every oracle is deterministic per-observation over a reliable channel — silence sound")


# --------------------------------------------------------------------------------------------------------
# The freshness challenge — binds the WHOLE causal chain, not just a random nonce.
# --------------------------------------------------------------------------------------------------------
def build_freshness_challenge(*, run_id: str, finding_id: str, original_certificate_digest: str,
                              identity_policy_digest: str, capability_chain_digest: str,
                              target_identity_digest: str, sequence: int, nonce: str) -> str:
    """H(domain ‖ canonical(all causal digests + nonce)). Binding the finding / original-cert / identity-policy
    / capability-chain / target identity means that IF the target's retained evidence contains this challenge
    string (verified deterministically at F2+, see :func:`_challenge_in_context`), that evidence can only have
    come from a run authorized for THIS finding against THIS target. ``nonce`` MUST be a fresh, unpredictable
    value the caller supplies; distinct runs → distinct challenge (domain-separated hash, no collision)."""
    core = {
        "protocol_version": PROTOCOL_VERSION, "run_id": str(run_id), "finding_id": str(finding_id),
        "original_certificate_digest": str(original_certificate_digest),
        "identity_policy_digest": str(identity_policy_digest),
        "capability_chain_digest": str(capability_chain_digest),
        "target_identity_digest": str(target_identity_digest), "sequence": int(sequence), "nonce": str(nonce),
    }
    return sha256_hex(_CHALLENGE_DOMAIN + canonical_json(core))


def capability_chain_digest(cap: Capability, attenuations: "list[Attenuation] | None") -> str:
    return digest_payload({
        "capability": cap.model_dump(mode="json"),
        "attenuations": [a.model_dump(mode="json") for a in (attenuations or [])],
    })


def target_identity_digest_of(identity_sample: dict) -> str:
    return digest_payload({str(k): identity_sample[k] for k in sorted(identity_sample or {})})


def _line_containing(text: str, idx: int) -> str:
    """The physical line (between ``\\n`` boundaries) of ``text`` holding position ``idx``."""
    start = text.rfind("\n", 0, idx) + 1        # 0 when there is no preceding newline
    end = text.find("\n", idx)
    return text[start:] if end < 0 else text[start:end]


def _challenge_in_firing_signature(challenge: str, oracle_context: dict) -> bool:
    """SOUND F2 for the error-signature channel (this driver's live adapter's sole channel): is the fresh
    challenge reflected INSIDE the datastore error LINE the oracle matched — i.e. did it come back through the
    SAME error channel the firing signal came from?

    This is deliberately STRONGER than "the challenge is somewhere in the judged bytes": a target that emits a
    STATIC error banner on one line and reflects the injected input on ANOTHER line (a non-executing echoer)
    does NOT satisfy it → the run is capped to F1. It is NOT byte-unforgeable — a target that fabricates a
    matching error EMBEDDING the nonce is indistinguishable on the response channel (that is the deferred
    OOB/zkTLS frontier; the OOB Tier-2 is the unforgeable channel) — so F2 here is only ever "as attributable as
    the error_signature oracle's own firing." It uses the oracle ITSELF (a lazy import, never a duplicated
    signature list) to locate the match, so the check can never drift from the authority. FATAL-2 safe."""
    if not isinstance(oracle_context, dict):
        return False
    needle = str(challenge)
    if not needle:
        return False
    try:
        from framework.v2.verify.oracles import error_signature_oracle   # lazy — FATAL-2
    except Exception:  # noqa: BLE001
        return False
    for k in _RESPONSE_KEYS:
        text = oracle_context.get(k)
        if not isinstance(text, str) or needle not in text:
            continue
        sig = error_signature_oracle(text)
        if not getattr(sig, "fired", False):
            continue
        match = str((getattr(sig, "observed", None) or {}).get("match") or "")
        idx = text.find(match) if match else -1
        if idx >= 0 and needle in _line_containing(text, idx):
            return True
    return False


# --------------------------------------------------------------------------------------------------------
# EffectiveAuthorization — an IMMUTABLE execution envelope + an ATOMIC, orchestrator-owned budget.
# --------------------------------------------------------------------------------------------------------
class BudgetExhausted(RuntimeError):
    """The action budget was consumed — raised by AtomicBudget.spend BEFORE any traffic is sent."""


class AtomicBudget:
    """Consume-BEFORE-send request budget, guarded by a lock so the check-and-decrement is a single atomic
    step — a concurrent executor cannot let two workers each observe remaining capacity and collectively
    exceed the authorized limit. The ORCHESTRATOR (not the adapter) spends one unit before each adapter call,
    so the trial loop is bounded by the budget regardless of adapter behaviour."""

    def __init__(self, remaining: int) -> None:
        self._remaining = int(remaining)
        self._lock = threading.Lock()

    @property
    def remaining(self) -> int:
        with self._lock:
            return self._remaining

    def spend(self, n: int = 1) -> None:
        if n <= 0:
            raise ValueError("budget spend must be positive")
        with self._lock:
            if self._remaining - n < 0:
                raise BudgetExhausted(f"action budget exhausted (need {n}, have {self._remaining})")
            self._remaining -= n


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
# Live-target adapter interface + observation types.
# --------------------------------------------------------------------------------------------------------
@dataclass(frozen=True)
class ControlObservation:
    reachable: bool
    channel_alive: bool
    oracle_context: dict
    freshness_level: int = Freshness.F0_NONCE_GENERATED
    definition_digest: str = ""
    detail: str = ""
    # VF-1a.3 — set True when a LIVE control probe saw a benign challenge-bearing marker (sent through the
    # injectable param) reflected in the response. INFORMATIONAL ONLY: reflection could come from the app OR
    # from an interposing edge/gateway that echoes the request, so it does NOT distinguish them and does NOT by
    # itself rule out a param-stripping edge (that discriminator is the deferred frontier). Never gates a verdict
    # and never promotes freshness (F2 stays exclusive to a firing trial's signature line).
    injectable_param_live: bool = False


@dataclass(frozen=True)
class TrialObservation:
    reachable: bool
    valid: bool
    oracle_context: Optional[dict]
    freshness_level: int = Freshness.F0_NONCE_GENERATED
    nonce_echoed: bool = False
    invalid_reason: str = ""
    detail: str = ""


@runtime_checkable
class LiveTargetAdapter(Protocol):
    bug_class: str
    oracle_family: str
    oracle_id: str
    oracle_version: str
    original_probe_recipe_digest: str
    execution_profile_digest: str
    destructive: bool

    def identity_sample(self) -> dict: ...
    def run_positive_control(self, *, challenge: str, auth: EffectiveAuthorization) -> ControlObservation: ...
    def run_exploit_trial(self, *, challenge: str, trial_index: int,
                          auth: EffectiveAuthorization) -> TrialObservation: ...


@dataclass(frozen=True)
class ProvePolicy:
    """The required floor. A run that would deliver LESS than this is REFUSED (downgrade resistance) — there
    are deliberately no --skip-identity / --no-control / --allow-stale knobs. ``require_proof_of_possession``
    is a HARD floor: a bearer ("*") capability cannot satisfy it (no key to prove) and is REFUSED under it."""
    require_identity_match: bool = True
    require_positive_control: bool = True
    require_proof_of_possession: bool = True
    require_fresh_revocation: bool = True
    minimum_freshness_level: int = Freshness.F1_TARGET_ECHOES
    single_instance_scope: bool = True


@dataclass
class ProveOutcome:
    state: str
    reason_code: str
    certificate: dict
    detail: str = ""
    trials_attempted: int = 0
    trials_valid: int = 0
    achieved_freshness: int = Freshness.F0_NONCE_GENERATED


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
    """Run the gated remediation-proof flow and return a four-state, signed outcome. ``now`` / ``run_id`` /
    ``pop_challenge`` / ``freshness_nonce`` are caller-supplied (fresh, unpredictable) — determinism is
    preserved and the run is reproducible in tests."""
    if not signers:
        raise ValueError("prove_remediation: governance signers are required (never an unsigned certificate)")
    chain_digest = capability_chain_digest(capability, attenuations)
    # The effective required freshness is the STRONGER of the policy floor and any caller request (a request
    # ABOVE the floor is enforced, not ignored; a request BELOW is a downgrade → refused).
    eff_min_freshness = max(int(policy.minimum_freshness_level),
                            int(requested_min_freshness) if requested_min_freshness is not None else 0)

    def mk(state: str, reason: str, **kw) -> dict:
        return _mint_cert(state, reason, adapter=adapter, identity=identity, capability=capability,
                          attenuations=attenuations, finding_id=finding_id,
                          original_certificate_digest=original_certificate_digest, run_id=run_id,
                          policy=policy, signers=signers, capability_chain_digest=chain_digest, **kw)

    def refuse(reason: str, detail: str) -> ProveOutcome:
        return ProveOutcome(State.REFUSED, reason, mk(State.REFUSED, reason, freshness_challenge=""), detail)

    # ---- DOWNGRADE RESISTANCE: a request weaker than the floor, or one that cannot meet the PoP floor. ----
    if requested_min_freshness is not None and int(requested_min_freshness) < int(policy.minimum_freshness_level):
        return refuse(Reason.DOWNGRADE_REQUESTED,
                      f"requested F{requested_min_freshness} < policy floor F{policy.minimum_freshness_level}")
    if policy.require_proof_of_possession and capability.audience == "*":
        return refuse(Reason.DOWNGRADE_REQUESTED,
                      "policy requires proof of possession but the capability is bearer ('*') — no key to prove")

    # ---- REFUSED gate (pre-execution, NO target traffic): full authorization must hold first. ----
    if adapter.destructive:
        return refuse(Reason.DESTRUCTIVE_UNDER_NONDESTRUCTIVE,
                      "the original probe recipe is destructive; the capability is non-destructive")
    try:
        verify_identity_attestation(identity, trusted_owner_pubkey=trusted_owner_pubkey, now=now,
                                    engagement=engagement)
    except CapabilityError as e:
        return refuse(Reason.INVALID_CAPABILITY, f"identity attestation invalid: {e}")
    try:
        eff = verify_capability(capability, trusted_owner_pubkey=trusted_owner_pubkey, now=now,
                                engagement=engagement, attenuations=attenuations, revoked_ids=revoked_ids)
    except CapabilityError as e:
        msg = str(e)
        reason = (Reason.EXPIRED_CAPABILITY if "not valid at now" in msg or "expired" in msg
                  else Reason.REVOKED_CAPABILITY if "revoked" in msg else Reason.INVALID_CAPABILITY)
        return refuse(reason, f"capability rejected: {e}")
    if adapter.bug_class not in set(eff.class_allowlist):
        return refuse(Reason.UNAUTHORIZED_BUG_CLASS,
                      f"bug_class {adapter.bug_class!r} not in {sorted(eff.class_allowlist)}")

    # ---- Repeat policy keyed on the AUTHORIZED bug_class; a non-certifiable family never reaches REMEDIATED,
    #      so we refuse BEFORE any traffic rather than run a test we could not conclude from. ----
    rp = repeat_policy_for(adapter.bug_class)
    if not rp.certifiable_by_silence:
        reason = Reason.STATISTICAL_RULE_UNIMPLEMENTED if rp.requires_significance else Reason.UNPROVABLE_ORACLE_FAMILY
        return refuse(reason, f"prove mode cannot certify remediation for oracle family {adapter.bug_class!r} "
                              f"(silence is not a sound negative proof without a significance/known rule)")

    # ---- Proof-of-possession BEFORE the first target touch (a PoP failure costs no live probe). ----
    if eff.audience != "*":
        try:
            verify_wielder_proof(wielder_proof, expected_audience=eff.audience, challenge=pop_challenge,
                                 capability=capability)
        except CapabilityError as e:
            return refuse(Reason.POP_FAILURE, f"wielder proof of possession failed: {e}")

    # ---- (first target touch) acquire + policy-match the live identity. ----
    try:
        sample1 = adapter.identity_sample()
    except Exception as e:  # noqa: BLE001
        return refuse(Reason.TARGET_UNAVAILABLE, f"could not sample target identity: {e}")
    if policy.require_identity_match and not identity_matches(identity.policy, sample1):
        return refuse(Reason.IDENTITY_POLICY_MISMATCH,
                      "the live target's identity does not satisfy the attested policy")
    tid_digest = target_identity_digest_of(sample1)
    identity_samples = [tid_digest]

    # ---- Execution envelope + orchestrator-owned budget (must cover 1 control + the required trials). ----
    required_sends = 1 + rp.min_valid_trials
    auth = EffectiveAuthorization(
        target_identity_digest=tid_digest, allowed_bug_classes=tuple(sorted(eff.class_allowlist)),
        maximum_requests=int(eff.rate_limit), not_before=int(eff.not_before), expires_at=int(eff.not_after),
        revocation_id=eff.revocation_id, capability_chain_digest=chain_digest, destructive=False)
    if auth.maximum_requests < required_sends:
        return refuse(Reason.BUDGET_EXHAUSTED,
                      f"rate_limit {auth.maximum_requests} < required {required_sends} "
                      f"(1 control + {rp.min_valid_trials} trials)")
    budget = AtomicBudget(auth.maximum_requests)

    challenge = build_freshness_challenge(
        run_id=run_id, finding_id=finding_id, original_certificate_digest=original_certificate_digest,
        identity_policy_digest=identity_digest(identity), capability_chain_digest=chain_digest,
        target_identity_digest=tid_digest, sequence=0, nonce=freshness_nonce)

    def inconclusive(reason: str, detail: str, *, freshness: int = Freshness.F0_NONCE_GENERATED,
                     attempted: int = 0, valid: int = 0) -> ProveOutcome:
        cert = mk(State.INCONCLUSIVE, reason, freshness_challenge=challenge, effective_authority_digest=auth.digest(),
                  identity_samples=identity_samples, trial_policy=_policy_dict(rp, eff_min_freshness),
                  trial_results={"attempted": attempted, "valid": valid}, achieved_freshness=freshness)
        return ProveOutcome(State.INCONCLUSIVE, reason, cert, detail, attempted, valid, freshness)

    # ---- (step 11) positive-control twin: prove the observation channel is alive. ORCHESTRATOR spends first. ----
    try:
        budget.spend(1)
        control = adapter.run_positive_control(challenge=challenge, auth=auth)
    except BudgetExhausted as e:
        return inconclusive(Reason.RATE_LIMIT_INTERRUPTED, f"budget interrupted the control: {e}")
    except Exception as e:  # noqa: BLE001
        return inconclusive(Reason.COLLECTOR_FAILED, f"control execution failed: {e}")
    if not control.reachable:
        return inconclusive(Reason.TARGET_UNAVAILABLE, "target unreachable for the positive control")
    if policy.require_positive_control and not (control.channel_alive
                                                and _fires(control.oracle_context, adapter.bug_class, finding_id)):
        return inconclusive(Reason.CONTROL_FAILED,
                            "the positive control did NOT fire — silence would be an artefact, not a fix")

    # ---- identity continuity #2 (before exploit trials). ----
    if not _same_identity(adapter, identity, policy, tid_digest, identity_samples):
        return inconclusive(Reason.IDENTITY_CHANGED, "identity changed before the exploit trials")

    # ---- DIFFERENTIAL CHANNEL (boolean_inference SPRT) — an ADDITIVE branch (TRUTHENOVATION R1). Reached only
    #      when the adapter declares the differential channel; the error-signature decision path BELOW is left
    #      BYTE-UNCHANGED. It reuses the whole preamble already run above (capability / identity / authorization
    #      / budget / positive-control / identity-continuity) via the injected auth/budget/control/mk/inconclusive
    #      and adjudicates entirely in :func:`_prove_differential` — REMEDIATED ONLY on a decisive SPRT refute
    #      AND WAF-closure; every other outcome is INCONCLUSIVE or STILL_VULNERABLE. ----
    if getattr(adapter, "differential_channel", False) or adapter.oracle_family == "boolean_inference":
        return _prove_differential(
            adapter=adapter, identity=identity, policy=policy, finding_id=finding_id, challenge=challenge,
            auth=auth, budget=budget, rp=rp, eff_min_freshness=eff_min_freshness, tid_digest=tid_digest,
            identity_samples=identity_samples, control=control, mk=mk, inconclusive=inconclusive)

    # ---- re-drive the ORIGINAL exploit under the repeat policy; re-fire the ORIGINAL oracle. ----
    attempted = valid = 0
    achieved_freshness = Freshness.F0_NONCE_GENERATED
    seen_contexts: list[dict] = []
    max_iterations = auth.maximum_requests   # belt-and-suspenders bound on top of the budget
    while valid < rp.min_valid_trials:
        if attempted >= max_iterations:
            return inconclusive(Reason.RATE_LIMIT_INTERRUPTED, "trial iteration bound reached",
                                attempted=attempted, valid=valid, freshness=achieved_freshness)
        try:
            budget.spend(1)   # consume-before-send; the orchestrator owns the bound, not the adapter
            trial = adapter.run_exploit_trial(challenge=challenge, trial_index=attempted, auth=auth)
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
            continue   # recorded but not counted; the budget bounds an invalid streak
        if not trial.nonce_echoed:
            return inconclusive(Reason.FRESHNESS_ECHO_MISSING,
                                "the target did not echo the run challenge — cannot prove fresh (not replayed)",
                                attempted=attempted, valid=valid, freshness=achieved_freshness)
        # ORACLE AUTHORITY — re-fire the ORIGINAL oracle over this fresh evidence. Computed HERE (before the
        # freshness credit) because F2 soundness depends on whether this trial FIRED (VF-1a.3).
        fired = _fires(trial.oracle_context, adapter.bug_class, finding_id)
        # FRESHNESS — the adapter's claimed level is CAPPED by what the core can verify. F2 is credited ONLY when
        # the oracle FIRED and the fresh challenge is reflected IN the matched datastore-error LINE
        # (``_challenge_in_firing_signature`` below) — the nonce came back through the SAME error channel the
        # signal did, so F2 is "as attributable as the error_signature oracle's own firing" (NOT byte-unforgeable:
        # a target that fabricates a matching error embedding the nonce is indistinguishable on the response
        # channel — the deferred OOB/zkTLS frontier). A SILENT trial can NEVER earn F2: with no firing signature,
        # a challenge in the response is mere reflection, which an app or interposing edge can fake — so silence
        # caps at F1 (target-responsive). A genuine remediation is therefore reported at F1, and a verifier that
        # demands F2 for a REMEDIATION correctly gets INCONCLUSIVE: once the sink is fixed its traversal is
        # unprovable by reflection (a fundamental limit, not a downgrade; ruling out a payload-discriminating WAF
        # or a request-echoing edge for the silent case needs a matched-decoy differential or the OOB Tier-2,
        # both deferred). The F2 case that IS sound — a live, fresh, sink-reflected EXPLOIT — is earned by the
        # STILL_VULNERABLE branch below.
        verified_level = int(trial.freshness_level)
        if verified_level >= Freshness.F2_PATH_TRAVERSED and not (
                fired and _challenge_in_firing_signature(challenge, trial.oracle_context)):
            verified_level = Freshness.F1_TARGET_ECHOES   # claimed F2+ but not reflected in the firing signature line
        if verified_level < eff_min_freshness:
            return inconclusive(Reason.INSUFFICIENT_FRESHNESS,
                                f"verified F{verified_level} < required floor F{eff_min_freshness}",
                                attempted=attempted, valid=valid, freshness=verified_level)
        achieved_freshness = max(achieved_freshness, verified_level)
        if fired:
            cert = mk(State.STILL_VULNERABLE, Reason.ORACLE_FIRED, freshness_challenge=challenge,
                      effective_authority_digest=auth.digest(), identity_samples=identity_samples,
                      trial_policy=_policy_dict(rp, eff_min_freshness),
                      trial_results={"attempted": attempted, "valid": valid + 1},
                      achieved_freshness=achieved_freshness, fresh_oracle_context=trial.oracle_context)
            return ProveOutcome(State.STILL_VULNERABLE, Reason.ORACLE_FIRED, cert,
                                "the original exploit oracle fired over fresh evidence", attempted, valid + 1,
                                achieved_freshness)
        valid += 1
        seen_contexts.append(trial.oracle_context)

    # ---- identity continuity #3 (after trials) and #4 (before mint). ----
    if not _same_identity(adapter, identity, policy, tid_digest, identity_samples):
        return inconclusive(Reason.IDENTITY_CHANGED, "identity changed after the exploit trials",
                            attempted=attempted, valid=valid, freshness=achieved_freshness)
    if not _same_identity(adapter, identity, policy, tid_digest, identity_samples):
        return inconclusive(Reason.IDENTITY_CHANGED, "identity changed before minting",
                            attempted=attempted, valid=valid, freshness=achieved_freshness)

    # ---- REMEDIATED: mint the embedded controlled RemediationCertificate (re-fires: control fires, patched
    #      silent, live) — the sole promoter of the negative claim; the orchestrator only sequenced. ----
    from .remediation_cert import mint_remediation_certificate   # lazy — needs framework (FATAL-2)
    try:
        embedded = mint_remediation_certificate(
            finding_ref=finding_id, bug_class=adapter.bug_class, patched_oracle_context=seen_contexts[-1],
            positive_control_context=control.oracle_context, engagement_slug=engagement, signers=signers,
            surface="", original_finding_cert_digest=original_certificate_digest,
            freshness_nonce=challenge, repeats=valid)
    except ValueError as e:
        # Surface an HONEST reason for WHY the negative claim was not earned rather than always blaming the
        # trial count. A liveness refusal ("no captured response" / "unreachable") means the target's answer
        # was not retained for this class — a response-channel/evidence issue, not too-few repetitions.
        msg = str(e).lower()
        reason = (Reason.RESPONSE_CHANNEL_DEGRADED if ("no captured response" in msg or "unreachable" in msg)
                  else Reason.INSUFFICIENT_REPETITIONS)
        return inconclusive(reason, f"controlled remediation mint refused: {e}",
                            attempted=attempted, valid=valid, freshness=achieved_freshness)

    cert = mk(State.REMEDIATED, Reason.ORACLE_SILENT_ACROSS_TRIALS, freshness_challenge=challenge,
              effective_authority_digest=auth.digest(), identity_samples=identity_samples,
              trial_policy=_policy_dict(rp, eff_min_freshness),
              trial_results={"attempted": attempted, "valid": valid}, achieved_freshness=achieved_freshness,
              fresh_oracle_context=seen_contexts[-1], embedded_remediation_cert=embedded,
              control_context=control.oracle_context)
    return ProveOutcome(State.REMEDIATED, Reason.ORACLE_SILENT_ACROSS_TRIALS, cert,
                        "the original exploit oracle did not reproduce across the protocol-required trials",
                        attempted, valid, achieved_freshness)


# --------------------------------------------------------------------------------------------------------
# DIFFERENTIAL CHANNEL (boolean_inference SPRT) — TRUTHENOVATION R1, PR1. ADDITIVE to the error-signature
# decision path above (which is byte-unchanged): a differential adapter is adjudicated ENTIRELY here.
# --------------------------------------------------------------------------------------------------------
def _prove_differential(*, adapter: LiveTargetAdapter, identity: IdentityAttestation, policy: ProvePolicy,
                        finding_id: str, challenge: str, auth: EffectiveAuthorization, budget: "AtomicBudget",
                        rp: RepeatPolicy, eff_min_freshness: int, tid_digest: str, identity_samples: list,
                        control: ControlObservation, mk, inconclusive) -> ProveOutcome:
    """Adjudicate the boolean-blind DIFFERENTIAL channel over FRESH matched-decoy rounds. Reuses the caller's
    already-run preamble via the injected ``auth`` / ``budget`` / ``control`` / ``mk`` / ``inconclusive`` — it
    re-verifies NOTHING the preamble already proved. Oracle authority is preserved: the SPRT decision is the
    EXISTING ``boolean_inference_oracle``'s, the WAF-closure is the EXISTING ``differential_response_oracle``'s;
    this function only sequences the probes and owns the fail-closed obligation.

    THE ONE INVARIANT — a false REMEDIATED is the exact overclaim this program KILLS:
      * SPRT ``confirm``                             -> STILL_VULNERABLE (the sink executes the injection OR an
                                                        interposer lexically fabricated the differential — either
                                                        way NOT remediated; a safe over-approximation, §4.1)
      * decisive SPRT ``refute`` AND WAF-closure     -> REMEDIATED (reported at F1 in PR1; the cert records
                                                        ``origin_reached`` ONLY — NOT a clean-code-fix claim, §4.2)
      * decisive ``refute`` AND WAF-closure FAILS    -> INCONCLUSIVE / INTERPOSER_SUSPECTED (a blocking
                                                        payload-discriminating WAF/edge blocked the decoy, §4.3)
      * SPRT ``inconclusive`` (no boundary)          -> INCONCLUSIVE / INSUFFICIENT_ROUNDS (absence of evidence
                                                        is not a fix — REMEDIATED needs a DECISIVE refute, HIGH-3)
      * any undelivered / malformed round            -> INCONCLUSIVE (FAIL-CLOSED; never silently skipped, §4.4)

    FATAL-2: the two oracles are imported function-local. Determinism: no wallclock/rng (the driver supplied
    ``challenge`` / nonces; the discriminators are fixed templates). PR1 freshness is honestly F1 for BOTH
    verdicts (§5); the differential F2 freshness verifier is the separately-reviewed PR2.
    """
    from framework.v2.verify.oracles import (   # lazy — FATAL-2
        boolean_inference_oracle, differential_response_oracle,
    )

    # Lexical-sensitive boolean discriminator (§4.1: a real injection may change only reflected TEXT, invisible
    # to status/structural alone) and the WAF-closure discriminator (§4.2).
    bool_disc = _BOOL_DISC
    closure_disc = _CLOSURE_DISC

    def dincon(reason: str, detail: str, *, attempted: int) -> ProveOutcome:
        # PR1: the differential channel is F1 (target-echoed) once a well-formed round is delivered.
        return inconclusive(reason, detail, freshness=Freshness.F1_TARGET_ECHOES, attempted=attempted, valid=0)

    # ---- collect ``min_valid_trials`` well-formed matched-decoy rounds; FAIL-CLOSED on any malformed round. ----
    rounds: list[dict] = []
    attempted = 0
    max_iterations = auth.maximum_requests   # belt-and-suspenders bound on top of the budget
    while len(rounds) < rp.min_valid_trials:
        if attempted >= max_iterations:
            return dincon(Reason.RATE_LIMIT_INTERRUPTED, "differential trial iteration bound reached",
                          attempted=attempted)
        try:
            budget.spend(1)   # consume-before-send; the orchestrator owns the bound, not the adapter
            trial = adapter.run_exploit_trial(challenge=challenge, trial_index=attempted, auth=auth)
        except BudgetExhausted as e:
            return dincon(Reason.RATE_LIMIT_INTERRUPTED, f"budget interrupted the differential trials: {e}",
                          attempted=attempted)
        except Exception as e:  # noqa: BLE001
            return dincon(Reason.COLLECTOR_FAILED, f"differential trial execution failed: {e}",
                          attempted=attempted)
        attempted += 1
        if not trial.reachable:
            return dincon(Reason.TARGET_UNAVAILABLE, "target became unreachable mid-run", attempted=attempted)
        # FAIL-CLOSED (§4.4 / §8 case 10): unlike the error-signature loop (which ``continue``s past an invalid
        # trial), the differential channel treats ANY undelivered/malformed round as FATAL — a matched decoy
        # that could not be built or delivered leaves the whole differential uninterpretable, so
        # ``boolean_inference_oracle`` must NOT be allowed to silently ``continue`` past it.
        if not trial.valid or not isinstance(trial.oracle_context, dict):
            return dincon(Reason.ORACLE_CONTEXT_UNREBUILDABLE,
                          trial.invalid_reason or "undelivered/malformed differential round",
                          attempted=attempted)
        ctx = trial.oracle_context
        if not all(k in ctx for k in ("true", "false_a", "false_b", "baseline")):
            return dincon(Reason.ORACLE_CONTEXT_UNREBUILDABLE,
                          "differential round missing baseline/true/false_a/false_b", attempted=attempted)
        # Live-marker reflection control (§4 / LOW-1): the inert challenge marker MUST come back (a
        # query-stripping cache / non-echoing edge serving one body for all probes fails this) — cannot prove
        # the round is fresh this run otherwise.
        if not trial.nonce_echoed:
            return dincon(Reason.FRESHNESS_ECHO_MISSING,
                          "the fresh challenge marker was not reflected — cannot prove the round is fresh",
                          attempted=attempted)
        rounds.append(ctx)

    # ---- identity continuity after the trials (mirror the error-signature path). ----
    if not _same_identity(adapter, identity, policy, tid_digest, identity_samples):
        return dincon(Reason.IDENTITY_CHANGED, "identity changed during the differential trials",
                      attempted=attempted)

    # ---- ORACLE AUTHORITY: the SPRT decision is the EXISTING boolean_inference_oracle's, never ours. ----
    sig = boolean_inference_oracle(rounds, discriminator=bool_disc)
    decision = str((sig.observed or {}).get("decision") or "inconclusive")
    achieved = Freshness.F1_TARGET_ECHOES   # PR1: F1 for BOTH verdicts (§5; the differential F2 verifier is PR2)
    trial_policy = _policy_dict(rp, eff_min_freshness)
    trial_results = {"attempted": attempted, "valid": len(rounds), "sprt_decision": decision,
                     "signal_rounds": (sig.observed or {}).get("signal_rounds"),
                     "rounds_used": (sig.observed or {}).get("rounds_used")}
    fresh_ctx = {"bug_class": adapter.bug_class, "probe_rounds": rounds, "discriminator": bool_disc}

    # ---- FRESHNESS FLOOR (parity with the error-signature path :601-608 + spec §5; red-pen: the differential
    #      branch silently dropped this). A caller that REQUESTS a level ABOVE the policy floor is ENFORCED, not
    #      ignored. The differential channel is honestly F1 for BOTH verdicts in PR1 (the differential F2 verifier
    #      is PR2), so any request for F2+ yields INCONCLUSIVE — a verifier demanding F2 for a REMEDIATION
    #      correctly gets INCONCLUSIVE, never a silently-downgraded REMEDIATED@F1. Gates BOTH verdicts, before the
    #      confirm/refute split, exactly as the error-signature freshness gate precedes its ``if fired``.
    if achieved < eff_min_freshness:
        return dincon(Reason.INSUFFICIENT_FRESHNESS,
                      f"differential channel proves F{achieved} < required floor F{eff_min_freshness} "
                      "(PR1 is F1 for both verdicts; the differential F2 freshness verifier is PR2)",
                      attempted=attempted)

    # (1) CONFIRM → STILL_VULNERABLE (a safe over-approximation — never a false all-clear, §4.1).
    if sig.fired and decision == "confirm":
        cert = mk(State.STILL_VULNERABLE, Reason.ORACLE_FIRED, freshness_challenge=challenge,
                  effective_authority_digest=auth.digest(), identity_samples=identity_samples,
                  trial_policy=trial_policy, trial_results=trial_results, achieved_freshness=achieved,
                  fresh_oracle_context=fresh_ctx, channel=_BOOLEAN_INFERENCE)
        return ProveOutcome(State.STILL_VULNERABLE, Reason.ORACLE_FIRED, cert,
                            "SPRT confirmed the boolean differential over fresh evidence (the sink executes the "
                            "injection OR an interposer fabricated a differential — either way not remediated)",
                            attempted, len(rounds), achieved)

    # (2) SPRT INCONCLUSIVE (no decisive boundary) → INCONCLUSIVE / INSUFFICIENT_ROUNDS. REMEDIATED requires a
    #     DECISIVE refute (``conclusive``), NEVER a non-decision (HIGH-3): absence of evidence is not a fix.
    if not (decision == "refute" and sig.conclusive):
        return dincon(Reason.INSUFFICIENT_ROUNDS,
                      f"SPRT reached no boundary in {len(rounds)} round(s) — not a decisive refute "
                      "(absence of evidence is not evidence of a fix)", attempted=attempted)

    # decisive refute from here — but a refute is NOT automatically a channel CLOSURE.
    # (3a) ATTRIBUTION (red-pen BLOCK — a reproduced false REMEDIATED over a live-vulnerable NOISY origin, e.g.
    #      an ASP.NET __VIEWSTATE app like the authorized testasp target): boolean_inference's per-round signal is
    #      (across AND within_same), across = (true != false_a) the boolean channel, within_same = (false_a ≈
    #      false_b) the dynamic-page control. A refute (signal→p0) arises EITHER from across=False (GENUINE
    #      closure — the predicate no longer changes the response = fixed) OR from within_same=False (the two
    #      FALSE responses disagree because of structurally-invisible per-request noise: __VIEWSTATE / rotating
    #      banner / big reflected token). The second is "too noisy to attribute," NOT a fix — over a still-
    #      vulnerable noisy origin across=True (the injection still fires) yet the SPRT refutes, and the {status,
    #      structural} WAF-closure below is deliberately blind to that lexical noise, so it cannot catch it. A
    #      SOUND REMEDIATED therefore REQUIRES the refute be attributable to CLOSURE: true must be indistinguishable
    #      from false_a (across=False) on EVERY judged round. If any round still SEPARATES true from false_a, the
    #      boolean channel is still firing → INCONCLUSIVE, never REMEDIATED. Recomputed here (oracle authority) on
    #      the SAME lexical-sensitive discriminator the SPRT used.
    if not rounds:   # defense-in-depth: never mint REMEDIATED off zero evidence (all(...) is vacuously True on [])
        return dincon(Reason.INSUFFICIENT_ROUNDS, "no judged rounds — cannot attribute a channel closure",
                      attempted=attempted)
    channel_closed = not any(
        differential_response_oracle(r.get("false_a"), r.get("true"), _ATTRIBUTION_DISC).fired for r in rounds
    )
    if not channel_closed:
        return dincon(Reason.CHANNEL_NOISE_UNATTRIBUTABLE,
                      "SPRT refuted but true still SEPARATES from false at zero tolerance on a judged round "
                      "(across=True) — either dynamic-page noise (false_a != false_b: __VIEWSTATE / rotating "
                      "token) OR a SUB-THRESHOLD leak the fuzzy SPRT missed (a 1-byte deterministic bit an "
                      "attacker reads directly); NOT genuine channel closure, so NOT a sound REMEDIATED",
                      attempted=attempted)

    # (3b) WAF-CLOSURE test on the JUDGED rounds (oracle authority — RECOMPUTED by differential_response_oracle,
    #     never trusted from the adapter): every metachar decoy (false_a) must come back baseline-shaped. A
    #     blocking/diverting WAF blocks false_a → it differs from baseline → closure FAILS → NOT REMEDIATED.
    closure_holds = all(
        differential_response_oracle(r.get("baseline"), r.get("false_a"), closure_disc).fired for r in rounds
    )
    if not closure_holds:
        return dincon(Reason.INTERPOSER_SUSPECTED,
                      "SPRT decisively refuted but a metachar decoy was blocked/diverted (WAF-closure failed) "
                      "— a blocking payload-discriminating interposer (WAF/edge) is suspected, so this is NOT a "
                      "sound REMEDIATED", attempted=attempted)

    # (3c) TRUNCATION (red-pen R2 BLOCK): the SPRT + attribution + closure were computed over the CAPTURED body
    #      EXCERPT. If any judged probe body was captured at the truncation cap, a boolean leak in the tail is
    #      INVISIBLE (identical prefixes → across=False), so channel-closure CANNOT be soundly attributed over a
    #      bounded observation window → INCONCLUSIVE. Real responses (HTML / JSON lists) routinely exceed the cap.
    if _rounds_truncated(rounds):
        return dincon(Reason.OBSERVATION_TRUNCATED,
                      "a judged response body was captured at the truncation cap — a boolean leak past the "
                      "observation window would be invisible, so channel-closure cannot be attributed; NOT a "
                      "sound REMEDIATED (the full body exceeded the capture excerpt)", attempted=attempted)

    # ---- R2: DIRECT-TO-ORIGIN re-drive — narrow the (a-sanitize) residual. The EDGE-observed path reached
    #      REMEDIATED; if the adapter can re-drive the SAME matched-decoy round DIRECTLY at the origin IP (Host
    #      pinned, bypassing a sanitizing / virtual-patching edge), let the ORIGIN truth decide. Every origin
    #      probe is STILL a gated_fetch admitted ONLY if the charter scopes the origin IP — this never bypasses
    #      scope. Three outcomes:
    #        * origin FIRES (SPRT confirm OR attribution across=True) → DEMOTE to STILL_VULNERABLE (edge-only fix)
    #        * origin SILENT (decisive refute + closure + across=False) → UPGRADE (origin_confirmed)
    #        * origin UNREACHABLE / IP out of scope / inconclusive → edge-only REMEDIATED, residual STILL OPEN
    origin_redrive = "not_attempted"      # not_attempted | unavailable | confirmed | inconclusive
    origin_rounds: list = []
    if getattr(adapter, "origin_redrive_available", False):
        origin_rounds = _collect_origin_rounds(
            adapter, challenge=challenge, auth=auth, budget=budget, need=rp.min_valid_trials)
        if origin_rounds is None:
            origin_redrive, origin_rounds = "unavailable", []     # cannot soundly re-drive → edge-only
        else:
            osig = boolean_inference_oracle(origin_rounds, discriminator=bool_disc)
            odecision = str((osig.observed or {}).get("decision") or "inconclusive")
            origin_open = any(
                differential_response_oracle(r.get("false_a"), r.get("true"), _ATTRIBUTION_DISC).fired
                for r in origin_rounds)
            origin_closed = all(
                differential_response_oracle(r.get("baseline"), r.get("false_a"), closure_disc).fired
                for r in origin_rounds)
            if (osig.fired and odecision == "confirm") or origin_open:
                # the injection FIRES when re-driven DIRECTLY at the origin → the edge sanitized / virtual-
                # patched it → NOT a code fix. Demote (mirrors the safe over-approximation direction, §4.1).
                cert = mk(State.STILL_VULNERABLE, Reason.ORACLE_FIRED, freshness_challenge=challenge,
                          effective_authority_digest=auth.digest(), identity_samples=identity_samples,
                          trial_policy=trial_policy, trial_results=trial_results, achieved_freshness=achieved,
                          fresh_oracle_context=fresh_ctx, channel=_BOOLEAN_INFERENCE,
                          differential_evidence={
                              "channel": _BOOLEAN_INFERENCE, "origin_redrive": "fired",
                              "edge_verdict": "refuted_at_edge_only", "judged_rounds": rounds,
                              "origin_rounds": origin_rounds,
                              "note": ("the boolean differential refuted AT THE EDGE but the SAME exploit FIRES "
                                       "when re-driven DIRECTLY at the origin IP (Host pinned) — the fix is at the "
                                       "edge (a-sanitize / virtual patch), the ORIGIN is still vulnerable")})
                return ProveOutcome(State.STILL_VULNERABLE, Reason.ORACLE_FIRED, cert,
                                    "REMEDIATED at the edge but the exploit FIRES direct-to-origin (Host pinned, "
                                    "edge bypassed) — the sanitizer is edge-only; the origin is still vulnerable",
                                    attempted, len(rounds), achieved)
            # a truncated origin observation cannot attribute origin closure (same tail-leak blind spot) → the
            # origin re-drive is inconclusive (edge-only), never origin_confirmed. A FIRING origin still demotes
            # above (a visible leak within the window is sound).
            origin_redrive = ("confirmed" if (odecision == "refute" and osig.conclusive and origin_closed
                                              and not origin_open and not _rounds_truncated(origin_rounds))
                              else "inconclusive")

    # (4) REMEDIATED — decisive SPRT refute AND WAF-closure. Reported at F1 (PR1). ``origin_reached`` records
    #     ONLY "a baseline-shaped response returned for a metacharacter-bearing probe" (a blocking WAF is ruled
    #     out). ``origin_confirmed`` (R2) upgrades that: the SAME exploit re-driven DIRECTLY at the origin (Host
    #     pinned, edge bypassed) ALSO stayed silent — so an in-flight SANITIZER is ruled out too. When the origin
    #     re-drive was not possible (unavailable / inconclusive) the (a-sanitize) residual stays OPEN (edge-only).
    origin_confirmed = origin_redrive == "confirmed"
    # Residuals that stay OPEN even under origin_confirmed — the re-drive still observes only the FORGEABLE
    # response channel over a BOUNDED window, so it cannot rule these out (red-pen R2 BLOCK-2: origin_confirmed
    # must NOT read as a clean bill of health):
    always_residual = (
        " Not ruled out (the observation is over the response BODY + STATUS only, forgeable and bounded): "
        "producer byte-forgery of the origin's own responses, a blind time-based/OOB channel or a leak carried "
        "only in response HEADERS (neither is observed), and any leak beyond the captured observation window. "
        "origin_reached/origin_confirmed assert closure of the observed content channel only — never "
        "byte-unforgeability (freshness stays F1).")
    sanitizer_residual = (
        "" if origin_confirmed else
        " Also NOT distinguished from a real fix (edge-only): an in-flight SANITIZING interposer (a-sanitize), a "
        "param-stripping edge (b), or a structurally-matched 200 block page — the disclosed frontier (TRUST-"
        "GRADIENT §7). REMEDIATED here means the injection no longer executes AS OBSERVED THROUGH THIS EDGE.")
    origin_note = (
        " The SAME exploit re-driven DIRECTLY at the origin IP (Host pinned, edge bypassed) ALSO stayed silent "
        "and closed — a sanitizing/virtual-patching EDGE is ruled out (origin_confirmed)." if origin_confirmed else
        f" A direct-to-origin re-drive was {origin_redrive or 'not_attempted'} (origin IP unknown / out of "
        "charter scope / unreachable / inconclusive), so the a-sanitize residual stays OPEN — edge-only.")
    differential_evidence = {
        "channel": _BOOLEAN_INFERENCE, "sprt_decision": "refute", "sprt_conclusive": True,
        "channel_closed": True,   # attribution: the refute is genuine closure (across=False on every judged
                                  # round), NOT the dynamic-page control tripping (§4.2a / red-pen BLOCK)
        "origin_reached": True, "waf_closure": "pass", "freshness_level": "F1",
        "origin_redrive": origin_redrive, "origin_confirmed": origin_confirmed,
        "boolean_discriminator": bool_disc, "closure_discriminator": closure_disc, "judged_rounds": rounds,
        "residual_disclosure": (
            "origin_reached asserts a baseline-shaped response returned for a metacharacter-bearing probe (a "
            "blocking/diverting payload-discriminating WAF is ruled out)." + sanitizer_residual + origin_note
            + always_residual),
    }
    if origin_confirmed:
        differential_evidence["origin_rounds"] = origin_rounds
    cert = mk(State.REMEDIATED, Reason.ORACLE_SILENT_ACROSS_TRIALS, freshness_challenge=challenge,
              effective_authority_digest=auth.digest(), identity_samples=identity_samples,
              trial_policy=trial_policy, trial_results=trial_results, achieved_freshness=achieved,
              fresh_oracle_context=fresh_ctx, channel=_BOOLEAN_INFERENCE,
              differential_evidence=differential_evidence)
    return ProveOutcome(State.REMEDIATED, Reason.ORACLE_SILENT_ACROSS_TRIALS, cert,
                        "the boolean differential DECISIVELY REFUTED (SPRT) and the metachar decoy reached the "
                        "origin baseline-shaped" + (
                            " AND a direct-to-origin re-drive (Host pinned) confirmed the origin is silent — a "
                            "sanitizing edge is ruled out (origin_confirmed)" if origin_confirmed else
                            "; the sanitizing-interposer residual (a-sanitize) is disclosed, not claimed closed "
                            "(edge-only)"), attempted, len(rounds), achieved)


# --------------------------------------------------------------------------------------------------------
# Helpers.
# --------------------------------------------------------------------------------------------------------
def _fires(context: dict, bug_class: str, ref: str) -> bool:
    from framework.v2.verify.reverify import reverify_context   # lazy — FATAL-2
    try:
        return bool(reverify_context(context, bug_class=bug_class, ref=ref).reproduced)
    except Exception:  # noqa: BLE001
        return False


def _rounds_truncated(rounds: "list[dict]") -> bool:
    """True if ANY probe body in ANY round was captured at the truncation cap (the executor's ``truncated`` flag
    on any of ``true``/``false_a``/``false_b``/``baseline``). Closure-attribution over a truncated body is
    unsound — a boolean leak in the untruncated tail is invisible (red-pen R2 BLOCK)."""
    for r in rounds or []:
        if not isinstance(r, dict):
            continue
        for k in ("true", "false_a", "false_b", "baseline"):
            probe = r.get(k)
            if isinstance(probe, dict) and probe.get("truncated"):
                return True
    return False


def _collect_origin_rounds(adapter, *, challenge: str, auth: EffectiveAuthorization, budget,
                           need: int) -> "list[dict] | None":
    """R2 — collect ``need`` well-formed DIRECT-TO-ORIGIN matched-decoy rounds via ``adapter.run_origin_trial``
    (a Host-pinned re-drive at the origin IP). Returns None the moment the origin re-drive cannot be SOUNDLY
    performed — the adapter lacks the method, the IP is out of charter scope / unreachable, a probe is malformed,
    or the shared budget is exhausted — so the caller keeps the edge-only verdict (a-sanitize residual OPEN) and
    NEVER fabricates an origin round. Best-effort on the shared budget (the required_sends floor covers only the
    control + edge trials; the origin re-drive is extra)."""
    run = getattr(adapter, "run_origin_trial", None)
    if run is None:
        return None
    rounds: list[dict] = []
    for i in range(need):
        try:
            budget.spend(1)
            t = run(challenge=challenge, trial_index=i, auth=auth)
        except BudgetExhausted:
            return None
        except Exception:  # noqa: BLE001 — any origin-probe crash → unavailable, not a fabricated silence
            return None
        if not getattr(t, "valid", False) or not isinstance(getattr(t, "oracle_context", None), dict):
            return None
        ctx = t.oracle_context
        if not all(k in ctx for k in ("true", "false_a", "false_b", "baseline")):
            return None
        if not getattr(t, "nonce_echoed", False):
            return None
        rounds.append(ctx)
    return rounds


def _same_identity(adapter: LiveTargetAdapter, identity: IdentityAttestation, policy: ProvePolicy,
                   expected_digest: str, samples: list[str]) -> bool:
    if not policy.require_identity_match:
        return True
    try:
        s = adapter.identity_sample()
    except Exception:  # noqa: BLE001
        return False
    d = target_identity_digest_of(s)
    samples.append(d)
    return identity_matches(identity.policy, s) and d == expected_digest


def _policy_dict(rp: RepeatPolicy, eff_min_freshness: int) -> dict:
    return {"bug_class": rp.bug_class, "min_valid_trials": rp.min_valid_trials,
            "certifiable_by_silence": rp.certifiable_by_silence,
            "requires_significance": rp.requires_significance,
            "unique_token_per_trial": rp.unique_token_per_trial,
            "required_freshness_level": int(eff_min_freshness),
            "stopping_rule": "all_required_trials_valid_fresh_and_silent"}


def _cert_signing_bytes(cert_without_sig: dict) -> bytes:
    return _CERT_DOMAIN + canonical_json(cert_without_sig)


def _mint_cert(state: str, reason: str, *, adapter: LiveTargetAdapter, identity: IdentityAttestation,
               capability: Capability, attenuations: "list[Attenuation] | None", finding_id: str,
               original_certificate_digest: str, run_id: str, freshness_challenge: str, policy: ProvePolicy,
               signers: "list[tuple[str, str]]", capability_chain_digest: str = "",
               effective_authority_digest: str = "", identity_samples: "list[str] | None" = None,
               trial_policy: "dict | None" = None, trial_results: "dict | None" = None,
               achieved_freshness: int = Freshness.F0_NONCE_GENERATED, fresh_oracle_context: "dict | None" = None,
               embedded_remediation_cert: "dict | None" = None, control_context: "dict | None" = None,
               channel: "str | None" = None, differential_evidence: "dict | None" = None) -> dict:
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
    # DIFFERENTIAL CHANNEL (TRUTHENOVATION R1) — keys added ONLY for the differential channel, so an
    # error-signature cert is byte-identical to before (no regression to the merged path or its signatures).
    if channel:
        cert["channel"] = str(channel)
    if differential_evidence is not None:
        cert["evidence"]["differential"] = differential_evidence
    key_id, priv = signers[0]
    cert["signer"] = {"key_id": str(key_id), "signature": sign(priv, _cert_signing_bytes(cert))}
    return cert


def verify_prove_certificate(cert: dict, *, signer_pubkeys: "dict[str, str]") -> tuple[bool, str]:
    """Offline verification: (1) the whole-cert Ed25519 signature verifies against a pinned governance key (so
    state, reason, and every bound digest are tamper-evident); (2) the verdict block agrees with the state;
    (3) for REMEDIATED, the embedded controlled RemediationCertificate independently RE-EXECUTES to ok AND is
    cross-bound to this outer cert (same finding, bug_class, freshness challenge, and evidence digest — so a
    valid embedded cert from another run cannot be spliced in). Fail-closed."""
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

    verdict = cert.get("verdict") or {}
    if str(verdict.get("remediation_state")) != state:
        return False, "verdict.remediation_state disagrees with the certificate state"
    if bool(verdict.get("oracle_fired")) != (state == State.STILL_VULNERABLE):
        return False, "verdict.oracle_fired disagrees with the state"

    # DIFFERENTIAL CHANNEL (TRUTHENOVATION R1) — a differential REMEDIATED re-executes its OWN evidence (the
    # SPRT re-refutes AND the WAF-closure re-holds over the retained rounds), NOT an embedded RemediationCert.
    if state == State.REMEDIATED and cert.get("channel") == _BOOLEAN_INFERENCE:
        return _verify_differential_remediated(cert)

    if state == State.REMEDIATED:
        embedded = ((cert.get("evidence") or {}).get("embedded_remediation_cert"))
        if not isinstance(embedded, dict):
            return False, "REMEDIATED cert has no embedded RemediationCertificate to re-execute"
        of = cert.get("original_finding") or {}
        ex = cert.get("execution") or {}
        ev = cert.get("evidence") or {}
        # cross-binding: the embedded negative proof must be about THIS finding/class/run, not spliced in.
        if str(embedded.get("finding_ref")) != str(of.get("finding_id")):
            return False, "embedded remediation cert finding_ref != outer finding_id"
        if str(embedded.get("bug_class")) != str(of.get("bug_class")):
            return False, "embedded remediation cert bug_class != outer bug_class"
        if str((embedded.get("controls") or {}).get("freshness_nonce")) != str(ex.get("freshness_challenge")):
            return False, "embedded remediation cert freshness_nonce != outer freshness_challenge"
        if str(embedded.get("patched_context_sha256")) != str(ev.get("fresh_oracle_context_digest")):
            return False, "embedded patched-context digest != outer fresh_oracle_context_digest"
        from .remediation_cert import verify_remediation_certificate   # lazy — FATAL-2
        v = verify_remediation_certificate(embedded, signer_pubkeys=signer_pubkeys)
        if not v.ok:
            return False, f"embedded remediation cert does not re-execute: {v.reason}"
        return True, "REMEDIATED: signed + cross-bound + embedded remediation re-executes (silent, control fires, live)"
    return True, f"{state}: signed and internally consistent"


def _verify_differential_remediated(cert: dict) -> tuple[bool, str]:
    """Offline re-execution of a DIFFERENTIAL-channel REMEDIATED cert (TRUTHENOVATION R1). The signature is
    already verified by the generic path; here the retained round evidence must itself RE-EXECUTE to the
    decisive verdict — the EXISTING ``boolean_inference_oracle`` must re-refute (``decision == "refute"`` AND
    ``conclusive``) over the judged rounds, AND the EXISTING ``differential_response_oracle`` WAF-closure must
    re-hold (each ``baseline`` vs ``false_a`` indistinguishable on ``status``+``structural``). Fail-closed, and
    honest — it re-checks ONLY what REMEDIATED claims (``origin_reached``), never a stronger clean-code-fix
    property. FATAL-2: the oracle import is function-local."""
    ev = ((cert.get("evidence") or {}).get("differential"))
    if not isinstance(ev, dict):
        return False, "differential REMEDIATED cert has no differential evidence block to re-execute"
    if ev.get("origin_reached") is not True:
        return False, "differential REMEDIATED must assert origin_reached"
    rounds = ev.get("judged_rounds")
    if not isinstance(rounds, list) or not rounds:
        return False, "differential evidence carries no judged_rounds to re-execute"
    try:
        from framework.v2.verify.oracles import (   # lazy — FATAL-2
            boolean_inference_oracle, differential_response_oracle,
        )
    except Exception:  # noqa: BLE001
        return False, "differential oracles unavailable — fail closed"
    # Discriminators are PROTOCOL CONSTANTS at verify, NOT cert-supplied (re-check #2 hardening): a signed cert
    # cannot weaken the SPRT/closure rule (e.g. drop ``structural`` from closure) to make an interposed origin
    # re-verify. The cert's recorded ``*_discriminator`` fields are informational/audit only.
    bool_disc = _BOOL_DISC
    closure_disc = _CLOSURE_DISC
    sig = boolean_inference_oracle(rounds, discriminator=bool_disc)
    decision = str((sig.observed or {}).get("decision") or "")
    if not (decision == "refute" and sig.conclusive):
        return False, "retained rounds do not re-execute to a DECISIVE SPRT refute"
    for r in rounds:
        if not (isinstance(r, dict) and "baseline" in r and "false_a" in r and "true" in r):
            return False, "a judged round is missing baseline/false_a/true for the differential re-check"
        # ATTRIBUTION re-check (red-pen BLOCK-A — parity with the mint gate): the refute must be genuine channel
        # CLOSURE, recomputed INDEPENDENT of the minter at ZERO tolerance (_ATTRIBUTION_DISC). If true still
        # SEPARATES from false_a on any round the channel is still OPEN (a still-vulnerable noisy / sub-threshold
        # origin) → DEMOTE. This is what lets the firewall demote a PRE-FIX false-REMEDIATED cert (across=True)
        # that was validly signed before the mint gate existed — invariant 3 (re-execution can only demote).
        if differential_response_oracle(r.get("false_a"), r.get("true"), _ATTRIBUTION_DISC).fired:
            return False, ("attribution re-check FAILED: true still separates from false_a at zero tolerance on "
                           "a judged round (the boolean channel is still OPEN — dynamic-page noise or a "
                           "sub-threshold leak) — NOT a genuine channel closure, so NOT a sound REMEDIATED")
        if not differential_response_oracle(r.get("baseline"), r.get("false_a"), closure_disc).fired:
            return False, "WAF-closure re-check failed (a metachar decoy diverged from baseline)"
    # TRUNCATION re-check (red-pen R2 BLOCK, mirrors the mint gate): closure cannot be attributed over a body
    # captured at the truncation cap — demote a REMEDIATED cert whose judged rounds are truncated.
    if _rounds_truncated(rounds):
        return False, ("a judged response body was truncated at the capture cap — channel-closure cannot be "
                       "attributed over a bounded observation window (a leak in the tail would be invisible)")
    # R2 — if the cert claims ORIGIN_CONFIRMED (the a-sanitize residual closed by a direct-to-origin re-drive),
    # the verifier MUST re-execute the origin rounds too (R1b lesson: a mint-side upgrade unmirrored at
    # re-execution means the firewall cannot demote a FALSE origin_confirmed). Same three checks as the edge
    # rounds, over the retained origin-re-drive bytes. A missing/failing origin claim is rejected, never ignored.
    # Key on the CLAIM shape (truthy `origin_confirmed` OR `origin_redrive=="confirmed"`), so a tampered cert
    # cannot dodge re-execution with a truthy non-bool flag (re-check #1 robustness note).
    if bool(ev.get("origin_confirmed")) or ev.get("origin_redrive") == "confirmed":
        origin_rounds = ev.get("origin_rounds")
        if not isinstance(origin_rounds, list) or not origin_rounds:
            return False, "origin_confirmed asserted but no origin_rounds to re-execute"
        osig = boolean_inference_oracle(origin_rounds, discriminator=bool_disc)
        if not (str((osig.observed or {}).get("decision") or "") == "refute" and osig.conclusive):
            return False, "origin_confirmed but the origin rounds do not re-execute to a decisive SPRT refute"
        for r in origin_rounds:
            if not (isinstance(r, dict) and "baseline" in r and "false_a" in r and "true" in r):
                return False, "an origin round is missing baseline/false_a/true for the origin re-check"
            if differential_response_oracle(r.get("false_a"), r.get("true"), _ATTRIBUTION_DISC).fired:
                return False, ("origin_confirmed but the ORIGIN channel is still OPEN (true separates from "
                               "false_a at zero tolerance, direct-to-origin) — the origin is still vulnerable")
            if not differential_response_oracle(r.get("baseline"), r.get("false_a"), closure_disc).fired:
                return False, "origin_confirmed but the origin WAF-closure re-check failed"
        if _rounds_truncated(origin_rounds):
            return False, ("origin_confirmed but an origin response body was truncated at the capture cap — the "
                           "origin closure cannot be attributed over a bounded observation window")
        return True, ("REMEDIATED (differential, ORIGIN_CONFIRMED): edge AND direct-to-origin re-drive both "
                      "re-refute decisively with channel-closure attributed — a sanitizing/virtual-patching edge "
                      "is ruled out for this finding")
    return True, ("REMEDIATED (differential): signed + SPRT re-refutes decisively + channel-closure attributed "
                  "(across=False, zero tolerance) + WAF-closure re-holds — origin_reached ONLY (a blocking WAF "
                  "is ruled out); the sanitizing-interposer residual (a-sanitize) is disclosed, NOT a "
                  "clean-code-fix claim (edge-only)")
