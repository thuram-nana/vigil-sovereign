"""M4.3 — narrowly-typed DEFENSIVE containment capabilities gated by a deterministic safety kernel.

The seam: between ``propose`` and ``execute``, a DEFENSIVE action (``isolate_endpoint`` / ``revoke_session`` /
``block_ip`` / ``quarantine_host``) is authorized ONLY by an owner-signed, scoped, short-lived, revocable,
rate-limited, target-bound ``vigil_core.Capability`` plus — for a pinned audience — a wielder proof-of-
possession. The capability authorizes; the GATE verifies. A defensive action with no valid capability is
REFUSED, fail-closed, with a distinct reason per cause.

These tests pair a real positive (a fully valid capability is gated-ALLOW and executes) with a safe-negative
control for EACH refusal axis (no token / expired / not-yet-valid / wrong engagement / wrong owner / kind not
in allowlist / wrong target / revoked / over rate limit / missing-stale-forged wielder proof), an offensive
kind that cannot be registered or minted as defensive, and the byte-identity of the existing ``http_get`` path.
No real containment is performed — the concrete test body's ``execute`` is inert.

Run (hermetic):
  PYTHONPATH=engine/crucible:packages/core/vigil_core pytest \
    engine/crucible/framework/v2/agent_body/tests/test_defensive_capability.py -q
"""
from __future__ import annotations

from typing import Optional

import pytest

from vigil_core import generate_keypair
from vigil_core.capability import Capability, attenuate, prove_wielder, sign_capability

from framework.v2.agent_body import (
    BLOCK_IP,
    DEFENSIVE_KINDS,
    ISOLATE_ENDPOINT,
    QUARANTINE_HOST,
    REVOKE_SESSION,
    CapabilityGatedBody,
    DefensiveCapabilityError,
    DefensiveRateLimiter,
    defensive_target_digest,
    gate_defensive_action,
    is_defensive_kind,
    mint_defensive_capability,
    register_defensive_kind,
)
from framework.v2.agent_body.interface import (
    ActionOutcome,
    GateDecision,
    Observation,
    ProposedAction,
    Thought,
)

OWNER = generate_keypair()
WIELDER = generate_keypair()
ATTACKER = generate_keypair()
SUBAUDITOR = generate_keypair()

ENG = "acme-ir"
NOW = 1_000
TARGET = "endpoint-42"
CHALLENGE = "kernel-nonce-xyz"   # the fresh per-authorization nonce the safety kernel supplies


# --- helpers ------------------------------------------------------------------------------------------
def _cap(kinds=None, target=TARGET, engagement=ENG, not_before=0, not_after=2_000, rate_limit=5,
         revocation_id="rev-ir-1", audience="*", owner=OWNER) -> Capability:
    return mint_defensive_capability(owner, engagement=engagement, target=target,
                                     kinds=(kinds or [ISOLATE_ENDPOINT]), not_before=not_before,
                                     not_after=not_after, rate_limit=rate_limit,
                                     revocation_id=revocation_id, audience=audience)


def _action(kind=ISOLATE_ENDPOINT, target=TARGET, cap=None, attenuations=None, proof=None) -> ProposedAction:
    params: dict = {}
    if cap is not None:
        params["capability"] = cap
    if attenuations is not None:
        params["attenuations"] = attenuations
    if proof is not None:
        params["wielder_proof"] = proof
    return ProposedAction(kind=kind, target=target, params=params)


def _gate(action, *, now=NOW, challenge=CHALLENGE, revoked_ids=frozenset(), limiter=None,
          owner_pub=None, engagement=ENG) -> Optional[GateDecision]:
    return gate_defensive_action(
        action, trusted_owner_pubkey=(owner_pub or OWNER.public_key_b64), engagement=engagement,
        now=now, challenge=challenge, revoked_ids=revoked_ids,
        rate_limiter=(limiter if limiter is not None else DefensiveRateLimiter()))


class _ContainmentBody(CapabilityGatedBody):
    """A concrete body that proposes one supplied action and records an INERT execution (no real containment)."""

    def __init__(self, action: ProposedAction, **kw) -> None:
        super().__init__(**kw)
        self._action = action
        self.performed: list[tuple[str, str, str]] = []
        self.learned: list[ActionOutcome] = []

    def think(self, observation: Observation) -> Thought:
        return Thought(intent="contain")

    def propose(self, thought: Thought) -> Optional[ProposedAction]:
        return self._action

    def execute(self, action: ProposedAction, decision: GateDecision) -> ActionOutcome:
        assert decision.authorized, "execute must never run on an unauthorized decision"
        self.performed.append((action.kind, action.target, decision.reason))
        return ActionOutcome(executed=True, ok=True, detail={"kind": action.kind, "target": action.target})

    def learn(self, outcome: ActionOutcome) -> None:
        self.learned.append(outcome)


# ======================================================================================================
# POSITIVE — a fully valid capability (+ wielder proof) is gated-ALLOW and executes.
# ======================================================================================================
def test_valid_pinned_capability_with_wielder_proof_is_allowed_and_executes():
    cap = _cap(audience=WIELDER.public_key_b64)
    proof = prove_wielder(WIELDER, challenge=CHALLENGE, capability=cap)
    dec = _gate(_action(cap=cap, proof=proof))
    assert dec is not None and dec.authorized is True
    assert "defensive gate authorized" in dec.reason and ISOLATE_ENDPOINT in dec.reason


def test_valid_defensive_action_runs_the_full_cycle_and_executes():
    cap = _cap(audience=WIELDER.public_key_b64)
    proof = prove_wielder(WIELDER, challenge=CHALLENGE, capability=cap)
    body = _ContainmentBody(_action(cap=cap, proof=proof), trusted_owner_pubkey=OWNER.public_key_b64,
                            engagement=ENG, now=NOW, challenge=CHALLENGE)
    outcome = body.run_cycle(Observation())
    assert outcome.executed is True and outcome.ok is True
    assert body.performed == [(ISOLATE_ENDPOINT, TARGET, body.gate(body._action).reason)]
    assert body.learned and body.learned[-1] is outcome


def test_valid_bearer_capability_needs_no_wielder_proof():
    # a bearer ("*") capability authorizes anyone holding the bytes, by design — no proof required.
    dec = _gate(_action(cap=_cap(audience="*")))
    assert dec is not None and dec.authorized is True


# ======================================================================================================
# SAFE-NEGATIVE CONTROLS — each refusal axis, asserting the RIGHT reason.
# ======================================================================================================
def test_no_capability_is_refused():
    dec = _gate(_action(cap=None))
    assert dec is not None and dec.authorized is False
    assert "no capability token" in dec.reason


def test_expired_capability_is_refused():
    dec = _gate(_action(cap=_cap(not_after=NOW - 1)))
    assert dec.authorized is False and "not valid at now" in dec.reason


def test_not_yet_valid_capability_is_refused():
    dec = _gate(_action(cap=_cap(not_before=NOW + 1, not_after=NOW + 100)))
    assert dec.authorized is False and "not valid at now" in dec.reason


def test_wrong_engagement_capability_is_refused():
    dec = _gate(_action(cap=_cap(engagement="other-engagement")))
    assert dec.authorized is False and "engagement" in dec.reason


def test_capability_signed_by_non_owner_is_refused():
    dec = _gate(_action(cap=_cap(owner=ATTACKER)))
    assert dec.authorized is False and "not by the trusted owner" in dec.reason


def test_tampered_capability_signature_is_refused():
    cap = _cap()
    tampered = cap.model_copy(update={"rate_limit": cap.rate_limit + 100})  # changes signed core, keeps old sig
    dec = _gate(_action(cap=tampered))
    assert dec.authorized is False and "does not verify" in dec.reason


def test_kind_not_in_allowlist_is_refused():
    # a capability for revoke_session cannot authorize isolate_endpoint.
    cap = _cap(kinds=[REVOKE_SESSION])
    dec = _gate(_action(kind=ISOLATE_ENDPOINT, cap=cap))
    assert dec.authorized is False and "not in the capability allowlist" in dec.reason


def test_wrong_target_capability_is_refused():
    # impact-bounding: a capability bound to one target cannot act on another.
    cap = _cap(target="some-other-endpoint")
    dec = _gate(_action(kind=ISOLATE_ENDPOINT, target=TARGET, cap=cap))
    assert dec.authorized is False and "not bound to this target" in dec.reason


def test_revoked_capability_is_refused():
    cap = _cap(revocation_id="rev-ir-9")
    dec = _gate(_action(cap=cap), revoked_ids=frozenset({"rev-ir-9"}))
    assert dec.authorized is False and "revoked" in dec.reason


def test_over_rate_limit_is_refused():
    # rate_limit=2 → two ALLOWs, then REFUSE; a refused action consumes no budget.
    limiter = DefensiveRateLimiter()
    cap = _cap(rate_limit=2, revocation_id="rev-rate", audience="*")
    a = _action(cap=cap)
    d1 = _gate(a, limiter=limiter)
    d2 = _gate(a, limiter=limiter)
    d3 = _gate(a, limiter=limiter)
    assert d1.authorized is True and d2.authorized is True
    assert d3.authorized is False and "over the capability rate limit" in d3.reason
    assert limiter.granted("rev-rate") == 2
    # a refused call does not increment the counter.
    _gate(a, limiter=limiter)
    assert limiter.granted("rev-rate") == 2


def test_pinned_capability_without_wielder_proof_is_refused():
    cap = _cap(audience=WIELDER.public_key_b64)
    dec = _gate(_action(cap=cap, proof=None))
    assert dec.authorized is False and "wielder proof" in dec.reason
    assert "requires a WielderProof" in dec.reason


def test_wielder_proof_for_wrong_challenge_is_refused():
    # anti-replay: a proof over a stale nonce does not satisfy the kernel's fresh challenge.
    cap = _cap(audience=WIELDER.public_key_b64)
    stale = prove_wielder(WIELDER, challenge="stale-nonce", capability=cap)
    dec = _gate(_action(cap=cap, proof=stale), challenge=CHALLENGE)
    assert dec.authorized is False and "wielder proof" in dec.reason
    assert "challenge does not match" in dec.reason


def test_wielder_proof_by_non_audience_key_is_refused():
    # a thief holding the bytes but not the audience private key cannot forge the proof.
    cap = _cap(audience=WIELDER.public_key_b64)
    forged = prove_wielder(ATTACKER, challenge=CHALLENGE, capability=cap)
    dec = _gate(_action(cap=cap, proof=forged))
    assert dec.authorized is False and "wielder proof" in dec.reason
    assert "does not verify" in dec.reason


def test_wielder_proof_bound_to_a_different_capability_is_refused():
    cap = _cap(audience=WIELDER.public_key_b64, revocation_id="rev-A")
    other = _cap(audience=WIELDER.public_key_b64, revocation_id="rev-B")
    proof_for_other = prove_wielder(WIELDER, challenge=CHALLENGE, capability=other)
    dec = _gate(_action(cap=cap, proof=proof_for_other))
    assert dec.authorized is False and "different capability" in dec.reason


def test_malformed_attenuation_bundle_is_refused():
    dec = _gate(ProposedAction(kind=ISOLATE_ENDPOINT, target=TARGET,
                               params={"capability": _cap(), "attenuations": [{"not": "valid"}]}))
    assert dec.authorized is False and "attenuation" in dec.reason


# ======================================================================================================
# ATTENUATION — the kernel honors a narrow-only chain.
# ======================================================================================================
def test_attenuation_narrowing_the_allowlist_removes_a_kind():
    # a bearer cap for {isolate_endpoint, block_ip}, attenuated down to {isolate_endpoint}.
    cap = _cap(kinds=[ISOLATE_ENDPOINT, BLOCK_IP], audience="*")
    att = attenuate(WIELDER, prev=cap, class_subset=[ISOLATE_ENDPOINT])  # bearer → any signer may attenuate
    # isolate_endpoint still authorized through the narrowed chain,
    allow = _gate(_action(kind=ISOLATE_ENDPOINT, cap=cap, attenuations=[att]))
    assert allow.authorized is True
    # but block_ip was narrowed out of the effective allowlist.
    deny = _gate(_action(kind=BLOCK_IP, cap=cap, attenuations=[att]))
    assert deny.authorized is False and "not in the capability allowlist" in deny.reason


def test_attenuation_redelegated_to_a_new_audience_requires_that_wielders_proof():
    # base pinned to WIELDER, re-delegated to SUBAUDITOR: SUBAUDITOR's proof passes, WIELDER's no longer does.
    cap = _cap(kinds=[ISOLATE_ENDPOINT], audience=WIELDER.public_key_b64)
    att = attenuate(WIELDER, prev=cap, next_audience=SUBAUDITOR.public_key_b64)
    sub_proof = prove_wielder(SUBAUDITOR, challenge=CHALLENGE, capability=cap)
    ok = _gate(_action(kind=ISOLATE_ENDPOINT, cap=cap, attenuations=[att], proof=sub_proof))
    assert ok.authorized is True
    old_proof = prove_wielder(WIELDER, challenge=CHALLENGE, capability=cap)
    bad = _gate(_action(kind=ISOLATE_ENDPOINT, cap=cap, attenuations=[att], proof=old_proof))
    assert bad.authorized is False and "wielder proof" in bad.reason


# ======================================================================================================
# OFFENSIVE KINDS — can never be registered or minted as defensive.
# ======================================================================================================
@pytest.mark.parametrize("bad", ["run_command", "exec", "reverse_shell", "exploit", "deploy_payload",
                                 "sqli", "upload_webshell", "code_exec"])
def test_offensive_kind_cannot_be_registered_as_defensive(bad):
    with pytest.raises(DefensiveCapabilityError, match="offensive"):
        register_defensive_kind(bad)
    assert is_defensive_kind(bad) is False


def test_offensive_kind_cannot_be_minted_into_a_defensive_capability():
    with pytest.raises(DefensiveCapabilityError, match="offensive"):
        mint_defensive_capability(OWNER, engagement=ENG, target=TARGET, kinds=["run_command"],
                                  not_before=0, not_after=2_000, rate_limit=5, revocation_id="r")
    # mixing a valid defensive kind with an offensive one is still refused (no partial grant).
    with pytest.raises(DefensiveCapabilityError, match="offensive"):
        mint_defensive_capability(OWNER, engagement=ENG, target=TARGET, kinds=[ISOLATE_ENDPOINT, "run_command"],
                                  not_before=0, not_after=2_000, rate_limit=5, revocation_id="r")


def test_unregistered_nonoffensive_kind_cannot_be_minted():
    with pytest.raises(DefensiveCapabilityError, match="not a registered defensive kind"):
        mint_defensive_capability(OWNER, engagement=ENG, target=TARGET, kinds=["frobnicate_widget"],
                                  not_before=0, not_after=2_000, rate_limit=5, revocation_id="r")


def test_empty_kinds_cannot_be_minted():
    with pytest.raises(DefensiveCapabilityError, match="at least one defensive kind"):
        mint_defensive_capability(OWNER, engagement=ENG, target=TARGET, kinds=[],
                                  not_before=0, not_after=2_000, rate_limit=5, revocation_id="r")


def test_an_offensive_kind_even_if_a_raw_cap_names_it_is_not_gated_as_defensive():
    # Defence in depth: even a raw owner-signed capability naming run_command is NOT a defensive action —
    # the kernel does not own the kind, so it returns None (the offensive kind never reaches this seam).
    raw = sign_capability(OWNER, engagement=ENG, identity_digest=defensive_target_digest(TARGET),
                          class_allowlist=["run_command"], not_before=0, not_after=2_000, rate_limit=5,
                          revocation_id="r", audience="*")
    assert _gate(ProposedAction(kind="run_command", target=TARGET, params={"capability": raw})) is None


# ======================================================================================================
# BYTE-IDENTITY / DEFAULT-OFF — existing kinds are untouched.
# ======================================================================================================
@pytest.mark.parametrize("kind", ["http_get", "http_post", "dns_lookup", "tls_probe", "anything_else"])
def test_non_defensive_kind_passes_through_untouched(kind):
    # the kernel returns None for every non-defensive kind — the caller gates it exactly as before.
    assert _gate(ProposedAction(kind=kind, target="https://in-scope.example")) is None


def test_http_get_gate_is_byte_identical_to_the_base_gate():
    # With the defensive seam present, an http_get decision is produced ENTIRELY by the base gate; the
    # defensive kernel contributes nothing (returns None), so body.gate == body.base_gate for http_get.
    base = lambda a: GateDecision(authorized=True, reason="scope ok")  # noqa: E731
    body = _ContainmentBody(ProposedAction(kind="http_get", target="https://in-scope.example"),
                            trusted_owner_pubkey=OWNER.public_key_b64, engagement=ENG, now=NOW,
                            challenge=CHALLENGE, base_gate=base)
    action = body._action
    assert gate_defensive_action(action, trusted_owner_pubkey=OWNER.public_key_b64, engagement=ENG,
                                 now=NOW, challenge=CHALLENGE, rate_limiter=DefensiveRateLimiter()) is None
    assert body.gate(action) == body.base_gate(action) == GateDecision(authorized=True, reason="scope ok")


def test_http_get_full_cycle_executes_without_any_capability():
    base = lambda a: GateDecision(authorized=True, reason="scope ok")  # noqa: E731
    body = _ContainmentBody(ProposedAction(kind="http_get", target="https://in-scope.example"),
                            trusted_owner_pubkey=OWNER.public_key_b64, engagement=ENG, now=NOW,
                            challenge=CHALLENGE, base_gate=base)
    outcome = body.run_cycle(Observation())
    assert outcome.executed is True and outcome.ok is True
    assert body.performed == [("http_get", "https://in-scope.example", "scope ok")]


def test_base_gate_defaults_to_fail_closed_deny_for_non_defensive_kinds():
    body = _ContainmentBody(ProposedAction(kind="http_get", target="x"),
                            trusted_owner_pubkey=OWNER.public_key_b64, engagement=ENG, now=NOW)
    dec = body.gate(body._action)
    assert dec.authorized is False and "no base gate configured" in dec.reason


# ======================================================================================================
# VOCABULARY — the fixed four.
# ======================================================================================================
def test_defensive_vocabulary_is_the_fixed_four():
    assert DEFENSIVE_KINDS == frozenset({"isolate_endpoint", "revoke_session", "block_ip", "quarantine_host"})
    for k in (ISOLATE_ENDPOINT, REVOKE_SESSION, BLOCK_IP, QUARANTINE_HOST):
        assert is_defensive_kind(k) is True


def test_capability_layer_adds_no_oracle_kind():
    # the capability is an authorization artifact, never an oracle input — the frozen 15 are untouched.
    from framework.v2.verify.verifier import _ALL_ORACLES
    assert len(_ALL_ORACLES) == 15
