"""The conjunctive offense gate (P7 Slice 3): CRUCIBLE-authority AND WARDEN, first-failure-wins,
fail-closed. Both halves injected as thunks, so the composition is tested without CRUCIBLE/kernel."""

from __future__ import annotations

import pytest

from vigil_integration.conjunctive_gate import (
    CrucibleResult,
    build_offense_gate,
    conjunctive_decide,
)
from vigil_integration.warden_gate import ToolDecision


def _cru(allowed: bool, reason: str = "ok"):
    return lambda: CrucibleResult(allowed=allowed, reason=reason)


def _cru_raises(exc: Exception):
    def f() -> CrucibleResult:
        raise exc
    return f


def _war(outcome: str, tier: str = "A2", tool: str = "http.get", reason: str = "r"):
    return lambda: ToolDecision(tool, tier, outcome, reason)


def test_crucible_deny_short_circuits_before_warden():
    called: list[int] = []

    def war() -> ToolDecision:
        called.append(1)
        return ToolDecision("http.get", "A0", "auto", "")

    v = conjunctive_decide(crucible_authorize=_cru(False, "out_of_scope"), warden_decide=war)
    assert v.outcome == "deny" and v.allowed is False
    assert v.crucible_allowed is False
    assert not called  # WARDEN half is never reached once CRUCIBLE denies (first-failure-wins)


def test_crucible_error_or_ethics_raise_fails_closed():
    # a raised EthicsViolation (e.g. killswitch tripped / expired) must DENY, not propagate/allow
    v = conjunctive_decide(
        crucible_authorize=_cru_raises(RuntimeError("engagement halted")),
        warden_decide=_war("auto"),
    )
    assert v.outcome == "deny" and v.crucible_allowed is None and v.warden is None


def test_both_allow_only_when_in_envelope_and_warden_auto():
    v = conjunctive_decide(crucible_authorize=_cru(True), warden_decide=_war("auto", "A1"))
    assert v.allowed is True and v.outcome == "allow"


def test_in_envelope_but_warden_queue_yields_queue():
    v = conjunctive_decide(crucible_authorize=_cru(True), warden_decide=_war("queue", "A2"))
    assert v.allowed is False and v.outcome == "queue" and v.crucible_allowed is True
    assert v.warden is not None and v.warden.outcome == "queue"


def test_warden_deny_yields_deny_even_in_envelope():
    v = conjunctive_decide(crucible_authorize=_cru(True), warden_decide=_war("deny", "A3"))
    assert v.outcome == "deny" and v.crucible_allowed is True


def test_warden_error_fails_closed():
    def war() -> ToolDecision:
        raise RuntimeError("kernel binary missing")

    v = conjunctive_decide(crucible_authorize=_cru(True), warden_decide=war)
    assert v.outcome == "deny" and v.crucible_allowed is True and v.warden is None


def test_only_auto_allows_unknown_warden_outcome_fails_closed():
    # BLOCK-3 regression: an unexpected WARDEN outcome must DENY, never default to ALLOW.
    for bad in ("allow", "", "maybe", "APPROVE"):
        v = conjunctive_decide(crucible_authorize=_cru(True), warden_decide=_war(bad))
        assert v.outcome == "deny" and v.allowed is False, f"outcome {bad!r} must fail closed"
    # and the ONLY outcome that allows is exactly "auto"
    assert conjunctive_decide(crucible_authorize=_cru(True), warden_decide=_war("auto")).outcome == "allow"


def test_build_offense_gate_refuses_none_trust_root():
    # BLOCK-4 regression: a None trust_root would load the authority UNSIGNED -> refuse to build.
    with pytest.raises(ValueError, match="trust_root"):
        build_offense_gate(slug="acme", trust_root=None, classify=lambda n: "A3")


# --- the threshold-destruction conjunct (I4 wiring) -------------------------------------------

from vigil_integration.conjunctive_gate import DestructionOutcome


def _dz(authorized: bool, reason: str = "r"):
    return lambda: DestructionOutcome(authorized=authorized, reason=reason)


def test_destructive_action_needs_the_destruction_gate_wired():
    # a destructive action with CRUCIBLE+WARDEN both allowing STILL denies if no destruction gate is
    # wired — fail-closed: an irreversible action never proceeds on the two base gates alone.
    v = conjunctive_decide(crucible_authorize=_cru(True), warden_decide=_war("auto"), destructive=True)
    assert v.outcome == "deny" and "threshold-destruction gate" in v.reason


def test_destructive_action_allowed_only_when_all_three_gates_pass():
    v = conjunctive_decide(crucible_authorize=_cru(True), warden_decide=_war("auto"),
                           destructive=True, destruction_authorize=_dz(True))
    assert v.outcome == "allow" and "threshold-authorized" in v.reason


def test_destructive_action_denied_when_threshold_not_met():
    v = conjunctive_decide(crucible_authorize=_cru(True), warden_decide=_war("auto"),
                           destructive=True, destruction_authorize=_dz(False, "missing owner"))
    assert v.outcome == "deny" and "not threshold-authorized" in v.reason and "missing owner" in v.reason


def test_destruction_gate_error_fails_closed():
    def boom():
        raise RuntimeError("spine unavailable")
    v = conjunctive_decide(crucible_authorize=_cru(True), warden_decide=_war("auto"),
                           destructive=True, destruction_authorize=boom)
    assert v.outcome == "deny" and "destruction gate error" in v.reason


def test_non_destructive_action_never_consults_the_destruction_gate():
    called: list[int] = []

    def dz():
        called.append(1)
        return DestructionOutcome(True, "")
    v = conjunctive_decide(crucible_authorize=_cru(True), warden_decide=_war("auto"),
                           destructive=False, destruction_authorize=dz)
    assert v.outcome == "allow" and not called  # not destructive → threshold gate irrelevant


def test_destructive_but_warden_queue_still_queues():
    # threshold authorization does not bypass WARDEN's owner-approval tier — both are needed
    v = conjunctive_decide(crucible_authorize=_cru(True), warden_decide=_war("queue"),
                           destructive=True, destruction_authorize=_dz(True))
    assert v.outcome == "queue"


def test_end_to_end_with_the_real_destruction_gate():
    # the real destruction_gate.DestructionDecision duck-types DestructionOutcome (.authorized/.reason)
    from vigil_core import AuthorizerKey, TrustRoot, generate_keypair
    from vigil_integration.destruction_gate import (
        DestructionAuthority,
        DestructionAuthorization,
        DestructiveAction,
        authorize_destruction,
        sign_authorization,
    )

    owner, worker = generate_keypair(), generate_keypair()
    tr = TrustRoot(threshold=2, authorizers=[
        AuthorizerKey(key_id="owner", name="owner", public_key_b64=owner.public_key_b64),
        AuthorizerKey(key_id="worker", name="worker", public_key_b64=worker.public_key_b64)])
    authority = DestructionAuthority(trust_root=tr, mandatory_signer_ids={"owner"})
    action = DestructiveAction(action_id="rm-1", engagement_slug="acme", target="db", blast_class="destructive")
    auth = DestructionAuthorization(action_id="rm-1", engagement_slug="acme", target="db",
                                    blast_class="destructive", not_before=0, not_after=100, nonce="n1")
    signed = sign_authorization(auth, [("owner", owner.private_key_b64), ("worker", worker.private_key_b64)])

    def real_dz():
        return authorize_destruction(action, signed, authority=authority, now=50, is_consumed=lambda n: False)

    assert conjunctive_decide(crucible_authorize=_cru(True), warden_decide=_war("auto"),
                              destructive=True, destruction_authorize=real_dz).outcome == "allow"
    # an owner-less quorum (worker only) is denied through the same wiring
    only_worker = sign_authorization(auth, [("worker", worker.private_key_b64)])

    def bad_dz():
        return authorize_destruction(action, only_worker, authority=authority, now=50, is_consumed=lambda n: False)
    assert conjunctive_decide(crucible_authorize=_cru(True), warden_decide=_war("auto"),
                              destructive=True, destruction_authorize=bad_dz).outcome == "deny"
