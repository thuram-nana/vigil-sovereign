"""S6 — the ONE gate-of-record composition (`vigil_core.gate.conjunctive_decide`).

Pins the fail-closed invariants that make the conjunction safe as the shared authorization gate: only an
explicit WARDEN "auto" opens the gate; any conjunct raising is a DENY; an unrecognised WARDEN outcome is a
DENY (never a silent ALLOW); the destructive m-of-n conjunct uses a STRICT `authorized is True` identity
check (a truthy-but-not-True value must not open an irreversible action); and a destructive action with no
destruction gate is a DENY. These are the properties a naive edge-fold must never regress.

Run: pytest packages/core/vigil_core/tests/test_gate.py -q
"""
from types import SimpleNamespace

from vigil_core.gate import CrucibleResult, conjunctive_decide

ALLOW = CrucibleResult(allowed=True, reason="in envelope")
DENY = CrucibleResult(allowed=False, reason="out of scope")


def _war(outcome, tool="curl", reason="r"):
    return SimpleNamespace(outcome=outcome, tool=tool, reason=reason)


def _decide(*, cru=None, war="auto", destructive=False, dz=None):
    return conjunctive_decide(
        crucible_authorize=(cru if callable(cru) else (lambda: cru or ALLOW)),
        warden_decide=(war if callable(war) else (lambda: _war(war))),
        destructive=destructive,
        destruction_authorize=dz,
    )


def test_all_allow_opens_the_gate():
    v = _decide(cru=ALLOW, war="auto")
    assert v.allowed is True and v.outcome == "allow"


def test_crucible_deny_is_deny_and_checked_first():
    # even with a WARDEN that would auto, a CRUCIBLE deny wins (and warden is never consulted)
    called = {"warden": False}

    def war():
        called["warden"] = True
        return _war("auto")
    v = conjunctive_decide(crucible_authorize=lambda: DENY, warden_decide=war)
    assert v.outcome == "deny" and v.crucible_allowed is False and called["warden"] is False


def test_crucible_raise_is_deny():
    def boom():
        raise RuntimeError("killswitch engaged")
    v = conjunctive_decide(crucible_authorize=boom, warden_decide=lambda: _war("auto"))
    assert v.allowed is False and v.outcome == "deny" and "fail-closed" in v.reason


def test_warden_queue_is_not_allowed():
    v = _decide(war="queue")
    assert v.allowed is False and v.outcome == "queue"


def test_warden_deny_is_deny():
    v = _decide(war="deny")
    assert v.allowed is False and v.outcome == "deny"


def test_unrecognised_warden_outcome_is_deny_not_allow():
    # the load-bearing clause: a NEW/unexpected outcome string must never silently open the gate
    v = _decide(war="approve")   # not "auto"
    assert v.allowed is False and v.outcome == "deny"


def test_warden_raise_is_deny():
    def boom():
        raise ValueError("classifier crashed")
    v = conjunctive_decide(crucible_authorize=lambda: ALLOW, warden_decide=boom)
    assert v.allowed is False and v.outcome == "deny"


def test_destructive_without_a_destruction_gate_is_deny():
    v = _decide(war="auto", destructive=True, dz=None)
    assert v.allowed is False and v.outcome == "deny" and "threshold-destruction" in v.reason


def test_destructive_with_authorized_quorum_allows():
    v = _decide(war="auto", destructive=True,
                dz=lambda: SimpleNamespace(authorized=True, reason="3-of-5"))
    assert v.allowed is True and v.outcome == "allow"


def test_destructive_truthy_but_not_True_is_refused():
    # STRICT identity: a truthy-but-not-bool `authorized` (1, "yes", a non-empty list) must NOT open an
    # irreversible action. This is the exact guard a refactor must never relax to a truthiness test.
    for truthy in (1, "yes", ["ok"], object()):
        v = _decide(war="auto", destructive=True,
                    dz=(lambda t=truthy: SimpleNamespace(authorized=t, reason="buggy")))
        assert v.allowed is False and v.outcome == "deny", f"truthy {truthy!r} must not authorize"


def test_destructive_gate_raise_is_deny():
    def boom():
        raise RuntimeError("quorum service down")
    v = _decide(war="auto", destructive=True, dz=boom)
    assert v.allowed is False and v.outcome == "deny"


def test_destructive_authorized_false_is_deny():
    v = _decide(war="auto", destructive=True,
                dz=lambda: SimpleNamespace(authorized=False, reason="only 1-of-5"))
    assert v.allowed is False and v.outcome == "deny"
