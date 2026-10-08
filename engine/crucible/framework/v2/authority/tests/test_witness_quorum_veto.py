"""
M4.4 — the OPT-IN, DEFAULT-OFF, DEMOTE-ONLY N-of-M oracle-witness quorum ACTION gate wired into
`authorize_action` as conjunct 6c, mirroring the M4.2 blast-radius veto precedent exactly.

Properties pinned (the blast-veto test's identical guard set, plus the M4.4-specific ones):

  * FIRE CONDITIONS: with an injected evaluator whose verdict is ``applicable and not ok`` (fewer than
    N distinct oracle-witness kinds re-fired for an operator-critical class), the otherwise-allowed
    action is DENIED (code ``witness_quorum``). An ``applicable and ok`` or an inapplicable verdict
    ALLOWS.
  * DEFAULT-OFF BYTE-IDENTITY: absent the kwargs (or with them None), every decision — allow AND each
    denial code — is byte-identical to the pre-M4.4 gate.
  * PRECEDENCE / NON-CONSULTATION: the veto is the LAST conjunct (after 6b blast), so a halted/expired/
    out-of-scope/destructive/budget/blast denial keeps its own code and the evaluator is NOT consulted
    for a refused action (proved with an evaluator that raises if called).
  * DEMOTE-ONLY: the veto can only ever map allowed True->False; an inapplicable or satisfied verdict
    never changes an outcome, and nothing is promoted.
  * RE-EXECUTED ORACLE WITNESSES ONLY: wired with the REAL `witness_quorum_predicate`, a 2-witness
    retained context ALLOWS and a 1-witness one is BLOCKED; a producer-carried corroboration set stuffed
    into the context does NOT add witnesses (only re-fired oracle signals count).
  * PROCEED-BELOW-QUORUM ACK: a signed ack bound to THIS action lets the under-quorum action through and
    does NOT generalise to another action (different target), a tampered/unsigned ack does not, and the
    ack NEVER promotes the finding (the gate still mints nothing).
  * MINTS NOTHING ON BLOCK: the gate returns a plain AuthorizationDecision and writes no FACT / cert /
    spine row; the gate module imports neither the oracle/veracity layer nor any crypto.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from framework.v2.entitlement.crypto import generate_keypair
from framework.v2.entitlement.models import AuthorizerKey, TrustRoot

from ...common.errors import (
    AuthorityExpired,
    BudgetExhausted,
    DestructiveActionRefused,
    EngagementHalted,
    OutOfScope,
    WitnessQuorumUnmet,
)
from ..gate import authorize_action, require_authorization
from ..killswitch import KillSwitch
from ..models import ActionRequest, AuthorityState, EngagementAuthority, TargetEnvironment
from ..witness_quorum_gate import (
    ProceedBelowQuorumAck,
    proceed_below_quorum_checker,
    sign_ack,
    witness_quorum_predicate,
)

_NOW = datetime(2026, 6, 1, 12, 0, tzinfo=timezone.utc)
_SLUG = "eng"
_CLASS = "error_based_sqli"


def _authority(**kw: object) -> EngagementAuthority:
    base = dict(
        engagement_slug=_SLUG,
        environment=TargetEnvironment.TWIN,
        scope=["*.example.com"],
        not_before=_NOW - timedelta(hours=1),
        not_after=_NOW + timedelta(hours=1),
    )
    base.update(kw)
    return EngagementAuthority(**base)  # type: ignore[arg-type]


def _req(target: str = "https://app.example.com/x", destructive: bool = False, **kw) -> ActionRequest:
    return ActionRequest(target=target, destructive=destructive, **kw)


@dataclass
class _Verdict:
    """A structural stand-in for QuorumOutcome — proves the gate duck-types the injected evaluator's
    return (it needs only ``applicable`` / ``ok`` / ``reason``, and ``kinds``/``required`` for the ack)."""
    applicable: bool
    ok: bool
    reason: str = "witness quorum NOT met: 1 < required 2"
    kinds: tuple = ()
    required: int = 2
    got: int = 1


def _fn(applicable: bool, ok: bool, **kw):
    return lambda _req: _Verdict(applicable, ok, **kw)


def _boom(_req):  # an evaluator that MUST NOT be consulted for a refused action
    raise AssertionError("witness-quorum evaluator consulted for an action denied by a prior check")


# --- fire conditions ---------------------------------------------------------------------------

def test_veto_denies_an_applicable_under_quorum_action() -> None:
    d = authorize_action(_authority(), _req(), now=_NOW, witness_quorum_fn=_fn(True, False))
    assert d.allowed is False
    assert d.denial_code == "witness_quorum"
    assert d.state is AuthorityState.ACTIVE
    assert "witness-quorum veto" in d.reason


def test_veto_allows_a_satisfied_quorum() -> None:
    d = authorize_action(_authority(), _req(), now=_NOW, witness_quorum_fn=_fn(True, True))
    assert d.allowed is True
    assert d.denial_code == ""


def test_veto_allows_an_inapplicable_verdict() -> None:
    # policy off / non-critical class / no witness_context ⇒ applicable False ⇒ no-op.
    d = authorize_action(_authority(), _req(), now=_NOW, witness_quorum_fn=_fn(False, True))
    assert d.allowed is True


def test_require_authorization_raises_typed_witness_quorum_unmet() -> None:
    with pytest.raises(WitnessQuorumUnmet):
        require_authorization(_authority(), _req(), now=_NOW, witness_quorum_fn=_fn(True, False))
    d = require_authorization(_authority(), _req(), now=_NOW, witness_quorum_fn=_fn(True, True))
    assert d.allowed is True


# --- precedence: the veto is last, and the evaluator is not consulted for a refused action ------

@pytest.mark.parametrize("make_call", [
    lambda: ((_authority(), _req(target="https://evil.invalid/x")),
             dict(now=_NOW, witness_quorum_fn=_boom), "out_of_scope"),
    lambda: ((_authority(), _req(destructive=True)),
             dict(now=_NOW, witness_quorum_fn=_boom), "destructive"),
    lambda: ((_authority(max_actions=1), _req()),
             dict(now=_NOW, actions_taken=1, witness_quorum_fn=_boom), "budget"),
    lambda: ((_authority(), _req()),
             dict(now=_NOW + timedelta(hours=9), witness_quorum_fn=_boom), "expired"),
])
def test_prior_denials_win_and_do_not_consult_the_evaluator(make_call) -> None:
    (args, kwargs, expected) = make_call()
    d = authorize_action(*args, **kwargs)   # _boom raises AssertionError if consulted
    assert d.allowed is False
    assert d.denial_code == expected


def test_killswitch_wins_over_the_veto_without_consulting_it(tmp_path: Path) -> None:
    ks = KillSwitch(_SLUG, path=tmp_path / "halt")
    ks.trip("stop")
    d = authorize_action(_authority(), _req(), killswitch=ks, now=_NOW, witness_quorum_fn=_boom)
    assert d.denial_code == "halted"


def test_blast_veto_wins_before_the_witness_quorum_is_consulted() -> None:
    """6b (blast) is BEFORE 6c (witness quorum): an action vetoed on blast keeps code ``blast_radius``
    and the witness evaluator is never consulted."""
    @dataclass
    class _BlastV:
        incremental_blast: float
        newly_reachable_jewels: list

    d = authorize_action(
        _authority(), _req(), now=_NOW,
        blast_radius_fn=lambda _r: _BlastV(50.0, ["datastore:crown"]), blast_ceiling=10.0,
        witness_quorum_fn=_boom)
    assert d.allowed is False and d.denial_code == "blast_radius"


# --- default-off byte-identity ----------------------------------------------------------------

_SCENARIOS = {
    "allowed": (lambda: (_authority(), _req()), dict(now=_NOW)),
    "out_of_scope": (lambda: (_authority(), _req(target="https://x.invalid/")), dict(now=_NOW)),
    "destructive": (lambda: (_authority(), _req(destructive=True)), dict(now=_NOW)),
    "budget": (lambda: (_authority(max_actions=2), _req()), dict(now=_NOW, actions_taken=2)),
    "expired": (lambda: (_authority(), _req()), dict(now=_NOW + timedelta(hours=9))),
}


def test_passing_none_kwargs_is_byte_identical_to_omitting_them() -> None:
    for name, (mk, kwargs) in _SCENARIOS.items():
        omitted = authorize_action(*mk(), **kwargs)
        explicit_none = authorize_action(*mk(), **kwargs,
                                         witness_quorum_fn=None, witness_quorum_ack=None)
        assert omitted.model_dump() == explicit_none.model_dump(), f"default-off drifted for {name}"


def test_an_armed_non_firing_evaluator_leaves_every_prior_outcome_untouched() -> None:
    # An evaluator that never fires (applicable but ok, or inapplicable) must reproduce the exact same
    # decisions as the un-armed gate for every scenario — the veto adds nothing on paths it does not own.
    satisfied = _fn(True, True)
    for name, (mk, kwargs) in _SCENARIOS.items():
        plain = authorize_action(*mk(), **kwargs)
        armed = authorize_action(*mk(), **kwargs, witness_quorum_fn=satisfied)
        assert plain.model_dump() == armed.model_dump(), f"armed-but-non-firing veto drifted for {name}"


# --- the REAL re-executed-oracle quorum composes with the gate ---------------------------------

def _ctx_two_witness() -> dict:
    """A GENUINE 2-witness context: a datastore error (ERROR_SIGNATURE) AND a unique canary reaching
    the sink (SIDE_EFFECT), merged under error_based_sqli (maps to both oracle kinds). Re-derived by
    RE-EXECUTING the deterministic oracle — nothing trusts a claimed corroboration set."""
    from framework.v2.verify.adapter import FindingContext
    err = FindingContext.from_error_signature(
        observed_body="You have an error in your SQL syntax; check the manual that corresponds to "
                      "your MySQL server version near ''' at line 1",
        control_body="OK normal page with results", bug_class=_CLASS)
    se = FindingContext.from_side_effect(
        marker="OBSIDIANCANARY7Z9Q",
        observed_sink="row: OBSIDIANCANARY7Z9Q reflected into the SQL error output OBSIDIANCANARY7Z9Q",
        control_sink="row: normal content, no canary here", bug_class=_CLASS)
    return err.merge(se).model_dump(mode="json")


def _ctx_one_witness() -> dict:
    from framework.v2.verify.adapter import FindingContext
    return FindingContext.from_error_signature(
        observed_body="You have an error in your SQL syntax; check the manual that corresponds to "
                      "your MySQL server version near ''' at line 1",
        control_body="OK normal page with results", bug_class=_CLASS).model_dump(mode="json")


_POLICY_ON = __import__(
    "framework.v2.veracity.witness_quorum", fromlist=["WitnessQuorumConfig"]
).WitnessQuorumConfig(enabled=True, quorum_n=2, critical_classes=frozenset({_CLASS}))


def test_real_predicate_allows_two_witnesses_and_blocks_one() -> None:
    fn = witness_quorum_predicate(_POLICY_ON)

    allowed = authorize_action(
        _authority(), _req(bug_class=_CLASS, witness_context=_ctx_two_witness()),
        now=_NOW, witness_quorum_fn=fn)
    assert allowed.allowed is True, allowed.reason

    blocked = authorize_action(
        _authority(), _req(bug_class=_CLASS, witness_context=_ctx_one_witness()),
        now=_NOW, witness_quorum_fn=fn)
    assert blocked.allowed is False and blocked.denial_code == "witness_quorum"
    assert "error_signature" in blocked.reason and "< required 2" in blocked.reason


def test_real_predicate_no_witness_context_is_a_noop() -> None:
    fn = witness_quorum_predicate(_POLICY_ON)
    d = authorize_action(_authority(), _req(bug_class=_CLASS), now=_NOW, witness_quorum_fn=fn)
    assert d.allowed is True  # witness_context None ⇒ inapplicable ⇒ byte-identical


def test_producer_carried_corroboration_set_does_not_satisfy_the_quorum() -> None:
    """A single real oracle witness with a FAKE carried corroboration set stuffed into the context must
    still BLOCK: only RE-FIRED oracle signals count, never a claimed/critic/LLM corroboration list."""
    fn = witness_quorum_predicate(_POLICY_ON)
    ctx = _ctx_one_witness()
    ctx["corroborating_witnesses"] = ["side_effect", "timing", "oob_callback"]  # a producer lie
    ctx["critic_votes"] = 5
    d = authorize_action(
        _authority(), _req(bug_class=_CLASS, witness_context=ctx), now=_NOW, witness_quorum_fn=fn)
    assert d.allowed is False and d.denial_code == "witness_quorum"


# --- PROCEED-BELOW-QUORUM operator acknowledgement ---------------------------------------------

def _trust_root(threshold: int = 1, n: int = 1):
    keys = [generate_keypair() for _ in range(n)]
    tr = TrustRoot(schema_version=1, threshold=threshold, authorizers=[
        AuthorizerKey(key_id=f"op-{i}", name=f"Op{i}", public_key_b64=k.public_key_b64)
        for i, k in enumerate(keys)])
    signers = [(f"op-{i}", k.private_key_b64) for i, k in enumerate(keys)]
    return tr, signers


def _ack_for(target: str, signers, *, kinds=("error_signature",), required=2, slug=_SLUG):
    ack = ProceedBelowQuorumAck(
        engagement_slug=slug, target=target, bug_class=_CLASS,
        witness_kinds_present=tuple(kinds), required_n=required, action_kind="generic")
    return sign_ack(ack, signers)


def test_signed_ack_bound_to_this_action_lets_the_under_quorum_action_through() -> None:
    tr, signers = _trust_root()
    fn = witness_quorum_predicate(_POLICY_ON)
    target = "https://app.example.com/x"
    signed = _ack_for(target, signers)
    ack = proceed_below_quorum_checker(signed, engagement_slug=_SLUG, trust_root=tr)

    # Without the ack: BLOCKED. With the bound ack: ALLOWED (the ACTION proceeds below quorum).
    blocked = authorize_action(
        _authority(), _req(target=target, bug_class=_CLASS, witness_context=_ctx_one_witness()),
        now=_NOW, witness_quorum_fn=fn)
    assert blocked.allowed is False and blocked.denial_code == "witness_quorum"

    allowed = authorize_action(
        _authority(), _req(target=target, bug_class=_CLASS, witness_context=_ctx_one_witness()),
        now=_NOW, witness_quorum_fn=fn, witness_quorum_ack=ack)
    assert allowed.allowed is True and allowed.denial_code == ""


def test_ack_does_not_generalise_to_another_action() -> None:
    tr, signers = _trust_root()
    fn = witness_quorum_predicate(_POLICY_ON)
    # ack bound to app host; attempt it on a DIFFERENT in-scope target → binding fails → still BLOCKED.
    signed = _ack_for("https://app.example.com/x", signers)
    ack = proceed_below_quorum_checker(signed, engagement_slug=_SLUG, trust_root=tr)
    d = authorize_action(
        _authority(), _req(target="https://other.example.com/y", bug_class=_CLASS,
                           witness_context=_ctx_one_witness()),
        now=_NOW, witness_quorum_fn=fn, witness_quorum_ack=ack)
    assert d.allowed is False and d.denial_code == "witness_quorum"


def test_ack_with_wrong_witness_set_does_not_cover_the_action() -> None:
    tr, signers = _trust_root()
    fn = witness_quorum_predicate(_POLICY_ON)
    target = "https://app.example.com/x"
    # ack claims a DIFFERENT re-fired witness set than the one the evaluator reports → binding fails.
    signed = _ack_for(target, signers, kinds=("timing",))
    ack = proceed_below_quorum_checker(signed, engagement_slug=_SLUG, trust_root=tr)
    d = authorize_action(
        _authority(), _req(target=target, bug_class=_CLASS, witness_context=_ctx_one_witness()),
        now=_NOW, witness_quorum_fn=fn, witness_quorum_ack=ack)
    assert d.allowed is False and d.denial_code == "witness_quorum"


def test_ack_signed_by_a_foreign_key_does_not_cover_the_action() -> None:
    tr, _signers = _trust_root()
    _foreign_tr, foreign_signers = _trust_root()      # a key NOT in `tr`
    fn = witness_quorum_predicate(_POLICY_ON)
    target = "https://app.example.com/x"
    signed = _ack_for(target, foreign_signers)        # correctly bound, but wrong signer
    ack = proceed_below_quorum_checker(signed, engagement_slug=_SLUG, trust_root=tr)
    d = authorize_action(
        _authority(), _req(target=target, bug_class=_CLASS, witness_context=_ctx_one_witness()),
        now=_NOW, witness_quorum_fn=fn, witness_quorum_ack=ack)
    assert d.allowed is False and d.denial_code == "witness_quorum"


def test_absent_ack_an_under_quorum_action_is_denied() -> None:
    fn = witness_quorum_predicate(_POLICY_ON)
    d = authorize_action(
        _authority(), _req(bug_class=_CLASS, witness_context=_ctx_one_witness()),
        now=_NOW, witness_quorum_fn=fn, witness_quorum_ack=None)
    assert d.allowed is False and d.denial_code == "witness_quorum"


# --- mints nothing on block + the gate stays decoupled -----------------------------------------

def test_block_mints_nothing_and_writes_no_file(tmp_path, monkeypatch) -> None:
    """A blocked action returns a plain AuthorizationDecision and creates NO FACT / cert / spine row.
    We run the full REAL evaluator path inside an isolated CRUCIBLE_ROOT and assert nothing was written
    and the return is only the decision object (no certificate is produced by the gate)."""
    from framework.v2.authority.models import AuthorizationDecision
    root = tmp_path / "crucible-root"
    root.mkdir()
    monkeypatch.setenv("CRUCIBLE_ROOT", str(root))
    fn = witness_quorum_predicate(_POLICY_ON)
    d = authorize_action(
        _authority(), _req(bug_class=_CLASS, witness_context=_ctx_one_witness()),
        now=_NOW, witness_quorum_fn=fn)
    assert isinstance(d, AuthorizationDecision)
    assert d.allowed is False and d.denial_code == "witness_quorum"
    # the gate wrote nothing: no files created under the isolated root by the decision.
    assert list(root.rglob("*")) == []


def test_the_gate_module_imports_neither_the_oracle_layer_nor_crypto() -> None:
    """The quorum (like the world model) is ADVISORY to the gate — reached only through the injected
    callables. If gate.py ever imported the veracity/verify/oracle layer or any crypto directly, the
    decoupling (and the 'never an oracle input / mints nothing' invariant) would be silently broken, so
    this AST-scans the real source."""
    src = (Path(__file__).resolve().parents[1] / "gate.py").read_text(encoding="utf-8")
    tree = ast.parse(src)
    forbidden = ("worldmodel", "verify", "oracle", "veracity", "witness_quorum", "crypto",
                 "evidence", "vigil_core")
    offenders: list[str] = []
    for node in ast.walk(tree):
        mods: list[str] = []
        if isinstance(node, ast.ImportFrom) and node.module:
            mods.append(node.module)
        elif isinstance(node, ast.Import):
            mods += [a.name for a in node.names]
        for mod in mods:
            if any(bad in mod for bad in forbidden):
                offenders.append(mod)
    assert not offenders, f"authority/gate.py must not import the oracle/veracity layer or crypto: {offenders}"
