"""
M4.2 — the OPT-IN, DEFAULT-OFF pre-action blast-radius veto wired into `authorize_action`.

Four properties are pinned:

  * FIRE CONDITIONS: with both a predictor and a ceiling supplied, an otherwise-allowed action whose
    predicted INCREMENTAL blast strictly exceeds the ceiling is DENIED (code `blast_radius`); at or
    below the ceiling it is ALLOWED.
  * DEFAULT-OFF BYTE-IDENTITY: absent the kwargs (or with either one absent), every decision — allow
    AND each denial code — is byte-identical to the pre-M4.2 gate.
  * PRECEDENCE / NON-CONSULTATION: the veto is the LAST conjunct, so a halted/expired/out-of-scope/
    destructive/budget denial keeps its own code and the predictor is NOT consulted for a refused
    action (proved with a predictor that raises if called).
  * ADVISORY BY INJECTION: the gate reaches the world model only through the injected callable — the
    gate module imports neither the world model nor the oracle/verify layer (a FACT is never minted).

The real `predict_action_blast_radius` is wired into the gate at the end, with a high-blast positive
and a benign safe-negative control, so the two halves are shown to compose.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from ...common.errors import (
    AuthorityExpired,
    BlastRadiusExceeded,
    BudgetExhausted,
    DestructiveActionRefused,
    EngagementHalted,
    OutOfScope,
)
from ..gate import authorize_action, require_authorization
from ..killswitch import KillSwitch
from ..models import ActionRequest, AuthorityState, EngagementAuthority, TargetEnvironment

_NOW = datetime(2026, 6, 1, 12, 0, tzinfo=timezone.utc)


def _authority(**kw: object) -> EngagementAuthority:
    base = dict(
        engagement_slug="eng",
        environment=TargetEnvironment.TWIN,
        scope=["*.example.com"],
        not_before=_NOW - timedelta(hours=1),
        not_after=_NOW + timedelta(hours=1),
    )
    base.update(kw)
    return EngagementAuthority(**base)  # type: ignore[arg-type]


def _req(target: str = "https://app.example.com/x", destructive: bool = False) -> ActionRequest:
    return ActionRequest(target=target, destructive=destructive)


@dataclass
class _Verdict:
    """A structural stand-in for ForwardBlastResult — proves the gate duck-types the injected
    predictor's return (it needs only these two attributes)."""
    incremental_blast: float
    newly_reachable_jewels: list[str]


def _fn(blast: float, jewels: list[str] | None = None):
    return lambda _req: _Verdict(blast, jewels or [])


def _boom(_req):  # a predictor that MUST NOT be consulted for a refused action
    raise AssertionError("blast predictor consulted for an action denied by a prior check")


# --- fire conditions ---------------------------------------------------------------------------

def test_veto_denies_strictly_above_ceiling() -> None:
    d = authorize_action(_authority(), _req(), now=_NOW,
                         blast_radius_fn=_fn(50.0, ["datastore:crown"]), blast_ceiling=10.0)
    assert d.allowed is False
    assert d.denial_code == "blast_radius"
    assert d.state is AuthorityState.ACTIVE
    assert "crown" in d.reason and "50.0" in d.reason


def test_veto_allows_at_the_ceiling_boundary() -> None:
    # the comparison is strict `>` — exactly at the ceiling is allowed.
    d = authorize_action(_authority(), _req(), now=_NOW, blast_radius_fn=_fn(10.0), blast_ceiling=10.0)
    assert d.allowed is True
    assert d.denial_code == ""


def test_veto_allows_below_ceiling() -> None:
    d = authorize_action(_authority(), _req(), now=_NOW, blast_radius_fn=_fn(3.0), blast_ceiling=10.0)
    assert d.allowed is True


def test_require_authorization_raises_typed_blast_radius_exceeded() -> None:
    with pytest.raises(BlastRadiusExceeded):
        require_authorization(_authority(), _req(), now=_NOW,
                              blast_radius_fn=_fn(99.0, ["datastore:crown"]), blast_ceiling=10.0)
    # below ceiling → returns the allowed decision, raises nothing
    d = require_authorization(_authority(), _req(), now=_NOW, blast_radius_fn=_fn(1.0), blast_ceiling=10.0)
    assert d.allowed is True


# --- both kwargs are required to arm the veto --------------------------------------------------

def test_predictor_without_ceiling_is_inert() -> None:
    d = authorize_action(_authority(), _req(), now=_NOW,
                         blast_radius_fn=_fn(1_000.0, ["x"]), blast_ceiling=None)
    assert d.allowed is True   # a would-veto predictor with no ceiling does nothing


def test_ceiling_without_predictor_is_inert() -> None:
    d = authorize_action(_authority(), _req(), now=_NOW, blast_radius_fn=None, blast_ceiling=0.0)
    assert d.allowed is True   # a ceiling of 0 with no predictor still never vetoes


# --- precedence: the veto is last, and the predictor is not consulted for a refused action ------

@pytest.mark.parametrize("make_call", [
    # each returns (args, kwargs) for a call that MUST be denied by a prior check, with a _boom
    # predictor armed — the predictor must never run, and the original denial code must survive.
    lambda: ((_authority(), _req(target="https://evil.invalid/x")),
             dict(now=_NOW, blast_radius_fn=_boom, blast_ceiling=0.0), "out_of_scope"),
    lambda: ((_authority(), _req(destructive=True)),
             dict(now=_NOW, blast_radius_fn=_boom, blast_ceiling=0.0), "destructive"),
    lambda: ((_authority(max_actions=1), _req()),
             dict(now=_NOW, actions_taken=1, blast_radius_fn=_boom, blast_ceiling=0.0), "budget"),
    lambda: ((_authority(), _req()),
             dict(now=_NOW + timedelta(hours=9), blast_radius_fn=_boom, blast_ceiling=0.0), "expired"),
])
def test_prior_denials_win_and_do_not_consult_the_predictor(make_call) -> None:
    (args, kwargs, expected) = make_call()
    d = authorize_action(*args, **kwargs)   # _boom raises AssertionError if consulted
    assert d.allowed is False
    assert d.denial_code == expected


def test_killswitch_wins_over_the_veto_without_consulting_it(tmp_path: Path) -> None:
    ks = KillSwitch("eng", path=tmp_path / "halt")
    ks.trip("stop")
    d = authorize_action(_authority(), _req(), killswitch=ks, now=_NOW,
                         blast_radius_fn=_boom, blast_ceiling=0.0)
    assert d.denial_code == "halted"


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
        explicit_none = authorize_action(*mk(), **kwargs, blast_radius_fn=None, blast_ceiling=None)
        assert omitted.model_dump() == explicit_none.model_dump(), f"default-off drifted for {name}"


def test_an_armed_veto_leaves_every_prior_outcome_untouched() -> None:
    # Arming the veto with a huge ceiling (so it never fires) must reproduce the exact same decisions
    # as the un-armed gate for every scenario — the veto adds nothing on the paths it does not own.
    huge = _fn(0.0)   # zero incremental blast, so it could only ever ALLOW
    for name, (mk, kwargs) in _SCENARIOS.items():
        plain = authorize_action(*mk(), **kwargs)
        armed = authorize_action(*mk(), **kwargs, blast_radius_fn=huge, blast_ceiling=1_000_000.0)
        assert plain.model_dump() == armed.model_dump(), f"armed-but-non-firing veto drifted for {name}"


# --- the real predictor composes with the gate ------------------------------------------------

def test_real_predictor_wired_into_the_gate_vetoes_high_blast_allows_benign() -> None:
    from framework.v2.worldmodel.graph import WorldModel
    from framework.v2.worldmodel.impact import ImpactModel, predict_action_blast_radius
    from framework.v2.worldmodel.models import Edge, EdgeKind, Node, NodeKind

    ek = EdgeKind.REACHABLE_FROM

    def _n(w, nid, k):
        w.add_node(Node(id=nid, kind=k, provenance="t", confidence=1.0, first_seen=1, last_seen=1))

    def _e(w, s, d):
        w.add_edge(Edge(src=s, dst=d, kind=ek, provenance="t", confidence=1.0, first_seen=1, last_seen=1))

    w = WorldModel()
    for nid, k in [("host:attacker", NodeKind.HOST), ("host:gw", NodeKind.HOST),
                   ("host:island", NodeKind.HOST), ("datastore:crown", NodeKind.DATASTORE)]:
        _n(w, nid, k)
    _e(w, "host:gw", "datastore:crown")     # crown behind gw; attacker cannot reach it yet
    m = ImpactModel(nodes={"datastore:crown": 500.0}, default=1.0)
    edges_before = w.edge_count

    def high_fn(_req):   # the action opens attacker -> gw, exposing the crown jewel
        return predict_action_blast_radius(
            w, "host:attacker", [("host:attacker", "host:gw")], [NodeKind.DATASTORE],
            edge_kinds=[ek], impact=m)

    def benign_fn(_req):  # the action opens a dead-end edge
        return predict_action_blast_radius(
            w, "host:attacker", [("host:attacker", "host:island")], [NodeKind.DATASTORE],
            edge_kinds=[ek], impact=m)

    denied = authorize_action(_authority(), _req(), now=_NOW, blast_radius_fn=high_fn, blast_ceiling=100.0)
    assert denied.allowed is False and denied.denial_code == "blast_radius"
    assert "datastore:crown" in denied.reason

    allowed = authorize_action(_authority(), _req(), now=_NOW, blast_radius_fn=benign_fn, blast_ceiling=100.0)
    assert allowed.allowed is True

    assert w.edge_count == edges_before   # the advisory predictor never mutated the world


# --- advisory BY INJECTION: the gate stays decoupled from the world model and the oracle layer --

def test_the_gate_module_imports_neither_the_world_model_nor_the_oracle_layer() -> None:
    """The world model is ADVISORY to the gate — reached only through the injected callable. If the
    gate ever imported `worldmodel` or the `verify`/oracle layer directly, the decoupling (and the
    'never an oracle input' invariant) would be silently broken, so this AST-scans the real source."""
    src = (Path(__file__).resolve().parents[1] / "gate.py").read_text(encoding="utf-8")
    tree = ast.parse(src)
    offenders: list[str] = []
    for node in ast.walk(tree):
        mods: list[str] = []
        if isinstance(node, ast.ImportFrom) and node.module:
            mods.append(node.module)
        elif isinstance(node, ast.Import):
            mods += [a.name for a in node.names]
        for mod in mods:
            if "worldmodel" in mod or "verify" in mod or "oracle" in mod:
                offenders.append(mod)
    assert not offenders, f"authority/gate.py must not import the world model / oracle layer: {offenders}"


# --- 6b ACK (M-11 eval-grant): an action-bound operator ack lifts the veto for THIS action only -----

def test_blast_ack_none_is_byte_identical_to_the_pre_ack_gate() -> None:
    """Default path: blast_radius_ack omitted / None ⇒ an over-ceiling action is DENIED exactly as before
    (the new kwarg defaults None ⇒ byte-identical)."""
    d_omit = authorize_action(_authority(), _req(), now=_NOW, blast_radius_fn=_fn(50.0), blast_ceiling=10.0)
    d_none = authorize_action(_authority(), _req(), now=_NOW, blast_radius_fn=_fn(50.0), blast_ceiling=10.0,
                              blast_radius_ack=None)
    assert d_omit.allowed is False and d_omit.denial_code == "blast_radius"
    assert (d_none.allowed, d_none.denial_code, d_none.state) == (False, "blast_radius", AuthorityState.ACTIVE)


def test_blast_ack_returning_true_lifts_the_veto_for_this_action() -> None:
    seen = {}

    def ack(request, verdict) -> bool:
        seen["target"] = request.target
        seen["blast"] = verdict.incremental_blast
        return True

    d = authorize_action(_authority(), _req(), now=_NOW, blast_radius_fn=_fn(50.0, ["datastore:crown"]),
                         blast_ceiling=10.0, blast_radius_ack=ack)
    assert d.allowed is True and d.denial_code == ""
    assert seen == {"target": "https://app.example.com/x", "blast": 50.0}


def test_blast_ack_returning_false_still_denies() -> None:
    d = authorize_action(_authority(), _req(), now=_NOW, blast_radius_fn=_fn(50.0), blast_ceiling=10.0,
                         blast_radius_ack=lambda r, v: False)
    assert d.allowed is False and d.denial_code == "blast_radius"


def test_blast_ack_is_not_consulted_when_the_veto_does_not_fire() -> None:
    def ack(r, v):
        raise AssertionError("ack consulted though the veto never fired")

    d = authorize_action(_authority(), _req(), now=_NOW, blast_radius_fn=_fn(3.0), blast_ceiling=10.0,
                         blast_radius_ack=ack)
    assert d.allowed is True


def test_blast_ack_is_not_consulted_for_a_prior_denial() -> None:
    def ack(r, v):
        raise AssertionError("ack consulted for an action denied by a prior check")

    # out-of-scope wins; the blast veto (and its ack) are never reached
    d = authorize_action(_authority(), _req(target="https://evil.invalid/x"), now=_NOW,
                         blast_radius_fn=_fn(50.0), blast_ceiling=10.0, blast_radius_ack=ack)
    assert d.allowed is False and d.denial_code == "out_of_scope"


def test_require_authorization_forwards_the_blast_ack() -> None:
    d = require_authorization(_authority(), _req(), now=_NOW, blast_radius_fn=_fn(99.0), blast_ceiling=10.0,
                              blast_radius_ack=lambda r, v: True)
    assert d.allowed is True
