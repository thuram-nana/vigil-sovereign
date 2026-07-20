"""
Tests for scanner.detection_cost — stealth ranking via detection ACCOUNTING.

Exercises real logic against the real technique catalog and the real DEL
telemetry model: no stubs. Deterministic (no randomness, no wallclock).
"""

from __future__ import annotations

from collections.abc import Generator

import pytest

from ...defender.models import ActionKind
from ...entitlement import policy as ent_policy
from ...knowledge.models import (
    Effect,
    EffectKind,
    Operator,
    Predicate,
    PredicateKind,
)
from ...worldmodel.models import Edge, EdgeKind, NodeKind
from ..detection_cost import (
    detection_cost_of_technique,
    path_detection_cost,
    rank_paths,
    weight_fn,
)


@pytest.fixture(autouse=True)
def _isolated_entitlement(
    tmp_path: object, monkeypatch: pytest.MonkeyPatch
) -> Generator[None, None, None]:
    """Isolate entitlement state so nothing leaks between tests; detection
    accounting itself bypasses the gate (check_capability=False), but keep
    the environment clean and deterministic."""
    monkeypatch.setenv("CRUCIBLE_ENTITLEMENT_DIR", str(tmp_path) + "/ent")
    monkeypatch.delenv("CRUCIBLE_ENTITLEMENT_ENFORCED", raising=False)
    monkeypatch.delenv("CRUCIBLE_ATTESTED_IDENTITY", raising=False)
    ent_policy.reset_policy()
    yield
    ent_policy.reset_policy()


# ---------------------------------------------------------------------------
# helpers — synthetic operators with controllable loudness
# ---------------------------------------------------------------------------


def _make_operator(op_id: str, *, refs: list[str], signals: list[str], tactic: str | None) -> Operator:
    """A minimal but valid planning operator with a tunable detection_signals
    list and intel refs, for isolating the two cost drivers."""
    return Operator(
        id=op_id,
        name=op_id,
        technique_ref=refs,
        tactic=tactic,
        preconditions=[Predicate(kind=PredicateKind.NODE_KIND, node_kind=NodeKind.ENDPOINT)],
        effects=[Effect(kind=EffectKind.SET_ATTR, attr="probe", value=True)],
        detection_signals=list(signals),
    )


def _edge(attrs: dict[str, object], provenance: str = "operator:x") -> Edge:
    return Edge(
        src="attacker",
        dst="host:1",
        kind=EdgeKind.SESSION_ON,
        attrs=attrs,
        provenance=provenance,
        first_seen=1,
        last_seen=1,
    )


# ---------------------------------------------------------------------------
# per-technique cost, from the real catalog
# ---------------------------------------------------------------------------


def test_cost_is_a_probability() -> None:
    for tech in ("unauth-endpoint-read", "deserialization-to-code-exec", "ssrf-internal-reach"):
        c = detection_cost_of_technique(tech)
        assert 0.0 <= c <= 1.0


def test_loud_code_exec_is_louder_than_quiet_info_read() -> None:
    quiet = detection_cost_of_technique("unauth-endpoint-read")  # IDOR object read
    loud = detection_cost_of_technique("deserialization-to-code-exec")  # RCE, WAF-visible
    assert loud > quiet


def test_injection_classified_technique_trips_high_severity_telemetry() -> None:
    # Deserialization maps to a WAF-visible injection probe: its telemetry
    # component alone must be substantial (the DEL scores that high).
    from ..detection_cost import _classify, _telemetry_cost  # noqa: PLC0415

    op = _make_operator("d", refs=["CWE-502"], signals=[], tactic="execution")
    assert _classify(op).kind is ActionKind.INJECTION_PROBE
    assert _telemetry_cost(op) > 0.5


def test_plain_read_classified_as_quiet_http() -> None:
    from ..detection_cost import _classify, _telemetry_cost  # noqa: PLC0415

    op = _make_operator("r", refs=["CWE-639"], signals=[], tactic="initial-access")
    assert _classify(op).kind is ActionKind.HTTP_REQUEST
    assert _telemetry_cost(op) < 0.1


def test_unknown_technique_is_neutral_not_silent() -> None:
    assert detection_cost_of_technique("no-such-technique") == 0.5
    assert detection_cost_of_technique(None) == 0.5


# ---------------------------------------------------------------------------
# monotonicity in the loud signals
# ---------------------------------------------------------------------------


def test_cost_monotonic_in_signal_count_same_class() -> None:
    # Same (loud) classification, only the number of detection tells varies.
    costs = [
        detection_cost_of_technique(
            _make_operator(f"op{n}", refs=["CWE-502"], signals=[f"s{i}" for i in range(n)], tactic="execution")
        )
        for n in range(5)
    ]
    assert costs == sorted(costs)
    assert costs[0] < costs[-1]  # strictly increasing overall
    # strictly increasing at every step (noisy-OR with a fixed telemetry term)
    assert all(b > a for a, b in zip(costs, costs[1:]))


def test_more_signals_never_lowers_cost_quiet_class() -> None:
    few = detection_cost_of_technique(
        _make_operator("q1", refs=["CWE-639"], signals=["a"], tactic="initial-access")
    )
    many = detection_cost_of_technique(
        _make_operator("q2", refs=["CWE-639"], signals=["a", "b", "c", "d"], tactic="initial-access")
    )
    assert many > few


# ---------------------------------------------------------------------------
# path ranking (list[str] and AttackPath-like duck typing)
# ---------------------------------------------------------------------------


def test_rank_paths_orders_quiet_before_loud_list_form() -> None:
    quiet_path = ["unauth-endpoint-read"]
    loud_path = ["deserialization-to-code-exec"]
    ranked = rank_paths([loud_path, quiet_path])
    assert [p for p, _ in ranked] == [quiet_path, loud_path]
    assert ranked[0][1] < ranked[1][1]


def test_rank_paths_duck_types_attackpath_steps() -> None:
    from dataclasses import dataclass

    @dataclass
    class _Step:
        technique: str

    @dataclass
    class _Path:
        steps: list[_Step]

    quiet = _Path([_Step("unauth-endpoint-read")])
    loud = _Path([_Step("token-replay"), _Step("deserialization-to-code-exec")])
    ranked = rank_paths([loud, quiet])
    assert ranked[0][0] is quiet
    assert ranked[1][0] is loud
    assert ranked[0][1] < ranked[1][1]


def test_rank_paths_works_with_real_orchestrator_attackpath() -> None:
    from ..orchestrator import AttackPath, ChainedConclusion  # noqa: PLC0415

    quiet = AttackPath(steps=[
        ChainedConclusion(src="a", edge="reached", dst="ep", technique="unauth-endpoint-read"),
    ])
    loud = AttackPath(steps=[
        ChainedConclusion(src="a", edge="session_on", dst="host", technique="deserialization-to-code-exec"),
    ])
    ranked = rank_paths([loud, quiet])
    assert ranked[0][0] is quiet
    assert ranked[1][0] is loud


def test_path_cost_monotonic_adding_a_loud_step() -> None:
    base = ["unauth-endpoint-read"]
    extended = ["unauth-endpoint-read", "deserialization-to-code-exec"]
    assert path_detection_cost(extended) > path_detection_cost(base)


def test_empty_path_costs_zero() -> None:
    assert path_detection_cost([]) == 0.0


def test_rank_paths_is_stable_on_ties() -> None:
    a = ["unauth-endpoint-read"]
    b = ["unauth-endpoint-read"]
    ranked = rank_paths([a, b])
    # equal cost -> input order preserved (stable, deterministic)
    assert ranked[0][0] is a
    assert ranked[1][0] is b


# ---------------------------------------------------------------------------
# weight_fn for pathsearch
# ---------------------------------------------------------------------------


def test_weight_fn_louder_edge_weighs_more_via_technique_attr() -> None:
    loud = _edge({"technique": "deserialization-to-code-exec"})
    quiet = _edge({"technique": "unauth-endpoint-read"})
    assert weight_fn(loud) > weight_fn(quiet)


def test_weight_fn_is_non_negative_and_has_floor() -> None:
    bare = _edge({}, provenance="finding:idor")
    w = weight_fn(bare)
    assert w >= 0.0
    assert w >= 0.05  # the hop floor applies even with no technique intel


def test_weight_fn_reads_detection_signals_list_when_no_technique() -> None:
    few = _edge({"detection_signals": ["a"]}, provenance="finding:x")
    many = _edge({"detection_signals": ["a", "b", "c", "d"]}, provenance="finding:x")
    assert weight_fn(many) > weight_fn(few)


def test_weight_fn_falls_back_to_operator_provenance() -> None:
    loud = _edge({}, provenance="operator:deserialization-to-code-exec")
    quiet = _edge({}, provenance="operator:unauth-endpoint-read")
    assert weight_fn(loud) > weight_fn(quiet)


def test_weight_fn_drives_best_paths_toward_stealthy_route() -> None:
    # Two attacker routes to distinct crown jewels: one loud, one quiet.
    # best_paths ranked by weight_fn must surface the quiet route first.
    from ...worldmodel.graph import WorldModel  # noqa: PLC0415
    from ...worldmodel.models import Node  # noqa: PLC0415
    from ...worldmodel.pathsearch import best_paths  # noqa: PLC0415

    world = WorldModel()

    def _node(nid: str, kind: NodeKind) -> None:
        world.add_node(Node(id=nid, kind=kind, provenance="test", first_seen=1, last_seen=1))

    _node("attacker", NodeKind.PRINCIPAL)
    _node("store", NodeKind.DATASTORE)      # quiet objective
    _node("host", NodeKind.HOST)            # loud objective

    world.add_edge(Edge(
        src="attacker", dst="store", kind=EdgeKind.REACHABLE_FROM,
        attrs={"technique": "unauth-endpoint-read"},
        provenance="operator:unauth-endpoint-read", confidence=0.8,
        first_seen=1, last_seen=1,
    ))
    world.add_edge(Edge(
        src="attacker", dst="host", kind=EdgeKind.SESSION_ON,
        attrs={"technique": "deserialization-to-code-exec"},
        provenance="operator:deserialization-to-code-exec", confidence=0.8,
        first_seen=1, last_seen=1,
    ))

    ranked = best_paths(
        world, "attacker", (NodeKind.DATASTORE, NodeKind.HOST),
        weight_fn=weight_fn, k=2,
        edge_kinds=(EdgeKind.REACHABLE_FROM, EdgeKind.SESSION_ON),
    )
    assert [p.edges[-1].dst for p in ranked] == ["store", "host"]
