"""
Workstream A — the opt-in AUTONOMOUS OODA cycle wires the dormant planner/tool-driving loop into a
real engagement, ADDITIVELY and default-OFF.

These tests prove:
  * ``--autonomous`` OFF (the default) leaves the authoritative scan report byte-identical — the
    cycle is telemetry over the already-authoritative result and never mutates a finding.
  * ``--autonomous`` ON runs ONE bounded OODA cycle: the planner (world-aware) PICKS the next
    action, drives it as a GATED ``invoke_tool`` call, folds the observation back into the world-
    model, and re-orients.
  * every tool call is fail-closed gated — a tripped kill-switch REFUSES it (the tool never runs).
  * the cycle is deterministic (same result → same step sequence).
  * the WS-B ``fuse_sensors`` / WS-F ``reason_step`` hooks are optional (no-op when absent) and
    compose when present.

Loopback pytest-httpserver only; nothing leaves the test host.
"""

from __future__ import annotations

import sys
import types
from pathlib import Path

import pytest
from pytest_httpserver import HTTPServer
from werkzeug.wrappers import Response

from framework.v2 import engage as engage_mod
from framework.v2 import engage_autonomous as auto_mod
from framework.v2.authority.killswitch import KillSwitch
from framework.v2.common import paths as _paths
from framework.v2.engage import EngagementResult, run_engagement
from framework.v2.engage_autonomous import run_autonomous_cycle
from framework.v2.scanner.campaign import ScanReport
from framework.v2.scanner.engine import AuditFinding
from framework.v2.worldmodel import Edge, EdgeKind, Node, NodeKind, WorldModel

_CHARTER = """\
# Engagement charter — `{slug}`

**Status:** Final

## 1. Operator attestation

Signed: `tester`     Date: `2026-05-04`

## 2. In-scope systems

| Host / Surface | Notes | Auth |
|----------------|-------|------|
| `{host}` | Test app | Yes |

## 3. Out of scope

- Anything not listed above.

## 7. Posture

- [x] **TEST**
- [ ] **AUDIT**
- [ ] **EMULATE**
"""


@pytest.fixture()
def isolated_engagement(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    targets_root = tmp_path / "targets"
    targets_root.mkdir()

    def build(slug: str, host: str) -> Path:
        td = targets_root / slug
        td.mkdir(parents=True, exist_ok=True)
        (td / "charter.md").write_text(_CHARTER.format(slug=slug, host=host), encoding="utf-8")
        return td

    monkeypatch.setattr(_paths, "target_dir", lambda s: targets_root / s)
    monkeypatch.setattr(_paths, "charter_path", lambda s: targets_root / s / "charter.md")
    monkeypatch.setattr(_paths, "killswitch_path", lambda s: targets_root / s / ".halt")
    return build


def _root(request) -> Response:
    return Response('<a href="/search?q=hi">search</a>', status=200, mimetype="text/html")


def _search(request) -> Response:
    q = request.args.get("q", "")
    if "'1'='1" in q or "1=1" in q:
        body = "echo:" + q + "\n" + "".join(f"user{i}:secret{i}\n" for i in range(40))
    else:
        body = "echo:" + q
    return Response(body, status=200, mimetype="text/html")


def _deny(_q: str, _t: float) -> bool:
    return False


# ---------------------------------------------------------------------------
# synthetic world + result builders (no traffic — deterministic unit tests)
# ---------------------------------------------------------------------------

_ATTACKER = "attacker:self"


def _pathaware_world() -> WorldModel:
    """attacker:self --REACHABLE_FROM--> on-path endpoint --> datastore (crown jewel); an off-path
    endpoint no crown-jewel route touches. Mirrors planner.tests.test_worldmodel_scoring."""
    w = WorldModel()

    def node(nid: str, kind: NodeKind, **attrs: object) -> None:
        w.add_node(Node(id=nid, kind=kind, attrs=attrs,
                        provenance="obs-1", confidence=1.0, first_seen=0, last_seen=0))

    def edge(src: str, dst: str) -> None:
        w.add_edge(Edge(src=src, dst=dst, kind=EdgeKind.REACHABLE_FROM,
                        provenance="obs-1", confidence=0.9, first_seen=0, last_seen=0))

    node(_ATTACKER, NodeKind.PRINCIPAL, role="attacker")
    node("ep_on", NodeKind.ENDPOINT, url="https://t.invalid/on-path")
    node("db", NodeKind.DATASTORE, url="https://t.invalid/db")
    node("ep_off", NodeKind.ENDPOINT, url="https://t.invalid/off-path")
    edge(_ATTACKER, "ep_on")
    edge("ep_on", "db")
    return w


def _finding(bug_class: str, endpoint: str, conf: float) -> AuditFinding:
    return AuditFinding(
        check_id=bug_class, bug_class=bug_class, insertion_point=f"query:{bug_class}",
        param=bug_class, endpoint=endpoint, confidence=conf, confirmed_by="oracle",
        oracle_context={"bug_class": bug_class}, rationale="synthetic")


def _synthetic_result(world: WorldModel, findings: list[AuditFinding]) -> EngagementResult:
    return EngagementResult(report=ScanReport(target="https://t.invalid/", active_findings=findings),
                            world=world)


# ---------------------------------------------------------------------------
# (1) default OFF path is byte-identical — the cycle never mutates the report
# ---------------------------------------------------------------------------


def test_autonomous_off_leaves_the_scan_report_byte_identical(
    isolated_engagement, httpserver: HTTPServer,
):
    port = httpserver.port
    isolated_engagement("alpha", "127.0.0.1")
    httpserver.expect_request("/").respond_with_handler(_root)
    httpserver.expect_request("/search").respond_with_handler(_search)

    result = run_engagement("alpha", f"http://127.0.0.1:{port}/",
                            max_pages=5, enable_oob=False, prompt_callback=_deny)
    assert result.report.active_findings, "engage confirmed nothing against a vulnerable target"

    def sig(rep):
        return [(f.bug_class, f.confirmed_by, round(f.confidence, 6), bool(f.oracle_context),
                 f.insertion_point) for f in rep.active_findings]

    before = sig(result.report)
    # running the OODA cycle over the result must NOT change the authoritative report
    out = run_autonomous_cycle(result, slug="alpha", prompt_callback=_deny)
    after = sig(result.report)
    assert before == after, "the autonomous cycle mutated the authoritative scan report"
    assert out.engagement is result  # the report is carried through untouched


def test_cli_routes_to_autonomous_only_when_flag_set(monkeypatch: pytest.MonkeyPatch):
    """The CLI branch is a pure additive guard: ``_run_autonomous`` is invoked iff ``--autonomous``
    is passed. Stub the heavy engagement so this exercises only the dispatch (no traffic)."""
    canned = EngagementResult(report=ScanReport(target="http://x/"), world=WorldModel())
    monkeypatch.setattr(engage_mod, "run_engagement", lambda *a, **k: canned)
    calls: list = []
    monkeypatch.setattr(engage_mod, "_run_autonomous", lambda *a, **k: calls.append(a))

    assert engage_mod.main(["alpha", "http://x/"]) == 0
    assert calls == [], "the cycle ran without --autonomous (default path not byte-identical)"

    assert engage_mod.main(["alpha", "http://x/", "--autonomous"]) == 0
    assert len(calls) == 1, "--autonomous did not route to the autonomous cycle"


# ---------------------------------------------------------------------------
# (2) ON runs one bounded, gated OODA cycle against a live loopback fixture
# ---------------------------------------------------------------------------


def test_autonomous_runs_one_bounded_gated_cycle_live(
    isolated_engagement, httpserver: HTTPServer,
):
    port = httpserver.port
    isolated_engagement("alpha", "127.0.0.1")
    httpserver.expect_request("/").respond_with_handler(_root)
    httpserver.expect_request("/search").respond_with_handler(_search)

    result = run_engagement("alpha", f"http://127.0.0.1:{port}/",
                            max_pages=5, enable_oob=False, prompt_callback=_deny)
    assert result.report.active_findings

    out = run_autonomous_cycle(result, slug="alpha", max_cycles=1, prompt_callback=_deny)
    assert len(out.cycles) <= 1, "the cycle is not bounded to max_cycles"
    assert out.cycles, "no OODA cycle ran against a target with confirmed findings"
    step = out.cycles[0]
    # ACT: the picked action was driven as a GATED tool call and was NOT refused (safe T1 tool).
    assert step.gated is True
    assert step.tool == "reverify_finding"
    assert step.refused is False and step.gate == ""
    # ORIENT: the pick corresponds to a real confirmed finding.
    assert step.picked_bug_class in {f.bug_class for f in result.report.active_findings}
    # RE-ORIENT: the planner re-selected after the update (a label, or the terminal marker).
    assert step.reoriented_to


# ---------------------------------------------------------------------------
# (3) the planner (world-aware) picks the crown-jewel-route action; the loop closes
# ---------------------------------------------------------------------------


def test_autonomous_planner_prefers_crownjewel_route_and_folds_observation():
    world = _pathaware_world()
    # off-path finding has the HIGHER greedy base (0.5) — the world-aware planner must still pick
    # the on-path finding (0.3) because it lies on the route to the DATASTORE crown jewel.
    on = _finding("idor", "https://t.invalid/on-path", 0.3)
    off = _finding("xss", "https://t.invalid/off-path", 0.5)
    result = _synthetic_result(world, [off, on])   # order-independent selection

    out = run_autonomous_cycle(result, slug="alpha", prompt_callback=_deny)
    assert out.planner_source == _ATTACKER
    assert out.objectives == ["datastore", "cloud_resource"]
    assert out.cycles, "no cycle ran"
    step = out.cycles[0]
    assert step.picked_bug_class == "idor", "planner did not prefer the crown-jewel-route action"
    assert step.gated is True and step.refused is False
    # UPDATE: the observation was folded onto the on-path endpoint node in the world-model.
    assert step.folded_node == "ep_on"
    assert world.get_node("ep_on").attrs.get("autonomy_reverify"), "observation not folded into world"
    # RE-ORIENT: with the on-path leaf resolved, the planner re-orients to the off-path action.
    assert "xss" in step.reoriented_to or "off-path" in step.reoriented_to


def test_autonomous_cycle_is_deterministic():
    def run():
        world = _pathaware_world()
        result = _synthetic_result(
            world, [_finding("xss", "https://t.invalid/off-path", 0.5),
                    _finding("idor", "https://t.invalid/on-path", 0.3)])
        out = run_autonomous_cycle(result, slug="alpha", prompt_callback=_deny)
        return [(s.picked_bug_class, s.reoriented_to) for s in out.cycles]

    assert run() == run(), "the autonomous cycle is not deterministic"


# ---------------------------------------------------------------------------
# (4) fail-closed gating — a tripped kill-switch REFUSES the tool call
# ---------------------------------------------------------------------------


def test_autonomous_tool_call_is_refused_by_tripped_killswitch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
):
    monkeypatch.setattr(_paths, "killswitch_path", lambda s: tmp_path / f"{s}.halt")
    KillSwitch("alpha").trip("operator stop")

    world = _pathaware_world()
    result = _synthetic_result(world, [_finding("idor", "https://t.invalid/on-path", 0.9)])
    out = run_autonomous_cycle(result, slug="alpha", prompt_callback=_deny)

    assert out.cycles
    step = out.cycles[0]
    assert step.gated is True
    assert step.refused is True, "a tripped kill-switch did not refuse the tool call"
    assert step.gate == "kill-switch"
    # a fail-closed refusal is NOT a refutation: the world node is not annotated with a verdict.
    assert world.get_node("ep_on").attrs.get("autonomy_reverify") is None
    assert any("fail-closed" in n for n in out.notes)


# ---------------------------------------------------------------------------
# (5) the WS-B / WS-F hooks are optional (no-op absent) and compose when present
# ---------------------------------------------------------------------------


def test_hooks_are_noop_when_absent(monkeypatch: pytest.MonkeyPatch):
    # Simulate the WS-B/WS-F hook modules being ABSENT. They are now part of the tree, so a plain
    # sys.modules check no longer reproduces "absent"; setting the entry to None makes the loader's
    # ``from .engage_fusion import ...`` raise ImportError → the best-effort fallback path (clean skip).
    monkeypatch.setitem(sys.modules, "framework.v2.engage_fusion", None)
    monkeypatch.setitem(sys.modules, "framework.v2.engage_reasoning", None)
    world = _pathaware_world()
    result = _synthetic_result(world, [_finding("idor", "https://t.invalid/on-path", 0.9)])
    out = run_autonomous_cycle(result, slug="alpha", prompt_callback=_deny)
    assert out.fused_observations == 0
    assert out.reasoning_advice is None


def test_hooks_compose_when_present(monkeypatch: pytest.MonkeyPatch):
    fusion = types.ModuleType("framework.v2.engage_fusion")
    fusion.fuse_sensors = lambda world, slug, ctx: ["obs-a", "obs-b"]  # type: ignore[attr-defined]
    reasoning = types.ModuleType("framework.v2.engage_reasoning")
    reasoning.reason_step = lambda world, findings, ctx: {"advice": "look-here"}  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "framework.v2.engage_fusion", fusion)
    monkeypatch.setitem(sys.modules, "framework.v2.engage_reasoning", reasoning)

    world = _pathaware_world()
    result = _synthetic_result(world, [_finding("idor", "https://t.invalid/on-path", 0.9)])
    out = run_autonomous_cycle(result, slug="alpha", prompt_callback=_deny)
    assert out.fused_observations == 2, "WS-B fuse_sensors hook was not called"
    assert out.reasoning_advice == {"advice": "look-here"}, "WS-F reason_step hook was not called"


def test_hook_signatures_match_the_published_contract():
    # guard the exact signatures WS-B / WS-F build against so a drift here is caught in review.
    import inspect

    src = Path(auto_mod.__file__).read_text(encoding="utf-8")
    assert "from .engage_fusion import fuse_sensors" in src
    assert "from .engage_reasoning import reason_step" in src
    assert list(inspect.signature(auto_mod._fuse_sensors).parameters) == ["world", "slug", "ctx"]
    assert list(inspect.signature(auto_mod._reason_step).parameters) == ["world", "findings", "ctx"]


# ---------------------------------------------------------------------------
# (6) the real Planner is constructed over the run world-model when a spine is present
# ---------------------------------------------------------------------------


def test_planner_is_constructed_over_world_when_blackboard_present(tmp_path: Path):
    from framework.v2.agents.blackboard import open_blackboard

    bb = open_blackboard(db_path=tmp_path / "bb.sqlite")
    try:
        world = _pathaware_world()
        result = _synthetic_result(world, [_finding("idor", "https://t.invalid/on-path", 0.9)])
        out = run_autonomous_cycle(result, slug="alpha", blackboard=bb, prompt_callback=_deny)
        assert out.planner_constructed is True, "the Planner was not constructed over the world-model"
        assert out.planner_source == _ATTACKER
        assert out.cycles and out.cycles[0].gated is True
    finally:
        bb.close()


# ---------------------------------------------------------------------------
# (7) I-D.1 — reason_step advice is FED BACK INTO selection: it re-weights the
#     open frontier so the reasoning actually CHANGES the next selected action.
# ---------------------------------------------------------------------------


def _greedy_world(surfaces: list[str]) -> WorldModel:
    """Endpoints only, NO crown jewel reachable → selection degrades to plain greedy
    (prior*value/cost). The reasoning-advice re-weight is then the only thing that can reorder."""
    w = WorldModel()
    for i, sf in enumerate(surfaces):
        w.add_node(Node(id=f"ep{i}", kind=NodeKind.ENDPOINT, attrs={"url": sf},
                        provenance="obs-1", confidence=1.0, first_seen=0, last_seen=0))
    return w


def test_reasoning_advice_reorders_the_next_selected_action(monkeypatch: pytest.MonkeyPatch):
    """The reasoning advice PROVABLY changes the next selected action. Greedy selection picks the
    higher-prior finding; concrete advice focusing the lower-prior one re-weights it to the top of
    the open frontier, so the planner picks IT instead — advisory, the oracle stays authoritative."""
    from framework.v2 import engage_reasoning as reasoning_mod
    from framework.v2.engage_reasoning import ReasoningAdvice

    on = "https://t.invalid/on-path"
    off = "https://t.invalid/off-path"

    def build_result() -> EngagementResult:
        world = _greedy_world([off, on])
        # greedy prefers xss (prior 0.6) over idor (prior 0.3)
        return _synthetic_result(world, [_finding("xss", off, 0.6), _finding("idor", on, 0.3)])

    # CONTROL: default DryRun advice carries an "(unspecified surface)" focus → no concrete match →
    # nothing is re-weighted, so greedy selection stands and picks xss.
    control = run_autonomous_cycle(build_result(), slug="alpha", prompt_callback=_deny)
    assert control.cycles and control.cycles[0].picked_bug_class == "xss"
    assert control.advice_reweighted == 0, "DryRun (unspecified-surface) advice must not re-weight"

    # TREATMENT: advice focuses the LOWER-prior idor@on-path with a CONCRETE surface → it is
    # re-weighted above xss and is now selected first. This is the loop closing.
    advice = ReasoningAdvice(
        next_focus="test idor on /on-path", abstain=False, is_dryrun=False,
        focus={"id": "H-1", "surface": on, "bug_class": "idor", "cheap_test": "swap id",
               "confidence": 0.3, "oracle_provable": True})
    monkeypatch.setattr(reasoning_mod, "reason_step", lambda world, findings, ctx: advice)
    treated = run_autonomous_cycle(build_result(), slug="alpha", prompt_callback=_deny)
    assert treated.cycles and treated.cycles[0].picked_bug_class == "idor", \
        "reasoning advice did not change the selected action"
    assert treated.advice_reweighted >= 1
    # ADVISORY-ONLY: the authoritative report is untouched — no finding promoted, no verdict changed.
    assert {f.bug_class for f in treated.engagement.report.active_findings} == {"xss", "idor"}


def test_reasoning_advice_reweight_is_bounded_and_deterministic(monkeypatch: pytest.MonkeyPatch):
    """The advice re-weight is recomputed from a fixed baseline each cycle (idempotent, bounded by
    the cap) so two identical runs are byte-identical, and the prior never reaches certainty."""
    from framework.v2 import engage_reasoning as reasoning_mod
    from framework.v2.engage_reasoning import ReasoningAdvice

    on = "https://t.invalid/on-path"
    advice = ReasoningAdvice(next_focus="x", abstain=False, is_dryrun=False,
                             focus={"surface": on, "bug_class": "idor", "confidence": 0.3,
                                    "cheap_test": "", "oracle_provable": True})
    monkeypatch.setattr(reasoning_mod, "reason_step", lambda w, f, c: advice)

    def run():
        world = _greedy_world([on, "https://t.invalid/off-path"])
        result = _synthetic_result(world, [_finding("xss", "https://t.invalid/off-path", 0.6),
                                           _finding("idor", on, 0.3)])
        out = run_autonomous_cycle(result, slug="alpha", max_cycles=3, prompt_callback=_deny)
        return [(s.picked_bug_class, s.reoriented_to, s.advice_reweighted) for s in out.cycles]

    assert run() == run(), "advice re-weighting made the cycle non-deterministic"


# ---------------------------------------------------------------------------
# (8) I-D.2 — fuse_sensors (OBSERVE) runs EVERY cycle and enriches the shared world.
# ---------------------------------------------------------------------------


def test_fuse_sensors_runs_every_cycle(monkeypatch: pytest.MonkeyPatch):
    """The WS-B ``fuse_sensors`` hook is invoked once per OODA cycle (not once per run), so fresh
    observations enrich the SAME world-model the planner reasons over before each selection."""
    fusion = types.ModuleType("framework.v2.engage_fusion")
    calls = {"n": 0, "worlds": []}

    def _fuse(world, slug, ctx):
        calls["n"] += 1
        calls["worlds"].append(world)
        return ["obs-a", "obs-b"]

    fusion.fuse_sensors = _fuse  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "framework.v2.engage_fusion", fusion)

    world = _greedy_world(["https://t.invalid/a", "https://t.invalid/b"])
    result = _synthetic_result(world, [_finding("xss", "https://t.invalid/a", 0.6),
                                       _finding("sqli", "https://t.invalid/b", 0.5)])
    out = run_autonomous_cycle(result, slug="alpha", max_cycles=2, prompt_callback=_deny)

    assert len(out.cycles) == 2, "expected two driven cycles"
    assert calls["n"] == 2, "fuse_sensors did not run once per cycle"
    assert all(w is world for w in calls["worlds"]), "fusion enriched a different world than the planner's"
    assert all(s.fused_observations == 2 for s in out.cycles)
    assert out.fused_observations == 4
