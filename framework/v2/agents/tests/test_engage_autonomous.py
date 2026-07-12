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


# ---------------------------------------------------------------------------
# (9) I-D.3 — the constructed Planner is now DRIVEN: its Coordinator ticks the
#     real advisory agents (multi-critic panel + reflection) INSIDE each cycle.
# ---------------------------------------------------------------------------


def test_planner_is_driven_advisory_agents_run_in_loop(tmp_path: Path):
    """The Coordinator is no longer constructed-inert (``agents=[]``): it carries the real
    multi-critic + reflection agents and is TICKED each cycle, so the nervous system runs IN-LOOP.
    Everything stays advisory — a critic never confirms, reflection only re-ranks; the authoritative
    report is untouched and only a fired oracle can promote a finding."""
    from framework.v2.agents.blackboard import open_blackboard

    bb = open_blackboard(db_path=tmp_path / "bb.sqlite")
    try:
        world = _pathaware_world()
        result = _synthetic_result(world, [
            _finding("idor", "https://t.invalid/on-path", 0.9),
            _finding("xss", "https://t.invalid/off-path", 0.5)])
        before = [(f.bug_class, f.confidence, f.confirmed_by) for f in result.report.active_findings]

        out = run_autonomous_cycle(result, slug="alpha", max_cycles=2, blackboard=bb, prompt_callback=_deny)

        # the Planner is DRIVEN (its Coordinator ticked the wired agents), not constructed-inert.
        assert out.planner_constructed is True
        assert out.planner_driven is True, "the Coordinator was constructed but never ticked in-loop"
        assert "multi-critic" in out.agents_wired and "reflection" in out.agents_wired
        assert out.coordinator_events > 0
        # BOTH advisory agents actually ran and posted their events this run.
        assert out.critic_verdicts > 0, "the multi-critic panel did not run in-loop"
        assert out.reflections > 0, "the reflection agent did not run in-loop"

        # ADVISORY-ONLY: the authoritative report is untouched by anything the agents did.
        after = [(f.bug_class, f.confidence, f.confirmed_by) for f in result.report.active_findings]
        assert before == after, "an in-loop agent mutated the authoritative report"

        # a critic verdict can NEVER be 'confirm' — only a fired deterministic oracle confirms.
        verdicts = bb.read(engagement="alpha", kinds=["critic_verdict"])
        assert verdicts and all(
            v.payload["verdict"] in ("endorse", "object", "abstain") for v in verdicts)
        # the mirrored findings are never PROMOTED by a critic (critique_status stays 'pending').
        fevents = bb.read(engagement="alpha", kinds=["finding"])
        assert fevents and all(f.payload["critique_status"] == "pending" for f in fevents)
    finally:
        bb.close()


def test_planner_constructed_inert_without_blackboard():
    """Without a blackboard there is no event substrate, so the Planner is not constructed and the
    cycle runs on the shared tree selection (byte-for-byte what the planner would select) — the
    nervous-system driving is cleanly skipped, never errored."""
    world = _pathaware_world()
    result = _synthetic_result(world, [_finding("idor", "https://t.invalid/on-path", 0.9)])
    out = run_autonomous_cycle(result, slug="alpha", prompt_callback=_deny)
    assert out.planner_constructed is False
    assert out.planner_driven is False
    assert out.agents_wired == [] and out.coordinator_events == 0
    assert out.cycles and out.cycles[0].gated is True   # the cycle still ran + gated the tool call


# ---------------------------------------------------------------------------
# (10) I-D.4 — the learner-health meta-monitor ORDERS effort (caution-only), never gates.
# ---------------------------------------------------------------------------


def _miscalibrated_ledger(n: int = 10):
    """A ledger of high-scored findings that all turned out false — materially miscalibrated, so
    assess_learner_health recommends 'trust_confidence_less' (be more cautious)."""
    from framework.v2.calibration.ledger import OutcomeLedger
    from framework.v2.calibration.models import Outcome, OutcomeLabel, Prediction

    led = OutcomeLedger()
    for i in range(n):
        fid = f"f{i}"
        led.add_prediction(Prediction(finding_id=fid, raw_score=0.9, feature_hash="h",
                                      model_version="v1", oracle_confirmed=True), seq=i)
        led.record_outcome(Outcome(finding_id=fid, label=OutcomeLabel.FALSE_POSITIVE), seq=1000 + i)
    return led


def test_meta_monitor_caution_orders_effort_never_gates():
    """When the learners are unhealthy the meta-monitor deprioritises the MOST borderline leaf so
    effort leads with a more-decisive lead — but EVERY surface stays covered across the run
    (order effort, never gate a surface). Only a fired oracle can promote; meta never does."""
    urls = ["https://t.invalid/a", "https://t.invalid/b", "https://t.invalid/c"]

    def build_result() -> EngagementResult:
        world = _greedy_world(urls)
        return _synthetic_result(world, [
            _finding("aaa", urls[0], 0.50),   # most borderline (nearest coin-flip)
            _finding("bbb", urls[1], 0.45),
            _finding("ccc", urls[2], 0.40)])  # most decisive

    # CONTROL: no ledger → no caution → greedy leads with the highest prior (the coin-flip aaa).
    control = run_autonomous_cycle(build_result(), slug="alpha", max_cycles=3, prompt_callback=_deny)
    assert control.meta_recommend == ""
    assert control.cycles[0].picked_bug_class == "aaa"
    assert {s.picked_bug_class for s in control.cycles} == {"aaa", "bbb", "ccc"}

    # TREATMENT: a miscalibrated ledger → 'trust_confidence_less' → caution deprioritises the most
    # borderline leaf, so effort now LEADS with the more-decisive ccc.
    treated = run_autonomous_cycle(build_result(), slug="alpha", max_cycles=3,
                                   outcome_ledger=_miscalibrated_ledger(), prompt_callback=_deny)
    assert treated.meta_recommend == "trust_confidence_less"
    assert treated.cycles[0].picked_bug_class == "ccc", "meta caution did not re-order effort"
    # NEVER GATES: all three surfaces are still covered across the run (coverage doctrine).
    assert {s.picked_bug_class for s in treated.cycles} == {"aaa", "bbb", "ccc"}, \
        "meta caution gated a surface"
    # ADVISORY-ONLY: the authoritative findings are untouched.
    assert {f.bug_class for f in treated.engagement.report.active_findings} == {"aaa", "bbb", "ccc"}


# ---------------------------------------------------------------------------
# (11) I-D.5 — SMT feasibility deprioritises a PROVABLY-infeasible region; never gates;
#      degrades to a no-op when the domain is too large and z3 is absent.
# ---------------------------------------------------------------------------


def test_smt_infeasible_region_is_deprioritised_never_gated():
    """A leaf whose bounded parameter region is provably infeasible is deprioritised below a
    feasible sibling before selection — but it stays selectable (covered later); the SMT layer only
    ORDERS effort, it never gates a surface and never refutes/promotes a finding (only an oracle does)."""
    urls = ["https://t.invalid/feas", "https://t.invalid/infeas"]

    def build_result() -> EngagementResult:
        world = _greedy_world(urls)
        return _synthetic_result(world, [_finding("feasible", urls[0], 0.4),
                                         _finding("infeasible", urls[1], 0.6)])

    # x in [0,10] AND x >= 20 has NO assignment — decided exactly by the dep-free bounded enumerator
    # (no z3 needed for this small domain).
    regions = {"infeasible": {"variables": {"x": (0, 10)},
                              "constraints": [{"coeffs": {"x": 1}, "op": ">=", "rhs": 20}]}}

    # CONTROL: no regions → greedy leads with the higher prior (the infeasible leaf, 0.6).
    control = run_autonomous_cycle(build_result(), slug="alpha", max_cycles=2, prompt_callback=_deny)
    assert control.smt_deprioritised == 0
    assert control.cycles[0].picked_bug_class == "infeasible"

    # TREATMENT: the provably-dead region deprioritises that leaf; effort now leads with feasible.
    treated = run_autonomous_cycle(build_result(), slug="alpha", max_cycles=2,
                                   smt_regions=regions, prompt_callback=_deny)
    assert treated.smt_deprioritised == 1
    assert treated.cycles[0].picked_bug_class == "feasible", "smt did not deprioritise the infeasible region"
    # NEVER GATES: the infeasible surface is still covered across the run (just later).
    assert {s.picked_bug_class for s in treated.cycles} == {"feasible", "infeasible"}


def test_smt_unknown_region_is_a_noop_without_z3():
    """A domain too large to enumerate with z3 absent is UNKNOWN — an honest no-op: the leaf is NOT
    deprioritised (never a guess), so greedy order is unchanged."""
    from framework.v2.analysis.smt import has_z3

    urls = ["https://t.invalid/big", "https://t.invalid/small"]
    world = _greedy_world(urls)
    result = _synthetic_result(world, [_finding("big", urls[0], 0.6), _finding("small", urls[1], 0.4)])
    # 2_000_001 assignments > DEFAULT_MAX_ENUM (1e6): enum refuses, and with no z3 the verdict is UNKNOWN.
    regions = {"big": {"variables": {"x": (0, 2_000_000)},
                       "constraints": [{"coeffs": {"x": 1}, "op": ">=", "rhs": 3_000_000}]}}
    out = run_autonomous_cycle(result, slug="alpha", max_cycles=2, smt_regions=regions, prompt_callback=_deny)

    if not has_z3():
        assert out.smt_deprioritised == 0, "an UNKNOWN region must not deprioritise (honest no-op)"
        assert out.cycles[0].picked_bug_class == "big"   # greedy order unchanged


# ---------------------------------------------------------------------------
# (12) I-C x I-D RECONCILIATION — the WS-B fused SENSOR observations reach the
#      unified report as LEADS on the spine, deduped by obs_id across cycles.
#
#      Regression guard: I-D refactored fusion into a per-cycle inline call and
#      dropped the pre-loop `fused` list that I-C's producer-unification block
#      referenced. The text-merge was clean but left a latent NameError on the
#      exact --autonomous + spine path (sink present AND a non-empty fused list).
#      This test drives precisely that path.
# ---------------------------------------------------------------------------


def test_fused_sensor_observations_reach_the_spine_as_leads_deduped(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
):
    from framework.v2.agents.blackboard import open_blackboard
    from framework.v2.intel.models import IntelSourceKind, Observation, SourceReliability
    from framework.v2.intel.refs import EntityRef

    def _obs(oid: str) -> Observation:
        return Observation(
            obs_id=oid, source="scoutsuite", source_kind=IntelSourceKind.CLOUD_POSTURE,
            collector="cloud", subject=EntityRef(kind=NodeKind.HOST, key="10.0.0.5"),
            attrs={"bug_class": "iam_overbroad_trust", "severity": "High"},
            confidence=0.5, seq=1, evidence="role trusts *", source_reliability=SourceReliability())

    # fuse_sensors returns the SAME two observations EVERY cycle (idempotent by obs_id) — so a
    # naive per-cycle emit would post 4 finding events over 2 cycles; the dedup must collapse to 2.
    fusion = types.ModuleType("framework.v2.engage_fusion")
    fusion.fuse_sensors = lambda world, slug, ctx: [  # type: ignore[attr-defined]
        _obs("cloud:iam:role-x"), _obs("cloud:iam:role-y")]
    monkeypatch.setitem(sys.modules, "framework.v2.engage_fusion", fusion)

    bb = open_blackboard(db_path=tmp_path / "bb.sqlite")
    try:
        world = _greedy_world(["https://t.invalid/a", "https://t.invalid/b"])
        result = _synthetic_result(world, [_finding("xss", "https://t.invalid/a", 0.6),
                                           _finding("sqli", "https://t.invalid/b", 0.5)])
        # sink is not None (blackboard) AND the fused list is non-empty → the exact path that
        # regressed. Must NOT raise (the NameError guard) ...
        out = run_autonomous_cycle(result, slug="alpha", max_cycles=2, blackboard=bb,
                                   prompt_callback=_deny)
        assert len(out.cycles) == 2 and out.fused_observations == 4  # 2 obs x 2 cycles counted

        # ... and each fused observation reaches the spine as EXACTLY ONE lead finding event
        # (deduped by obs_id across cycles: 2 distinct leads, not 4).
        leads = [r for r in bb.read(engagement="alpha", kinds=["finding"])
                 if str(r.payload.get("finding_slug", "")).startswith("lead:")]
        slugs = {r.payload["finding_slug"] for r in leads}
        assert slugs == {"lead:cloud:iam:role-x", "lead:cloud:iam:role-y"}, \
            "fused sensor observations did not reach the spine as deduped leads"
        assert len(leads) == 2, "a fused observation was emitted more than once (dedup broke)"
        # PROVE-DON'T-GUESS: every fused lead is graded a LEAD, never a fact.
        assert all(r.payload.get("verified_by_oracle") is False for r in leads)
        assert all(r.payload.get("oracle_context") is None for r in leads)
    finally:
        bb.close()


def test_fused_leads_on_the_no_findings_early_return_reach_the_spine(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
):
    """The no-confirmed-findings early return also fuses sensors — its fused leads must reach the
    spine too (the second call site of the reconciled _emit_fused_leads)."""
    from framework.v2.agents.blackboard import open_blackboard
    from framework.v2.intel.models import IntelSourceKind, Observation, SourceReliability
    from framework.v2.intel.refs import EntityRef

    fusion = types.ModuleType("framework.v2.engage_fusion")
    fusion.fuse_sensors = lambda world, slug, ctx: [Observation(  # type: ignore[attr-defined]
        obs_id="dns:acme", source="doh", source_kind=IntelSourceKind.DNS, collector="dns",
        subject=EntityRef(kind=NodeKind.DOMAIN, key="acme.test"), seq=1,
        source_reliability=SourceReliability())]
    monkeypatch.setitem(sys.modules, "framework.v2.engage_fusion", fusion)

    bb = open_blackboard(db_path=tmp_path / "bb.sqlite")
    try:
        world = _greedy_world(["https://t.invalid/a"])
        result = _synthetic_result(world, [])   # NO confirmed findings → early return path
        out = run_autonomous_cycle(result, slug="alpha", blackboard=bb, prompt_callback=_deny)
        assert out.fused_observations == 1
        leads = [r for r in bb.read(engagement="alpha", kinds=["finding"])
                 if str(r.payload.get("finding_slug", "")).startswith("lead:")]
        assert {r.payload["finding_slug"] for r in leads} == {"lead:dns:acme"}
    finally:
        bb.close()


# ---------------------------------------------------------------------------
# (13) LEARN — the autonomous OODA loop feeds its confirm/refute outcomes back into
#      the persistent OutcomeLedger, closing the learning loop the meta-monitor reads.
#      Before this, the flagship/autonomous loop confirmed/refuted findings but fed NO
#      persistent learner (`_meta_caution` always read a ledger no run ever wrote).
# ---------------------------------------------------------------------------


class _FakeReverify:
    """A controllable reverify ToolResult: ``is_fact`` drives the confirm/refute the loop learns."""

    def __init__(self, is_fact: bool, *, refused: bool = False):
        self.output = {"is_fact": is_fact, "verdict": "grounded" if is_fact else "not-grounded"}
        self.refused = refused
        self.ok = True
        self.gate = ""
        self.summary = self.output["verdict"]


def _written_ledger(slug: str):
    from framework.v2.calibration.ledger import OutcomeLedger
    return OutcomeLedger.load(_paths.target_dir(slug) / "outcomes.json")


def test_autonomous_confirmed_outcome_is_written_and_persisted(isolated_engagement, monkeypatch):
    isolated_engagement("alpha", "127.0.0.1")
    monkeypatch.setattr(auto_mod, "_drive_reverify",
                        lambda finding, registry, ctx, sink: _FakeReverify(is_fact=True))
    world = _greedy_world(["https://t.invalid/a"])
    result = _synthetic_result(world, [_finding("xss", "https://t.invalid/a", 0.8)])
    out = run_autonomous_cycle(result, slug="alpha", persist_learning=True, prompt_callback=_deny)

    assert out.outcomes_credited == 1
    assert out.learner_persisted is True
    assert out.cycles[0].learned is True
    led = _written_ledger("alpha")
    assert len(led) == 1
    pred = led.predictions()[0]
    assert pred.oracle_confirmed is True
    assert pred.finding_id == "xss:query:xss"            # bug_class:insertion_point (spine slug convention)
    assert pred.model_version == "autonomous-reverify-v1"


def test_single_oracle_reverify_is_disputed_never_a_fact(isolated_engagement, monkeypatch):
    """PROVE-DON'T-GUESS: a single-oracle confirm is DISPUTED (excluded from every calibrator fit),
    never auto-EXPLOITABLE. The loop can never train its learner on an un-corroborated 'fact'."""
    from framework.v2.calibration.models import OutcomeLabel

    isolated_engagement("alpha", "127.0.0.1")
    monkeypatch.setattr(auto_mod, "_drive_reverify",
                        lambda finding, registry, ctx, sink: _FakeReverify(is_fact=True))
    world = _greedy_world(["https://t.invalid/a"])
    result = _synthetic_result(world, [_finding("xss", "https://t.invalid/a", 0.8)])
    run_autonomous_cycle(result, slug="alpha", persist_learning=True, prompt_callback=_deny)

    (pred, outcome), = _written_ledger("alpha").pairs()
    assert outcome.label is OutcomeLabel.DISPUTED         # one oracle kind -> not cross-corroborated


def test_ledger_dedup_across_runs_no_double_count(isolated_engagement, monkeypatch):
    """A second autonomous run over the same finding does NOT double-count — the persisted ledger's
    append-only guard dedups the stable finding id and credit_outcome swallows the no-op."""
    isolated_engagement("alpha", "127.0.0.1")
    monkeypatch.setattr(auto_mod, "_drive_reverify",
                        lambda finding, registry, ctx, sink: _FakeReverify(is_fact=True))
    world = _greedy_world(["https://t.invalid/a"])
    result = _synthetic_result(world, [_finding("xss", "https://t.invalid/a", 0.8)])
    out1 = run_autonomous_cycle(result, slug="alpha", persist_learning=True, prompt_callback=_deny)
    assert out1.outcomes_credited == 1

    world2 = _greedy_world(["https://t.invalid/a"])
    result2 = _synthetic_result(world2, [_finding("xss", "https://t.invalid/a", 0.8)])
    out2 = run_autonomous_cycle(result2, slug="alpha", persist_learning=True, prompt_callback=_deny)
    assert out2.outcomes_credited == 0                    # deduped, not re-counted
    assert len(_written_ledger("alpha")) == 1


def test_persist_learning_false_writes_no_ledger_file(isolated_engagement, monkeypatch):
    """persist_learning=False preserves the pre-LEARN read-only behaviour: nothing written to disk."""
    isolated_engagement("alpha", "127.0.0.1")
    monkeypatch.setattr(auto_mod, "_drive_reverify",
                        lambda finding, registry, ctx, sink: _FakeReverify(is_fact=True))
    world = _greedy_world(["https://t.invalid/a"])
    result = _synthetic_result(world, [_finding("xss", "https://t.invalid/a", 0.8)])
    out = run_autonomous_cycle(result, slug="alpha", persist_learning=False, prompt_callback=_deny)

    assert out.outcomes_credited == 0 and out.learner_persisted is False
    assert not (_paths.target_dir("alpha") / "outcomes.json").is_file()


def test_fail_closed_refusal_is_not_credited(isolated_engagement, monkeypatch):
    """A fail-closed gate refusal is NOT a refutation — it must never be written as an outcome."""
    isolated_engagement("alpha", "127.0.0.1")
    monkeypatch.setattr(auto_mod, "_drive_reverify",
                        lambda finding, registry, ctx, sink: _FakeReverify(is_fact=False, refused=True))
    world = _greedy_world(["https://t.invalid/a"])
    result = _synthetic_result(world, [_finding("xss", "https://t.invalid/a", 0.8)])
    out = run_autonomous_cycle(result, slug="alpha", persist_learning=True, prompt_callback=_deny)

    assert out.outcomes_credited == 0
    assert not (_paths.target_dir("alpha") / "outcomes.json").is_file()


def test_learning_closes_the_loop_meta_monitor_reads_what_the_loop_wrote(isolated_engagement, monkeypatch):
    """The closure end-to-end: run 1 WRITES the ledger; `_load_ledger` (what `_meta_caution` reads at
    the START of every run) now returns a non-empty ledger the LOOP ITSELF produced."""
    isolated_engagement("alpha", "127.0.0.1")
    monkeypatch.setattr(auto_mod, "_drive_reverify",
                        lambda finding, registry, ctx, sink: _FakeReverify(is_fact=True))
    world = _greedy_world(["https://t.invalid/a", "https://t.invalid/b"])
    result = _synthetic_result(world, [_finding("xss", "https://t.invalid/a", 0.8),
                                       _finding("sqli", "https://t.invalid/b", 0.7)])
    out1 = run_autonomous_cycle(result, slug="alpha", max_cycles=2, persist_learning=True, prompt_callback=_deny)
    assert out1.outcomes_credited >= 1 and out1.learner_persisted

    loaded = auto_mod._load_ledger("alpha")               # exactly the read `_meta_caution` performs
    assert loaded is not None and len(loaded) == out1.outcomes_credited


# ---------------------------------------------------------------------------
# (14) W2.2b — bounded MULTI-STEP lookahead (depth-2) selection. Default off
#      (depth-1 greedy) so every test above stays byte-identical; when enabled it
#      commits a tight budget to COMPLETING a crown-jewel route rather than chasing
#      the single highest-scoring off-route leaf — a pick greedy never makes.
# ---------------------------------------------------------------------------


def _twohop_route_world() -> WorldModel:
    """attacker:self -> ep_on -> db(DATASTORE) is a TWO-hop crown-jewel route (completing it needs
    the leaves on BOTH ep_on AND db); ep_off is an endpoint no crown-jewel route touches. Mirrors
    planner.tests.test_lookahead's fixture through the autonomous helpers."""
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


def _twohop_result() -> EngagementResult:
    # two LOW-prior on-route leaves (on ep_on and on db) whose confirmation TOGETHER completes the
    # route, and one HIGH-prior OFF-route leaf both greedy and myopic-path-aware prefer.
    return _synthetic_result(_twohop_route_world(), [
        _finding("xss", "https://t.invalid/off-path", 0.9),   # greedy/pathaware winner (off-route)
        _finding("idor", "https://t.invalid/on-path", 0.3),   # on-route (mid hop)
        _finding("leak", "https://t.invalid/db", 0.3)])       # on-route (the crown jewel itself)


def test_lookahead_default_off_is_greedy_and_byte_identical():
    """Default depth-1 selection is the one-step greedy/path-aware pick — the off-route high-prior
    leaf — byte-identical to the pre-lookahead behaviour."""
    out = run_autonomous_cycle(_twohop_result(), slug="alpha", request_budget=2, prompt_callback=_deny)
    assert out.lookahead_depth == 1
    assert out.cycles and out.cycles[0].picked_bug_class == "xss", \
        "greedy default should chase the high-prior off-route leaf"


def test_lookahead_depth2_commits_budget_to_completing_the_route():
    """With --autonomous-lookahead (depth-2) and a budget that fits exactly the two-leaf route, the
    planner DROPS the high-prior off-route leaf and commits to COMPLETING the crown-jewel route —
    executing that plan's highest-value step (the leaf on the datastore) first. A pick neither the
    greedy nor the myopic path-aware selector makes."""
    treated = run_autonomous_cycle(_twohop_result(), slug="alpha", request_budget=2,
                                   lookahead_depth=2, prompt_callback=_deny)
    assert treated.lookahead_depth == 2
    assert treated.cycles
    first = treated.cycles[0].picked_bug_class
    assert first != "xss", "lookahead squandered the budget on the off-route leaf"
    assert first in ("idor", "leak"), "lookahead did not commit to the crown-jewel route"
    assert first == "leak", "lookahead did not execute the route's highest-value (crown-jewel) step"
    # ADVISORY-ONLY: the authoritative findings are untouched — lookahead only re-ranks effort.
    assert {f.bug_class for f in treated.engagement.report.active_findings} == {"xss", "idor", "leak"}


def test_lookahead_still_gates_the_tool_call():
    """Lookahead only changes SELECTION; the picked action is still driven as a fail-closed GATED
    tool call (an out-of-scope host here refuses it — the tool never runs unauthorized)."""
    out = run_autonomous_cycle(_twohop_result(), slug="alpha", request_budget=2,
                               lookahead_depth=2, prompt_callback=_deny)
    step = out.cycles[0]
    assert step.gated is True and step.tool == "reverify_finding"


def test_lookahead_selection_is_deterministic():
    def run():
        out = run_autonomous_cycle(_twohop_result(), slug="alpha", max_cycles=3,
                                   request_budget=2, lookahead_depth=2, prompt_callback=_deny)
        return [(s.picked_bug_class, s.reoriented_to) for s in out.cycles]

    assert run() == run(), "lookahead selection is not deterministic"


def test_lookahead_without_crownjewel_degrades_to_greedy():
    """With no reachable crown jewel, depth-2 lookahead degrades VERBATIM to the greedy pick, so it
    is byte-identical to depth-1 there (the receding-horizon selector's documented fallback)."""
    world = _greedy_world(["https://t.invalid/a", "https://t.invalid/b"])
    findings = [_finding("xss", "https://t.invalid/a", 0.6), _finding("sqli", "https://t.invalid/b", 0.5)]
    greedy = run_autonomous_cycle(_synthetic_result(world, list(findings)), slug="alpha",
                                  request_budget=2, prompt_callback=_deny)
    look = run_autonomous_cycle(_synthetic_result(_greedy_world(["https://t.invalid/a", "https://t.invalid/b"]),
                                                  list(findings)),
                                slug="alpha", request_budget=2, lookahead_depth=2, prompt_callback=_deny)
    assert greedy.cycles[0].picked_bug_class == look.cycles[0].picked_bug_class == "xss"
