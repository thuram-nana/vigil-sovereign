"""framework.v2.agents.graph_projection — the OFFENSE projector that mirrors the real agent SPINE onto the
customer-safe live-graph seam.

Invariants a false-green would break:
  * EVERY projected event row is grounded in a REAL blackboard event (its ``ref`` is a live event id) — there is
    no fabricated node, no placeholder agent, no invented heartbeat (the honesty doctrine, AS-4a);
  * the recorded edges are grounded — delegation follows a real ``parent_id``, the phase backbone follows the
    real stage order, attach follows the active stage;
  * read-only — the projector never posts/supersedes/edits (the spine stays append-only);
  * the reused-slug boundary — a RESET anchors at the spine high-water, so a re-launch on the same (org, host)
    slug never replays the PRIOR run's events as the current graph;
  * every role the projector can emit is on the seam's allowlist (no silently-dropped node);
  * the mirror is flag-gated + best-effort (a projection failure never raises into the engine).
"""
from __future__ import annotations

import os
import tempfile
from pathlib import Path

import pytest


def _bb():
    from framework.v2.agents.blackboard import open_blackboard
    return open_blackboard(db_path=Path(tempfile.mkdtemp()) / "bb.sqlite")


def _finding(slug: str, bb, agent: str, *, verified: bool, parent_id=None):
    return bb.post(engagement=slug, kind="finding", agent_name=agent,
                   payload={"finding_slug": "idor-1", "title": "IDOR", "severity": "High", "bug_class": "idor",
                            "surface": "/a", "summary": "x", "verified_by_oracle": verified}, parent_id=parent_id)


@pytest.fixture(autouse=True)
def _iso(monkeypatch):
    monkeypatch.setenv("CRUCIBLE_V2_ROOT", tempfile.mkdtemp())


def test_projects_only_real_events_with_grounded_nodes_and_edges():
    from framework.v2.agents.graph_projection import GraphProjector
    from vigil_core import live_graph as lg
    base = tempfile.mkdtemp()
    bb = _bb()
    slug = "org-host-1"
    proj = GraphProjector(bb, slug, base)
    proj.reset()
    proj.on_phase("preflight", "started", ts=1.0)
    h = bb.post(engagement=slug, kind="observation", agent_name="recon",
                payload={"source": "recon", "surface": "svc", "summary": "seen"})
    proj.on_phase("scan", "started", ts=2.0)
    tc = bb.post(engagement=slug, kind="tool_call", agent_name="exploit", payload={"tool": "http"}, parent_id=h)
    f = _finding(slug, bb, "exploit", verified=True, parent_id=tc)
    proj.on_phase("scan", "completed", ts=3.0)
    bb.post(engagement=slug, kind="critic_verdict", agent_name="grounding",
            payload={"critic": "grounding", "target_event_id": f, "verdict": "endorse"}, parent_id=f)
    proj.on_phase("assess_grounding", "started", ts=4.0)

    g = lg.graph(base, slug)
    nodes = {n["id"]: n for n in g["nodes"]}
    assert "agent:recon" in nodes and "agent:exploit" in nodes and "agent:grounding" in nodes
    assert nodes["agent:exploit"]["verified"] == 1
    assert nodes["phase:scan"]["status"] == "done"

    # EVERY projected event row's ref is a REAL live blackboard event id — zero fabrication.
    rows = lg.read(base, slug)
    real_ids = {r.id for r in bb.replay(engagement=slug)}
    event_rows = [r for r in rows if r["kind"] != "phase"]
    assert event_rows, "the projector must mirror the real agent events"
    assert all(r["ref"] in real_ids for r in event_rows)

    edges = {(e["src"], e["dst"], e["kind"]) for e in g["edges"]}
    assert ("agent:recon", "agent:exploit", "delegation") in edges       # follows the real parent_id
    assert ("agent:exploit", "agent:grounding", "delegation") in edges
    assert ("phase:preflight", "phase:scan", "sequence") in edges        # the real stage order
    assert ("phase:scan", "agent:exploit", "attach") in edges            # active during the stage


def test_reset_anchors_at_highwater_so_a_prior_run_is_never_replayed():
    from framework.v2.agents.graph_projection import GraphProjector
    from vigil_core import live_graph as lg
    base = tempfile.mkdtemp()
    bb = _bb()
    slug = "org-host-reused"                                 # a slug reused by every launch of the same (org, host)
    proj = GraphProjector(bb, slug, base)
    # a PRIOR run already posted a pile of events on this slug's spine
    proj.reset()
    proj.on_phase("scan", "started", ts=1.0)
    _finding(slug, bb, "exploit", verified=True)
    bb.post(engagement=slug, kind="observation", agent_name="recon",
            payload={"source": "r", "surface": "s", "summary": "old"})
    proj.on_phase("scan", "completed", ts=2.0)
    old_cursor = lg.graph(base, slug)["generation"]
    assert old_cursor > 0

    # a NEW launch on the SAME slug resets the trail — the prior run's spine events must NOT reappear
    proj.reset()
    proj.on_phase("preflight", "started", ts=10.0)
    g = lg.graph(base, slug)
    assert [n["id"] for n in g["nodes"]] == ["phase:preflight"]           # ONLY the new run — no stale agents
    rows = lg.read(base, slug)
    assert all(r["kind"] == "phase" for r in rows)                        # none of the prior run's agent events


def test_every_projected_role_is_on_the_seam_allowlist():
    # a drift between the projector's role map and the seam's allowlist would silently drop a real node.
    from framework.v2.agents.graph_projection import _ROLE_BY_AGENT
    from vigil_core.live_graph import _AGENT_ROLES
    for role in _ROLE_BY_AGENT.values():
        assert role in _AGENT_ROLES, role
    assert "agent" in _AGENT_ROLES                                        # the generic bucket for an unknown name


def test_an_unknown_agent_name_normalises_to_a_real_generic_node_not_dropped():
    from framework.v2.agents.graph_projection import GraphProjector
    from vigil_core import live_graph as lg
    base = tempfile.mkdtemp()
    bb = _bb()
    slug = "org-host-x"
    proj = GraphProjector(bb, slug, base)
    proj.reset()
    proj.on_phase("scan", "started", ts=1.0)
    bb.post(engagement=slug, kind="observation", agent_name="some-new-specialist",
            payload={"source": "x", "surface": "y", "summary": "z"})
    proj.on_phase("scan", "completed", ts=2.0)
    nodes = {n["id"] for n in lg.graph(base, slug)["nodes"]}
    assert "agent:agent" in nodes                                        # a real node, generically labelled (honest)


def test_projection_is_read_only_and_best_effort():
    from framework.v2.agents.graph_projection import GraphProjector
    base = tempfile.mkdtemp()
    bb = _bb()
    slug = "org-host-ro"
    proj = GraphProjector(bb, slug, base)
    proj.reset()
    proj.on_phase("scan", "started", ts=1.0)
    bb.post(engagement=slug, kind="observation", agent_name="recon",
            payload={"source": "r", "surface": "s", "summary": "t"})
    before = [(r.id, r.kind, r.agent_name) for r in bb.replay(engagement=slug, include_superseded=True)]
    proj.on_phase("scan", "completed", ts=2.0)
    after = [(r.id, r.kind, r.agent_name) for r in bb.replay(engagement=slug, include_superseded=True)]
    assert before == after                                               # the projector wrote NOTHING to the spine

    # best-effort: a broken seam base never raises out of on_phase
    bad = GraphProjector(bb, slug, base="\x00not-a-dir")
    bad.reset()
    bad.on_phase("scan", "started", ts=1.0)                              # must not raise


def test_flag_default_off(monkeypatch):
    from framework.v2.agents import graph_projection as gp
    for off in ("", "0", "no", "off", "false"):
        monkeypatch.setenv("VIGIL_CUSTOMER_LIVE_GRAPH", off)
        assert gp.flag_enabled() is False
    # EVERY canonical affirmative token turns the EMIT plane on — crucially INCLUDING ``enabled`` (and its mixed
    # case ``Enabled``), the token whose omission used to strand the read plane polling an empty seam.
    for on in ("1", "true", "yes", "on", "enabled", "Enabled"):
        monkeypatch.setenv("VIGIL_CUSTOMER_LIVE_GRAPH", on)
        assert gp.flag_enabled() is True, on
    monkeypatch.delenv("VIGIL_CUSTOMER_LIVE_GRAPH", raising=False)
    assert gp.flag_enabled() is False


def test_emit_and_read_planes_agree_on_every_affirmative_token(monkeypatch):
    # The two-plane invariant the divergence broke: the OFFENSE emit gate (flag_enabled) and the SOVEREIGN read
    # gate (config.customer_live_graph_enabled) must agree on EVERY token, or an engagement emits onto a seam the
    # reader never turns on (or vice-versa). The FATAL-2 boundary forbids a cross-plane import in PRODUCTION code,
    # so the projector mirrors the literal set; here in a TEST we import both to PROVE they stay in lockstep.
    from framework.v2.agents import graph_projection as gp
    sov = pytest.importorskip("sigil.config")                         # the sovereign gate (skip if sigil not on path)

    assert set(gp._AFFIRMATIVE) == set(sov._OIDC_AFFIRMATIVE)          # the literal sets are byte-for-byte identical
    assert "enabled" in gp._AFFIRMATIVE                                # the token the divergence dropped
    for tok in gp._AFFIRMATIVE:                                        # every canonical token: ON on BOTH planes
        monkeypatch.setenv("VIGIL_CUSTOMER_LIVE_GRAPH", tok)
        assert gp.flag_enabled() is True and sov.customer_live_graph_enabled() is True, tok
    for tok in ("enabled", "Enabled", "ENABLED"):                     # case-folded identically on both planes
        monkeypatch.setenv("VIGIL_CUSTOMER_LIVE_GRAPH", tok)
        assert gp.flag_enabled() is True and sov.customer_live_graph_enabled() is True, tok
    for tok in ("", "0", "off", "disabled", "enable"):               # a non-affirmative token is OFF on BOTH planes
        monkeypatch.setenv("VIGIL_CUSTOMER_LIVE_GRAPH", tok)
        assert gp.flag_enabled() is False and sov.customer_live_graph_enabled() is False, tok


# --- the PhaseLedger wiring: the graph mirror is driven ONLY when the flag is on AND a spine is handed in -----
def _ledger_graph_rows(monkeypatch, *, flag: str | None, spine):
    import tempfile as _tmp

    from framework.v2.phase_ledger import PhaseLedger
    from vigil_core import live_graph as lg
    base = _tmp.mkdtemp()
    monkeypatch.setenv("VIGIL_BASE_DIR", base)                           # where resolve_seam_base() points
    if flag is None:
        monkeypatch.delenv("VIGIL_CUSTOMER_LIVE_GRAPH", raising=False)
    else:
        monkeypatch.setenv("VIGIL_CUSTOMER_LIVE_GRAPH", flag)
    slug = "led-" + os.urandom(4).hex()
    ledger = PhaseLedger(slug, sink=None, spine=spine)
    ledger.start("preflight")
    if spine is not None:
        bb = spine
        bb.post(engagement=slug, kind="observation", agent_name="recon",
                payload={"source": "r", "surface": "s", "summary": "t"})
    ledger.complete("scan")
    return lg.read(base, slug), slug


def test_phase_ledger_drives_the_mirror_only_with_flag_on_and_a_spine(monkeypatch):
    bb = _bb()
    # flag OFF + spine present -> NO seam written (byte-identical to the surface not existing)
    rows_off, _ = _ledger_graph_rows(monkeypatch, flag="0", spine=bb)
    assert rows_off == []
    # flag ON but NO spine -> still nothing (the projector needs the spine handle)
    rows_nospine, _ = _ledger_graph_rows(monkeypatch, flag="1", spine=None)
    assert rows_nospine == []
    # flag ON + spine -> the phase backbone AND the real agent event are mirrored
    bb2 = _bb()
    rows_on, slug = _ledger_graph_rows(monkeypatch, flag="1", spine=bb2)
    kinds = [r["kind"] for r in rows_on]
    assert "phase" in kinds and "observation" in kinds
    # every non-phase row is grounded in a real spine event
    real_ids = {r.id for r in bb2.replay(engagement=slug)}
    assert all(r["ref"] in real_ids for r in rows_on if r["kind"] != "phase")
