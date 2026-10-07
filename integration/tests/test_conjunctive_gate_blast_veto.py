"""M4.2 — the pre-action blast-radius VETO wired ON at its production caller (`build_offense_gate`).

The authority gate's blast-radius conjunct was built but had NO production caller — only tests
injected a predictor. These tests exercise the REAL wiring: `build_offense_gate` now resolves a
per-engagement ceiling, builds the real `predict_action_blast_radius` predictor over the engagement
world-model, and passes both into the REAL `authorize_action` for a CONSEQUENTIAL action only.

To keep the test cheap (no trust-root / signed-authority provisioning) ONLY `load_authority_for_gate`
is stubbed to return a real in-scope TWIN authority; `authorize_action`, `ActionRequest` and the whole
blast-radius math are the REAL code. The WorldModel is injected through the `world_provider` seam.

Pinned properties:
  * VETO FIRES: a destructive action whose predicted incremental blast exceeds the ceiling → DENY.
  * BENIGN PASSES: a destructive action that opens a dead-end (zero incremental blast) → ALLOW.
  * READS ARE OFF THE HOT PATH: a read (destructive=False) never builds the predictor — proven with a
    `world_provider` that raises if consulted — and is ALLOWED.
  * DEFAULT-OFF: with no ceiling the destructive high-blast action is ALLOWED (byte-identical).
  * REFUSE-ONLY / ADVISORY: the veto returns a `deny` GateVerdict (never a FACT) and never mutates the
    world-model.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from vigil_integration.conjunctive_gate import build_offense_gate

_NOW = datetime(2026, 6, 1, 12, 0, tzinfo=timezone.utc)


@pytest.fixture
def _real_authority(monkeypatch):
    """Stub ONLY `load_authority_for_gate` → a real in-scope, destructive-permitting TWIN authority.
    `authorize_action` + `ActionRequest` stay REAL, so the blast-radius conjunct runs for real."""
    from framework.v2.authority import gate as _gate
    from framework.v2.authority.models import EngagementAuthority, TargetEnvironment

    auth = EngagementAuthority(
        engagement_slug="acme",
        environment=TargetEnvironment.TWIN,          # TWIN ⇒ no LIVE-attestation / live-ack path
        scope=["*.example.com"],
        not_before=_NOW - timedelta(hours=1),
        not_after=_NOW + timedelta(hours=1),
        allow_destructive=True,                      # so a destructive action reaches the blast conjunct
    )
    monkeypatch.setattr(_gate, "load_authority_for_gate", lambda slug, trust_root=None: auth)
    return auth


def _world_with_crown_behind_gateway():
    """attacker:self --(opened by the action)--> host:app.example.com --> host:gw --> datastore:crown.
    The crown jewel (worth 500) is only reachable once the action opens the attacker's reach to the
    app host; a benign island host reaches nothing."""
    from framework.v2.worldmodel.graph import WorldModel
    from framework.v2.worldmodel.models import Edge, EdgeKind, Node, NodeKind

    ek = EdgeKind.REACHABLE_FROM
    w = WorldModel()

    def _n(nid, k):
        w.add_node(Node(id=nid, kind=k, provenance="t", confidence=1.0, first_seen=1, last_seen=1))

    def _e(s, d):
        w.add_edge(Edge(src=s, dst=d, kind=ek, provenance="t", confidence=1.0, first_seen=1, last_seen=1))

    for nid, k in [("host:app.example.com", NodeKind.HOST), ("host:gw", NodeKind.HOST),
                   ("host:island.example.com", NodeKind.HOST), ("datastore:crown", NodeKind.DATASTORE)]:
        _n(nid, k)
    _e("host:app.example.com", "host:gw")
    _e("host:gw", "datastore:crown")   # crown is reachable FROM the app host, worth 500
    return w


def _impact_crown_500(monkeypatch):
    from framework.v2.worldmodel import impact as _impact

    monkeypatch.setattr(_impact.ImpactModel, "from_slug",
                        classmethod(lambda cls, slug: cls(nodes={"datastore:crown": 500.0}, default=1.0)))


def _boom_provider():
    raise AssertionError("world_provider consulted for a non-consequential (read) action")


def test_destructive_high_blast_action_is_vetoed(_real_authority, monkeypatch):
    _impact_crown_500(monkeypatch)
    w = _world_with_crown_behind_gateway()
    gate = build_offense_gate(
        slug="acme", trust_root=object(), classify=lambda n: "A0", floor="A0", ceiling="A3",
        now=_NOW, blast_ceiling=100.0, world_provider=lambda: w)

    v = gate("http.post", "https://app.example.com/x", destructive=True)
    assert v.allowed is False and v.outcome == "deny"
    assert v.crucible_allowed is False                 # the CRUCIBLE leg denied (blast-radius conjunct)
    assert "blast-radius" in v.reason and "datastore:crown" in v.reason
    # ADVISORY & read-only: the predictor never mutated the world-model.
    assert w.edge_count == 2


def test_destructive_benign_action_passes(_real_authority, monkeypatch):
    _impact_crown_500(monkeypatch)
    w = _world_with_crown_behind_gateway()
    gate = build_offense_gate(
        slug="acme", trust_root=object(), classify=lambda n: "A0", floor="A0", ceiling="A3",
        now=_NOW, blast_ceiling=100.0, world_provider=lambda: w)

    # island host reaches no crown jewel → zero incremental blast → the CRUCIBLE leg (which holds the
    # blast conjunct) ALLOWS. The final verdict is still a deny, but ONLY on the orthogonal
    # threshold-destruction requirement (no destruction gate wired in this test) — NOT the blast veto.
    v = gate("http.post", "https://island.example.com/x", destructive=True)
    assert v.crucible_allowed is True                  # the blast veto did NOT fire
    assert "blast-radius" not in v.reason


def test_read_is_never_vetoed_and_never_builds_the_predictor(_real_authority, monkeypatch):
    _impact_crown_500(monkeypatch)
    gate = build_offense_gate(
        slug="acme", trust_root=object(), classify=lambda n: "A0", floor="A0", ceiling="A3",
        now=_NOW, blast_ceiling=0.0, world_provider=_boom_provider)   # would veto everything IF consulted

    # destructive=False ⇒ the veto path is never entered: _boom_provider must NOT be called.
    v = gate("http.get", "https://app.example.com/x", destructive=False)
    assert v.allowed is True and v.outcome == "allow"


def test_no_ceiling_is_default_off_and_allows_the_high_blast_action(_real_authority, monkeypatch):
    _impact_crown_500(monkeypatch)
    w = _world_with_crown_behind_gateway()
    # No explicit ceiling and (stubbed) no impact.yaml ceiling → veto OFF → the same high-blast
    # destructive action that was vetoed above is now ALLOWED (byte-identical to pre-M4.2).
    monkeypatch.setattr("vigil_integration.conjunctive_gate._effective_blast_ceiling",
                        lambda slug, explicit: explicit)   # explicit is None here
    gate = build_offense_gate(
        slug="acme", trust_root=object(), classify=lambda n: "A0", floor="A0", ceiling="A3",
        now=_NOW, world_provider=lambda: w)

    # Same high-blast destructive action as test_destructive_high_blast_action_is_vetoed, but with no
    # ceiling: the blast veto never fires, so the CRUCIBLE leg ALLOWS (byte-identical to pre-M4.2).
    v = gate("http.post", "https://app.example.com/x", destructive=True)
    assert v.crucible_allowed is True and "blast-radius" not in v.reason


def test_missing_world_model_leaves_the_veto_disarmed(_real_authority, monkeypatch):
    _impact_crown_500(monkeypatch)
    # A ceiling is set but there is no world-model (provider returns None) → the veto has no basis and
    # is left DISARMED (it never fabricates a refusal from no evidence): the CRUCIBLE leg ALLOWS.
    gate = build_offense_gate(
        slug="acme", trust_root=object(), classify=lambda n: "A0", floor="A0", ceiling="A3",
        now=_NOW, blast_ceiling=0.0, world_provider=lambda: None)

    v = gate("http.post", "https://app.example.com/x", destructive=True)
    assert v.crucible_allowed is True and "blast-radius" not in v.reason
