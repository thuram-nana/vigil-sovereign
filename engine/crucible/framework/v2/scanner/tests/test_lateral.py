"""
C4 — internal attack paths / lateral movement over the FUSED world.

These tests build a world-model by hand in exactly the shape fusion leaves it
(``engage_fusion._project_oracle_fact``: a GROUNDED ``finding:<oracle>:<res>`` node +
an EVIDENCES edge to its subject) and assert:

  * a confirmed ``active_exposure`` gives the attacker a REACHED edge to the public
    crown jewel (a real 1-hop lateral route);
  * a confirmed ``policy_path`` grant, when the attacker can ALREADY reach the granting
    principal, chains into a multi-hop route to the resource;
  * NEAR-ZERO-FP: a confirmed grant to a principal the attacker CANNOT reach yields NO
    path (a dangling lateral edge is never a fabricated attacker route);
  * an UNGROUNDED (non-oracle) finding is never bridged;
  * the bridge is idempotent (a re-run adds no duplicate edges / paths).
"""

from __future__ import annotations

from framework.v2.scanner.lateral import bridge_confirmed_cloud_facts, lateral_paths
from framework.v2.worldmodel.attacker import ATTACKER_ID
from framework.v2.worldmodel.graph import WorldModel
from framework.v2.worldmodel.impact import ImpactModel
from framework.v2.worldmodel.models import Edge, EdgeKind, Node, NodeKind

_IMPACT = ImpactModel.from_slug("c4-test")


def _oracle_fact(world: WorldModel, *, oracle_kind: str, subject_id: str, subject_kind: NodeKind,
                 seq: int, detail: dict | None = None) -> str:
    """Reproduce the fusion projection: a GROUNDED finding node + an EVIDENCES edge to its subject
    (the subject minted as a plain LEAD, exactly as the sensor leaves it)."""
    key = subject_id.split(":", 1)[-1]
    fid = f"finding:{oracle_kind}:{key}"
    attrs = {"bug_class": oracle_kind, "confirmed_by": oracle_kind}
    if detail:
        attrs.update(detail)
    world.add_node(Node(id=fid, kind=NodeKind.FINDING, attrs=attrs,
                        provenance=f"oracle:{oracle_kind}", confidence=0.99,
                        first_seen=seq, last_seen=seq))
    if not world.has_node(subject_id):
        world.add_node(Node(id=subject_id, kind=subject_kind, attrs={},
                            provenance=f"intel:fusion:{subject_id}", confidence=0.6,
                            first_seen=seq, last_seen=seq))
    world.add_edge(Edge(src=fid, dst=subject_id, kind=EdgeKind.EVIDENCES, attrs={},
                        provenance=f"oracle:{oracle_kind}", confidence=0.99,
                        first_seen=seq, last_seen=seq))
    return fid


def test_active_exposure_gives_the_attacker_a_reached_edge_to_the_crown_jewel() -> None:
    world = WorldModel()
    _oracle_fact(world, oracle_kind="active_exposure", subject_id="datastore:public-bucket",
                 subject_kind=NodeKind.DATASTORE, seq=1)
    paths = lateral_paths(world, impact_model=_IMPACT, seq_base=10)
    # the anonymously-reachable bucket is reached by the external attacker directly
    assert world.get_edge(ATTACKER_ID, "datastore:public-bucket", EdgeKind.REACHED) is not None
    dests = {p.destination for p in paths}
    assert "datastore:public-bucket" in dests


def test_policy_path_grant_chains_when_the_attacker_can_reach_the_principal() -> None:
    world = WorldModel()
    # a confirmed grant path: principal 'role/app' can reach the datastore.
    _oracle_fact(world, oracle_kind="policy_path", subject_id="datastore:crown-db",
                 subject_kind=NodeKind.DATASTORE, seq=1, detail={"principal": "role/app", "access": "read"})
    # the attacker ALREADY controls that principal (established by some other confirmed means).
    world.add_node(Node(id="attacker:self", kind=NodeKind.PRINCIPAL, attrs={"role": "attacker"},
                        provenance="attacker:init", confidence=1.0, first_seen=2, last_seen=2))
    world.add_node(Node(id="principal:role/app", kind=NodeKind.PRINCIPAL, attrs={},
                        provenance="intel:iam", confidence=0.7, first_seen=2, last_seen=2))
    world.add_edge(Edge(src=ATTACKER_ID, dst="principal:role/app", kind=EdgeKind.OWNS, attrs={},
                        provenance="postcondition:own", confidence=0.9, first_seen=3, last_seen=3))
    paths = lateral_paths(world, impact_model=_IMPACT, seq_base=10)
    # the bridge added the confirmed grant as a traversable edge ...
    assert world.get_edge("principal:role/app", "datastore:crown-db", EdgeKind.HAS_GRANT) is not None
    # ... and best_paths chains attacker -> principal -> resource
    assert any(p.destination == "datastore:crown-db" for p in paths)


def test_dangling_grant_to_an_unreachable_principal_yields_no_path() -> None:
    # NEAR-ZERO-FP: a confirmed grant whose principal the attacker CANNOT reach must not produce
    # a fabricated attacker route to the resource.
    world = WorldModel()
    _oracle_fact(world, oracle_kind="policy_path", subject_id="datastore:crown-db",
                 subject_kind=NodeKind.DATASTORE, seq=1, detail={"principal": "role/unreachable"})
    paths = lateral_paths(world, impact_model=_IMPACT, seq_base=10)
    # the grant edge IS materialised (it is a real confirmed grant) ...
    assert world.get_edge("principal:role/unreachable", "datastore:crown-db", EdgeKind.HAS_GRANT) is not None
    # ... but no attacker route reaches the resource (the attacker cannot reach the principal).
    assert all(p.destination != "datastore:crown-db" for p in paths)


def test_ungrounded_finding_is_never_bridged() -> None:
    world = WorldModel()
    # a LEAD-tier (intel) look-alike, NOT an oracle fact — must not be bridged.
    world.add_node(Node(id="finding:active_exposure:maybe-public", kind=NodeKind.FINDING,
                        attrs={"bug_class": "active_exposure"}, provenance="intel:guess",
                        confidence=0.5, first_seen=1, last_seen=1))
    world.add_node(Node(id="datastore:maybe-public", kind=NodeKind.DATASTORE, attrs={},
                        provenance="intel:fusion:x", confidence=0.5, first_seen=1, last_seen=1))
    world.add_edge(Edge(src="finding:active_exposure:maybe-public", dst="datastore:maybe-public",
                        kind=EdgeKind.EVIDENCES, attrs={}, provenance="intel:guess",
                        confidence=0.5, first_seen=1, last_seen=1))
    added = bridge_confirmed_cloud_facts(world, seq_base=10)
    assert added == 0
    assert world.get_edge(ATTACKER_ID, "datastore:maybe-public", EdgeKind.REACHED) is None


def test_bridge_is_idempotent_over_re_runs() -> None:
    world = WorldModel()
    _oracle_fact(world, oracle_kind="active_exposure", subject_id="datastore:public-bucket",
                 subject_kind=NodeKind.DATASTORE, seq=1)
    first = bridge_confirmed_cloud_facts(world, seq_base=10)
    edges_after_first = len(world.all_edges())
    second = bridge_confirmed_cloud_facts(world, seq_base=20)
    assert first == 1 and second == 1                 # counts the fact each run ...
    assert len(world.all_edges()) == edges_after_first  # ... but upserts the same edge (no duplicate)


def test_missing_subject_edge_is_skipped_not_crashed() -> None:
    # a finding with no EVIDENCES edge (defensive) is skipped, never raises.
    world = WorldModel()
    world.add_node(Node(id="finding:active_exposure:orphan", kind=NodeKind.FINDING,
                        attrs={"bug_class": "active_exposure"}, provenance="oracle:active_exposure",
                        confidence=0.99, first_seen=1, last_seen=1))
    assert bridge_confirmed_cloud_facts(world, seq_base=10) == 0


def _finding_with_subject(world: WorldModel, *, fid: str, provenance: str, subject_id: str,
                          subject_kind: NodeKind, detail: dict | None = None) -> None:
    """A finding node at an ARBITRARY provenance + a single EVIDENCES edge to a crown-jewel subject —
    used to probe the admission gate directly (bypassing _oracle_fact's oracle: provenance)."""
    world.add_node(Node(id=fid, kind=NodeKind.FINDING, attrs=dict(detail or {}),
                        provenance=provenance, confidence=0.99, first_seen=1, last_seen=1))
    world.add_node(Node(id=subject_id, kind=subject_kind, attrs={}, provenance="intel:x",
                        confidence=0.6, first_seen=1, last_seen=1))
    world.add_edge(Edge(src=fid, dst=subject_id, kind=EdgeKind.EVIDENCES, attrs={},
                        provenance=provenance, confidence=0.99, first_seen=1, last_seen=1))


def test_grounded_but_non_oracle_provenance_is_never_bridged() -> None:
    # GROUNDING_GROUNDED admits cert:/finding:/evidence: too — but the bridge gates on the EXACT
    # confirming-oracle provenance, so a GROUNDED-but-not-cloud-oracle finding (even with a matching
    # finding-id) is NOT bridged and never restamped oracle:*.
    for prov in ("cert:signed-abc", "finding:derived-agg", "evidence:blob-42"):
        world = WorldModel()
        _finding_with_subject(world, fid="finding:active_exposure:crown", provenance=prov,
                              subject_id="datastore:crown", subject_kind=NodeKind.DATASTORE)
        assert bridge_confirmed_cloud_facts(world, seq_base=10) == 0, prov
        assert world.get_edge(ATTACKER_ID, "datastore:crown", EdgeKind.REACHED) is None


def test_other_grounded_oracle_kinds_are_not_bridged() -> None:
    # ONLY active_exposure + policy_path are bridged; every OTHER fired cloud/posture oracle
    # (cloud_posture, k8s_posture, reachability, tls_weakness, …) is a GROUNDED fact but NOT a
    # lateral-movement edge — it must not become an attacker-traversable edge.
    for kind in ("cloud_posture", "k8s_posture", "reachability", "tls_weakness"):
        world = WorldModel()
        _finding_with_subject(world, fid=f"finding:{kind}:res", provenance=f"oracle:{kind}",
                              subject_id="datastore:res", subject_kind=NodeKind.DATASTORE,
                              detail={"principal": "role/x"})
        assert bridge_confirmed_cloud_facts(world, seq_base=10) == 0, kind
        assert world.get_edge(ATTACKER_ID, "datastore:res", EdgeKind.REACHED) is None


def test_finding_id_key_collision_is_skipped_fail_closed() -> None:
    # two resources of DIFFERENT kinds sharing a key ('acme') collide on one finding id
    # 'finding:policy_path:acme' (the id omits the kind) -> two EVIDENCES subjects. The principal attr
    # is last-writer-wins and may not match a given subject, so the bridge SKIPS it fail-closed rather
    # than cross-wire a grant onto the wrong resource.
    world = WorldModel()
    world.add_node(Node(id="finding:policy_path:acme", kind=NodeKind.FINDING,
                        attrs={"principal": "role/app"}, provenance="oracle:policy_path",
                        confidence=0.99, first_seen=1, last_seen=1))
    for sid in ("datastore:acme", "host:acme"):
        kind = NodeKind.DATASTORE if sid.startswith("datastore") else NodeKind.HOST
        world.add_node(Node(id=sid, kind=kind, attrs={}, provenance="intel:x",
                            confidence=0.6, first_seen=1, last_seen=1))
        world.add_edge(Edge(src="finding:policy_path:acme", dst=sid, kind=EdgeKind.EVIDENCES,
                            attrs={}, provenance="oracle:policy_path", confidence=0.99,
                            first_seen=1, last_seen=1))
    assert bridge_confirmed_cloud_facts(world, seq_base=10) == 0
    assert world.get_edge("principal:role/app", "datastore:acme", EdgeKind.HAS_GRANT) is None
    assert world.get_edge("principal:role/app", "host:acme", EdgeKind.HAS_GRANT) is None
