"""
World-model admission (anti-hallucination P2): every write is tagged with a provenance
grounding tier, additively — belief is UNCHANGED in the default mode (no regression), and
only an opt-in strict mode floors an ungrounded (LLM/assumption) write's belief. The tag
makes grounding queryable everywhere and reuses the one classifier the veracity firewall
also uses.
"""

from __future__ import annotations

from framework.v2.intel.models import IntelSourceKind, Observation
from framework.v2.intel.project import project_observation
from framework.v2.intel.refs import canonicalize
from framework.v2.worldmodel.graph import WorldModel
from framework.v2.worldmodel.models import (
    GROUNDING_GROUNDED,
    GROUNDING_INTEL,
    GROUNDING_UNCLASSIFIED,
    GROUNDING_UNGROUNDED,
    EdgeKind,
    Edge,
    Node,
    NodeKind,
    classify_provenance,
)
from framework.v2.worldmodel.store import from_json, to_json


def _node(nid, prov, conf=0.9):
    return Node(id=nid, kind=NodeKind.HOST, provenance=prov, confidence=conf,
                first_seen=1, last_seen=1)


# ---- the classifier ---------------------------------------------------------


def test_classify_provenance_tiers() -> None:
    assert classify_provenance("oracle:finding-1") == GROUNDING_GROUNDED
    assert classify_provenance("cert:abc") == GROUNDING_GROUNDED
    assert classify_provenance("finding:xss") == GROUNDING_GROUNDED
    assert classify_provenance("llm-said-so") == GROUNDING_UNGROUNDED
    assert classify_provenance("assume:budget") == GROUNDING_UNGROUNDED
    assert classify_provenance("intel:obs-42") == GROUNDING_INTEL
    assert classify_provenance("derived:co-hosting") == GROUNDING_INTEL
    assert classify_provenance("operator:seed") == GROUNDING_UNCLASSIFIED
    assert classify_provenance("") == GROUNDING_UNCLASSIFIED


# ---- add_node tags grounding, DEFAULT belief unchanged ----------------------


def test_add_node_tags_grounding_without_changing_belief() -> None:
    w = WorldModel()
    grounded = w.add_node(_node("host:a", "oracle:f1", 0.9))
    ungrounded = w.add_node(_node("host:b", "llm-said-so", 0.9))
    assert grounded.grounding == GROUNDING_GROUNDED
    assert ungrounded.grounding == GROUNDING_UNGROUNDED
    # DEFAULT mode: belief is byte-identical regardless of grounding (no regression).
    assert abs(grounded.belief_mean - ungrounded.belief_mean) < 1e-12


def test_merge_grounding_follows_winning_provenance() -> None:
    w = WorldModel()
    w.add_node(_node("host:x", "llm-said-so", 0.5))       # weak LLM assertion first
    merged = w.add_node(_node("host:x", "oracle:f9", 0.9))  # then oracle corroborates
    assert merged.grounding == GROUNDING_GROUNDED           # follows the higher-confidence provenance


# ---- strict mode floors ONLY ungrounded belief ------------------------------


def test_strict_mode_floors_ungrounded_belief_only() -> None:
    w = WorldModel(strict_grounding=True)
    grounded = w.add_node(_node("host:g", "oracle:f1", 0.9))
    ungrounded = w.add_node(_node("host:u", "llm-said-so", 0.9))
    assert grounded.belief_mean > 0.6                       # a real fact keeps its belief
    assert ungrounded.belief_mean < 0.45                    # an LLM assertion is floored
    # a plain WorldModel leaves both at the same (unfloored) belief
    plain = WorldModel()
    assert plain.add_node(_node("host:u", "llm-said-so", 0.9)).belief_mean > 0.6


# ---- round-trip through the store ------------------------------------------


def test_grounding_survives_store_round_trip() -> None:
    w = WorldModel()
    w.add_node(_node("host:a", "oracle:f1"))
    w.add_node(_node("host:b", "llm-said-so"))
    w.add_edge(Edge(src="host:a", dst="host:b", kind=EdgeKind.REACHABLE_FROM,
                    provenance="oracle:f1", confidence=0.9, first_seen=1, last_seen=1))
    reloaded = from_json(to_json(w))
    assert reloaded.get_node("host:a").grounding == GROUNDING_GROUNDED
    assert reloaded.get_node("host:b").grounding == GROUNDING_UNGROUNDED
    assert reloaded.get_edge("host:a", "host:b", EdgeKind.REACHABLE_FROM).grounding == GROUNDING_GROUNDED


# ---- bug fix: intel projection preserves edge attrs -------------------------


def test_intel_projection_carries_edge_attrs() -> None:
    w = WorldModel()
    obs = Observation(
        obs_id="infer:transitive_ownership:asn:AS1|asset_owns|domain:x.com",
        source="infer", source_kind=IntelSourceKind.INFERENCE,
        subject=canonicalize(NodeKind.ASN, "AS1"), relation=EdgeKind.ASSET_OWNS,
        object=canonicalize(NodeKind.DOMAIN, "x.com"),
        attrs={"via_host": "host:10.0.0.1", "via_netblock": "netblock:10.0.0.0/24"},
        confidence=0.6, seq=1)
    project_observation(w, obs)
    edge = w.get_edge("asn:AS1", "domain:x.com", EdgeKind.ASSET_OWNS)
    assert edge is not None and edge.attrs.get("via_host") == "host:10.0.0.1"   # rationale preserved
    assert edge.grounding == GROUNDING_INTEL                                      # intel provenance
