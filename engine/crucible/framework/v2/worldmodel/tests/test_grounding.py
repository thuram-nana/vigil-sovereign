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


def test_a_grounded_prefix_cannot_launder_an_ungrounded_claim() -> None:
    """THE ORDERING HAZARD, pinned. The classifier used to test grounded prefixes BEFORE the
    ungrounded markers, so a string that carried a grounded prefix AND an ungrounded marker in its
    remainder — ``oracle:llm-said-so``, ``evidence:unverified-thing`` — read back as a FACT. Nothing
    writes such a string today, but an unsound classifier is a latch waiting for a future caller. The
    marker now wins inside the grounded-prefix branch."""
    assert classify_provenance("oracle:llm-said-so") == GROUNDING_UNGROUNDED
    assert classify_provenance("evidence:unverified-thing") == GROUNDING_UNGROUNDED
    assert classify_provenance("finding:assume-it-works") == GROUNDING_UNGROUNDED
    assert classify_provenance("cert:hallucinated") == GROUNDING_UNGROUNDED
    # the fix is SCOPED to the grounded-prefix branch: an ordinary intel provenance that legitimately
    # contains a marker word ("advisory") stays INTEL, not reclassified to ungrounded.
    assert classify_provenance("intel:advisory:CVE-2024-0001") == GROUNDING_INTEL
    # and a genuine oracle fact is untouched.
    assert classify_provenance("oracle:boolean_sqli") == GROUNDING_GROUNDED


def test_grounded_is_sticky_a_lead_cannot_demote_a_fact() -> None:
    """A confirmed fact must not be silently erased. A conf-1.0 sensor LEAD re-asserted on an
    oracle-grounded node wins the max-confidence tiebreak — and used to rewrite the provenance to
    itself, demoting the fact to a lead (belief-floored under strict mode). GROUNDED is now sticky:
    the belief still updates, but the node stays a fact. This never promotes — a lead on a lead is
    unaffected, and a second oracle still wins."""
    w = WorldModel()
    w.add_node(_node("host:f", "oracle:boolean_sqli", 0.99))           # an oracle confirms it
    after = w.add_node(_node("host:f", "intel:nmap-reobserved", 1.0))  # a higher-conf lead re-observes
    assert after.grounding == GROUNDING_GROUNDED, "a high-confidence lead demoted a confirmed fact"
    assert after.provenance == "oracle:boolean_sqli", "the fact's provenance pointer was overwritten"
    # sticky protects a fact; it does NOT fabricate one — a lead re-observed on a lead stays a lead.
    w.add_node(_node("host:g", "intel:a", 0.5))
    lead_after = w.add_node(_node("host:g", "intel:b", 1.0))
    assert lead_after.grounding == GROUNDING_INTEL


def test_the_veracity_firewall_can_still_demote_a_fact_whose_proof_did_not_refire() -> None:
    """THE EXCEPTION THAT MAKES STICKINESS SAFE, and a defect the first version of it introduced.

    ``demoted:`` is what the veracity firewall writes when a recorded-confirmed finding's RETAINED
    PROOF DID NOT RE-FIRE (``scanner/campaign.py``). That layer's whole authority is that it may only
    ever demote — so its write MUST land. The first sticky rule blocked it, which inverted the
    firewall: a stale or tampered finding whose proof no longer fires stayed GROUNDED and read back
    out of the graph as a fact.

    This is the regression test for that. It is the one direction where refusing to overwrite a
    grounded node is the UNSAFE choice."""
    w = WorldModel()
    w.add_node(_node("finding:x", "oracle:boolean_sqli", 0.99))
    demoted = w.add_node(_node("finding:x", "demoted:boolean_sqli", 0.99))
    assert demoted.provenance == "demoted:boolean_sqli", "the firewall's demotion was blocked"
    assert demoted.grounding != GROUNDING_GROUNDED, "a finding whose proof did not re-fire reads as a fact"
    # and the demotion holds even when the demoting write is LOWER confidence than the fact was.
    w2 = WorldModel()
    w2.add_node(_node("finding:y", "oracle:xss", 0.99))
    d2 = w2.add_node(_node("finding:y", "demoted:xss", 0.10))
    assert d2.grounding != GROUNDING_GROUNDED, "a low-confidence demotion was ignored"


def test_an_llm_assertion_still_cannot_overwrite_a_fact() -> None:
    """MUTATION CONTROL for the demotion exception: it must be scoped to the firewall's marker, not a
    blanket 'any ungrounded write wins'. A high-confidence LLM assertion on an oracle-confirmed node
    must still be refused — that is the case stickiness exists for."""
    w = WorldModel()
    w.add_node(_node("host:z", "oracle:boolean_sqli", 0.99))
    after = w.add_node(_node("host:z", "llm-said-so", 1.0))
    assert after.grounding == GROUNDING_GROUNDED and after.provenance == "oracle:boolean_sqli"


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
