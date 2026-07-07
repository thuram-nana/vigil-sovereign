"""
intel.infer — sound derivation over the asset graph.

Pins the two guarantees that make derivation trustworthy: it produces facts true by
composition (transitive ownership, co-hosting, shared-registrant attribution) with
weakest-link belief and fanout discounting; and it STRUCTURALLY CANNOT emit an
attacker-state edge (OWNS/REACHED), so it can never hallucinate reachability.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from framework.v2.intel.collectors import DEFAULT_COLLECTORS
from framework.v2.intel.infer import (
    _mk,
    derive,
    derive_and_project,
    derive_co_hosting,
    derive_registrant_ownership,
    derive_transitive_ownership,
)
from framework.v2.intel.ingest import IntelIngest
from framework.v2.intel.models import (
    Credibility,
    IntelSourceKind,
    Observation,
    Reliability,
    SourceReliability,
)
from framework.v2.intel.project import project_observation
from framework.v2.intel.refs import EntityRef, canonicalize
from framework.v2.intel.transport import FixtureTransport
from framework.v2.worldmodel.graph import WorldModel
from framework.v2.worldmodel.models import EdgeKind, NodeKind

_FIX = Path(__file__).resolve().parents[1] / "collectors" / "fixtures"


def _worked_world() -> WorldModel:
    world = WorldModel()
    IntelIngest(world).run_collectors(
        [canonicalize(NodeKind.DOMAIN, "company.com")], list(DEFAULT_COLLECTORS),
        FixtureTransport(_FIX), max_depth=2)
    return world


# ---- transitive ownership ---------------------------------------------------


def test_transitive_ownership_attributes_domain_to_asn() -> None:
    world = _worked_world()
    derived = derive_transitive_ownership(world, seq=100)
    owns = {(o.subject.node_id, o.object.node_id) for o in derived}
    assert ("asn:AS64501", "domain:api.company.com") in owns
    assert ("asn:AS64501", "domain:backend.company.com") in owns
    assert all(o.relation is EdgeKind.ASSET_OWNS for o in derived)
    assert all(o.source_kind is IntelSourceKind.INFERENCE for o in derived)


def test_transitive_ownership_belief_is_weakest_link_discounted() -> None:
    world = _worked_world()
    derived = derive_transitive_ownership(world, seq=100)
    # derived belief is a discount of the premise beliefs — never a fabricated certainty
    assert derived and all(0.0 < o.confidence < 0.9 for o in derived)


def _announce(world, asn, netblock, seq):
    project_observation(world, Observation(
        obs_id=f"ann:{asn}:{seq}", source="asn_bgp", source_kind=IntelSourceKind.ASN_BGP,
        subject=EntityRef(kind=NodeKind.ASN, key=asn), relation=EdgeKind.ANNOUNCES,
        object=EntityRef(kind=NodeKind.NETBLOCK, key=netblock), confidence=0.9, seq=seq))


def _resolves(world, domain, host, seq):
    project_observation(world, Observation(
        obs_id=f"res:{domain}:{seq}", source="dns", source_kind=IntelSourceKind.DNS,
        subject=canonicalize(NodeKind.DOMAIN, domain), relation=EdgeKind.RESOLVES_TO,
        object=canonicalize(NodeKind.HOST, host), confidence=0.9, seq=seq))


def test_transitive_ownership_not_derived_across_transit_aggregate() -> None:
    # a transit AS announcing a huge aggregate must NOT be attributed ownership of a
    # domain that merely resolves somewhere inside it (soundness — the shared/transit rule)
    world = WorldModel()
    _announce(world, "AS3356", "4.0.0.0/9", 1)
    _resolves(world, "victim-unrelated.com", "4.2.2.2", 2)
    derived = derive_transitive_ownership(world, seq=100)
    assert not any(o.object.node_id == "domain:victim-unrelated.com" for o in derived)


def test_transitive_ownership_busy_host_attributes_faintly() -> None:
    # 8 tenant domains on one dedicated-looking host inside an owner /24 → each ownership
    # attribution is faint (shared host → the owner owns the block, not the tenants)
    world = WorldModel()
    _announce(world, "AS64500", "198.51.100.0/24", 1)
    for i in range(8):
        _resolves(world, f"tenant{i}.example.com", "198.51.100.7", i + 2)
    derived = derive_transitive_ownership(world, seq=100)
    assert derived and all(o.confidence < 0.25 for o in derived)   # faint by fanout discount


# ---- co-hosting -------------------------------------------------------------


def test_co_hosting_links_domains_on_shared_host() -> None:
    world = _worked_world()
    derived = derive_co_hosting(world, seq=100)
    pairs = {(o.subject.node_id, o.object.node_id) for o in derived}
    assert ("domain:api.company.com", "domain:backend.company.com") in pairs
    assert all(o.relation is EdgeKind.CO_HOSTED_WITH for o in derived)


def test_co_hosting_is_fanout_discounted() -> None:
    # 6 domains on one shared IP → each pair only faintly linked (busy host)
    world = WorldModel()
    for i in range(6):
        o = Observation(
            obs_id=f"r{i}", source="dns", source_kind=IntelSourceKind.DNS,
            subject=canonicalize(NodeKind.DOMAIN, f"s{i}.example.com"),
            relation=EdgeKind.RESOLVES_TO, object=canonicalize(NodeKind.HOST, "203.0.113.9"),
            confidence=0.9, seq=i + 1)
        project_observation(world, o)
    derived = derive_co_hosting(world, seq=100)
    assert derived and all(o.confidence < 0.3 for o in derived)   # faint by design


# ---- registrant ownership (owner attribution, NOT asset merge) --------------


def _dom_with_email(name: str, email: str, seq: int) -> Observation:
    return Observation(
        obs_id=f"rdap:{name}:{seq}", source="rdap", source_kind=IntelSourceKind.RDAP_WHOIS,
        subject=canonicalize(NodeKind.DOMAIN, name),
        source_reliability=SourceReliability(reliability=Reliability.A, credibility=Credibility.C1),
        confidence=0.85, seq=seq, attrs={"registrant_email": email})


def test_registrant_ownership_attributes_shared_registrant() -> None:
    world = WorldModel()
    project_observation(world, _dom_with_email("a.company.com", "admin@company.com", 1))
    project_observation(world, _dom_with_email("b.company.net", "admin@company.com", 2))
    derived = derive_registrant_ownership(world, seq=100)
    owners = {(o.subject.node_id, o.object.node_id) for o in derived}
    assert ("identity:admin@company.com", "domain:a.company.com") in owners
    assert ("identity:admin@company.com", "domain:b.company.net") in owners
    # attribution only — the two domains are NEVER merged into one asset here
    assert all(o.relation is EdgeKind.ASSET_OWNS for o in derived)


def test_registrant_privacy_proxy_attributes_almost_nothing() -> None:
    world = WorldModel()
    for i in range(16):  # a proxy email on many domains → huge fanout
        project_observation(world, _dom_with_email(f"d{i}.example.com", "proxy@whoisguard.com", i + 1))
    derived = derive_registrant_ownership(world, seq=100)
    assert derived and all(o.confidence < 0.2 for o in derived)   # anti-catastrophe


def test_single_registrant_domain_derives_nothing() -> None:
    world = WorldModel()
    project_observation(world, _dom_with_email("only.example.com", "me@example.com", 1))
    assert derive_registrant_ownership(world, seq=100) == []


# ---- the load-bearing safety property ---------------------------------------


def test_infer_refuses_to_emit_attacker_state_edges() -> None:
    a = canonicalize(NodeKind.DOMAIN, "a.com")
    b = canonicalize(NodeKind.DOMAIN, "b.com")
    # ASSET_OWNS / CO_HOSTED_WITH are allowed
    assert _mk(a, EdgeKind.ASSET_OWNS, b, confidence=0.5, rule="t", seq=1)
    # OWNS (attacker state) and any other kind are structurally refused
    for forbidden in (EdgeKind.OWNS, EdgeKind.REACHED, EdgeKind.RESOLVES_TO):
        with pytest.raises(ValueError, match="attacker-state|only derive"):
            _mk(a, forbidden, b, confidence=0.5, rule="t", seq=1)


def test_derive_only_produces_asset_tier_edges() -> None:
    world = _worked_world()
    for o in derive(world, seq=100):
        assert o.relation in (EdgeKind.ASSET_OWNS, EdgeKind.CO_HOSTED_WITH)


def _cohost_beliefs(world) -> dict:
    return {(e.src, e.dst, e.kind.value): e.belief_mean
            for e in world.all_edges() if e.kind is EdgeKind.CO_HOSTED_WITH}


def test_derive_and_project_is_idempotent_across_seqs() -> None:
    world = _worked_world()
    n1 = derive_and_project(world, seq=1000)
    b1 = _cohost_beliefs(world)
    # re-run with a DIFFERENT seq (the production caller advances the high-water mark) —
    # belief must not runaway: an already-present edge adds no independent evidence.
    n2 = derive_and_project(world, seq=9999)
    b2 = _cohost_beliefs(world)
    assert n1 > 0 and n2 == 0 and b1 == b2


def test_derivation_never_recorroborates_a_direct_edge() -> None:
    # a strong DIRECT ownership edge that the transitive rule would also derive must be
    # left untouched (a weaker derived fact must not bump the stronger observed belief)
    world = WorldModel()
    project_observation(world, Observation(
        obs_id="rdap-own", source="rdap", source_kind=IntelSourceKind.RDAP_WHOIS,
        subject=EntityRef(kind=NodeKind.ORGANIZATION, key="acme"), relation=EdgeKind.ASSET_OWNS,
        object=canonicalize(NodeKind.DOMAIN, "example.com"), confidence=0.95, seq=1))
    project_observation(world, Observation(
        obs_id="rdap-nb", source="rdap", source_kind=IntelSourceKind.RDAP_WHOIS,
        subject=EntityRef(kind=NodeKind.ORGANIZATION, key="acme"), relation=EdgeKind.ASSET_OWNS,
        object=EntityRef(kind=NodeKind.NETBLOCK, key="192.0.2.0/24"), confidence=0.9, seq=2))
    _resolves(world, "example.com", "192.0.2.5", 3)
    before = world.get_edge("organization:acme", "domain:example.com", EdgeKind.ASSET_OWNS).belief_mean
    derive_and_project(world, seq=100)
    after = world.get_edge("organization:acme", "domain:example.com", EdgeKind.ASSET_OWNS).belief_mean
    assert after == before   # the direct edge already existed → derivation skipped it
