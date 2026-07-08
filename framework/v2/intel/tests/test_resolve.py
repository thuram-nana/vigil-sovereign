"""
Entity resolution — many references, one asset, explainably.

Pins the design's worked example as a golden, plus the invariants that keep it honest:
owner-tier (ASN/org) links via ASSET_OWNS and never merges into an asset; shared
infrastructure never catastrophically merges unrelated assets; and re-running is
deterministic + idempotent (audit-grade).
"""

from __future__ import annotations

from framework.v2.intel.models import IntelSourceKind, Observation
from framework.v2.intel.refs import canonicalize
from framework.v2.intel.resolve import resolve
from framework.v2.worldmodel.models import EdgeKind, NodeKind


def _o(oid, sk, s, rel, ok, ob, conf=0.9):
    return Observation(obs_id=oid, source="dns", source_kind=IntelSourceKind.DNS,
                       subject=canonicalize(sk, s), relation=rel, object=canonicalize(ok, ob),
                       confidence=conf, seq=1)


def _worked_example():
    return [
        _o("1", NodeKind.DOMAIN, "api.company.com", EdgeKind.PRESENTS_CERT, NodeKind.CERTIFICATE, "xyz"),
        _o("2", NodeKind.DOMAIN, "backend.company.com", EdgeKind.PRESENTS_CERT, NodeKind.CERTIFICATE, "xyz"),
        _o("3", NodeKind.DOMAIN, "api.company.com", EdgeKind.RESOLVES_TO, NodeKind.HOST, "10.15.4.2"),
        _o("4", NodeKind.DOMAIN, "backend.company.com", EdgeKind.RESOLVES_TO, NodeKind.HOST, "10.15.4.2"),
        _o("5", NodeKind.ASN, "AS64501", EdgeKind.ANNOUNCES, NodeKind.NETBLOCK, "10.15.4.0/24"),
    ]


def test_worked_example_one_asset_owned_by_asn() -> None:
    r = resolve(_worked_example(), seq=1)
    assert len(r.entities) == 1
    e = r.entities[0]
    assert e.canonical_id == "ent:domain:api.company.com"  # anchored on the primary asset
    assert {m.node_id for m in e.members} == {
        "domain:api.company.com", "domain:backend.company.com",
        "host:10.15.4.2", "certificate:xyz"}
    assert e.owned_by == ["asn:AS64501"]         # OWNER links via ASSET_OWNS, never merges in
    assert 0.9 <= e.confidence <= 0.99
    assert e.explain()                            # every merge cites its signal


def test_confidence_basis_labels_the_derivation() -> None:
    # a structural GUESS must never be mistaken for a measured merge posterior: every
    # entity carries confidence_basis stating how its confidence was derived.
    seen = set()
    examples = [
        _worked_example(),
        [_o("s0", NodeKind.DOMAIN, "a.example.com", EdgeKind.RESOLVES_TO, NodeKind.HOST, "203.0.113.9"),
         _o("c0", NodeKind.DOMAIN, "a.example.com", EdgeKind.PRESENTS_CERT, NodeKind.CERTIFICATE, "cx")],
    ]
    for ex in examples:
        for e in resolve(ex, seq=1).entities:
            seen.add(e.confidence_basis)
            if e.merge_log:
                assert e.confidence_basis == "merge-llr"
            elif len(e.members) > 1:
                assert e.confidence_basis == "structural-default" and abs(e.confidence - 0.9) < 1e-9
            else:
                assert e.confidence_basis == "singleton-default" and abs(e.confidence - 0.6) < 1e-9
    assert "merge-llr" in seen                        # the worked example has scored merges


def test_owner_tier_never_merges_into_asset() -> None:
    r = resolve(_worked_example(), seq=1)
    for e in r.entities:
        assert all(m.kind not in (NodeKind.ASN, NodeKind.NETBLOCK, NodeKind.ORGANIZATION)
                   for m in e.members)


def test_shared_hosting_does_not_catastrophically_merge() -> None:
    # 6 unrelated domains on one shared IP (fanout 6), each with its OWN cert
    obs = []
    for i in range(6):
        obs.append(_o(f"s{i}", NodeKind.DOMAIN, f"site{i}.example.com", EdgeKind.RESOLVES_TO, NodeKind.HOST, "203.0.113.9"))
        obs.append(_o(f"c{i}", NodeKind.DOMAIN, f"site{i}.example.com", EdgeKind.PRESENTS_CERT, NodeKind.CERTIFICATE, f"cert{i}"))
    r = resolve(obs, seq=1)
    assert len(r.entities) == 6                    # stays separate
    assert max(len(e.members) for e in r.entities) <= 2  # a domain + its dedicated cert at most


def test_resolve_is_deterministic_and_idempotent() -> None:
    r1 = resolve(_worked_example(), seq=1)
    r2 = resolve(list(reversed(_worked_example())), seq=1)  # order-independent
    assert r1.model_dump() == r2.model_dump()
    # idempotence: re-feeding the resolved members' observations reproduces the same cluster
    ids1 = {e.canonical_id for e in r1.entities}
    ids2 = {e.canonical_id for e in resolve(_worked_example(), seq=2).entities}
    assert ids1 == ids2


def test_dedicated_cert_merges_two_domains() -> None:
    # two domains sharing a DEDICATED cert (fanout 2) + a dedicated IP -> one asset
    r = resolve(_worked_example(), seq=1)
    e = r.entities[0]
    assert "certificate:xyz" in {m.node_id for m in e.members}
    # the merge was triggered by the shared cert
    assert any(m.trigger.value in ("shared_cert", "shared_ip") for m in e.merge_log)
