"""intel.frontier — the unified DISCOVERY FRONTIER (Phase-1 Slice 1).

Pins the canonical-location dedup (value-variants of one URL collapse to one testable surface), the
VOI ordering + size cap (a large graph cannot flood the goal tree), and determinism.
"""

from __future__ import annotations

from framework.v2.intel.frontier import (
    DiscoveryFrontier,
    FrontierItem,
    canonical_key,
    frontier_from_targets,
)
from framework.v2.worldmodel import Node, NodeKind, WorldModel


# ---------------------------------------------------------------------------
# the canonical location key
# ---------------------------------------------------------------------------


def test_value_variants_share_a_key_but_param_set_and_path_do_not():
    a = canonical_key("http://h/x?id=1", "xss")
    b = canonical_key("http://h/x?id=2", "xss")      # same location, different VALUE
    assert a == b
    assert canonical_key("http://h/x?id=1&z=2", "xss") != a   # different param SET
    assert canonical_key("http://h/y?id=1", "xss") != a        # different PATH
    assert canonical_key("http://h/x?id=1", "sqli") != a       # different bug_class


def test_scheme_host_lowercased_and_empty_path_is_root():
    assert canonical_key("HTTP://H.EXAMPLE.com", "xss")[0] == "http://h.example.com"
    assert canonical_key("http://h", "xss")[1] == "/"


# ---------------------------------------------------------------------------
# dedup + ordering + cap
# ---------------------------------------------------------------------------


def test_ingest_dedups_value_variants_to_one_item():
    fr = DiscoveryFrontier()
    assert fr.ingest("http://h/x?id=1", "n1") is True
    assert fr.ingest("http://h/x?id=2", "n2") is False    # canonical dup
    assert fr.ingest("http://h/y?id=1", "n3") is True
    urls = {it.url for it in fr.items()}
    assert urls == {"http://h/x?id=1", "http://h/y?id=1"}   # the FIRST value-variant wins


def test_ingest_rejects_non_http_and_empty():
    fr = DiscoveryFrontier()
    assert fr.ingest("ftp://h/x", "n") is False
    assert fr.ingest("", "n") is False
    assert fr.ingest("http://h/x", "") is False
    assert fr.items() == []


def test_items_are_deterministic_regardless_of_ingest_order():
    def build(order):
        fr = DiscoveryFrontier()
        for u in order:
            fr.ingest(u, u)
        return [it.url for it in fr.items()]
    urls = ["http://h/a", "http://h/b", "http://h/c", "http://h/d"]
    assert build(urls) == build(list(reversed(urls)))   # order-independent (VOI tie-broken by key)


def test_cap_keeps_max_items_and_reports_truncation():
    fr = DiscoveryFrontier(max_items=3)
    for i in range(10):
        fr.ingest(f"http://h/p{i:02d}", f"n{i}")
    items = fr.items()
    assert len(items) == 3
    assert fr.truncated == 7            # reported, not silent
    # deterministic which 3 survive (equal priors → key order → p00,p01,p02)
    assert [it.url for it in items] == ["http://h/p00", "http://h/p01", "http://h/p02"]


def test_higher_prior_orders_first():
    fr = DiscoveryFrontier(max_items=1)
    fr.ingest("http://h/low", "n1", prior=0.05)
    fr.ingest("http://h/high", "n2", prior=0.5)   # higher prior → higher EIG → kept by the cap
    assert [it.url for it in fr.items()] == ["http://h/high"]


# ---------------------------------------------------------------------------
# frontier_from_targets — origin tagging from world-model provenance
# ---------------------------------------------------------------------------


def test_from_targets_tags_origin_from_provenance():
    w = WorldModel()
    w.add_node(Node(id="endpoint:promoted:http://h/a", kind=NodeKind.ENDPOINT,
                    attrs={"url": "http://h/a"}, provenance="intel:promote:domain:h",
                    confidence=0.5, first_seen=1, last_seen=1))
    w.add_node(Node(id="ep_lead", kind=NodeKind.ENDPOINT, attrs={"url": "http://h/b"},
                    provenance="scan:web_scanner", confidence=0.5, first_seen=1, last_seen=1))
    fr = frontier_from_targets(
        [("endpoint:promoted:http://h/a", "http://h/a"), ("ep_lead", "http://h/b")], world=w)
    by_url = {it.url: it.origin for it in fr.items()}
    assert by_url == {"http://h/a": "promotion", "http://h/b": "sensor"}


def test_frontier_item_is_frozen_hashable():
    it = FrontierItem(url="http://h/a", node_id="n")
    assert hash(it) is not None      # usable in a set / dict key
    assert it.key == canonical_key("http://h/a", "xss")
