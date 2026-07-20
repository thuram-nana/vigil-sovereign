"""
Collectors — transport-injected, offline, deterministic. Each collector parses its
source's records into Observations and nothing else (no graph writes, no network).
Egress is OFF by default; missing data degrades to "found nothing", never a crash.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from framework.v2.intel.collectors import (
    AsnBgpCollector,
    CertTransparencyCollector,
    DEFAULT_COLLECTORS,
    DnsCollector,
    RdapCollector,
)
from framework.v2.intel.models import IntelSourceKind, Polarity
from framework.v2.intel.refs import canonicalize
from framework.v2.intel.transport import (
    CollectorEgressRefused,
    DisabledTransport,
    FixtureTransport,
    MappingTransport,
    RawRecord,
)
from framework.v2.worldmodel.models import EdgeKind, NodeKind

_FIX = Path(__file__).resolve().parents[1] / "collectors" / "fixtures"


def _fixture_transport() -> FixtureTransport:
    return FixtureTransport(_FIX)


def test_dns_collector_emits_resolves_and_cname() -> None:
    t = _fixture_transport()
    obs = DnsCollector().collect(canonicalize(NodeKind.DOMAIN, "backend.company.com"), t, seq=1)
    rels = {(o.relation, o.object.node_id if o.object else None) for o in obs}
    assert (EdgeKind.RESOLVES_TO, "host:10.15.4.2") in rels
    assert (EdgeKind.SAME_AS, "domain:api.company.com") in rels
    assert all(o.source_kind is IntelSourceKind.DNS for o in obs)


def test_cert_transparency_discovers_subdomains_and_certs() -> None:
    t = _fixture_transport()
    obs = CertTransparencyCollector().collect(canonicalize(NodeKind.DOMAIN, "company.com"), t, seq=1)
    # discovered subdomain node claims (relation None)
    discovered = {o.subject.node_id for o in obs if o.relation is None}
    assert {"domain:api.company.com", "domain:backend.company.com", "domain:www.company.com"} <= discovered
    # presents_cert edges to the shared cert xyz
    cert_edges = {(o.subject.node_id, o.object.node_id) for o in obs if o.relation is EdgeKind.PRESENTS_CERT}
    assert ("domain:api.company.com", "certificate:xyz") in cert_edges
    assert ("domain:backend.company.com", "certificate:xyz") in cert_edges


def test_cert_transparency_is_enumerative_flag() -> None:
    assert CertTransparencyCollector().enumerative is True
    assert DnsCollector().enumerative is False


def test_rdap_emits_owner_link_not_a_merge() -> None:
    t = _fixture_transport()
    obs = RdapCollector().collect(canonicalize(NodeKind.DOMAIN, "api.company.com"), t, seq=1)
    owns = [o for o in obs if o.relation is EdgeKind.ASSET_OWNS]
    assert owns and owns[0].subject.node_id == "organization:company inc"
    assert owns[0].object.node_id == "domain:api.company.com"


def test_asn_collector_emits_announces() -> None:
    t = _fixture_transport()
    obs = AsnBgpCollector().collect(canonicalize(NodeKind.HOST, "10.15.4.2"), t, seq=1)
    ann = [o for o in obs if o.relation is EdgeKind.ANNOUNCES]
    assert ann and ann[0].subject.node_id == "asn:AS64501"
    assert ann[0].object.node_id == "netblock:10.15.4.0/24"


def test_collector_ignores_wrong_subject_kind() -> None:
    # a DNS collector asked about an ASN yields nothing (accepts() gate)
    assert DnsCollector().collect(canonicalize(NodeKind.ASN, "AS1"), _fixture_transport(), seq=1) == []


def test_disabled_transport_refuses_live() -> None:
    with pytest.raises(CollectorEgressRefused):
        DnsCollector().collect(canonicalize(NodeKind.DOMAIN, "api.company.com"),
                               DisabledTransport(), seq=1)


def test_missing_fixture_degrades_to_empty() -> None:
    obs = DnsCollector().collect(canonicalize(NodeKind.DOMAIN, "nonexistent.example"),
                                 _fixture_transport(), seq=1)
    assert obs == []


def test_mapping_transport_roundtrips() -> None:
    rec = RawRecord(source_kind=IntelSourceKind.DNS, query="api.company.com",
                    payload={"A": ["203.0.113.7"]})
    t = MappingTransport({(IntelSourceKind.DNS, "api.company.com"): rec})
    obs = DnsCollector().collect(canonicalize(NodeKind.DOMAIN, "api.company.com"), t, seq=5)
    assert obs and obs[0].object.node_id == "host:203.0.113.7"
    assert obs[0].seq == 5


def test_obs_ids_are_deterministic() -> None:
    t = _fixture_transport()
    a = DnsCollector().collect(canonicalize(NodeKind.DOMAIN, "backend.company.com"), t, seq=1)
    b = DnsCollector().collect(canonicalize(NodeKind.DOMAIN, "backend.company.com"), t, seq=1)
    assert [o.obs_id for o in a] == [o.obs_id for o in b]


def test_default_roster_has_four_collectors() -> None:
    kinds = {c.source_kind for c in DEFAULT_COLLECTORS}
    assert kinds == {IntelSourceKind.DNS, IntelSourceKind.CERT_TRANSPARENCY,
                     IntelSourceKind.RDAP_WHOIS, IntelSourceKind.ASN_BGP}
