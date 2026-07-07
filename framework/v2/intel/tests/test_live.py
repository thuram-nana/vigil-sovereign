"""
Gated live recon — offline. Exercises the real-API → canonical-payload normalizers and
the guarded live transport with an INJECTED recording client returning real-shaped JSON.
No network is touched; the point is that live collection is real, gated, and that a
source's messy response maps correctly onto what the collectors already parse.
"""

from __future__ import annotations

import pytest

from framework.v2.intel.collectors import (
    AsnBgpCollector,
    CertTransparencyCollector,
    DnsCollector,
    RdapCollector,
)
from framework.v2.intel.live import (
    DEFAULT_COLLECTOR_HOSTS,
    LIVE_ENDPOINTS,
    build_live_transport,
    normalize_response,
)
from framework.v2.intel.models import IntelSourceKind
from framework.v2.intel.refs import canonicalize
from framework.v2.intel.transport import CollectorEgressRefused
from framework.v2.worldmodel.models import EdgeKind, NodeKind


class _CannedClient:
    """Returns a fixed JSON body for any URL, recording the calls (so we can prove the
    guard checks the host before any request)."""

    def __init__(self, payload, status=200):
        self.calls = []
        self._payload = payload
        self._status = status

    def get(self, url):
        self.calls.append(url)
        return _Resp(self._status, self._payload)


class _Resp:
    def __init__(self, status, payload):
        self.status_code = status
        self._p = payload
        self.text = ""

    def json(self):
        return self._p


# ---- normalizers: real API JSON → canonical payload -------------------------


def test_normalize_doh_dns() -> None:
    doh = {"Status": 0, "Answer": [
        {"name": "api.company.com.", "type": 1, "data": "10.15.4.2"},
        {"name": "api.company.com.", "type": 5, "data": "edge.company.com."},
        {"name": "api.company.com.", "type": 28, "data": "2001:db8::1"}]}
    out = normalize_response(IntelSourceKind.DNS, doh)
    assert out == {"A": ["10.15.4.2"], "AAAA": ["2001:db8::1"], "CNAME": ["edge.company.com"]}


def test_normalize_crtsh_collapses_shared_cert() -> None:
    crtsh = [
        {"name_value": "api.company.com\nbackend.company.com", "common_name": "api.company.com",
         "serial_number": "0A0B", "issuer_ca_id": 42, "not_after": "2026-06-01"}]
    out = normalize_response(IntelSourceKind.CERT_TRANSPARENCY, crtsh)
    assert isinstance(out, list) and len(out) == 1
    assert set(out[0]["names"]) == {"api.company.com", "backend.company.com"}
    assert out[0]["fingerprint"]                       # a stable synthesized cert key


def test_normalize_rdap_domain_org() -> None:
    rdap = {"handle": "COMPANY-1", "entities": [
        {"roles": ["registrant"], "vcardArray": ["vcard", [
            ["version", {}, "text", "4.0"], ["fn", {}, "text", "Company Inc"]]]}]}
    out = normalize_response(IntelSourceKind.RDAP_WHOIS, rdap)
    assert out["org"] == "Company Inc" and out["handle"] == "COMPANY-1"


def test_normalize_ripestat_asn() -> None:
    ripe = {"data": {"asns": ["64501"], "prefix": "10.15.4.0/24"}}
    out = normalize_response(IntelSourceKind.ASN_BGP, ripe)
    assert out == {"asn": "AS64501", "netblock": "10.15.4.0/24"}


@pytest.mark.parametrize("sk", list(IntelSourceKind))
def test_normalizers_are_total(sk) -> None:
    # garbage never raises — degrades to an empty canonical payload
    for junk in (None, 123, "x", {"weird": True}, [1, 2, 3]):
        out = normalize_response(sk, junk)
        assert isinstance(out, (dict, list))


# ---- end-to-end through the guarded live transport --------------------------


def test_live_transport_ct_collector_end_to_end() -> None:
    crtsh = [{"name_value": "api.company.com\nbackend.company.com",
              "serial_number": "1", "issuer_ca_id": 7}]
    client = _CannedClient(crtsh)
    transport = build_live_transport(target_hosts=("company.com",), client=client)
    obs = CertTransparencyCollector().collect(
        canonicalize(NodeKind.DOMAIN, "company.com"), transport, seq=1)
    presenters = {o.subject.node_id for o in obs if o.relation is EdgeKind.PRESENTS_CERT}
    certs = {o.object.node_id for o in obs if o.relation is EdgeKind.PRESENTS_CERT}
    assert {"domain:api.company.com", "domain:backend.company.com"} <= presenters
    assert len(certs) == 1                                 # both on ONE synthesized cert
    assert client.calls and "crt.sh" in client.calls[0]   # hit the real endpoint host


def test_live_transport_dns_collector_end_to_end() -> None:
    doh = {"Answer": [{"name": "api.company.com.", "type": 1, "data": "203.0.113.9"}]}
    transport = build_live_transport(target_hosts=("company.com",), client=_CannedClient(doh))
    obs = DnsCollector().collect(canonicalize(NodeKind.DOMAIN, "api.company.com"), transport, seq=1)
    assert any(o.object and o.object.node_id == "host:203.0.113.9" for o in obs)


# ---- gating: disjoint from target, off-allowlist refused --------------------


def test_live_transport_refuses_target_overlap() -> None:
    # a source host that is also the target must refuse construction
    with pytest.raises(CollectorEgressRefused):
        build_live_transport(collector_hosts=("crt.sh",), target_hosts=("crt.sh",))


def test_live_transport_default_hosts_match_endpoints() -> None:
    # every configured endpoint host is on the default allowlist (else it would refuse)
    from urllib.parse import urlsplit
    for sk, tmpl in LIVE_ENDPOINTS.items():
        host = urlsplit(tmpl.format(query="x")).hostname
        assert host in DEFAULT_COLLECTOR_HOSTS, f"{sk} endpoint host {host} not allowlisted"


def test_live_transport_refuses_off_allowlist_endpoint() -> None:
    from framework.v2.intel.transport import GuardedHttpTransport
    client = _CannedClient({})
    t = GuardedHttpTransport(collector_hosts=("crt.sh",),
                             endpoints={IntelSourceKind.DNS: "https://dns.google/resolve?name={query}"},
                             client=client)
    with pytest.raises(CollectorEgressRefused):
        t.fetch(IntelSourceKind.DNS, "x.com", seq=1)   # dns.google not in ('crt.sh',)
    assert client.calls == []                          # nothing left the process
