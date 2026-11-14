"""Slice G0 / SS-1 — the SSRF-hardened ownership fetcher (well-known HTTP file AND DNS-TXT over DoH).

The host is CUSTOMER-NAMED, so the whole risk is SSRF. Load-bearing invariants:
  * any resolved NON-GLOBAL address (loopback, link-local incl. 169.254.169.254, RFC1918, CGNAT, ULA,
    multicast, reserved, unspecified) REFUSES the fetch — and if ANY of several resolved addresses is
    internal, the whole fetch refuses (split-horizon defence) — with NO connection attempted;
  * an unparseable/odd address is treated as internal (fail-closed);
  * the host floor (no IP literal / URL / path / port / categorical domain) is re-applied before any network
    for BOTH methods;
  * dns-txt connects to the PINNED public DoH resolver (which itself passes the SSRF gate), NOT the customer
    host, and parses the TXT answers fail-closed; an unsupported method is refused.
The real TLS GET against live loopback servers is exercised in ``test_ownership_fetch_loopback.py``; the
security-critical gates + the DoH dispatch/parse are here.
"""
from __future__ import annotations

import json
import socket

import pytest

from sigil.governor.asset_ownership import METHOD_DNS_TXT, METHOD_META_TAG, METHOD_WELL_KNOWN
from sigil.ui.ownership_fetch import (
    OwnershipFetchError,
    WellKnownFetcher,
    _addr_is_internal,
    _parse_doh_txt,
    _resolve_public_ip,
)


def _res(*ips):
    """A stub getaddrinfo returning the given IPs (addr family inferred by ':' in the string)."""
    def resolver(host, port, **kw):
        out = []
        for ip in ips:
            fam = socket.AF_INET6 if ":" in ip else socket.AF_INET
            out.append((fam, socket.SOCK_STREAM, 6, "", (ip, port)))
        return out
    return resolver


@pytest.mark.parametrize("ip,internal", [
    ("8.8.8.8", False), ("1.1.1.1", False),
    ("127.0.0.1", True), ("169.254.169.254", True), ("10.0.0.5", True), ("192.168.1.1", True),
    ("172.16.9.9", True), ("100.64.0.1", True), ("0.0.0.0", True), ("224.0.0.1", True),
    ("::1", True), ("fc00::1", True), ("fd12::1", True), ("fe80::1", True),
    ("not-an-ip", True), ("", True),
])
def test_addr_is_internal(ip, internal):
    assert _addr_is_internal(ip) is internal


def test_resolve_refuses_internal():
    with pytest.raises(OwnershipFetchError):
        _resolve_public_ip("apme.cm", resolver=_res("10.0.0.5"))


def test_resolve_refuses_split_horizon_any_internal():
    """A name resolving to BOTH a public and an internal address is refused (never fetched)."""
    with pytest.raises(OwnershipFetchError):
        _resolve_public_ip("apme.cm", resolver=_res("1.1.1.1", "169.254.169.254"))


def test_resolve_returns_public():
    assert _resolve_public_ip("apme.cm", resolver=_res("1.1.1.1")) == "1.1.1.1"


@pytest.mark.parametrize("timeout", [None, 1.0])         # direct, and through the budget-bounded worker
def test_resolve_failure_is_refusal(timeout):
    """Fail-closed with the fetcher's own wording for the customer; the resolver's error for the operator."""
    def boom(host, port, **kw):
        raise socket.gaierror("nope")
    with pytest.raises(OwnershipFetchError) as ei:
        _resolve_public_ip("apme.cm", resolver=boom, timeout=timeout)
    assert str(ei.value) == "could not resolve 'apme.cm'"
    assert ei.value.detail == "gaierror: nope"


def test_fetch_refuses_unsupported_method():
    f = WellKnownFetcher(resolver=_res("1.1.1.1"))
    with pytest.raises(OwnershipFetchError):
        f.fetch("html-meta", "apme.cm")      # not yet a method (SS-2) — refused, not silently wrong


@pytest.mark.parametrize("method", [METHOD_WELL_KNOWN, METHOD_DNS_TXT, METHOD_META_TAG])
def test_fetch_refuses_internal_host_before_connecting(method):
    """An internal-resolving host raises at the SSRF gate — the socket connect is never reached. For dns-txt
    the gate falls on the DoH resolver (which the stub resolves internal here)."""
    f = WellKnownFetcher(resolver=_res("127.0.0.1"))
    with pytest.raises(OwnershipFetchError):
        f.fetch(method, "apme.cm")


@pytest.mark.parametrize("method", [METHOD_WELL_KNOWN, METHOD_DNS_TXT, METHOD_META_TAG])
@pytest.mark.parametrize("bad", ["whitehouse.gov", "https://apme.cm", "apme.cm/x", "apme.cm:443", "203.0.113.9"])
def test_fetch_reapplies_host_floor(method, bad):
    f = WellKnownFetcher(resolver=_res("1.1.1.1"))
    with pytest.raises(OwnershipFetchError):
        f.fetch(method, bad)


# --- DNS-TXT over DoH -------------------------------------------------------------------------------

def test_parse_doh_txt_strips_quotes_filters_types_and_bounds():
    body = json.dumps({"Status": 0, "Answer": [
        {"name": "_vigil-challenge.apme.cm", "type": 16, "data": "\"vigil-site-verification=TOK\""},
        {"name": "apme.cm", "type": 1, "data": "1.2.3.4"},                      # A record — filtered out
        {"name": "_vigil-challenge.apme.cm", "type": 16, "data": "unquoted-ok"},  # tolerate no quotes
    ]}).encode()
    assert _parse_doh_txt(body) == ["vigil-site-verification=TOK", "unquoted-ok"]
    # malformed / non-dict / no-answer → [] (fail-closed, never raises)
    assert _parse_doh_txt(b"}{ not json") == []
    assert _parse_doh_txt(b"[]") == []
    assert _parse_doh_txt(json.dumps({"Status": 2}).encode()) == []
    # bounded
    many = {"Answer": [{"type": 16, "data": f'"v{i}"'} for i in range(100)]}
    assert len(_parse_doh_txt(json.dumps(many).encode())) <= 32


class _FakeResp:
    def __init__(self, status, body):
        self.status, self._b = status, body

    def read(self, n):
        return self._b[:n]


class _FakeConn:
    def __init__(self, status, body):
        self._resp = _FakeResp(status, body)
        self.sock = type("S", (), {"settimeout": lambda self, t: None})()
        self.requested = []

    def request(self, method, path, headers=None):
        self.requested.append((method, path, headers))

    def getresponse(self):
        return self._resp

    def close(self):
        pass


def _pair(conn):
    """``_open_pinned_https`` returns ``(conn, tls)`` — the TLS socket the request goes out on."""
    return conn, conn.sock


def test_dns_txt_queries_the_doh_resolver_and_returns_values(monkeypatch):
    f = WellKnownFetcher(resolver=_res("1.1.1.1"))
    body = json.dumps({"Answer": [{"type": 16, "data": "\"vigil-site-verification=TOK\""}]}).encode()
    fake = _FakeConn(200, body)
    monkeypatch.setattr(f, "_open_pinned_https", lambda host, start: (fake, fake.sock))
    out = f.fetch(METHOD_DNS_TXT, "apme.cm")
    assert out == ["vigil-site-verification=TOK"]
    # it queried TXT at the EXACT challenge name for the proven host (no wildcard/parent)
    assert fake.requested[0][0] == "GET"
    assert fake.requested[0][1].startswith("/dns-query?name=_vigil-challenge.apme.cm&type=TXT")


def test_dns_txt_non_200_resolver_is_failclosed(monkeypatch):
    f = WellKnownFetcher(resolver=_res("1.1.1.1"))
    monkeypatch.setattr(f, "_open_pinned_https", lambda host, start: _pair(_FakeConn(302, b"")))  # a redirect -> refused
    with pytest.raises(OwnershipFetchError):
        f.fetch(METHOD_DNS_TXT, "apme.cm")


# --- HTML meta-tag ----------------------------------------------------------------------------------

def test_meta_tag_fetches_homepage_html(monkeypatch):
    f = WellKnownFetcher(resolver=_res("1.1.1.1"))
    html = b"<html><head><meta name='vigil-site-verification' content='TOK'></head></html>"
    fake = _FakeConn(200, html)
    monkeypatch.setattr(f, "_open_pinned_https", lambda host, start: (fake, fake.sock))
    out = f.fetch(METHOD_META_TAG, "apme.cm")
    assert isinstance(out, str) and "vigil-site-verification" in out
    assert fake.requested[0] == ("GET", "/", fake.requested[0][2])     # GETs the homepage root


def test_meta_tag_non_200_is_failclosed(monkeypatch):
    f = WellKnownFetcher(resolver=_res("1.1.1.1"))
    monkeypatch.setattr(f, "_open_pinned_https", lambda host, start: _pair(_FakeConn(301, b"")))  # root redirect -> refused
    with pytest.raises(OwnershipFetchError):
        f.fetch(METHOD_META_TAG, "apme.cm")


def test_total_deadline_caps_per_op_and_fails_closed_when_spent():
    """The absolute wall-clock budget caps each per-op socket timeout, and refuses once spent (anti slow-drip)."""
    clock = [0.0]
    f = WellKnownFetcher(timeout=5.0, total_timeout=8.0, monotonic=lambda: clock[0])
    assert f._op_timeout(0.0) == 5.0        # at start: full per-op budget (min(5, 8))
    clock[0] = 6.0
    assert f._op_timeout(0.0) == 2.0        # 6s of an 8s budget elapsed → 2s remaining caps the per-op 5s
    clock[0] = 9.0
    with pytest.raises(OwnershipFetchError):
        f._op_timeout(0.0)                  # budget exhausted → fail-closed, no further I/O
