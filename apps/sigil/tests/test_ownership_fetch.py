"""Slice G0 — the SSRF-hardened well-known ownership fetcher.

The host is CUSTOMER-NAMED, so the whole risk is SSRF. Load-bearing invariants:
  * any resolved NON-GLOBAL address (loopback, link-local incl. 169.254.169.254, RFC1918, CGNAT, ULA,
    multicast, reserved, unspecified) REFUSES the fetch — and if ANY of several resolved addresses is
    internal, the whole fetch refuses (split-horizon defence) — with NO connection attempted;
  * an unparseable/odd address is treated as internal (fail-closed);
  * only the well-known method is served (dns-txt fetch is not available, honestly refused);
  * the host floor (no IP literal / URL / path / port / categorical domain) is re-applied before any network.
The real TLS GET is not exercised here (it needs a live server); the security-critical gates are.
"""
from __future__ import annotations

import socket

import pytest

from sigil.governor.asset_ownership import METHOD_DNS_TXT, METHOD_WELL_KNOWN
from sigil.ui.ownership_fetch import OwnershipFetchError, WellKnownFetcher, _addr_is_internal, _resolve_public_ip


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


def test_resolve_failure_is_refusal():
    def boom(host, port, **kw):
        raise socket.gaierror("nope")
    with pytest.raises(OwnershipFetchError):
        _resolve_public_ip("apme.cm", resolver=boom)


def test_fetch_refuses_dns_txt_method():
    f = WellKnownFetcher(resolver=_res("1.1.1.1"))
    with pytest.raises(OwnershipFetchError):
        f.fetch(METHOD_DNS_TXT, "apme.cm")


def test_fetch_refuses_internal_host_before_connecting():
    """An internal-resolving host raises at the SSRF gate — the socket connect is never reached."""
    f = WellKnownFetcher(resolver=_res("127.0.0.1"))
    with pytest.raises(OwnershipFetchError):
        f.fetch(METHOD_WELL_KNOWN, "apme.cm")


@pytest.mark.parametrize("bad", ["whitehouse.gov", "https://apme.cm", "apme.cm/x", "apme.cm:443", "203.0.113.9"])
def test_fetch_reapplies_host_floor(bad):
    f = WellKnownFetcher(resolver=_res("1.1.1.1"))
    with pytest.raises(OwnershipFetchError):
        f.fetch(METHOD_WELL_KNOWN, bad)


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
