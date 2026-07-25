"""denylist — the always-refused ranges, including every IPv6 way to spell 169.254.169.254."""

from __future__ import annotations

import pytest

from vigil_gateway import denylist


# 169.254.169.254 == 0xA9FEA9FE. Each of these is a different encoding of the SAME
# cloud-metadata address; all must be denied or the SSRF-to-credentials path is open.
METADATA_FORMS = [
    "169.254.169.254",              # plain IPv4 link-local metadata
    "::ffff:169.254.169.254",       # IPv4-mapped IPv6
    "::ffff:a9fe:a9fe",             # IPv4-mapped IPv6, hex form
    "2002:a9fe:a9fe::",             # 6to4 embedding
    "64:ff9b::169.254.169.254",     # NAT64 well-known prefix
    "64:ff9b:1::169.254.169.254",   # NAT64 RFC 8215 local /48
    "::169.254.169.254",            # deprecated IPv4-compatible ::/96 (red-pen BLOCK-2)
]


@pytest.mark.parametrize(
    "ip",
    ["::127.0.0.1", "::10.0.0.5", "::192.168.1.1", "::255.255.255.255", "::0.0.0.0"],
)
def test_ipv4_compatible_forms_of_local_addresses_denied(ip):
    # ::a.b.c.d (::/96) unwraps to a.b.c.d and inherits its verdict — loopback/private/reserved.
    denied, _ = denylist.is_egress_denied(ip)
    assert denied


@pytest.mark.parametrize("ip", METADATA_FORMS)
def test_metadata_denied_in_every_encoding(ip):
    denied, reason = denylist.is_egress_denied(ip)
    assert denied, f"{ip} ({reason}) must be denied"


@pytest.mark.parametrize("ip", METADATA_FORMS)
def test_metadata_denied_even_if_allowlisted(ip):
    # Hard-deny outranks the charter allowlist: a listing is more likely injection than intent.
    denied, _ = denylist.is_egress_denied(ip, allowed_ips={ip, "169.254.169.254"})
    assert denied


@pytest.mark.parametrize(
    "ip",
    ["127.0.0.1", "127.1.2.3", "::1", "0.0.0.0", "224.0.0.1", "255.255.255.255",
     "fe80::1", "ff02::1", "fd00:ec2::254", "192.0.2.5", "198.51.100.9", "203.0.113.1",
     "198.18.0.1", "192.88.99.1"],
)
def test_reserved_and_local_denied(ip):
    denied, _ = denylist.is_egress_denied(ip)
    assert denied


@pytest.mark.parametrize("ip", ["10.0.0.5", "172.16.9.9", "192.168.1.1", "100.64.0.1", "fc00::1", "fd12::1"])
def test_private_denied_by_default(ip):
    denied, reason = denylist.is_egress_denied(ip)
    assert denied
    assert "private" in reason or "not globally routable" in reason


def test_private_allowed_only_when_exactly_authorized():
    # Operator scoped an internal staging host by IP → that exact IP is reachable.
    denied, _ = denylist.is_egress_denied("10.0.0.5", allowed_ips={"10.0.0.5"})
    assert not denied
    # A neighbour in the same /24 is NOT authorized by that listing.
    denied2, _ = denylist.is_egress_denied("10.0.0.6", allowed_ips={"10.0.0.5"})
    assert denied2


@pytest.mark.parametrize("ip", ["8.8.8.8", "1.1.1.1", "93.184.216.34", "2606:4700:4700::1111"])
def test_global_addresses_allowed(ip):
    denied, reason = denylist.is_egress_denied(ip)
    assert not denied, f"{ip} should be allowed, got {reason}"


def test_unparseable_fails_closed():
    denied, reason = denylist.is_egress_denied("not-an-ip")
    assert denied and "fail-closed" in reason
    denied2, _ = denylist.is_egress_denied("")
    assert denied2


def test_is_hard_denied_matches_tier1_only():
    assert denylist.is_hard_denied("169.254.169.254")
    assert denylist.is_hard_denied("::ffff:169.254.169.254")
    assert denylist.is_hard_denied("127.0.0.1")
    # private is NOT hard-denied (it is conditional on scope)
    assert not denylist.is_hard_denied("10.0.0.5")
    assert not denylist.is_hard_denied("8.8.8.8")
    # unparseable is treated as hard-denied (fail closed)
    assert denylist.is_hard_denied("garbage")


def test_cidr_helpers_nonempty_and_parseable():
    import ipaddress

    for c in denylist.hard_deny_cidrs():
        ipaddress.ip_network(c)
    for c in denylist.private_cidrs():
        ipaddress.ip_network(c)
    # the metadata /16 is in the hard-deny set
    assert any("169.254" in c for c in denylist.hard_deny_cidrs())


# --- WS-A: the loopback opt-in (executor-only; default-off) -----------------------------------------

def test_loopback_denied_by_default_liftable_only_when_scoped_and_opted_in():
    # DEFAULT (gateway/proxy/nftables path): loopback is hard-denied.
    assert denylist.is_egress_denied("127.0.0.1")[0] is True
    assert denylist.is_egress_denied("::1")[0] is True
    # opt-in AND the exact resolved IP in the signed allow-set → lifted (the offense executor engaging a
    # loopback target the owner's charter authorizes).
    assert denylist.is_egress_denied(
        "127.0.0.1", allowed_ips={"127.0.0.1"}, loopback_allowed_if_scoped=True)[0] is False
    assert denylist.is_egress_denied(
        "::1", allowed_ips={"::1"}, loopback_allowed_if_scoped=True)[0] is False
    # opt-in but NOT in the allow-set → still denied (the opt-in alone never opens loopback).
    assert denylist.is_egress_denied(
        "127.0.0.1", allowed_ips=set(), loopback_allowed_if_scoped=True)[0] is True


def test_metadata_floor_never_liftable_even_with_the_loopback_optin():
    # the absolute floor stays absolute even with the opt-in AND the IP allowlisted.
    for ip in ("169.254.169.254", "169.254.1.1", "fe80::1", "224.0.0.1"):
        denied, _ = denylist.is_egress_denied(
            ip, allowed_ips={ip}, loopback_allowed_if_scoped=True)
        assert denied is True, ip


def test_hard_deny_set_unchanged_by_the_split():
    # is_hard_denied / the nftables drop set still include loopback — the opt-in is executor-only.
    assert denylist.is_hard_denied("127.0.0.1") is True
    assert denylist.is_hard_denied("::1") is True
    assert "127.0.0.0/8" in denylist.hard_deny_cidrs()
