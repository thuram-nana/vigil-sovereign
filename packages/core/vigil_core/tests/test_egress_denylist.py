"""egress_denylist — the shared always-refused egress ranges, now living in vigil_core.

This mirrors gateway/tests/test_denylist.py against the module in its new home. The classification
logic has a SINGLE source (``vigil_core.egress_denylist``); ``vigil_gateway.denylist`` re-exports it.
Because the primitive moved here, its tests run in the ``vigil_core`` CI leg too — covering the module
where it is measured, and asserting the never-liftable Tier-1a floor is byte-for-byte the same behaviour
that was proven in the gateway.
"""

from __future__ import annotations

import ipaddress

import pytest

from vigil_core import egress_denylist as denylist


# 169.254.169.254 == 0xA9FEA9FE. Each of these is a different encoding of the SAME
# cloud-metadata address; all must be denied or the SSRF-to-credentials path is open.
METADATA_FORMS = [
    "169.254.169.254",              # plain IPv4 link-local metadata
    "::ffff:169.254.169.254",       # IPv4-mapped IPv6
    "::ffff:a9fe:a9fe",             # IPv4-mapped IPv6, hex form
    "2002:a9fe:a9fe::",             # 6to4 embedding
    "64:ff9b::169.254.169.254",     # NAT64 well-known prefix
    "64:ff9b:1::169.254.169.254",   # NAT64 RFC 8215 local /48
    "::169.254.169.254",            # deprecated IPv4-compatible ::/96
]


@pytest.mark.parametrize(
    "ip",
    ["::127.0.0.1", "::10.0.0.5", "::192.168.1.1", "::255.255.255.255", "::0.0.0.0"],
)
def test_ipv4_compatible_forms_of_local_addresses_denied(ip):
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
    denied, _ = denylist.is_egress_denied("10.0.0.5", allowed_ips={"10.0.0.5"})
    assert not denied
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
    assert not denylist.is_hard_denied("10.0.0.5")
    assert not denylist.is_hard_denied("8.8.8.8")
    assert denylist.is_hard_denied("garbage")


def test_cidr_helpers_nonempty_and_parseable():
    for c in denylist.hard_deny_cidrs():
        ipaddress.ip_network(c)
    for c in denylist.private_cidrs():
        ipaddress.ip_network(c)
    for c in denylist.host_backstop_cidrs():
        ipaddress.ip_network(c)
    assert any("169.254" in c for c in denylist.hard_deny_cidrs())
    # the host-backstop is the narrow instance-metadata + container-credential set
    assert "169.254.169.254/32" in denylist.host_backstop_cidrs()
    assert "169.254.170.2/32" in denylist.host_backstop_cidrs()


def test_coerce_allowed_canonicalises_and_drops_unparseable():
    out = denylist._coerce_allowed(["10.0.0.1", " [::1] ", "not-an-ip", ""])
    assert "10.0.0.1" in out
    assert "::1" in out
    assert "not-an-ip" not in out
    assert denylist._coerce_allowed(None) == frozenset()


# --- the loopback opt-in (executor-only; default-off) -----------------------------------------------

def test_loopback_denied_by_default_liftable_only_when_scoped_and_opted_in():
    assert denylist.is_egress_denied("127.0.0.1")[0] is True
    assert denylist.is_egress_denied("::1")[0] is True
    assert denylist.is_egress_denied(
        "127.0.0.1", allowed_ips={"127.0.0.1"}, loopback_allowed_if_scoped=True)[0] is False
    assert denylist.is_egress_denied(
        "::1", allowed_ips={"::1"}, loopback_allowed_if_scoped=True)[0] is False
    assert denylist.is_egress_denied(
        "127.0.0.1", allowed_ips=set(), loopback_allowed_if_scoped=True)[0] is True


def test_metadata_floor_never_liftable_even_with_the_loopback_optin():
    floor = (
        "169.254.169.254", "169.254.1.1",
        "::ffff:169.254.169.254", "::ffff:a9fe:a9fe",
        "::169.254.169.254",
        "2002:a9fe:a9fe::",
        "64:ff9b::169.254.169.254", "64:ff9b:1::169.254.169.254",
        "fe80::1",
        "fd00:ec2::254",
        "224.0.0.1", "ff02::1",
        "0.0.0.0", "::",
        "240.0.0.1", "255.255.255.255",
    )
    for ip in floor:
        denied, _ = denylist.is_egress_denied(
            ip, allowed_ips={ip}, loopback_allowed_if_scoped=True)
        assert denied is True, ip


def test_hard_deny_set_unchanged():
    assert denylist.is_hard_denied("127.0.0.1") is True
    assert denylist.is_hard_denied("::1") is True
    assert "127.0.0.0/8" in denylist.hard_deny_cidrs()
