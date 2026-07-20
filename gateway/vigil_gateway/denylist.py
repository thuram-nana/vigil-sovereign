"""
denylist — the always-refused egress destinations, and the private-unless-scoped set.

This module is the L3/L4 conscience of the gateway. It answers one question with a
fail-closed default: *may traffic from the offense sandbox be allowed to reach this IP?*

Two tiers:

  * HARD DENY — refused for egress no matter what the charter says. Reaching any of
    these from an autonomous, prompt-injectable offense agent is never a legitimate
    in-scope action. The canonical example is ``169.254.169.254`` (cloud instance
    metadata) — an SSRF/credential-theft target that lives inside link-local space —
    plus loopback, multicast, and the IPv6 equivalents. A charter can NOT re-enable
    these; they are denied even if an operator lists them, because a listing is far
    more likely to be an injection or a mistake than a real intent to let the agent
    read the host's cloud credentials.

  * PRIVATE (conditional) — RFC1918 / CGNAT / IPv6 ULA. Denied *unless* the exact
    resolved IP is in the charter-authorized allowlist (an operator may legitimately
    scope an internal staging host by IP or by a hostname that resolves to one).

Embedded-IPv4 forms (IPv4-mapped ``::ffff:a.b.c.d``, 6to4 ``2002::/16``, NAT64
``64:ff9b::/96``) are unwrapped and the embedded IPv4 is checked under the v4 rules —
otherwise ``::ffff:169.254.169.254`` would slip past a naive v6-only check.

Everything here is pure and deterministic: no DNS, no I/O, no clock. It is imported by
both the nftables renderer (to build the static drop set) and the forward proxy (to
re-check every resolved connection IP, defeating DNS rebinding).
"""

from __future__ import annotations

from ipaddress import (
    IPv4Address,
    IPv4Network,
    IPv6Address,
    IPv6Network,
    ip_address,
    ip_network,
)
from typing import Iterable

# ---------------------------------------------------------------------------
# Tier 1 — ALWAYS denied (charter-independent). Kept as explicit literals so the
# set is auditable in one read rather than hidden behind ipaddress predicates.
# ---------------------------------------------------------------------------

_ALWAYS_DENY_V4: tuple[str, ...] = (
    "0.0.0.0/8",          # "this host on this network" / unspecified source (RFC 1122)
    "127.0.0.0/8",        # loopback
    "169.254.0.0/16",     # link-local — INCLUDES 169.254.169.254 cloud metadata (IMDS)
    "192.0.0.0/24",       # IETF protocol assignments (incl. 192.0.0.8 etc.)
    "192.0.2.0/24",       # TEST-NET-1 (documentation)
    "198.51.100.0/24",    # TEST-NET-2 (documentation)
    "203.0.113.0/24",     # TEST-NET-3 (documentation)
    "198.18.0.0/15",      # benchmarking (RFC 2544)
    "192.88.99.0/24",     # 6to4 relay anycast (deprecated)
    "224.0.0.0/4",        # multicast
    "240.0.0.0/4",        # reserved / future use (incl. 255.255.255.255 broadcast)
)

_ALWAYS_DENY_V6: tuple[str, ...] = (
    "::/128",             # unspecified
    "::1/128",            # loopback
    "100::/64",           # discard-only (RFC 6666)
    "2001:db8::/32",      # documentation
    "fd00:ec2::/32",      # AWS IMDS-over-IPv6 (fd00:ec2::254) — hard-deny even within ULA
    "fe80::/10",          # link-local
    "fec0::/10",          # deprecated site-local
    "ff00::/8",           # multicast
)

# ---------------------------------------------------------------------------
# Tier 2 — PRIVATE (denied unless the exact IP is charter-authorized).
# ---------------------------------------------------------------------------

_PRIVATE_V4: tuple[str, ...] = (
    "10.0.0.0/8",         # RFC 1918
    "172.16.0.0/12",      # RFC 1918
    "192.168.0.0/16",     # RFC 1918
    "100.64.0.0/10",      # CGNAT (RFC 6598)
)

_PRIVATE_V6: tuple[str, ...] = (
    "fc00::/7",           # unique local addresses (ULA)
)

_ALWAYS_DENY_NETS: tuple[IPv4Network | IPv6Network, ...] = tuple(
    ip_network(c) for c in (*_ALWAYS_DENY_V4, *_ALWAYS_DENY_V6)
)
_PRIVATE_NETS: tuple[IPv4Network | IPv6Network, ...] = tuple(
    ip_network(c) for c in (*_PRIVATE_V4, *_PRIVATE_V6)
)

# NAT64 well-known prefix — not exposed by ipaddress, handled explicitly.
_NAT64 = IPv6Network("64:ff9b::/96")
# NAT64 RFC 8215 network-specific well-known /48 (the WKP twin); embeds IPv4 in its low bits.
_NAT64_LOCAL = IPv6Network("64:ff9b:1::/48")
# Deprecated IPv4-compatible form ``::a.b.c.d`` (``::/96``): the low 32 bits are an IPv4
# address, so ``::169.254.169.254`` must be unwrapped and re-checked or it evades the v6 rules.
_IPV4_COMPAT = IPv6Network("::/96")
_V6_UNSPEC = IPv6Address("::")
_V6_LOOPBACK = IPv6Address("::1")


def hard_deny_cidrs() -> list[str]:
    """The Tier-1 always-denied CIDRs, for rendering into a static firewall drop set."""
    return [*_ALWAYS_DENY_V4, *_ALWAYS_DENY_V6]


def private_cidrs() -> list[str]:
    """The Tier-2 private CIDRs (denied unless a contained IP is charter-authorized)."""
    return [*_PRIVATE_V4, *_PRIVATE_V6]


def _embedded_ipv4(ip: IPv4Address | IPv6Address) -> IPv4Address | None:
    """The IPv4 address embedded in an IPv6 form, else None.

    Covers every embedding that carries a v4 destination: IPv4-mapped ``::ffff:a.b.c.d``,
    6to4 ``2002::/16``, NAT64 well-known ``64:ff9b::/96`` and its RFC 8215 local twin
    ``64:ff9b:1::/48``, and the deprecated IPv4-compatible ``::a.b.c.d`` (``::/96``). Without
    these, ``::ffff:169.254.169.254`` OR ``::169.254.169.254`` would evade the v6 metadata check.
    """
    if not isinstance(ip, IPv6Address):
        return None
    if ip.ipv4_mapped is not None:
        return ip.ipv4_mapped
    if ip.sixtofour is not None:  # 2002::/16
        return ip.sixtofour
    if ip in _NAT64 or ip in _NAT64_LOCAL:
        return IPv4Address(int(ip) & 0xFFFFFFFF)
    # IPv4-compatible ::/96, excluding :: and ::1 (unspecified/loopback are hard-denied already).
    if ip in _IPV4_COMPAT and ip != _V6_UNSPEC and ip != _V6_LOOPBACK:
        return IPv4Address(int(ip) & 0xFFFFFFFF)
    return None


def _candidates(ip: IPv4Address | IPv6Address) -> list[IPv4Address | IPv6Address]:
    cands: list[IPv4Address | IPv6Address] = [ip]
    emb = _embedded_ipv4(ip)
    if emb is not None:
        cands.append(emb)
    return cands


def _in_any(ip: IPv4Address | IPv6Address, nets: Iterable[IPv4Network | IPv6Network]) -> bool:
    return any(ip.version == net.version and ip in net for net in nets)


def _coerce_allowed(allowed_ips: Iterable[str] | None) -> frozenset[str]:
    """Normalise the caller's authorized-IP allowlist to canonical string forms.

    Accepts strings; canonicalises via ``ip_address`` so ``10.0.0.1`` and any
    non-canonical spelling compare equal. Unparseable entries are dropped (they can
    never authorise anything).
    """
    out: set[str] = set()
    for entry in allowed_ips or ():
        try:
            out.add(str(ip_address(str(entry).strip().strip("[]"))))
        except ValueError:
            continue
    return frozenset(out)


def is_egress_denied(
    ip_str: str,
    allowed_ips: Iterable[str] | None = None,
) -> tuple[bool, str]:
    """Return ``(denied, reason)`` for letting sandbox egress reach ``ip_str``.

    Fail-closed: an unparseable address is denied. ``allowed_ips`` is the set of
    charter-authorized concrete IPs (typically the resolved in-scope hosts); it can
    lift the *private* tier for an exactly-matching IP but never the *hard-deny* tier.
    """
    raw = (ip_str or "").strip().strip("[]")
    try:
        ip = ip_address(raw)
    except ValueError:
        return True, f"unparseable IP {ip_str!r} (fail-closed)"

    allowed = _coerce_allowed(allowed_ips)
    cands = _candidates(ip)

    # Tier 1 — hard deny wins over everything, including the allowlist.
    for c in cands:
        if _in_any(c, _ALWAYS_DENY_NETS):
            return True, f"{c} is in an always-denied range (metadata/loopback/link-local/reserved)"

    # An IP that authorises itself must still not be hard-denied (checked above).
    self_authorized = any(str(c) in allowed for c in cands)

    # Tier 2 — private is denied unless the exact IP is charter-authorized.
    for c in cands:
        if _in_any(c, _PRIVATE_NETS) and not self_authorized:
            return True, f"{c} is private/internal and not in the charter-authorized allowlist"

    # Final backstop: the destination must be globally routable. ipaddress.is_global
    # catches anything the explicit lists above missed (e.g. future special-use blocks).
    for c in cands:
        if not c.is_global and not self_authorized:
            return True, f"{c} is not globally routable (is_global=False)"

    return False, "allowed"


def is_hard_denied(ip_str: str) -> bool:
    """True iff ``ip_str`` is in the Tier-1 always-denied set (charter-independent).

    Used by the nftables renderer to build the static, scope-independent drop set.
    """
    raw = (ip_str or "").strip().strip("[]")
    try:
        ip = ip_address(raw)
    except ValueError:
        return True
    return any(_in_any(c, _ALWAYS_DENY_NETS) for c in _candidates(ip))
