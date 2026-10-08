"""common.egress_pin — the engine-side never-liftable egress FLOOR for the engine's own connectors.

DEFENSIVE. This module only ever REFUSES a destination or returns the exact IP the caller must pin to;
it never widens what may be reached. It exists to close the residual named in
``integration/vigil_integration/live/egress_floor.py:23-35``: the integration re-drive paths pin their
egress through ``pin_egress`` + ``vigil_gateway.denylist``, but the engine's own raw-socket / urllib egress
sites historically did a string scope check and then connected on a RE-RESOLVED name — so a metadata /
link-local / RFC1918 address (directly, or via a DNS-rebinding answer) could be dialled.

COVERAGE — be precise about which same-class engine sites this helper is wired into (do not read it as
covering all of them):
  * WIRED (#874): ``verify/reachability.py`` (TCP handshake), ``verify/tls.py`` (TLS handshake, pin +
    SNI preserved), ``verify/reachability_cloud.py`` (anonymous GET — floor CHECK only; urllib re-resolves,
    so a precisely-timed DNS rebinding is a NARROW named residual there — an IP-pin breaks a vhost's cert).
  * WIRED (WS1.1b, #879): the raw sockets in ``scanner/websocket.py`` (CSWSH — a FACT-minting path),
    ``scanner/race.py::raw_race`` (LEAD), and ``scanner/smuggling.py`` (``raw_send`` + ``_desync_leg``). The
    engagement slug is threaded from their campaign drivers; each resolves once, refuses metadata/link-local/
    RFC1918 (and a name rebinding to them), and dials the pinned IP. Channel-only — no FACT, oracles frozen.

This helper resolves the host ONCE, runs the SAME shared floor primitive
``vigil_gateway.denylist.is_egress_denied`` over EVERY resolved address, and returns the first validated
address for the caller to CONNECT TO DIRECTLY (never re-resolving the name) — the anti-rebinding pin. It is
the engine's re-use of the one shared floor, respecting layering: the engine may import ``vigil_gateway``
(it already does, e.g. ``console/actions.py``), but must not import the integration layer.

The floor is charter-independent where it must be: the metadata/link-local/reserved tier is NEVER liftable.
The private and loopback tiers lift ONLY for an exact IP LITERAL written in the signed charter scope
(``ethics.parse_scope`` filtered to literals — mirroring ``charter_allowed_ips``: literals only, no DNS, so
there is no second DNS view that could authorise itself). Fail-closed throughout: any resolution/parse
error REFUSES.

GATEWAY-LESS ENGINE PLANE (the backstop). When ``vigil_gateway.denylist`` — the richer L3/L4 authority — is
importable it stays the SOLE floor authority. When it is ABSENT (the CRUCIBLE-core "engine v2 test tree" CI
leg and any ``vigil_core``-only sovereign deploy legitimately run gateway-less against OWNER-CONTROLLED
loopback targets), the check does NOT fail-open (an unguarded connect) and does NOT fail the whole loopback
plane closed; it DEGRADES to a pure-stdlib ``ipaddress`` structural floor (:func:`_stdlib_floor_denied`)
that mirrors ``is_egress_denied``'s NEVER-LIFTABLE tier EXACTLY and applies the SAME charter-literal /
loopback lift. The backstop's refusals are a SUPERSET-OR-EQUAL of the full denylist's on the never-liftable
tier (the explicit CIDR mirror plus the ipaddress predicate fallbacks can only refuse MORE, never less) and
its lifts are identical, so it is never LESS strict than the richer authority — it never contradicts or
widens it, only ever refuses, never authorises anything the full denylist would deny. This is the Lane-O
disarm doctrine: a
control degrades to its safe structural floor when its richer authority is absent, it does not fail-open.
The INTEGRATION ``egress_floor.pin_egress`` real-external-egress plane always ships vigil_gateway and
correctly stays fail-closed — no backstop there.

DIVERGENCE from the integration ``pin_egress`` (deliberate, named): this helper enforces the L3/L4 floor +
the anti-rebinding pin + the caller's name-level scope check (in each connector's ``_authorize``), but does
NOT add ``pin_egress``'s scope-over-RESOLVED-ADDRESSES step (its ``charter_address_authorizer``). Effect: a
charter-listed NAME that resolves to several PUBLIC addresses will pin the first — the floor still refuses
every metadata/link-local/RFC1918 address, so the only residual is an out-of-scope *public* address on an
in-scope name (the name itself already passed the scope gate). Replicating the address-level scope predicate
soundly means replicating ``charter_address_authorizer`` (and its self-reference pitfalls); this helper
deliberately does not, so that out-of-scope-public residual is a documented divergence, not an open gap.
"""

from __future__ import annotations

import ipaddress
import socket
from typing import Any, Callable


class EgressFloorRefused(Exception):
    """The never-liftable egress floor refused this destination. The message is the reason; callers turn
    it into a fail-closed ``connected: False`` / refusal, never an unguarded connect."""


# ---------------------------------------------------------------------------
# Stdlib structural BACKSTOP for the gateway-less engine plane (Lane-O disarm doctrine: a control
# DEGRADES to its SAFE structural floor when its richer authority is absent — it does NOT fail-open).
#
# The engine's own scan/test plane (the CRUCIBLE-core "engine v2 test tree" CI leg, and any sovereign
# deployment that ships only ``vigil_core`` + ``framework``) legitimately runs WITHOUT ``vigil_gateway``
# on the path: it engages LOOPBACK werkzeug test servers the owner controls, and the two-env boundary
# installs the gateway only on the offense egress plane. When ``vigil_gateway.denylist`` — the richer
# L3/L4 authority — IS importable it stays the SOLE authority (see ``resolve_and_validate_all``). When it
# is ABSENT the control must neither fail-OPEN (an unguarded connect — forbidden) nor fail the whole
# loopback plane CLOSED (a gateway-less loopback scan is legitimate); it degrades to this pure-stdlib
# floor, which mirrors ``is_egress_denied``'s NEVER-LIFTABLE tier EXACTLY and applies the SAME
# charter-literal / loopback lift. Its refusals on the never-liftable tier (metadata/link-local/multicast/
# CGNAT/RFC1918/ULA/reserved/unspecified) are a SUPERSET-OR-EQUAL of the full denylist's (the explicit CIDR
# mirror plus the ipaddress predicate fallbacks can only refuse MORE, never less) and the lifts are
# identical, so it is never LESS strict than the richer authority — it can never contradict or widen it, only
# ever refuses, never authorises anything the full denylist would deny. Pure ``ipaddress``: no DNS, no I/O.

# Tier 1a — ABSOLUTE floor (never liftable). The exact non-loopback always-deny set from
# ``vigil_gateway.denylist._ALWAYS_DENY_{V4,V6}`` (loopback split out to Tier 1b), re-expressed in stdlib.
_BACKSTOP_ALWAYS_DENY_V4: tuple[str, ...] = (
    "0.0.0.0/8", "169.254.0.0/16", "192.0.0.0/24", "192.0.2.0/24", "198.51.100.0/24",
    "203.0.113.0/24", "198.18.0.0/15", "192.88.99.0/24", "224.0.0.0/4", "240.0.0.0/4",
)
_BACKSTOP_ALWAYS_DENY_V6: tuple[str, ...] = (
    "::/128", "100::/64", "2001:db8::/32", "fd00:ec2::/32", "fe80::/10", "fec0::/10", "ff00::/8",
)
_BACKSTOP_ALWAYS_DENY_NETS = tuple(
    ipaddress.ip_network(c) for c in (*_BACKSTOP_ALWAYS_DENY_V4, *_BACKSTOP_ALWAYS_DENY_V6))
# Tier 1b — loopback: hard-denied unless the caller opts in AND the exact IP is charter-authorized.
_BACKSTOP_LOOPBACK_NETS = (ipaddress.ip_network("127.0.0.0/8"), ipaddress.ip_network("::1/128"))
# Tier 2 — private (RFC1918 / CGNAT / IPv6 ULA): denied unless the exact IP is a charter literal.
_BACKSTOP_PRIVATE_NETS = tuple(
    ipaddress.ip_network(c) for c in (
        "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "fc00::/7"))
# Embedded-IPv4 forms, so ``::ffff:169.254.169.254`` / ``::169.254.169.254`` cannot evade the v6 check.
_BACKSTOP_NAT64 = ipaddress.ip_network("64:ff9b::/96")
_BACKSTOP_NAT64_LOCAL = ipaddress.ip_network("64:ff9b:1::/48")
_BACKSTOP_IPV4_COMPAT = ipaddress.ip_network("::/96")
_BACKSTOP_V6_UNSPEC = ipaddress.IPv6Address("::")
_BACKSTOP_V6_LOOPBACK = ipaddress.IPv6Address("::1")


def _coerce_allowed(allowed_ips: "Any") -> "frozenset[str]":
    """Canonicalise the caller's authorized-IP allowlist to canonical string forms (mirrors
    ``denylist._coerce_allowed``). Unparseable entries drop (they can never authorise anything)."""
    out: set[str] = set()
    for entry in allowed_ips or ():
        try:
            out.add(str(ipaddress.ip_address(str(entry).strip().strip("[]"))))
        except ValueError:
            continue
    return frozenset(out)


def _backstop_embedded_v4(ip: "ipaddress._BaseAddress") -> "ipaddress.IPv4Address | None":
    """The IPv4 address embedded in an IPv6 form, else None (mirrors ``denylist._embedded_ipv4``)."""
    if not isinstance(ip, ipaddress.IPv6Address):
        return None
    if ip.ipv4_mapped is not None:
        return ip.ipv4_mapped
    if ip.sixtofour is not None:
        return ip.sixtofour
    if ip in _BACKSTOP_NAT64 or ip in _BACKSTOP_NAT64_LOCAL:
        return ipaddress.IPv4Address(int(ip) & 0xFFFFFFFF)
    if ip in _BACKSTOP_IPV4_COMPAT and ip != _BACKSTOP_V6_UNSPEC and ip != _BACKSTOP_V6_LOOPBACK:
        return ipaddress.IPv4Address(int(ip) & 0xFFFFFFFF)
    return None


def _backstop_candidates(ip: "ipaddress._BaseAddress") -> "list[Any]":
    cands: list[Any] = [ip]
    emb = _backstop_embedded_v4(ip)
    if emb is not None:
        cands.append(emb)
    return cands


def _backstop_in_any(ip: "Any", nets: "Any") -> bool:
    return any(ip.version == net.version and ip in net for net in nets)


def _stdlib_floor_denied(
    ip_str: str,
    allowed_ips: "Any" = None,
    *,
    loopback_allowed_if_scoped: bool = False,
) -> "tuple[bool, str]":
    """Pure-stdlib structural mirror of ``vigil_gateway.denylist.is_egress_denied`` — same signature,
    same decision order, same never-liftable tier and same charter-literal / loopback lift — for the
    gateway-less engine plane. Returns ``(denied, reason)``. On the never-liftable tier its refusals are a
    SUPERSET-OR-EQUAL of the full denylist's: the explicit CIDR mirror reproduces the authority's set
    (minus loopback) and the ``ipaddress`` predicate fallbacks (is_link_local / is_multicast / is_reserved
    / is_unspecified / is_private) can only refuse MORE, never less — so it is never LESS strict than the
    authority. Its lifts are identical: it refuses the never-liftable tier (metadata/link-local/multicast/
    reserved/unspecified) regardless of scope, lifts the private tier only for an exact charter literal, and
    lifts loopback only on the caller's opt-in + an exact literal — so it never authorises anything the full
    denylist would deny. Fail-closed: an unparseable address is denied."""
    raw = (ip_str or "").strip().strip("[]")
    try:
        ip = ipaddress.ip_address(raw)
    except ValueError:
        return True, f"unparseable IP {ip_str!r} (fail-closed) [stdlib backstop]"
    allowed = _coerce_allowed(allowed_ips)
    cands = _backstop_candidates(ip)
    # An IP that authorises itself must still not hit the never-liftable floor (checked FIRST below).
    self_authorized = any(str(c) in allowed for c in cands)
    # Tier 1a — the ABSOLUTE floor: metadata / link-local / multicast / reserved / unspecified. Never
    # liftable by any scope or opt-in. The explicit CIDR set mirrors ``denylist._ALWAYS_DENY_*`` (minus
    # loopback); the predicate fallbacks also refuse any future special-use block ipaddress learns.
    # Loopback is EXCLUDED here and handled in Tier 1b — ``denylist`` splits loopback out of its
    # always-deny set so an opted-in caller can lift it, and stdlib ``::1.is_reserved`` is True (``::1``
    # sits in ``::/8``), which would otherwise wrongly hard-deny a charter-scoped loopback target.
    for c in cands:
        if not c.is_loopback and (
                _backstop_in_any(c, _BACKSTOP_ALWAYS_DENY_NETS)
                or c.is_link_local or c.is_multicast or c.is_reserved or c.is_unspecified):
            return True, (f"{c} is in an always-denied range "
                          "(metadata/link-local/multicast/reserved) [stdlib backstop]")
    # Tier 1b — loopback: hard-denied unless the caller opted in AND the exact IP is charter-authorized.
    for c in cands:
        if _backstop_in_any(c, _BACKSTOP_LOOPBACK_NETS) or c.is_loopback:
            if loopback_allowed_if_scoped and self_authorized:
                return False, f"allowed ({c} is a charter-authorized loopback target) [stdlib backstop]"
            return True, f"{c} is loopback (denied for egress) [stdlib backstop]"
    # Tier 2 — private (RFC1918 / CGNAT / ULA): denied unless the exact IP is a charter literal.
    for c in cands:
        if (_backstop_in_any(c, _BACKSTOP_PRIVATE_NETS) or c.is_private) and not self_authorized:
            return True, (f"{c} is private/internal and not in the charter-authorized "
                          "allowlist [stdlib backstop]")
    # Final — the destination must be globally routable (unless an exact literal lifted it above).
    for c in cands:
        if not c.is_global and not self_authorized:
            return True, f"{c} is not globally routable (is_global=False) [stdlib backstop]"
    return False, "allowed [stdlib backstop]"


def _as_ip_literal(entry: str) -> str | None:
    """Return the bare IP-literal form of a charter scope ``entry``, or None if it is not an IP literal.

    Accepts a bare literal (``127.0.0.1``, ``::1``), a bracketed IPv6 (``[::1]``), or a URL/host-shaped
    entry whose host part is a literal (``http://127.0.0.1:8080`` -> ``127.0.0.1``). A hostname or wildcard
    row is NOT a literal and returns None — only literals may lift the private/loopback tiers, exactly as
    ``egress_floor.charter_allowed_ips`` documents (no DNS is performed here)."""
    s = (entry or "").strip()
    if not s:
        return None
    # Strip a URL scheme + path so a scope row like "http://10.0.0.5/app" reduces to its host.
    if "://" in s:
        s = s.split("://", 1)[1]
    s = s.split("/", 1)[0]
    # Drop a trailing :port that is NOT part of an IPv6 literal (an IPv6 literal is bracketed for that).
    if s.startswith("[") and "]" in s:
        s = s[1 : s.index("]")]
    elif s.count(":") == 1:
        s = s.split(":", 1)[0]
    try:
        return str(ipaddress.ip_address(s))
    except ValueError:
        return None


def charter_ip_literals(slug: str) -> "frozenset[str]":
    """The IP LITERALS in ``slug``'s signed charter scope — the only set that may lift the denylist's
    private/loopback tiers for the engine connectors. Fail-closed: any error yields the EMPTY set, which can
    only make the floor STRICTER. Mirrors ``egress_floor.charter_allowed_ips`` using the engine's own
    ``common.ethics.parse_scope`` (no integration import, no DNS)."""
    try:
        from . import ethics
        rows = ethics.parse_scope(slug) or []
    except Exception:
        return frozenset()
    out = {lit for row in rows if (lit := _as_ip_literal(str(row)))}
    return frozenset(out)


def _resolve(host: str, port: int, resolver: Callable[..., Any]) -> "list[str]":
    """Every address ``host`` resolves to, deduped and order-preserving. An IP literal resolves to itself
    (never handed to a resolver, so a hostile resolver cannot rewrite a literal). Mirrors
    ``egress_floor._resolve``."""
    h = host.strip()
    if h.startswith("[") and h.endswith("]"):
        h = h[1:-1]
    try:
        ipaddress.ip_address(h)
        return [h]
    except ValueError:
        pass
    infos = resolver(host, port or None, proto=socket.IPPROTO_TCP)
    out: list[str] = []
    for info in infos or ():
        sockaddr = info[4] if len(info) >= 5 else None
        if not sockaddr:
            continue
        addr = str(sockaddr[0]).strip()
        if addr and addr not in out:
            out.append(addr)
    return out


def resolve_and_pin(
    host: str,
    port: int,
    *,
    slug: str = "",
    allowed_ips: "frozenset[str] | None" = None,
    loopback_allowed_if_scoped: bool = False,
    resolver: Callable[..., Any] | None = None,
) -> str:
    """Resolve ``host`` and return the exact IP the caller MUST connect to, or raise
    :class:`EgressFloorRefused`. Every resolved address must clear
    ``vigil_gateway.denylist.is_egress_denied``; the connection is then pinned to the first validated
    address so a rebinding resolver cannot swap in a denied IP after the check.

    ``allowed_ips`` defaults to :func:`charter_ip_literals` for ``slug`` (the charter's IP literals — the
    only lift of the private/loopback tiers; the metadata/link-local/reserved tier is never lifted).
    ``loopback_allowed_if_scoped`` defaults False (fail-closed): a resolved-to-loopback destination is
    REFUSED unless the CALLER explicitly opts in — the deliberate, greppable decision a path that engages
    an owner-authorised loopback target (a loopback range or MERIDIAN) makes. Even when opted in, loopback
    lifts ONLY for an exact charter IP literal, so the opt-in never widens a charter; a caller that does
    not opt in (or a future one that forgets) gets the stricter refusal. The private (RFC1918/CGNAT/ULA)
    tier is unaffected by this flag — it lifts on an exact charter literal regardless. The
    metadata/link-local/reserved floor is never lifted either way. Total / fail-closed: any error
    REFUSES rather than connecting unguarded."""
    return resolve_and_validate_all(
        host, port, slug=slug, allowed_ips=allowed_ips,
        loopback_allowed_if_scoped=loopback_allowed_if_scoped, resolver=resolver,
    )[0]  # pin the first validated address; every address cleared the floor


def resolve_and_validate_all(
    host: str,
    port: int,
    *,
    slug: str = "",
    allowed_ips: "frozenset[str] | None" = None,
    loopback_allowed_if_scoped: bool = False,
    resolver: Callable[..., Any] | None = None,
) -> "list[str]":
    """Resolve ``host`` ONCE and return EVERY resolved address (order-preserving) after each has cleared
    ``vigil_gateway.denylist.is_egress_denied``, or raise :class:`EgressFloorRefused` if ANY resolved
    address is denied (or resolution fails). Same floor and same ``allowed_ips`` / loopback semantics as
    :func:`resolve_and_pin`, which returns element ``[0]`` of this list.

    A caller that connects over this WHOLE validated list (create_connection-style fallback across it)
    gets the anti-rebinding guarantee AND dual-stack connect fallback: the host is resolved exactly once
    here, only these validated addresses are ever dialled, and the name is never re-resolved — so a
    rebinding resolver cannot present a safe answer to this check and a denied answer to the dialer."""
    h = (host or "").strip()
    if h.startswith("[") and h.endswith("]"):
        h = h[1:-1]
    if not h:
        raise EgressFloorRefused("empty target host (fail-closed)")
    try:
        from vigil_gateway import denylist
        floor_check = denylist.is_egress_denied  # the richer L3/L4 authority; SOLE authority when present
    except Exception:
        # Gateway-less engine plane (the CRUCIBLE-core engine test tree; a vigil_core-only sovereign
        # deploy): DEGRADE to the pure-stdlib structural floor rather than fail-OPEN (an unguarded
        # connect) or fail the whole legitimate loopback plane CLOSED. The backstop mirrors the
        # never-liftable tier EXACTLY and is a strict structural subset of the full denylist, so it
        # never widens it. Lane-O disarm doctrine: a control degrades to its safe structural floor when
        # its richer authority is absent; it does not fail-open. (The INTEGRATION ``egress_floor``
        # real-external-egress plane always ships vigil_gateway and correctly stays fail-closed.)
        floor_check = _stdlib_floor_denied
    allowed = allowed_ips if allowed_ips is not None else charter_ip_literals(slug)
    resolve = resolver or socket.getaddrinfo
    try:
        addresses = _resolve(h, port, resolve)
    except Exception as e:  # gaierror / OSError / UnicodeError all fail closed
        raise EgressFloorRefused(
            f"cannot resolve {h!r} (fail-closed): {type(e).__name__}: {e}") from e
    if not addresses:
        raise EgressFloorRefused(f"{h!r} resolved to no address (fail-closed)")
    for address in addresses:
        try:
            denied, why = floor_check(
                address, allowed, loopback_allowed_if_scoped=loopback_allowed_if_scoped)
        except Exception as e:  # a floor that errored refuses
            denied, why = True, f"egress-floor check errored (fail-closed): {type(e).__name__}: {e}"
        if denied:
            raise EgressFloorRefused(
                f"egress floor refused {h!r} -> {address}: {why} (the metadata/link-local/reserved floor "
                "is charter-independent and cannot be lifted by a scope listing)")
    return addresses  # every address cleared the floor; dial over this validated set, never the name
