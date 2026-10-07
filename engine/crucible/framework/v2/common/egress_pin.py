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
there is no second DNS view that could authorise itself). Fail-closed throughout: any error REFUSES.

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
    h = (host or "").strip()
    if h.startswith("[") and h.endswith("]"):
        h = h[1:-1]
    if not h:
        raise EgressFloorRefused("empty target host (fail-closed)")
    try:
        from vigil_gateway import denylist
    except Exception as e:  # no floor importable => refuse rather than connect unguarded
        raise EgressFloorRefused(
            "egress floor (vigil_gateway.denylist) not importable, so no destination can be authorized "
            f"(fail-closed): {type(e).__name__}: {e}") from e
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
            denied, why = denylist.is_egress_denied(
                address, allowed, loopback_allowed_if_scoped=loopback_allowed_if_scoped)
        except Exception as e:  # a floor that errored refuses
            denied, why = True, f"egress-floor check errored (fail-closed): {type(e).__name__}: {e}"
        if denied:
            raise EgressFloorRefused(
                f"egress floor refused {h!r} -> {address}: {why} (the metadata/link-local/reserved floor "
                "is charter-independent and cannot be lifted by a scope listing)")
    return addresses[0]  # pin the first validated address; every address cleared the floor
