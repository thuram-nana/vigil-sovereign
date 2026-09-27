"""egress_floor — the ONE never-liftable egress floor + connect-pin shared by every live re-drive path.

WHY THIS MODULE EXISTS (the class-bug, closed once). A charter/scope gate answers a question about a
*string*: ``ethics.host_matches_scope`` is pure text matching. It resolves nothing and classifies no
address. So a gate chain built only from ``agents.scope_gate.validate_action`` +
``verify.reachability._authorize`` authorises ``imds.corp.example`` without ever learning that the name
resolves to ``169.254.169.254`` — the cloud instance-metadata address the gateway denylist declares
charter-INDEPENDENTLY denied ("A charter can NOT re-enable these; they are denied even if an operator
lists them", ``gateway/vigil_gateway/denylist.py``). A charter that LISTS the literal is worse still: the
string gate then says yes for the exact case the floor exists to make impossible.

Two re-drive paths bottomed out in that string-only chain (``live/transport_redrive.py`` and
``live/smuggling_redrive.py`` — the latter DNS-pinned, but charter-relative, so the pin re-asked the same
string gate about the resolved IP). The repo's recorded lesson is that a class-bug recurs at every
unguarded site and must be closed with ONE shared helper rather than per-site patches, so both call
:func:`pin_egress` here, and any future resolve-then-connect site must too.

WHAT IT ENFORCES, in order, before any byte leaves the box:

  1. RESOLVE the target once (an IP literal resolves to itself). An unresolvable name is refused — an
     unresolvable target is not an authorized one.
  2. Run ``vigil_gateway.denylist.is_egress_denied`` over EVERY resolved address. That function is the
     single source of truth for egress: the metadata / link-local / multicast / reserved floor is never
     liftable by any charter or opt-in; loopback is liftable ONLY for a caller that opts in AND whose
     charter-authorized allow-set contains the exact loopback IP; RFC1918/CGNAT/ULA is liftable ONLY for
     an exactly-charter-authorized IP. Embedded-IPv4 forms (``::ffff:169.254.169.254``, 6to4, NAT64,
     ``::a.b.c.d``) are unwrapped there, so a v6 spelling of the metadata address is refused too.
  3. Optionally re-ask the CALLER's own charter-relative predicate about each address (the property
     ``dns_pin.resolve_and_validate`` already gave the smuggling path; kept, not replaced — the floor is
     an ADDITIONAL authority, never a substitute for scope).
  4. PIN: return the validated address so the caller connects to THAT literal, closing the DNS
     rebinding / short-TTL / poisoned-resolver / multi-A window a re-resolve at connect time reopens.

All-or-nothing on a multi-address name, exactly as ``dns_pin`` is: connecting to the one address that
happens to be in scope would leave the others reachable on a retry.

LOOPBACK STAYS REACHABLE. Loopback engagements are a heavily used legitimate mode, so the default here is
``loopback_allowed_if_scoped=True`` — which is NOT an exception carved into this module but the denylist's
own parameter: the exact loopback IP must still be in the charter-authorized allow-set. The
metadata/link-local floor is not liftable by that flag, by ``allowed_ips``, or by anything else.

FAIL-CLOSED. An empty host, an unresolvable host, an unparseable address, a denied address, or a missing
``vigil_gateway.denylist`` all REFUSE. A missing denylist in particular must never mean "connect
unguarded" — it means the conscience is absent, so there is no authorization.

FATAL-2: every ``framework``-touching import is FUNCTION-LOCAL; at module scope this is stdlib plus the
lazily-imported gateway denylist (pure stdlib itself, and already imported on the integration side by
``live/executor.py`` and ``live/external_tool.py``).
"""

from __future__ import annotations

import ipaddress
import socket
import ssl
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Iterable, Optional

__all__ = [
    "EgressPin",
    "charter_allowed_ips",
    "pin_egress",
    "pinned_tcp_connector",
    "pinned_tls_connector",
]


@dataclass
class EgressPin:
    """The outcome of resolving a target and running the never-liftable egress floor over every address.

    ``checked`` is the POSITIVE audit trail — one ``(address, denied, reason)`` row per address the floor
    actually adjudicated. A caller (or a test) asserting that the guard RAN reads this, rather than
    inferring it from the absence of a connection."""

    host: str = ""
    port: int = 0
    addresses: "list[str]" = field(default_factory=list)    # every address the name resolved to
    checked: "list[tuple[str, bool, str]]" = field(default_factory=list)   # (address, denied, reason)
    allowed_ips: "tuple[str, ...]" = ()                     # the charter-authorized lift set consulted
    pinned: str = ""                                        # the validated address the connect must use
    refused_reason: str = ""

    @property
    def allowed(self) -> bool:
        return bool(self.pinned) and not self.refused_reason

    @property
    def floor_ran(self) -> bool:
        """True iff ``is_egress_denied`` was actually consulted for at least one resolved address."""
        return bool(self.checked)


def _denylist():
    """The gateway's L3/L4 conscience. Imported lazily (and with the same repo-root path fix
    ``external_tool._gateway_modules`` uses) so this module imports anywhere; a failure to import RAISES,
    and every caller turns that into a refusal — never into an unguarded connect."""
    try:
        from vigil_gateway import denylist  # type: ignore  # noqa: PLC0415
        return denylist
    except ImportError:
        gw = Path(__file__).resolve().parents[3] / "gateway"
        if gw.is_dir() and str(gw) not in sys.path:
            sys.path.insert(0, str(gw))
        from vigil_gateway import denylist  # type: ignore  # noqa: PLC0415
        return denylist


def charter_allowed_ips(slug: str, *, resolver: Optional[Callable[..., Any]] = None) -> "frozenset[str]":
    """The concrete IPs of the NON-WILDCARD entries of ``slug``'s signed charter scope.

    This is the ONLY set that may lift the denylist's private/loopback tiers, and it mirrors
    ``external_tool.ScopeGate.authorize`` exactly: the target's OWN resolved IP is never self-added, so a
    broad wildcard scope (``*.example.com`` resolving to 10.x via split-horizon or attacker-controlled
    DNS) cannot lift the private tier for itself. A legitimate IP-literal or exact-hostname scope entry is
    already in this set, so a charter-scoped RFC1918 staging host — or an authorized loopback target —
    still works.

    Fail-closed: any error (no charter, unsigned charter, no gateway) yields the EMPTY set, which can only
    make the floor stricter, never looser."""
    try:
        from vigil_gateway.scope_source import CharterScopeSource  # type: ignore  # noqa: PLC0415
    except ImportError:
        try:
            _denylist()  # fixes sys.path when the repo layout needs it
            from vigil_gateway.scope_source import CharterScopeSource  # type: ignore  # noqa: PLC0415
        except Exception:  # noqa: BLE001 — fail-closed: no lift set at all
            return frozenset()
    try:
        source = CharterScopeSource(str(slug or ""))
        if resolver is not None:
            return frozenset(source.resolved_allowed_ips(resolver=resolver))
        return frozenset(source.resolved_allowed_ips())
    except Exception:  # noqa: BLE001 — an unreadable/unsigned charter authorises no lift
        return frozenset()


def _normalise(address: Any) -> str:
    """A bare address string: brackets stripped, IPv6 zone id (``fe80::1%eth0``) dropped."""
    return str(address or "").strip().strip("[]").split("%")[0]


def _resolve(host: str, port: int, resolver: Callable[..., Any]) -> "list[str]":
    """Every address ``host`` resolves to, deduped and order-preserving. An IP literal resolves to itself
    (never handed to a resolver, so a hostile resolver cannot rewrite a literal)."""
    try:
        ipaddress.ip_address(host)
        return [host]
    except ValueError:
        pass
    infos = resolver(host, port or None, proto=socket.IPPROTO_TCP)
    out: list[str] = []
    for info in infos or ():
        sockaddr = info[4] if len(info) >= 5 else None
        if not sockaddr:
            continue
        addr = _normalise(sockaddr[0])
        if addr and addr not in out:
            out.append(addr)
    return out


def pin_egress(host: str, port: Any = 0, *, slug: str = "",
               allowed_ips: Optional[Iterable[str]] = None,
               loopback_allowed_if_scoped: bool = True,
               resolver: Optional[Callable[..., Any]] = None,
               address_authorized: Optional[Callable[[str], bool]] = None) -> EgressPin:
    """Resolve ``host``, run the never-liftable egress floor over EVERY resolved address, and return the
    address the caller must PIN its connection to. Total: never raises.

    ``allowed_ips`` defaults to :func:`charter_allowed_ips` for ``slug`` — the charter-authorized lift set
    for the private and (opted-in) loopback tiers. Pass an explicit set only to narrow it or for a
    hermetic test. ``address_authorized`` is the caller's own charter-relative predicate, applied to every
    address IN ADDITION to the floor."""
    try:
        port_i = int(port or 0)
    except (TypeError, ValueError):
        port_i = 0
    pin = EgressPin(host=_normalise(host), port=port_i)
    if not pin.host:
        pin.refused_reason = "empty target host (fail-closed)"
        return pin
    try:
        denylist = _denylist()
    except Exception as exc:  # noqa: BLE001 — no conscience ⇒ no authorization
        pin.refused_reason = (
            f"the egress floor (vigil_gateway.denylist) is not importable, so no destination can be "
            f"authorized — refusing rather than connecting unguarded: {type(exc).__name__}: {exc}")
        return pin
    resolve = resolver or socket.getaddrinfo
    try:
        pin.addresses = _resolve(pin.host, pin.port, resolve)
    except Exception as exc:  # noqa: BLE001 — gaierror/UnicodeError/OSError/... all fail closed
        pin.refused_reason = f"cannot resolve {pin.host!r} (fail-closed): {type(exc).__name__}: {exc}"
        return pin
    if not pin.addresses:
        pin.refused_reason = f"{pin.host!r} resolved to no address (fail-closed)"
        return pin

    # The charter's lift set MUST be resolved with the SAME resolver as the target: resolving the scope
    # entries through a different one would compare two different views of DNS (and, because
    # ``ScopeSource.resolved_allowed_ips`` binds ``socket.getaddrinfo`` as a DEFAULT ARGUMENT at class-
    # definition time, would silently ignore a later replacement of it).
    allowed = (frozenset(str(a) for a in allowed_ips) if allowed_ips is not None
               else charter_allowed_ips(slug, resolver=resolve))
    pin.allowed_ips = tuple(sorted(allowed))

    for address in pin.addresses:
        try:
            denied, why = denylist.is_egress_denied(
                address, allowed, loopback_allowed_if_scoped=loopback_allowed_if_scoped)
        except Exception as exc:  # noqa: BLE001 — a floor that errored refuses
            denied, why = True, f"egress-floor check errored (fail-closed): {type(exc).__name__}: {exc}"
        pin.checked.append((address, bool(denied), str(why)))
        if denied:
            pin.refused_reason = (
                f"egress floor refused {pin.host!r} -> {address}: {why} (the metadata/link-local/reserved "
                f"floor is charter-independent and cannot be lifted by a scope listing)")
            return pin

    if address_authorized is not None:
        for address in pin.addresses:
            try:
                ok = bool(address_authorized(address))
            except Exception as exc:  # noqa: BLE001 — a predicate that errored refuses
                pin.refused_reason = (f"scope re-check errored for {address} (fail-closed): "
                                      f"{type(exc).__name__}: {exc}")
                return pin
            if not ok:
                pin.refused_reason = (
                    f"{pin.host!r} resolves to {address} which the scope decision does not authorize "
                    f"(all {len(pin.addresses)} address(es) must be in scope)")
                return pin

    # Pin the FIRST validated address (``dns_pin.resolve_and_validate``'s choice, kept byte-identical);
    # every address in the list has already cleared both the floor and the caller's scope predicate.
    pin.pinned = pin.addresses[0]
    return pin


# ---------------------------------------------------------------------------
# Pinned connectors — the capture connects to the VALIDATED LITERAL, not to a name it re-resolves.
# ---------------------------------------------------------------------------

def pinned_tcp_connector(pinned: str) -> Callable[..., "tuple[str, str]"]:
    """A ``capture_handshake(connect=...)`` connector that dials the pinned address.

    It DELEGATES to CRUCIBLE's audited ``verify.reachability._socket_connect`` (looked up at call time, so
    a test that replaces that module attribute still intercepts — and now records the PINNED address,
    which is what proves the pin). Only the destination is substituted; the bounded timeout and the
    bounded banner read are the engine's unchanged behaviour."""

    def _connect(host: str, port: int, timeout: float, read_banner: bool) -> "tuple[str, str]":
        from framework.v2.verify.reachability import _socket_connect  # noqa: PLC0415 — FATAL-2, late-bound
        return _socket_connect(str(pinned), int(port), timeout, read_banner)

    return _connect


def _tls_socket_connect(address: str, host: str, port: int,
                        timeout: float) -> "tuple[str, str, Optional[int], Optional[bytes]]":
    """ONE bounded TLS handshake to ``address`` while still presenting ``host`` for SNI.

    This mirrors ``verify.tls._tls_connect`` exactly (same context, same disabled cert validation — a
    posture probe, not a trust check — same 4-tuple), and splits only the two things the engine's
    connector fuses: the ADDRESS dialled and the NAME presented. Pinning the transport must not weaken
    which certificate the peer selects, so SNI stays the requested hostname; re-resolving the name at
    connect time (what the unpinned connector does) is precisely the window the floor check would
    otherwise leave open. Kept as a module-level function so a test can replace it and count calls."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with socket.create_connection((address, int(port)), timeout=timeout) as raw:
        raw.settimeout(timeout)
        with ctx.wrap_socket(raw, server_hostname=host) as tls:
            version = tls.version() or ""
            cipher = tls.cipher()
            try:
                cert_der = tls.getpeercert(binary_form=True)
            except Exception:  # noqa: BLE001 — a cert we could not read is simply absent evidence
                cert_der = None
    name = cipher[0] if cipher else ""
    bits = cipher[2] if cipher and len(cipher) > 2 else None
    return version, name, (int(bits) if isinstance(bits, int) else None), cert_der


def pinned_tls_connector(pinned: str) -> Callable[..., Any]:
    """A ``capture_tls_handshake(connect=...)`` connector that dials the pinned address with the original
    hostname as SNI."""

    def _connect(host: str, port: int, timeout: float):
        return _tls_socket_connect(str(pinned), _normalise(host), int(port), timeout)

    return _connect
