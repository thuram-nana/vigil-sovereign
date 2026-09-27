"""egress_floor — the ONE never-liftable egress floor + connect-pin shared by the live re-drive paths.

WHY THIS MODULE EXISTS (the class-bug, closed once). A charter/scope gate answers a question about a
*string*: ``ethics.host_matches_scope`` is pure text matching. It resolves nothing and classifies no
address. So a gate chain built only from ``agents.scope_gate.validate_action`` +
``verify.reachability._authorize`` authorises ``imds.corp.example`` without ever learning that the name
resolves to ``169.254.169.254`` — the cloud instance-metadata address the gateway denylist declares
charter-INDEPENDENTLY denied ("A charter can NOT re-enable these; they are denied even if an operator
lists them", ``gateway/vigil_gateway/denylist.py``). A charter that LISTS the literal is worse still: the
string gate then says yes for the exact case the floor exists to make impossible.

WHAT THIS MODULE COVERS, EXACTLY (scope of the claim — it is NOT "repo-wide"). :func:`pin_egress` is
called by the INTEGRATION-SIDE RE-DRIVE paths and by the runner's own gated captures:

  * ``live/transport_redrive.py``   (TCP + TLS captures)
  * ``live/smuggling_redrive.py``   (the raw desync sockets)
  * ``live/race_bizlogic_redrive.py`` (the ``raw_race`` bursts)
  * ``live/web_redrive.py``         (the urllib re-drive)
  * ``live/external_tool.py``       (``_default_capture`` / ``_tls_capture``)
  * ``remediation/live_adapter.py`` and ``remediation/differential_adapter.py`` (the TLS-SPKI identity
    samples taken on an operator-triggered re-test)

ENGINE-SIDE RESIDUAL (explicitly NOT closed here, and not claimed to be). ``framework.v2`` still holds
connect sites this module does not sit in front of, and a caller that reaches them directly gets the
string-only chain:

  * ``scanner/smuggling.py:raw_send``  — a raw socket with NO gate of its own at all.
  * ``verify/reachability.py:_socket_connect`` and ``verify/tls.py:_tls_connect`` — re-resolve the NAME
    and dial it whenever the caller does not inject a pinned ``connect=``. Every call site in the list
    above now injects one; an engine-internal caller (e.g. ``engage_fusion``) does not.

So the honest framing is: this closes the class on the INTEGRATION RE-DRIVE PATHS, not repo-wide. The
repo's recorded lesson (a class-bug recurs at every unguarded site, so close it with ONE shared helper)
is why those paths all call :func:`pin_egress`; any future resolve-then-connect site must too, and the
engine-side sites above remain open work.

WHAT IT ENFORCES, in order, before any byte leaves the box:

  1. RESOLVE the target once (an IP literal resolves to itself). An unresolvable name is refused — an
     unresolvable target is not an authorized one.
  2. Run ``vigil_gateway.denylist.is_egress_denied`` over EVERY resolved address. That function is the
     single source of truth for egress: the metadata / link-local / multicast / reserved floor is never
     liftable by any charter or opt-in; loopback and RFC1918/CGNAT/ULA are liftable ONLY for an address
     that is EXACTLY an IP LITERAL WRITTEN IN THE SIGNED CHARTER SCOPE (see :func:`charter_allowed_ips`
     for why a hostname scope row may not lift them). Embedded-IPv4 forms (``::ffff:169.254.169.254``,
     6to4, NAT64, ``::a.b.c.d``) are unwrapped there, so a v6 spelling of the metadata address is
     refused too.
  3. SCOPE OVER ADDRESSES — re-ask the charter about every resolved address, not just about the name the
     caller was given (:func:`charter_address_authorizer`). The floor above allows ANY globally-routable
     address, so without this step a multi-A answer carrying one in-scope and one out-of-scope public
     address would connect. ``EgressPin.scope_over_addresses`` records whether this step ran, so a test
     asserts the guard RAN rather than inferring it from the absence of a connection.
  4. PIN: return the validated address so the caller connects to THAT literal, closing the DNS
     rebinding / short-TTL / poisoned-resolver / multi-A window a re-resolve at connect time reopens.

All-or-nothing on a multi-address name, exactly as ``dns_pin`` was: connecting to the one address that
happens to be in scope would leave the others reachable on a retry.

LOOPBACK STAYS REACHABLE. Loopback engagements are a heavily used legitimate mode, so the default here is
``loopback_allowed_if_scoped=True`` — which is NOT an exception carved into this module but the denylist's
own parameter: the exact loopback IP must still be an IP-literal row of the signed charter. The
metadata/link-local floor is not liftable by that flag, by ``allowed_ips``, or by anything else.

FAIL-CLOSED. An empty host, an unresolvable host, an unparseable address, a denied address, an
out-of-scope address, or a missing ``vigil_gateway.denylist`` all REFUSE. A missing denylist in
particular must never mean "connect unguarded" — it means the conscience is absent, so there is no
authorization.

FATAL-2: every ``framework``-touching import is FUNCTION-LOCAL; at module scope this is stdlib plus the
lazily-imported gateway denylist (pure stdlib itself, and already imported on the integration side by
``live/executor.py`` and ``live/external_tool.py``).
"""

from __future__ import annotations

import hashlib
import ipaddress
import socket
import ssl
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Iterable, Optional

__all__ = [
    "EgressPin",
    "charter_address_authorizer",
    "charter_allowed_ips",
    "charter_scope_entries",
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
    allowed_ips: "tuple[str, ...]" = ()                     # the charter IP-LITERAL lift set consulted
    pinned: str = ""                                        # the validated address the connect must use
    refused_reason: str = ""
    #: The POSITIVE audit trail of step 3 (scope over ADDRESSES) — one ``(address, authorized, reason)``
    #: row per address the scope predicate adjudicated. Empty iff the step did not run.
    scope_checked: "list[tuple[str, bool, str]]" = field(default_factory=list)
    #: ``"not requested"`` (no predicate was passed — the caller gets name-scope + the floor ONLY),
    #: or ``"enforced"`` once the predicate has adjudicated at least one address.
    scope_over_addresses: str = "not requested"

    @property
    def allowed(self) -> bool:
        return bool(self.pinned) and not self.refused_reason

    @property
    def floor_ran(self) -> bool:
        """True iff ``is_egress_denied`` was actually consulted for at least one resolved address."""
        return bool(self.checked)

    @property
    def scope_ran(self) -> bool:
        """True iff the scope-over-ADDRESSES predicate actually adjudicated at least one address."""
        return bool(self.scope_checked)


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


# ---------------------------------------------------------------------------
# The signed charter, read ONCE per (slug, charter bytes).
#
# B7: ``pin_egress`` runs on EVERY request of a re-drive. Re-parsing and re-signature-verifying the
# charter (and, before this slice, re-RESOLVING every scope entry) per request cost 14.3 ms/req and ~14
# DNS queries/req on a 13-entry charter — +15.3 s and ~15,000 queries over a 1069-request ``make gate``
# run, which is both latency and, under constitution §VI, a self-inflicted amplification signature
# against the operator's resolver and the in-scope domains' authoritative servers. The cache key is
# (slug, charter mtime_ns, charter size), so a mid-engagement RE-SIGN of the charter still invalidates
# it — the property the uncached read was there to give.
# ---------------------------------------------------------------------------

_SCOPE_CACHE: "dict[tuple, tuple[tuple[str, ...], frozenset[str], bool]]" = {}
_NAMED_CACHE: "dict[tuple, frozenset[str]]" = {}
_CACHE_MAX = 32


def _charter_stamp(slug: str) -> tuple:
    """A cache key that changes whenever the charter FILE changes: ``(slug, mtime_ns, size, sha256)``.

    The brief's key is (slug, charter mtime) — enough to preserve the mid-engagement RE-SIGN detection
    that reading the charter on every request was there to give. The CONTENT HASH is added on top
    because mtime granularity is filesystem-dependent and two writes inside one tick would otherwise
    serve a stale scope; hashing a few KB costs ~20 us against the ~14 ms/req this cache removes.
    Everything the cached values depend on — the scope table AND the ``Signed:`` line
    ``require_charter_signed`` checks — lives in these bytes, so the hash is a COMPLETE key.

    Fail-safe: when the charter cannot be read the stamp is unique per call, so the cache simply never
    hits (it can go cold, never stale) and every caller re-reads and fails closed on its own."""
    try:
        from framework.v2.common import paths  # type: ignore  # noqa: PLC0415 — FATAL-2, function-local
        cp = Path(paths.charter_path(str(slug or "")))
        st = cp.stat()
        return (str(slug or ""), int(st.st_mtime_ns), int(st.st_size),
                hashlib.sha256(cp.read_bytes()).hexdigest())
    except Exception:  # noqa: BLE001 — no stamp ⇒ no caching (correctness over speed)
        return (str(slug or ""), object())


def _put(cache: dict, key: tuple, value):
    if len(cache) >= _CACHE_MAX:
        cache.clear()
    cache[key] = value
    return value


def charter_scope_entries(slug: str) -> "tuple[tuple[str, ...], frozenset[str], bool]":
    """``(entries, ip_literals, has_wildcard)`` for ``slug``'s SIGNED charter scope — NO DNS at all.

    ``entries`` are the literal scope rows as the signed charter writes them; ``ip_literals`` are the
    rows that parse as an IP address; ``has_wildcard`` is True iff any row is a ``*.`` wildcard.

    Fail-closed: any error (no charter, UNSIGNED charter, no gateway) yields ``((), frozenset(), False)``
    — an empty scope authorises nothing and lifts nothing."""
    key = _charter_stamp(slug)
    hit = _SCOPE_CACHE.get(key)
    if hit is not None:
        return hit
    try:
        from vigil_gateway.scope_source import CharterScopeSource  # type: ignore  # noqa: PLC0415
    except ImportError:
        try:
            _denylist()  # fixes sys.path when the repo layout needs it
            from vigil_gateway.scope_source import CharterScopeSource  # type: ignore  # noqa: PLC0415
        except Exception:  # noqa: BLE001 — fail-closed: no scope at all
            return ((), frozenset(), False)
    try:
        # ``.hosts()`` runs ``_require_charter_signed`` first: an UNSIGNED charter raises here.
        raw = list(CharterScopeSource(str(slug or "")).hosts())
    except Exception:  # noqa: BLE001 — an unreadable/unsigned charter authorises nothing
        return ((), frozenset(), False)
    entries: list[str] = []
    literals: set[str] = set()
    wildcard = False
    for row in raw:
        entry = str(row or "").strip().strip("`").rstrip(".")
        if not entry or entry.lower() in {"n/a", "none"}:
            continue
        entries.append(entry)
        if entry.startswith("*."):
            wildcard = True
            continue
        try:
            ipaddress.ip_address(_normalise(entry))
        except ValueError:
            continue
        literals.add(_normalise(entry))
    return _put(_SCOPE_CACHE, key, (tuple(entries), frozenset(literals), wildcard))


def charter_allowed_ips(slug: str) -> "frozenset[str]":
    """The IP LITERALS written in ``slug``'s signed charter scope — the ONLY set that may lift the
    denylist's private / loopback tiers. NO DNS is performed.

    WHY LITERALS ONLY (the self-reference this closes). Until this slice the lift set was
    ``CharterScopeSource.resolved_allowed_ips()``: every non-wildcard scope entry RESOLVED AT REQUEST
    TIME. The signed charter carries a NAME; the address came from a DNS answer taken milliseconds
    before the target's own. When the target IS the scope entry — the common case for an exact-hostname
    scope — both sides of the comparison are the same query against the same resolver, so the "private
    tier lifts only for an exactly-charter-authorized IP" rule collapsed into "lifts for whatever the
    resolver just said". A split-horizon view, an attacker-controlled or poisoned resolver, or an
    ordinary dual-homed / round-robin record ( ``[10.0.0.5, 93.184.216.34]`` ) each put an internal
    address into the lift set, and ``pin.addresses[0]`` then dialled it — a signed ``service_reachable``
    FACT about a host the operator never authorized. It was an *exactly-DNS-asserted* IP, never a
    charter-authorized one.

    A NAME therefore gets name-scope plus the floor; only an IP LITERAL written into the signed,
    operator-attested charter gets the private/loopback lift. Measured before committing to this rule:
    across the 59 charters under all three target roots on this box (73 scope entries), exactly ONE
    hostname entry resolves into RFC1918/loopback — ``localhost`` in ``targets/meridian/charter.md``,
    whose charter ALSO lists the ``127.0.0.1`` literal, so its loopback lift survives. Zero RFC1918
    hostname entries anywhere. The rule breaks no operator workflow on record; an operator who needs a
    private host reachable writes its address, which is what "exactly-charter-authorized IP" always
    claimed to mean.

    Fail-closed: any error (no charter, unsigned charter, no gateway) yields the EMPTY set, which can
    only make the floor stricter, never looser."""
    return charter_scope_entries(slug)[1]


def _row_matches_host(row: str, host: str) -> bool:
    """True iff the NON-WILDCARD scope ``row`` is the scope entry that authorises ``host``.

    Non-wildcard scope matching is exact: case-insensitive, trailing dot stripped, and IPv6 compared in
    canonical form (``::1`` == ``0:0:0:0:0:0:0:1``) — the same normalisation ``ethics.host_matches_scope``
    applies for a literal entry. Kept local (a few lines of stdlib) rather than importing the ethics gate,
    because this module is imported by callers that have no ``framework`` on the path."""
    a, b = _normalise(row).lower().rstrip("."), _normalise(host).lower().rstrip(".")
    if not a or not b:
        return False
    if a == b:
        return True
    try:
        return ipaddress.ip_address(a) == ipaddress.ip_address(b)
    except ValueError:
        return False


def _row_addresses(row: str, resolver: Callable[..., Any], slug: str) -> "frozenset[str]":
    """Every address the non-wildcard scope ``row`` resolves to (an IP literal resolves to itself).

    Cached per (charter bytes, row, resolver) so a 1069-request re-drive resolves the scope entry ONCE,
    not 1069 times (B7). Fail-closed: a row that will not resolve contributes nothing."""
    key = _charter_stamp(slug) + (_normalise(row).lower(), resolver)
    hit = _NAMED_CACHE.get(key)
    if hit is not None:
        return hit
    entry = _normalise(row)
    try:
        ipaddress.ip_address(entry)
        return _put(_NAMED_CACHE, key, frozenset({entry}))
    except ValueError:
        pass
    out: set[str] = set()
    try:
        infos = resolver(entry, None, proto=socket.IPPROTO_TCP)
    except TypeError:      # a resolver double that does not accept ``proto``
        try:
            infos = resolver(entry, None)
        except Exception:  # noqa: BLE001 — a name that will not resolve authorises nothing
            infos = ()
    except Exception:      # noqa: BLE001 — same
        infos = ()
    for info in infos or ():
        sockaddr = info[4] if len(info) >= 5 else None
        if sockaddr and sockaddr[0]:
            out.add(_normalise(sockaddr[0]))
    return _put(_NAMED_CACHE, key, frozenset(out))


def charter_address_authorizer(slug: str, host: str = "", *,
                               resolver: Optional[Callable[..., Any]] = None
                               ) -> Callable[[str], "tuple[bool, str]"]:
    """The ONE scope-over-ADDRESSES predicate, shared by every :func:`pin_egress` call site.

    WHY IT MUST EXIST. The floor (step 2) allows ANY globally-routable address, so on a call site that
    passes no predicate the property "every resolved address must be in scope" — the property the shared
    docstring advertises, and the one ``dns_pin.resolve_and_validate`` used to give the smuggling path —
    is simply ABSENT. It was absent on ``transport_redrive`` and ``race_bizlogic_redrive`` (measured: an
    out-of-scope second A record was allowed there and refused on the two predicate sites), and mutating
    the predicate away (``if False and address_authorized is not None:``) killed ZERO tests.

    THE RULE, and exactly how much each branch proves:

      1. The address is written as an IP-LITERAL row of the signed charter scope → AUTHORIZED. This is
         the strong branch: the operator attested to this address.
      2. Otherwise the TARGET matches a non-wildcard HOSTNAME row, and the address is one that row
         resolves to →
           a. if the charter ALSO writes an IP literal that is one of THAT row's addresses, the operator
              has stated this host's address(es) explicitly, so the statement is EXHAUSTIVE for this
              host and any other address of the name is REFUSED;
           b. otherwise the charter authorises only the NAME, and a name means whatever it resolves to,
              so the address is authorized as NAME-DERIVED. Be clear about what that is worth: the
              comparison re-asks the same resolver the same question, so for this branch the predicate
              proves provenance from the charter's own view of the name and NOTHING MORE. The real
              guards for it are the floor above and the all-or-nothing TOCTOU refusal in
              :func:`pin_egress` (the target is resolved first, the charter second; divergent answers
              refuse).
      3. Otherwise → REFUSED. In practice that is the WILDCARD-ONLY case: ``*.corp.example`` authorises
         a NAME PATTERN and names no address at all, so no address can be attributed to the charter.
         This is a deliberate tightening on the transport/race sites (the two predicate sites already
         refused it, as a side-effect of asking a string gate about an IP literal); the operator's
         remedy is to write the concrete host, or its address, into the signed charter.

    THE ASYMMETRY THIS ALSO CLOSES. The per-site predicates it replaces re-asked
    ``reachability_cloud._authorize`` — and so ``ethics.host_matches_scope`` — about the resolved IP
    LITERAL. That string question can only ever be satisfied by an IP-literal charter row, so
    ``web_redrive`` / ``smuggling_redrive`` refused a HOSTNAME-ONLY charter outright: verified against
    the shipped ``targets/testasp/charter.md`` (scope: ``testasp.vulnweb.com``), which those two sites
    refused while ``transport`` / ``race`` allowed it. Branch 2b keeps them working; branch 2a keeps the
    out-of-scope-extra-address refusal they really did have.

    Returns ``(authorized, reason)`` so :func:`pin_egress` records a POSITIVE audit row per address.
    Fail-closed: no charter, or a charter with no scope, authorises no address at all."""
    resolve = resolver or socket.getaddrinfo
    entries, literals, _wild = charter_scope_entries(slug)
    target = _normalise(host)

    def _authorized(address: str) -> "tuple[bool, str]":
        addr = _normalise(address)
        if not entries:
            return False, ("the signed charter authorises no scope entry at all, so it names no address "
                           "(fail-closed)")
        if addr in literals:
            return True, f"{addr} is written as an IP-literal row of the signed charter scope"
        rows = [e for e in entries if not e.startswith("*.") and _row_matches_host(e, target)]
        for row in rows:
            row_addrs = _row_addresses(row, resolve, slug)
            if addr not in row_addrs:
                continue
            stated = literals & row_addrs
            if stated:
                return False, (
                    f"the signed charter states {row!r}'s address(es) explicitly as "
                    f"{sorted(stated)!r}, so that statement is exhaustive for this host and {addr} — "
                    f"also in the answer — is NOT authorized")
            return True, (f"{addr} is name-derived: the signed charter authorises the name {row!r} and "
                          f"this address is in that name's own resolution (no address-level attestation)")
        return False, (
            f"{addr} is attributable to no row of the signed charter scope {list(entries)!r} — a "
            f"wildcard row authorises a NAME PATTERN and names no address, so write the concrete host "
            f"(or its IP literal) to authorise it")

    return _authorized


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

    ``allowed_ips`` defaults to :func:`charter_allowed_ips` for ``slug`` — the IP LITERALS of the signed
    charter scope, the only set that may lift the private and (opted-in) loopback tiers. Pass an explicit
    set only to narrow it or for a hermetic test. ``address_authorized`` is the scope-over-ADDRESSES
    predicate, applied to every address IN ADDITION to the floor; pass
    :func:`charter_address_authorizer` unless you have a narrower one. It may return a plain ``bool`` or
    ``(bool, reason)``; either way the outcome lands in ``pin.scope_checked`` so a caller (or a test) can
    assert POSITIVELY that the step ran. Omitting it means the caller gets name-scope + the floor ONLY —
    ``pin.scope_over_addresses`` says so."""
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

    # The lift set is the signed charter's IP LITERALS — no DNS, so there is no second view of DNS to
    # disagree with the target's own (see ``charter_allowed_ips`` for the self-reference this closes).
    allowed = (frozenset(str(a) for a in allowed_ips) if allowed_ips is not None
               else charter_allowed_ips(slug))
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
                verdict = address_authorized(address)
            except Exception as exc:  # noqa: BLE001 — a predicate that errored refuses
                pin.scope_checked.append((address, False, f"{type(exc).__name__}: {exc}"))
                pin.scope_over_addresses = "enforced"
                pin.refused_reason = (f"scope re-check errored for {address} (fail-closed): "
                                      f"{type(exc).__name__}: {exc}")
                return pin
            # A predicate may answer ``bool`` (the historic shape) or ``(bool, reason)``; the reason is
            # what makes ``scope_checked`` a POSITIVE audit trail rather than a silent boolean.
            if isinstance(verdict, tuple):
                ok, why = bool(verdict[0]), str(verdict[1] if len(verdict) > 1 else "")
            else:
                ok, why = bool(verdict), ""
            pin.scope_checked.append((address, ok, why))
            pin.scope_over_addresses = "enforced"
            if not ok:
                pin.refused_reason = (
                    f"{pin.host!r} resolves to {address} which the scope decision does not authorize "
                    f"(all {len(pin.addresses)} address(es) must be in scope)"
                    + (f": {why}" if why else ""))
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
