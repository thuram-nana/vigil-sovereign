"""aegis.broker — AS-2d: the per-host egress BROKER + origin LOCK (§4.4).

In the hosted request path the unit's egress leaves ONLY through this broker (R15): the gateway
(``PrivateNetwork=yes``, no DNS, no IMDS) hands an inspected request to the broker, which

  1. maps the serving ``uid`` to the bound ``(host, port)`` taken from the READ-ONLY signed grant
     (``grant.origin``) — a grant that binds a DIFFERENT org never serves this uid (tenant isolation);
  2. runs the never-liftable L3/L4 egress FLOOR (``common.egress_pin.resolve_and_validate_all`` with
     ``allowed_ips=frozenset()`` and ``loopback_allowed_if_scoped=False``) over EVERY resolved origin
     address, so a metadata/IMDS/link-local/RFC1918 origin — and loopback, which is never edge identity
     (R15) — is refused, resolved once and dialled by pinned address (anti-rebinding);
  3. presents the origin LOCK credential (mTLS client cert preferred, or an HMAC ``X-Vigil-Origin-Auth``
     over (request id, ts, client-IP header), or a secret header over HTTPS) so the locked origin can
     tell a real SIGIL broker from the open internet; and
  4. splices the request to the locked origin over a fresh HTTPS leg (viewer TLS is terminated at the
     edge; this origin hop re-establishes TLS with ``SNI = the origin host``).

The CLIENT-IP header is trusted only on a CREDENTIALED request, and the broker binds it only when it is a
trustworthy EDGE identity — so a forged source IP on an un-edge-verified or loopback hop never arrives at
the origin. An IP allowlist alone "does not isolate you from other SIGIL tenants", so ``lock.state`` is one
of {none, ip_allowlist_only, crypto_verified, crypto_verified+ip} and **a release requires crypto_verified**
— the STARTUP REFUSAL this module enforces fail-closed.

This module is the deterministic resolve / floor / lock / forward-composition plane. The physical origin-hop
splice over the defense egress is performed by an injected ``BrokerTransport`` (production: the hosted cell's
transport provisioned by AS-6a placement over the AS-26 defense NAT EIPs + the central keyless origin-hop
cert issuer). Everything here is a pure function of its inputs: no wallclock, no RNG on any signed path or id
(the request id and timestamp are supplied by the request context), so every decision is reproducible.

Default-OFF: the LIVE forward is inert unless ``VIGIL_AEGIS_BROKER`` is explicitly set (the
``_saas_enforce_flag`` discipline); off ⇒ the broker never dials, and the gateway's legacy path is
byte-identical.

FATAL-2: engine leg — imports only ``vigil_core`` (the shared grant contracts), stdlib, and the
framework-internal egress floor (``..common.egress_pin``); nothing from ``sigil`` or the integration layer.
"""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import os
from dataclasses import dataclass
from enum import Enum
from typing import Any, Callable, Mapping, Optional, Protocol

from vigil_core.authority_v2 import MonitoringAuthorityV2, OriginTuple

from ..common.egress_pin import EgressFloorRefused, resolve_and_validate_all

__all__ = [
    "BROKER_ENV",
    "ArmedBroker",
    "BrokerForwardResult",
    "BrokerRefused",
    "BrokerStartupRefused",
    "BrokerTarget",
    "BrokerTransport",
    "LockMethod",
    "LockState",
    "OriginLock",
    "OriginLockVerdict",
    "arm_broker",
    "broker_enabled",
    "broker_forward",
    "is_valid_edge_identity",
    "origin_lock_verify",
    "resolve_broker_target",
    "z4_payload_free_probe",
]

# The default-OFF switch that ARMS the live broker transport (the ``_saas_enforce_flag`` discipline: strict,
# fail-closed, read per call). OFF ⇒ the live splice is inert and the deterministic plane is pure. ENFORCEMENT
# additionally requires a release and a crypto lock (``arm_broker`` + ``_saas_enforce_flag`` upstream).
BROKER_ENV = "VIGIL_AEGIS_BROKER"

# The lock credential header the broker stamps on the origin-hop request; the locked origin verifies them.
HDR_ORIGIN_AUTH = "X-Vigil-Origin-Auth"      # HMAC tag:  ``v1=<hex>``
HDR_REQUEST_ID = "X-Vigil-Request-Id"        # the request id bound into the HMAC
HDR_TIMESTAMP = "X-Vigil-Timestamp"          # the request unix ts bound into the HMAC (skew-checked)
HDR_CLIENT_IP = "X-Vigil-Client-IP"          # the EDGE-provided viewer IP; trusted only on a credentialed req

# The default accepted clock skew (seconds) for the HMAC timestamp at the origin. Compared against an INJECTED
# ``now_ts`` (never a wallclock in this module), so the window is reproducible in tests.
DEFAULT_MAX_SKEW_S = 300


def broker_enabled() -> bool:
    """Is the LIVE broker transport armed? Strict, fail-closed, DEFAULT OFF — only an explicit affirmative
    token arms it (mirrors ``gateway._saas_enforce_flag``). The deterministic resolve/floor/lock/compose plane
    below does NOT consult this flag (it is pure and always safe); only the live origin-hop dial does."""
    return (os.environ.get(BROKER_ENV) or "").strip().lower() in ("1", "true", "yes", "on")


class BrokerRefused(Exception):
    """The broker refused a request/target fail-closed (cross-tenant grant, unbound/non-https origin, an
    egress-floor refusal, or an uncredentialed lock asked to sign). Never a silent pass."""


class BrokerStartupRefused(BrokerRefused):
    """The broker refused to START (arm) fail-closed — the §4.4 "startup refusal". A release/enforcement path
    without a crypto-verified lock, or an unresolvable/refused origin, keeps the broker down rather than
    forwarding tenant traffic without origin isolation."""


class LockMethod(str, Enum):
    """How the origin authenticates a request as coming from a real SIGIL broker (§4.4)."""

    MTLS = "mtls"                      # mutual TLS client certificate (preferred)
    HMAC = "hmac"                      # HMAC ``X-Vigil-Origin-Auth`` over (request id, ts, client-IP)
    SECRET_HEADER = "secret_header"    # a shared secret header over HTTPS
    NONE = "none"                      # no crypto lock (an IP allowlist does NOT isolate SIGIL tenants)


class LockState(str, Enum):
    """The lock's isolation state. A release requires ``crypto_verified`` (``_IP`` variants merely ADD an IP
    allowlist on top; the allowlist alone never reaches crypto_verified)."""

    NONE = "none"
    IP_ALLOWLIST_ONLY = "ip_allowlist_only"
    CRYPTO_VERIFIED = "crypto_verified"
    CRYPTO_VERIFIED_IP = "crypto_verified+ip"


@dataclass(frozen=True)
class OriginLock:
    """One origin's lock configuration: the method + its credential material, and whether an IP allowlist is
    also in force. Immutable; carries the shared secret ONLY for the HMAC/secret-header methods (production
    loads it keylessly via ``LoadCredential``, never from a wallclock or RNG here)."""

    method: LockMethod
    hmac_secret: bytes = b""
    secret_header_name: str = ""
    secret_header_value: str = ""
    ip_allowlist: bool = False

    @property
    def crypto_verified(self) -> bool:
        """True iff the lock carries a real cryptographic credential (not merely an IP allowlist). A release
        requires this to be True."""
        if self.method is LockMethod.HMAC:
            return bool(self.hmac_secret)
        if self.method is LockMethod.SECRET_HEADER:
            return bool(self.secret_header_name and self.secret_header_value)
        if self.method is LockMethod.MTLS:
            return True
        return False

    @property
    def state(self) -> LockState:
        if self.crypto_verified:
            return LockState.CRYPTO_VERIFIED_IP if self.ip_allowlist else LockState.CRYPTO_VERIFIED
        return LockState.IP_ALLOWLIST_ONLY if self.ip_allowlist else LockState.NONE

    def sign(self, *, request_id: str, ts: int, client_ip: str) -> dict[str, str]:
        """The credential headers the broker stamps on the origin-hop request. Deterministic: ``request_id``
        and ``ts`` come from the request context — no wallclock, no RNG. The client-IP is carried (and, for
        HMAC, cryptographically BOUND) only here, on a credentialed request; an uncredentialed (none) lock
        REFUSES to sign, so no client-IP header is ever emitted uncredentialed. ``client_ip`` MUST already be
        the broker's trusted edge value ("" when there is none)."""
        if self.method is LockMethod.HMAC:
            if not self.hmac_secret:
                raise BrokerRefused("hmac lock has no secret (fail-closed)")
            tag = hmac.new(self.hmac_secret, _auth_message(request_id, ts, client_ip),
                           hashlib.sha256).hexdigest()
            out = {HDR_ORIGIN_AUTH: f"v1={tag}", HDR_REQUEST_ID: request_id, HDR_TIMESTAMP: str(int(ts))}
            if client_ip:
                out[HDR_CLIENT_IP] = client_ip
            return out
        if self.method is LockMethod.SECRET_HEADER:
            if not (self.secret_header_name and self.secret_header_value):
                raise BrokerRefused("secret-header lock is not configured (fail-closed)")
            out = {self.secret_header_name: self.secret_header_value}
            if client_ip:
                out[HDR_CLIENT_IP] = client_ip
            return out
        if self.method is LockMethod.MTLS:
            # the client certificate authenticates at the TLS layer; the app-layer carries the trusted IP.
            return {HDR_CLIENT_IP: client_ip} if client_ip else {}
        raise BrokerRefused("an uncredentialed (none) lock cannot sign an origin-hop forward (fail-closed)")


def _auth_message(request_id: str, ts: int, client_ip: str) -> bytes:
    """The canonical, order-fixed HMAC message over (request id, ts, client-IP). Newline-separated so no field
    can be smuggled into another; ``int(ts)`` normalises the timestamp."""
    return f"{request_id}\n{int(ts)}\n{client_ip}".encode("utf-8")


def _header(headers: Mapping[str, str], name: str) -> str:
    """Case-insensitive header lookup (HTTP header names are case-insensitive); "" when absent."""
    low = name.lower()
    for key, value in headers.items():
        if key.lower() == low:
            return value
    return ""


def is_valid_edge_identity(client_ip: str) -> bool:
    """R15: loopback is NEVER edge identity. A loopback / unspecified / empty / unparseable source address is
    not a trustworthy edge-provided viewer IP (the real viewer address always arrives from the edge over the
    verified ``CloudFront-Viewer-Address``, never from the loopback hop between the front and the gateway), so
    it is refused as edge identity. Any other parseable literal is accepted as a candidate edge identity (its
    trust still requires ``edge_verified`` at the broker)."""
    raw = (client_ip or "").strip().strip("[]")
    if not raw:
        return False
    try:
        ip = ipaddress.ip_address(raw)
    except ValueError:
        return False
    return not (ip.is_loopback or ip.is_unspecified)


@dataclass(frozen=True)
class OriginLockVerdict:
    """The locked origin's answer to one request (and to a Z4/prover payload-free GET). ``status`` is 200 when
    the credential verifies (or there is no crypto lock to refuse), 401 when a crypto lock refuses an
    unauthenticated/invalid request. ``client_ip_trusted`` is True only on a credentialed 200 — the client-IP
    header is trusted ONLY on a credentialed request."""

    status: int
    reason: str
    client_ip: str = ""
    client_ip_trusted: bool = False


def origin_lock_verify(
    headers: Mapping[str, str],
    *,
    lock: OriginLock,
    now_ts: int,
    max_skew_s: int = DEFAULT_MAX_SKEW_S,
    mtls_client_verified: bool = False,
) -> OriginLockVerdict:
    """The origin-side verifier (what the tenant's locked origin runs, and what a Z3 prover / Z4 payload-free
    GET checks). Deterministic: the clock is INJECTED (``now_ts``), never read here. Fail-closed — any missing
    or mismatched credential on a crypto lock yields 401.

    * HMAC: requires ``X-Vigil-Origin-Auth`` (``v1=<hex>``), ``X-Vigil-Request-Id`` and ``X-Vigil-Timestamp``;
      the timestamp must be within ``max_skew_s`` of ``now_ts``, and the tag must match a constant-time HMAC
      over (request id, ts, client-IP). A valid tag TRUSTS the carried client IP.
    * secret header: a constant-time match of the configured secret header value.
    * mTLS: the TLS layer must have presented+verified the client certificate (``mtls_client_verified``).
    * none: there is no crypto lock — 200 but ``client_ip_trusted=False`` (an IP allowlist does not isolate
      SIGIL tenants, so the lock state stays ``none``/``ip_allowlist_only`` and a release is refused)."""
    if lock.method is LockMethod.HMAC:
        if not lock.hmac_secret:
            return OriginLockVerdict(401, "origin hmac lock misconfigured (no secret)")
        auth = _header(headers, HDR_ORIGIN_AUTH)
        rid = _header(headers, HDR_REQUEST_ID)
        ts_raw = _header(headers, HDR_TIMESTAMP)
        cip = _header(headers, HDR_CLIENT_IP)
        if not (auth and rid and ts_raw):
            return OriginLockVerdict(401, "missing origin-auth credential")
        if not auth.startswith("v1="):
            return OriginLockVerdict(401, "unknown origin-auth version")
        try:
            ts = int(ts_raw)
        except ValueError:
            return OriginLockVerdict(401, "malformed origin-auth timestamp")
        if abs(int(now_ts) - ts) > int(max_skew_s):
            return OriginLockVerdict(401, "origin-auth timestamp outside the accepted window")
        expected = hmac.new(lock.hmac_secret, _auth_message(rid, ts, cip), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(auth[3:], expected):
            return OriginLockVerdict(401, "origin-auth signature mismatch")
        return OriginLockVerdict(200, "origin-auth verified", client_ip=cip, client_ip_trusted=bool(cip))
    if lock.method is LockMethod.SECRET_HEADER:
        if not (lock.secret_header_name and lock.secret_header_value):
            return OriginLockVerdict(401, "origin secret-header lock misconfigured")
        presented = _header(headers, lock.secret_header_name)
        if not presented or not hmac.compare_digest(presented, lock.secret_header_value):
            return OriginLockVerdict(401, "secret-header credential missing or mismatched")
        cip = _header(headers, HDR_CLIENT_IP)
        return OriginLockVerdict(200, "secret-header verified", client_ip=cip, client_ip_trusted=bool(cip))
    if lock.method is LockMethod.MTLS:
        if not mtls_client_verified:
            return OriginLockVerdict(401, "mTLS client certificate not presented/verified")
        cip = _header(headers, HDR_CLIENT_IP)
        return OriginLockVerdict(200, "mTLS client verified", client_ip=cip, client_ip_trusted=bool(cip))
    # method none — no crypto lock. The request is not refused by a credential (there is none), but the client
    # IP is NOT trusted and the lock state never reaches crypto_verified (a release is refused upstream).
    return OriginLockVerdict(200, "origin has no crypto lock (ip-allowlist-only does not isolate tenants)",
                             client_ip="", client_ip_trusted=False)


def z4_payload_free_probe(
    lock: OriginLock,
    *,
    credential_headers: Optional[Mapping[str, str]] = None,
    now_ts: int,
    mtls_client_verified: bool = False,
) -> int:
    """A keyless, PAYLOAD-FREE GET a Z3 prover / Z4 check sends to confirm the origin lock state (B-4/B-5: Z2
    and Z3 send payload-free requests only; no attack payload). Returns the origin's HTTP status: an
    UNAUTHENTICATED probe against a crypto lock returns 401 (the lock is enforcing); a validly credentialed
    probe (or a lock with no crypto to refuse) returns 200."""
    return origin_lock_verify(credential_headers or {}, lock=lock, now_ts=now_ts,
                              mtls_client_verified=mtls_client_verified).status


@dataclass(frozen=True)
class BrokerTarget:
    """The resolved, egress-floor-validated origin for one tenant: the bound origin tuple, the pinned
    validated addresses to dial (never the re-resolvable name — anti-rebinding), the ``SNI``/cert name, and the
    grant's origin-binding hash (its full cross-check against the published ``aegis.origin_binding`` record is
    the Z3 prover's job, AS-2g)."""

    uid: str
    origin: OriginTuple
    sni: str
    addresses: tuple[str, ...]
    origin_binding_sha256: str


def resolve_broker_target(
    grant: MonitoringAuthorityV2,
    *,
    uid: str,
    resolver: Optional[Callable[..., Any]] = None,
) -> BrokerTarget:
    """Map the serving ``uid`` to the bound origin from the READ-ONLY signed grant and validate the egress.
    ENFORCES tenant isolation (the grant must bind the SAME org as ``uid``; a cross-tenant grant is refused, so
    one tenant can never be forwarded to another's origin). Runs the never-liftable L3/L4 floor over EVERY
    resolved origin address with ``allowed_ips=frozenset()`` and ``loopback_allowed_if_scoped=False`` — so a
    metadata/IMDS/link-local/RFC1918 origin, or loopback (never edge identity, R15), is refused; the origin is
    resolved ONCE and the pinned addresses returned for the dial (anti-rebinding). Raises :class:`BrokerRefused`
    on a cross-tenant grant, an unbound / non-https origin, or an egress-floor refusal. Deterministic given an
    injected ``resolver``."""
    if grant.subject.org_id != uid:
        raise BrokerRefused(
            f"cross-tenant: grant binds org {grant.subject.org_id!r}, this broker serves uid {uid!r}")
    origin = grant.origin
    if origin is None:
        raise BrokerRefused("grant declares no origin tuple — no forward target (fail-closed)")
    binding = (grant.origin_binding_sha256 or "").strip()
    if len(binding) != 64:
        raise BrokerRefused("grant origin is unbound (missing / malformed origin_binding_sha256)")
    if origin.scheme != "https":
        raise BrokerRefused(f"origin scheme must be https, got {origin.scheme!r}")
    try:
        addresses = resolve_and_validate_all(
            origin.host, origin.port, allowed_ips=frozenset(),
            loopback_allowed_if_scoped=False, resolver=resolver)
    except EgressFloorRefused as exc:
        raise BrokerRefused(f"origin egress refused by the never-liftable L3/L4 floor: {exc}") from exc
    return BrokerTarget(uid=uid, origin=origin, sni=origin.host, addresses=tuple(addresses),
                        origin_binding_sha256=binding)


@dataclass(frozen=True)
class ArmedBroker:
    """A broker that passed the §4.4 STARTUP REFUSAL: a validated forward target + the origin lock. Only an
    armed broker forwards."""

    target: BrokerTarget
    lock: OriginLock


def arm_broker(
    grant: MonitoringAuthorityV2,
    *,
    uid: str,
    lock: OriginLock,
    require_crypto_lock: bool = False,
    resolver: Optional[Callable[..., Any]] = None,
) -> ArmedBroker:
    """The broker STARTUP gate — the §4.4 "startup refusal", fail-closed. Resolves + validates the forward
    target (tenant isolation + egress floor), and when the deployment renders a RELEASE / enforcement
    (``require_crypto_lock``) requires the origin lock to be ``crypto_verified`` ("a release requires
    crypto_verified"; an IP allowlist does not isolate you from other SIGIL tenants). Raises
    :class:`BrokerStartupRefused` on any fail-closed condition rather than bringing the broker up."""
    try:
        target = resolve_broker_target(grant, uid=uid, resolver=resolver)
    except BrokerRefused as exc:
        raise BrokerStartupRefused(f"broker refused to start: {exc}") from exc
    if require_crypto_lock and not lock.crypto_verified:
        raise BrokerStartupRefused(
            "broker refused to start: a release requires a crypto-verified origin lock, but lock.state is "
            f"{lock.state.value!r} (an IP allowlist does not isolate you from other SIGIL tenants)")
    return ArmedBroker(target=target, lock=lock)


class BrokerTransport(Protocol):
    """The physical origin-hop transport: splice ``(headers, body)`` to the locked origin over the TARGET's
    pinned validated addresses with ``SNI = target.sni``, returning ``(status, body)``. Injected so the
    resolve/floor/lock composition is tested offline with no socket.

    The production transport is the hosted cell's TLS splice provisioned by AS-6a placement over the AS-26
    defense NAT EIPs and the central keyless origin-hop cert issuer; it re-validates + pins through the SAME
    ``common.egress_pin`` floor at dial time and fails closed to a 502 on any transport error (never a silent
    unguarded connect).

    VIGIL-LIMIT:AS2D-live-broker-transport — the live origin splice over the defense egress is deploy-gated on
    AS-26 infra (defense NAT EIPs + keyless origin-hop issuer); the resolve/floor/lock/compose plane here is
    exercised offline and the live leg is verified in the TT-STG account (AS-1b).
    """

    def __call__(self, target: BrokerTarget, headers: dict[str, str], body: bytes) -> tuple[int, bytes]:
        ...


@dataclass(frozen=True)
class BrokerForwardResult:
    """The outcome of one brokered forward: the origin's ``(status, body)``, the client IP the broker actually
    forwarded ("" when a forged/loopback/un-edge-verified IP was dropped), and the exact headers sent to the
    origin (so a test can prove a forged source IP never arrived)."""

    status: int
    body: bytes
    forwarded_client_ip: str
    sent_headers: dict[str, str]


def broker_forward(
    armed: ArmedBroker,
    *,
    request_id: str,
    ts: int,
    client_ip: str,
    edge_verified: bool,
    transport: BrokerTransport,
    body: bytes = b"",
    extra_headers: Optional[Mapping[str, str]] = None,
) -> BrokerForwardResult:
    """Forward one request through the armed broker to the locked origin. The client IP is carried to the
    origin (and, for HMAC, cryptographically BOUND) ONLY when it is a trustworthy edge identity:
    ``edge_verified`` (the front verified the per-tenant edge secret over the ``CloudFront-Viewer-Address``)
    AND a valid edge identity (R15: loopback is never edge identity). A forged client IP on an un-edge-verified
    or loopback hop is DROPPED — it never arrives at the origin. The broker is the SOLE setter of the lock /
    identity headers: any caller-supplied copy of them is stripped first. Deterministic: ``request_id`` and
    ``ts`` come from the request context. ``transport`` performs the TLS splice (injected)."""
    trusted_ip = client_ip if (edge_verified and is_valid_edge_identity(client_ip)) else ""
    reserved = {HDR_ORIGIN_AUTH.lower(), HDR_REQUEST_ID.lower(), HDR_TIMESTAMP.lower(), HDR_CLIENT_IP.lower()}
    # The lock's OWN credential header is reserved too: the broker is the sole setter of the secret-header
    # lock, so a caller-supplied copy of it (any case) is stripped before sign() applies the authentic value,
    # rather than riding alongside it as an ambiguous case-variant duplicate on the wire.
    if armed.lock.secret_header_name:
        reserved.add(armed.lock.secret_header_name.lower())
    headers: dict[str, str] = {
        k: v for k, v in (extra_headers or {}).items() if k.lower() not in reserved}
    headers.update(armed.lock.sign(request_id=request_id, ts=ts, client_ip=trusted_ip))
    status, resp = transport(armed.target, headers, body)
    return BrokerForwardResult(status=status, body=resp, forwarded_client_ip=trusted_ip, sent_headers=headers)
