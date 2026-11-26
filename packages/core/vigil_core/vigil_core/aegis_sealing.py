"""vigil_core.aegis_sealing — AS-2h: KMS+AAD sealing and ZERO-GAP rotation of the AEGIS secrets.

The lifecycle of the four AEGIS secrets SIGIL holds for a tenant — ``origin``, ``edge``, ``report`` and
``pseudonym`` — plus per-connector credentials. Each is a symmetric secret a managed gateway/unit uses to
authenticate what it emits (a report MAC, an origin binding), and SIGIL must be able to ROTATE any of them
WITHOUT dropping a single in-flight event. Today rotating the report secret "invalidates the deployed
gateway's copy: its reports stop verifying until redeployed" (``governor/monitoring_secrets.py``) — that
window is a real EVENT GAP, and this module closes it.

This slice is deliberately PURE (``vigil_core`` canonical, importable in BOTH planes, no I/O, no key custody,
deterministic on the sign/verify path), so SIGIL's offense-free import guarantee (FATAL-2) is unaffected. It
composes the already-shipped primitives rather than re-implementing crypto:

  * at-rest confidentiality + context binding — :mod:`vigil_core.sealing` (ChaCha20-Poly1305 AEAD).
  * KEK custody (TPM default, AWS-KMS envelope) — :mod:`vigil_core.kek_backends` (the KMS seam already
    exists; the real AWS CMK is owner-gated — see :class:`vigil_core.kek_backends.KmsKekBackend`).
  * proven KEK/DEK re-wrap for data AT REST — :mod:`vigil_core.rotation`.

What AS-2h ADDS on top of those:

  1. **AAD binding for the AEGIS secret kinds** (:func:`secret_aad`): every sealed secret bundle binds its
     ``(kind, org, scope, epoch)`` into the AEAD additional-authenticated-data, honouring the plan's
     connector convention ``aegis-conn\\0<org>\\0<conn>`` and extending it with an epoch component so a
     bundle from one kind/org/epoch can NEVER be opened as another — an **AAD mismatch fails closed**.
  2. **The zero-gap rotation state machine** (:class:`SecretRing`): a per-``(kind, org, scope)`` ring of
     epoch'd secrets with a designated CURRENT epoch (what new events are signed under) and an ACCEPT-SET
     (what a verifier still accepts). ``begin_rotation`` adds the fresh epoch as current while KEEPING the
     outgoing epoch in the accept-set — the OVERLAP — so no event is ever rejected across the cut (**no
     gap**). ``close_overlap`` drops the retired epochs; the **old secret is then REFUSED**.
  3. **The AS-6a delivery seam** (:class:`SecretDelivery` / :func:`deliver_bundle`): the contract the fleet
     reconciler (AS-6a, not yet built) implements to push a sealed :class:`SecretBundle` to the units. It is
     STUBBED here and DEFAULT-OFF: with the flag unset it performs no delivery and returns a fail-closed
     ``deferred`` receipt — it never claims a secret was delivered.

Determinism: the sign/verify path uses HMAC-SHA256 and reads NO wall-clock and NO RNG; whether a given epoch
is accepted is a pure function of the ring's state. The at-rest seal uses :mod:`vigil_core.sealing`'s random
AEAD nonce (confidentiality at rest, exactly as that module already does) — that is not an ordering/signed
path. Fail-closed throughout: every guard defaults to REFUSE, and a verify of an unaccepted epoch returns
False rather than raising.

FATAL-2: imports only :mod:`vigil_core.sealing` + the stdlib. No ``sigil``, no ``framework``.
"""
from __future__ import annotations

import hashlib
import hmac
import os
from dataclasses import dataclass
from enum import Enum
from typing import Optional, Protocol, runtime_checkable

from .sealing import seal, unseal

__all__ = [
    "SecretKind", "SealingError", "secret_aad", "connector_aad",
    "SealedSecret", "seal_secret", "open_secret", "open_secret_as",
    "secret_mac", "SecretRing",
    "SecretBundle", "DeliveryReceipt", "SecretDelivery", "DeferredDelivery",
    "SEALING_DELIVER_ENV", "delivery_enabled", "build_bundle", "deliver_bundle",
]

_MAX_COMPONENT = 256          # a bound on org / scope so an AAD / manifest stays small and non-adversarial
_MIN_SECRET = 16             # a secret shorter than this is rejected (too weak to key a MAC / seal)


class SealingError(Exception):
    """A sealing/rotation CONTRACT was violated and the operation was REFUSED (fail-closed): a bad kind/org/
    scope/epoch, a non-monotone or reused rotation epoch, a no-op rotation, or signing with no active secret.
    Distinct from :class:`vigil_core.sealing.SealError` (an AEAD open failure). Leaks no secret material."""


class SecretKind(str, Enum):
    """The AEGIS secret kinds SIGIL seals, rotates and delivers. The value IS the AEAD domain label — the
    first NUL-separated field of every bundle's additional-authenticated-data — so a blob sealed as one kind
    can never open as another. ``origin``/``edge``/``report``/``pseudonym`` are the four SIGIL holds per
    tenant; ``connector`` is a per-connector provider credential (broker, AS-9a)."""

    ORIGIN = "aegis-origin"
    EDGE = "aegis-edge"
    REPORT = "aegis-report"
    PSEUDONYM = "aegis-pseudonym"
    CONNECTOR = "aegis-conn"


def _check_kind(kind: SecretKind) -> SecretKind:
    if not isinstance(kind, SecretKind):
        raise SealingError("kind must be a SecretKind")
    return kind


def _check_component(value: str, what: str, *, allow_empty: bool) -> str:
    if not isinstance(value, str):
        raise SealingError(f"{what} must be a str")
    if "\x00" in value:
        # a NUL in a component would let two logical (org, scope) pairs collide in the NUL-separated AAD.
        raise SealingError(f"{what} must not contain a NUL byte")
    if len(value) > _MAX_COMPONENT:
        raise SealingError(f"{what} is too long (max {_MAX_COMPONENT} chars)")
    if not allow_empty and not value:
        raise SealingError(f"{what} must not be empty")
    return value


def _check_epoch(epoch: int) -> int:
    # bool is an int subclass — reject it explicitly so a stray True/False cannot masquerade as an epoch.
    if not isinstance(epoch, int) or isinstance(epoch, bool) or epoch < 0:
        raise SealingError("epoch must be a non-negative int")
    return epoch


def secret_aad(kind: SecretKind, org: str, scope: str = "", *, epoch: Optional[int] = None) -> bytes:
    """The additional-authenticated-data that binds a sealed AEGIS secret to its ``(kind, org, scope, epoch)``.

    ``<kind-label>\\0<org>\\0<scope>`` (NUL-separated; NUL is rejected inside a component so the fielding is
    unambiguous), optionally suffixed with ``\\0e<epoch>`` when ``epoch`` is given. With ``epoch=None`` for a
    connector this is exactly the plan's ``aegis-conn\\0<org>\\0<conn>`` convention; the epoch suffix is the
    AS-2h rotation binding that lets a verifier distinguish one epoch's bundle from the next. ``scope`` may be
    empty for a tenant-wide secret (e.g. the pseudonym key)."""
    _check_kind(kind)
    _check_component(org, "org", allow_empty=False)
    _check_component(scope, "scope", allow_empty=True)
    base = kind.value.encode("ascii") + b"\x00" + org.encode("utf-8") + b"\x00" + scope.encode("utf-8")
    if epoch is None:
        return base
    return base + b"\x00e" + str(_check_epoch(epoch)).encode("ascii")


def connector_aad(org: str, conn: str, *, epoch: Optional[int] = None) -> bytes:
    """The connector-credential AAD ``aegis-conn\\0<org>\\0<conn>`` (plan convention), with the optional
    AS-2h ``\\0e<epoch>`` rotation suffix. A thin, named alias of :func:`secret_aad` for the broker path."""
    return secret_aad(SecretKind.CONNECTOR, org, conn, epoch=epoch)


def _check_secret(secret: bytes) -> bytes:
    if not isinstance(secret, (bytes, bytearray)):
        raise SealingError("secret must be bytes")
    if len(secret) < _MIN_SECRET:
        raise SealingError(f"secret must be at least {_MIN_SECRET} bytes")
    return bytes(secret)


@dataclass(frozen=True)
class SealedSecret:
    """One AEGIS secret, AEAD-sealed under the KEK and bound to its ``(kind, org, scope, epoch)``. ``blob`` is
    the self-describing output of :func:`vigil_core.sealing.seal`; the four binding fields are carried in the
    clear only to RECOMPUTE the AAD on open — tampering with any of them changes the AAD and the open
    fails closed, so they are integrity-protected by the AEAD, not trusted."""

    kind: SecretKind
    org: str
    scope: str
    epoch: int
    blob: bytes


def seal_secret(kek: bytes, kind: SecretKind, org: str, scope: str, epoch: int, secret: bytes) -> SealedSecret:
    """Seal ``secret`` under ``kek`` (32 bytes), binding ``(kind, org, scope, epoch)`` into the AEAD AAD.
    The KEK comes from the chosen custody backend (TPM / AWS-KMS envelope — see
    :mod:`vigil_core.kek_backends`); this module never holds it. Raises :class:`SealingError` on a bad
    binding/secret (the KEK itself is validated by :func:`vigil_core.sealing.seal`)."""
    _check_kind(kind)
    _check_component(org, "org", allow_empty=False)
    _check_component(scope, "scope", allow_empty=True)
    _check_epoch(epoch)
    _check_secret(secret)
    blob = seal(kek, bytes(secret), context=secret_aad(kind, org, scope, epoch=epoch))
    return SealedSecret(kind=kind, org=org, scope=scope, epoch=epoch, blob=blob)


def open_secret(kek: bytes, sealed: SealedSecret) -> bytes:
    """Open a :class:`SealedSecret` under ``kek``, re-deriving the AAD from its OWN binding fields. Raises
    :class:`vigil_core.sealing.SealError` on any tamper / wrong-KEK / altered-binding (an **AAD mismatch
    fails closed**) — it never returns a secret that was not sealed under exactly this KEK and binding."""
    if not isinstance(sealed, SealedSecret):
        raise SealingError("open_secret expects a SealedSecret")
    aad = secret_aad(sealed.kind, sealed.org, sealed.scope, epoch=sealed.epoch)
    return unseal(kek, sealed.blob, context=aad)


def open_secret_as(kek: bytes, blob: bytes, kind: SecretKind, org: str, scope: str, *, epoch: int) -> bytes:
    """Open a raw sealed ``blob`` under a CALLER-ASSERTED ``(kind, org, scope, epoch)`` binding. Used by a
    consumer that knows which secret it expects (and by the negative-control tests): if the asserted binding
    is not the one the blob was sealed under, the AEAD open **fails closed** with
    :class:`vigil_core.sealing.SealError`."""
    aad = secret_aad(_check_kind(kind), org, scope, epoch=epoch)
    return unseal(kek, blob, context=aad)


def secret_mac(secret: bytes, kind: SecretKind, org: str, scope: str, epoch: int, payload: bytes) -> bytes:
    """A domain-separated HMAC-SHA256 of ``payload`` under ``secret`` for one ``(kind, org, scope, epoch)``.

    The message is ``sha256(aad) || payload`` (a fixed-length 32-byte context prefix, so no (context, payload)
    pair is ambiguous), keyed by the operational ``secret``. PURE and deterministic — no clock, no RNG — so a
    gateway and the sovereign drainer compute byte-identical tags, and a tag made under one epoch/kind/org can
    never validate under another."""
    _check_kind(kind)
    if not isinstance(secret, (bytes, bytearray)):
        raise SealingError("secret must be bytes")
    if not isinstance(payload, (bytes, bytearray)):
        raise SealingError("payload must be bytes")
    ctx = secret_aad(kind, org, scope, epoch=epoch)
    msg = hashlib.sha256(ctx).digest() + bytes(payload)
    return hmac.new(bytes(secret), msg, hashlib.sha256).digest()


class SecretRing:
    """The zero-gap rotation state machine for ONE ``(kind, org, scope)`` secret.

    It holds the operational (unsealed) secret for each live epoch, a single CURRENT epoch that new events
    are signed under, and an ACCEPT-SET of epochs a verifier still honours. The invariant that gives "no
    event gap": ``current_epoch`` is ALWAYS in the accept-set, and :meth:`begin_rotation` adds the fresh
    epoch to the accept-set BEFORE (atomically with) making it current while leaving the outgoing epoch in
    the set — so at no instant is an in-flight event's epoch unaccepted. :meth:`close_overlap` is the only
    operation that removes acceptance, and it can never remove the current epoch.

    Every transition is fail-closed: a non-monotone or reused epoch, a no-op (same-secret) rotation, or an
    attempt to retire the live epoch is REFUSED with :class:`SealingError`, leaving the ring unchanged."""

    __slots__ = ("_kind", "_org", "_scope", "_secrets", "_accept", "_current")

    def __init__(self, kind: SecretKind, org: str, scope: str = "") -> None:
        self._kind = _check_kind(kind)
        self._org = _check_component(org, "org", allow_empty=False)
        self._scope = _check_component(scope, "scope", allow_empty=True)
        self._secrets: dict[int, bytes] = {}
        self._accept: set[int] = set()
        self._current: Optional[int] = None

    # --- introspection ---------------------------------------------------------------------------
    @property
    def kind(self) -> SecretKind:
        return self._kind

    @property
    def org(self) -> str:
        return self._org

    @property
    def scope(self) -> str:
        return self._scope

    @property
    def current_epoch(self) -> int:
        if self._current is None:
            raise SealingError("ring has no active secret (call activate first)")
        return self._current

    @property
    def accepted_epochs(self) -> frozenset[int]:
        """The epochs a verifier currently accepts. During an overlap this holds BOTH the outgoing and the
        incoming epoch; after :meth:`close_overlap` it narrows toward just the current epoch."""
        return frozenset(self._accept)

    def is_accepted(self, epoch: int) -> bool:
        return epoch in self._accept

    def in_overlap(self) -> bool:
        """True iff more than one epoch is currently accepted — i.e. a rotation is mid-overlap."""
        return len(self._accept) > 1

    def secret_at(self, epoch: int) -> bytes:
        """The operational secret for an ACCEPTED ``epoch`` (used to seal it for delivery). Fail-closed:
        raises :class:`SealingError` for an epoch that is not currently accepted (retired / never present),
        so a caller can never seal and ship a secret the ring no longer honours."""
        if epoch not in self._accept or epoch not in self._secrets:
            raise SealingError(f"epoch {epoch} is not an accepted epoch of this ring")
        return self._secrets[epoch]

    # --- lifecycle -------------------------------------------------------------------------------
    def activate(self, epoch: int, secret: bytes) -> None:
        """Install the FIRST secret (genesis): sets it current and the sole accepted epoch. Refuses if the
        ring already has an active secret (use :meth:`begin_rotation` to rotate)."""
        _check_epoch(epoch)
        _check_secret(secret)
        if self._current is not None:
            raise SealingError("ring is already active — use begin_rotation to rotate")
        self._secrets[epoch] = bytes(secret)
        self._accept = {epoch}
        self._current = epoch

    def begin_rotation(self, new_epoch: int, new_secret: bytes) -> None:
        """Open an overlap: install ``new_secret`` at ``new_epoch``, make it current, and KEEP the outgoing
        epoch(s) accepted so no in-flight event is rejected across the cut (the no-gap property).

        Fail-closed guards (all leave the ring unchanged): the ring must be active; ``new_epoch`` must be
        strictly greater than the current epoch (monotone) and not a reused epoch; ``new_secret`` must differ
        from the current secret (a same-secret rotation is a no-op, not a rotation)."""
        _check_epoch(new_epoch)
        _check_secret(new_secret)
        if self._current is None:
            raise SealingError("ring has no active secret (call activate first)")
        if new_epoch <= self._current:
            raise SealingError(f"rotation epoch {new_epoch} must be strictly greater than the current "
                               f"epoch {self._current} (monotone)")
        if new_epoch in self._secrets:
            raise SealingError(f"rotation epoch {new_epoch} is already in the ring (no reuse)")
        if hmac.compare_digest(bytes(new_secret), self._secrets[self._current]):
            raise SealingError("refusing to rotate to the SAME secret — that is a no-op, not a rotation")
        self._secrets[new_epoch] = bytes(new_secret)
        self._accept.add(new_epoch)      # incoming accepted…
        # …outgoing stays accepted (it already is): the overlap. current advances last, atomically here.
        self._current = new_epoch

    def close_overlap(self, *, retire_below: Optional[int] = None) -> tuple[int, ...]:
        """Close the overlap: stop accepting (and forget the secret for) every epoch strictly below the
        floor, so the **old secret is then refused**. The floor defaults to the current epoch (retire
        everything older); pass ``retire_below`` to retire only part of a multi-step overlap. The current
        epoch can NEVER be retired (``retire_below`` above it is refused). Returns the retired epochs."""
        if self._current is None:
            raise SealingError("ring has no active secret")
        floor = self._current if retire_below is None else _check_epoch(retire_below)
        if floor > self._current:
            raise SealingError(f"refusing to retire at/above the current epoch {self._current} "
                               "(that would drop the live secret and OPEN a gap)")
        retired = tuple(sorted(e for e in self._accept if e < floor))
        for e in retired:
            self._accept.discard(e)
            self._secrets.pop(e, None)
        return retired

    # --- sign / verify (deterministic) -----------------------------------------------------------
    def sign(self, payload: bytes) -> tuple[int, bytes]:
        """MAC ``payload`` under the CURRENT epoch's secret. Returns ``(epoch, tag)`` so a verifier knows
        which epoch to check. Deterministic (HMAC-SHA256); no clock, no RNG."""
        if self._current is None:
            raise SealingError("ring has no active secret (call activate first)")
        cur = self._current
        tag = secret_mac(self._secrets[cur], self._kind, self._org, self._scope, cur, payload)
        return cur, tag

    def verify(self, payload: bytes, epoch: int, tag: bytes) -> bool:
        """True iff ``tag`` is the valid MAC of ``payload`` under ``epoch`` AND ``epoch`` is still accepted.

        An epoch NOT in the accept-set is refused outright (the retired-secret case) WITHOUT a constant-time
        compare — acceptance is a pure set-membership check, carrying no secret. For an accepted epoch the
        tag is compared in constant time. Total: any malformed input returns False, never raises."""
        if not isinstance(tag, (bytes, bytearray)):
            return False
        if epoch not in self._accept or epoch not in self._secrets:
            return False
        try:
            expected = secret_mac(self._secrets[epoch], self._kind, self._org, self._scope, epoch, payload)
        except SealingError:
            return False
        return hmac.compare_digest(expected, bytes(tag))


# ======================================================================================================
# Delivery seam to the AS-6a fleet reconciler — STUBBED + DEFAULT-OFF (AS-6a not yet built)
# ======================================================================================================
@dataclass(frozen=True)
class SecretBundle:
    """What AS-6a delivers to a unit in one shot: the KEK-sealed secrets for a ``(org, scope)`` across every
    accepted epoch, plus the accept manifest (which epoch is current and which are still accepted). The unit
    installs each as a ``LoadCredential``; the manifest lets the unit/drainer honour the SAME overlap the
    sovereign :class:`SecretRing` holds, so rotation stays gap-free end to end."""

    kind: SecretKind
    org: str
    scope: str
    current_epoch: int
    accepted_epochs: tuple[int, ...]
    sealed: tuple[SealedSecret, ...]


@dataclass(frozen=True)
class DeliveryReceipt:
    """The outcome of a delivery attempt. ``delivered`` is True ONLY when a real seam confirmed the bundle
    reached the units; otherwise it is False and ``status`` says why (``deferred`` when AS-6a is not wired,
    ``refused`` when a seam declined). Fail-closed: a caller treats anything but ``delivered is True`` as
    'not yet on the unit' and does not close the overlap."""

    delivered: bool
    status: str
    detail: str


@runtime_checkable
class SecretDelivery(Protocol):
    """The contract the AS-6a fleet reconciler implements to push a :class:`SecretBundle` to the units it
    places. Defined here (engine-free) so the sovereign side can hand it bundles without importing the
    fleet. Not yet implemented — see :class:`DeferredDelivery`."""

    def deliver(self, bundle: SecretBundle) -> DeliveryReceipt: ...


class DeferredDelivery:
    """The default seam while AS-6a is unbuilt: it performs NO delivery and returns a fail-closed ``deferred``
    receipt. It never claims a secret reached a unit, so a caller can honestly report the delivery leg as
    pending/owner-gated rather than silently assume success."""

    def deliver(self, bundle: SecretBundle) -> DeliveryReceipt:
        return DeliveryReceipt(
            delivered=False, status="deferred",
            detail="AS-6a fleet reconciler not yet built — secret bundle staged, not delivered",
        )


SEALING_DELIVER_ENV = "VIGIL_AEGIS_SEALING_DELIVER"


def delivery_enabled() -> bool:
    """The AS-2h delivery flag — strict, fail-closed, DEFAULT OFF (mirrors the gateway's
    ``_saas_enforce_flag``). Only an explicit affirmative token enables an attempt through an injected real
    seam; anything else (unset, typo, empty) keeps delivery off and every bundle ``deferred``."""
    return (os.environ.get(SEALING_DELIVER_ENV) or "").strip().lower() in ("1", "true", "yes", "on")


def build_bundle(ring: SecretRing, kek: bytes) -> SecretBundle:
    """Seal every ACCEPTED epoch of ``ring`` under ``kek`` (KMS/TPM custody is the caller's) into a
    deliverable :class:`SecretBundle`, carrying the ring's current/accepted manifest. Pure: it reads the
    ring and seals; it does not deliver. The sealed blobs each carry their ``(kind, org, scope, epoch)``
    AAD binding, so a bundle meant for one tenant/kind can never be opened as another."""
    accepted = tuple(sorted(ring.accepted_epochs))
    sealed = tuple(
        seal_secret(kek, ring.kind, ring.org, ring.scope, e, ring.secret_at(e))
        for e in accepted
    )
    return SecretBundle(
        kind=ring.kind, org=ring.org, scope=ring.scope,
        current_epoch=ring.current_epoch, accepted_epochs=accepted, sealed=sealed,
    )


def deliver_bundle(bundle: SecretBundle, delivery: Optional[SecretDelivery] = None) -> DeliveryReceipt:
    """Deliver a sealed ``bundle`` to the units via the AS-6a seam — DEFAULT-OFF and fail-closed.

    With the :func:`delivery_enabled` flag off (the default) OR no real seam injected, this performs NO
    delivery and returns the :class:`DeferredDelivery` ``deferred`` receipt — byte-identical to doing
    nothing, which is the honest state while AS-6a is unbuilt. Only when the flag is on AND a real seam is
    supplied is the bundle handed to that seam."""
    if not delivery_enabled() or delivery is None:
        return DeferredDelivery().deliver(bundle)
    return delivery.deliver(bundle)
