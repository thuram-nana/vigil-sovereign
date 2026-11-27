"""aegis.connector_secrets — AS-9a: the CONNECTOR-SECRETS BROKER (Domain 5, ingest/receiver).

A connector is an OUTBOUND integration a tenant's managed defence authenticates to — a SIEM/notify
sink (AS-20), an EDR provider (AS-10b), a CloudTrail/provider reader (AS-17b/AS-10a). Each needs a
per-connector credential to speak to that sink: a bearer token, an API-key header, or an HMAC body
signature. SIGIL already SEALS those credentials (AS-2h: ``SecretKind.CONNECTOR`` / ``connector_aad``,
``aegis-conn\\0<org>\\0<conn>``) and ROTATES them gap-free (``aegis_sealing.SecretRing``). This slice is
the BROKER that stands between a registered connector *consumer* and its sealed credential — the runtime
piece AS-2h named ("``connector`` is a per-connector provider credential (broker, AS-9a)").

"Wire, don't rebuild" (plan §9.1 rule 10): the broker composes the shipped substrate — the AS-2h sealing
primitives (``open_secret``), the AS-2a authority contract (``MonitoringAuthorityV2`` — tenant isolation,
grant window, epoch) and the shared redaction helpers — rather than minting its own crypto or key custody.

Two planes, and the secret only ever crosses the second one:

  * The REFERENCE plane (:meth:`ConnectorSecretBroker.issue`) is PURE and always safe: it validates
    authority + registration and returns a value-free :class:`ConnectorHandle` carrying only references
    (org, connector id, scheme, epoch, a non-reversible ``secret_ref`` fingerprint, a lease). A handle is
    what is written to a log, a report, or the event spine — it holds NO credential, by construction.
  * The MATERIALISATION plane (:meth:`ConnectorSecretBroker.authorize` / :meth:`stamp`) is the only place a
    plaintext credential exists. It opens the sealed secret transiently into a ``bytearray``, derives the
    outbound auth material, ZEROISES the plaintext, and returns a :class:`ConnectorAuth` that is
    self-redacting and NON-SERIALISABLE — it can only be ``apply``-ed onto an outbound request's headers
    (single-use), never logged, pickled, JSON-dumped, or returned as a bare value.

NO-SECRET-LEAK (this is a secrets broker on a PUBLIC repo): a credential value never reaches a log, a
report, the event spine, a handle, a receipt, or an error message. Handles/receipts are value-free;
``ConnectorAuth`` redacts its ``repr``/``str`` and refuses pickling; errors name the org/connector/
``secret_ref`` only. No real secret, secret-shaped fixture, or weakness matrix is committed — tests seal
test-only bytes under a test KEK at runtime.

DETERMINISM: every decision is a pure function of its inputs + an INJECTED ``now`` — no wall-clock, no RNG
on any auth/ordering path (the fingerprint is SHA-256, the HMAC signature is HMAC-SHA256; the at-rest AEAD
nonce belongs to AS-2h's seal, done upstream, not to this open path). FAIL-CLOSED throughout: a
cross-tenant grant, an inactive grant, an unregistered connector, a stale handle, or a missing/mismatched
sealed secret is REFUSED, never a silent pass.

DEFAULT-OFF: materialisation is gated behind ``VIGIL_AEGIS_CONNECTOR_BROKER`` (the ``_saas_enforce_flag``
discipline — strict, fail-closed, DEFAULT OFF). With the flag off the broker opens NO plaintext: the
reference plane still issues handles, but :meth:`authorize`/:meth:`stamp` refuse inert. Nothing under
``aegis/__init__`` or ``framework.v2.__main__`` imports this module (off the gate path, like ``broker`` and
``job_runner``), so ``make gate`` stays byte-identical; its tests import it directly.

FATAL-2: engine leg — imports only ``vigil_core`` (the shared sealing + authority contracts), the stdlib,
and the framework-internal ``..common`` redaction/logging helpers; nothing from ``sigil`` / ``governor``.
"""

from __future__ import annotations

import hashlib
import hmac
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import MutableMapping, NoReturn, Optional, Protocol, runtime_checkable

from vigil_core.aegis_sealing import (
    SealedSecret,
    SecretKind,
    connector_aad,
    open_secret,
)
from vigil_core.authority_v2 import MonitoringAuthorityV2
from vigil_core.sealing import SealError

from ..common.logging import get_logger

__all__ = [
    "CONNECTOR_BROKER_ENV",
    "connector_broker_enabled",
    "ConnectorScheme",
    "ConnectorBrokerRefused",
    "ConnectorBrokerDisabled",
    "ConnectorConsumer",
    "ConsumerRegistry",
    "KekSource",
    "SealedConnectorStore",
    "ConnectorHandle",
    "ConnectorAuth",
    "ConnectorReceipt",
    "ConnectorSecretBroker",
    "connector_secret_ref",
]

_log = get_logger("aegis.connector_secrets")

# The DEFAULT-OFF switch that ARMS the live materialisation plane (strict, fail-closed, read per call;
# mirrors ``broker.BROKER_ENV`` and ``job_runner.JOBS_ENV``). OFF ⇒ the broker opens no plaintext; only the
# pure reference plane (``issue``) runs.
CONNECTOR_BROKER_ENV = "VIGIL_AEGIS_CONNECTOR_BROKER"

_MAX_COMPONENT = 256  # a bound on org / connector ids so a handle / AAD stays small and non-adversarial
_FINGERPRINT_CHARS = 16  # how many hex chars of the SHA-256 AAD digest a secret_ref carries (non-reversible)


def connector_broker_enabled() -> bool:
    """Is the LIVE materialisation plane armed? Strict, fail-closed, DEFAULT OFF — only an explicit
    affirmative token arms it. The reference plane (:meth:`ConnectorSecretBroker.issue`) does NOT consult
    this flag (it opens no secret and is always safe); only the plaintext-opening path does."""
    return (os.environ.get(CONNECTOR_BROKER_ENV) or "").strip().lower() in ("1", "true", "yes", "on")


class ConnectorScheme(str, Enum):
    """How a connector's credential authenticates the OUTBOUND request to its sink.

    * ``HMAC_SIGNATURE`` — the credential keys an HMAC-SHA256 over the request body; the broker emits only a
      ``v1=<tag>`` signature header, so the secret itself NEVER leaves the broker (the strongest mode).
    * ``BEARER`` — ``Authorization: Bearer <secret>`` (e.g. a Splunk HEC token).
    * ``HEADER_KEY`` — a custom header carries the key verbatim (e.g. an API-key header).

    For ``BEARER``/``HEADER_KEY`` the emitted header value IS the credential; it lives only inside the
    non-serialisable :class:`ConnectorAuth` until :meth:`ConnectorAuth.apply` stamps it onto the outbound
    request and clears it."""

    HMAC_SIGNATURE = "hmac_signature"
    BEARER = "bearer"
    HEADER_KEY = "header_key"


class ConnectorBrokerRefused(Exception):
    """The broker refused a request fail-closed (cross-tenant/inactive grant, unregistered connector, stale
    handle, missing/mismatched sealed secret, or a spent/non-serialisable auth). Never a silent pass; its
    message names the org/connector/``secret_ref`` only — never a credential value."""


class ConnectorBrokerDisabled(ConnectorBrokerRefused):
    """Materialisation was asked for while the broker is DEFAULT-OFF (``VIGIL_AEGIS_CONNECTOR_BROKER`` unset).
    Raised BEFORE any sealed secret is opened, so an un-armed build never touches plaintext."""


def _as_utc(dt: datetime) -> datetime:
    """Normalise to an aware UTC datetime; a naive datetime is read as UTC (never silently local)."""
    return dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt.astimezone(timezone.utc)


def _check_component(value: object, *, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise ConnectorBrokerRefused(f"{label} must be a non-empty str")
    if "\x00" in value:
        # a NUL would let two logical (org, connector) pairs collide in the NUL-separated connector AAD.
        raise ConnectorBrokerRefused(f"{label} must not contain a NUL byte")
    if len(value) > _MAX_COMPONENT:
        raise ConnectorBrokerRefused(f"{label} is too long (max {_MAX_COMPONENT} chars)")
    return value


def connector_secret_ref(org: str, connector_id: str, epoch: int) -> str:
    """A non-reversible, deterministic fingerprint of a connector credential's identity — the SHA-256 of its
    AS-2h ``(connector) AAD`` at ``epoch``, truncated. It CORRELATES a handle/receipt/log line to one sealed
    credential (so an operator can trace a rotation) WITHOUT carrying any secret bytes. Pure: no clock, no
    RNG."""
    _check_component(org, label="org")
    _check_component(connector_id, label="connector_id")
    if not isinstance(epoch, int) or isinstance(epoch, bool) or epoch < 0:
        raise ConnectorBrokerRefused("epoch must be a non-negative int")
    digest = hashlib.sha256(connector_aad(org, connector_id, epoch=epoch)).hexdigest()
    return digest[:_FINGERPRINT_CHARS]


@dataclass(frozen=True)
class ConnectorConsumer:
    """One REGISTERED connector consumer: which ``(org, connector_id)`` is allowed a credential, by which
    :class:`ConnectorScheme`, and into which outbound header. Immutable; carries NO secret — only the shape
    of how the (separately sealed) credential is applied. ``scope`` is the connector id used as the AS-2h
    connector-AAD scope, so a credential sealed for connector X can never be applied as connector Y."""

    org: str
    connector_id: str
    scheme: ConnectorScheme
    header_name: str

    def __post_init__(self) -> None:
        _check_component(self.org, label="org")
        _check_component(self.connector_id, label="connector_id")
        if not isinstance(self.scheme, ConnectorScheme):
            raise ConnectorBrokerRefused("scheme must be a ConnectorScheme")
        _check_component(self.header_name, label="header_name")

    @property
    def scope(self) -> str:
        """The AS-2h connector-AAD scope for this consumer (the connector id)."""
        return self.connector_id


class ConsumerRegistry:
    """The CONSUMER REGISTRY the broker stands on (FORGE map: AS-9a is "on consumer registry"). An ALLOWLIST
    of registered connector consumers keyed by ``(org, connector_id)`` — a connector that is not registered
    for an org can never obtain that org's credential (fail-closed), which blocks a confused-deputy ask for
    connector X's secret under a grant that only names the org. Registration is append-only-per-identity:
    re-registering the SAME ``(org, connector_id)`` is refused unless the record is byte-identical (no silent
    edit of a consumer's scheme/header out from under an issued handle)."""

    __slots__ = ("_by_key",)

    def __init__(self) -> None:
        self._by_key: dict[tuple[str, str], ConnectorConsumer] = {}

    def register(self, consumer: ConnectorConsumer) -> None:
        if not isinstance(consumer, ConnectorConsumer):
            raise ConnectorBrokerRefused("register expects a ConnectorConsumer")
        key = (consumer.org, consumer.connector_id)
        existing = self._by_key.get(key)
        if existing is not None and existing != consumer:
            raise ConnectorBrokerRefused(
                f"connector {consumer.connector_id!r} is already registered for org {consumer.org!r} "
                "with a different scheme/header (append-only: supersede, never edit)")
        self._by_key[key] = consumer

    def get(self, org: str, connector_id: str) -> Optional[ConnectorConsumer]:
        return self._by_key.get((org, connector_id))

    def require(self, org: str, connector_id: str) -> ConnectorConsumer:
        """The registered consumer, or a fail-closed refusal (an unregistered connector is never brokered)."""
        consumer = self._by_key.get((org, connector_id))
        if consumer is None:
            raise ConnectorBrokerRefused(
                f"connector {connector_id!r} is not a registered consumer for org {org!r} (fail-closed)")
        return consumer


@runtime_checkable
class KekSource(Protocol):
    """The KEK-custody seam: hand back the 32-byte key-encryption key for an org's connector credentials.
    Injected so the broker never holds a KEK on ``self`` and the open path is tested offline with a fixed
    key. Production supplies the real TPM/AWS-KMS backend (``vigil_core.kek_backends``); the broker fetches
    per :meth:`ConnectorSecretBroker.authorize` and discards."""

    def kek_for(self, org: str) -> bytes: ...


class SealedConnectorStore:
    """An APPEND-ONLY store of sealed per-connector credentials, keyed by ``(org, connector_id)`` and
    versioned by AS-2h epoch. It holds only AEAD-sealed :class:`SealedSecret` blobs (no plaintext, no KEK);
    :meth:`put` SUPERSEDES with a strictly-greater epoch and REFUSES to edit an existing epoch (append-only:
    supersede, never edit), so a handle issued against the current epoch is detectably stale once a rotation
    lands. :meth:`current` returns the highest-epoch sealed secret."""

    __slots__ = ("_by_key",)

    def __init__(self) -> None:
        self._by_key: dict[tuple[str, str], dict[int, SealedSecret]] = {}

    def put(self, sealed: SealedSecret) -> None:
        if not isinstance(sealed, SealedSecret):
            raise ConnectorBrokerRefused("put expects a SealedSecret")
        if sealed.kind is not SecretKind.CONNECTOR:
            raise ConnectorBrokerRefused(
                f"connector store holds only {SecretKind.CONNECTOR.value!r} secrets, got {sealed.kind.value!r}")
        key = (sealed.org, sealed.scope)
        epochs = self._by_key.setdefault(key, {})
        if sealed.epoch in epochs:
            raise ConnectorBrokerRefused(
                f"epoch {sealed.epoch} already stored for connector {sealed.scope!r} (append-only, no edit)")
        if epochs and sealed.epoch <= max(epochs):
            raise ConnectorBrokerRefused(
                f"epoch {sealed.epoch} must be strictly greater than the current epoch {max(epochs)} "
                "(monotone supersede)")
        epochs[sealed.epoch] = sealed

    def current(self, org: str, connector_id: str) -> SealedSecret:
        """The highest-epoch sealed credential for a connector, or a fail-closed refusal if none is stored."""
        epochs = self._by_key.get((org, connector_id))
        if not epochs:
            raise ConnectorBrokerRefused(
                f"no sealed credential stored for connector {connector_id!r} of org {org!r} (fail-closed)")
        return epochs[max(epochs)]


@dataclass(frozen=True)
class ConnectorHandle:
    """The value-FREE reference a broker issues: enough to identify and later redeem a connector credential,
    carrying NO secret bytes. This is the object safe to log, put in a report, or append to the event spine.
    ``secret_ref`` is the non-reversible fingerprint (:func:`connector_secret_ref`); ``epoch`` pins the
    credential version so a rotation makes the handle detectably stale; ``lease_not_after`` bounds how long
    the handle may be redeemed."""

    org: str
    connector_id: str
    scheme: ConnectorScheme
    epoch: int
    header_name: str
    secret_ref: str
    lease_not_after: datetime

    def lease_live(self, now: datetime) -> bool:
        """True iff the handle may still be redeemed at ``now`` (``now < lease_not_after``; injected clock)."""
        return _as_utc(now) < _as_utc(self.lease_not_after)

    def redacted(self) -> dict[str, str]:
        """A value-free dict for recording into a log/report/spine — by construction it holds no credential."""
        return {
            "org": self.org,
            "connector_id": self.connector_id,
            "scheme": self.scheme.value,
            "epoch": str(self.epoch),
            "secret_ref": self.secret_ref,
            "header_name": self.header_name,
        }


@dataclass(frozen=True)
class ConnectorReceipt:
    """The value-free record of one applied stamp — proof a credential WAS applied, safe for logs/spine. It
    names the connector, scheme, epoch and ``secret_ref``, never the credential value."""

    org: str
    connector_id: str
    scheme: ConnectorScheme
    epoch: int
    header_name: str
    secret_ref: str
    applied: bool


class ConnectorAuth:
    """Live, single-use outbound auth material — the ONLY object in this module that carries a credential
    value, and it is built so the value cannot escape to a serialisable surface:

      * :meth:`__repr__` / :meth:`__str__` REDACT the material (``value=<redacted>``), so an accidental log of
        the auth object leaks nothing.
      * pickling is REFUSED (``__reduce__`` / ``__reduce_ex__`` / ``__getstate__`` raise), and with
        ``__slots__`` and no ``__dict__`` there is no state for a serialiser to read; it is not a pydantic
        model and ``json.dumps`` cannot encode it.
      * the material is reachable ONLY through :meth:`apply`, which stamps it onto a caller-supplied outbound
        headers mapping and then CLEARS it — single-use. A second apply is refused.

    For ``HMAC_SIGNATURE`` the material is a ``v1=<tag>`` signature (not the secret); for ``BEARER``/
    ``HEADER_KEY`` it is the header value that carries the credential."""

    __slots__ = ("org", "connector_id", "scheme", "epoch", "header_name", "secret_ref", "_material", "_spent")

    def __init__(self, *, org: str, connector_id: str, scheme: ConnectorScheme, epoch: int,
                 header_name: str, secret_ref: str, material: str) -> None:
        self.org = org
        self.connector_id = connector_id
        self.scheme = scheme
        self.epoch = epoch
        self.header_name = header_name
        self.secret_ref = secret_ref
        self._material: Optional[str] = material
        self._spent = False

    def __repr__(self) -> str:
        state = "spent" if self._spent else "live"
        return (f"ConnectorAuth(org={self.org!r}, connector_id={self.connector_id!r}, "
                f"scheme={self.scheme.value}, epoch={self.epoch}, secret_ref={self.secret_ref!r}, "
                f"header_name={self.header_name!r}, value=<redacted>, state={state})")

    __str__ = __repr__

    # Refuse every pickling entry point so a credential can never be frozen into a snapshot/spine. With
    # ``__slots__`` and no ``__dict__`` there is also no state for a serialiser to read behind these.
    def __reduce__(self) -> NoReturn:
        raise ConnectorBrokerRefused(
            "ConnectorAuth carries live credential material and is not serialisable (fail-closed)")

    def __reduce_ex__(self, protocol: object) -> NoReturn:
        raise ConnectorBrokerRefused(
            "ConnectorAuth carries live credential material and is not serialisable (fail-closed)")

    def __getstate__(self) -> NoReturn:
        raise ConnectorBrokerRefused(
            "ConnectorAuth carries live credential material and is not serialisable (fail-closed)")

    def apply(self, headers: MutableMapping[str, str]) -> ConnectorReceipt:
        """Stamp the auth material onto an outbound request's ``headers`` (single-use), then CLEAR it so the
        value lives nowhere after. Returns a value-free :class:`ConnectorReceipt`. Fail-closed: a spent auth
        refuses to apply again."""
        if self._spent or self._material is None:
            raise ConnectorBrokerRefused(
                f"connector auth for {self.connector_id!r} is already spent (single-use, fail-closed)")
        headers[self.header_name] = self._material
        self._material = None
        self._spent = True
        return ConnectorReceipt(
            org=self.org, connector_id=self.connector_id, scheme=self.scheme, epoch=self.epoch,
            header_name=self.header_name, secret_ref=self.secret_ref, applied=True)


class ConnectorSecretBroker:
    """The AS-9a connector-secrets broker: it brokers sealed per-connector credentials to REGISTERED,
    AUTHORISED consumers without ever letting a credential value reach a serialisable surface.

    It holds the consumer registry, the append-only sealed store, and the KEK-custody SEAM (injected) — but
    no plaintext and no KEK on ``self``. The pure reference plane (:meth:`issue`) always runs; the plaintext
    plane (:meth:`authorize`/:meth:`stamp`) is DEFAULT-OFF and fail-closed."""

    __slots__ = ("_registry", "_store", "_kek", "_enabled")

    def __init__(self, registry: ConsumerRegistry, store: SealedConnectorStore, kek_source: KekSource,
                 *, enabled: Optional[bool] = None) -> None:
        if not isinstance(registry, ConsumerRegistry):
            raise ConnectorBrokerRefused("registry must be a ConsumerRegistry")
        if not isinstance(store, SealedConnectorStore):
            raise ConnectorBrokerRefused("store must be a SealedConnectorStore")
        if not isinstance(kek_source, KekSource):
            raise ConnectorBrokerRefused("kek_source must implement the KekSource protocol")
        self._registry = registry
        self._store = store
        self._kek = kek_source
        # Read the flag ONCE at construction unless the caller pins it (tests pin both legs).
        self._enabled = connector_broker_enabled() if enabled is None else bool(enabled)

    # --- reference plane (pure; opens no secret; always safe) -------------------------------------
    def issue(self, grant: MonitoringAuthorityV2, *, org: str, connector_id: str, now: datetime,
              lease_not_after: Optional[datetime] = None) -> ConnectorHandle:
        """Validate authority + registration and return a value-FREE :class:`ConnectorHandle`. Fail-closed:

          * ``org``/``connector_id`` must be well-formed; ``grant`` must be a :class:`MonitoringAuthorityV2`.
          * TENANT ISOLATION — the grant's subject org must equal ``org`` (a grant binding another tenant can
            never issue this org's connector handle).
          * the grant must be ACTIVE at the injected ``now`` (an expired/not-yet grant is refused).
          * the connector must be a REGISTERED consumer for ``org``.
          * a sealed credential must exist in the store (its CURRENT epoch pins the handle).

        Opens no plaintext, consults no flag — it is pure and always safe."""
        _check_component(org, label="org")
        _check_component(connector_id, label="connector_id")
        if not isinstance(grant, MonitoringAuthorityV2):
            raise ConnectorBrokerRefused("grant must be a MonitoringAuthorityV2")
        if grant.subject.org_id != org:
            raise ConnectorBrokerRefused(
                f"cross-tenant: grant binds org {grant.subject.org_id!r}, broker was asked for org {org!r}")
        if not grant.lease_active(now):
            raise ConnectorBrokerRefused(
                f"grant for org {org!r} is not active at the given time (lease not live — fail-closed)")
        consumer = self._registry.require(org, connector_id)
        sealed = self._store.current(org, connector_id)
        lease = _as_utc(lease_not_after) if lease_not_after is not None else _as_utc(grant.lease.not_after)
        # The handle lease never outlives the grant's own lease window (clamp to the tighter bound).
        grant_lease_end = _as_utc(grant.lease.not_after)
        if lease > grant_lease_end:
            lease = grant_lease_end
        handle = ConnectorHandle(
            org=org, connector_id=connector_id, scheme=consumer.scheme, epoch=sealed.epoch,
            header_name=consumer.header_name,
            secret_ref=connector_secret_ref(org, connector_id, sealed.epoch), lease_not_after=lease)
        _log.info("aegis connector handle issued", extra=handle.redacted())
        return handle

    # --- materialisation plane (default-OFF; the only path that opens plaintext) ------------------
    def authorize(self, handle: ConnectorHandle, *, now: datetime, body: bytes = b"") -> ConnectorAuth:
        """Redeem a :class:`ConnectorHandle` into live, single-use :class:`ConnectorAuth`. This is the ONLY
        path that opens a plaintext credential, and it is DEFAULT-OFF + fail-closed:

          * REFUSE before opening anything if the broker is not armed (``ConnectorBrokerDisabled``).
          * the handle lease must be live at the injected ``now``.
          * the connector must still be registered with the SAME scheme/header the handle carries.
          * the store's CURRENT sealed epoch must equal the handle's epoch — a rotated (superseded) secret
            makes the handle STALE and is refused (never silently upgraded).
          * open the sealed secret transiently under the org's KEK, derive the scheme's auth material, and
            ZEROISE the plaintext before returning. A SealError (tamper / wrong-KEK / AAD mismatch) is
            re-raised as a fail-closed refusal that names no secret bytes."""
        if not isinstance(handle, ConnectorHandle):
            raise ConnectorBrokerRefused("authorize expects a ConnectorHandle")
        if not self._enabled:
            raise ConnectorBrokerDisabled(
                f"connector broker is DEFAULT-OFF ({CONNECTOR_BROKER_ENV} unset): refusing to open a "
                f"credential for {handle.connector_id!r} (no plaintext touched)")
        if not handle.lease_live(now):
            raise ConnectorBrokerRefused(
                f"handle for connector {handle.connector_id!r} (secret_ref {handle.secret_ref}) lease has "
                "expired (fail-closed)")
        consumer = self._registry.require(handle.org, handle.connector_id)
        if consumer.scheme is not handle.scheme or consumer.header_name != handle.header_name:
            raise ConnectorBrokerRefused(
                f"connector {handle.connector_id!r} registration changed since the handle was issued "
                "(scheme/header mismatch — fail-closed)")
        sealed = self._store.current(handle.org, handle.connector_id)
        if sealed.epoch != handle.epoch:
            raise ConnectorBrokerRefused(
                f"handle for connector {handle.connector_id!r} is stale: it pins epoch {handle.epoch} but "
                f"the current sealed epoch is {sealed.epoch} (rotated — fail-closed)")
        kek = self._kek.kek_for(handle.org)
        plain = bytearray()
        try:
            try:
                plain += open_secret(kek, sealed)
            except SealError as exc:
                # The AS-2h open guarantees SealError leaks no secret material; re-raise as a broker refusal
                # that names only the connector + fingerprint, never any bytes.
                raise ConnectorBrokerRefused(
                    f"sealed credential for connector {handle.connector_id!r} (secret_ref "
                    f"{handle.secret_ref}) failed to open (fail-closed)") from exc
            # Pass the mutable bytearray itself (not an immutable bytes copy) so the plaintext lives in
            # exactly ONE object we can zeroise. For HMAC_SIGNATURE no string copy of the secret is ever
            # made (only the tag); for BEARER/HEADER_KEY the one unavoidable immutable copy is the header
            # value str (Python strings cannot be zeroised — see the module limitation).
            material = self._derive_material(handle.scheme, plain, body)
        finally:
            # Zeroise the transient plaintext regardless of outcome — the broker holds no plaintext it does
            # not need, for no longer than it needs it.
            for i in range(len(plain)):
                plain[i] = 0
            del plain
        return ConnectorAuth(
            org=handle.org, connector_id=handle.connector_id, scheme=handle.scheme, epoch=handle.epoch,
            header_name=handle.header_name, secret_ref=handle.secret_ref, material=material)

    def stamp(self, handle: ConnectorHandle, headers: MutableMapping[str, str], *, now: datetime,
              body: bytes = b"") -> ConnectorReceipt:
        """Convenience: :meth:`authorize` then :meth:`ConnectorAuth.apply` in one call. The credential value
        touches only ``headers`` (the outbound request) and is cleared immediately; the returned receipt is
        value-free."""
        return self.authorize(handle, now=now, body=body).apply(headers)

    @staticmethod
    def _derive_material(scheme: ConnectorScheme, plain: bytearray, body: bytes) -> str:
        """Derive the outbound auth material for a scheme. HMAC_SIGNATURE emits a tag (the secret never
        leaves); BEARER/HEADER_KEY emit the header value that carries the credential. Deterministic — no
        clock, no RNG. ``plain`` is the caller's zeroisable bytearray; the credential is read only here,
        inside the zeroising frame of :meth:`authorize`, and never copied into a longer-lived object than the
        returned material."""
        if scheme is ConnectorScheme.HMAC_SIGNATURE:
            if not isinstance(body, (bytes, bytearray)):
                raise ConnectorBrokerRefused("HMAC_SIGNATURE body must be bytes")
            return "v1=" + hmac.new(plain, bytes(body), hashlib.sha256).hexdigest()
        # Validate UTF-8 WITHOUT letting the failure capture the plaintext. ``bytes.decode`` raises
        # ``UnicodeDecodeError`` whose ``.object`` is a FRESH, un-zeroisable copy of the WHOLE credential;
        # if that exception is bound (``as exc``) or chained (``from exc`` — and even ``from None`` leaves
        # ``__context__`` pointing at it), the raised refusal carries the plaintext out of ``authorize``'s
        # zeroising frame. So catch it UNBOUND and raise the plaintext-free refusal OUTSIDE the handler, so
        # no exception chain (``__cause__``/``__context__``) retains the decode error or its captured bytes.
        decoded: "str | None" = None
        try:
            decoded = plain.decode("utf-8")
        except UnicodeDecodeError:
            pass
        if decoded is None:
            raise ConnectorBrokerRefused(
                "connector credential is not valid utf-8 for a header value (fail-closed)")
        value = decoded
        if "\r" in value or "\n" in value:
            # A credential value with CR/LF would allow header-injection into the outbound request.
            raise ConnectorBrokerRefused("connector credential contains a CR/LF (header-injection guard)")
        if scheme is ConnectorScheme.BEARER:
            return "Bearer " + value
        return value  # HEADER_KEY — the key verbatim in its configured header
