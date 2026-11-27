"""AEGIS AS-9a (connector-secrets broker) — deterministic, offline acceptance tests.

POSITIVE controls — the broker admits what it should:
  * a registered connector under a valid, same-tenant, active grant issues a value-free handle;
  * armed, it materialises BEARER / HEADER_KEY / HMAC_SIGNATURE auth and stamps the right header;
  * same inputs ⇒ byte-identical HMAC tag + identical secret_ref (determinism).

NEGATIVE / fail-closed controls — the broker refuses/redacts what it shouldn't:
  * a cross-tenant grant, an inactive grant, an unregistered connector, a stale (rotated) handle, an
    expired handle lease, a wrong-KEK open, a CR/LF credential (header-injection) — each REFUSED;
  * DEFAULT-OFF refuses to materialise WITHOUT opening any plaintext (the KEK source is never touched);
  * a credential value NEVER appears in a handle, receipt, log-safe dict, ConnectorAuth repr, pickled/JSON
    form, or any error message; ConnectorAuth is single-use and non-serialisable.

Every credential and KEK is generated at RUNTIME (``os.urandom`` / ``secrets.token_hex``) and sealed with
the AS-2h primitives in-test — no real secret or secret-shaped fixture is committed. Everything is a pure
function of its inputs with an INJECTED clock (no socket, no wallclock, no RNG on the auth path).
"""
from __future__ import annotations

import json
import os
import pickle
import secrets
from datetime import datetime, timedelta, timezone

import pytest
from vigil_core.aegis_sealing import SecretKind, seal_secret
from vigil_core.authority_v2 import (
    AuthoritySubject,
    MonitoringAuthorityV2,
    MonitoringCapability,
    MonitoringLease,
    SubjectKind,
)

from framework.v2.aegis import connector_secrets as C
from framework.v2.aegis.connector_secrets import (
    ConnectorAuth,
    ConnectorBrokerDisabled,
    ConnectorBrokerRefused,
    ConnectorConsumer,
    ConnectorHandle,
    ConnectorScheme,
    ConnectorSecretBroker,
    ConsumerRegistry,
    SealedConnectorStore,
    connector_secret_ref,
)

ORG_A, ORG_B = "org_a", "org_b"
HOST_A = "a.apme.cm"
CONN = "siem_splunk_hec"
NOW = datetime(2026, 1, 1, tzinfo=timezone.utc)


def _dt(offset_s: float) -> datetime:
    return NOW + timedelta(seconds=offset_s)


def _grant(*, org: str = ORG_A, nb: float = -10.0, na: float = 1.0e6) -> MonitoringAuthorityV2:
    return MonitoringAuthorityV2(
        subject=AuthoritySubject(kind=SubjectKind.HOST, org_id=org, host=HOST_A),
        capabilities=[MonitoringCapability.OBSERVE], epoch=1,
        not_before=_dt(nb), not_after=_dt(na),
        lease=MonitoringLease(not_before=_dt(nb), not_after=_dt(na)),
        instance_id="gw")


class _FixedKek:
    """An injected KEK source returning one fixed 32-byte key for every org (test custody seam)."""

    def __init__(self, kek: bytes) -> None:
        self._kek = kek

    def kek_for(self, org: str) -> bytes:  # noqa: ARG002
        return self._kek


class _ExplodingKek:
    """A KEK source that RAISES if consulted — proves the DEFAULT-OFF path opens no plaintext."""

    def kek_for(self, org: str) -> bytes:  # noqa: ARG002
        raise AssertionError("kek_for must NOT be called on the default-OFF path")


def _seal(kek: bytes, org: str, conn: str, epoch: int, secret: bytes):
    return seal_secret(kek, SecretKind.CONNECTOR, org, conn, epoch, secret)


def _fixture(scheme: ConnectorScheme, *, header: str, org: str = ORG_A, conn: str = CONN,
             credential: bytes | None = None, epoch: int = 1, enabled: bool = True):
    """A wired broker + the generated credential, for one scheme. Returns (broker, kek, credential)."""
    kek = os.urandom(32)
    credential = credential if credential is not None else secrets.token_hex(24).encode("ascii")
    registry = ConsumerRegistry()
    registry.register(ConnectorConsumer(org=org, connector_id=conn, scheme=scheme, header_name=header))
    store = SealedConnectorStore()
    store.put(_seal(kek, org, conn, epoch, credential))
    broker = ConnectorSecretBroker(registry, store, _FixedKek(kek), enabled=enabled)
    return broker, kek, credential, store


# --------------------------------------------------------------------------------------------------
# POSITIVE controls
# --------------------------------------------------------------------------------------------------
def test_issue_returns_value_free_handle():
    broker, _kek, credential, _store = _fixture(ConnectorScheme.BEARER, header="Authorization")
    handle = broker.issue(_grant(), org=ORG_A, connector_id=CONN, now=NOW)
    assert isinstance(handle, ConnectorHandle)
    assert handle.org == ORG_A and handle.connector_id == CONN and handle.epoch == 1
    assert handle.secret_ref == connector_secret_ref(ORG_A, CONN, 1)
    # The handle — and everything derived for logging — carries NO credential bytes.
    blob = json.dumps(handle.redacted()) + repr(handle)
    assert credential.decode() not in blob


def test_bearer_materialise_and_stamp():
    broker, _kek, credential, _store = _fixture(ConnectorScheme.BEARER, header="Authorization")
    handle = broker.issue(_grant(), org=ORG_A, connector_id=CONN, now=NOW)
    headers: dict[str, str] = {}
    receipt = broker.stamp(handle, headers, now=NOW)
    assert headers["Authorization"] == "Bearer " + credential.decode()
    assert receipt.applied and receipt.secret_ref == handle.secret_ref
    # The receipt is value-free.
    assert credential.decode() not in (json.dumps(receipt.__dict__, default=str) + repr(receipt))


def test_header_key_materialise():
    broker, _kek, credential, _store = _fixture(ConnectorScheme.HEADER_KEY, header="X-Api-Key")
    handle = broker.issue(_grant(), org=ORG_A, connector_id=CONN, now=NOW)
    headers: dict[str, str] = {}
    broker.stamp(handle, headers, now=NOW)
    assert headers["X-Api-Key"] == credential.decode()


def test_hmac_signature_is_deterministic_and_secret_never_leaves():
    broker, _kek, credential, _store = _fixture(ConnectorScheme.HMAC_SIGNATURE, header="X-Vigil-Signature")
    handle = broker.issue(_grant(), org=ORG_A, connector_id=CONN, now=NOW)
    h1: dict[str, str] = {}
    h2: dict[str, str] = {}
    body = b'{"event":"finding"}'
    broker.stamp(handle, h1, now=NOW, body=body)
    # a second, independent authorize of the SAME handle+body yields the SAME tag (deterministic).
    broker.authorize(handle, now=NOW, body=body).apply(h2)
    assert h1["X-Vigil-Signature"].startswith("v1=")
    assert h1 == h2
    # the HMAC tag is not the secret.
    assert credential.decode() not in h1["X-Vigil-Signature"]


# --------------------------------------------------------------------------------------------------
# NEGATIVE / fail-closed controls
# --------------------------------------------------------------------------------------------------
def test_cross_tenant_grant_is_refused():
    broker, *_ = _fixture(ConnectorScheme.BEARER, header="Authorization")
    with pytest.raises(ConnectorBrokerRefused, match="cross-tenant"):
        broker.issue(_grant(org=ORG_B), org=ORG_A, connector_id=CONN, now=NOW)


def test_inactive_grant_is_refused():
    broker, *_ = _fixture(ConnectorScheme.BEARER, header="Authorization")
    expired = _grant(nb=-100.0, na=-10.0)  # not_after already in the past relative to NOW
    with pytest.raises(ConnectorBrokerRefused, match="not active"):
        broker.issue(expired, org=ORG_A, connector_id=CONN, now=NOW)


def test_unregistered_connector_is_refused():
    broker, *_ = _fixture(ConnectorScheme.BEARER, header="Authorization")
    with pytest.raises(ConnectorBrokerRefused, match="not a registered consumer"):
        broker.issue(_grant(), org=ORG_A, connector_id="unregistered_conn", now=NOW)


def test_default_off_refuses_without_opening_plaintext():
    # The broker is NOT armed, and the KEK source explodes if touched — so a refusal before any open proves
    # the default-OFF path reads no plaintext.
    kek = os.urandom(32)
    cred = secrets.token_hex(24).encode("ascii")
    registry = ConsumerRegistry()
    registry.register(ConnectorConsumer(org=ORG_A, connector_id=CONN,
                                        scheme=ConnectorScheme.BEARER, header_name="Authorization"))
    store = SealedConnectorStore()
    store.put(_seal(kek, ORG_A, CONN, 1, cred))
    broker = ConnectorSecretBroker(registry, store, _ExplodingKek(), enabled=False)
    handle = broker.issue(_grant(), org=ORG_A, connector_id=CONN, now=NOW)  # reference plane still works
    with pytest.raises(ConnectorBrokerDisabled):
        broker.authorize(handle, now=NOW)


def test_stale_handle_after_rotation_is_refused():
    broker, kek, _cred, store = _fixture(ConnectorScheme.BEARER, header="Authorization")
    handle = broker.issue(_grant(), org=ORG_A, connector_id=CONN, now=NOW)  # pins epoch 1
    store.put(_seal(kek, ORG_A, CONN, 2, secrets.token_hex(24).encode("ascii")))  # supersede → epoch 2
    with pytest.raises(ConnectorBrokerRefused, match="stale"):
        broker.authorize(handle, now=NOW)


def test_expired_handle_lease_is_refused():
    broker, *_ = _fixture(ConnectorScheme.BEARER, header="Authorization")
    handle = broker.issue(_grant(), org=ORG_A, connector_id=CONN, now=NOW,
                          lease_not_after=_dt(60.0))
    with pytest.raises(ConnectorBrokerRefused, match="lease has expired"):
        broker.authorize(handle, now=_dt(120.0))  # past the lease


def test_wrong_kek_fails_closed_and_leaks_no_secret():
    kek = os.urandom(32)
    cred = secrets.token_hex(24).encode("ascii")
    registry = ConsumerRegistry()
    registry.register(ConnectorConsumer(org=ORG_A, connector_id=CONN,
                                        scheme=ConnectorScheme.BEARER, header_name="Authorization"))
    store = SealedConnectorStore()
    store.put(_seal(kek, ORG_A, CONN, 1, cred))
    # a broker wired with a DIFFERENT KEK cannot open the sealed blob (AEAD fails closed).
    broker = ConnectorSecretBroker(registry, store, _FixedKek(os.urandom(32)), enabled=True)
    handle = broker.issue(_grant(), org=ORG_A, connector_id=CONN, now=NOW)
    with pytest.raises(ConnectorBrokerRefused) as ei:
        broker.authorize(handle, now=NOW)
    assert "failed to open" in str(ei.value)
    assert cred.decode() not in str(ei.value)


def test_crlf_credential_is_refused_header_injection_guard():
    bad = b"token\r\nX-Injected: evil"
    broker, *_ = _fixture(ConnectorScheme.HEADER_KEY, header="X-Api-Key", credential=bad)
    handle = broker.issue(_grant(), org=ORG_A, connector_id=CONN, now=NOW)
    with pytest.raises(ConnectorBrokerRefused, match="header-injection"):
        broker.authorize(handle, now=NOW)


def test_non_utf8_credential_refused_without_leaking_plaintext_via_exception_chain():
    # A non-UTF-8 BEARER/HEADER_KEY credential makes the header-value decode fail. UnicodeDecodeError.object
    # is a FRESH full plaintext copy of the credential; binding (``as exc``) or chaining (``from exc`` — and
    # even ``from None`` leaves ``__context__``) that exception would smuggle the plaintext out of authorize's
    # zeroising frame via ``__cause__``/``__context__``/``.args``. The refusal must carry NONE of it.
    secret = bytes([0xff, 0xfe, 0x00, 0x80]) + secrets.token_bytes(20)   # >=16 bytes, invalid UTF-8
    for scheme, header in ((ConnectorScheme.BEARER, "Authorization"),
                           (ConnectorScheme.HEADER_KEY, "X-Api-Key")):
        broker, *_ = _fixture(scheme, header=header, credential=secret)
        handle = broker.issue(_grant(), org=ORG_A, connector_id=CONN, now=NOW)
        with pytest.raises(ConnectorBrokerRefused) as ei:
            broker.authorize(handle, now=NOW)
        exc = ei.value
        assert "utf-8" in str(exc)
        # the raised refusal AND its whole reachable exception chain expose the secret through nothing —
        # not str(), not .args, not a UnicodeDecodeError.object left dangling on __cause__/__context__.
        for e in (exc, exc.__cause__, exc.__context__):
            if e is None:
                continue
            assert secret not in str(e).encode(errors="ignore")
            for a in getattr(e, "args", ()):
                assert not (isinstance(a, (bytes, bytearray)) and secret in bytes(a))
            obj = getattr(e, "object", None)
            assert not (isinstance(obj, (bytes, bytearray)) and secret in bytes(obj))


# --------------------------------------------------------------------------------------------------
# NO-SECRET-LEAK: ConnectorAuth is self-redacting, single-use, non-serialisable
# --------------------------------------------------------------------------------------------------
def test_connector_auth_redacts_and_refuses_serialisation():
    broker, _kek, credential, _store = _fixture(ConnectorScheme.BEARER, header="Authorization")
    handle = broker.issue(_grant(), org=ORG_A, connector_id=CONN, now=NOW)
    auth = broker.authorize(handle, now=NOW)
    assert isinstance(auth, ConnectorAuth)
    assert credential.decode() not in repr(auth)
    assert credential.decode() not in str(auth)
    assert "<redacted>" in repr(auth)
    with pytest.raises(ConnectorBrokerRefused):
        pickle.dumps(auth)
    with pytest.raises(TypeError):
        json.dumps(auth)  # not JSON-encodable — no credential can be serialised out
    # the value is reachable only by stamping it onto an outbound request's headers.
    headers: dict[str, str] = {}
    auth.apply(headers)
    assert headers["Authorization"] == "Bearer " + credential.decode()


def test_connector_auth_is_single_use():
    broker, *_ = _fixture(ConnectorScheme.BEARER, header="Authorization")
    handle = broker.issue(_grant(), org=ORG_A, connector_id=CONN, now=NOW)
    auth = broker.authorize(handle, now=NOW)
    auth.apply({})
    with pytest.raises(ConnectorBrokerRefused, match="already spent"):
        auth.apply({})


# --------------------------------------------------------------------------------------------------
# Registry + store invariants (append-only / supersede, never edit)
# --------------------------------------------------------------------------------------------------
def test_registry_refuses_conflicting_reregistration():
    registry = ConsumerRegistry()
    registry.register(ConnectorConsumer(org=ORG_A, connector_id=CONN,
                                        scheme=ConnectorScheme.BEARER, header_name="Authorization"))
    # idempotent re-register of the SAME record is fine…
    registry.register(ConnectorConsumer(org=ORG_A, connector_id=CONN,
                                        scheme=ConnectorScheme.BEARER, header_name="Authorization"))
    # …a conflicting one (different scheme/header) is refused.
    with pytest.raises(ConnectorBrokerRefused, match="already registered"):
        registry.register(ConnectorConsumer(org=ORG_A, connector_id=CONN,
                                            scheme=ConnectorScheme.HEADER_KEY, header_name="X-Api-Key"))


def test_store_is_append_only_and_monotone():
    kek = os.urandom(32)
    store = SealedConnectorStore()
    store.put(_seal(kek, ORG_A, CONN, 2, secrets.token_hex(24).encode("ascii")))
    # editing an existing epoch is refused…
    with pytest.raises(ConnectorBrokerRefused, match="append-only"):
        store.put(_seal(kek, ORG_A, CONN, 2, secrets.token_hex(24).encode("ascii")))
    # …and so is a non-monotone (<= current) epoch.
    with pytest.raises(ConnectorBrokerRefused, match="strictly greater"):
        store.put(_seal(kek, ORG_A, CONN, 1, secrets.token_hex(24).encode("ascii")))
    assert store.current(ORG_A, CONN).epoch == 2


def test_store_rejects_non_connector_secret_kind():
    kek = os.urandom(32)
    store = SealedConnectorStore()
    wrong = seal_secret(kek, SecretKind.REPORT, ORG_A, CONN, 1, secrets.token_hex(24).encode("ascii"))
    with pytest.raises(ConnectorBrokerRefused, match="holds only"):
        store.put(wrong)


def test_secret_ref_is_deterministic_and_not_the_credential():
    r1 = connector_secret_ref(ORG_A, CONN, 1)
    r2 = connector_secret_ref(ORG_A, CONN, 1)
    assert r1 == r2 and len(r1) == 16
    assert connector_secret_ref(ORG_A, CONN, 2) != r1  # epoch separation
    assert connector_secret_ref(ORG_B, CONN, 1) != r1  # org separation


def test_default_off_flag_env(monkeypatch):
    monkeypatch.delenv(C.CONNECTOR_BROKER_ENV, raising=False)
    assert C.connector_broker_enabled() is False
    monkeypatch.setenv(C.CONNECTOR_BROKER_ENV, "1")
    assert C.connector_broker_enabled() is True
    monkeypatch.setenv(C.CONNECTOR_BROKER_ENV, "nope")
    assert C.connector_broker_enabled() is False
