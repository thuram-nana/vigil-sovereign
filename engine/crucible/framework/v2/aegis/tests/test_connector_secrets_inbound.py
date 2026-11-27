"""AEGIS AS-9b — the INBOUND verify peer (``connector_secrets.InboundConnectorVerifier``), NET-NEW.

connector_secrets ships only the OUTBOUND ``stamp`` (materialise a credential to SEND). The AS-9b ingest
receiver needs the DUAL: VERIFY an inbound HMAC body signature (``v1=<hmac-sha256 over body>``) and confirm
an mTLS client — reusing the AS-2h ``open_secret`` / ``connector_aad`` custody (no plaintext ever returned).

POSITIVE controls: a good tag over the body verifies; the same inputs verify again (determinism); a verified
mTLS client verifies.
NEGATIVE / fail-closed controls: a tag under the WRONG secret is rejected; a tag replayed over a TAMPERED
body is rejected; a malformed/non-``v1=`` tag is rejected (never raises); an unverified mTLS client is
rejected; an unregistered / wrong-scheme connector is refused; and DEFAULT-OFF refuses to open any plaintext
(the KEK source is never touched).

Every secret + KEK is generated at RUNTIME and sealed with the AS-2h primitives in-test — no committed
secret-shaped fixture. Pure functions of the inputs (HMAC-SHA256): no socket, no wall-clock, no RNG.
"""
from __future__ import annotations

import hashlib
import hmac
import os
import secrets

import pytest
from vigil_core.aegis_sealing import SecretKind, seal_secret

from framework.v2.aegis.connector_secrets import (
    ConnectorBrokerDisabled,
    ConnectorBrokerRefused,
    ConnectorConsumer,
    ConnectorScheme,
    ConsumerRegistry,
    InboundConnectorVerifier,
    InboundVerifyReceipt,
    SealedConnectorStore,
    connector_secret_ref,
)

ORG = "org_a"
HMAC_CONN = "ingest-hmac"
MTLS_CONN = "ingest-mtls"
EPOCH = 1


class _FixedKek:
    def __init__(self, kek: bytes) -> None:
        self._kek = kek

    def kek_for(self, org: str) -> bytes:  # noqa: ARG002
        return self._kek


class _ExplodingKek:
    def kek_for(self, org: str) -> bytes:  # noqa: ARG002
        raise AssertionError("kek_for must NOT be called on the default-OFF path")


def _rig(*, enabled=True, kek=None, ingest_secret=b"", seal_secret_bytes=None):
    kek = kek if kek is not None else os.urandom(32)
    ingest_secret = ingest_secret or secrets.token_bytes(32)
    reg = ConsumerRegistry()
    reg.register(ConnectorConsumer(org=ORG, connector_id=HMAC_CONN, scheme=ConnectorScheme.HMAC_SIGNATURE,
                                   header_name="X-Vigil-Ingest-Auth"))
    reg.register(ConnectorConsumer(org=ORG, connector_id=MTLS_CONN, scheme=ConnectorScheme.HMAC_SIGNATURE,
                                   header_name="X-Vigil-Ingest-Auth"))
    store = SealedConnectorStore()
    store.put(seal_secret(kek, SecretKind.CONNECTOR, ORG, HMAC_CONN, EPOCH,
                          seal_secret_bytes if seal_secret_bytes is not None else ingest_secret))
    store.put(seal_secret(kek, SecretKind.CONNECTOR, ORG, MTLS_CONN, EPOCH, secrets.token_bytes(32)))
    v = InboundConnectorVerifier(reg, store, _FixedKek(kek), enabled=enabled)
    return v, ingest_secret


def _tag(secret: bytes, body: bytes) -> str:
    return "v1=" + hmac.new(secret, body, hashlib.sha256).hexdigest()


# --- HMAC accept/reject -------------------------------------------------------------------------------
def test_good_tag_verifies():
    v, secret = _rig()
    body = b'{"finding":"ok"}'
    r = v.verify_hmac(org=ORG, connector_id=HMAC_CONN, body=body, presented=_tag(secret, body))
    assert isinstance(r, InboundVerifyReceipt) and r.ok and r.method == "hmac"
    assert r.secret_ref == connector_secret_ref(ORG, HMAC_CONN, EPOCH)  # value-free fingerprint only


def test_same_inputs_verify_again_determinism():
    v, secret = _rig()
    body = b"deterministic"
    a = v.verify_hmac(org=ORG, connector_id=HMAC_CONN, body=body, presented=_tag(secret, body))
    b = v.verify_hmac(org=ORG, connector_id=HMAC_CONN, body=body, presented=_tag(secret, body))
    assert a.ok and b.ok and a.secret_ref == b.secret_ref


def test_wrong_secret_rejected():
    v, _secret = _rig()
    body = b"payload"
    forged = _tag(secrets.token_bytes(32), body)       # a tag under a DIFFERENT secret
    assert v.verify_hmac(org=ORG, connector_id=HMAC_CONN, body=body, presented=forged).ok is False


def test_tampered_body_rejected_replay():
    # A captured valid tag (over body A) REPLAYED onto a TAMPERED body A' must not verify (the tag binds body).
    v, secret = _rig()
    good = _tag(secret, b"amount=1")
    assert v.verify_hmac(org=ORG, connector_id=HMAC_CONN, body=b"amount=1000000", presented=good).ok is False


def test_malformed_tag_rejected_without_raising():
    v, secret = _rig()
    body = b"x"
    # The non-ASCII ``v1=…`` tags are the regression guard: ``hmac.compare_digest`` on two ``str`` RAISES
    # ``TypeError`` when either holds a non-ASCII char, so a hostile ``"v1=café…"`` tag must fail CLOSED
    # (ok=False) and NEVER unwind the stack — the documented "malformed tag → ok=False (never raises)" contract.
    for bad in ("", "deadbeef", "v2=" + hmac.new(secret, body, hashlib.sha256).hexdigest(), "v1=zzzz",
                "v1=café", "v1=" + "\U0001f600" * 8, "v1=" + "ÿ" * 64):
        assert v.verify_hmac(org=ORG, connector_id=HMAC_CONN, body=body, presented=bad).ok is False


# --- mTLS accept/reject -------------------------------------------------------------------------------
def test_mtls_verified_client_accepts():
    v, _ = _rig()
    assert v.verify_mtls(org=ORG, connector_id=MTLS_CONN, mtls_client_verified=True).ok is True


def test_mtls_unverified_client_rejected():
    v, _ = _rig()
    r = v.verify_mtls(org=ORG, connector_id=MTLS_CONN, mtls_client_verified=False)
    assert r.ok is False and r.method == "mtls"


# --- fail-closed: default-off, unregistered, wrong-scheme ---------------------------------------------
def test_default_off_refuses_without_opening_plaintext():
    reg = ConsumerRegistry()
    reg.register(ConnectorConsumer(org=ORG, connector_id=HMAC_CONN, scheme=ConnectorScheme.HMAC_SIGNATURE,
                                   header_name="X-Vigil-Ingest-Auth"))
    store = SealedConnectorStore()
    store.put(seal_secret(os.urandom(32), SecretKind.CONNECTOR, ORG, HMAC_CONN, EPOCH, secrets.token_bytes(32)))
    v = InboundConnectorVerifier(reg, store, _ExplodingKek(), enabled=False)   # un-armed, KEK must never open
    with pytest.raises(ConnectorBrokerDisabled):
        v.verify_hmac(org=ORG, connector_id=HMAC_CONN, body=b"x", presented="v1=deadbeef")


def test_unregistered_connector_refused():
    v, secret = _rig()
    with pytest.raises(ConnectorBrokerRefused):
        v.verify_hmac(org=ORG, connector_id="not-registered", body=b"x", presented=_tag(secret, b"x"))


def test_wrong_scheme_connector_refused():
    reg = ConsumerRegistry()
    reg.register(ConnectorConsumer(org=ORG, connector_id="bearer-conn", scheme=ConnectorScheme.BEARER,
                                   header_name="Authorization"))
    store = SealedConnectorStore()
    kek = os.urandom(32)
    store.put(seal_secret(kek, SecretKind.CONNECTOR, ORG, "bearer-conn", EPOCH, secrets.token_bytes(32)))
    v = InboundConnectorVerifier(reg, store, _FixedKek(kek), enabled=True)
    with pytest.raises(ConnectorBrokerRefused):
        v.verify_hmac(org=ORG, connector_id="bearer-conn", body=b"x", presented="v1=deadbeef")
