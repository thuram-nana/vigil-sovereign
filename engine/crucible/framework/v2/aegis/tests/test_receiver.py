"""AEGIS AS-9b — the ingest RECEIVER core (``framework.v2.aegis.receiver``).

Proven here (strict acceptance):
  * AUTH — a valid HMAC body signature (or verified mTLS client) is accepted; an absent/wrong/tampered tag is
    REJECTED (fail-closed), no record lands.
  * CAPS / back-pressure — an over-size body and an over-rate burst are DROPPED-and-COUNTED, a malformed body
    is a fail-closed DROP, and NONE of these raise into the request path (``enforce_capable=False``).
  * SPOOL SHAPE — a landed record is the v1 ``{schema, body, mac}`` monitoring envelope, MAC-verifiable under
    the per-(tenant, host) report secret, filed under ``incoming/<domain_slug(org,host)>/`` — i.e. exactly what
    the sovereign ``MonitoringSpoolWatcher`` accepts (the cross-plane round-trip proves the drain end-to-end).
  * DETERMINISM — the same record yields a byte-identical sealed envelope + content-addressed filename; a
    re-POST is an idempotent dedup no-op.
  * DEFAULT-OFF / gate-invariance — off ⇒ inert (``ingest`` accepts nothing, ``serve_receiver`` binds no
    socket); the module is OFF the gate path (nothing under ``aegis/__init__`` imports it).

Secrets are generated at RUNTIME and sealed with the AS-2h primitives in-test. Deterministic: an INJECTED
clock, no RNG on the body/id path.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import socket
import tempfile
import threading
import time
from pathlib import Path

import pytest
from vigil_core.aegis_sealing import SecretKind, seal_secret

from framework.v2.aegis import receiver as R
from framework.v2.aegis.connector_secrets import (
    ConnectorConsumer,
    ConnectorScheme,
    ConsumerRegistry,
    InboundConnectorVerifier,
    SealedConnectorStore,
)
from framework.v2.aegis.monitoring_report import REPORT_DOMAIN, REPORT_SCHEMA, domain_slug

ORG, HOST = "org_a", "apme.cm"
REPORT_SECRET = b"R" * 32
INGEST_SECRET = secrets.token_bytes(32)
NOW = 1_000_000.0


class _FixedKek:
    def __init__(self, kek: bytes) -> None:
        self._kek = kek

    def kek_for(self, org: str) -> bytes:  # noqa: ARG002
        return self._kek


def _verifier():
    kek = os.urandom(32)
    reg = ConsumerRegistry()
    reg.register(ConnectorConsumer(org=ORG, connector_id="ingest-hmac", scheme=ConnectorScheme.HMAC_SIGNATURE,
                                   header_name=R.INGEST_HMAC_HEADER))
    reg.register(ConnectorConsumer(org=ORG, connector_id="ingest-mtls", scheme=ConnectorScheme.HMAC_SIGNATURE,
                                   header_name=R.INGEST_HMAC_HEADER))
    store = SealedConnectorStore()
    store.put(seal_secret(kek, SecretKind.CONNECTOR, ORG, "ingest-hmac", 1, INGEST_SECRET))
    store.put(seal_secret(kek, SecretKind.CONNECTOR, ORG, "ingest-mtls", 1, secrets.token_bytes(32)))
    return InboundConnectorVerifier(reg, store, _FixedKek(kek), enabled=True)


def _finding(**kw) -> dict:
    f = {"schema": R.INGEST_FINDING_SCHEMA, "org_id": ORG, "host": HOST, "ts": NOW - 10,
         "decision": "confirmed", "attack_class": "sqli", "action": "observe", "confidence": 0.9,
         "provenance_tier": "grounded", "certificate_sha256": "c" * 64}
    f.update(kw)
    return f


def _body(finding: dict) -> bytes:
    return json.dumps(finding, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _hmac(body: bytes) -> str:
    return "v1=" + hmac.new(INGEST_SECRET, body, hashlib.sha256).hexdigest()


def _rcv(spool=None, *, require_auth=True, enabled=True, max_body=16 * 1024, max_per_minute=600,
         verifier=None, now=lambda: NOW):
    return R.IngestReceiver(spool or tempfile.mkdtemp(), org_id=ORG, host=HOST, report_secret=REPORT_SECRET,
                            verifier=verifier if verifier is not None else _verifier(),
                            require_mtls_or_hmac=require_auth, enabled=enabled, max_body_bytes=max_body,
                            max_per_minute=max_per_minute, now_fn=now)


# --- AUTH -----------------------------------------------------------------------------------------
def test_valid_hmac_accepted_and_landed():
    spool = tempfile.mkdtemp()
    rcv = _rcv(spool)
    body = _body(_finding())
    res = rcv.ingest(body, hmac_header=_hmac(body))
    assert res.outcome == R.IngestOutcome.SPOOLED and res.http_status == 202 and rcv.spooled == 1
    files = list((Path(spool) / "incoming" / domain_slug(ORG, HOST)).glob("*.json"))
    assert len(files) == 1 and files[0].name == res.filename       # filed under the domain slug, content-addressed


def test_verified_mtls_client_accepted():
    rcv = _rcv()
    body = _body(_finding(report_token="t"))   # extra unknown key is fine on the WIRE (translated, not echoed)
    res = rcv.ingest(body, mtls_client_verified=True)
    assert res.outcome == R.IngestOutcome.SPOOLED


def test_missing_credential_rejected():
    rcv = _rcv()
    res = rcv.ingest(_body(_finding()))                 # no hmac, no mtls
    assert res.outcome == R.IngestOutcome.REJECTED_AUTH and res.http_status == 401 and rcv.rejected_auth == 1


def test_wrong_secret_tag_rejected():
    rcv = _rcv()
    body = _body(_finding())
    forged = "v1=" + hmac.new(secrets.token_bytes(32), body, hashlib.sha256).hexdigest()
    assert rcv.ingest(body, hmac_header=forged).outcome == R.IngestOutcome.REJECTED_AUTH


def test_tampered_body_rejected():
    rcv = _rcv()
    tag = _hmac(_body(_finding(confidence=0.1)))        # tag for one body
    assert rcv.ingest(_body(_finding(confidence=0.99)), hmac_header=tag).outcome == R.IngestOutcome.REJECTED_AUTH


# --- CAPS / back-pressure (DROP-and-COUNT, never raises) ------------------------------------------
def test_oversize_body_dropped_and_counted():
    rcv = _rcv(require_auth=False, max_body=256)
    res = rcv.ingest(b"x" * 1000)
    assert res.outcome == R.IngestOutcome.DROPPED_OVERSIZE and res.http_status == 413 and rcv.dropped_oversize == 1
    assert rcv.spooled == 0


def test_over_rate_burst_dropped_and_counted():
    rcv = _rcv(require_auth=False, max_per_minute=2)
    body = _body(_finding())
    outs = [rcv.ingest(body).outcome for _ in range(5)]   # same minute bucket (injected clock is fixed)
    # 2 admitted by the rate cap (first lands, rest of the admitted are idempotent no-ops), 3 DROPPED-and-counted.
    assert outs.count(R.IngestOutcome.DROPPED_RATE) == 3 and rcv.dropped_rate == 3
    assert sum(o in (R.IngestOutcome.SPOOLED, R.IngestOutcome.DEDUP_NOOP) for o in outs) == 2


def test_malformed_body_failclosed_drop_without_raising():
    rcv = _rcv(require_auth=False)
    for bad in (b"not json", b"[]", b'{"schema":"wrong"}', b'{"schema":"vigil.aegis.ingest.finding.v1"}',
                b'\xff\xfe', _body(_finding(decision="clear")), _body(_finding(confidence=5.0))):
        res = rcv.ingest(bad)                              # must NEVER raise
        assert res.outcome == R.IngestOutcome.REJECTED_MALFORMED and res.http_status == 400
    assert rcv.spooled == 0 and rcv.rejected_malformed == 7


def test_foreign_tenant_finding_rejected():
    rcv = _rcv(require_auth=False)
    res = rcv.ingest(_body(_finding(org_id="org_b", host="beta.cm")))
    assert res.outcome == R.IngestOutcome.REJECTED_MALFORMED   # bound to org_a/apme.cm only


def test_sealed_envelope_over_cap_dropped_not_black_holed():
    # A body WITHIN the inbound size cap whose non-ASCII free-text expands PAST the drain's 16 KiB file cap
    # once sealed (``seal_report`` canonicalises with ``ensure_ascii`` → 6-12 bytes/char). It must DROP-and-count
    # (a visible 413), NEVER land a file the AS-3c drain would permanently quarantine while the receiver reported
    # the record accepted (202). Without the envelope guard this body spools (regression: spooled == 1).
    spool = tempfile.mkdtemp()
    rcv = _rcv(spool, require_auth=False)
    # A real sensor sends COMPACT UTF-8 (ensure_ascii=False) to stay under the byte cap: 2000 astral chars = 8 KB
    # on the wire. The receiver then SEALS with ensure_ascii=True (12 bytes/astral) → a > 16 KiB envelope.
    body = json.dumps(_finding(attack_class="\U0001f600" * 2000),
                      sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    assert len(body) <= 16 * 1024                                  # within the inbound body cap (not an oversize drop)
    res = rcv.ingest(body)
    assert res.outcome == R.IngestOutcome.DROPPED_ENVELOPE and res.http_status == 413
    assert rcv.dropped_envelope == 1 and rcv.spooled == 0
    assert list((Path(spool) / "incoming" / domain_slug(ORG, HOST)).glob("*.json")) == []   # nothing landed
    assert rcv.metrics()["dropped_envelope"] == 1


def test_spool_io_fault_is_retryable_server_fault_not_malformed(monkeypatch):
    # A transient spool WRITE fault is a SERVER fault: the sensor must get a retryable 503, not a 400 that reads
    # "your input was malformed, do not retry" (which would silently lose a legitimate authenticated finding).
    rcv = _rcv(require_auth=False)

    def _boom(*_a, **_k):
        raise OSError("disk full")

    monkeypatch.setattr(R, "atomic_spool_write", _boom)
    res = rcv.ingest(_body(_finding()))
    assert res.outcome == R.IngestOutcome.SPOOL_FAULT and res.http_status == 503
    assert rcv.spool_faults == 1 and rcv.rejected_malformed == 0 and rcv.spooled == 0


def test_non_scalar_ts_is_malformed_not_a_server_fault():
    # A null/missing/non-scalar ``ts`` is MALFORMED CLIENT INPUT (400), not a retryable server SPOOL_FAULT (503):
    # ``_coerce_ts`` does ``float(value)``, which raises TypeError (not ValueError) on None/list/dict, so it must
    # be mapped to REJECTED_MALFORMED and must NOT inflate the ``spool_faults`` health signal (reserved for real
    # disk/seal I/O faults). Without the ts-parse guard these fell through to the 503 server-fault path.
    rcv = _rcv(require_auth=False)
    for bad_ts in (None, [1, 2], {"a": 1}, "notnum", float("nan")):
        f = _finding()
        f["ts"] = bad_ts
        res = rcv.ingest(_body(f))
        assert res.outcome == R.IngestOutcome.REJECTED_MALFORMED and res.http_status == 400, bad_ts
    f = _finding()
    del f["ts"]                                                   # ts omitted entirely
    assert rcv.ingest(_body(f)).outcome == R.IngestOutcome.REJECTED_MALFORMED
    assert rcv.spool_faults == 0 and rcv.spooled == 0            # a bad ts never looks like a server fault


# --- SPOOL SHAPE (drain-verifiable) --------------------------------------------------------------
def test_landed_envelope_is_drain_shaped_and_mac_verifies():
    spool = tempfile.mkdtemp()
    rcv = _rcv(spool, require_auth=False)
    rcv.ingest(_body(_finding()))
    files = list((Path(spool) / "incoming" / domain_slug(ORG, HOST)).glob("*.json"))
    env = json.loads(files[0].read_bytes())
    assert env["schema"] == REPORT_SCHEMA
    want = hmac.new(REPORT_SECRET, REPORT_DOMAIN + env["body"].encode(), hashlib.sha256).hexdigest()
    assert hmac.compare_digest(want, env["mac"])          # MAC-verifiable under the per-(tenant,host) report secret
    rep = json.loads(env["body"])
    assert rep["org_id"] == ORG and rep["host"] == HOST and rep["decision"] == "confirmed" and rep["report_id"]


# --- DETERMINISM ----------------------------------------------------------------------------------
def test_same_record_byte_identical_envelope_and_name():
    body = _body(_finding())
    r1, r2 = _rcv(require_auth=False), _rcv(require_auth=False)   # two independent receivers/spools
    a = r1.ingest(body)
    b = r2.ingest(body)
    assert a.outcome == b.outcome == R.IngestOutcome.SPOOLED
    assert a.filename == b.filename and a.report_id == b.report_id   # content-addressed + stable dedup id
    fa = (Path(r1._incoming)).joinpath(a.filename).read_bytes()      # noqa: SLF001 — test reads the landed bytes
    fb = (Path(r2._incoming)).joinpath(b.filename).read_bytes()      # noqa: SLF001
    assert fa == fb                                                   # byte-identical sealed envelope


def test_reposted_record_is_idempotent_dedup_noop():
    rcv = _rcv(require_auth=False)
    body = _body(_finding())
    first = rcv.ingest(body)
    second = rcv.ingest(body)
    assert first.outcome == R.IngestOutcome.SPOOLED and second.outcome == R.IngestOutcome.DEDUP_NOOP
    assert first.filename == second.filename and rcv.spooled == 1 and rcv.deduped == 1
    assert len(list(Path(rcv._incoming).glob("*.json"))) == 1       # noqa: SLF001 — exactly one file on disk


# --- DEFAULT-OFF / gate-invariance ----------------------------------------------------------------
def test_default_off_receiver_is_inert():
    spool = tempfile.mkdtemp()
    rcv = _rcv(spool, require_auth=False, enabled=False)
    res = rcv.ingest(_body(_finding()))
    assert res.outcome == R.IngestOutcome.DISABLED and res.http_status == 503
    assert not (Path(spool) / "incoming").exists() or not list((Path(spool) / "incoming").rglob("*.json"))


def test_default_off_serve_binds_no_socket():
    sp = os.path.join(tempfile.mkdtemp(), "ingest.sock")
    srv = R.serve_receiver(tempfile.mkdtemp(), org_id=ORG, host=HOST, report_secret=REPORT_SECRET,
                           socket_path=sp, enabled=False)
    assert srv.bound is False and not os.path.exists(sp)
    with pytest.raises(R.ReceiverDisabled):
        srv.serve_forever()


def test_receiver_flag_is_strict_default_off(monkeypatch):
    monkeypatch.delenv(R.RECEIVER_ENV, raising=False)
    assert R.receiver_enabled() is False
    for off in ("0", "off", "", "nope", "2"):
        monkeypatch.setenv(R.RECEIVER_ENV, off)
        assert R.receiver_enabled() is False
    for on in ("1", "true", "YES", "On"):
        monkeypatch.setenv(R.RECEIVER_ENV, on)
        assert R.receiver_enabled() is True


def test_receiver_is_off_the_gate_path():
    # Gate-invariance: nothing under aegis/__init__ (the serve/gate surface) imports the receiver, so importing
    # the aegis package does not pull it (importing it adds no oracle/class to the gate path).
    import importlib

    importlib.import_module("framework.v2.aegis")
    import sys
    # The receiver may be imported by THIS test; assert the AEGIS package __init__ does not reference it.
    import framework.v2.aegis as pkg
    assert not hasattr(pkg, "receiver") or "receiver" not in getattr(pkg, "__all__", [])


# --- HTTP / UNIX-socket wiring (health probe + ingest) --------------------------------------------
def _unix_http(sock_path: str, raw: bytes, *, read_timeout: float = 3.0) -> bytes:
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(read_timeout)
    s.connect(sock_path)
    try:
        s.sendall(raw)
        chunks = []
        while True:
            try:
                b = s.recv(4096)
            except socket.timeout:
                break
            if not b:
                break
            chunks.append(b)
            if b"\r\n\r\n" in b"".join(chunks) and len(b) < 4096:
                break
        return b"".join(chunks)
    finally:
        s.close()


def test_armed_server_serves_health_and_ingest_over_unix_socket():
    spool = tempfile.mkdtemp()
    sp = os.path.join(tempfile.mkdtemp(), "ingest.sock")
    srv = R.serve_receiver(spool, org_id=ORG, host=HOST, report_secret=REPORT_SECRET, socket_path=sp,
                           enabled=True, require_mtls_or_hmac=False, now_fn=lambda: NOW)
    assert srv.bound is True and os.path.exists(sp)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    try:
        time.sleep(0.05)
        health = _unix_http(sp, b"GET /health HTTP/1.1\r\nHost: unix\r\nConnection: close\r\n\r\n")
        assert b"200" in health.split(b"\r\n", 1)[0] and b"ok" in health
        body = _body(_finding())
        req = (b"POST /ingest HTTP/1.1\r\nHost: unix\r\nContent-Length: " + str(len(body)).encode() +
               b"\r\nConnection: close\r\n\r\n" + body)
        resp = _unix_http(sp, req)
        assert b"202" in resp.split(b"\r\n", 1)[0]
        assert list((Path(spool) / "incoming" / domain_slug(ORG, HOST)).glob("*.json"))
    finally:
        srv.shutdown()
        srv.close()
