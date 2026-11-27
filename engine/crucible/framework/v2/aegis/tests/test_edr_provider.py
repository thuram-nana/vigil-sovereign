"""AEGIS AS-10b — the EDR telemetry PROVIDER / ingest source (``framework.v2.aegis.edr_provider``).

Proven here (strict acceptance, the 7-point DoD):
  * E2E — a real EDR vendor alert → AS-30 poll job → mapped ``vigil.aegis.ingest.finding.v1`` → OUTBOUND
    ingest-HMAC stamp → armed ``IngestReceiver.ingest`` returns SPOOLED; the landed v1 envelope is the exact
    drain-shaped ``{schema, body, mac}`` the AS-3c drain accepts; the AS-9c ProducerAnchor re-verifies.
  * NEAR-ZERO-FP (SOURCE, not detector) — a benign/info event and a heartbeat map to NO finding / NO push;
    the provider NEVER emits ``decision="confirmed"`` — only ``"lead"`` (no certificate).
  * FATAL-2 two-env — ``edr_provider`` imports only ``vigil_core`` + ``framework.v2.aegis`` siblings + stdlib,
    never ``sigil`` (AST import-leg); the write leg runs in a SEPARATE engine process (the ``python -m`` driver).
  * DETERMINISM — same alert → byte-identical ``AegisEventV2`` bytes + identical ProducerAnchor tag + identical
    content-addressed spool filename; the ts is the alert's own (no wallclock / global-RNG on the signed path).
  * DEFAULT-OFF + fail-closed — flag off ⇒ inert (no push, no secret open); a hostile/oversize alert drops;
    a down broker raises ``ConnectorBrokerDisabled`` BEFORE any plaintext.
  * NEGATIVE CONTROLS (mutation-sensitive) — the lead-clamp, the benign-drop, the default-OFF gate, the anchor
    mint, and the boundary redaction each have a test that REDS if the guard is removed/corrupted.
  * GATE-INVARIANCE — the module is OFF the make-gate path (nothing under ``aegis/__init__`` imports it) and
    registers NO new OracleKind: ``verify/verifier.py::_ALL_ORACLES`` stays 15.

Secrets/KEKs are generated at RUNTIME and sealed with the AS-2h primitives in-test (no committed secret).
Deterministic: an INJECTED clock, no RNG on the mapped/anchored/pushed path.
"""
from __future__ import annotations

import ast
import hashlib
import hmac
import json
import os
import subprocess
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from vigil_core.aegis_anchors import ProducerAnchor, produce_producer_anchor, verify_producer_anchor
from vigil_core.aegis_sealing import SecretKind, seal_secret
from vigil_core.authority_v2 import (
    AuthoritySubject,
    MonitoringAuthorityV2,
    MonitoringCapability,
    MonitoringLease,
    SubjectKind,
)
from vigil_core.protection_contract import (
    EffectVerification,
    OutcomeClass,
    baseline_provider_registry,
)

from framework.v2.aegis import edr_provider as E
from framework.v2.aegis import receiver as R
from framework.v2.aegis.connector_secrets import (
    ConnectorBrokerDisabled,
    ConnectorScheme,
    ConnectorSecretBroker,
    ConsumerRegistry,
    InboundConnectorVerifier,
    SealedConnectorStore,
)
from framework.v2.aegis.job_runner import JobSpec, PerTenantRunner
from framework.v2.aegis.monitoring_report import REPORT_DOMAIN, REPORT_SCHEMA, domain_slug
from framework.v2.aegis.receiver import IngestOutcome, IngestReceiver

ORG, HOST = "org_a", "apme.cm"
INSTANCE = "edr-inst-1"
VENDOR_CONN = "edr-crowdstrike"
INGEST_CONN = "ingest-hmac"
ANCHOR_CONN = "edr-anchor"
REPORT_SECRET = b"R" * 32
INGEST_SECRET = b"I" * 32
VENDOR_SECRET = b"V" * 32
ANCHOR_SECRET = b"A" * 32
NOW_TS = 1_000_000.0
NOW_DT = datetime(2026, 1, 1, tzinfo=timezone.utc)

_ROOT = Path(__file__).resolve().parents[6]            # .../engine/crucible/framework/v2/aegis/tests -> repo root
_ENGINE_PYTHONPATH = os.pathsep.join([str(_ROOT / "packages/core/vigil_core"), str(_ROOT / "engine/crucible")])
_EDR_MODULE = "framework.v2.aegis.edr_provider"


class _FixedKek:
    def __init__(self, kek: bytes) -> None:
        self._kek = kek

    def kek_for(self, org: str) -> bytes:  # noqa: ARG002
        return self._kek


class _ExplodingKek:
    """A KEK source that RAISES if consulted — proves an inert path opens NO plaintext."""

    def kek_for(self, org: str) -> bytes:  # noqa: ARG002
        raise AssertionError("kek_for must NOT be called on the inert / default-OFF path")


class _ExplodingFetch:
    """A vendor source that RAISES if called — proves an inert poll fetches nothing."""

    def fetch(self) -> list:
        raise AssertionError("fetch must NOT be called on the default-OFF path")


def _grant(*, org: str = ORG) -> MonitoringAuthorityV2:
    nb, na = NOW_DT - timedelta(seconds=50), NOW_DT + timedelta(seconds=1e6)
    return MonitoringAuthorityV2(
        subject=AuthoritySubject(kind=SubjectKind.HOST, org_id=org, host=HOST),
        capabilities=[MonitoringCapability.OBSERVE], epoch=1,
        not_before=nb, not_after=na, lease=MonitoringLease(not_before=nb, not_after=na),
        instance_id="gw")


def _wiring(kek: bytes, *, broker_enabled: bool = True):
    """Build the shared (registry, store) with the ingest / vendor / anchor connectors sealed, plus an OUTBOUND
    broker and an INBOUND verifier over the SAME custody (so a stamped ingest tag verifies at the receiver)."""
    reg = ConsumerRegistry()
    reg.register(E.edr_ingest_consumer(ORG, connector_id=INGEST_CONN))
    reg.register(E.edr_vendor_consumer(ORG, VENDOR_CONN, ConnectorScheme.BEARER, "Authorization"))
    reg.register(E.edr_vendor_consumer(ORG, ANCHOR_CONN, ConnectorScheme.HMAC_SIGNATURE, "X-Vigil-Anchor"))
    store = SealedConnectorStore()
    store.put(seal_secret(kek, SecretKind.CONNECTOR, ORG, INGEST_CONN, 1, INGEST_SECRET))
    store.put(seal_secret(kek, SecretKind.CONNECTOR, ORG, VENDOR_CONN, 1, VENDOR_SECRET))
    store.put(seal_secret(kek, SecretKind.CONNECTOR, ORG, ANCHOR_CONN, 1, ANCHOR_SECRET))
    broker = ConnectorSecretBroker(reg, store, _FixedKek(kek), enabled=broker_enabled)
    verifier = InboundConnectorVerifier(reg, store, _FixedKek(kek), enabled=True)
    return reg, store, broker, verifier


def _alert(**kw) -> dict:
    a = {"alert_id": "a-1", "type": "detection", "severity": "critical",
         "detection_name": "Ransomware.Encryptor", "timestamp": NOW_TS - 10, "score": 95,
         "hostname": "DESKTOP-ABC123"}
    a.update(kw)
    return a


def _armed_receiver(spool: str, verifier, *, require_auth: bool = True) -> IngestReceiver:
    return IngestReceiver(spool, org_id=ORG, host=HOST, report_secret=REPORT_SECRET, verifier=verifier,
                          require_mtls_or_hmac=require_auth, enabled=True, now_fn=lambda: NOW_TS)


def _poll_job(spool: str, alerts, *, kek: bytes = None, broker_enabled: bool = True, enabled: bool = True,
              require_auth: bool = True):
    """A fully-wired poll job driving a real armed receiver via the direct (no-socket) sender."""
    kek = kek if kek is not None else os.urandom(32)
    reg, store, broker, verifier = _wiring(kek, broker_enabled=broker_enabled)
    receiver = _armed_receiver(spool, verifier, require_auth=require_auth)
    ingest_handle = broker.issue(_grant(), org=ORG, connector_id=INGEST_CONN, now=NOW_DT)
    vendor_handle = broker.issue(_grant(), org=ORG, connector_id=VENDOR_CONN, now=NOW_DT)
    fetch = E.BrokeredVendorFetch(broker=broker, handle=vendor_handle, now=NOW_DT,
                                  transport=lambda headers: list(alerts))
    push = E.EdrPushClient(broker=broker, handle=ingest_handle, now=NOW_DT, sender=E.receiver_sender(receiver))
    minter = E.EdrAnchorMinter(store, _FixedKek(kek), enabled=broker_enabled)
    cfg = E.EdrPollConfig(org=ORG, host=HOST, instance_id=INSTANCE, anchor_connector_id=ANCHOR_CONN)
    job = E.EdrPollJob(fetch=fetch, push=push, minter=minter, config=cfg, enabled=enabled)
    return job, receiver


# ==================================================================================================
# 1. E2E acceptance (full OUTBOUND HMAC path) + anchor verifies.
# ==================================================================================================
def test_e2e_poll_maps_anchors_pushes_and_lands_spooled():
    spool = tempfile.mkdtemp()
    job, receiver = _poll_job(spool, [_alert()])
    runner = PerTenantRunner(ORG, enabled=True)
    out = runner.run_job(JobSpec(tenant=ORG, kind="edr_poll", payload={}), job.as_execute())
    # the AS-30 job ran cleanly for this tenant
    assert out.state is not None and out.state.value == "succeeded"
    res = job.result
    assert res.push_count == 1 and res.skipped == 0 and res.dropped == 0
    push = res.pushed[0]
    assert push.result.outcome == IngestOutcome.SPOOLED and push.result.http_status == 202
    # the finding is a LEAD with no certificate (EDR is intel-tier)
    assert push.finding["decision"] == "lead" and push.finding["certificate_sha256"] == ""
    assert push.finding["provenance_tier"] == "intel"
    # the landed v1 envelope is drain-shaped + MAC-verifiable under the per-(tenant,host) report secret
    files = list((Path(spool) / "incoming" / domain_slug(ORG, HOST)).glob("*.json"))
    assert len(files) == 1 and files[0].name == push.result.filename
    env = json.loads(files[0].read_bytes())
    assert env["schema"] == REPORT_SCHEMA
    want = hmac.new(REPORT_SECRET, REPORT_DOMAIN + env["body"].encode(), hashlib.sha256).hexdigest()
    assert hmac.compare_digest(want, env["mac"])
    rep = json.loads(env["body"])
    assert rep["org_id"] == ORG and rep["host"] == HOST and rep["decision"] == "lead" and rep["report_id"]
    # the ProducerAnchor verifies under the same connector secret (prove-don't-guess)
    ok, reason = verify_producer_anchor(push.record, push.anchor, secret=ANCHOR_SECRET)
    assert ok, reason
    assert push.record.decision == "lead" and push.record.certificate_sha256 == ""
    assert push.record.outcome_class is OutcomeClass.DETECTED_WITHOUT_ENFORCEMENT


def test_e2e_multiple_alerts_mixed_benign_and_detections():
    spool = tempfile.mkdtemp()
    alerts = [_alert(alert_id="d1"), {"type": "heartbeat", "timestamp": NOW_TS},
              _alert(alert_id="d2", detection_name="Credential.Dumping", severity="high", score=80),
              {"type": "detection", "severity": "info", "detection_name": "noise", "timestamp": NOW_TS}]
    job, receiver = _poll_job(spool, alerts)
    PerTenantRunner(ORG, enabled=True).run_job(JobSpec(tenant=ORG, kind="edr_poll", payload={}), job.as_execute())
    res = job.result
    assert res.push_count == 2 and res.skipped == 2 and res.dropped == 0
    assert all(p.result.outcome in (IngestOutcome.SPOOLED, IngestOutcome.DEDUP_NOOP) for p in res.pushed)


# ==================================================================================================
# 2. NEAR-ZERO-FP — a benign / heartbeat / info event produces NO finding and NO push.
# ==================================================================================================
@pytest.mark.parametrize("alert", [
    {"type": "heartbeat", "severity": "info", "timestamp": NOW_TS},
    {"type": "status", "severity": "none", "timestamp": NOW_TS},
    {"type": "detection", "severity": "info", "detection_name": "benign-login", "timestamp": NOW_TS},
    {"type": "detection", "severity": "informational", "detection_name": "x", "timestamp": NOW_TS},
    {"type": "detection", "detection_name": "low-score", "timestamp": NOW_TS, "score": 0.1},
    {"type": "detection", "severity": "high", "benign": True, "detection_name": "x", "timestamp": NOW_TS},
])
def test_benign_or_heartbeat_maps_to_no_finding(alert):
    assert E.map_edr_alert(alert, org=ORG, host=HOST) is None
    assert E.is_reportable(alert) is False


def test_benign_input_does_not_trip_a_push():
    spool = tempfile.mkdtemp()
    job, receiver = _poll_job(spool, [{"type": "heartbeat", "timestamp": NOW_TS},
                                      {"type": "detection", "severity": "info", "detection_name": "x",
                                       "timestamp": NOW_TS}])
    PerTenantRunner(ORG, enabled=True).run_job(JobSpec(tenant=ORG, kind="edr_poll", payload={}), job.as_execute())
    assert job.result.push_count == 0 and job.result.skipped == 2
    assert receiver.spooled == 0
    assert not list((Path(spool) / "incoming").rglob("*.json")) if (Path(spool) / "incoming").exists() else True


def test_score_only_detection_is_reportable_but_no_signal_is_dropped():
    # A genuine detection with a high score but NO severity field is reportable (score alone qualifies)...
    assert E.is_reportable({"type": "detection", "detection_name": "x", "score": 0.9, "timestamp": NOW_TS})
    # ...while an ambiguous alert with no severity AND no score is NOT reportable (safe default — near-zero-FP).
    assert E.is_reportable({"type": "detection", "detection_name": "x", "timestamp": NOW_TS}) is False
    assert E.is_reportable({}) is False
    # an explicit info severity still wins over a high score (the vendor labelled it info).
    assert E.is_reportable({"type": "detection", "severity": "info", "score": 0.99, "timestamp": NOW_TS}) is False


def test_provider_never_emits_confirmed_even_for_a_critical_alert():
    # A SOURCE never mints a CONFIRMED verdict (no certificate). Even the most severe EDR alert is a lead.
    for sev in ("critical", "severe", "high"):
        f = E.map_edr_alert(_alert(severity=sev, score=100), org=ORG, host=HOST)
        assert f is not None and f["decision"] == "lead" and f["certificate_sha256"] == ""
        rec = E.build_canonical_record(f, instance_id=INSTANCE, epoch=1)
        assert rec.decision == "lead" and rec.certificate_sha256 == ""


# ==================================================================================================
# 3. FATAL-2 — import-leg (AST) + the SEPARATE-PROCESS write leg (the python -m driver).
# ==================================================================================================
def test_edr_provider_imports_only_its_allowed_plane():
    src = Path(E.__file__).read_text(encoding="utf-8")
    tree = ast.parse(src)
    roots: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            roots |= {a.name.split(".")[0] for a in node.names}
        elif isinstance(node, ast.ImportFrom) and node.level == 0:
            roots.add((node.module or "").split(".")[0])
    assert "sigil" not in roots, "edr_provider must never import the sovereign plane (FATAL-2)"
    assert "strix" not in roots, "edr_provider must never import strix"
    assert "vigil_core" in roots, "edr_provider must drive the vigil_core contracts"
    # only vigil_core + stdlib are absolute-imported; framework siblings are relative (level > 0)
    assert roots <= {"vigil_core", "__future__", "json", "math", "os", "re", "unicodedata", "dataclasses",
                     "datetime", "typing", "socket", "sys"}, f"unexpected absolute import roots: {roots}"


def _engine_available() -> bool:
    env = {k: v for k, v in os.environ.items() if k != "PYTHONPATH"}
    env["PYTHONPATH"] = _ENGINE_PYTHONPATH
    try:
        proc = subprocess.run([sys.executable, "-c", f"import {_EDR_MODULE}"],
                              capture_output=True, text=True, cwd=str(_ROOT), env=env, timeout=60)
    except (OSError, subprocess.SubprocessError):
        return False
    return proc.returncode == 0


def test_write_leg_runs_in_a_separate_engine_process_and_anchor_verifies():
    # The write leg (map -> record -> anchor -> land) runs ENTIRELY in a separate engine-leg subprocess via the
    # `python -m framework.v2.aegis.edr_provider` driver — so no single process co-imports framework.aegis AND
    # sigil.inbound (the sovereign assert_no_offense boundary). This process then re-verifies the anchor.
    if not _engine_available():
        pytest.skip("engine-leg edr_provider cannot start here (runtime deps absent)")
    spool = tempfile.mkdtemp()
    alert = _alert()
    job = {"spool": spool, "org_id": ORG, "host": HOST, "instance_id": INSTANCE,
           "report_secret_hex": REPORT_SECRET.hex(), "anchor_connector_id": ANCHOR_CONN,
           "anchor_secret_hex": ANCHOR_SECRET.hex(), "anchor_epoch": 1, "alert": alert}
    jobfile = os.path.join(tempfile.mkdtemp(), "job.json")
    Path(jobfile).write_text(json.dumps(job), encoding="utf-8")
    env = {k: v for k, v in os.environ.items() if k != "PYTHONPATH"}
    env["PYTHONPATH"] = _ENGINE_PYTHONPATH
    proc = subprocess.run([sys.executable, "-m", _EDR_MODULE, jobfile],
                          capture_output=True, text=True, cwd=str(_ROOT), env=env, timeout=120)
    assert proc.returncode == 0, f"edr_provider subprocess failed: {proc.stdout}\n{proc.stderr}"
    out = json.loads(proc.stdout.strip().splitlines()[-1])
    assert out["outcome"] == "spooled" and out["report_id"]
    assert (Path(spool) / "incoming" / domain_slug(ORG, HOST) / out["filename"]).is_file()
    # Re-verify the anchor the separate process minted. The CLI self-verified it in-process (anchor_verified);
    # here we rebuild the record locally and independently recompute + verify the anchor from the known secret,
    # so no secret-derived material has to cross the process boundary on stdout.
    record = E.build_canonical_record(E.map_edr_alert(alert, org=ORG, host=HOST), instance_id=INSTANCE, epoch=1)
    assert record.digest() == out["record_digest"]
    assert out["anchor_verified"] is True
    assert out["anchor_connector_id"] == ANCHOR_CONN and out["anchor_epoch"] == 1
    anchor = produce_producer_anchor(record, org=ORG, connector_id=ANCHOR_CONN, epoch=1, secret=ANCHOR_SECRET)
    ok, reason = verify_producer_anchor(record, anchor, secret=ANCHOR_SECRET)
    assert ok, reason


# ==================================================================================================
# 4. DETERMINISM — byte-identical record + anchor tag + content-addressed filename; ts from the alert.
# ==================================================================================================
def test_same_alert_byte_identical_record_anchor_and_filename():
    kek = os.urandom(32)
    f1 = E.map_edr_alert(_alert(), org=ORG, host=HOST)
    f2 = E.map_edr_alert(_alert(), org=ORG, host=HOST)
    r1 = E.build_canonical_record(f1, instance_id=INSTANCE, epoch=1)
    r2 = E.build_canonical_record(f2, instance_id=INSTANCE, epoch=1)
    assert r1.canonical_bytes() == r2.canonical_bytes() and r1.event_id == r2.event_id
    a1 = produce_producer_anchor(r1, org=ORG, connector_id=ANCHOR_CONN, epoch=1, secret=ANCHOR_SECRET)
    a2 = produce_producer_anchor(r2, org=ORG, connector_id=ANCHOR_CONN, epoch=1, secret=ANCHOR_SECRET)
    assert a1.tag_hex == a2.tag_hex
    # identical content-addressed spool filename across two independent receivers (two injected clocks)
    s1, s2 = tempfile.mkdtemp(), tempfile.mkdtemp()
    rcv1 = IngestReceiver(s1, org_id=ORG, host=HOST, report_secret=REPORT_SECRET, require_mtls_or_hmac=False,
                          enabled=True, now_fn=lambda: NOW_TS)
    rcv2 = IngestReceiver(s2, org_id=ORG, host=HOST, report_secret=REPORT_SECRET, require_mtls_or_hmac=False,
                          enabled=True, now_fn=lambda: NOW_TS + 999999)   # a DIFFERENT clock
    body = E.EdrPushClient.wire_bytes(f1)
    res1, res2 = rcv1.ingest(body), rcv2.ingest(body)
    assert res1.filename == res2.filename and res1.report_id == res2.report_id   # clock-independent


def test_ts_is_taken_from_the_alert_not_wallclock():
    f_a = E.map_edr_alert(_alert(timestamp=111.0), org=ORG, host=HOST)
    f_b = E.map_edr_alert(_alert(timestamp=222.0), org=ORG, host=HOST)
    assert f_a["ts"] == 111.0 and f_b["ts"] == 222.0
    # the derived record seq is from the alert's own ts (monotonic), so different ts -> different records
    assert E.build_canonical_record(f_a, instance_id=INSTANCE, epoch=1).seq == 111
    assert E.build_canonical_record(f_b, instance_id=INSTANCE, epoch=1).seq == 222
    # an ISO-8601 timestamp coerces deterministically (naive read as UTC)
    f_iso = E.map_edr_alert(_alert(timestamp="1970-01-01T00:00:10"), org=ORG, host=HOST)
    assert f_iso["ts"] == 10.0


def test_unstamped_alert_is_dropped_never_wallclocked():
    bad = _alert()
    del bad["timestamp"]
    with pytest.raises(Exception):   # BoundaryError — refuses to stamp with a clock
        E.map_edr_alert(bad, org=ORG, host=HOST)


# ==================================================================================================
# 5. DEFAULT-OFF + fail-closed.
# ==================================================================================================
def test_flag_is_strict_default_off(monkeypatch):
    monkeypatch.delenv(E.EDR_PROVIDER_ENV, raising=False)
    assert E.edr_provider_enabled() is False
    for off in ("0", "off", "", "nope", "2"):
        monkeypatch.setenv(E.EDR_PROVIDER_ENV, off)
        assert E.edr_provider_enabled() is False
    for on in ("1", "true", "YES", "On"):
        monkeypatch.setenv(E.EDR_PROVIDER_ENV, on)
        assert E.edr_provider_enabled() is True


def test_default_off_provider_is_inert_opens_no_secret_and_pushes_nothing():
    spool = tempfile.mkdtemp()
    reg, store, broker, verifier = _wiring(os.urandom(32))
    receiver = _armed_receiver(spool, verifier, require_auth=False)
    # the fetch and the minter's KEK EXPLODE if touched — an inert provider touches neither.
    fetch = _ExplodingFetch()
    push = E.EdrPushClient(broker=broker, handle=broker.issue(_grant(), org=ORG, connector_id=INGEST_CONN,
                                                              now=NOW_DT), now=NOW_DT, sender=E.receiver_sender(receiver))
    minter = E.EdrAnchorMinter(store, _ExplodingKek(), enabled=True)
    cfg = E.EdrPollConfig(org=ORG, host=HOST, instance_id=INSTANCE, anchor_connector_id=ANCHOR_CONN)
    job = E.EdrPollJob(fetch=fetch, push=push, minter=minter, config=cfg, enabled=False)   # flag OFF
    out = PerTenantRunner(ORG, enabled=True).run_job(JobSpec(tenant=ORG, kind="edr_poll", payload={}),
                                                     job.as_execute())
    assert out.state.value == "succeeded"           # the inert body returns cleanly
    assert job.result.enabled is False and job.result.push_count == 0
    assert receiver.spooled == 0


def test_down_broker_refuses_before_any_plaintext():
    # VIGIL_AEGIS_CONNECTOR_BROKER unset ⇒ the minter refuses BEFORE opening the anchor secret (no plaintext).
    spool = tempfile.mkdtemp()
    reg, store, broker, verifier = _wiring(os.urandom(32), broker_enabled=False)
    minter = E.EdrAnchorMinter(store, _ExplodingKek(), enabled=False)      # broker OFF; KEK explodes if touched
    rec = E.build_canonical_record(E.map_edr_alert(_alert(), org=ORG, host=HOST), instance_id=INSTANCE, epoch=1)
    with pytest.raises(ConnectorBrokerDisabled):
        minter.mint(rec, org=ORG, connector_id=ANCHOR_CONN)
    # and the vendor fetch stamp is likewise refused fail-closed before any open
    vendor_handle = broker.issue(_grant(), org=ORG, connector_id=VENDOR_CONN, now=NOW_DT)   # reference plane OK
    fetch = E.BrokeredVendorFetch(broker=broker, handle=vendor_handle, now=NOW_DT,
                                  transport=lambda headers: [])
    with pytest.raises(ConnectorBrokerDisabled):
        fetch.fetch()


def test_hostile_and_oversize_alerts_fail_closed():
    # An oversize vendor payload + a non-JSON byte blob are DROPPED-and-counted by the bounded boundary parse;
    # the runner never sees a raise and no finding lands.
    spool = tempfile.mkdtemp()
    oversize = {"type": "detection", "severity": "high", "timestamp": NOW_TS,
                "detection_name": "x" * (17 * 1024)}
    job, receiver = _poll_job(spool, [oversize, b"\xff\xfe not json", _alert()], require_auth=False)
    PerTenantRunner(ORG, enabled=True).run_job(JobSpec(tenant=ORG, kind="edr_poll", payload={}), job.as_execute())
    res = job.result
    assert res.dropped == 2 and res.push_count == 1          # the two hostile alerts dropped; the real one lands


def test_reportable_but_unstampable_alert_mid_batch_is_dropped_and_batch_continues():
    # REGRESSION (AS-10b red-pen HIGH): a REPORTABLE alert with NO coercible timestamp is DROPPED by the map
    # path (it fails closed rather than wallclock-stamp) — but that drop must NEVER abort the batch. Feed one in
    # the MIDDLE of a batch THROUGH EdrPollJob.execute / run_job and prove: (a) the job COMPLETES (not failed),
    # (b) the bad alert is dropped-and-counted, (c) the genuine detection ordered AFTER it still lands.
    # On the pre-fix code map_edr_alert was called OUTSIDE the parse try/except, so this BoundaryError propagated
    # into PerTenantRunner.run_job -> the WHOLE tenant poll went FAILED and the trailing detection was lost
    # (push_count==1, state=="failed"); this test REDS there and GREENS only with the per-record guard.
    spool = tempfile.mkdtemp()
    before = _alert(alert_id="d1")                                   # a genuine detection ordered BEFORE the bad one
    bad = _alert(alert_id="x1")                                      # reportable (critical/score 95)...
    del bad["timestamp"]                                             # ...but un-stampable: no coercible ts -> drop-class
    after = _alert(alert_id="d2", detection_name="Credential.Dumping", severity="high", score=80)  # ordered AFTER
    assert E.is_reportable(bad) is True                              # it IS a genuine detection, not benign-skipped
    job, receiver = _poll_job(spool, [before, bad, after], require_auth=False)
    out = PerTenantRunner(ORG, enabled=True).run_job(
        JobSpec(tenant=ORG, kind="edr_poll", payload={}), job.as_execute())
    # (a) the job completed — a single record's data fault did NOT fail the tenant poll
    assert out.state is not None and out.state.value != "failed"
    assert out.state.value == "succeeded"
    res = job.result
    # (b) the bad alert was dropped-and-counted as a data fault (NOT an unexpected per-record error)
    assert res.dropped == 1 and res.errors == 0
    # (c) BOTH genuine detections landed — crucially the one ordered AFTER the bad record was not lost
    assert res.push_count == 2
    pushed_classes = {p.finding["attack_class"] for p in res.pushed}
    assert "edr/Credential.Dumping" in pushed_classes               # the trailing detection reached the receiver
    assert all(p.result.outcome in (IngestOutcome.SPOOLED, IngestOutcome.DEDUP_NOOP) for p in res.pushed)


def _poll_job_with_sender(spool, alerts, sender, *, kek=None):
    """A poll job whose ingest delivery is the injected ``sender`` (so a test can make the push of ONE record
    fault). Everything else is the real wired path (broker-armed minter + ingest stamp, armed receiver)."""
    kek = kek if kek is not None else os.urandom(32)
    reg, store, broker, verifier = _wiring(kek)
    receiver = _armed_receiver(spool, verifier, require_auth=False)
    ingest_handle = broker.issue(_grant(), org=ORG, connector_id=INGEST_CONN, now=NOW_DT)
    push = E.EdrPushClient(broker=broker, handle=ingest_handle, now=NOW_DT, sender=sender(receiver))
    minter = E.EdrAnchorMinter(store, _FixedKek(kek), enabled=True)
    cfg = E.EdrPollConfig(org=ORG, host=HOST, instance_id=INSTANCE, anchor_connector_id=ANCHOR_CONN)
    job = E.EdrPollJob(fetch=E.StaticVendorFetch(list(alerts)), push=push, minter=minter, config=cfg, enabled=True)
    return job, receiver


def test_genuine_per_record_fault_is_counted_as_error_and_the_batch_continues():
    # A per-record fault that is NEITHER drop-class (BoundaryError) NOR systemic (broker/transport down) — e.g. a
    # transient ValueError raised while delivering ONE finding — must be counted on `errors` and the loop must
    # CONTINUE. Pins the fix's per-record `errors` guard, distinct from the drop path. (Pre-fix: map/build/mint/
    # push ran OUTSIDE any per-record guard, so this would propagate and fail the whole tenant poll.)
    spool = tempfile.mkdtemp()

    def _trap(receiver):
        base = E.receiver_sender(receiver)

        def _send(body, headers):
            if b'"attack_class":"edr/TRAP"' in body:
                raise ValueError("synthetic per-record delivery fault for THIS finding")   # not Boundary/systemic
            return base(body, headers)
        return _send

    alerts = [_alert(alert_id="g1"),
              _alert(alert_id="t1", detection_name="TRAP"),                                # this one errors
              _alert(alert_id="g2", detection_name="Credential.Dumping", severity="high", score=80)]
    job, receiver = _poll_job_with_sender(spool, alerts, _trap)
    out = PerTenantRunner(ORG, enabled=True).run_job(
        JobSpec(tenant=ORG, kind="edr_poll", payload={}), job.as_execute())
    assert out.state.value == "succeeded"                           # a single record's fault did NOT fail the poll
    res = job.result
    assert res.errors == 1 and res.dropped == 0 and res.push_count == 2   # trap errored; both good records landed


def test_systemic_transport_fault_propagates_and_fails_only_this_tenant():
    # Contrast: a SYSTEMIC fault — the ingest transport is DOWN (an OSError on delivery) — fails EVERY record this
    # cycle, so it must NOT be swallowed as a per-record error. It propagates; the runner CONTAINS it (this
    # tenant's job goes FAILED, no other tenant degraded). This is the "broker down may still fail the job" line.
    spool = tempfile.mkdtemp()

    def _down(receiver):                                            # noqa: ARG001 — the transport never reaches it
        def _send(body, headers):
            raise OSError("ingest socket is down")                  # systemic outage, identical for every record
        return _send

    job, receiver = _poll_job_with_sender(spool, [_alert()], _down)
    out = PerTenantRunner(ORG, enabled=True).run_job(
        JobSpec(tenant=ORG, kind="edr_poll", payload={}), job.as_execute())
    assert out.state.value == "failed"                             # systemic → the runner fails THIS tenant's poll
    assert job.result.errors == 0 and job.result.push_count == 0   # not miscounted as a swallowed per-record error


def test_oversize_sealed_envelope_is_dropped_by_the_receiver_cap():
    # A finding whose non-ASCII label expands PAST the receiver's 16 KiB sealed-envelope cap is DROPPED by the
    # receiver (visible 413), never black-holed. Proves the receiver's cap governs the pushed finding.
    spool = tempfile.mkdtemp()
    kek = os.urandom(32)
    reg, store, broker, verifier = _wiring(kek)
    receiver = _armed_receiver(spool, verifier, require_auth=False)
    finding = {"schema": R.INGEST_FINDING_SCHEMA, "org_id": ORG, "host": HOST, "ts": NOW_TS,
               "decision": "lead", "attack_class": "\U0001f600" * 2000, "action": "observe",
               "confidence": 0.9, "certificate_sha256": "", "provenance_tier": "intel"}
    body = json.dumps(finding, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    assert len(body) <= 16 * 1024
    res = receiver.ingest(body)
    assert res.outcome == IngestOutcome.DROPPED_ENVELOPE and res.http_status == 413


# ==================================================================================================
# 6. NEGATIVE CONTROLS (mutation-sensitive) — each guard REDS if removed/corrupted.
# ==================================================================================================
def test_negctl_lead_clamp_is_the_only_decision():
    # If the clamp were removed and the decision came from the alert severity, a 'critical' alert could mint a
    # 'confirmed'. This pins the clamp: the mapped + recorded decision is ALWAYS 'lead' regardless of severity.
    for sev, score in (("critical", 100), ("severe", 99), ("high", 80)):
        f = E.map_edr_alert(_alert(severity=sev, score=score), org=ORG, host=HOST)
        assert f["decision"] == E.EDR_DECISION == "lead"
    assert E.EDR_DECISION == "lead"                          # the clamp constant itself


def test_negctl_benign_drop_guard():
    # Remove is_reportable's benign screen and a benign/info event would map to a finding (and push). This pins
    # the drop: a benign/info/heartbeat maps to None.
    assert E.map_edr_alert({"type": "heartbeat", "timestamp": NOW_TS}, org=ORG, host=HOST) is None
    assert E.map_edr_alert({"type": "detection", "severity": "info", "detection_name": "x",
                            "timestamp": NOW_TS}, org=ORG, host=HOST) is None
    # positive control: a genuine detection DOES map (so the test is not vacuously passing)
    assert E.map_edr_alert(_alert(), org=ORG, host=HOST) is not None


def test_negctl_default_off_gate_blocks_the_push():
    # Delete the default-OFF gate (execute would run regardless of enabled) and an inert provider pushes. This
    # pins the gate: enabled=False ⇒ zero pushes even with a real detection queued.
    spool = tempfile.mkdtemp()
    job, receiver = _poll_job(spool, [_alert()], enabled=False)
    PerTenantRunner(ORG, enabled=True).run_job(JobSpec(tenant=ORG, kind="edr_poll", payload={}), job.as_execute())
    assert job.result.push_count == 0 and receiver.spooled == 0


def test_negctl_anchor_mint_and_a_corrupt_tag():
    # Drop the anchor mint (or corrupt a tag byte) and verify_producer_anchor REDS. This pins the anchor: a
    # genuine anchor verifies; a one-byte-flipped tag does not.
    rec = E.build_canonical_record(E.map_edr_alert(_alert(), org=ORG, host=HOST), instance_id=INSTANCE, epoch=1)
    kek = os.urandom(32)
    _, store, _, _ = _wiring(kek)
    anchor = E.EdrAnchorMinter(store, _FixedKek(kek), enabled=True).mint(rec, org=ORG, connector_id=ANCHOR_CONN)
    ok, _ = verify_producer_anchor(rec, anchor, secret=ANCHOR_SECRET)
    assert ok
    flipped_hex = ("0" if anchor.tag_hex[0] != "0" else "1") + anchor.tag_hex[1:]
    corrupt = ProducerAnchor(org=anchor.org, connector_id=anchor.connector_id, epoch=anchor.epoch,
                             secret_ref=anchor.secret_ref, tag_hex=flipped_hex)
    bad, _ = verify_producer_anchor(rec, corrupt, secret=ANCHOR_SECRET)
    assert bad is False


def test_negctl_boundary_redaction_strips_pii_and_ip():
    # Skip the boundary redaction and a raw IP / email reaches the pushed finding. This pins the hygiene: a
    # hostile label with an IP + email is redacted in BOTH the wire finding and the anchored record.
    alert = _alert(detection_name="c2 10.0.0.9 -> victim@acme.com beacon")
    f = E.map_edr_alert(alert, org=ORG, host=HOST)
    assert "10.0.0.9" not in f["attack_class"] and "victim@acme.com" not in f["attack_class"]
    assert "<ip>" in f["attack_class"] and "<email>" in f["attack_class"]
    rec = E.build_canonical_record(f, instance_id=INSTANCE, epoch=1)
    assert "10.0.0.9" not in rec.attack_class and "victim@acme.com" not in rec.attack_class


def test_negctl_label_control_chars_are_stripped_for_the_record():
    # A label with a newline / zero-width / bidi-override char must still produce a clean_token-valid
    # record (no raise). Built via chr() so the SOURCE file stays ASCII-clean (no Trojan-Source chars).
    label = "evil" + chr(10) + "label" + chr(0x200B) + chr(0x202E) + "bidi"
    f = E.map_edr_alert(_alert(detection_name=label), org=ORG, host=HOST)
    rec = E.build_canonical_record(f, instance_id=INSTANCE, epoch=1)   # must not raise
    assert chr(10) not in rec.attack_class and chr(0x200B) not in rec.attack_class
    assert chr(0x202E) not in rec.attack_class


# ==================================================================================================
# 7. GATE-INVARIANCE — off the gate path, no new OracleKind, registry append-only.
# ==================================================================================================
def test_module_is_off_the_gate_path():
    import importlib

    importlib.import_module("framework.v2.aegis")
    import framework.v2.aegis as pkg
    assert not hasattr(pkg, "edr_provider") or "edr_provider" not in getattr(pkg, "__all__", [])


def test_all_oracles_unchanged_and_no_new_oracle_kind():
    from framework.v2.verify import verifier as V
    assert len(V._ALL_ORACLES) == 15, "AS-10b must add NO OracleKind — EDR is telemetry, not an oracle"


def test_edr_provider_descriptor_is_the_honest_floor():
    assert E.EDR_PROVIDER.provider_id == "edr"
    caps = E.EDR_PROVIDER.capabilities
    assert len(caps) == 1 and caps[0].kind == "edr_process"
    assert caps[0].outcome_class is OutcomeClass.DETECTED_WITHOUT_ENFORCEMENT   # class 5 — observes only
    assert caps[0].effect_verification is EffectVerification.REPORTED           # K17 — provider-reported


def test_registry_append_is_append_only_and_leaves_baseline_intact():
    base = baseline_provider_registry()
    assert base.provider_ids == ("sigil_gateway",)             # baseline UNCHANGED (no central-enum edit)
    reg = E.register_edr_provider(base)
    assert reg.provider_ids == ("sigil_gateway", "edr")        # appended
    assert base.provider_ids == ("sigil_gateway",)             # original is immutable
    assert reg.get("edr").outcome_classes == (OutcomeClass.DETECTED_WITHOUT_ENFORCEMENT,)


def test_connector_consumer_is_runtime_config_not_a_central_edit():
    reg = ConsumerRegistry()
    reg.register(E.edr_vendor_consumer(ORG, VENDOR_CONN, ConnectorScheme.BEARER, "Authorization"))
    reg.register(E.edr_ingest_consumer(ORG))
    assert reg.get(ORG, VENDOR_CONN).scheme is ConnectorScheme.BEARER
    assert reg.get(ORG, INGEST_CONN).header_name == R.INGEST_HMAC_HEADER
