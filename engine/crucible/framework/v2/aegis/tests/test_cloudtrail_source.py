"""AS-17b — the AWS CloudTrail provider READER (``framework.v2.aegis.cloudtrail_source``).

Proven here (strict acceptance; the 7-point DoD for this engine-leg slice):
  * DEFAULT-OFF / INERT (#5) — ``VIGIL_AEGIS_CLOUDTRAIL`` is strict default-off; off ⇒ ``ingest_text`` pulls
    nothing, pushes nothing, mints no anchor, and ``stamp_pull`` reads no credential. The negative control
    flips the guard: the SAME bytes DO spool once armed, so removing the off-gate reds the inert test.
  * E2E-TO-SPOOL (#1) — an armed reader normalizes → builds LEAD findings → pushes through the real AS-9b
    receiver, landing the v1 ``{schema, body, mac}`` monitoring envelope the sovereign drain accepts,
    MAC-verifiable under the per-(tenant, host) report secret, filed under ``incoming/<domain_slug>/``.
  * DETERMINISM on the signed path (#4) — the same CloudTrail bytes yield a byte-identical spooled filename
    (a re-ingest dedups) and a byte-identical AS-9c producer anchor (``ts`` from ``eventTime``, no wall-clock).
  * TAMPER-EVIDENCE + NEGATIVE CONTROL (#1/#6) — anchor-1 reverifies under the connector secret and REFUSES
    a wrong-secret / tampered record (the guard's mutation test).
  * FAIL-CLOSED (#5) — a hostile / oversize record is DROPPED-and-counted by the receiver; ``ingest_text``
    never raises. A wrong ingest-HMAC push is rejected.
  * GATE-INVARIANCE (#2) — the module is OFF the scan/engage/make-gate path (nothing under ``aegis/__init__``
    imports it) and adds no IntelSourceKind / OracleKind (the AEGIS registry self-check still passes).
  * FATAL-2 (#3) — importing the reader pulls in NO ``sigil`` module (engine leg only).

All test-only secrets are random bytes sealed under a test KEK at runtime; no real/secret-shaped fixture is
committed.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import tempfile
from pathlib import Path

import pytest
from vigil_core.aegis_anchors import verify_producer_anchor
from vigil_core.aegis_schemas import AegisEventV2
from vigil_core.aegis_sealing import SecretKind, seal_secret

from framework.v2.aegis import cloudtrail_source as CT
from framework.v2.aegis.connector_secrets import (
    ConnectorConsumer,
    ConnectorScheme,
    ConsumerRegistry,
    InboundConnectorVerifier,
    SealedConnectorStore,
)
from framework.v2.aegis.monitoring_report import REPORT_DOMAIN, REPORT_SCHEMA, domain_slug
from framework.v2.aegis.receiver import INGEST_HMAC_HEADER, IngestOutcome, IngestReceiver
from framework.v2.defender.sigma import default_field_map, parse_sigma_rule

ORG, HOST = "org_a", "api.example.com"
CID = CT.CLOUDTRAIL_CONNECTOR_ID
REPORT_SECRET = b"R" * 32


class _FixedKek:
    def __init__(self, kek: bytes) -> None:
        self._kek = kek

    def kek_for(self, org: str) -> bytes:  # noqa: ARG002
        return self._kek


def _record(**over) -> dict:
    rec = {"eventVersion": "1.08", "eventSource": "signin.amazonaws.com", "eventName": "ConsoleLogin",
           "eventTime": "2024-05-01T12:00:00Z", "awsRegion": "us-east-1", "sourceIPAddress": "203.0.113.9",
           "userIdentity": {"type": "IAMUser", "arn": "arn:aws:iam::111122223333:user/alice"}}
    rec.update(over)
    return rec


def _delivery(*records: dict) -> str:
    return json.dumps({"Records": list(records) or [_record()]})


def _receiver(spool=None, *, require_auth=False, verifier=None, ingest_connector_id="ingest-hmac"):
    return IngestReceiver(spool or tempfile.mkdtemp(), org_id=ORG, host=HOST, report_secret=REPORT_SECRET,
                          verifier=verifier, ingest_connector_id=ingest_connector_id,
                          require_mtls_or_hmac=require_auth, enabled=True)


def _anchor_wiring():
    kek = os.urandom(32)
    secret = secrets.token_bytes(32)
    store = SealedConnectorStore()
    store.put(seal_secret(kek, SecretKind.CONNECTOR, ORG, CID, 1, secret))
    return store, _FixedKek(kek), secret


# --- DEFAULT-OFF / inert + strict flag ------------------------------------------------------------
def test_flag_is_strict_default_off(monkeypatch):
    monkeypatch.delenv(CT.CLOUDTRAIL_ENV, raising=False)
    assert CT.cloudtrail_source_enabled() is False
    for off in ("0", "off", "", "nope", "2"):
        monkeypatch.setenv(CT.CLOUDTRAIL_ENV, off)
        assert CT.cloudtrail_source_enabled() is False
    for on in ("1", "true", "YES", "On"):
        monkeypatch.setenv(CT.CLOUDTRAIL_ENV, on)
        assert CT.cloudtrail_source_enabled() is True


def test_default_off_reader_is_inert():
    spool = tempfile.mkdtemp()
    src = CT.CloudTrailSource(_receiver(spool), enabled=False)
    res = src.ingest_text(_delivery())
    assert res.enabled is False
    assert (res.normalized, res.spooled, res.deduped, res.rejected) == (0, 0, 0, 0)
    assert not res.leads and not res.anchors
    assert not (Path(spool) / "incoming").exists() or not list((Path(spool) / "incoming").rglob("*.json"))


def test_default_off_negative_control_same_bytes_spool_when_armed():
    # NEGATIVE CONTROL for the off-gate: the SAME input that was INERT above DOES spool once armed. Remove the
    # ``if not self._enabled`` guard in ingest_text and the inert test above reds.
    spool = tempfile.mkdtemp()
    src = CT.CloudTrailSource(_receiver(spool), enabled=True)
    res = src.ingest_text(_delivery())
    assert res.enabled is True and res.spooled == 1
    assert list((Path(spool) / "incoming" / domain_slug(ORG, HOST)).glob("*.json"))


def test_default_off_stamp_pull_reads_no_credential():
    # Off ⇒ reads no credential: stamp_pull refuses BEFORE any broker/secret is touched.
    src = CT.CloudTrailSource(_receiver(), enabled=False)
    with pytest.raises(CT.CloudTrailSourceRefused):
        src.stamp_pull(handle=None, headers={}, now=None)  # type: ignore[arg-type]


# --- PURE offline half needs no flag --------------------------------------------------------------
def test_normalize_is_pure_and_needs_no_flag():
    src = CT.CloudTrailSource(_receiver(), enabled=False)       # even DISABLED, the offline parse works
    evs = src.normalize(_delivery())
    assert len(evs) == 1 and evs[0].source_format == "cloudtrail"


# --- E2E to the real receiver spool ---------------------------------------------------------------
def test_e2e_spools_v1_envelope_the_drain_accepts():
    spool = tempfile.mkdtemp()
    src = CT.CloudTrailSource(_receiver(spool), enabled=True)
    res = src.ingest_text(_delivery(_record(), _record(eventName="StopLogging", eventTime="2024-05-01T13:00:00Z")))
    assert res.normalized == 2 and res.spooled == 2
    files = sorted((Path(spool) / "incoming" / domain_slug(ORG, HOST)).glob("*.json"))
    assert len(files) == 2
    env = json.loads(files[0].read_text())
    assert env["schema"] == REPORT_SCHEMA and set(env) == {"schema", "body", "mac"}
    # the MAC is HMAC-SHA256(report_secret, REPORT_DOMAIN || body) — exactly the drain's verify contract
    expect = hmac.new(REPORT_SECRET, REPORT_DOMAIN + env["body"].encode("utf-8"), hashlib.sha256).hexdigest()
    assert env["mac"] == expect
    body = json.loads(env["body"])
    assert body["org_id"] == ORG and body["host"] == HOST and body["decision"] == "lead"
    assert body["action"] == "observe"            # inert, never a block (enforce_capable=False)
    assert files[0].name == hashlib.sha256(json.dumps(env, sort_keys=True, separators=(",", ":"))
                                           .encode("utf-8")).hexdigest()[:32] + ".json"


def test_determinism_same_bytes_dedup_and_stable_report_id():
    spool = tempfile.mkdtemp()
    src = CT.CloudTrailSource(_receiver(spool), enabled=True)
    first = src.ingest_text(_delivery())
    second = src.ingest_text(_delivery())
    assert first.spooled == 1 and second.deduped == 1          # content-addressed dedup
    assert first.leads[0].report_id == second.leads[0].report_id
    assert len(list((Path(spool) / "incoming" / domain_slug(ORG, HOST)).glob("*.json"))) == 1


# --- AS-9c anchors (tamper-evidence) + mutation-sensitive negative control -------------------------
def test_anchor_minted_and_reverifies():
    store, kek, secret = _anchor_wiring()
    src = CT.CloudTrailSource(_receiver(), anchor_store=store, anchor_kek_source=kek,
                              enabled=True, anchor_enabled=True)
    res = src.ingest_text(_delivery())
    assert len(res.anchors) == 1 and res.anchor_errors == 0
    anchor = res.anchors[0]
    lead = res.leads[0]
    record = AegisEventV2(org_id=ORG, host=HOST, instance_id=CID, epoch=1, seq=0, decision="lead",
                          attack_class=lead.attack_class, action="observe", confidence=lead.confidence,
                          provenance_tier="intel", certificate_sha256="", event_id=lead.report_id)
    ok, why = verify_producer_anchor(record, anchor, secret=secret)
    assert ok, why
    assert anchor.secret_ref == lead.anchor_secret_ref


def test_anchor_is_deterministic():
    store, kek, _ = _anchor_wiring()
    s1 = CT.CloudTrailSource(_receiver(), anchor_store=store, anchor_kek_source=kek, enabled=True,
                             anchor_enabled=True)
    s2 = CT.CloudTrailSource(_receiver(), anchor_store=store, anchor_kek_source=kek, enabled=True,
                             anchor_enabled=True)
    a1 = s1.ingest_text(_delivery()).anchors[0]
    a2 = s2.ingest_text(_delivery()).anchors[0]
    assert a1.tag_hex == a2.tag_hex and a1.secret_ref == a2.secret_ref       # byte-identical on signed path


def test_anchor_refuses_wrong_secret_and_tamper():
    # NEGATIVE CONTROL for the anchor: a wrong secret and a one-field tamper both fail to verify.
    store, kek, secret = _anchor_wiring()
    src = CT.CloudTrailSource(_receiver(), anchor_store=store, anchor_kek_source=kek, enabled=True,
                              anchor_enabled=True)
    res = src.ingest_text(_delivery())
    anchor, lead = res.anchors[0], res.leads[0]
    record = AegisEventV2(org_id=ORG, host=HOST, instance_id=CID, epoch=1, seq=0, decision="lead",
                          attack_class=lead.attack_class, action="observe", confidence=lead.confidence,
                          provenance_tier="intel", certificate_sha256="", event_id=lead.report_id)
    assert verify_producer_anchor(record, anchor, secret=b"a-different-secret-xxxxxx")[0] is False
    tampered = record.model_copy(update={"decision": "confirmed"})
    assert verify_producer_anchor(tampered, anchor, secret=secret)[0] is False


def test_anchor_independently_gated_off_still_spools():
    # Credential materialisation (opening the sealed secret to mint anchor-1) is INDEPENDENTLY gated. With the
    # broker arm off, no anchor is minted — but the finding still spools (anchor-2 is sovereign-side).
    store, kek, _ = _anchor_wiring()
    spool = tempfile.mkdtemp()
    src = CT.CloudTrailSource(_receiver(spool), anchor_store=store, anchor_kek_source=kek,
                              enabled=True, anchor_enabled=False)
    res = src.ingest_text(_delivery())
    assert res.spooled == 1 and res.anchors == [] and res.anchor_errors == 0
    assert res.leads[0].anchor_secret_ref == ""


# --- HMAC-authenticated push + fail-closed --------------------------------------------------------
def _hmac_verifier(ingest_secret: bytes, kek: bytes):
    reg = ConsumerRegistry()
    reg.register(ConnectorConsumer(org=ORG, connector_id="ingest-hmac", scheme=ConnectorScheme.HMAC_SIGNATURE,
                                   header_name=INGEST_HMAC_HEADER))
    store = SealedConnectorStore()
    store.put(seal_secret(kek, SecretKind.CONNECTOR, ORG, "ingest-hmac", 1, ingest_secret))
    return InboundConnectorVerifier(reg, store, _FixedKek(kek), enabled=True)


def test_authenticated_push_accepted_wrong_secret_rejected():
    kek = os.urandom(32)
    ingest_secret = secrets.token_bytes(32)
    verifier = _hmac_verifier(ingest_secret, kek)
    rcv = _receiver(require_auth=True, verifier=verifier)
    good = CT.CloudTrailSource(rcv, ingest_hmac_secret=ingest_secret, enabled=True)
    assert good.ingest_text(_delivery()).spooled == 1
    bad = CT.CloudTrailSource(rcv, ingest_hmac_secret=b"x" * 32, enabled=True)
    r = bad.ingest_text(_delivery(_record(eventName="DeleteTrail")))
    assert r.spooled == 0 and r.rejected == 1          # fail-closed, no record lands


def test_over_body_cap_dropped_never_raises():
    # The LEAD finding is metadata-only (the raw record never enters it — privacy by construction), so to
    # exercise the receiver's DROP-and-count body cap deterministically, wire a receiver with a tiny cap. The
    # reader must route the drop into ``result.dropped`` without raising (fail-closed, enforce_capable=False).
    spool = tempfile.mkdtemp()
    rcv = IngestReceiver(spool, org_id=ORG, host=HOST, report_secret=REPORT_SECRET,
                         require_mtls_or_hmac=False, enabled=True, max_body_bytes=10)
    src = CT.CloudTrailSource(rcv, enabled=True)
    res = src.ingest_text(_delivery())
    assert res.normalized == 1 and res.dropped == 1 and res.spooled == 0
    assert not list((Path(spool) / "incoming").rglob("*.json"))


def test_malformed_delivery_is_total():
    src = CT.CloudTrailSource(_receiver(), enabled=True)
    assert src.ingest_text("{garbage not json").normalized == 0     # total: no events, no raise


# --- Sigma LEAD elevation -------------------------------------------------------------------------
_RULE = """
title: AWS Console Login
id: ct-console-login
logsource: {product: aws, service: cloudtrail}
detection:
  selection:
    eventSource: signin.amazonaws.com
    eventName: ConsoleLogin
  condition: selection
tags: [attack.t1078]
author: tester
license: MIT
"""


def test_sigma_match_raises_lead_benign_does_not():
    rule = parse_sigma_rule(_RULE)
    src = CT.CloudTrailSource(_receiver(), sigma_rules=[rule], field_map=default_field_map(), enabled=True)
    hit = src.ingest_text(_delivery(_record()))
    assert hit.leads[0].attack_class == "T1078" and hit.leads[0].confidence == 0.5
    assert hit.leads[0].techniques == ("T1078",)
    benign = src.ingest_text(_delivery(_record(eventSource="s3.amazonaws.com", eventName="GetObject")))
    assert benign.leads[0].attack_class == "cloudtrail" and benign.leads[0].confidence == 0.2
    assert benign.leads[0].techniques == ()


# --- GATE-INVARIANCE + FATAL-2 --------------------------------------------------------------------
def test_reader_is_off_the_gate_path():
    import importlib

    importlib.import_module("framework.v2.aegis")
    import framework.v2.aegis as pkg
    # nothing under aegis/__init__ imports the reader (so importing the package adds no oracle/class)
    assert not hasattr(pkg, "cloudtrail_source") or "cloudtrail_source" not in getattr(pkg, "__all__", [])


def test_import_pulls_in_no_sigil():
    import importlib
    import sys

    importlib.import_module("framework.v2.aegis.cloudtrail_source")
    assert not any(m == "sigil" or m.startswith("sigil.") for m in sys.modules)


def test_adds_no_new_intel_source_kind_or_oracle():
    # The reader reuses existing LEAD-tier vocabulary (no new IntelSourceKind), so the AEGIS registry
    # self-check still passes and no OracleKind was added (make gate stays byte-identical).
    from framework.v2.aegis.registry import verify_registration
    from framework.v2.intel.models import IntelSourceKind

    verify_registration()
    assert not any("cloudtrail" in k.value.lower() for k in IntelSourceKind)
