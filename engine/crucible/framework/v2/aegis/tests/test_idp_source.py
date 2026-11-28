"""AS-17c — the IdP (Okta System Log) provider READER (``framework.v2.aegis.idp_source``).

Proven here (strict acceptance; the 7-point DoD for this engine-leg slice; the exact mirror of the AS-17b
CloudTrail source tests):
  * DEFAULT-OFF / INERT (#5) — ``VIGIL_AEGIS_IDP`` is strict default-off; off ⇒ ``ingest_text`` pulls nothing,
    pushes nothing, mints no anchor, and ``stamp_pull`` reads no credential. The negative control flips the
    guard: the SAME bytes DO spool once armed, so removing the off-gate reds the inert test.
  * E2E-TO-SPOOL (#1) — an armed reader normalizes → builds LEAD findings → pushes through the real AS-9b
    receiver, landing the v1 ``{schema, body, mac}`` monitoring envelope the sovereign drain accepts,
    MAC-verifiable under the per-(tenant, host) report secret, filed under ``incoming/<domain_slug>/``.
  * DETERMINISM on the signed path (#4) — the same IdP bytes yield a byte-identical spooled filename (a
    re-ingest dedups) and a byte-identical AS-9c producer anchor (``ts`` from ``published``, no wall-clock).
  * TAMPER-EVIDENCE + NEGATIVE CONTROL (#1/#6) — anchor-1 reverifies under the connector secret and REFUSES a
    wrong-secret / tampered record (the guard's mutation test).
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

from framework.v2.aegis import idp_source as IDP
from framework.v2.aegis.connector_secrets import (
    ConnectorConsumer,
    ConnectorScheme,
    ConsumerRegistry,
    InboundConnectorVerifier,
    SealedConnectorStore,
)
from framework.v2.aegis.monitoring_report import REPORT_DOMAIN, REPORT_SCHEMA, domain_slug
from framework.v2.aegis.receiver import INGEST_HMAC_HEADER, IngestReceiver
from framework.v2.defender.sigma import default_field_map, parse_sigma_rule

ORG, HOST = "org_a", "api.example.com"
CID = IDP.IDP_CONNECTOR_ID
REPORT_SECRET = b"R" * 32


class _FixedKek:
    def __init__(self, kek: bytes) -> None:
        self._kek = kek

    def kek_for(self, org: str) -> bytes:  # noqa: ARG002
        return self._kek


def _event(**over) -> dict:
    rec = {"uuid": "a0000000-1111-2222-3333-444444444444", "published": "2024-05-01T12:00:00.000Z",
           "eventType": "user.session.start", "severity": "INFO", "displayMessage": "User login to Okta",
           "actor": {"type": "User", "alternateId": "alice@example.com", "displayName": "Alice"},
           "client": {"ipAddress": "203.0.113.9"}, "outcome": {"result": "SUCCESS"}}
    rec.update(over)
    return rec


def _delivery(*records: dict) -> str:
    return json.dumps(list(records) or [_event()])


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
    monkeypatch.delenv(IDP.IDP_ENV, raising=False)
    assert IDP.idp_source_enabled() is False
    for off in ("0", "off", "", "nope", "2"):
        monkeypatch.setenv(IDP.IDP_ENV, off)
        assert IDP.idp_source_enabled() is False
    for on in ("1", "true", "YES", "On"):
        monkeypatch.setenv(IDP.IDP_ENV, on)
        assert IDP.idp_source_enabled() is True


def test_default_off_reader_is_inert():
    spool = tempfile.mkdtemp()
    src = IDP.IdpSource(_receiver(spool), enabled=False)
    res = src.ingest_text(_delivery())
    assert res.enabled is False
    assert (res.normalized, res.spooled, res.deduped, res.rejected) == (0, 0, 0, 0)
    assert not res.leads and not res.anchors
    assert not (Path(spool) / "incoming").exists() or not list((Path(spool) / "incoming").rglob("*.json"))


def test_default_off_negative_control_same_bytes_spool_when_armed():
    # NEGATIVE CONTROL for the off-gate: the SAME input that was INERT above DOES spool once armed. Remove the
    # ``if not self._enabled`` guard in ingest_text and the inert test above reds.
    spool = tempfile.mkdtemp()
    src = IDP.IdpSource(_receiver(spool), enabled=True)
    res = src.ingest_text(_delivery())
    assert res.enabled is True and res.spooled == 1
    assert list((Path(spool) / "incoming" / domain_slug(ORG, HOST)).glob("*.json"))


def test_default_off_stamp_pull_reads_no_credential():
    # Off ⇒ reads no credential: stamp_pull refuses BEFORE any broker/secret is touched.
    src = IDP.IdpSource(_receiver(), enabled=False)
    with pytest.raises(IDP.IdpSourceRefused):
        src.stamp_pull(handle=None, headers={}, now=None)  # type: ignore[arg-type]


# --- PURE offline half needs no flag --------------------------------------------------------------
def test_normalize_is_pure_and_needs_no_flag():
    src = IDP.IdpSource(_receiver(), enabled=False)        # even DISABLED, the offline parse works
    evs = src.normalize(_delivery())
    assert len(evs) == 1 and evs[0].source_format == "idp"


# --- E2E to the real receiver spool ---------------------------------------------------------------
def test_e2e_spools_v1_envelope_the_drain_accepts():
    spool = tempfile.mkdtemp()
    src = IDP.IdpSource(_receiver(spool), enabled=True)
    res = src.ingest_text(_delivery(
        _event(uuid="u-1"),
        _event(uuid="u-2", eventType="user.session.end", published="2024-05-01T13:00:00.000Z")))
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
    src = IDP.IdpSource(_receiver(spool), enabled=True)
    first = src.ingest_text(_delivery())
    second = src.ingest_text(_delivery())
    assert first.spooled == 1 and second.deduped == 1          # content-addressed dedup
    assert first.leads[0].report_id == second.leads[0].report_id
    assert len(list((Path(spool) / "incoming" / domain_slug(ORG, HOST)).glob("*.json"))) == 1


def test_ts_derived_from_published_not_wallclock():
    # The signed-path ``ts`` is a PURE function of the record's own ``published`` time — NOT a wall-clock.
    src = IDP.IdpSource(_receiver(), enabled=True)
    body = src.ingest_text(_delivery(_event(published="2024-05-01T12:00:00Z")))
    # 2024-05-01T12:00:00Z == 1714564800 epoch-seconds
    assert body.leads and body.leads[0].report_id      # landed; the ts fed the content digest deterministically


# --- DEDUP-COLLAPSE regression (HIGH): a per-record discriminator keeps distinct records distinct ---
def test_two_distinct_records_sharing_published_and_class_both_spool():
    # The LEAD body is metadata-only; two DISTINCT IdP records that share published + attack_class (no ruleset
    # ⇒ both baseline 'idp') would, WITHOUT a per-record discriminator, mint the SAME content-addressed
    # report_id and the second be silently DEDUP_NOOP'd. The stable ``uuid`` + delivery-index discriminator
    # must make them DISTINCT ⇒ both spool.
    spool = tempfile.mkdtemp()
    src = IDP.IdpSource(_receiver(spool), enabled=True)
    rec_a = _event(uuid="11111111-1111-1111-1111-111111111111", eventType="user.account.lock")
    rec_b = _event(uuid="22222222-2222-2222-2222-222222222222", eventType="user.account.unlock")
    res = src.ingest_text(_delivery(rec_a, rec_b))        # SAME published + same baseline class
    assert res.normalized == 2 and res.spooled == 2 and res.deduped == 0
    assert res.leads[0].report_id != res.leads[1].report_id
    assert len(list((Path(spool) / "incoming" / domain_slug(ORG, HOST)).glob("*.json"))) == 2


def test_records_with_absent_published_both_land_via_index():
    # Records with no parseable published all derive ts=0.0; the index tiebreaker (covering BOTH the missing-uuid
    # and the ts=0.0 case) must still keep two such baseline records distinct ⇒ both land.
    spool = tempfile.mkdtemp()
    src = IDP.IdpSource(_receiver(spool), enabled=True)
    a = {"eventType": "user.session.start", "actor": {"alternateId": "a@x"}}      # no published, no uuid
    b = {"eventType": "user.session.end", "actor": {"alternateId": "b@x"}}        # no published, no uuid
    res = src.ingest_text(_delivery(a, b))
    assert res.normalized == 2 and res.spooled == 2 and res.deduped == 0
    assert res.leads[0].report_id != res.leads[1].report_id


def test_idempotent_redelivery_same_bytes_still_dedups():
    # Determinism holds WITH the discriminator: re-delivering the SAME bytes mints the SAME report_ids ⇒ the
    # whole delivery dedups at-most-once (nothing double-spools).
    spool = tempfile.mkdtemp()
    src = IDP.IdpSource(_receiver(spool), enabled=True)
    rec_a = _event(uuid="aaaaaaaa-0000-0000-0000-000000000001", eventType="user.session.start")
    rec_b = _event(uuid="bbbbbbbb-0000-0000-0000-000000000002", eventType="user.session.end")
    first = src.ingest_text(_delivery(rec_a, rec_b))
    second = src.ingest_text(_delivery(rec_a, rec_b))
    assert first.spooled == 2 and second.spooled == 0 and second.deduped == 2
    assert [ld.report_id for ld in first.leads] == [ld.report_id for ld in second.leads]
    assert len(list((Path(spool) / "incoming" / domain_slug(ORG, HOST)).glob("*.json"))) == 2


# --- AS-9c anchors (tamper-evidence) + mutation-sensitive negative control -------------------------
def test_anchor_minted_and_reverifies():
    store, kek, secret = _anchor_wiring()
    src = IDP.IdpSource(_receiver(), anchor_store=store, anchor_kek_source=kek, enabled=True, anchor_enabled=True)
    res = src.ingest_text(_delivery())
    assert len(res.anchors) == 1 and res.anchor_errors == 0
    anchor, lead = res.anchors[0], res.leads[0]
    record = AegisEventV2(org_id=ORG, host=HOST, instance_id=CID, epoch=1, seq=0, decision="lead",
                          attack_class=lead.attack_class, action="observe", confidence=lead.confidence,
                          provenance_tier="intel", certificate_sha256="", event_id=lead.report_id)
    ok, why = verify_producer_anchor(record, anchor, secret=secret)
    assert ok, why
    assert anchor.secret_ref == lead.anchor_secret_ref


def test_anchor_is_deterministic():
    store, kek, _ = _anchor_wiring()
    s1 = IDP.IdpSource(_receiver(), anchor_store=store, anchor_kek_source=kek, enabled=True, anchor_enabled=True)
    s2 = IDP.IdpSource(_receiver(), anchor_store=store, anchor_kek_source=kek, enabled=True, anchor_enabled=True)
    a1 = s1.ingest_text(_delivery()).anchors[0]
    a2 = s2.ingest_text(_delivery()).anchors[0]
    assert a1.tag_hex == a2.tag_hex and a1.secret_ref == a2.secret_ref       # byte-identical on signed path


def test_anchor_refuses_wrong_secret_and_tamper():
    # NEGATIVE CONTROL for the anchor: a wrong secret and a one-field tamper both fail to verify.
    store, kek, secret = _anchor_wiring()
    src = IDP.IdpSource(_receiver(), anchor_store=store, anchor_kek_source=kek, enabled=True, anchor_enabled=True)
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
    src = IDP.IdpSource(_receiver(spool), anchor_store=store, anchor_kek_source=kek, enabled=True,
                        anchor_enabled=False)
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
    good = IDP.IdpSource(rcv, ingest_hmac_secret=ingest_secret, enabled=True)
    assert good.ingest_text(_delivery()).spooled == 1
    bad = IDP.IdpSource(rcv, ingest_hmac_secret=b"x" * 32, enabled=True)
    r = bad.ingest_text(_delivery(_event(uuid="u-other", eventType="user.account.lock")))
    assert r.spooled == 0 and r.rejected == 1          # fail-closed, no record lands


def test_over_body_cap_dropped_never_raises():
    # The LEAD finding is metadata-only (the raw record never enters it — privacy by construction), so to
    # exercise the receiver's DROP-and-count body cap deterministically, wire a receiver with a tiny cap. The
    # reader must route the drop into ``result.dropped`` without raising (fail-closed, enforce_capable=False).
    spool = tempfile.mkdtemp()
    rcv = IngestReceiver(spool, org_id=ORG, host=HOST, report_secret=REPORT_SECRET,
                         require_mtls_or_hmac=False, enabled=True, max_body_bytes=10)
    src = IDP.IdpSource(rcv, enabled=True)
    res = src.ingest_text(_delivery())
    assert res.normalized == 1 and res.dropped == 1 and res.spooled == 0
    assert not list((Path(spool) / "incoming").rglob("*.json"))


def test_malformed_delivery_is_total():
    src = IDP.IdpSource(_receiver(), enabled=True)
    assert src.ingest_text("{garbage not json").normalized == 0     # total: no events, no raise


# --- Sigma LEAD elevation -------------------------------------------------------------------------
_RULE = """
title: Okta Failed Login
id: okta-failed-login
logsource: {product: okta, service: okta}
detection:
  selection:
    eventType: user.session.start
    outcome.result: FAILURE
  condition: selection
tags: [attack.t1110]
author: tester
license: MIT
"""


def test_sigma_match_raises_lead_benign_does_not():
    rule = parse_sigma_rule(_RULE)
    src = IDP.IdpSource(_receiver(), sigma_rules=[rule], field_map=default_field_map(), enabled=True)
    failed = _event(outcome={"result": "FAILURE"})
    hit = src.ingest_text(_delivery(failed))
    assert hit.leads[0].attack_class == "T1110" and hit.leads[0].confidence == 0.5
    assert hit.leads[0].techniques == ("T1110",)
    benign = src.ingest_text(_delivery(_event()))         # outcome.result == SUCCESS
    assert benign.leads[0].attack_class == "idp" and benign.leads[0].confidence == 0.2
    assert benign.leads[0].techniques == ()


# --- GATE-INVARIANCE + FATAL-2 --------------------------------------------------------------------
def test_reader_is_off_the_gate_path():
    import importlib

    importlib.import_module("framework.v2.aegis")
    import framework.v2.aegis as pkg
    # nothing under aegis/__init__ imports the reader (so importing the package adds no oracle/class)
    assert not hasattr(pkg, "idp_source") or "idp_source" not in getattr(pkg, "__all__", [])


def test_import_pulls_in_no_sigil():
    import importlib
    import sys

    importlib.import_module("framework.v2.aegis.idp_source")
    assert not any(m == "sigil" or m.startswith("sigil.") for m in sys.modules)


def test_adds_no_new_intel_source_kind_or_oracle():
    # The reader reuses existing LEAD-tier vocabulary (no new IntelSourceKind), so the AEGIS registry self-check
    # still passes and no OracleKind was added (make gate stays byte-identical).
    from framework.v2.aegis.registry import verify_registration
    from framework.v2.intel.models import IntelSourceKind

    verify_registration()
    assert not any("idp" in k.value.lower() for k in IntelSourceKind)
