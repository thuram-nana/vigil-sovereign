"""AEGIS AS-2f — the SOVEREIGN v2 authority REGISTRY (grant/revoke/epoch/high-water/read-back/labels).

Deterministic, NO-LLM, FATAL-2-clean. Pins:
  * a minted v2 grant verifies against the owner root and a tampered one does not (read-back);
  * the per-subject EPOCH is strictly MONOTONE across grant -> revoke -> re-grant (high-water read-back);
  * ``issued_at`` is the anti-replay high-water (an old issued_at is refused) and is seeded from the spine;
  * NO tenant origin is attached (AS-2g seam): the published grant carries origin=None;
  * every authority mutation carries the TRUE A3 / explicit-required labels (never A0/auto) and the INTENT
    row precedes the grant;
  * the signing bytes are deterministic (same document -> identical bytes) and no model/framework is imported.
"""
from __future__ import annotations

import itertools
import os
import tempfile

import pytest

_iss = itertools.count(1000)


@pytest.fixture(autouse=True)
def _iso(monkeypatch):
    monkeypatch.setenv("VIGIL_BASE_DIR", tempfile.mkdtemp())
    monkeypatch.setenv("SIGIL_SPINE_DIR", tempfile.mkdtemp())
    monkeypatch.setenv("SIGIL_HOME", tempfile.mkdtemp())
    monkeypatch.setenv("VIGIL_MONITORING_PUBLISH_DIR", os.path.join(tempfile.mkdtemp(), "pub"))


def _store():
    from sigil.governor.identity import ensure_owner_keypair
    from sigil.spine.store import SpineStore
    ensure_owner_keypair()
    return SpineStore(os.path.join(tempfile.mkdtemp(), "spine.jsonl"))


def _prove(store, org, host, *, ttl=1e9):
    from sigil.governor.asset_ownership import METHOD_DNS_TXT, AssetOwnershipRegistry
    reg = AssetOwnershipRegistry(store)
    ch = reg.issue_challenge(org, host, issued_at=float(next(_iss)))
    reg.verify_and_record(org, host, method=METHOD_DNS_TXT, observed=[ch.marker], now=float(next(_iss)),
                          ttl_seconds=ttl)


def _owner_root():
    from sigil.governor.identity import owner_keypair
    from vigil_core import AuthorizerKey, TrustRoot
    return TrustRoot(threshold=1, authorizers=[
        AuthorizerKey(key_id="owner", name="owner", public_key_b64=owner_keypair().public_key_b64)])


def _reg(store):
    from sigil.governor.monitoring_authority_v2 import MonitoringAuthorityV2Registry
    return MonitoringAuthorityV2Registry(store)


def _grant(reg, org, host, caps, *, now, issued, window=1000.0, lease=200.0):
    return reg.grant(org, host, capabilities=caps, not_before=now, not_after=now + window,
                     lease_not_before=now, lease_not_after=now + lease, instance_id="i1", now=now,
                     issued_at=issued)


# --- positive mint + read-back ------------------------------------------------------------------------
def test_grant_publishes_a_verifiable_v2_authority_with_no_origin():
    from vigil_core.authority_v2 import MonitoringCapability, verify_monitoring_authority_v2
    s = _store()
    _prove(s, "org_a", "apme.cm")
    reg = _reg(s)
    view, signed = _grant(reg, "org_a", "apme.cm", [MonitoringCapability.OBSERVE], now=5000.0, issued=5000.0)
    assert view.epoch == 1 and [c.value for c in view.capabilities] == ["observe"]
    assert signed.document.origin is None and signed.document.origin_binding_sha256 is None     # AS-2g seam
    assert signed.document.edge_chain == "shared_actor"
    path = reg.publish(signed)
    back = reg.read_back(signed, _owner_root())                                   # read-back verifies
    assert back.document.epoch == 1
    ok, why = verify_monitoring_authority_v2(back, _owner_root())
    assert ok, why
    # a tampered published grant does not verify (every field is inside the signed bytes)
    tampered = signed.model_copy(update={"document": signed.document.model_copy(update={"epoch": 99})})
    assert verify_monitoring_authority_v2(tampered, _owner_root())[0] is False
    assert path.name.endswith(".json") and "apme" not in path.name                # hashed, no host string


def test_read_back_fails_closed_when_the_published_bytes_do_not_verify():
    from vigil_core.authority_v2 import MonitoringCapability
    s = _store()
    _prove(s, "org_a", "apme.cm")
    reg = _reg(s)
    _, signed = _grant(reg, "org_a", "apme.cm", [MonitoringCapability.OBSERVE], now=5000.0, issued=5000.0)
    reg.publish(signed)
    # a DIFFERENT (wrong) trust root => read-back refuses
    from vigil_core import AuthorizerKey, TrustRoot
    from vigil_core.crypto import generate_keypair
    wrong = TrustRoot(threshold=1, authorizers=[
        AuthorizerKey(key_id="x", name="x", public_key_b64=generate_keypair().public_key_b64)])
    with pytest.raises(ValueError, match="read-back failed"):
        reg.read_back(signed, wrong)


# --- high-water monotonicity + anti-replay ------------------------------------------------------------
def test_epoch_is_strictly_monotone_across_grant_revoke_regrant():
    from vigil_core.authority_v2 import MonitoringCapability
    s = _store()
    _prove(s, "org_a", "apme.cm")
    reg = _reg(s)
    v1, _ = _grant(reg, "org_a", "apme.cm", [MonitoringCapability.OBSERVE], now=5000.0, issued=5000.0)
    assert v1.epoch == 1 and reg.epoch_highwater("org_a", "apme.cm") == 1
    v2, _ = _grant(reg, "org_a", "apme.cm", [MonitoringCapability.OBSERVE], now=5001.0, issued=5001.0)
    assert v2.epoch == 2 and reg.epoch_highwater("org_a", "apme.cm") == 2
    seq, rev = reg.revoke("org_a", "apme.cm", issued_at=5002.0)
    assert rev.document.epoch == 3                                                # revoke advances the floor
    assert reg.epoch_highwater("org_a", "apme.cm") == 3
    assert reg.grant_for("org_a", "apme.cm") is None                              # revoked => not active
    v4, _ = _grant(reg, "org_a", "apme.cm", [MonitoringCapability.OBSERVE], now=5003.0, issued=5003.0)
    assert v4.epoch == 4                                                          # re-grant mints ABOVE the revoke
    assert reg.grant_for("org_a", "apme.cm").epoch == 4                           # and is active again


def test_issued_at_below_the_highwater_is_refused():
    from vigil_core.authority_v2 import MonitoringCapability
    s = _store()
    _prove(s, "org_a", "apme.cm")
    reg = _reg(s)
    _grant(reg, "org_a", "apme.cm", [MonitoringCapability.OBSERVE], now=5000.0, issued=5000.0)
    with pytest.raises(ValueError, match="anti-replay high-water"):
        _grant(reg, "org_a", "apme.cm", [MonitoringCapability.OBSERVE], now=5001.0, issued=4999.0)


def test_issued_highwater_seeds_a_fresh_registry():
    from vigil_core.authority_v2 import MonitoringCapability
    s = _store()
    _prove(s, "org_a", "apme.cm")
    _grant(_reg(s), "org_a", "apme.cm", [MonitoringCapability.OBSERVE], now=5000.0, issued=7777.0)
    # a BRAND-NEW registry reads the spine high-water back (no in-memory state carried over)
    assert _reg(s).issued_highwater("org_a", "apme.cm") == 7777.0
    assert _reg(s).epoch_highwater("org_a", "apme.cm") == 1


def test_no_ownership_proof_refused():
    from vigil_core.authority_v2 import MonitoringCapability
    s = _store()                                                                 # no proof minted
    reg = _reg(s)
    with pytest.raises(ValueError, match="ownership"):
        _grant(reg, "org_a", "apme.cm", [MonitoringCapability.OBSERVE], now=5000.0, issued=5000.0)
    assert reg.grant_for("org_a", "apme.cm") is None


def test_not_after_clamped_to_ownership_proof_expiry():
    from vigil_core.authority_v2 import MonitoringCapability
    from sigil.governor.asset_ownership import AssetOwnershipRegistry
    s = _store()
    _prove(s, "org_a", "apme.cm", ttl=50.0)                                       # a SHORT owner-signed expiry
    expiry = AssetOwnershipRegistry(s).proof("org_a", "apme.cm").expires_at
    reg = _reg(s)
    view, _ = reg.grant("org_a", "apme.cm", capabilities=[MonitoringCapability.OBSERVE], not_before=1001.0,
                        not_after=1001.0 + 1e9, lease_not_before=1001.0, lease_not_after=1001.5,
                        instance_id="i1", now=1001.0, issued_at=1001.0)
    assert view.not_after == expiry                                              # clamped to proven ownership
    assert view.not_after < 1001.0 + 1e9                                         # far below the (huge) requested end


# --- A3 labels + intent-row-first ---------------------------------------------------------------------
def test_authority_events_carry_a3_explicit_labels_and_intent_precedes_grant():
    from vigil_core.authority_v2 import MonitoringCapability
    from sigil.governor import monitoring_authority_v2 as m2
    s = _store()
    _prove(s, "org_a", "apme.cm")
    reg = _reg(s)
    reg.record_intent(requester="alice", org_id="org_a", host="apme.cm",
                      capabilities=[MonitoringCapability.OBSERVE], now=5000.0, issued_at=5000.0)
    _grant(reg, "org_a", "apme.cm", [MonitoringCapability.OBSERVE], now=5000.0, issued=5000.0)
    sigs, states = [], []
    for r in s.iter_records():
        p = getattr(r, "payload", None)
        if isinstance(p, dict) and str(p.get("signal", "")).startswith(m2.SIGNAL_V2):
            sigs.append(p.get("signal"))
            states.append(p)
    # the A0/auto mislabel is gone: every v2 authority event is A3 / explicit-required
    assert all(p.get("tier") == "A3" and p.get("decision") == "explicit-required" for p in states)
    # the INTENT row is appended FIRST, before the active grant record
    assert sigs[0] == m2.SIGNAL_V2_INTENT
    assert m2.SIGNAL_V2 in sigs and sigs.index(m2.SIGNAL_V2_INTENT) < sigs.index(m2.SIGNAL_V2)
    # the classifier itself puts a monitoring grant/revoke at A3 (the ONE classifier of record)
    assert m2.TIER_GRANT.label == "A3" and m2.DECISION_GRANT == "explicit-required"
    assert m2.TIER_REVOKE.label == "A3" and m2.DECISION_REVOKE == "explicit-required"


# --- epoch statement + capability shape ---------------------------------------------------------------
def test_epoch_statement_is_signed_and_verifies():
    from vigil_core.authority_v2 import verify_epoch_statement
    s = _store()
    _prove(s, "org_a", "apme.cm")
    reg = _reg(s)
    stmt = reg.issue_epoch_statement("org_a", "apme.cm", epoch=1, issued_at=5000.0)
    ok, why = verify_epoch_statement(stmt, _owner_root())
    assert ok, why
    assert stmt.document.epoch == 1 and stmt.document.subject.org_id == "org_a"


def test_enforcing_capabilities_are_carried_inside_the_signed_bytes():
    from vigil_core.authority_v2 import MonitoringCapability, verify_monitoring_authority_v2
    s = _store()
    _prove(s, "org_a", "apme.cm")
    reg = _reg(s)
    _, signed = _grant(reg, "org_a", "apme.cm",
                       [MonitoringCapability.OBSERVE, MonitoringCapability.RESPOND], now=5000.0, issued=5000.0)
    assert [c.value for c in signed.document.capabilities] == ["observe", "respond"]   # sorted + deduped
    # flipping a capability outside the signed bytes breaks verification
    flipped = signed.model_copy(update={"document": signed.document.model_copy(
        update={"capabilities": [MonitoringCapability.OBSERVE, MonitoringCapability.BLOCK]})})
    assert verify_monitoring_authority_v2(flipped, _owner_root())[0] is False


# --- determinism + FATAL-2 (no model / no framework on the signed path) -------------------------------
def test_signing_bytes_are_deterministic_no_model_in_the_loop():
    from vigil_core.authority_v2 import (MonitoringCapability, monitoring_authority_v2_signing_bytes)
    s = _store()
    _prove(s, "org_a", "apme.cm")
    reg = _reg(s)
    _, signed = _grant(reg, "org_a", "apme.cm",
                       [MonitoringCapability.RESPOND, MonitoringCapability.OBSERVE], now=5000.0, issued=5000.0)
    # the exact same document signs to byte-identical bytes every time (no wallclock / RNG / model on the path)
    b1 = monitoring_authority_v2_signing_bytes(signed.document)
    b2 = monitoring_authority_v2_signing_bytes(signed.document)
    assert b1 == b2 and isinstance(b1, bytes)


def test_fatal2_module_imports_no_framework_or_offense():
    # Isolated subprocess: importing the SOVEREIGN v2 module must not pull in `framework` / `strix` (the offense
    # tree) or any model/LLM client — the FATAL-2 two-plane boundary + the "no AI on authority paths" doctrine.
    import subprocess
    import sys
    code = ("import sys; import sigil.governor.monitoring_authority_v2 as m; "
            "bad=[k for k in sys.modules if k=='framework' or k.startswith('framework.') or k.startswith('strix')]; "
            "assert not bad, bad; print('ok')")
    r = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True)
    assert r.returncode == 0 and r.stdout.strip() == "ok", (r.stdout, r.stderr)
