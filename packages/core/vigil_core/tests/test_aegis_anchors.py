"""Deterministic, offline tests for vigil_core.aegis_anchors — AS-9c (two-anchor tamper-evidence).

Load-bearing invariants a false-green would break (an untrustworthy AEGIS record ingested as a FACT):

  * anchor-1 (PRODUCER) verifies a correctly connector-secret-signed record, and REFUSES fail-closed a
    wrong-secret, a tampered-body, and a wrong-connector (confused-deputy) record;
  * anchor-2 (OWNER) verifies a record under the current owner-signed head, and DETECTS tamper + reorder
    (a flipped/mutated chain fails);
  * COMBINED — a record is trustworthy ONLY when BOTH anchors verify; any single-anchor failure ⇒ refused;
  * OFFLINE RE-VERIFY / DETERMINISM — the same record yields byte-identical anchor digests, and both anchors
    re-check with vigil_core ALONE (no framework / strix / sigil import; no env/flag/clock/RNG on the path);
  * GATE-INVARIANCE — importing the module adds no oracle/class and has no runtime effect on any signed path.

All test-only secrets are random bytes sealed under a test KEK at runtime; no real or secret-shaped fixture
is committed (this exercises a producer-identity contract on a PUBLIC repo).
"""
from __future__ import annotations

import pathlib

import pytest

from vigil_core.aegis_anchors import (
    ANCHOR1_SCHEME,
    AegisAnchorError,
    AnchorVerification,
    ProducerAnchor,
    connector_secret_ref,
    open_and_verify_producer_anchor,
    produce_producer_anchor,
    record_cert_digest,
    require_trustworthy,
    verify_anchored_record,
    verify_anchored_record_sealed,
    verify_owner_anchor,
    verify_producer_anchor,
)
from vigil_core.aegis_schemas import AdapterCapability, AegisEventV2, EffectVerification, OutcomeClass
from vigil_core.aegis_sealing import SecretKind, seal_secret
from vigil_core.chain import build_chain, sign_head
from vigil_core.crypto import generate_keypair
from vigil_core.models import AuthorizerKey, ChainEntry, TrustRoot

KEK = b"\x11" * 32
SECRET_SLACK = b"connector-secret-slack-aaaaaa"       # >= 16 bytes
SECRET_PAGERDUTY = b"connector-secret-pagerduty-bb"
OWNER = generate_keypair()
ATTACKER = generate_keypair()


def _owner_root(key=OWNER) -> TrustRoot:
    return TrustRoot(threshold=1, authorizers=[
        AuthorizerKey(key_id="owner", name="owner", public_key_b64=key.public_key_b64)])


def _event(**over) -> AegisEventV2:
    base = dict(org_id="acme", host="api.example.com", instance_id="i1", epoch=2, seq=5,
                decision="confirmed", event_id="e1")
    base.update(over)
    return AegisEventV2(**base)


def _anchor(record, *, org="acme", connector_id="slack", epoch=2, secret=SECRET_SLACK) -> ProducerAnchor:
    return produce_producer_anchor(record, org=org, connector_id=connector_id, epoch=epoch, secret=secret)


def _chain_and_head(records, *, key=OWNER):
    entries = build_chain([r.digest() for r in records])
    head = sign_head(entries, engagement_slug="acme", signers=[("owner", key.private_key_b64)])
    return entries, head


# ============================================================================================
# anchor-1 (PRODUCER): verifies a correct record; refuses wrong-secret / tampered / wrong-connector
# ============================================================================================
def test_anchor1_verifies_correct_record():
    rec = _event()
    anc = _anchor(rec)
    ok, why = verify_producer_anchor(rec, anc, secret=SECRET_SLACK)
    assert ok, why
    assert anc.scheme == ANCHOR1_SCHEME
    assert anc.secret_ref == connector_secret_ref("acme", "slack", 2)


def test_anchor1_refuses_wrong_secret():
    rec = _event()
    anc = _anchor(rec)
    ok, why = verify_producer_anchor(rec, anc, secret=b"a-totally-different-secret-xx")
    assert not ok
    assert "HMAC does not verify" in why


def test_anchor1_refuses_tampered_body():
    rec = _event()
    anc = _anchor(rec)
    # Any one-field change moves the canonical bytes; the tag (made over the original) no longer verifies.
    tampered = _event(decision="clear")
    assert tampered.canonical_bytes() != rec.canonical_bytes()
    ok, why = verify_producer_anchor(tampered, anc, secret=SECRET_SLACK)
    assert not ok
    assert "HMAC does not verify" in why


def test_anchor1_refuses_wrong_connector_confused_deputy():
    # A producer holding PAGERDUTY's secret labels the record as SLACK's (anchor.connector_id="slack").
    # It can only MAC with its own secret; the verifier recomputes under SLACK's secret -> mismatch.
    rec = _event()
    forged = produce_producer_anchor(rec, org="acme", connector_id="slack", epoch=2, secret=SECRET_PAGERDUTY)
    ok, why = verify_producer_anchor(rec, forged, secret=SECRET_SLACK)
    assert not ok
    assert "HMAC does not verify" in why


def test_anchor1_refuses_unknown_scheme():
    rec = _event()
    anc = _anchor(rec)
    bad = ProducerAnchor(org=anc.org, connector_id=anc.connector_id, epoch=anc.epoch,
                         secret_ref=anc.secret_ref, tag_hex=anc.tag_hex, scheme="some-other-scheme")
    ok, why = verify_producer_anchor(rec, bad, secret=SECRET_SLACK)
    assert not ok
    assert "unknown scheme" in why


def test_anchor1_refuses_lying_secret_ref():
    # An anchor that misstates which credential identity it used (secret_ref for a DIFFERENT connector)
    # is refused on the self-consistency conjunct, before the HMAC compare.
    rec = _event()
    anc = _anchor(rec)
    wrong_ref = connector_secret_ref("acme", "pagerduty", 2)
    assert wrong_ref != anc.secret_ref
    lying = ProducerAnchor(org="acme", connector_id="slack", epoch=2, secret_ref=wrong_ref,
                           tag_hex=anc.tag_hex)
    ok, why = verify_producer_anchor(rec, lying, secret=SECRET_SLACK)
    assert not ok
    assert "secret_ref does not match" in why


def test_anchor1_refuses_non_hex_tag():
    rec = _event()
    anc = _anchor(rec)
    bad = ProducerAnchor(org="acme", connector_id="slack", epoch=2, secret_ref=anc.secret_ref,
                         tag_hex="zz-not-hex")
    ok, why = verify_producer_anchor(rec, bad, secret=SECRET_SLACK)
    assert not ok
    assert "not valid hex" in why


# ---- the SEALED path (sovereign-side open) and its confused-deputy wall --------------------
def test_anchor1_sealed_path_verifies():
    rec = _event()
    anc = _anchor(rec)
    sealed = seal_secret(KEK, SecretKind.CONNECTOR, "acme", "slack", 2, SECRET_SLACK)
    ok, why = open_and_verify_producer_anchor(rec, anc, sealed=sealed, kek=KEK)
    assert ok, why


def test_anchor1_sealed_path_refuses_wrong_connector_credential():
    # Confused-deputy at the sealing layer: a SLACK anchor presented with PAGERDUTY's sealed secret is
    # refused BEFORE any open (the sealed binding does not match the anchor's connector).
    rec = _event()
    anc = _anchor(rec)
    sealed_pd = seal_secret(KEK, SecretKind.CONNECTOR, "acme", "pagerduty", 2, SECRET_PAGERDUTY)
    ok, why = open_and_verify_producer_anchor(rec, anc, sealed=sealed_pd, kek=KEK)
    assert not ok
    assert "wrong connector" in why


def test_anchor1_sealed_path_refuses_wrong_kek():
    rec = _event()
    anc = _anchor(rec)
    sealed = seal_secret(KEK, SecretKind.CONNECTOR, "acme", "slack", 2, SECRET_SLACK)
    ok, why = open_and_verify_producer_anchor(rec, anc, sealed=sealed, kek=b"\x22" * 32)
    assert not ok
    assert "failed to open" in why


def test_anchor1_sealed_path_refuses_stale_epoch():
    # A record anchored at epoch 2 presented with the epoch-3 (rotated) sealed credential is refused.
    rec = _event(epoch=2)
    anc = _anchor(rec, epoch=2)
    sealed_e3 = seal_secret(KEK, SecretKind.CONNECTOR, "acme", "slack", 3, SECRET_SLACK)
    ok, why = open_and_verify_producer_anchor(rec, anc, sealed=sealed_e3, kek=KEK)
    assert not ok
    assert "wrong connector" in why  # (org, connector, epoch) mismatch -> refused before open


# ============================================================================================
# anchor-2 (OWNER / SPINE): verifies under the current head; detects tamper + reorder
# ============================================================================================
def test_anchor2_verifies_record_under_owner_head():
    rec, other = _event(event_id="e1"), _event(event_id="e2", seq=6, decision="lead")
    entries, head = _chain_and_head([rec, other])
    ok, why = verify_owner_anchor(rec, entries, head, _owner_root())
    assert ok, why


def test_anchor2_detects_reorder_flip_fails():
    rec, other = _event(event_id="e1"), _event(event_id="e2", seq=6, decision="lead")
    entries, head = _chain_and_head([rec, other])
    # Flipping the entry order breaks prev_hash linkage: the owner head no longer verifies.
    ok, why = verify_owner_anchor(rec, list(reversed(entries)), head, _owner_root())
    assert not ok
    assert "does not verify" in why


def test_anchor2_detects_tampered_entry():
    rec, other = _event(event_id="e1"), _event(event_id="e2", seq=6, decision="lead")
    entries, head = _chain_and_head([rec, other])
    # Rewrite a stored record's cert_digest (its entry_hash no longer matches) -> tamper caught.
    tampered = list(entries)
    tampered[0] = ChainEntry(seq=entries[0].seq, prev_hash=entries[0].prev_hash,
                             cert_digest="f" * 64, entry_hash=entries[0].entry_hash)
    ok, why = verify_owner_anchor(rec, tampered, head, _owner_root())
    assert not ok
    assert "does not verify" in why


def test_anchor2_refuses_record_not_in_chain():
    # A valid owner head over OTHER records does not launder a record that was never appended.
    anchored, outsider = _event(event_id="e1"), _event(event_id="e-outsider", seq=99)
    entries, head = _chain_and_head([anchored])
    ok, why = verify_owner_anchor(outsider, entries, head, _owner_root())
    assert not ok
    assert "not present in the owner-anchored chain" in why


def test_anchor2_refuses_wrong_owner_key():
    rec = _event()
    entries, head = _chain_and_head([rec])
    # The head is signed by OWNER; a trust root pinned to the ATTACKER key must not verify it.
    ok, why = verify_owner_anchor(rec, entries, head, _owner_root(ATTACKER))
    assert not ok
    assert "does not verify" in why


def test_anchor2_refuses_rollback_below_highwater():
    rec = _event()
    entries, head = _chain_and_head([rec])
    ok, why = verify_owner_anchor(rec, entries, head, _owner_root(), prev_highwater=head.last_seq + 10)
    assert not ok
    assert "does not verify" in why


# ============================================================================================
# COMBINED: trustworthy ONLY when BOTH anchors verify
# ============================================================================================
def test_combined_trustworthy_only_when_both_verify():
    rec = _event()
    anc = _anchor(rec)
    entries, head = _chain_and_head([rec])
    v = verify_anchored_record(rec, anc, secret=SECRET_SLACK, entries=entries, head=head,
                               trust_root=_owner_root())
    assert isinstance(v, AnchorVerification)
    assert v.trustworthy and v.anchor1_ok and v.anchor2_ok
    require_trustworthy(v)  # does not raise


def test_combined_refused_when_anchor1_fails():
    rec = _event()
    anc = _anchor(rec)
    entries, head = _chain_and_head([rec])  # anchor-2 is sound
    v = verify_anchored_record(rec, anc, secret=b"wrong-secret-xxxxxxxxxxxx", entries=entries, head=head,
                               trust_root=_owner_root())
    assert not v.trustworthy
    assert v.anchor2_ok and not v.anchor1_ok
    with pytest.raises(AegisAnchorError):
        require_trustworthy(v)


def test_combined_refused_when_anchor2_fails():
    rec = _event()
    anc = _anchor(rec)  # anchor-1 is sound
    # A head over a DIFFERENT record: anchor-2 cannot find rec in the chain.
    entries, head = _chain_and_head([_event(event_id="other", seq=42)])
    v = verify_anchored_record(rec, anc, secret=SECRET_SLACK, entries=entries, head=head,
                               trust_root=_owner_root())
    assert not v.trustworthy
    assert v.anchor1_ok and not v.anchor2_ok


def test_combined_sealed_path_both_verify():
    rec = _event()
    anc = _anchor(rec)
    sealed = seal_secret(KEK, SecretKind.CONNECTOR, "acme", "slack", 2, SECRET_SLACK)
    entries, head = _chain_and_head([rec])
    v = verify_anchored_record_sealed(rec, anc, sealed=sealed, kek=KEK, entries=entries, head=head,
                                      trust_root=_owner_root())
    assert v.trustworthy


def test_combined_works_for_any_canonical_record():
    # The contract anchors ANY AS-2b CanonicalModel, not only AegisEventV2 (e.g. an AdapterCapability).
    rec = AdapterCapability(kind="inline_block", outcome_class=OutcomeClass.PREVENTED_BEFORE_EXECUTION,
                            effect_verification=EffectVerification.RECEIPT)
    anc = _anchor(rec)
    entries, head = _chain_and_head([rec])
    v = verify_anchored_record(rec, anc, secret=SECRET_SLACK, entries=entries, head=head,
                               trust_root=_owner_root())
    assert v.trustworthy


# ============================================================================================
# OFFLINE RE-VERIFY / DETERMINISM
# ============================================================================================
def test_same_record_yields_byte_identical_anchor_digests():
    rec = _event()
    a1 = produce_producer_anchor(rec, org="acme", connector_id="slack", epoch=2, secret=SECRET_SLACK)
    a2 = produce_producer_anchor(rec, org="acme", connector_id="slack", epoch=2, secret=SECRET_SLACK)
    assert a1.tag_hex == a2.tag_hex                 # anchor-1 is a pure function (no clock, no RNG)
    assert a1.secret_ref == a2.secret_ref
    assert record_cert_digest(rec) == rec.digest() == record_cert_digest(_event())  # anchor-2 content id stable


def test_both_anchors_reverify_with_vigil_core_alone():
    # The module imports vigil_core + stdlib ONLY — no framework / strix / sigil (like finding_receiver.py:5-8),
    # so an offline re-verify needs nothing from the offense engine or the sovereign app.
    import vigil_core.aegis_anchors as mod
    src = pathlib.Path(mod.__file__).read_text(encoding="utf-8")
    for forbidden in ("import framework", "from framework", "import strix", "from strix",
                      "import sigil", "from sigil"):
        assert forbidden not in src, f"aegis_anchors must not {forbidden!r} (FATAL-2 cross-plane contract)"
    # Determinism on the signed path: no env/flag, no wallclock, no RNG anywhere in the module.
    for forbidden in ("os.environ", "import os", "time.time", "random", "datetime", "urandom"):
        assert forbidden not in src, f"aegis_anchors must not reference {forbidden!r} (determinism/no-flag)"


# ============================================================================================
# GATE-INVARIANCE — a pure inert contract: import has no runtime effect on any signed/request path
# ============================================================================================
def test_import_is_inert_and_registers_nothing():
    import importlib

    import vigil_core.aegis_anchors as mod
    # Re-importing is a no-op (idempotent, no module-level side effect to re-run).
    again = importlib.import_module("vigil_core.aegis_anchors")
    assert again is mod
    # The module exposes exactly its declared contract surface and no mutable registry/oracle object.
    public = {n for n in dir(mod) if not n.startswith("_")}
    assert set(mod.__all__).issubset(public)


def test_malformed_anchor_is_refused_at_construction():
    with pytest.raises(AegisAnchorError):
        ProducerAnchor(org="", connector_id="slack", epoch=2, secret_ref="0" * 16, tag_hex="ab")
    with pytest.raises(AegisAnchorError):
        ProducerAnchor(org="acme", connector_id="slack", epoch=-1, secret_ref="0" * 16, tag_hex="ab")


def test_verify_never_raises_on_hostile_input():
    # Fail-closed: verify returns (False, reason), never an uncaught exception, on garbage.
    rec = _event()
    anc = _anchor(rec)
    bad_entry = ChainEntry(seq=0, prev_hash="0" * 64, cert_digest="x", entry_hash="y")
    ok, _ = verify_owner_anchor(rec, [bad_entry], _chain_and_head([rec])[1], _owner_root())
    assert ok is False
