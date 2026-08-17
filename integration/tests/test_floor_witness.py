"""Claim 6 / C-S4 — the witnessed-checkpoint anti-rollback floor anchor (OFFENSE parity).

Mirrors ``apps/sigil/tests/test_floor_witness.py`` for the offense high-water floor
(``vigil_core.highwater``). The offense witnessed checkpoint is co-signed with the offense GOVERNANCE key
(never an owner key). Same properties:

  * Risk #11 (rollback interlock): emit + retain at height N, then locally roll BOTH the head and the
    high-water floor back to a valid, genuinely-old signed height below N → ``verify_highwater_against_
    witnessed`` REFUSES; a genuine forward advance ACCEPTS.
  * Risk #13 (self-witness honesty): a threshold==1 governance-only self-witness is labelled DETECTION,
    never independence / split-view prevention.
  * Negatives: a forged / wrong-scope / stripped-floor anchor fails CLOSED.
  * FATAL-2: exercising the offense module imports NO ``sigil``/``apps.sigil``/``framework``.
"""
from __future__ import annotations

import sys

import pytest

from vigil_core import (
    AuthorizerKey, TrustRoot, build_chain, generate_keypair, sha256_hex, sign_head,
)
from vigil_integration import floor_witness as FW

SCOPE = "loopback"
GOV = generate_keypair()


def _chain(n, salt=""):
    entries = build_chain([sha256_hex(f"{i}:{salt}".encode()) for i in range(n)])
    head = sign_head(entries, engagement_slug=SCOPE, signers=[("spine", GOV.private_key_b64)])
    return entries, head


def _hw(head):
    return {"entry_count": head.entry_count, "last_seq": head.last_seq}


def _tr():
    return FW.offense_witness_trust_root(GOV.public_key_b64)


def _emit(head, retain, hw=None):
    return FW.emit_highwater_witness(head, hw if hw is not None else _hw(head),
                                     [FW.offense_governance_witness(GOV)], retain_path=retain, scope=SCOPE)


def _env(retain):
    return retain.read_text()


# --------------------------------------------------------------------- risk #11: rollback interlock -------

def test_genuine_forward_advance_accepts(tmp_path):
    retain = tmp_path / "hw-witnessed.json"
    _e2, h2 = _chain(2)
    _emit(h2, retain)
    _e5, h5 = _chain(5)
    ok, msg, _ = FW.verify_highwater_against_witnessed(h5, _hw(h5), [_env(retain)], scope=SCOPE, trust_root=_tr())
    assert ok, msg


def test_co_rewrite_head_and_floor_rollback_refused(tmp_path):
    retain = tmp_path / "hw-witnessed.json"
    _e5, h5 = _chain(5)
    _emit(h5, retain)
    _e3, h3 = _chain(3)                                   # a validly governance-signed OLD head at height 3
    ok, msg, _ = FW.verify_highwater_against_witnessed(h3, _hw(h3), [_env(retain)], scope=SCOPE, trust_root=_tr())
    assert not ok
    assert "ROLLBACK" in msg


def test_same_height_fork_refused(tmp_path):
    retain = tmp_path / "hw-witnessed.json"
    _e3, h3 = _chain(3)
    _emit(h3, retain)
    _e3f, h3f = _chain(3, salt="FORK")
    ok, msg, _ = FW.verify_highwater_against_witnessed(h3f, _hw(h3f), [_env(retain)], scope=SCOPE, trust_root=_tr())
    assert not ok
    assert "ROLLBACK/FORK" in msg


def test_floor_only_rollback_refused(tmp_path):
    retain = tmp_path / "hw-witnessed.json"
    _e5, h5 = _chain(5)
    _emit(h5, retain)
    _e8, h8 = _chain(8)
    ok, msg, _ = FW.verify_highwater_against_witnessed(h8, {"entry_count": 3, "last_seq": 2},
                                                       [_env(retain)], scope=SCOPE, trust_root=_tr())
    assert not ok
    assert "FLOOR ROLLBACK" in msg


def test_stripped_floor_refused(tmp_path):
    retain = tmp_path / "hw-witnessed.json"
    _e5, h5 = _chain(5)
    _emit(h5, retain)
    _e8, h8 = _chain(8)
    ok, msg, _ = FW.verify_highwater_against_witnessed(h8, None, [_env(retain)], scope=SCOPE, trust_root=_tr())
    assert not ok
    assert "FLOOR STRIPPED" in msg


# --------------------------------------------------------------------- negatives: fail-closed anchor ------

def test_forged_anchor_refused_fail_closed(tmp_path):
    retain = tmp_path / "hw-witnessed.json"
    _e5, h5 = _chain(5)
    _emit(h5, retain)
    forged = _env(retain).replace("\"entry_count\":5", "\"entry_count\":9")
    ok, msg, _ = FW.verify_highwater_against_witnessed(h5, _hw(h5), [forged], scope=SCOPE, trust_root=_tr())
    assert not ok
    assert "CANNOT VERIFY (refused)" in msg


def test_wrong_scope_anchor_refused(tmp_path):
    retain = tmp_path / "hw-witnessed.json"
    _e5, h5 = _chain(5)
    _emit(h5, retain)
    ok, msg, _ = FW.verify_highwater_against_witnessed(h5, _hw(h5), [_env(retain)],
                                                       scope="OTHER", trust_root=_tr())
    assert not ok
    assert "CANNOT VERIFY (refused)" in msg


def test_empty_sources_skips_anchor(tmp_path):
    _e5, h5 = _chain(5)
    ok, msg, _ = FW.verify_highwater_against_witnessed(h5, _hw(h5), [], scope=SCOPE, trust_root=_tr())
    assert ok
    assert "anchor skipped" in msg


def test_incoherent_highwater_head_emit_refused(tmp_path):
    retain = tmp_path / "hw-witnessed.json"
    _e5, h5 = _chain(5)
    _e3, h3 = _chain(3)
    with pytest.raises(FW.OffenseFloorWitnessError):
        FW.emit_highwater_witness(h5, _hw(h3), [FW.offense_governance_witness(GOV)],
                                  retain_path=retain, scope=SCOPE)


# --------------------------------------------------------------------- risk #13: self-witness honesty -----

def test_solo_self_witness_is_detection_not_independence(tmp_path):
    retain = tmp_path / "hw-witnessed.json"
    _e5, h5 = _chain(5)
    _emit(h5, retain)
    ok, _msg, label = FW.verify_highwater_against_witnessed(h5, _hw(h5), [_env(retain)],
                                                            scope=SCOPE, trust_root=_tr())
    assert ok
    assert "DETECTION only" in label
    assert "split-view prevention IF" not in label
    assert "independent parties (strict-majority set" not in label


def test_strict_majority_independent_set_labelled_conditional_prevention():
    keys = [generate_keypair() for _ in range(3)]
    tr = TrustRoot(threshold=2, authorizers=[
        AuthorizerKey(key_id=f"w{i}", name=f"w{i}", public_key_b64=k.public_key_b64)
        for i, k in enumerate(keys)])
    label = FW.offense_guarantee_label(tr)
    assert "split-view prevention IF the witness keys are held by independent parties" in label
    assert "independence is not checkable here" in label


# --------------------------------------------------------------------- FATAL-2 boundary -------------------

def test_fatal2_no_cross_plane_import():
    """Exercising the offense floor-witness path must never load a sovereign/framework module — the two
    trust domains never co-load (the witnessed checkpoint is inert bytes, read out-of-band)."""
    bad = [m for m in sys.modules
           if m == "sigil" or m.startswith("sigil.") or m.startswith("apps.sigil")
           or m.startswith("framework") or m.startswith("strix")]
    assert not bad, f"offense path co-loaded a cross-plane module: {bad}"
