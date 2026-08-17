"""Claim 6 / C-S4 — the witnessed-checkpoint anti-rollback FLOOR anchor (sovereign side).

Closes the C-S2/C-S3 residual (``floor.py`` §1.3): a same-host attacker with the owner UID rewrites
``head.json`` AND ``floor.json`` together (or strips a signed floor to unsigned), and a purely LOCAL verify
re-reads both from that same attacker-controlled disk — so it cannot catch the rollback. A verifier that
RETAINED an off-box witness-cosigned checkpoint at height N catches any local head/floor below N (a
co-rewrite) or forked at N.

Risk #11 (rollback interlock): emit + retain at height N, then locally roll BOTH head and floor back below N
(a valid, genuinely-old owner-signed head) → ``verify_floor_against_witnessed`` REFUSES; a genuine forward
advance ACCEPTS. Risk #13 (self-witness honesty): a threshold==1 owner-only self-witness is labelled
DETECTION, never independence. Negatives: a forged / wrong-scope / stripped-floor anchor fails CLOSED.
"""
from __future__ import annotations

import pytest

from sigil.reuse import build_chain, digest_payload, generate_keypair
from sigil.reuse.chain import sign_head
from sigil.spine import witness as W
from sigil.spine.floor import Floor
from sigil.spine import floor_witness as FW
from vigil_core import AuthorizerKey, TrustRoot
from vigil_integration.transparency import Witness

SCOPE = "sigil"
OWNER = generate_keypair()


def _chain(n, salt=""):
    entries = build_chain([digest_payload({"i": i, "s": salt}) for i in range(n)])
    head = sign_head(entries, engagement_slug=SCOPE, signers=[("owner", OWNER.private_key_b64)])
    return entries, head


def _floor(head):
    """A durable floor that TRACKS ``head`` exactly (as ``advance_floor`` would produce it)."""
    return Floor(scope=SCOPE, entry_count=head.entry_count, last_seq=head.last_seq,
                 base_seq=head.base_seq, base_count=head.base_count,
                 head_sig_hash="a" * 64, updated_ts="t")


def _owner_witness():
    return Witness("owner", OWNER.private_key_b64)


def _tr():
    return W.witness_trust_root(None, owner_pub=OWNER.public_key_b64, owner_key_id="owner")


def _emit(head, retain, floor=None):
    return FW.emit_floor_witness(head, floor if floor is not None else _floor(head),
                                 [_owner_witness()], retain_path=retain, scope=SCOPE)


def _env(retain):
    return retain.read_text()


# --------------------------------------------------------------------- risk #11: rollback interlock -------

def test_genuine_forward_advance_accepts(tmp_path):
    retain = tmp_path / "floor-witnessed.json"
    _e2, h2 = _chain(2)
    _emit(h2, retain)
    _e5, h5 = _chain(5)                                   # same salt → a real forward extension
    ok, msg, _ = FW.verify_floor_against_witnessed(h5, _floor(h5), [_env(retain)], scope=SCOPE, trust_root=_tr())
    assert ok, msg
    assert "no rollback below it" in msg


def test_co_rewrite_head_and_floor_rollback_refused(tmp_path):
    """The whole point: BOTH the head and the floor rolled back to a valid, genuinely-old owner-signed
    height below the retained witnessed checkpoint → REFUSE."""
    retain = tmp_path / "floor-witnessed.json"
    _e5, h5 = _chain(5)
    _emit(h5, retain)                                     # retained at height 5
    _e3, h3 = _chain(3)                                   # a validly-signed OLD head at height 3
    ok, msg, _ = FW.verify_floor_against_witnessed(h3, _floor(h3), [_env(retain)], scope=SCOPE, trust_root=_tr())
    assert not ok
    assert "ROLLBACK" in msg


def test_same_height_fork_refused(tmp_path):
    retain = tmp_path / "floor-witnessed.json"
    _e3, h3 = _chain(3)
    _emit(h3, retain)
    _e3f, h3f = _chain(3, salt="FORK")                   # same height, different head
    ok, msg, _ = FW.verify_floor_against_witnessed(h3f, _floor(h3f), [_env(retain)], scope=SCOPE, trust_root=_tr())
    assert not ok
    assert "ROLLBACK/FORK" in msg


def test_floor_only_rollback_refused(tmp_path):
    """Head stays high, but the FLOOR was rolled back below the witnessed height — the floor-side catch."""
    retain = tmp_path / "floor-witnessed.json"
    _e5, h5 = _chain(5)
    _emit(h5, retain)
    _e8, h8 = _chain(8)
    ok, msg, _ = FW.verify_floor_against_witnessed(h8, _floor(_chain(3)[1]), [_env(retain)],
                                                   scope=SCOPE, trust_root=_tr())
    assert not ok
    assert "FLOOR ROLLBACK" in msg


def test_stripped_floor_refused(tmp_path):
    """Floor removed entirely while a witnessed checkpoint at height>0 was retained → REFUSE."""
    retain = tmp_path / "floor-witnessed.json"
    _e5, h5 = _chain(5)
    _emit(h5, retain)
    _e8, h8 = _chain(8)
    ok, msg, _ = FW.verify_floor_against_witnessed(h8, None, [_env(retain)], scope=SCOPE, trust_root=_tr())
    assert not ok
    assert "FLOOR STRIPPED" in msg


# --------------------------------------------------------------------- negatives: fail-closed anchor ------

def test_forged_anchor_refused_fail_closed(tmp_path):
    """A tampered witnessed checkpoint (signature no longer verifies) supplied as the anchor must REFUSE,
    never fall through to a pass."""
    retain = tmp_path / "floor-witnessed.json"
    _e5, h5 = _chain(5)
    _emit(h5, retain)
    forged = _env(retain).replace("\"entry_count\":5", "\"entry_count\":9")  # break the signed bytes
    ok, msg, _ = FW.verify_floor_against_witnessed(h5, _floor(h5), [forged], scope=SCOPE, trust_root=_tr())
    assert not ok
    assert "CANNOT VERIFY (refused)" in msg


def test_wrong_scope_anchor_refused(tmp_path):
    retain = tmp_path / "floor-witnessed.json"
    _e5, h5 = _chain(5)
    _emit(h5, retain)
    ok, msg, _ = FW.verify_floor_against_witnessed(h5, _floor(h5), [_env(retain)],
                                                   scope="OTHER-SCOPE", trust_root=_tr())
    assert not ok
    assert "CANNOT VERIFY (refused)" in msg


def test_empty_sources_skips_anchor(tmp_path):
    """A verifier that retained NOTHING gets exactly today's local-only guarantee — no false refusal."""
    _e5, h5 = _chain(5)
    ok, msg, _ = FW.verify_floor_against_witnessed(h5, _floor(h5), [], scope=SCOPE, trust_root=_tr())
    assert ok
    assert "anchor skipped" in msg


def test_incoherent_floor_head_emit_refused(tmp_path):
    """Emit refuses to witness a head the floor does not track (a mismatched pair would misrepresent the
    floor's committed height)."""
    retain = tmp_path / "floor-witnessed.json"
    _e5, h5 = _chain(5)
    _e3, h3 = _chain(3)
    with pytest.raises(FW.FloorWitnessError):
        FW.emit_floor_witness(h5, _floor(h3), [_owner_witness()], retain_path=retain, scope=SCOPE)


# --------------------------------------------------------------------- risk #13: self-witness honesty -----

def test_solo_self_witness_is_detection_not_independence(tmp_path):
    """The default owner-only, threshold==1 witness is retention-based DETECTION — NEVER labelled
    'independent' / 'split-view prevention'. This is the load-bearing honesty of C-S4."""
    retain = tmp_path / "floor-witnessed.json"
    _e5, h5 = _chain(5)
    _emit(h5, retain)
    ok, _msg, label = FW.verify_floor_against_witnessed(h5, _floor(h5), [_env(retain)],
                                                        scope=SCOPE, trust_root=_tr())
    assert ok
    assert "DETECTION only" in label
    # No affirmative independence / prevention claim for a solo self-witness.
    assert "split-view prevention IF" not in label
    assert "independent parties (strict-majority set" not in label


def test_strict_majority_independent_set_labelled_conditional_prevention():
    """Contrast (guards against a blanket-DETECTION regression): a 2-of-3 strict-majority set of DISTINCT
    keys is labelled CONDITIONAL prevention — 'IF the witness keys are held by independent parties'."""
    keys = [generate_keypair() for _ in range(3)]
    tr = TrustRoot(threshold=2, authorizers=[
        AuthorizerKey(key_id=f"w{i}", name=f"w{i}", public_key_b64=k.public_key_b64)
        for i, k in enumerate(keys)])
    label = FW.WA.guarantee_label(tr)
    assert "split-view prevention IF the witness keys are held by independent parties" in label
    # …still HONEST: it says IF independently held, never asserts independence outright.
    assert "independence is not checkable here" in label
