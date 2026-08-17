"""Claim 6 Piece B (B-S4) — the HA active-passive FAILOVER INTERLOCK.

Risk #11 (failover rollback interlock): a passive whose local spine head is BELOW the highest off-box
witnessed checkpoint MUST be refused (fail-closed, exit 2); a head at/above the witnessed height
activates. Risk #13 (self-witness honesty): a solo/owner-only (threshold==1) witness anchor is labelled
retention-based DETECTION, NEVER independent "split-view-resistant".

The guard lives at tools/ha/spine_failover_guard.py (not an installed package); load it by path. Fixtures
mirror test_witness_checkpoint.py: witness.py is config-free, so keys + heads are injected directly.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest
from vigil_integration.transparency import Witness

from sigil.reuse import build_chain, digest_payload, generate_keypair
from sigil.reuse.chain import sign_head
from sigil.spine import witness as W

_REPO = Path(__file__).resolve().parents[3]
_GUARD_DIR = _REPO / "tools" / "ha"
if str(_GUARD_DIR) not in sys.path:
    sys.path.insert(0, str(_GUARD_DIR))
import spine_failover_guard as guard  # noqa: E402

OWNER = generate_keypair()
SCOPE = "sigil"


def _chain(n, salt=""):
    entries = build_chain([digest_payload({"i": i, "s": salt}) for i in range(n)])
    head = sign_head(entries, engagement_slug=SCOPE, signers=[("owner", OWNER.private_key_b64)])
    return entries, head


def _solo_tr():
    """The DEFAULT owner-only, threshold-1 witness set — a solo self-witness (DETECTION, not independence)."""
    return W.witness_trust_root(None, owner_pub=OWNER.public_key_b64, owner_key_id="owner")


def _owner_tr():
    """The OWNER trust root (owner-only, threshold 1) the LOCAL head is AUTHENTICATED against — the same
    anchor the live spine's verify_checkpoint uses. Distinct from the witness quorum trust_root (which may
    add independent witness keys); here they coincide only because OWNER is the solo witness too."""
    return W.witness_trust_root(None, owner_pub=OWNER.public_key_b64, owner_key_id="owner")


def _witnessed_env(head, tmp_path):
    wc = W.emit_checkpoint(head, [Witness("owner", OWNER.private_key_b64)],
                           tip_path=tmp_path / "tip", scope=SCOPE)
    return W.dump_witnessed(wc, scope=SCOPE)


# --------------------------------------------------------------- risk #11: the rollback interlock

def test_head_at_witnessed_height_activates(tmp_path):
    e2, h2 = _chain(2)
    env = _witnessed_env(h2, tmp_path)
    v = guard.evaluate_promotion(h2, env, scope=SCOPE, trust_root=_solo_tr(),
                                 owner_trust_root=_owner_tr(), entries=e2)
    assert v.activate and v.exit_code == 0 and "safe to promote" in v.reason


def test_head_above_witnessed_activates(tmp_path):
    _e2, h2 = _chain(2)
    env = _witnessed_env(h2, tmp_path)          # witnessed at count 2
    e3, h3 = _chain(3)                           # local head grew to count 3 (same history — extension)
    v = guard.evaluate_promotion(h3, env, scope=SCOPE, trust_root=_solo_tr(),
                                 owner_trust_root=_owner_tr(), entries=e3)
    assert v.activate and v.exit_code == 0


def test_stale_passive_below_witnessed_refuses(tmp_path):
    """THE interlock: a passive at count 2, off-box witnessed checkpoint at count 3 -> REFUSE (exit 2)."""
    _e3, h3 = _chain(3)
    env = _witnessed_env(h3, tmp_path)          # witnessed at count 3
    e2, h2 = _chain(2)                           # stale mirror: local head only at count 2
    v = guard.evaluate_promotion(h2, env, scope=SCOPE, trust_root=_solo_tr(),
                                 owner_trust_root=_owner_tr(), entries=e2)
    assert not v.activate and v.exit_code == 2 and "ROLLBACK" in v.reason


def test_forged_or_unsigned_checkpoint_refuses(tmp_path):
    """A 'checkpoint' not signed by a trusted witness quorum is not a floor -> fail-closed refuse."""
    e2, h2 = _chain(2)
    env = json.loads(_witnessed_env(h2, tmp_path))
    env["checkpoint"]["entry_count"] = 999       # invalidates the witness signature
    v = guard.evaluate_promotion(h2, json.dumps(env), scope=SCOPE, trust_root=_solo_tr(),
                                 owner_trust_root=_owner_tr(), entries=e2)
    assert not v.activate and v.exit_code == 2 and "trusted witness quorum" in v.reason


def test_wrong_scope_refuses(tmp_path):
    e2, h2 = _chain(2)
    env = json.loads(_witnessed_env(h2, tmp_path))
    env["scope"] = "some-other-store"
    v = guard.evaluate_promotion(h2, json.dumps(env), scope=SCOPE, trust_root=_solo_tr(),
                                 owner_trust_root=_owner_tr(), entries=e2)
    assert not v.activate and v.exit_code == 2 and "scope" in v.reason


def test_no_local_head_refuses(tmp_path):
    _e2, h2 = _chain(2)
    env = _witnessed_env(h2, tmp_path)
    v = guard.evaluate_promotion(None, env, scope=SCOPE, trust_root=_solo_tr(),
                                 owner_trust_root=_owner_tr(), entries=[])
    assert not v.activate and v.exit_code == 2 and "no local spine head" in v.reason


def test_malformed_envelope_refuses():
    e2, h2 = _chain(2)
    out = guard.evaluate_promotion(h2, "not a checkpoint envelope", scope=SCOPE, trust_root=_solo_tr(),
                                   owner_trust_root=_owner_tr(), entries=e2)
    assert not out.activate and out.exit_code == 2 and "unreadable" in out.reason


# --------------------------------------------------------------- risk #13: self-witness honesty

def test_solo_witness_is_labelled_detection_not_independence(tmp_path):
    e2, h2 = _chain(2)
    env = _witnessed_env(h2, tmp_path)
    v = guard.evaluate_promotion(h2, env, scope=SCOPE, trust_root=_solo_tr(),
                                 owner_trust_root=_owner_tr(), entries=e2)
    assert v.activate                                   # activation is fine...
    assert v.independent is False                       # ...but it is NOT independent
    blob = " ".join(v.lines())
    assert "DETECTION" in blob and "NOT independent" in blob
    assert "split-view-resistant" not in blob           # never claim prevention for a solo self-witness


def test_independent_quorum_is_labelled_independent(tmp_path):
    """A 2-of-2 roster of DISTINCT keys is labelled (conditional) prevention, not DETECTION-only."""
    phone = generate_keypair()
    core = W.set_roster([{"key_id": "owner", "public_key_b64": OWNER.public_key_b64},
                         {"key_id": "phone", "public_key_b64": phone.public_key_b64}],
                        threshold=2, path=tmp_path / "roster.json", owner_key=OWNER, scope=SCOPE)
    tr = W.witness_trust_root(core, owner_pub=OWNER.public_key_b64, owner_key_id="owner")
    e2, h2 = _chain(2)
    # owner emits, phone co-signs on its own box (the honest stand-in) -> a full 2-of-2 quorum.
    wc = W.emit_checkpoint(h2, [Witness("owner", OWNER.private_key_b64)], tip_path=tmp_path / "tip", scope=SCOPE)
    env = W.cosign_envelope(W.dump_witnessed(wc, scope=SCOPE), witness_key_id="phone",
                            witness_priv_b64=phone.private_key_b64)
    # the LOCAL head is owner-signed -> authenticated against the owner-only root, even though the WITNESS
    # quorum is the 2-of-2 (owner+phone) set.
    v = guard.evaluate_promotion(h2, env, scope=SCOPE, trust_root=tr,
                                 owner_trust_root=_owner_tr(), entries=e2)
    assert v.activate and v.independent is True and "prevention IF" in v.guarantee


# ------------------------------------------------ soundness: authenticate + bind the LOCAL head (BLOCK fix)

def test_attack1_same_height_fork_refuses(tmp_path):
    """ATTACK1 — owner-key EQUIVOCATION (same-height fork). The off-box witnessed checkpoint is at height N
    on the TRUE history; the passive presents a DIFFERENT owner-signed history at the SAME height N (equal
    entry_count/last_seq, DIFFERENT head_hash — the passive shares the owner key, conceded in HA-PROFILE §4).
    The old guard compared only the self-declared scalars (equal counts) and returned activate=True; the fix
    BINDS the local head to the witnessed head_hash at equal height and REFUSES the fork (exit 2)."""
    ea, ha = _chain(2, salt="TRUE")             # the history the off-box checkpoint witnesses
    env = _witnessed_env(ha, tmp_path)
    eb, hb = _chain(2, salt="FORK")             # a DIFFERENT owner-signed history at the same height
    assert hb.entry_count == ha.entry_count and hb.last_seq == ha.last_seq   # same height ...
    assert hb.head_hash != ha.head_hash                                      # ... different head (the fork)
    v = guard.evaluate_promotion(hb, env, scope=SCOPE, trust_root=_solo_tr(),
                                 owner_trust_root=_owner_tr(), entries=eb)
    assert not v.activate and v.exit_code == 2 and "SAME-HEIGHT FORK" in v.reason


def test_attack2_forged_head_inflated_count_refuses(tmp_path):
    """ATTACK2 — a FORGED head: signed by a NON-owner ATTACKER key with entry_count mutated to 999999. The
    old guard never checked the head's owner signature, so a self-declared height of 999999 was accepted as
    'at/above the witnessed checkpoint'. The fix authenticates the head first (owner signature + binding to
    the live chain) -> REFUSE (exit 2)."""
    attacker = generate_keypair()
    e2, h2 = _chain(2)
    env = _witnessed_env(h2, tmp_path)
    forged = sign_head(e2, engagement_slug=SCOPE, signers=[("owner", attacker.private_key_b64)])
    forged = forged.model_copy(update={"entry_count": 999999})   # inflate the self-declared height
    v = guard.evaluate_promotion(forged, env, scope=SCOPE, trust_root=_solo_tr(),
                                 owner_trust_root=_owner_tr(), entries=e2)
    assert not v.activate and v.exit_code == 2 and "authentically owner-signed" in v.reason


def test_attack2b_attacker_signed_head_correct_count_refuses(tmp_path):
    """ATTACK2 (isolating the OWNER-SIGNATURE check): a well-formed head at the correct height, matching the
    live chain, but signed by an ATTACKER key rather than the owner. classify_head's owner-signature/
    threshold check rejects it -> REFUSE, proving activation depends on the OWNER signature, not just shape."""
    attacker = generate_keypair()
    e2, h2 = _chain(2)
    env = _witnessed_env(h2, tmp_path)
    imposter = sign_head(e2, engagement_slug=SCOPE, signers=[("owner", attacker.private_key_b64)])
    assert imposter.head_hash == h2.head_hash and imposter.entry_count == h2.entry_count  # shape is correct
    v = guard.evaluate_promotion(imposter, env, scope=SCOPE, trust_root=_solo_tr(),
                                 owner_trust_root=_owner_tr(), entries=e2)
    assert not v.activate and v.exit_code == 2 and "authentically owner-signed" in v.reason


def test_positive_path_is_not_trivially_true(tmp_path):
    """The positive path is NOT always-true: the SAME witnessed anchor + entries + owner root ACTIVATES for a
    genuine owner-signed head, but flipping ONLY the head's signer to an attacker key flips the verdict to
    REFUSE — so activation is gated on real owner authentication, not on the scalar comparison alone."""
    e2, h2 = _chain(2)
    env = _witnessed_env(h2, tmp_path)
    good = guard.evaluate_promotion(h2, env, scope=SCOPE, trust_root=_solo_tr(),
                                    owner_trust_root=_owner_tr(), entries=e2)
    assert good.activate and good.exit_code == 0
    attacker = generate_keypair()
    imposter = sign_head(e2, engagement_slug=SCOPE, signers=[("owner", attacker.private_key_b64)])
    bad = guard.evaluate_promotion(imposter, env, scope=SCOPE, trust_root=_solo_tr(),
                                   owner_trust_root=_owner_tr(), entries=e2)
    assert not bad.activate and bad.exit_code == 2
