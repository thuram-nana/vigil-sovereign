"""G3(b) — witnessed anti-rollback checkpoints over the signed spine head.

Proves the honest property: a witnessed checkpoint EMITTED and RETAINED off-box detects a same-host
rollback that rewrote head.json (and would rewrite floor.json too) — the anti-rollback the local floor
cannot give. Two layers are exercised: (1) ``consistent`` rejects a rollback BELOW the retained height
(count/last_seq shrink, same-height fork); (2) the hash-chained ``entry_hash`` at the retained ``last_seq``
PROVES a genuine append-only extension and CATCHES a higher-count history rewrite the pairwise check misses.
The guarantee label is honest (owner-only = DETECTION, not PREVENTION); a tampered envelope, a wrong-scope
checkpoint, an untrusted witness, and a rolled-back/forked head all fail CLOSED. The independent-witness
cosign shuttle (the honest stand-in for the deferred live device transport) reaches a strict-majority set
labelled CONDITIONAL prevention. witness.py is config-free, so every path is exercised by injecting keys +
tmp paths (the floor-test pattern).
"""
from __future__ import annotations

import json

import pytest
from vigil_integration.transparency import Witness, checkpoint_hash

from sigil.reuse import build_chain, digest_payload, generate_keypair
from sigil.reuse.chain import sign_head
from sigil.spine import witness as W

OWNER = generate_keypair()
SCOPE = "sigil"


def _chain(n, salt=""):
    """Return (entries, signed_head) for an n-record spine; ``salt`` forks the whole history."""
    entries = build_chain([digest_payload({"i": i, "s": salt}) for i in range(n)])
    head = sign_head(entries, engagement_slug=SCOPE, signers=[("owner", OWNER.private_key_b64)])
    return entries, head


def _owner_witness():
    return Witness("owner", OWNER.private_key_b64)


def _tr(roster=None):
    return W.witness_trust_root(roster, owner_pub=OWNER.public_key_b64, owner_key_id="owner")


def _emit(head, tip, witnesses=None):
    return W.emit_checkpoint(head, witnesses or [_owner_witness()], tip_path=tip, scope=SCOPE)


def _verify(env, entries, head, tr=None):
    return W.verify_against_external(env, head=head, entries=entries, scope=SCOPE, trust_root=tr or _tr())


def test_genuine_extension_is_proven(tmp_path):
    """A current chain that SHARES the retained prefix and grew is proven a genuine append-only extension
    by the hash-chained entry at the retained last_seq."""
    e2, h2 = _chain(2)
    retained = W.dump_witnessed(_emit(h2, tmp_path / "tip"), scope=SCOPE)
    e3, h3 = _chain(3)                                        # same salt → records 0..1 byte-identical to e2
    ok, msg = _verify(retained, e3, h3)
    assert ok and "genuine append-only extension" in msg


def test_higher_count_rewrite_is_detected(tmp_path):
    """THE red-pen BLOCK: a forged chain that shares NO history yet grows past the retained height must be
    caught — the entry at the retained last_seq does not carry the retained head_hash → HISTORY REWRITE."""
    e2, h2 = _chain(2)
    retained = W.dump_witnessed(_emit(h2, tmp_path / "tip"), scope=SCOPE)
    e3f, h3f = _chain(3, salt="REWRITE")                     # different history, higher count
    ok, msg = _verify(retained, e3f, h3f)
    assert not ok and "HISTORY REWRITE" in msg


def test_emit_default_owner_is_detection_only_not_prevention(tmp_path):
    """HONESTY: the default owner-only, threshold-1 witness set is DETECTION, never PREVENTION — a single
    witness that is the head signer provides no independence, even though 2*1>1 is arithmetic strict-majority."""
    e2, h2 = _chain(2)
    env = W.dump_witnessed(_emit(h2, tmp_path / "tip"), scope=SCOPE)
    _ok, msg = _verify(env, e2, h2)
    assert "DETECTION only" in msg
    assert "PREVENTION" not in msg and "prevention IF" not in msg


def test_retained_checkpoint_detects_a_rollback(tmp_path):
    """A checkpoint retained at count 2 catches a head rolled back to count 1 — which the local floor
    cannot, because a same-host attacker rewrote head.json (and would rewrite floor.json too)."""
    _e2, h2 = _chain(2)
    retained = W.dump_witnessed(_emit(h2, tmp_path / "tip"), scope=SCOPE)
    e1, h1 = _chain(1)
    ok, msg = _verify(retained, e1, h1)
    assert not ok and "ROLLBACK" in msg and "shrank" in msg


def test_same_height_fork_is_rejected(tmp_path):
    """A forked head at the SAME count but a different head_hash is caught (split view)."""
    _e2, h2 = _chain(2)
    retained = W.dump_witnessed(_emit(h2, tmp_path / "tip"), scope=SCOPE)
    e2f, h2f = _chain(2, salt="FORK")                         # same count, different head_hash
    ok, msg = _verify(retained, e2f, h2f)
    assert not ok and ("same height" in msg or "ROLLBACK" in msg)


def test_pruned_retained_point_fails_closed(tmp_path):
    """FAIL-CLOSED: if the retained point is below the current prune base the superset proof is not
    available from the live window — the check is REFUSED (ok=False), never silently passed."""
    _e2, h2 = _chain(2)
    retained = W.dump_witnessed(_emit(h2, tmp_path / "tip"), scope=SCOPE)
    e3, h3 = _chain(3)
    pruned_head = h3.model_copy(update={"base_seq": 5})       # retained.last_seq (1) < base_seq (5)
    ok, msg = _verify(retained, e3, pruned_head)
    assert not ok and "CANNOT VERIFY" in msg and "prune base" in msg


def test_rewrite_hidden_behind_a_bumped_base_seq_is_not_passed(tmp_path):
    """THE re-check BLOCK: an attacker (who signs base_seq) rewrites the anchored history AND declares it
    pruned by bumping base_seq past the retained last_seq. The proof must NOT be skipped into a pass — it
    fails closed, so the fail-open escape hatch is shut."""
    _e2, h2 = _chain(2)
    retained = W.dump_witnessed(_emit(h2, tmp_path / "tip"), scope=SCOPE)
    e3f, h3f = _chain(3, salt="REWRITE")                     # total rewrite, zero shared history
    forged_prune = h3f.model_copy(update={"base_seq": 2})    # claim the anchored records are "pruned"
    ok, msg = _verify(retained, e3f, forged_prune)
    assert not ok and "CANNOT VERIFY" in msg                 # refused, NOT a silent "NO ROLLBACK OK"


def test_entries_not_matching_the_head_fail_closed(tmp_path):
    """The proof binds entries to the AUTHENTICATED head: a live-chain that does not link to head.head_hash
    (a forged/mismatched entries list) is refused, so an injected fake entry cannot smuggle a matching hash."""
    _e2, h2 = _chain(2)
    retained = W.dump_witnessed(_emit(h2, tmp_path / "tip"), scope=SCOPE)
    e3, h3 = _chain(3)
    other_entries, _oh = _chain(3, salt="OTHER")             # a different chain than h3
    ok, msg = _verify(retained, other_entries, h3)
    assert not ok and "authenticated live chain" in msg


def test_advance_links_the_meta_chain_across_runs(tmp_path):
    """The persisted tip makes the checkpoint meta-chain link across process restarts."""
    tip = tmp_path / "tip"
    _e2, h2 = _chain(2)
    _e3, h3 = _chain(3)
    wc1 = _emit(h2, tip)
    wc2 = _emit(h3, tip)
    assert wc2.checkpoint.entry_count == 3
    assert wc2.checkpoint.prev_checkpoint_hash == checkpoint_hash(wc1.checkpoint)


def test_emit_is_idempotent_on_an_unchanged_head(tmp_path):
    tip = tmp_path / "tip"
    _e, h = _chain(2)
    assert _emit(h, tip).checkpoint == _emit(h, tip).checkpoint     # no head change → no second mint


def test_emit_refuses_a_regressed_head(tmp_path):
    tip = tmp_path / "tip"
    _e3, h3 = _chain(3)
    _e2, h2 = _chain(2)
    _emit(h3, tip)
    with pytest.raises(W.WitnessError, match="inconsistent"):
        _emit(h2, tip)                                       # a lower head than the persisted tip


def test_tampered_envelope_fails_witness_verify(tmp_path):
    """Flipping the checkpoint's entry_count invalidates the witness signature → not a trusted anchor."""
    e2, h2 = _chain(2)
    env = json.loads(W.dump_witnessed(_emit(h2, tmp_path / "tip"), scope=SCOPE))
    env["checkpoint"]["entry_count"] = 999
    ok, msg = _verify(json.dumps(env), e2, h2)
    assert not ok and "not signed by a trusted witness quorum" in msg


def test_wrong_scope_checkpoint_is_rejected(tmp_path):
    e2, h2 = _chain(2)
    env = json.loads(W.dump_witnessed(_emit(h2, tmp_path / "tip"), scope=SCOPE))
    env["scope"] = "some-other-store"
    ok, msg = _verify(json.dumps(env), e2, h2)
    assert not ok and "scope" in msg


def test_malformed_envelope_fails_closed():
    for bad in ("not json", "[]", '{"scope":"sigil"}',
                '{"scope":1,"checkpoint":{},"witness_signatures":[]}',
                '{"scope":"sigil","checkpoint":{"last_seq":0},"witness_signatures":[]}'):
        with pytest.raises(W.WitnessError):
            W.load_witnessed(bad)


def test_independent_cosign_reaches_conditional_prevention(tmp_path):
    """The cosign shuttle (honest stand-in for the deferred live transport): an INDEPENDENT witness co-signs
    on its own box, the operator configures a 2-of-2 roster, and verify then labels CONDITIONAL prevention."""
    phone = generate_keypair()
    core = W.set_roster([{"key_id": "owner", "public_key_b64": OWNER.public_key_b64},
                         {"key_id": "phone", "public_key_b64": phone.public_key_b64}],
                        threshold=2, path=tmp_path / "roster.json", owner_key=OWNER, scope=SCOPE)
    tr = W.witness_trust_root(core, owner_pub=OWNER.public_key_b64, owner_key_id="owner")
    e2, h2 = _chain(2)
    env = W.dump_witnessed(_emit(h2, tmp_path / "tip"), scope=SCOPE)   # owner sig only (1 of 2)
    ok_before, _ = _verify(env, e2, h2, tr)
    assert not ok_before                                     # 1-of-2 does not meet the quorum → fail closed
    cosigned = W.cosign_envelope(env, witness_key_id="phone", witness_priv_b64=phone.private_key_b64)
    ok, msg = _verify(cosigned, e2, h2, tr)
    assert ok and "prevention IF the witness keys are held by independent parties" in msg


def test_roster_roundtrip_and_wrong_owner_key_fails(tmp_path):
    phone = generate_keypair()
    p = tmp_path / "roster.json"
    core = W.set_roster([{"key_id": "owner", "public_key_b64": OWNER.public_key_b64},
                         {"key_id": "phone", "public_key_b64": phone.public_key_b64}],
                        threshold=2, path=p, owner_key=OWNER, scope=SCOPE)
    assert W.load_roster(p, owner_pub=OWNER.public_key_b64, scope=SCOPE) == core
    with pytest.raises(W.WitnessError):                      # a different owner pub cannot verify the roster
        W.load_roster(p, owner_pub=generate_keypair().public_key_b64, scope=SCOPE)


def test_roster_signature_tamper_is_rejected(tmp_path):
    """A witness roster whose signed core is altered under its old signature fails closed (owner-signed)."""
    phone = generate_keypair()
    p = tmp_path / "roster.json"
    W.set_roster([{"key_id": "owner", "public_key_b64": OWNER.public_key_b64},
                  {"key_id": "phone", "public_key_b64": phone.public_key_b64}],
                 threshold=2, path=p, owner_key=OWNER, scope=SCOPE)
    obj = json.loads(p.read_text())
    obj["core"]["threshold"] = 1                             # weaken threshold under the stale signature
    p.write_text(json.dumps(obj))
    with pytest.raises(W.WitnessError, match="does not verify"):
        W.load_roster(p, owner_pub=OWNER.public_key_b64, scope=SCOPE)


def test_a_duplicate_witness_key_cannot_forge_a_majority(tmp_path):
    """is_split_view_resistant fail-closes on a duplicated authorizer key, so the owner cannot register its
    own key twice to fake a strict-majority set → the guarantee stays DETECTION, never prevention."""
    core = W.set_roster([{"key_id": "owner", "public_key_b64": OWNER.public_key_b64},
                         {"key_id": "owner-again", "public_key_b64": OWNER.public_key_b64}],
                        threshold=2, path=tmp_path / "roster.json", owner_key=OWNER, scope=SCOPE)
    tr = W.witness_trust_root(core, owner_pub=OWNER.public_key_b64, owner_key_id="owner")
    assert "DETECTION only" in W.guarantee_label(tr)
