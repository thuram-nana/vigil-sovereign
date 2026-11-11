"""A real hard prune, then every way the spine head gets re-signed — the prune boundary must survive, or reads must
fail CLOSED (never an empty seed).

  (a) `SnapshotState.load` after a real `commit_prune`: the prune persists its folded state with `snapshot_seq=-1`
      (it cannot know the record's own seq before appending it) while the signed head names the real seq — load
      used to require them equal and raised for every caller;
  (b) `checkpoint()` after a prune (`sigil sign`, warden-anchor-set, key rotate, consolidate --sign) used to sign a
      plain "no prune" head over the retained window, after which `load` returned the EMPTY seed: the kill switch
      read released, wallets 0, no error. It now re-signs the owner-signed boundary forward, and REFUSES when the
      live window starts above seq 0 but no verifying pruned head stands;
  (c) `load` refuses the same unanchored pruned window (head.json gone, a plain head) — O(1), one line read.
"""
from __future__ import annotations

import dataclasses
import json
import time

import pytest

import sigil.config as cfg
import sigil.spine.checkpoint as _cp
import sigil.spine.floor as _fl
import sigil.spine.snapshot as _snap
import sigil.spine.tail as _tail
from sigil.governor import identity
from sigil.governor import key_history as kh
from sigil.governor.killswitch import KillSwitch
from sigil.spine import fold_cache, prune
from sigil.spine.snapshot import SnapshotError, SnapshotState
from sigil.spine.store import SpineStore


@pytest.fixture
def home(tmp_path, monkeypatch):
    """Relocate every owner-key / head / floor path into tmp_path (identity, checkpoint, snapshot, store, tail),
    so the registries, `checkpoint()` and `commit_prune` share ONE owner key and ONE head, hermetically."""
    from sigil.platform.vault import reset_owner_vault_for_test
    keys = tmp_path / "keys"
    keys.mkdir()
    head = tmp_path / "head.json"
    for mod, name, val in [
        (identity, "_PRIV", keys / "owner.priv"), (identity, "_PUB", keys / "owner.pub"),
        (identity, "_GENESIS_PUB", keys / "owner.genesis.pub"),
        (_cp, "_PRIV", keys / "owner.priv"), (_cp, "_PUB", keys / "owner.pub"), (_cp, "KEYS_DIR", keys),
        (_cp, "HEAD_PATH", head), (_snap, "HEAD_PATH", head), (cfg, "HEAD_PATH", head), (_tail, "HEAD_PATH", head),
        (_fl, "FLOOR_PATH", tmp_path / "floor.json"),
    ]:
        monkeypatch.setattr(mod, name, val)
    monkeypatch.setenv("SIGIL_SPINE_ARCHIVE_DIR", str(tmp_path / "archive"))
    reset_owner_vault_for_test()
    kh.clear_resolver_cache()
    fold_cache.clear_all()
    identity.ensure_owner_keypair()
    yield tmp_path
    kh.clear_resolver_cache()
    fold_cache.clear_all()
    reset_owner_vault_for_test()


K = 10


def _pruned(home, *, engage=True):
    """A segmented spine whose kill switch is ENGAGED below K, signed, then really pruned at K."""
    s = SpineStore(str(home / "spine.jsonl"))
    s.migrate()
    if engage:
        KillSwitch(s).engage()                                   # seq 0, owner-signed
    _fill_to_k(s)
    for i in range(3):
        s.append(kind="event", source="t", actor="u", payload={"tail": i})
    _cp.checkpoint(s)
    rep = prune.commit_prune(s, K, confirm=True)
    fresh = SpineStore(str(home / "spine.jsonl"))
    assert fresh.first_live_seq() == K
    return fresh, rep


def _fill_to_k(s):
    """Records up to K + 5, sealing a segment every 5, so K is the first seq of a SEALED segment (a prune
    boundary must be one)."""
    while s.next_seq < K + 5:
        s.append(kind="event", source="t", actor="u", payload={"i": s.next_seq})
        if s.next_seq % 5 == 0:
            s.rotate()


def _grow(s, n):
    for i in range(n):
        s.append(kind="event", source="t", actor="u", payload={"after": i})


def _spine_files(s):
    """Every file of the spine unit a backup captures: data file, manifest, segments, the signed head."""
    lay = s._layout
    out = {p: p.read_bytes() for p in lay.segments_dir.rglob("*") if p.is_file()}
    for p in (lay.data_path, lay.manifest_path, _cp.HEAD_PATH):
        if p.exists():
            out[p] = p.read_bytes()
    return out


def _restore(s, files):
    """Restore the captured unit over the live one (files added since are removed, as a unit swap does)."""
    for p in [p for p in s._layout.segments_dir.rglob("*") if p.is_file() and p not in files]:
        p.unlink()
    for p, b in files.items():
        p.write_bytes(b)


def _head():
    return _cp._read_head_on_disk()


# ---- (a) load after a real prune -----------------------------------------------------------------------------------

@pytest.mark.parametrize("flag", ["0", "1"])
def test_load_after_a_real_prune_returns_the_seed(home, monkeypatch, flag):
    monkeypatch.setenv("VIGIL_FOLD_CACHE_ENABLED", flag)
    s, rep = _pruned(home)
    st = SnapshotState.load(s)
    assert (st.base_seq, st.snapshot_seq) == (K, rep["snapshot_seq"])
    assert st.killswitch_engaged
    assert KillSwitch(s).is_engaged() is True                    # the engaged latch was pruned: seeded, not lost


def test_load_refuses_a_snapshot_folded_for_another_boundary(home):
    """The relaxed seq check (-1 accepted) never relaxes the BOUNDARY: a snapshot record whose base disagrees with
    the signed head is refused."""
    s, rep = _pruned(home)
    rec = s.get(rep["snapshot_seq"])
    bad = {**rec.payload["folded_state"], "base_seq": K + 1}
    real_get = SpineStore.get

    def get(self, seq):
        r = real_get(self, seq)
        if r is not None and seq == rep["snapshot_seq"]:
            r = dataclasses.replace(r, payload={**r.payload, "folded_state": bad})
        return r
    with pytest.MonkeyPatch.context() as m:
        m.setattr(SpineStore, "get", get)
        with pytest.raises(SnapshotError, match="disagree"):
            SnapshotState.load(s)


def test_load_refuses_a_snapshot_seq_outside_the_signed_window(home):
    s, rep = _pruned(home)
    h = _head()
    st = h.model_copy(update={"snapshot_seq": h.last_seq + 1})
    monkey_ok = (True, "ok")
    with pytest.MonkeyPatch.context() as m:
        m.setattr(_cp, "verify_checkpoint", lambda store=None: monkey_ok)   # isolate the bound check itself
        _snap.HEAD_PATH.write_text(st.model_dump_json())
        with pytest.raises(SnapshotError, match="outside its signed window"):
            SnapshotState.load(s)


# ---- (b) every re-sign after a prune carries the boundary -----------------------------------------------------------

@pytest.mark.parametrize("grow", [0, 2, 40])
@pytest.mark.parametrize("flag", ["0", "1"])
def test_sign_after_a_prune_carries_the_owner_signed_boundary(home, monkeypatch, grow, flag):
    monkeypatch.setenv("VIGIL_FOLD_CACHE_ENABLED", flag)
    s, rep = _pruned(home)
    assert KillSwitch(s).is_engaged()
    _grow(s, grow)
    h = _cp.checkpoint(s)
    assert (h.schema_version, h.base_seq, h.base_count, h.snapshot_seq) == (2, K, K, rep["snapshot_seq"])
    assert h.cumulative_merkle_root == rep["cumulative_merkle_root"]
    assert h.last_seq == s.next_seq - 1 and h.entry_count == s.next_seq
    assert _cp.verify_checkpoint(s)[0], _cp.verify_checkpoint(s)
    assert s.verify()[0]
    st = SnapshotState.load(s)
    assert st.base_seq == K and st.killswitch_engaged
    assert KillSwitch(s).is_engaged() is True                    # D1: used to read False here, silently
    assert prune.verify_with_archive(s)[0]


def test_repeated_signs_keep_carrying_and_keep_the_floor_monotonic(home):
    s, rep = _pruned(home)
    for _ in range(3):
        _grow(s, 3)
        _cp.checkpoint(s)
        assert _cp.verify_checkpoint(s)[0]
    fl = _fl.load_floor()
    assert (fl.base_seq, fl.last_seq) == (K, s.next_seq - 1)
    assert KillSwitch(s).is_engaged()


def test_a_crash_after_the_head_commit_before_the_manifest_rebase_still_carries(home):
    """Prune phases: the head committed, the manifest still lists [0..K). The live window still starts at 0 —
    `checkpoint()` must carry the verifying pruned head (it selects the window by seq), not sign a plain head."""
    s = SpineStore(str(home / "spine.jsonl"))
    s.migrate()
    KillSwitch(s).engage()
    _fill_to_k(s)
    _grow(s, 2)
    _cp.checkpoint(s)
    payload = prune.snapshot_payload(s, K)
    prune.archive_copy(s, K, payload)
    snap_seq = prune._append_snapshot_idempotent(s, payload)
    _cp.sign_pruned_head(s, base_seq=K, base_prev_hash=payload["base_prev_hash"],
                         cumulative_merkle_root=payload["cumulative_merkle_root"], snapshot_seq=snap_seq)
    assert s.first_live_seq() == 0                               # the cutover stopped before the rebase
    _grow(s, 30)
    h = _cp.checkpoint(s)
    assert (h.base_seq, h.snapshot_seq) == (K, snap_seq)
    assert _cp.verify_checkpoint(s)[0]
    assert SpineStore(str(home / "spine.jsonl")).finish_prune() is True    # the roll-forward still completes
    s2 = SpineStore(str(home / "spine.jsonl"))
    assert s2.first_live_seq() == K and KillSwitch(s2).is_engaged()


def test_a_prune_committed_while_a_sign_is_in_flight_is_never_overwritten(home, monkeypatch):
    """Race: checkpoint() read the un-pruned spine, then a prune committed its pruned head before our write. The
    plain head we computed must NOT replace the pruned head (that re-creates the empty-seed fail-open)."""
    s = SpineStore(str(home / "spine.jsonl"))
    s.migrate()
    KillSwitch(s).engage()
    _fill_to_k(s)
    _grow(s, 25)
    _cp.checkpoint(s)
    real = _cp.standing_pruned_head

    def racing(store, **kw):
        out = real(store, **kw)                                  # decided: un-pruned -> plain head
        prune.commit_prune(SpineStore(str(home / "spine.jsonl")), K, confirm=True)
        return out
    monkeypatch.setattr(_cp, "standing_pruned_head", racing)
    h = _cp.checkpoint(s)
    assert h.base_seq == K and _head().base_seq == K
    monkeypatch.setattr(_cp, "standing_pruned_head", real)
    s2 = SpineStore(str(home / "spine.jsonl"))
    assert KillSwitch(s2).is_engaged() and SnapshotState.load(s2).base_seq == K


def test_key_rotation_after_a_prune_carries_the_boundary_under_the_new_key(home):
    s, rep = _pruned(home)
    new_kp, _seq = kh.rotate(s, issued_at=time.time())
    h = _cp.checkpoint(s)                                        # the old head was signed by the retired key
    assert (h.base_seq, h.snapshot_seq) == (K, rep["snapshot_seq"])
    assert _cp.verify_checkpoint(s)[0]
    assert _cp.trust_root(s).authorizers[0].public_key_b64 == new_kp.public_key_b64
    assert KillSwitch(s).is_engaged()


def test_floor_reset_re_anchors_a_restored_post_prune_spine(home):
    """A post-prune backup restored on a box whose floor already moved past it: the floor rejects the restored
    head (stale), so the ordinary sign defers; `sigil floor reset` (force) re-anchors it CARRYING the boundary."""
    s, rep = _pruned(home)
    files = _spine_files(s)                                      # the post-prune backup: spine files + head.json
    _grow(s, 10)
    _cp.checkpoint(s)                                            # the floor advances past the backup
    _restore(s, files)
    r = SpineStore(str(home / "spine.jsonl"))
    assert not _cp.verify_checkpoint(r)[0]                       # stale against the advanced floor
    h = _cp.checkpoint(r, force=True)
    _fl.reset_floor(h, owner_key=identity.owner_keypair())
    assert (h.base_seq, h.snapshot_seq) == (K, rep["snapshot_seq"])
    assert _cp.verify_checkpoint(r)[0] and KillSwitch(r).is_engaged()


def test_a_pre_prune_backup_restored_signs_a_plain_head_over_the_full_spine(home):
    """The reverse restore: a backup taken BEFORE the prune holds the full chain from genesis (and its own plain
    head + floor). Nothing is missing, so a plain head is correct and the empty seed is the right seed."""
    s = SpineStore(str(home / "spine.jsonl"))
    s.migrate()
    KillSwitch(s).engage()
    _fill_to_k(s)
    _grow(s, 3)
    _cp.checkpoint(s)
    files = {**_spine_files(s), _fl.FLOOR_PATH: _fl.FLOOR_PATH.read_bytes()}   # the pre-prune backup + floor
    prune.commit_prune(s, K, confirm=True)
    _restore(s, files)
    r = SpineStore(str(home / "spine.jsonl"))
    assert r.first_live_seq() == 0
    _grow(r, 30)
    h = _cp.checkpoint(r)
    assert h.schema_version == 1 and h.base_seq == 0
    assert _cp.verify_checkpoint(r)[0]
    assert SnapshotState.load(r).base_seq == 0 and KillSwitch(r).is_engaged()


# ---- refusals: no verifying pruned head over a pruned window --------------------------------------------------------

def _no_head(home):
    _cp.HEAD_PATH.unlink()


def _plain_head(home):
    """The pre-fix D1 state: a plain owner-signed head over the retained window."""
    s = SpineStore(str(home / "spine.jsonl"))
    priv, _pub = _cp._owner_keys()
    h = _cp.sign_head(s.entries(), engagement_slug=_cp.SCOPE, signers=[(_cp.OWNER_KEY_ID, priv)])
    _cp.HEAD_PATH.write_text(h.model_dump_json())


def _forged_head(home):
    d = json.loads(_cp.HEAD_PATH.read_text())
    d["snapshot_seq"] = d["snapshot_seq"]                        # same boundary, broken signature
    d["signatures"][0]["signature_b64"] = d["signatures"][0]["signature_b64"][::-1]
    _cp.HEAD_PATH.write_text(json.dumps(d))


def _garbage_head(home):
    _cp.HEAD_PATH.write_text("{not json")


BREAKS = {"no-head": _no_head, "plain-head": _plain_head, "forged-head": _forged_head, "garbage": _garbage_head}


@pytest.mark.parametrize("flag", ["0", "1"])
@pytest.mark.parametrize("brk", sorted(BREAKS))
def test_reads_fail_closed_on_an_unanchored_pruned_window(home, monkeypatch, brk, flag):
    monkeypatch.setenv("VIGIL_FOLD_CACHE_ENABLED", flag)
    s, _rep = _pruned(home)
    assert KillSwitch(s).is_engaged()                            # warm any cache first
    BREAKS[brk](home)
    s2 = SpineStore(str(home / "spine.jsonl"))
    with pytest.raises(SnapshotError):
        SnapshotState.load(s2)
    # The flag-OFF verdict cache answers the last verified verdict until the SPINE changes (it keys on the spine's
    # change token, not head.json) — engaged, the safe answer. Once the spine moves, the read must fail closed.
    s2.append(kind="event", source="t", actor="u", payload={"after": "break"})
    with pytest.raises(SnapshotError):                           # never a silent False
        KillSwitch(s2).is_engaged()


@pytest.mark.parametrize("brk", sorted(BREAKS))
def test_sign_refuses_and_writes_nothing_on_an_unanchored_pruned_window(home, brk):
    s, _rep = _pruned(home)
    BREAKS[brk](home)
    before = _cp.HEAD_PATH.read_bytes() if _cp.HEAD_PATH.exists() else None
    floor_before = _fl.FLOOR_PATH.read_bytes()
    _grow(s, 40)
    with pytest.raises(_cp.CheckpointRefused) as e:
        _cp.checkpoint(s)
    msg = str(e.value)
    assert "Restore the spine directory" in msg and "run `sigil sign`" not in msg
    assert (_cp.HEAD_PATH.read_bytes() if _cp.HEAD_PATH.exists() else None) == before
    assert _fl.FLOOR_PATH.read_bytes() == floor_before
    with pytest.raises(_cp.CheckpointRefused):
        _cp.checkpoint(s, force=True)                            # `sigil floor reset` refuses too


def test_a_never_pruned_spine_signs_exactly_as_before(home):
    s = SpineStore(str(home / "spine.jsonl"))
    for i in range(5):
        s.append(kind="event", source="t", actor="u", payload={"i": i})
    assert _cp.standing_pruned_head(s) is None
    h = _cp.checkpoint(s)
    priv, _ = _cp._owner_keys()
    ref = _cp.sign_head(s.entries(), engagement_slug=_cp.SCOPE, signers=[(_cp.OWNER_KEY_ID, priv)])
    assert h == ref and h.schema_version == 1
    _cp.HEAD_PATH.unlink()
    assert SnapshotState.load(s) == SnapshotState.empty()        # no head over a genesis spine: identity


# ---- CLI callers refuse up front, before mutating -------------------------------------------------------------------

def _cli(monkeypatch, store, argv):
    import sigil.cli as cli
    monkeypatch.setattr(cli, "SpineStore", lambda *a, **k: store)
    monkeypatch.setattr(cli, "_assert_store_operable_or_exit", lambda _cmd: None)
    with pytest.raises(SystemExit) as e:
        cli.main(argv)
    return e.value.code


def test_cli_sign_refuses_with_operator_guidance(home, monkeypatch, capsys):
    s, _rep = _pruned(home)
    _no_head(home)
    assert _cli(monkeypatch, s, ["sign"]) == 2
    err = capsys.readouterr().err
    assert "Restore the spine directory" in err and not _cp.HEAD_PATH.exists()


def test_cli_key_rotate_refuses_before_rotating(home, monkeypatch, capsys):
    s, _rep = _pruned(home)
    _no_head(home)
    n = s.next_seq
    pub = identity.owner_pubkey()
    assert _cli(monkeypatch, s, ["key", "rotate", "--yes"]) == 2
    assert s.next_seq == n and identity.owner_pubkey() == pub    # no succession record, no key swap


def test_cli_re_genesis_refuses_on_a_pruned_spine(home, monkeypatch, capsys):
    s, _rep = _pruned(home)
    n = s.next_seq
    pub = identity.owner_pubkey()
    assert _cli(monkeypatch, s, ["key", "re-genesis", "--yes", "--i-understand-continuity-is-abandoned"]) == 2
    assert "pruned" in capsys.readouterr().err
    assert s.next_seq == n and identity.owner_pubkey() == pub
    assert _cp.verify_checkpoint(s)[0]


def test_cli_warden_anchor_set_refuses_before_appending(home, monkeypatch):
    import sigil.cli as cli
    s, _rep = _pruned(home)
    _no_head(home)
    n = s.next_seq
    monkeypatch.setattr(cli, "_verify_ed25519", lambda *a: True)
    assert _cli(monkeypatch, s, ["warden-anchor-set", "--count", "1", "--head-hash", "ab" * 32,
                                 "--pubkey", "k", "--sig", "s"]) == 2
    assert s.next_seq == n


def test_consolidate_sign_refuses_before_promoting(home):
    from sigil.consolidate import run_consolidation
    s, _rep = _pruned(home)
    _no_head(home)
    n = s.next_seq
    with pytest.raises(_cp.CheckpointRefused):
        run_consolidation(store=s, sign=True, save_cursor=False)
    assert s.next_seq == n
    run_consolidation(store=s, sign=False, save_cursor=False)    # an unsigned pass is unaffected
