"""SIGIL hard-prune Slice B — the durable external anti-rollback floor (`floor.json`, C1).

The floor is a SECOND, out-of-band tamper witness layered on the in-band owner-signed head: it catches a
validly-signed but STALE head (an attacker replays an old `head.json`, or a routine reset shortens the
spine) — a rollback the Ed25519 signature alone cannot catch, because the old head was validly signed.
Pins: monotonic {last_seq, base_seq, base_count} reject rules; the v2 meta-chain (self / unique-child /
reject-fork); upward-only advance; corrupt-floor fail-closed; and the end-to-end truncation-attack that
reads CLEAN without the floor but ROLLBACK with it. NO prune yet — v1 heads keep base_count=0.
Run: ~/.sigil/venv/bin/python -m pytest tests/test_spine_floor.py -q
"""
import pytest
from pydantic import ValidationError

from sigil.reuse import AuthorizerKey, TrustRoot, build_chain, digest_payload, generate_keypair
from sigil.reuse.chain import sign_head
from sigil.reuse.models import _GENESIS_PREV, SignedChainHead
from sigil.spine.checkpoint import classify_head
from sigil.spine.floor import (
    Floor,
    advance_floor,
    check_floor,
    head_sig_hash,
    load_floor,
    reset_floor,
)


def _chain(n: int):
    return build_chain([digest_payload({"i": i}) for i in range(n)])


def _owner():
    kp = generate_keypair()
    tr = TrustRoot(threshold=1, authorizers=[AuthorizerKey(key_id="owner", name="owner",
                                                           public_key_b64=kp.public_key_b64)])
    return kp, tr


def _floor(last_seq=0, base_seq=0, base_count=0, head_sig_hash="", scope="s", entry_count=None):
    # entry_count defaults to last_seq+1 (a full non-pruned window) unless a test pins it explicitly.
    ec = entry_count if entry_count is not None else last_seq + 1
    return Floor(scope=scope, entry_count=ec, last_seq=last_seq, base_seq=base_seq, base_count=base_count,
                 head_sig_hash=head_sig_hash)


def _v2_head(**kw):
    base = dict(schema_version=2, engagement_slug="s", last_seq=10, entry_count=10, head_hash="aa" * 32,
                base_seq=0, base_prev_hash=_GENESIS_PREV, base_count=0, cumulative_merkle_root="",
                snapshot_seq=5, prev_head_hash="")
    base.update(kw)
    return SignedChainHead(**base)


# ---- check_floor: pure reject rules ---------------------------------------------------------------

def test_no_floor_is_byte_identical_pass():
    h = _v2_head()
    assert check_floor(h, None)[0]                          # no floor -> pass (pre-floor behaviour)


def test_last_seq_rollback_rejected():
    h = _v2_head(last_seq=5, entry_count=6)
    ok, msg = check_floor(h, _floor(last_seq=9))
    assert not ok and "ROLLBACK" in msg


def test_base_seq_and_base_count_unprune_rejected():
    h = _v2_head(last_seq=100, entry_count=100, base_seq=10, base_count=10)
    assert not check_floor(h, _floor(last_seq=0, base_seq=20, base_count=10))[0]   # base_seq down
    assert not check_floor(h, _floor(last_seq=0, base_seq=10, base_count=20))[0]   # base_count down
    assert check_floor(h, _floor(last_seq=0, base_seq=10, base_count=10))[0]       # equal -> ok


def test_v1_head_skips_the_metachain_rule():
    """A v1 head (no prune yet) carries no prev_head_hash — the meta-chain check is dormant, only the
    monotonic rules apply. This keeps Slice B byte-identical for every existing v1 deployment."""
    v1 = SignedChainHead(schema_version=1, engagement_slug="s", last_seq=10, entry_count=10,
                         head_hash="aa" * 32)
    assert check_floor(v1, _floor(last_seq=5, head_sig_hash="anything-unrelated"))[0]


def test_v2_metachain_accepts_self_and_child_rejects_fork():
    h1 = _v2_head(last_seq=10)                               # entry_count=10 (synthetic)
    fl = _floor(last_seq=10, entry_count=10, head_sig_hash=head_sig_hash(h1))
    assert check_floor(h1, fl)[0]                            # IS the accepted head (re-verify)
    child = _v2_head(last_seq=20, prev_head_hash=head_sig_hash(h1))
    assert check_floor(child, fl)[0]                         # descends from it (advance)
    fork = _v2_head(last_seq=20, prev_head_hash="de" * 32)   # neither self nor descendant
    ok, msg = check_floor(fork, fl)
    assert not ok and "META-CHAIN" in msg


def test_entry_count_catches_the_empty_vs_one_record_blind_spot():
    """last_seq is 0 for BOTH an empty spine and a 1-record spine, so a 1->0 rollback slips a last_seq-only
    floor. The ABSOLUTE entry_count guard catches it (review nit)."""
    empty = SignedChainHead(schema_version=1, engagement_slug="s", last_seq=0, entry_count=0,
                            head_hash="aa" * 32)
    ok, msg = check_floor(empty, _floor(last_seq=0, entry_count=1))   # floor remembers 1 record
    assert not ok and "ROLLBACK" in msg


def test_wrong_scope_floor_fails_closed(tmp_path):
    """A floor for a DIFFERENT scope must not silently govern this spine — load_floor raises (fail-closed),
    exactly like a corrupt floor."""
    p = tmp_path / "floor.json"
    p.write_text(Floor(scope="some-other-scope", entry_count=5, last_seq=4, base_seq=0, base_count=0,
                       head_sig_hash="").model_dump_json())
    with pytest.raises(ValueError):
        load_floor(p)


# ---- advance_floor / reset_floor / load_floor -----------------------------------------------------

def test_advance_is_upward_only_and_persists(tmp_path):
    p = tmp_path / "floor.json"
    kp, _ = _owner()
    h5 = sign_head(_chain(5), engagement_slug="s", signers=[("owner", kp.private_key_b64)])
    advance_floor(h5, path=p)
    assert load_floor(p).last_seq == 4                       # 5 records -> last_seq 4
    h10 = sign_head(_chain(10), engagement_slug="s", signers=[("owner", kp.private_key_b64)])
    advance_floor(h10, path=p)
    assert load_floor(p).last_seq == 9                       # advanced up
    with pytest.raises(ValueError):                          # refuses to go back DOWN
        advance_floor(h5, path=p)
    assert load_floor(p).last_seq == 9                       # unchanged after the refusal


def test_reset_floor_forces_downward(tmp_path):
    p = tmp_path / "floor.json"
    kp, _ = _owner()
    advance_floor(sign_head(_chain(10), engagement_slug="s", signers=[("owner", kp.private_key_b64)]), path=p)
    assert load_floor(p).last_seq == 9
    reset_floor(sign_head(_chain(3), engagement_slug="s", signers=[("owner", kp.private_key_b64)]), path=p)
    assert load_floor(p).last_seq == 2                       # deliberately lowered


def test_advance_floor_is_last_writer_monotonic_under_races(tmp_path):
    """Regression for the review MED: advance_floor's load->check->write is atomic under floor_lock and
    RE-loads the prior floor INSIDE the lock, so N racing advances leave the floor at the MAX head — a
    stale concurrent writer can never roll it BACKWARDS (which would open a false-CLEAN replay window)."""
    import threading
    p = tmp_path / "floor.json"
    kp, _ = _owner()
    heads = [sign_head(_chain(n), engagement_slug="s", signers=[("owner", kp.private_key_b64)])
             for n in (10, 8, 6, 12, 4, 9, 11, 3)]
    errs = []

    def worker(h):
        try:
            advance_floor(h, path=p)
        except ValueError:
            pass                                            # a stale (downward) advance is correctly refused
        except Exception as e:  # noqa: BLE001
            errs.append(e)

    threads = [threading.Thread(target=worker, args=(h,)) for h in heads]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errs, errs
    assert load_floor(p).entry_count == 12                  # the MAX head (12 records) — never rolled back


def test_floor_lock_degrades_when_lockfile_unopenable(tmp_path):
    """MED regression (re-check): a lockfile that can't be opened (read-only home, a root-owned lock left
    by a stray `sudo`, simulated here by a DIRECTORY at the lock path) must DEGRADE to best-effort
    UNLOCKED — never brick the advance / the head sign."""
    p = tmp_path / "floor.json"
    (tmp_path / "floor.json.lock").mkdir()                  # os.open(O_RDWR) on a dir -> OSError
    kp, _ = _owner()
    h = sign_head(_chain(5), engagement_slug="s", signers=[("owner", kp.private_key_b64)])
    advance_floor(h, path=p)                                # must NOT raise
    assert load_floor(p).entry_count == 5                   # floor still written (degraded, unlocked)


def test_load_floor_absent_is_none_corrupt_raises(tmp_path):
    p = tmp_path / "floor.json"
    assert load_floor(p) is None                             # absent -> None (byte-identical)
    p.write_text("{ this is not json")
    with pytest.raises(ValidationError):                     # present-but-corrupt -> RAISE (never None)
        load_floor(p)


# ---- classify_head with a floor -------------------------------------------------------------------

def test_classify_head_flags_a_validly_signed_but_stale_head():
    """The core value: head@5 is a VALID owner signature over the first 5 records, but the durable floor
    remembers last_seq=9 — so re-presenting head@5 is a ROLLBACK/TAMPERING, not a benign anchor."""
    kp, tr = _owner()
    entries = _chain(5)
    h5 = sign_head(entries, engagement_slug="s", signers=[("owner", kp.private_key_b64)])
    assert classify_head(h5, entries, tr, floor=_floor(last_seq=4))[0]              # at the floor -> clean
    ok, msg = classify_head(h5, entries, tr, floor=_floor(last_seq=9))             # below the floor
    assert not ok and "TAMPERING" in msg and "ROLLBACK" in msg


# ---- end-to-end through checkpoint()/verify_checkpoint() ------------------------------------------

def test_e2e_floor_blocks_truncation_and_reset(tmp_path, monkeypatch):
    import sigil.spine.checkpoint as cp
    import sigil.spine.floor as fl
    from sigil.spine.store import SpineStore

    keys = tmp_path / "keys"
    head_path = tmp_path / "head.json"
    floor_path = tmp_path / "floor.json"
    monkeypatch.setattr(cp, "HEAD_PATH", head_path)
    monkeypatch.setattr(cp, "KEYS_DIR", keys)
    monkeypatch.setattr(cp, "_PRIV", keys / "owner.priv")
    monkeypatch.setattr(cp, "_PUB", keys / "owner.pub")
    monkeypatch.setattr(fl, "FLOOR_PATH", floor_path)

    def _mk(path, n):
        s = SpineStore(path)
        for i in range(n):
            s.append(kind="event", source="t", actor="u", payload={"i": i})
        return s

    store = _mk(tmp_path / "spine.jsonl", 5)
    cp.checkpoint(store)
    assert floor_path.exists()
    old_head = head_path.read_text()                        # snapshot head@5 for the replay
    assert cp.verify_checkpoint(store)[0]

    for i in range(5, 10):                                   # grow to 10 + re-sign -> floor advances to 9
        store.append(kind="event", source="t", actor="u", payload={"i": i})
    cp.checkpoint(store)
    assert cp.verify_checkpoint(store)[0]
    assert load_floor(floor_path).last_seq == 9

    # TRUNCATION ATTACK — a 5-record spine + the replayed head@5. WITHOUT the floor this reads CLEAN
    # ("anchors all 5 (current)"); the durable floor catches the 5 deleted records as a ROLLBACK.
    store5 = _mk(tmp_path / "spine5.jsonl", 5)
    head_path.write_text(old_head)
    ok, msg = cp.verify_checkpoint(store5)
    assert not ok and "TAMPERING" in msg, msg

    # A routine reset preserves the floor (it lives outside spine/). `sigil floor reset` re-seeds it
    # deliberately downward to the fresh spine, after which verify is clean again. force=True mirrors the
    # real reset path: it re-signs the SHORTER spine (skipping the monotonic head guard); advance_floor
    # then refuses (5<10) + warns, so the floor stays at 10 until the deliberate reset_floor.
    fresh = cp.checkpoint(store5, force=True)
    assert not cp.verify_checkpoint(store5)[0]              # still ROLLBACK until the deliberate re-seed
    reset_floor(fresh, path=floor_path)
    assert cp.verify_checkpoint(store5)[0]                  # re-seeded -> clean
