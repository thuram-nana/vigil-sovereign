"""Hard-prune fold equivalence for the `authorized_devices` bearer (sigil/mesh/registry.py).

`authorized_devices` computes a MONOTONIC-under-associative-LWW security state (the owner-signed device
authz set, keep-revoked) by scanning the spine from genesis. Slice C rewires it to seed from the folded
SnapshotState of the pruned prefix `[0..base_seq)` and fold only the LIVE window `[base_seq..T]` forward.

This proves fold == scan two ways:
  (A) IDENTITY — with no committed prune (empty snapshot) the rewired consumer returns the known-correct set
      (byte-identical to the old genesis scan): base_seq==0 => since_seq=-1 (full scan) + empty seed.
  (B) SPLIT — the real proof: split the SAME store at K, fold [0..K) via SnapshotState.build() into a
      synthetic snapshot, monkeypatch load() to return it, and confirm consumer(store) == the full scan.
      This is fold([0..K)) + fold([K..T]) == scan([0..T]) for a K whose prefix carries state that MATTERS:
        - A authorized in the prefix and NEVER touched again  -> survives ONLY via the seed
        - B authorized in the prefix, REVOKED in the live window -> LWW live-override of a seeded device
        - D authorized THEN revoked entirely inside the prefix -> a PRUNED revoke must fold to "revoked" and
          must NOT be re-authorized by anything in the live window (keep-revoked survives pruning)
        - a mesh.device record whose owner-signed device_pubkey is NON-STRING (None / int) in the prefix ->
          the fold (build) mirrors the scan, which keys on p.get("device_pubkey") with NO type guard, so the
          non-str key must be preserved VERBATIM through the list-of-rows persisted form; an isinstance(str)
          guard in build() (the checker's easy-to-miss bug) would DROP it and make build() != scan.

`SnapshotState.mesh_dev_state` is a LIST-of-rows persisted form (`[[device_pubkey, state], ...]`), not a
dict — so a non-str key an owner signed round-trips through JSON verbatim. Reconstruct with
`dict(st.mesh_dev_state)` (exactly what the consumer does).

Run: SIGIL_HOME=$(mktemp -d) ~/.sigil/venv/bin/python -m pytest tests/test_snapshot_fold_mesh_authorized.py -q
"""
import tempfile

from sigil.governor.authn import signed_payload
from sigil.mesh import authorize_device, authorized_devices, revoke_device
from sigil.mesh.registry import DEV_SIGNAL
from sigil.reuse import generate_keypair
from sigil.spine import snapshot as snapshot_mod
from sigil.spine.snapshot import SnapshotState
from sigil.spine.store import SpineStore

OWNER = generate_keypair()
OP = OWNER.public_key_b64

# NON-STRING device_pubkeys an owner can (malformedly) sign. The scan keys on them with no type guard, so
# the fold must too; the persisted list-of-rows form round-trips them verbatim (None -> JSON null -> None,
# int -> JSON number -> int; both re-verify under the owner anchor). See _build_store seq 4 / seq 5.
NONE_KEY = None
INT_KEY = 1337


def _store():
    return SpineStore(tempfile.mktemp(suffix=".jsonl"))


def _forged_authorize(store, device_pubkey, attacker_key, device_id):
    """An authorization signed by a NON-owner key — must be ignored by the fold in prefix AND live."""
    return store.append(kind="event", source="mesh", actor="OWNER",
                        payload=signed_payload({"signal": DEV_SIGNAL, "state": "authorized",
                                                "device_id": device_id, "device_pubkey": device_pubkey},
                                               attacker_key))


def _build_store():
    """A store whose device ledger exercises every fold edge. Returns (store, A, B, C, D) and appends in
    this exact seq order:

        seq 0  authorize A      (OWNER)      -- prefix; A is NEVER touched again -> survives only via the seed
        seq 1  authorize B      (OWNER)      -- prefix; revoked in the LIVE window (LWW live-override)
        seq 2  authorize D      (OWNER)      -- prefix; revoked in the PREFIX (pruned revoke)
        seq 3  revoke   D      (OWNER)      -- prefix; PRUNED revoke -> folds to "revoked", must NOT re-auth
        seq 4  authorize <None> (OWNER)      -- prefix; NON-STR device_pubkey, never touched -> only via seed
        seq 5  authorize <1337> (OWNER)      -- prefix; NON-STR int device_pubkey, never touched -> only seed
        seq 6  forged authorize E            -- prefix; attacker-signed -> ignored
        --- split K = 7 ---
        seq 7  authorize C      (OWNER)      -- live
        seq 8  revoke   B      (OWNER)      -- live; LWW live-override of a prefix-seeded device
        seq 9  forged authorize F            -- live; attacker-signed -> ignored
    """
    s = _store()
    A, B, C, D = generate_keypair(), generate_keypair(), generate_keypair(), generate_keypair()
    attacker = generate_keypair()
    E, F = generate_keypair(), generate_keypair()
    authorize_device(s, "phoneA", A.public_key_b64, OWNER)          # seq 0
    authorize_device(s, "phoneB", B.public_key_b64, OWNER)          # seq 1
    authorize_device(s, "phoneD", D.public_key_b64, OWNER)          # seq 2
    revoke_device(s, "phoneD", D.public_key_b64, OWNER)             # seq 3  (pruned revoke)
    authorize_device(s, "phoneNone", NONE_KEY, OWNER)              # seq 4  (non-str key = None)
    authorize_device(s, "phoneInt", INT_KEY, OWNER)                # seq 5  (non-str key = int)
    _forged_authorize(s, E.public_key_b64, attacker, "evilE")       # seq 6
    authorize_device(s, "phoneC", C.public_key_b64, OWNER)          # seq 7
    revoke_device(s, "phoneB", B.public_key_b64, OWNER)             # seq 8
    _forged_authorize(s, F.public_key_b64, attacker, "evilF")       # seq 9
    return s, A, B, C, D


# the known-correct authorized set for _build_store: A + C authorized, B revoked-in-live, D revoked-in-prefix,
# the two NON-STR keys authorized (never revoked), E/F forged -> ignored.
def _expected(A, C):
    return {A.public_key_b64, C.public_key_b64, NONE_KEY, INT_KEY}


# ---- (A) IDENTITY: rewired consumer == known-correct value under the empty snapshot ---------------
def test_identity_known_correct(monkeypatch):
    # Force the universal Slice-C empty-snapshot path deterministically (no committed prune => head absent),
    # independent of the ambient SIGIL_HOME: load() -> empty identity -> base_seq 0 -> full genesis scan.
    monkeypatch.setattr(snapshot_mod, "HEAD_PATH", snapshot_mod.HEAD_PATH.with_name("nonexistent-head.json"))
    assert SnapshotState.load(_store()).base_seq == 0, "no committed prune must yield the empty identity"

    s, A, B, C, D = _build_store()
    got = authorized_devices(s, OP)
    assert got == _expected(A, C), \
        "authorized = owner-authorized minus later-revoked (B live-revoke, D prefix-revoke), forged ignored"
    assert B.public_key_b64 not in got, "a device revoked in the live window is not authorized"
    assert D.public_key_b64 not in got, "a device revoked in the (pruned) prefix is not authorized"
    assert NONE_KEY in got and INT_KEY in got, "an owner-signed NON-STR device_pubkey is kept verbatim"


def test_identity_bypass_wrong_anchor_is_empty(monkeypatch):
    # Pubkey-dependent bypass under the empty snapshot: a caller whose anchor != the snapshot's re-scans from
    # genesis with that anchor; no record verifies under a stranger's key -> empty (byte-identical old scan).
    monkeypatch.setattr(snapshot_mod, "HEAD_PATH", snapshot_mod.HEAD_PATH.with_name("nonexistent-head.json"))
    s, _A, _B, _C, _D = _build_store()
    stranger = generate_keypair().public_key_b64
    assert authorized_devices(s, stranger) == set(), "records signed by OWNER don't verify under a stranger anchor"


# ---- (B) SPLIT: fold([0..K)) via build() + fold([K..T)) via consumer == scan([0..T)) --------------
def test_split_fold_equals_full_scan(monkeypatch):
    monkeypatch.setattr(snapshot_mod, "HEAD_PATH", snapshot_mod.HEAD_PATH.with_name("nonexistent-head.json"))
    s, A, B, C, D = _build_store()

    # full = the real empty-load consumer -> scans all [0..T]
    full = authorized_devices(s, OP)
    assert full == _expected(A, C)

    K = 7
    prefix = [r for r in s.iter_records() if r.seq < K]
    # sanity: the prefix is NON-EMPTY and carries state that MATTERS
    assert len(prefix) == 7, "prefix must be the non-trivial [0..K) window"
    synthetic = snapshot_mod.build(prefix, trusted_pubkey=OP, base_seq=K, snapshot_seq=K - 1)

    # mesh_dev_state is a LIST-of-rows persisted form -> reconstruct with dict() (exactly what the consumer
    # does). The folded prefix carries A (authorized, untouched in live), B (about to be live-revoked),
    # D (already revoked in the prefix -> "revoked"), and BOTH non-str keys authorized (verbatim).
    assert dict(synthetic.mesh_dev_state) == {
        A.public_key_b64: "authorized",
        B.public_key_b64: "authorized",
        D.public_key_b64: "revoked",
        NONE_KEY: "authorized",
        INT_KEY: "authorized",
    }, "the folded prefix keys mirror the scan (incl. the pruned revoke of D and the NON-STR keys)"
    # the non-str keys survive the JSON round-trip through the list-of-rows form with their EXACT types
    _keys = [row[0] for row in synthetic.mesh_dev_state]
    assert NONE_KEY in _keys and INT_KEY in _keys, "build() keeps NON-STR device_pubkeys (no isinstance guard)"
    assert type(_keys[_keys.index(INT_KEY)]) is int, "the int key round-trips as an int, not a string"
    assert synthetic.base_seq == K and synthetic.trusted_pubkey == OP

    # split = seed the synthetic prefix + fold only the LIVE window [K..T] from the SAME store
    monkeypatch.setattr(SnapshotState, "load", classmethod(lambda cls, store: synthetic))
    split = authorized_devices(s, OP)
    assert split == full, "fold(prefix via build) + fold(live via consumer) == the genesis scan"

    # A appears in NO live record — it survives ONLY because the synthetic prefix seed carried it.
    assert A.public_key_b64 in split, "A (prefix-only) is present -> the seed was folded in, not dropped"
    assert not any(r.payload.get("device_pubkey") == A.public_key_b64
                   for r in s.iter_records() if r.seq >= K), "A is touched by no live record (proves seeding)"
    # the pruned revoke of D is preserved (keep-revoked survives pruning) and NOT re-authorized in live.
    assert D.public_key_b64 not in split, "a device revoked inside the pruned prefix stays revoked"
    assert not any(r.payload.get("device_pubkey") == D.public_key_b64
                   for r in s.iter_records() if r.seq >= K), "D is touched by no live record (pruned-revoke seed)"
    # the NON-STR keys survive ONLY via the seed (no live record touches them) -> they prove the missed case.
    assert NONE_KEY in split and INT_KEY in split, "NON-STR device_pubkeys survive via the seed (prefix-only)"
    assert not any(r.payload.get("device_pubkey") in (NONE_KEY, INT_KEY)
                   for r in s.iter_records() if r.seq >= K), "the non-str keys are touched by no live record"

    # counterfactual 1 (non-green-wash): an EMPTY seed at the SAME base_seq drops every prefix-only device.
    empty_synth = SnapshotState(base_seq=K, snapshot_seq=K - 1, trusted_pubkey=OP)
    monkeypatch.setattr(SnapshotState, "load", classmethod(lambda cls, store: empty_synth))
    dropped = authorized_devices(s, OP)
    assert dropped == {C.public_key_b64} and dropped != full, \
        "an empty seed loses the prefix-only devices (A + both non-str keys) -> the split's PASS is load-bearing"

    # counterfactual 2 (pins the MISSED CASE specifically): a seed that keeps ONLY str keys — i.e. what a
    # build() with a stray `isinstance(device_pubkey, str)` guard would emit — DROPS the non-str keys and so
    # the split would NO LONGER equal the full scan. This is exactly the checker bug the strengthened test
    # exists to catch.
    stronly_rows = [[d, s2] for d, s2 in dict(synthetic.mesh_dev_state).items() if isinstance(d, str)]
    stronly_synth = SnapshotState(base_seq=K, snapshot_seq=K - 1, trusted_pubkey=OP, mesh_dev_state=stronly_rows)
    monkeypatch.setattr(SnapshotState, "load", classmethod(lambda cls, store: stronly_synth))
    stronly = authorized_devices(s, OP)
    assert NONE_KEY not in stronly and INT_KEY not in stronly, "a str-only seed drops the non-str keys"
    assert stronly != full, "dropping the non-str keys breaks fold==scan -> keeping them is load-bearing"
    assert stronly == {A.public_key_b64, C.public_key_b64}, "str-only seed = the strings A+C, non-str keys lost"


class _MP:
    """Tiny monkeypatch shim so the __main__ runner can exercise the fixture-taking tests too."""
    def __init__(self):
        self._undo = []

    def setattr(self, obj, name, val):
        self._undo.append((obj, name, getattr(obj, name)))
        setattr(obj, name, val)

    def undo(self):
        for obj, name, val in reversed(self._undo):
            setattr(obj, name, val)


if __name__ == "__main__":
    import inspect

    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    passed = 0
    for fn in fns:
        mp = _MP()
        try:
            if "monkeypatch" in inspect.signature(fn).parameters:
                fn(mp)
            else:
                fn()
            print(f"  PASS  {fn.__name__}"); passed += 1
        except AssertionError as e:
            print(f"  FAIL  {fn.__name__}: {e}")
        except Exception as e:  # noqa: BLE001
            import traceback
            print(f"  ERROR {fn.__name__}: {e}")
            traceback.print_exc()
        finally:
            mp.undo()
    print(f"{passed}/{len(fns)} mesh authorized_devices snapshot-fold equivalence guarantees hold")
