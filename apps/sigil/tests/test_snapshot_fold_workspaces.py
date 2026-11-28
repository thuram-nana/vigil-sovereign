"""Prune-survival proof for the SnapshotState-seeded `WorkspaceRegistry._fold` (engagement workspaces, C-WS).

The engagement-workspace fold (`governor.engagement_workspace`) used to be a GENESIS scan with NO snapshot
seed, so a hard prune below a workspace's only owner-signed `active` create/rename record would:

  * STRANDING (availability): SILENTLY vanish the workspace (`list_workspaces` -> [], `get_workspace` -> None,
    `export_bundle` -> raises) — a run's indexed work becomes unreachable, and `ensure_workspace` re-creates it
    fresh (losing its history); and
  * ARCHIVE-RESURRECTION (the anti-replay half): reset the per-(org_id, workspace_id) high-water, so a
    captured/replayed owner-signed `active` create record for a workspace the owner ARCHIVED re-applies above K
    (freshness passes because the high-water is gone) — flipping an archived workspace back to active, exactly
    the replay the module's old DEFERRED note wrongly claimed a prune could not re-open.

This slice seeds the fold from `SnapshotState` (v14 grew `workspace_*` rows) exactly as
`orgs._fold_orgs` / `customer_credentials._fold` do, and `spine.prune` refuses any prune that would strand an
active workspace the seed does not carry.

PHYSICAL-PRUNE HARNESS (identical to tests/test_snapshot_fold_ownership.py /
tests/test_snapshot_fold_integrations.py): a `PrunedView` physically hides every record with `seq < K` from
`iter_records` regardless of `since_seq`, so only the SEED can carry the pruned state. Each test also carries an
inline NEUTERED control (`SnapshotState.load` -> the empty identity) that reproduces the pre-fix genesis-scan
behaviour from inside the test, proving the seed is load-bearing.
"""
import tempfile

import pytest

from sigil.governor import engagement_workspaces as ew
from sigil.reuse import generate_keypair
from sigil.spine import prune
from sigil.spine.manifest import read_manifest
from sigil.spine.snapshot import SnapshotState, build
from sigil.spine.store import SpineStore

OWNER = generate_keypair()
OWNER_PUB = OWNER.public_key_b64


def _store():
    return SpineStore(tempfile.mktemp(suffix=".jsonl"))


def _reg(store):
    return ew.WorkspaceRegistry(store, owner_key=OWNER, trusted_pubkey=OWNER_PUB)


def _create(store, org, eng, title, *, now):
    """Owner-sign a create-on-start workspace for (org, eng); issued_at = now. Returns the derived id."""
    _reg(store).ensure_workspace(org, eng, title, issued_at=now)
    return ew.derive_workspace_id(org, eng)


def _captured_active(store, wid):
    return next(r.payload for r in store.iter_records()
               if isinstance(r.payload, dict) and r.payload.get("signal") == ew.WORKSPACE_SIGNAL
               and r.payload.get("status") == "active" and r.payload.get("workspace_id") == wid)


class PrunedView:
    """A REAL hard prune: physically hide every record with `seq < K` from `iter_records`."""
    def __init__(self, inner, K):
        self._inner = inner
        self._K = K

    def iter_records(self, *, since_seq=-1):
        for r in self._inner.iter_records(since_seq=since_seq):
            if r.seq >= self._K:
                yield r

    def get(self, seq):
        return self._inner.get(seq)

    def append(self, **kw):
        return self._inner.append(**kw)


# ---- (a) an active WORKSPACE whose only grant is PHYSICALLY PRUNED survives via the seed (no stranding) ----
def test_active_workspace_survives_a_hard_prune(monkeypatch):
    store = _store()
    wid = _create(store, "acme", "eng1", "Run alpha", now=5.0)      # active workspace at seq0 (issued 5.0)
    k = store.append(kind="event", source="governor", actor="WARDEN", payload={"signal": "marker"})
    prefix = [r for r in store.iter_records() if r.seq < k]
    snap = build(prefix, trusted_pubkey=OWNER_PUB, base_seq=k, snapshot_seq=k - 1)
    assert snap.workspace_state_map().get(("acme", wid)) == "active"
    assert snap.workspace_issued_map().get(("acme", wid)) == 5.0
    assert any(row[0] == "acme" and row[1] == wid for row in snap.workspace_row)

    pruned = PrunedView(store, k)                                   # [0..k) GONE — the create grant is unreadable
    monkeypatch.setattr(SnapshotState, "load", classmethod(lambda cls, s: snap))
    reg2 = ew.WorkspaceRegistry(pruned, owner_key=OWNER, trusted_pubkey=OWNER_PUB)
    w = reg2.get_workspace("acme", wid)
    assert w is not None, "a pruned active workspace must survive via the seed (no stranding)"
    assert w.status == "active" and w.title == "Run alpha" and w.engagement_id == "eng1"
    assert w.created_at == 5.0 and w.updated_at == 5.0
    assert [x.workspace_id for x in reg2.list_workspaces("acme")] == [wid]
    assert reg2.export_bundle("acme", wid)["manifest"]["workspace"]["title"] == "Run alpha"

    monkeypatch.setattr(SnapshotState, "load", classmethod(lambda cls, s: SnapshotState.empty()))
    reg2b = ew.WorkspaceRegistry(pruned, owner_key=OWNER, trusted_pubkey=OWNER_PUB)
    assert reg2b.get_workspace("acme", wid) is None, "no seed over a physically-pruned store ⇒ workspace stranded"
    assert reg2b.list_workspaces("acme") == []


# ---- (b) the per-(org,workspace) high-water SURVIVES the prune (no archive-replay resurrection) ----------
def test_workspace_high_water_survives_the_prune_no_archive_resurrection(monkeypatch):
    store = _store()
    wid = _create(store, "acme", "eng1", "Run alpha", now=5.0)      # active workspace at seq0 (issued 5.0)
    captured = _captured_active(store, wid)                         # the owner-signed create grant
    _reg(store).archive_workspace("acme", wid)                      # owner ARCHIVES it (safe direction, issued 0.0)
    k = store.append(kind="event", source="governor", actor="WARDEN", payload={"signal": "marker"})
    prefix = [r for r in store.iter_records() if r.seq < k]
    snap = build(prefix, trusted_pubkey=OWNER_PUB, base_seq=k, snapshot_seq=k - 1)
    assert snap.workspace_state_map().get(("acme", wid)) == "archived"
    assert snap.workspace_issued_map().get(("acme", wid)) == 5.0    # high-water preserved though archived

    store.append(kind="event", source="governor", actor="WARDEN", payload=captured)   # replay the create grant
    pruned = PrunedView(store, k)                                   # create + archive are both pruned away
    monkeypatch.setattr(SnapshotState, "load", classmethod(lambda cls, s: snap))
    reg2 = ew.WorkspaceRegistry(pruned, owner_key=OWNER, trusted_pubkey=OWNER_PUB)
    w = reg2.get_workspace("acme", wid)
    assert w is not None and w.status == "archived", \
        "a replayed create grant must NOT resurrect an archived workspace (seed high-water)"
    assert [x.status for x in reg2.list_workspaces("acme")] == ["archived"]

    monkeypatch.setattr(SnapshotState, "load", classmethod(lambda cls, s: SnapshotState.empty()))
    reg2b = ew.WorkspaceRegistry(pruned, owner_key=OWNER, trusted_pubkey=OWNER_PUB)
    w2 = reg2b.get_workspace("acme", wid)
    assert w2 is not None and w2.status == "active", "no seed ⇒ high-water lost ⇒ the replayed grant resurrects"


# ---- (c) empty-identity load == genesis scan (byte-identity of the no-prune path) -----------------------
def test_workspace_empty_load_matches_genesis():
    store = _store()
    wid1 = _create(store, "acme", "eng1", "Run alpha", now=1.0)
    wid2 = _create(store, "acme", "eng2", "Run beta", now=2.0)
    _reg(store).archive_workspace("acme", wid2)                     # archived live (still listed)
    assert SnapshotState.load(store).base_seq == 0                 # no prune -> empty identity (genesis scan)
    reg = _reg(store)
    assert reg.get_workspace("acme", wid1).status == "active"
    assert reg.get_workspace("acme", wid2).status == "archived"    # archive is a status, not a deletion
    assert {w.workspace_id for w in reg.list_workspaces("acme")} == {wid1, wid2}


# ---- (d) check_prune_safe referential floor ------------------------------------------------------------
def _workspace_segmented_store(tmp_path):
    """A migrated store: an owner-signed active workspace sits in segment 0 [0..5), which a prune at K=5
    archives+deletes; the seed must carry it or the floor refuses."""
    s = SpineStore(str(tmp_path / "spine.jsonl"))
    s.migrate()
    _create(s, "acme", "eng1", "Run alpha", now=1.0)                # active workspace at seq0
    while s.next_seq < 5:
        s.append(kind="event", source="t", actor="u", payload={"i": "pad"})          # fill segment 0 to [0..5)
    s.rotate()                                                                        # seal segment 0 [0..5)
    for _ in range(5):
        s.append(kind="event", source="t", actor="u", payload={"i": "seg1"})         # seq 5..9
    s.rotate()                                                                        # seal segment 1 [5..10)
    for _ in range(3):
        s.append(kind="event", source="t", actor="u", payload={"i": "tail"})         # a live tail
    return s


def _archived_below(store, K):
    return [seg for seg in read_manifest(store._layout).sealed_in_order()
            if seg.last_seq is not None and seg.last_seq < K]


def test_check_prune_safe_allows_a_carried_active_workspace(tmp_path, monkeypatch):
    monkeypatch.setattr("sigil.governor.identity.owner_pubkey", lambda: OWNER_PUB)
    s = _workspace_segmented_store(tmp_path)
    archived = prune.check_prune_safe(s, 5)                         # must NOT raise: the workspace IS carried
    assert [seg.first_seq for seg in archived] == [0]
    assert prune.stranded_active_workspaces(s, archived, 5) == []  # detector empty on a complete seed


def test_referential_floor_detects_a_seed_that_omits_an_active_workspace(tmp_path, monkeypatch):
    """Positive control: if build()/the seed ever DROPPED an active workspace whose only grant is below K, the
    floor must DETECT it (non-empty) and refuse — not silently prune the workspace away (stranding it)."""
    monkeypatch.setattr("sigil.governor.identity.owner_pubkey", lambda: OWNER_PUB)
    s = _workspace_segmented_store(tmp_path)
    wid = ew.derive_workspace_id("acme", "eng1")
    real_build = prune.build

    def incomplete_build(records, **kw):
        seed = real_build(records, **kw)
        return seed.model_copy(update={
            "workspace_state": [r for r in seed.workspace_state if (r[0], r[1]) != ("acme", wid)],
            "workspace_issued": [r for r in seed.workspace_issued if (r[0], r[1]) != ("acme", wid)],
            "workspace_row": [r for r in seed.workspace_row if (r[0], r[1]) != ("acme", wid)],
        })

    monkeypatch.setattr(prune, "build", incomplete_build)
    stranded = prune.stranded_active_workspaces(s, _archived_below(s, 5), 5)
    assert stranded == [f"{wid}@acme"]                             # real diff: active minus carried={}
    with pytest.raises(prune.PruneUnsafe) as e:
        prune.check_prune_safe(s, 5)
    msg = str(e.value).lower()
    assert "strand" in msg and f"{wid}@acme".lower() in msg and "workspace" in msg


def test_check_prune_safe_reraises_a_nonempty_workspace_floor_wiring_only(tmp_path, monkeypatch):
    """Pure wiring check: check_prune_safe re-raises PruneUnsafe when the workspace detector reports non-empty."""
    monkeypatch.setattr("sigil.governor.identity.owner_pubkey", lambda: OWNER_PUB)
    s = _workspace_segmented_store(tmp_path)
    monkeypatch.setattr(prune, "stranded_active_workspaces", lambda store, archived, K: ["ghost@org"])
    with pytest.raises(prune.PruneUnsafe) as e:
        prune.check_prune_safe(s, 5)
    assert "strand" in str(e.value).lower() and "ghost@org" in str(e.value)
