"""A hard prune deletes nothing unless the archive it relies on VERIFIES for exactly that prune.

  * the candidate archive manifest is verified for the pending prune BEFORE it is written — a refused attempt
    leaves no row behind (every row re-derived from the archived bytes, the still-live part equal to the
    owner-signed records, the prefix the current head commits re-deriving the head's cumulative root);
  * a row left by an interrupted attempt at another boundary is named, with the command that completes it;
  * the next prune chains from the snapshot the owner-signed head COMMITS — never from a snapshot record no
    signed head names;
  * re-running a prune whose head already committed reports it complete (never "UNSAFE"); a prune at or below the
    committed boundary is refused.

Run: SIGIL_HOME=$(mktemp -d) PYTHONPATH=apps/sigil:integration:packages/core/vigil_core \
     .venv-sovereign/bin/python -m pytest apps/sigil/tests/test_spine_prune_archive_guard.py
"""
from __future__ import annotations

import json
from types import SimpleNamespace as NS

import pytest

import sigil.spine.checkpoint as _cp
import sigil.spine.floor as _fl
import sigil.spine.snapshot as _snap
import sigil.spine.store as _store
from sigil.spine import prune
from sigil.spine.merkle import chain_cumulative, merkle_root
from sigil.spine.store import SpineStore


class _Crash(Exception):
    pass


def _build(path, *, tag=0) -> SpineStore:
    s = SpineStore(path)
    s.migrate()
    seq = 0
    for _seg in range(4):
        for _i in range(2):
            s.append(kind="event", source="t", actor="u", payload={"i": seq, "tag": tag})
            seq += 1
        s.rotate()                                          # sealed boundaries at 2, 4, 6, 8
    for _i in range(3):
        s.append(kind="event", source="t", actor="u", payload={"i": seq, "tag": tag})
        seq += 1
    return s


@pytest.fixture
def world(tmp_path, monkeypatch):
    import sigil.config as cfg
    keys, head = tmp_path / "keys", tmp_path / "head.json"
    for mod in (_cp, _snap):
        monkeypatch.setattr(mod, "HEAD_PATH", head)
    monkeypatch.setattr(cfg, "HEAD_PATH", head, raising=False)
    monkeypatch.setattr(_cp, "KEYS_DIR", keys)
    monkeypatch.setattr(_cp, "_PRIV", keys / "owner.priv")
    monkeypatch.setattr(_cp, "_PUB", keys / "owner.pub")
    monkeypatch.setattr(_fl, "FLOOR_PATH", tmp_path / "floor.json")
    monkeypatch.setenv("SIGIL_SPINE_ARCHIVE_DIR", str(tmp_path / "archive"))
    _cp.checkpoint(_build(tmp_path / "spine.jsonl"))
    yield tmp_path
    _store._crash_hook = None


def _store_of(root):
    return SpineStore(root / "spine.jsonl")


def _mpath(root):
    return root / "archive" / "archive.manifest.json"


def _manifest(root) -> dict:
    return json.loads(_mpath(root).read_text())


def _crash_at(name):
    def hook(n):
        if n == name:
            raise _Crash(n)
    _store._crash_hook = hook


def _crashed_prune(root, K, barrier):
    _crash_at(barrier)
    with pytest.raises(_Crash):
        prune.commit_prune(_store_of(root), K, confirm=True)
    _store._crash_hook = None


def _first_seq(root):
    return next(iter(_store_of(root).iter_records())).seq


def _snapshots(root):
    return [r for r in _store_of(root).iter_records() if r.kind == "snapshot"]


def _head(root):
    return _cp.SignedChainHead.model_validate_json((root / "head.json").read_text())


def _verified(root):
    ok, why = prune.verify_with_archive(_store_of(root))
    assert ok, why


# ---- the candidate is verified before it is written ---------------------------------------------------------

def test_a_refused_first_archive_copy_writes_no_manifest(world):
    s = _store_of(world)
    bad = dict(prune.snapshot_payload(s, 4), base_prev_hash="0" * 64)
    with pytest.raises(prune.PruneUnsafe, match="nothing was pruned"):
        prune.archive_copy(s, 4, bad)
    assert not _mpath(world).exists(), "the refused attempt's manifest was persisted"


@pytest.mark.parametrize("field", ["cumulative_merkle_root", "base_prev_hash"])
def test_a_refused_archive_copy_leaves_no_row_behind(world, field):
    s = _store_of(world)
    payload = prune.snapshot_payload(s, 4)
    prune.archive_copy(s, 4, payload)
    before = _mpath(world).read_bytes()
    with pytest.raises(prune.PruneUnsafe, match="nothing was pruned"):
        prune.archive_copy(s, 4, dict(payload, **{field: "f" * 64}))
    assert _mpath(world).read_bytes() == before, "the refused attempt's row was persisted"


def test_a_second_row_at_the_same_boundary_is_refused(world):
    """A row that chains an empty delta onto the first one (what chaining a re-run from its own uncommitted
    snapshot produces) re-derives consistently — it is refused because the rows no longer partition the prefix."""
    s = _store_of(world)
    payload = prune.snapshot_payload(s, 4)
    prune.archive_copy(s, 4, payload)
    empty = merkle_root([])
    again = dict(payload, delta_merkle_root=empty,
                 cumulative_merkle_root=chain_cumulative(payload["cumulative_merkle_root"], empty))
    with pytest.raises(prune.PruneUnsafe, match="do not partition"):
        prune.archive_copy(s, 4, again)
    assert len(_manifest(world)["snapshots"]) == 1


def test_an_archive_that_is_not_a_copy_of_the_live_spine_is_refused(world):
    """An archive that is internally consistent (bound records, a genesis chain, its own snapshot row) but was
    taken from a different spine does not verify for a pending prune of THIS one."""
    other = _build(world / "other" / "spine.jsonl", tag=1)
    pay = prune.snapshot_payload(other, 4)
    ad = world / "forged"
    (ad / "segments").mkdir(parents=True)
    am: dict = {"scope": "x", "schema_version": 1, "segments": [], "snapshots": []}
    prune._copy_segments(other, prune.check_prune_safe(other, 4), am, set(), ad / "segments", ad)
    am["snapshots"].append({k: pay[k] for k in ("base_seq", "base_count", "delta_merkle_root",
                                               "cumulative_merkle_root", "prev_snapshot_seq")})
    ok, why = prune.verify_with_archive(_store_of(world), adir=ad, pending=pay, manifest=am)
    assert ok is False and "does not match the owner-signed live spine" in why


def test_an_archived_segment_tampered_after_the_copy_stops_the_prune(world, monkeypatch):
    real_verify = prune.verify_with_archive

    def tamper_then_verify(store, **kw):
        seg = sorted((world / "archive" / "segments").glob("seg-00000001*"))[0]
        lines = seg.read_bytes().splitlines(keepends=True)
        rec = json.loads(lines[0])
        rec["payload"]["i"] = 999                         # content swapped after the copy
        lines[0] = (json.dumps(rec) + "\n").encode()
        seg.write_bytes(b"".join(lines))
        for row in kw["manifest"]["segments"]:
            if row["file"].endswith(seg.name):
                row["sha256"] = prune._sha256_file(seg)
        return real_verify(store, **kw)

    monkeypatch.setattr(prune, "verify_with_archive", tamper_then_verify)
    with pytest.raises(prune.PruneUnsafe, match="nothing was pruned"):
        prune.commit_prune(_store_of(world), 4, confirm=True)
    assert _first_seq(world) == 0 and not _snapshots(world) and _head(world).snapshot_seq < 0
    assert not _mpath(world).exists()


# ---- interrupted attempts -------------------------------------------------------------------------------------

def test_the_reviewed_sequence_leaves_an_archive_that_verifies(world):
    """A prune at 4 dies after its archive copy; a retry at 2 is refused (naming the prune to complete) and
    writes nothing; the prune at 4 then completes, and the archive verifies against the owner-signed head."""
    _crashed_prune(world, 4, "prune_after_archive")
    assert _first_seq(world) == 0
    before = _mpath(world).read_bytes()
    with pytest.raises(prune.PruneUnsafe, match=r"uncommitted prune at 4 .* `sigil spine prune -K 4 --yes`"):
        prune.commit_prune(_store_of(world), 2, confirm=True)
    assert _mpath(world).read_bytes() == before and _first_seq(world) == 0
    rep = prune.commit_prune(_store_of(world), 4, confirm=True)
    assert rep["base_seq"] == 4 and _first_seq(world) == 4
    _verified(world)


def test_a_wider_prune_after_an_interrupted_narrower_one_names_it_and_writes_nothing(world):
    _crashed_prune(world, 4, "prune_after_snapshot")
    orphan = _snapshots(world)
    assert len(orphan) == 1 and _head(world).snapshot_seq < 0
    before = _mpath(world).read_bytes()
    with pytest.raises(prune.PruneUnsafe, match="uncommitted prune at 4"):
        prune.commit_prune(_store_of(world), 6, confirm=True)
    assert _mpath(world).read_bytes() == before and _first_seq(world) == 0
    prune.commit_prune(_store_of(world), 4, confirm=True)
    assert [r.seq for r in _snapshots(world)] == [orphan[0].seq], "the completed prune stacked a second snapshot"
    rep = prune.commit_prune(_store_of(world), 6, confirm=True)
    assert rep["base_seq"] == 6
    _verified(world)
    assert _snapshots(world)[-1].payload["prev_snapshot_seq"] == orphan[0].seq


def test_a_narrower_prune_after_an_interrupted_wider_one_names_it(world):
    _crashed_prune(world, 6, "prune_after_archive")
    with pytest.raises(prune.PruneUnsafe, match="uncommitted prune at 6"):
        prune.commit_prune(_store_of(world), 4, confirm=True)
    assert prune.commit_prune(_store_of(world), 6, confirm=True)["base_seq"] == 6
    _verified(world)


def test_a_row_inconsistent_with_the_committed_head_stops_the_next_prune(world):
    prune.commit_prune(_store_of(world), 4, confirm=True)
    m = _manifest(world)
    m["snapshots"].insert(0, dict(m["snapshots"][0], base_seq=2, base_count=2))   # no head committed this
    _mpath(world).write_text(json.dumps(m))
    before, head, snaps = _mpath(world).read_bytes(), _head(world), len(_snapshots(world))
    with pytest.raises(prune.PruneUnsafe, match="nothing was pruned"):
        prune.commit_prune(_store_of(world), 6, confirm=True)
    assert _first_seq(world) == 4 and len(_snapshots(world)) == snaps
    assert _head(world) == head and _mpath(world).read_bytes() == before


# ---- the prior snapshot is the one the signed head commits -----------------------------------------------------

def test_the_next_prune_chains_from_the_committed_snapshot_not_a_newer_record(world):
    prune.commit_prune(_store_of(world), 4, confirm=True)
    committed = _head(world).snapshot_seq
    s = _store_of(world)
    real = s.get(committed)
    s.append(kind="snapshot", source="spine", actor="OWNER",       # a snapshot record no signed head names
             payload=dict(real.payload, base_seq=5, cumulative_merkle_root="f" * 64))
    assert prune._prior_snapshot(_store_of(world))["snapshot_seq"] == committed
    rep = prune.commit_prune(_store_of(world), 6, confirm=True)
    assert rep["base_seq"] == 6
    _verified(world)
    assert _snapshots(world)[-1].payload["prev_snapshot_seq"] == committed


def test_no_prior_snapshot_before_the_first_prune_even_with_a_snapshot_record(world):
    _crashed_prune(world, 4, "prune_after_snapshot")
    assert _snapshots(world) and prune._prior_snapshot(_store_of(world)) is None


def test_a_head_naming_a_missing_snapshot_is_refused(world, monkeypatch):
    prune.commit_prune(_store_of(world), 4, confirm=True)
    head = _head(world)
    monkeypatch.setattr(_cp, "_read_head_on_disk", lambda: head.model_copy(update={"snapshot_seq": 999}))
    with pytest.raises(prune.PruneUnsafe, match="no snapshot record"):
        prune._prior_snapshot(_store_of(world))


# ---- re-runs and boundaries ------------------------------------------------------------------------------------

@pytest.mark.parametrize("barrier", ["prune_after_head", "prune_after_manifest"])
def test_re_running_a_prune_whose_head_committed_reports_it_complete(world, barrier, capsys, monkeypatch):
    _crashed_prune(world, 4, barrier)
    from sigil import cli
    monkeypatch.setattr(cli, "SpineStore", lambda *a, **k: _store_of(world))
    cli.cmd_spine(NS(action="prune", boundary=4, yes=True, archive=None))      # exits 0 (no SystemExit)
    assert "already committed" in capsys.readouterr().out
    assert _first_seq(world) == 4
    _verified(world)
    rep = prune.commit_prune(_store_of(world), 4, confirm=True)
    assert rep["already_complete"] is True and rep["base_seq"] == 4
    assert rep["snapshot_seq"] == _head(world).snapshot_seq


def test_a_prune_at_or_below_the_committed_boundary_is_refused(world):
    prune.commit_prune(_store_of(world), 6, confirm=True)
    for K in (2, 4):
        with pytest.raises(prune.PruneUnsafe, match="already pruned at 6"):
            prune.commit_prune(_store_of(world), K, confirm=True)
    assert _first_seq(world) == 6


def test_the_pending_check_refuses_a_prune_that_is_not_past_the_committed_one(world):
    prune.commit_prune(_store_of(world), 4, confirm=True)
    payload = {"base_seq": 4, "base_prev_hash": "x", "cumulative_merkle_root": "y"}
    ok, why = prune.verify_with_archive(_store_of(world), pending=payload)
    assert ok is False and "not past" in why
