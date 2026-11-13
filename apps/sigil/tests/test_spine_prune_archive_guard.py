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
    with pytest.raises(prune.PruneUnsafe, match=r"uncommitted prune at 4 .* `sigil spine prune -K 4 --yes`"):
        prune.commit_prune(_store_of(world), 6, confirm=True)
    assert _mpath(world).read_bytes() == before and _first_seq(world) == 0
    assert prune.commit_prune(_store_of(world), 4, confirm=True)["base_seq"] == 4
    assert [r.seq for r in _snapshots(world)] == [orphan[0].seq], "the completed prune stacked a second snapshot"
    assert _head(world).snapshot_seq == orphan[0].seq
    _verified(world)


def test_a_narrower_prune_after_an_interrupted_wider_one_names_it(world):
    _crashed_prune(world, 6, "prune_after_archive")
    with pytest.raises(prune.PruneUnsafe, match="uncommitted prune at 6"):
        prune.commit_prune(_store_of(world), 4, confirm=True)
    assert prune.commit_prune(_store_of(world), 6, confirm=True)["base_seq"] == 6
    _verified(world)


def _pending_past_the_committed_prune(root, rows_before=()):
    """A candidate archive for a prune at 6 on top of the committed prune at 4: the archived [0..4), plus [4..6)
    copied from the live spine and a row chaining from the committed one (`rows_before` are prepended)."""
    s = _store_of(root)
    am = _manifest(root)
    seg = next(g for g in prune.read_manifest(s._layout).segments if g.first_seq == 4)
    ad = root / "archive"
    prune._copy_segments(s, [seg], am, {r["id"] for r in am["segments"]}, ad / "segments", ad)
    leaves = [r.entry_hash for r in s.iter_records() if 4 <= r.seq < 6]
    head = _head(root)
    delta = merkle_root(leaves)
    pending = {"base_seq": 6, "base_count": 6, "base_prev_hash": leaves[-1], "delta_merkle_root": delta,
               "cumulative_merkle_root": chain_cumulative(head.cumulative_merkle_root, delta),
               "prev_snapshot_seq": head.snapshot_seq}
    am["snapshots"] = [*rows_before, *am["snapshots"], {k: pending[k] for k in (
        "base_seq", "base_count", "delta_merkle_root", "cumulative_merkle_root", "prev_snapshot_seq")}]
    return s, am, pending


def test_a_pending_prune_past_a_committed_one_verifies_only_if_the_committed_rows_re_derive_the_head(world):
    prune.commit_prune(_store_of(world), 4, confirm=True)
    s, am, pending = _pending_past_the_committed_prune(world)
    ok, why = prune.verify_with_archive(s, pending=pending, manifest=am)
    assert ok, why
    committed = am["snapshots"][0]
    forged = dict(committed, base_seq=2, base_count=2)                  # a row no signed head committed
    s, am, pending = _pending_past_the_committed_prune(world, rows_before=[forged])
    ok, why = prune.verify_with_archive(s, pending=pending, manifest=am)
    assert ok is False and "the current head commits does not re-derive" in why


# ---- the prior snapshot is the one the signed head commits -----------------------------------------------------

def test_the_prior_snapshot_is_the_committed_one_not_a_newer_record(world):
    prune.commit_prune(_store_of(world), 4, confirm=True)
    committed = _head(world).snapshot_seq
    s = _store_of(world)
    real = s.get(committed)
    s.append(kind="snapshot", source="spine", actor="OWNER",       # a snapshot record no signed head names
             payload=dict(real.payload, base_seq=5, cumulative_merkle_root="f" * 64))
    prior = prune._prior_snapshot(_store_of(world))
    assert prior["snapshot_seq"] == committed
    assert prior["cumulative_merkle_root"] == _head(world).cumulative_merkle_root


def test_no_prior_snapshot_before_the_first_prune_even_with_a_snapshot_record(world):
    _crashed_prune(world, 4, "prune_after_snapshot")
    assert _snapshots(world) and prune._prior_snapshot(_store_of(world)) is None


@pytest.mark.parametrize("named", [999, 5])                  # nothing there / an ordinary event record
def test_a_head_naming_a_missing_snapshot_is_refused(world, monkeypatch, named):
    prune.commit_prune(_store_of(world), 4, confirm=True)
    head = _head(world)
    monkeypatch.setattr(_cp, "_read_head_on_disk", lambda: head.model_copy(update={"snapshot_seq": named}))
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


def test_the_pending_check_refuses_an_archive_with_no_segments(world):
    pay = prune.snapshot_payload(_store_of(world), 4)
    ok, why = prune.verify_with_archive(_store_of(world), pending=pay, manifest={"segments": [], "snapshots": []})
    assert ok is False and "does not cover exactly [0..4)" in why


def test_the_pending_check_refuses_a_payload_whose_root_the_archive_does_not_re_derive(world):
    """The archive (left by an interrupted attempt) is consistent with itself; the payload the head would sign is
    not consistent with it — the prune must not commit that root."""
    _crashed_prune(world, 4, "prune_after_archive")
    pay = dict(prune.snapshot_payload(_store_of(world), 4), cumulative_merkle_root="f" * 64)
    ok, why = prune.verify_with_archive(_store_of(world), pending=pay)
    assert ok is False and "the pending prune's cumulative_merkle_root" in why


def test_the_pending_check_refuses_a_prune_that_is_not_past_the_committed_one(world):
    prune.commit_prune(_store_of(world), 4, confirm=True)
    payload = {"base_seq": 4, "base_prev_hash": "x", "cumulative_merkle_root": "y"}
    ok, why = prune.verify_with_archive(_store_of(world), pending=payload)
    assert ok is False and "not past" in why


# ---- review fold: the archive a deletion relies on, and refusals instead of crashes ---------------------------

def _seg_files(root):
    return sorted(p.name for p in (root / "spine.segments").glob("seg-*.jsonl"))


def test_a_committed_prune_keeps_its_files_until_its_archive_verifies(world, tmp_path):
    import shutil
    _crashed_prune(world, 4, "prune_after_head")             # committed; its files below 4 not yet reclaimed
    files = _seg_files(world)
    shutil.copytree(world / "archive", tmp_path / "saved")
    shutil.rmtree(world / "archive")
    with pytest.raises(prune.PruneUnsafe, match="committed, but its archive does not verify"):
        prune.commit_prune(_store_of(world), 4, confirm=True)
    assert _seg_files(world) == files, "a pruned segment file was deleted while the archive does not verify"
    _store_of(world).finish_prune()                          # `sigil spine prune-finish` keeps them too
    assert _seg_files(world) == files
    shutil.copytree(tmp_path / "saved", world / "archive")
    assert prune.commit_prune(_store_of(world), 4, confirm=True)["already_complete"] is True
    assert len(_seg_files(world)) == len(files) - 2           # reclaimed once the archive verifies
    _verified(world)


def _archived_seg0(root):
    m = _manifest(root)
    return m, next(r for r in m["segments"] if r["first_seq"] == 0)


def _make_row_the_live_file(root, how):
    import os
    live = root / "spine.segments" / "seg-00000000.jsonl"
    m, row = _archived_seg0(root)
    held = root / "archive" / row["file"]
    if how == "traversal":
        row["file"] = "../spine.segments/seg-00000000.jsonl"
        _mpath(root).write_text(json.dumps(m))
    else:
        held.unlink()
        (os.symlink if how == "symlink" else os.link)(live, held)
    return live


@pytest.mark.parametrize("how", ["traversal", "symlink", "hardlink"])
def test_the_verifier_refuses_an_archive_row_that_is_the_live_file(world, how):
    _crashed_prune(world, 4, "prune_after_archive")
    _make_row_the_live_file(world, how)
    pay = prune.snapshot_payload(_store_of(world), 4)
    ok, why = prune.verify_with_archive(_store_of(world), pending=pay)
    assert ok is False and ("segments directory" in why or "live segment file" in why)


@pytest.mark.parametrize("how", ["traversal", "symlink", "hardlink"])
def test_a_prune_copies_again_an_archive_row_that_is_the_live_file(world, how):
    import os
    _crashed_prune(world, 4, "prune_after_archive")
    live = _make_row_the_live_file(world, how)
    ino = live.stat().st_ino
    assert prune.commit_prune(_store_of(world), 4, confirm=True)["base_seq"] == 4
    _verified(world)
    m, row = _archived_seg0(world)
    held = world / "archive" / row["file"]
    assert held.parent == world / "archive" / "segments" and not held.is_symlink() and held.stat().st_ino != ino
    assert not os.path.exists(live)


@pytest.mark.parametrize("bad", ["4", None, 4.5, {}])
def test_a_malformed_snapshot_row_is_a_refusal_never_a_traceback(world, capsys, monkeypatch, bad):
    from sigil import cli
    _crashed_prune(world, 4, "prune_after_archive")
    m = _manifest(world)
    m["snapshots"][0]["base_seq"] = bad
    _mpath(world).write_text(json.dumps(m))
    ok, why = prune.verify_with_archive(_store_of(world))
    assert ok is False and "malformed" in why
    monkeypatch.setattr(cli, "SpineStore", lambda *a, **k: _store_of(world))
    with pytest.raises(SystemExit) as ei:
        cli.cmd_spine(NS(action="prune", boundary=4, yes=True, archive=None))
    assert ei.value.code == 2 and "prune UNSAFE" in capsys.readouterr().err
    assert _first_seq(world) == 0


@pytest.mark.parametrize("damage", ["missing", "flipped"])
def test_a_damaged_copy_of_a_still_live_segment_is_copied_again(world, damage):
    _crashed_prune(world, 4, "prune_after_archive")
    m, row = _archived_seg0(world)
    held = world / "archive" / row["file"]
    if damage == "missing":
        held.unlink()
    else:
        held.write_bytes(held.read_bytes()[:-3] + b"X}\n")
    assert prune.commit_prune(_store_of(world), 4, confirm=True)["base_seq"] == 4
    _verified(world)


def test_a_stuck_uncommitted_row_names_a_way_out_when_no_prune_is_committed(world):
    _crashed_prune(world, 6, "prune_after_archive")
    with pytest.raises(prune.PruneUnsafe, match=r"move .*archive aside \(no prune is committed"):
        prune.commit_prune(_store_of(world), 4, confirm=True)


# ---- a commit interrupted between its head and its floor; a stale row at the very boundary ----------------------

def test_a_re_run_brings_the_floor_up_to_a_head_committed_without_it(world, monkeypatch, capsys):
    """The prune commit moves the durable floor with its head. One interrupted between the two (here: the floor write
    fails) leaves the floor on the pre-prune head; the re-run that reports the prune complete also completes that
    half, so the committed boundary is pinned against a rollback."""
    def floor_write_fails(*a, **kw):
        raise OSError("disk full (test)")

    with monkeypatch.context() as m:
        m.setattr(_cp, "advance_floor", floor_write_fails)
        with pytest.raises(OSError):
            prune.commit_prune(_store_of(world), 4, confirm=True)
    head = _head(world)
    assert head.base_seq == 4 and head.snapshot_seq >= 0, "the head committed"
    assert _fl.load_floor().base_seq == 0, "the floor did not move with it"
    from sigil import cli
    monkeypatch.setattr(cli, "SpineStore", lambda *a, **k: _store_of(world))
    cli.cmd_spine(NS(action="prune", boundary=4, yes=True, archive=None))
    out = capsys.readouterr().out
    fl = _fl.load_floor()
    assert (fl.base_seq, fl.head_sig_hash) == (4, _fl.head_sig_hash(head))
    assert "already committed" in out and "floor is now brought up" in out
    rep = prune.commit_prune(_store_of(world), 4, confirm=True)
    assert rep["already_complete"] is True and rep["floor_advanced"] is False
    assert _cp.verify_checkpoint(_store_of(world))[0]


def test_a_stale_row_at_the_same_boundary_is_superseded_by_the_prune_that_verifies(world):
    """An earlier attempt at K left a row whose root chained differently (an older build) and that no signed head
    commits. The prune at K replaces it with its own row — the candidate verifies for exactly this prune — rather
    than refusing the boundary until the archive is moved aside by hand."""
    _crashed_prune(world, 4, "prune_after_archive")
    m = _manifest(world)
    m["snapshots"] = [dict(m["snapshots"][0], delta_merkle_root="e" * 64, cumulative_merkle_root="f" * 64)]
    _mpath(world).write_text(json.dumps(m, indent=2), encoding="utf-8")
    with pytest.raises(prune.PruneUnsafe, match=r"uncommitted prune at 4 .* `sigil spine prune -K 4 --yes`"):
        prune.commit_prune(_store_of(world), 6, confirm=True)
    rep = prune.commit_prune(_store_of(world), 4, confirm=True)
    assert rep["base_seq"] == 4 and _first_seq(world) == 4
    rows = _manifest(world)["snapshots"]
    assert [r["base_seq"] for r in rows] == [4] and rows[0]["cumulative_merkle_root"] == _head(world).cumulative_merkle_root
    _verified(world)


def test_a_committed_row_is_never_superseded(world):
    """The same-boundary replacement never touches a row at or below the boundary the signed head commits."""
    prune.commit_prune(_store_of(world), 4, confirm=True)
    m = _manifest(world)
    srow = dict(m["snapshots"][0], cumulative_merkle_root="f" * 64)
    assert prune._superseding_uncommitted_rows_at(m, srow) is None
    pending = dict(srow, base_seq=6, base_count=6)
    m["snapshots"].append(dict(pending, cumulative_merkle_root="e" * 64))
    replaced = prune._superseding_uncommitted_rows_at(m, pending)
    assert replaced is not None and replaced["snapshots"][0] == m["snapshots"][0]
    assert [r["cumulative_merkle_root"] for r in replaced["snapshots"]] == [m["snapshots"][0]["cumulative_merkle_root"],
                                                                         "f" * 64]


def test_a_damaged_copy_copied_again_must_hash_as_its_source(world, monkeypatch):
    """The fresh copy of a still-live segment whose archived copy was damaged is checked against the source hash
    like every first copy: a copy that does not hash as its source stops the prune."""
    _crashed_prune(world, 4, "prune_after_archive")
    m, row = _archived_seg0(world)
    (world / "archive" / row["file"]).unlink()
    real = prune._copy_file

    def short_copy(src, dst, segdir):
        real(src, dst, segdir)
        dst.write_bytes(dst.read_bytes()[:-2])

    monkeypatch.setattr(prune, "_copy_file", short_copy)
    with pytest.raises(prune.PruneUnsafe, match="hashes differently than the source"):
        prune.commit_prune(_store_of(world), 4, confirm=True)
    assert _first_seq(world) == 0 and _head(world).snapshot_seq < 0


def test_a_partition_refusal_names_the_way_out_when_no_prune_is_committed(world):
    """A candidate whose snapshot rows do not partition the prefix (here: a row at seq 0, which no prune writes) is
    refused, and — with no prune committed, so nothing relies on the archive — the refusal names moving it aside."""
    _crashed_prune(world, 4, "prune_after_archive")
    m = _manifest(world)
    m["snapshots"].insert(0, dict(m["snapshots"][0], base_seq=0, base_count=0))
    _mpath(world).write_text(json.dumps(m, indent=2), encoding="utf-8")
    with pytest.raises(prune.PruneUnsafe, match=r"do not partition .*move .*archive aside \(no prune is committed"):
        prune.commit_prune(_store_of(world), 4, confirm=True)
    assert _first_seq(world) == 0 and _head(world).snapshot_seq < 0
