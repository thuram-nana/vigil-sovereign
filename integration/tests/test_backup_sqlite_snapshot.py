"""SUB-PART 1 — the CRUCIBLE ``.blackboard/store.sqlite`` is captured as a CONSISTENT point-in-time snapshot.

A naive ``read_bytes`` of a live db mid-transaction captures a TORN page mix that fails
``PRAGMA integrity_check`` on restore. ``create_offense_backup`` now routes ``store.sqlite`` through the
stdlib sqlite3 online backup API, so:
  * a real store.sqlite backs up + restores and the restored db opens with ``integrity_check == "ok"`` and
    the exact rows;
  * a db written CONCURRENTLY during the snapshot is captured consistently (integrity_check ok);
  * a non-SQLite file at that path falls back to a verbatim raw byte copy (never lost).

Needs framework (create/restore re-verify) → run in the offense leg:
    PYTHONPATH=integration:engine/crucible:gateway:packages/core/vigil_core .venv-offense/bin/python \
        -m pytest integration/tests/test_backup_sqlite_snapshot.py -q
"""
from __future__ import annotations

import sqlite3
import threading
from pathlib import Path

import pytest

pytest.importorskip("framework.v2.evidence.cli")

from vigil_integration.backup import (
    _SQLITE_MAGIC,
    _STORE_SQLITE_REL,
    _read_sqlite_consistent,
    create_offense_backup,
    restore_offense_backup,
)

# reuse the offense-home seeder (spine + the three identity keys) so create/restore find a *.spine to protect.
from test_backup_roundtrip import PW, _seed_offense_home  # type: ignore


def _make_store(path: Path, rows: int = 200) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(str(path))
    try:
        con.execute("CREATE TABLE events (id INTEGER PRIMARY KEY, payload TEXT)")
        con.executemany("INSERT INTO events (payload) VALUES (?)", [(f"row-{i}",) for i in range(rows)])
        con.commit()
    finally:
        con.close()


def _integrity_ok(path: Path) -> bool:
    con = sqlite3.connect(str(path))
    try:
        return con.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
    finally:
        con.close()


def test_store_sqlite_snapshot_backs_up_and_restores_consistent(tmp_path):
    base, croot = tmp_path / "b", tmp_path / "c"
    _seed_offense_home(base)
    store = croot / ".blackboard" / "store.sqlite"
    _make_store(store, rows=500)

    dest = tmp_path / "o.vglbk"
    summary = create_offense_backup(dest, PW, base_dir=str(base), crucible_root=str(croot))
    assert summary["files"] >= 2                                   # spine + the store snapshot

    new_base, new_croot = tmp_path / "nb", tmp_path / "nc"
    res = restore_offense_backup(dest, str(new_base), PW, crucible_root=str(new_croot))
    assert res["verified"] is True

    restored = new_croot / ".blackboard" / "store.sqlite"
    assert restored.is_file()
    assert _integrity_ok(restored), "restored store.sqlite must pass PRAGMA integrity_check"
    con = sqlite3.connect(str(restored))
    try:
        assert con.execute("SELECT count(*) FROM events").fetchone()[0] == 500
    finally:
        con.close()


def test_read_sqlite_consistent_captures_a_concurrent_writer(tmp_path):
    """A writer commits rows in a tight loop while the snapshot is taken; the snapshot must be a COHERENT db
    (integrity_check ok), never a torn page mix — that is exactly what the online backup API guarantees."""
    store = tmp_path / "store.sqlite"
    _make_store(store, rows=50)

    stop = threading.Event()

    def _writer():
        con = sqlite3.connect(str(store), timeout=30.0)
        try:
            i = 0
            while not stop.is_set():
                con.execute("INSERT INTO events (payload) VALUES (?)", (f"live-{i}",))
                con.commit()
                i += 1
        finally:
            con.close()

    t = threading.Thread(target=_writer)
    t.start()
    try:
        # take several snapshots while writes are in flight — each must be internally consistent.
        for _ in range(5):
            snap = _read_sqlite_consistent(store)
            assert snap[:len(_SQLITE_MAGIC)] == _SQLITE_MAGIC
            out = tmp_path / "snap.sqlite"
            out.write_bytes(snap)
            assert _integrity_ok(out), "a concurrent-writer snapshot must be a consistent db"
    finally:
        stop.set()
        t.join()


def test_non_sqlite_file_falls_back_to_raw_copy(tmp_path, caplog):
    """A file at the store path that is NOT a valid SQLite db is preserved verbatim (raw byte copy), with a
    logged note — never silently dropped or mangled."""
    junk = tmp_path / "store.sqlite"
    junk.write_bytes(b"this is not a sqlite database at all\x00\x01\x02")
    with caplog.at_level("WARNING"):
        out = _read_sqlite_consistent(junk)
    assert out == junk.read_bytes(), "a non-db file must be copied verbatim"
    assert any("not a SQLite database" in r.message for r in caplog.records)


def test_store_rel_constant_matches_the_packaged_path():
    """Guard the routing constant: it must equal the crucible-prefixed store.sqlite rel the create loop tests
    against (a drift here would silently skip the snapshot and fall back to raw byte reads)."""
    assert _STORE_SQLITE_REL == "crucible/.blackboard/store.sqlite"
