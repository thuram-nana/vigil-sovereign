"""`sigil backup` of a HARD-PRUNED home (SIGIL_PRUNED_RESTORE on): the spine, its signed head, the floor and the
archive are captured as ONE consistent, verified unit — manifest schema 4 with a ``prune_unit`` block — and a unit
that does not verify, or keeps changing, is refused with nothing written. With the flag off, or for a home that is not
pruned, the backup is exactly what it was.

Each backup runs in a child process whose SIGIL_HOME is the real home (``tests/_real_home.py``).

Run: SIGIL_HOME=$(mktemp -d) python -m pytest tests/test_backup_pruned_capture.py
"""
from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from sigil import backup
from sigil.backup import BackupError, create_backup, restore_backup
from vigil_core.vault import Vault

from tests._real_home import (PW, backup_home, open_backup, read_home, run_in_home,  # type: ignore
                              signed_home)
from tests.test_backup import PW as SRC_PW, _make_source, make_fake_tpm  # type: ignore

HEAD_FLOOR = """
import json
from sigil import config
from sigil.reuse import SignedChainHead
from sigil.spine.floor import head_sig_hash, load_floor
h = SignedChainHead.model_validate_json(config.HEAD_PATH.read_text())
print(json.dumps({"head_sig_hash": head_sig_hash(h), "floor": load_floor().head_sig_hash, "base_seq": h.base_seq,
                  "snapshot_seq": h.snapshot_seq, "last_seq": h.last_seq, "entry_count": h.entry_count,
                  "cumulative": h.cumulative_merkle_root,
                  "pub": (config.KEYS_DIR / "owner.pub").read_text().strip()}))
"""

# a capture that races a `sigil sign`: the in-lock listing is wrapped so a checkpoint lands between the digests
TORN = """
import json, sys
from sigil import backup, config
from sigil.backup import BackupError, create_backup
from sigil.governor.identity import ensure_owner_keypair
from sigil.platform.vault import owner_vault
from sigil.spine import checkpoint as cp
from sigil.spine.store import SpineStore
backup._CAPTURE_BACKOFF_S = 0
real, calls = backup._spine_files, []
def racing(*a, **k):
    res = real(*a, **k)
    calls.append(1)
    if sys.argv[2] == "always" or len(calls) == 1:
        cp.checkpoint(SpineStore())
    return res
backup._spine_files = racing
try:
    res = create_backup(sys.argv[1], "pw-test-only", home=config.SIGIL_HOME, vault=owner_vault(),
                        owner_key=ensure_owner_keypair())
except BackupError as e:
    res = {"error": str(e)}
res["calls"] = len(calls)
print(json.dumps(res))
"""

ROTATE = """
import sys, time
from sigil import config
from sigil.governor import key_history as kh
from sigil.spine import checkpoint as cp
from sigil.spine.store import SpineStore
s = SpineStore(config.SPINE_PATH)
standing = cp.standing_pruned_head(s)
kh.rotate(s, issued_at=time.time())
if sys.argv[1] == "finish":
    cp.checkpoint(s, carry=standing)
"""


def _info(home: Path) -> dict:
    return json.loads(run_in_home(home, HEAD_FLOOR, SIGIL_SPINE_ARCHIVE_DIR=None).stdout.strip().splitlines()[-1])


@pytest.fixture(scope="module")
def pruned_home(tmp_path_factory):
    return signed_home(tmp_path_factory.mktemp("pc"), pruned=True, world=True)


def _copy(src: Path, tmp_path: Path, name: str = "home") -> Path:
    dst = tmp_path / name
    shutil.copytree(src, dst)
    return dst


# ---- a pruned unit ----------------------------------------------------------------------------------------------
def test_a_pruned_home_is_captured_as_one_verified_unit(pruned_home, tmp_path):
    home = _copy(pruned_home, tmp_path)
    dest = tmp_path / "bk.sglbk"
    res = backup_home(home, dest, SIGIL_SPINE_ARCHIVE_DIR=None)
    assert "error" not in res, res
    body = open_backup(dest)
    m = body["manifest"]
    assert m["schema"] == 4
    pu, info = m["prune_unit"], _info(home)
    assert res["prune_unit"] == pu
    assert (pu["base_seq"], pu["snapshot_seq"], pu["last_seq"], pu["entry_count"]) == (
        info["base_seq"], info["snapshot_seq"], info["last_seq"], info["entry_count"]) == (10, 23, 23, 24)
    assert pu["head_sig_hash"] == info["head_sig_hash"] and pu["floor_head_sig_hash"] == info["floor"]
    assert pu["cumulative_merkle_root"] == info["cumulative"] and pu["succession_tip"] == info["pub"]
    assert pu["archive"]["rel"] == "spine/archive" and pu["archive"]["source"] == "default"
    assert pu["archive"]["segments"] == 2 and pu["verified_at_capture"] is True
    rels = set(body["files"])
    assert "spine/archive/archive.manifest.json" in rels and "floor.json" in rels and "spine/head.json" in rels
    assert not [r for r in rels if r.endswith((".idx", ".lock", ".tmp"))]
    assert not [r for r in rels if r.endswith((".priv", ".dek"))]


def test_with_the_flag_off_a_pruned_home_is_backed_up_as_before(pruned_home, tmp_path):
    home = _copy(pruned_home, tmp_path)
    dest = tmp_path / "bk.sglbk"
    res = backup_home(home, dest, flag=False, SIGIL_SPINE_ARCHIVE_DIR=None)
    assert "error" not in res and "prune_unit" not in res, res
    m = open_backup(dest)["manifest"]
    assert m["schema"] == 3 and "prune_unit" not in m


def test_an_unpruned_home_backup_is_byte_identical_in_shape_with_the_flag_on(tmp_path, monkeypatch):
    src, v, owner = _make_source(tmp_path)
    monkeypatch.delenv("SIGIL_PRUNED_RESTORE", raising=False)
    off = create_backup(tmp_path / "off.sglbk", SRC_PW, home=src, vault=v, owner_key=owner)
    monkeypatch.setenv("SIGIL_PRUNED_RESTORE", "1")
    on = create_backup(tmp_path / "on.sglbk", SRC_PW, home=src, vault=v, owner_key=owner)
    assert {k: x for k, x in off.items() if k not in ("dest", "bytes")} == \
           {k: x for k, x in on.items() if k not in ("dest", "bytes")}

    def manifest(p):
        from vigil_core.sealing import unseal
        salt, sealed = backup._read_header(p)
        return json.loads(unseal(backup._derive_key(SRC_PW, salt), sealed, context=backup._BODY_CONTEXT))["manifest"]
    assert manifest(tmp_path / "off.sglbk") == manifest(tmp_path / "on.sglbk")
    assert manifest(tmp_path / "on.sglbk")["schema"] == 3


def test_a_pruned_home_that_is_not_this_process_home_is_refused(pruned_home, tmp_path):
    home = _copy(pruned_home, tmp_path)
    other = tmp_path / "other"
    other.mkdir()
    code = ("import json, sys\nfrom pathlib import Path\nfrom sigil.backup import BackupError, create_backup\n"
            "try:\n    create_backup(sys.argv[1], 'pw', home=Path(sys.argv[2]), vault=None, owner_key=None)\n"
            "    print(json.dumps({}))\nexcept BackupError as e:\n    print(json.dumps({'error': str(e)}))\n")
    out = json.loads(run_in_home(other, code, str(tmp_path / "bk"), str(home),
                                 SIGIL_PRUNED_RESTORE="1").stdout.splitlines()[-1])
    assert "not this process's home" in out["error"] and f"SIGIL_HOME={home}" in out["error"]
    assert not (tmp_path / "bk").exists()


# ---- consistency ---------------------------------------------------------------------------------------------------
def test_a_capture_torn_by_a_concurrent_sign_is_retried_and_consistent(pruned_home, tmp_path):
    home = _copy(pruned_home, tmp_path)
    before = _info(home)
    dest = tmp_path / "bk.sglbk"
    res = json.loads(run_in_home(home, TORN, str(dest), "once", SIGIL_PRUNED_RESTORE="1",
                                 SIGIL_SPINE_ARCHIVE_DIR=None).stdout.strip().splitlines()[-1])
    assert "error" not in res and res["calls"] == 2, res
    after = _info(home)
    assert after["head_sig_hash"] != before["head_sig_hash"]                 # the sign really changed the head
    pu = open_backup(dest)["manifest"]["prune_unit"]
    assert pu["head_sig_hash"] == after["head_sig_hash"] and pu["floor_head_sig_hash"] == after["floor"]


def test_a_capture_that_never_settles_is_refused(pruned_home, tmp_path):
    home = _copy(pruned_home, tmp_path)
    dest = tmp_path / "bk.sglbk"
    res = json.loads(run_in_home(home, TORN, str(dest), "always", SIGIL_PRUNED_RESTORE="1",
                                 SIGIL_SPINE_ARCHIVE_DIR=None).stdout.strip().splitlines()[-1])
    assert "kept changing" in res["error"] and res["calls"] == backup._CAPTURE_ATTEMPTS
    assert not dest.exists() and not dest.with_name(dest.name + ".tmp").exists()


# ---- capture-time verification -------------------------------------------------------------------------------------
def _flip_archived_byte(home: Path) -> None:
    p = sorted((home / "spine" / "archive" / "segments").iterdir())[0]
    raw = bytearray(p.read_bytes())
    raw[len(raw) // 2] ^= 0x01
    p.write_bytes(bytes(raw))


@pytest.mark.parametrize("case,phrase", [
    ("archived segment tampered", "sha256 mismatch"),
    ("floor deleted", "floor.json"),
    ("archive missing", "SIGIL_SPINE_ARCHIVE_DIR"),
])
def test_a_unit_that_does_not_verify_is_refused_with_nothing_written(pruned_home, tmp_path, case, phrase):
    home = _copy(pruned_home, tmp_path)
    if case == "archived segment tampered":
        _flip_archived_byte(home)
    elif case == "floor deleted":
        (home / "floor.json").unlink()
    else:
        shutil.rmtree(home / "spine" / "archive")
    dest = tmp_path / "bk.sglbk"
    res = backup_home(home, dest, SIGIL_SPINE_ARCHIVE_DIR=None)
    assert "does not verify as one unit" in res["error"] and phrase in res["error"], res
    assert not dest.exists() and not dest.with_name(dest.name + ".tmp").exists()


@pytest.fixture(scope="module")
def rotation_homes(tmp_path_factory):
    root = tmp_path_factory.mktemp("rot")
    done = signed_home(root, pruned=True, world=True, name="done")
    keys = done / "spine" / "keys"
    retired = {"owner.pub": (keys / "owner.pub").read_bytes(), "owner.priv": (keys / "owner.priv").read_bytes()}
    run_in_home(done, ROTATE, "finish", SIGIL_SPINE_ARCHIVE_DIR=None)
    half = signed_home(root, pruned=True, world=True, name="half")
    run_in_home(half, ROTATE, "interrupt", SIGIL_SPINE_ARCHIVE_DIR=None)
    return {"done": done, "retired": retired, "half": half}


def test_a_home_whose_key_files_are_not_the_succession_tip_is_refused(rotation_homes, tmp_path):
    home = _copy(rotation_homes["done"], tmp_path)
    assert "error" not in backup_home(home, tmp_path / "ok.sglbk", SIGIL_SPINE_ARCHIVE_DIR=None)
    for name, raw in rotation_homes["retired"].items():                     # put back the retired key pair
        (home / "spine" / "keys" / name).write_bytes(raw)
    dest = tmp_path / "bk.sglbk"
    res = backup_home(home, dest, SIGIL_SPINE_ARCHIVE_DIR=None)
    assert "succession tip" in res["error"], res
    assert not dest.exists()


def test_a_home_with_an_unfinished_rotation_is_refused_naming_the_finish(rotation_homes, tmp_path):
    home = _copy(rotation_homes["half"], tmp_path)
    dest = tmp_path / "bk.sglbk"
    res = backup_home(home, dest, SIGIL_SPINE_ARCHIVE_DIR=None)
    assert "does not verify as one unit" in res["error"] and "sigil key rotate --finish --yes" in res["error"], res
    assert not dest.exists()


# ---- a relocated archive -------------------------------------------------------------------------------------------
def test_a_relocated_archive_is_captured_under_the_normalized_rel(tmp_path):
    arch = tmp_path / "ebs" / "archive"
    home = signed_home(tmp_path, pruned=True, world=True, archive_dir=arch)
    assert (arch / "archive.manifest.json").is_file() and not (home / "spine" / "archive").exists()
    stale = home / "spine" / "archive"
    stale.mkdir()
    (stale / "left-over.txt").write_text("a stale default archive dir")
    dest = tmp_path / "bk.sglbk"
    res = backup_home(home, dest, SIGIL_SPINE_ARCHIVE_DIR=str(arch))
    assert "error" not in res, res
    body = open_backup(dest)
    pu = body["manifest"]["prune_unit"]
    assert pu["archive"]["source"] == "relocated" and pu["archive"]["stale_default_skipped"] is True
    assert pu["archive"]["segments"] == 2
    rels = set(body["files"])
    arch_rels = {r for r in rels if r.startswith("spine/archive/")}
    assert arch_rels == {"spine/archive/" + p.relative_to(arch).as_posix() for p in arch.rglob("*")
                         if p.is_file() and not p.name.endswith(".lock")}
    assert "spine/archive/left-over.txt" not in rels
    assert not [r for r in rels if r.startswith("/") or str(tmp_path) in r]
    # the same home backed up WITHOUT the services' archive setting is refused, not silently archive-less
    res = backup_home(home, tmp_path / "bk2.sglbk", SIGIL_SPINE_ARCHIVE_DIR=None)
    assert "SIGIL_SPINE_ARCHIVE_DIR" in res["error"], res


# ---- schema / staged-rotation guards ---------------------------------------------------------------------------------
def test_a_schema_4_backup_is_refused_by_a_build_that_reads_schema_3(pruned_home, tmp_path, monkeypatch):
    home = _copy(pruned_home, tmp_path)
    dest = tmp_path / "bk.sglbk"
    assert "error" not in backup_home(home, dest, SIGIL_SPINE_ARCHIVE_DIR=None)
    monkeypatch.setattr(backup, "_MAX_BACKUP_SCHEMA", 3)
    new = tmp_path / "restored"
    with pytest.raises(BackupError, match="newer"):
        restore_backup(dest, new, PW, vault=Vault(new / "vault", make_fake_tpm()))
    assert not new.exists() or not any(new.iterdir())


def test_a_staged_owner_key_rotation_refuses_the_backup_and_its_key_is_never_packaged(tmp_path):
    src, v, owner = _make_source(tmp_path)
    keys = src / "spine" / "keys"
    (keys / "owner.next.priv").write_text("a staged successor private key")
    res = create_backup(tmp_path / "a.sglbk", SRC_PW, home=src, vault=v, owner_key=owner)
    from vigil_core.sealing import unseal
    salt, sealed = backup._read_header(tmp_path / "a.sglbk")
    files = json.loads(unseal(backup._derive_key(SRC_PW, salt), sealed, context=backup._BODY_CONTEXT))["files"]
    assert res["files"] == len(files) and "spine/keys/owner.next.priv" not in files
    (keys / "owner.next.pub").write_text(owner.public_key_b64)
    with pytest.raises(BackupError, match="rotation is staged"):
        create_backup(tmp_path / "b.sglbk", SRC_PW, home=src, vault=v, owner_key=owner)
    assert not (tmp_path / "b.sglbk").exists()


def test_the_captured_unit_reads_back_like_the_source(pruned_home, tmp_path):
    """Sanity for the restore side: the bytes captured for the unit are the home's own (spine, floor, archive)."""
    home = _copy(pruned_home, tmp_path)
    dest = tmp_path / "bk.sglbk"
    assert "error" not in backup_home(home, dest, SIGIL_SPINE_ARCHIVE_DIR=None)
    import base64
    files = open_backup(dest)["files"]
    for rel in ("spine/head.json", "floor.json", "spine/archive/archive.manifest.json", "spine/spine.manifest.json"):
        assert base64.b64decode(files[rel]) == (home / rel).read_bytes()
    assert read_home(home)["verify_checkpoint"][0] is True


LOCK_SPY = """
import fcntl, json, os, sys
from sigil import config
from sigil.backup import create_backup
from sigil.governor.identity import ensure_owner_keypair
from sigil.platform.vault import owner_vault
seen, real = [], fcntl.flock
def spy(fd, op):
    seen.append((os.readlink(f"/proc/self/fd/{fd}"), op))
    return real(fd, op)
fcntl.flock = spy
create_backup(sys.argv[1], "pw-test-only", home=config.SIGIL_HOME, vault=owner_vault(), owner_key=ensure_owner_keypair())
print(json.dumps([[p, op == fcntl.LOCK_SH] for p, op in seen]))
"""


def test_the_capture_holds_a_shared_lock_on_the_writer_lockfile(pruned_home, tmp_path):
    home = _copy(pruned_home, tmp_path)
    lock = home / "spine" / "spine.lock"
    assert lock.is_file()
    seen = json.loads(run_in_home(home, LOCK_SPY, str(tmp_path / "bk.sglbk"), SIGIL_PRUNED_RESTORE="1",
                                  SIGIL_SPINE_ARCHIVE_DIR=None).stdout.strip().splitlines()[-1])
    assert [str(lock), True] in seen, seen


LOCK_ORDER = """
import fcntl, json, os, sys
import sigil.spine.home_unit as hu
from sigil import config
from sigil.backup import create_backup
from sigil.governor.identity import ensure_owner_keypair
from sigil.platform.vault import owner_vault
events, real_flock, real_verify = [], fcntl.flock, hu.verify_unit_isolated
def flock(fd, op):
    if os.readlink(f"/proc/self/fd/{fd}") == str(config.SIGIL_HOME / "spine" / "spine.lock"):
        events.append({fcntl.LOCK_SH: "shared", fcntl.LOCK_UN: "released"}.get(op, str(op)))
    return real_flock(fd, op)
def verify(unit, **kw):
    events.append("verify")
    events.append(str(unit.home))
    return real_verify(unit, **kw)
fcntl.flock, hu.verify_unit_isolated = flock, verify
create_backup(sys.argv[1], "pw-test-only", home=config.SIGIL_HOME, vault=owner_vault(), owner_key=ensure_owner_keypair())
print(json.dumps(events))
"""


def test_the_captured_unit_is_verified_after_the_writer_lock_is_released(pruned_home, tmp_path):
    """Appenders wait only for the capture's read of the unit (digest, read, digest): the verification of the
    captured bytes runs after the shared lock is released, in a child scoped to a scratch copy of them beside the
    backup (removed afterwards)."""
    home = _copy(pruned_home, tmp_path)
    out = tmp_path / "out"
    events = json.loads(run_in_home(home, LOCK_ORDER, str(out / "bk.sglbk"), SIGIL_PRUNED_RESTORE="1",
                                    SIGIL_SPINE_ARCHIVE_DIR=None).stdout.strip().splitlines()[-1])
    assert events[:3] == ["shared", "released", "verify"] and len(events) == 4, events
    scratch = Path(events[3])
    assert scratch.parent.parent == out and scratch.parent.name.startswith(".sigil-backup-verify-"), events
    assert not scratch.parent.exists() and sorted(p.name for p in out.iterdir()) == ["bk.sglbk"]
