"""`sigil restore` of a HARD-PRUNED home (SIGIL_PRUNED_RESTORE on): the backup's spine, signed head, floor, owner
public key(s) and archive are staged, verified as ONE unit by the real readers in a child process scoped to the staged
home (private keys and sigil.env held back until then), and only then swapped in — a partial or mismatched set is
refused with the target untouched. Also: a restore swaps exactly the units the backup captured, and places the archive
where it is told (never where the restoring process's own environment points).

Restores run in-process unless the restoring process's own SIGIL_HOME matters (then in a child); the restored home is
read back in a child whose SIGIL_HOME is that home (``tests/_real_home.py``).

Run: SIGIL_HOME=$(mktemp -d) python -m pytest tests/test_restore_pruned_unit.py
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import shutil
from pathlib import Path

import pytest

from sigil import backup
from sigil.backup import BackupError, restore_backup
from sigil.reuse import canonical_json, sha256_hex, sign
from vigil_core.sealing import seal
from vigil_core.vault import Vault

from tests._real_home import (PW, backup_home, open_backup, read_home, run_in_home,  # type: ignore
                              signed_home)

RESTORE = """
import json, sys
from pathlib import Path
from sigil.backup import BackupError, restore_backup
from vigil_core.vault import Vault
a = json.loads(sys.argv[1])
home = Path(a["home"])
kw = {k: a[k] for k in ("force", "archive_dir") if a.get(k) is not None}
try:
    res = restore_backup(a["src"], home, "pw-test-only", vault=Vault(home / "vault"), **kw)
except BackupError as e:
    res = {"error": str(e)}
print(json.dumps(res, default=str))
"""

CRASH_PRUNE = """
import os
from sigil import config
import sigil.spine.store as st
from sigil.spine import prune
def hook(name):
    if name == "prune_after_head":
        os._exit(77)
st._crash_hook = hook
prune.commit_prune(st.SpineStore(config.SPINE_PATH), 10, confirm=True)
"""

ROTATE = """
import time
from sigil import config
from sigil.governor import key_history as kh
from sigil.spine import checkpoint as cp
from sigil.spine.store import SpineStore
s = SpineStore(config.SPINE_PATH)
standing = cp.standing_pruned_head(s)
kh.rotate(s, issued_at=time.time())
cp.checkpoint(s, carry=standing)
"""


def _tree(root: Path) -> dict:
    """Every path under ``root`` with its content digest (a full monitor)."""
    if not root.exists():
        return {}
    return {str(p.relative_to(root)): (hashlib.sha256(p.read_bytes()).hexdigest() if p.is_file() else "dir")
            for p in sorted(root.rglob("*"))}


@pytest.fixture(scope="module")
def world(tmp_path_factory):
    root = tmp_path_factory.mktemp("rw")
    w: dict = {}
    pre = signed_home(root, pruned=False, world=True, name="pre")
    w["pre_head"] = (pre / "spine" / "head.json").read_bytes()
    src = signed_home(root, pruned=True, world=True, name="src")
    w["src"] = src
    w["priv"] = (src / "spine" / "keys" / "owner.priv").read_text().strip()
    w["good"] = root / "good.sglbk"
    assert "error" not in backup_home(src, w["good"], SIGIL_SPINE_ARCHIVE_DIR=None)
    w["flag_off"] = root / "flag-off.sglbk"                     # the same home, captured with the flag off
    assert "error" not in backup_home(src, w["flag_off"], flag=False, SIGIL_SPINE_ARCHIVE_DIR=None)
    foreign = signed_home(root, pruned=True, world=True, name="foreign")
    w["foreign_floor"] = (foreign / "floor.json").read_bytes()
    w["foreign_pub"] = (foreign / "spine" / "keys" / "owner.pub").read_bytes()
    w["foreign_priv"] = (foreign / "spine" / "keys" / "owner.priv").read_text().strip()
    crash = signed_home(root, pruned=False, world=True, name="crash")
    assert run_in_home(crash, CRASH_PRUNE, check=False, SIGIL_SPINE_ARCHIVE_DIR=None).returncode == 77
    w["crash_priv"] = (crash / "spine" / "keys" / "owner.priv").read_text().strip()
    w["crash"] = root / "crash.sglbk"                         # head commits the prune; the prefix is still on disk
    assert "error" not in backup_home(crash, w["crash"], flag=False, SIGIL_SPINE_ARCHIVE_DIR=None)
    w["pre_priv"] = (pre / "spine" / "keys" / "owner.priv").read_text().strip()
    w["unpruned"] = root / "unpruned.sglbk"
    assert "error" not in backup_home(pre, w["unpruned"], SIGIL_SPINE_ARCHIVE_DIR=None)
    rot = signed_home(root, pruned=True, world=True, name="rot")
    w["retired_pub"] = (rot / "spine" / "keys" / "owner.pub").read_bytes()
    run_in_home(rot, ROTATE, SIGIL_SPINE_ARCHIVE_DIR=None)
    w["rot_priv"] = (rot / "spine" / "keys" / "owner.priv").read_text().strip()
    w["rotated"] = root / "rotated.sglbk"
    assert "error" not in backup_home(rot, w["rotated"], SIGIL_SPINE_ARCHIVE_DIR=None)
    return w


def _rewrite(good: Path, dest: Path, priv: str, *, files=None, manifest=None, body=None) -> Path:
    """A copy of a backup with its body changed and its manifest RE-SIGNED by the owner key: a backup that is
    authentic but whose set is partial or mismatched. ``files`` maps rel -> bytes (None deletes)."""
    b = open_backup(good)
    m = b["manifest"]
    for rel, data in (files or {}).items():
        if data is None:
            b["files"].pop(rel, None)
            m["file_sha256"].pop(rel, None)
        else:
            b["files"][rel] = base64.b64encode(data).decode("ascii")
            m["file_sha256"][rel] = sha256_hex(data)
    if manifest:
        manifest(m)
    if body:
        body(b)
    b["manifest_sig"] = sign(priv, canonical_json(m))
    salt = os.urandom(backup._SALT_LEN)
    dest.write_bytes(backup._MAGIC + salt + seal(backup._derive_key(PW, salt), canonical_json(b),
                                                 context=backup._BODY_CONTEXT))
    return dest


def _restore(src: Path, new: Path, **kw) -> dict:
    return restore_backup(src, new, PW, vault=Vault(new.parent / (new.name + "-vault")), **kw)


@pytest.fixture
def flag(monkeypatch):
    monkeypatch.setenv("SIGIL_PRUNED_RESTORE", "1")
    monkeypatch.delenv("SIGIL_SPINE_ARCHIVE_DIR", raising=False)


# ---- the disaster-recovery case: a fresh host --------------------------------------------------------------------
@pytest.mark.parametrize("fold_cache", [False, True])
def test_a_fresh_host_restores_a_pruned_backup_and_its_readers_hold(world, tmp_path, fold_cache):
    """The restoring process's own SIGIL_HOME is an EMPTY dir (a new host): the pruned backup restores into it and
    the restored home reads exactly as the source did — kill switch engaged, the wallet grant pruned into the seed."""
    host = tmp_path / "new-host-home"
    host.mkdir()
    res = json.loads(run_in_home(host, RESTORE, json.dumps({"src": str(world["good"]), "home": str(host)}),
                                 SIGIL_PRUNED_RESTORE="1", SIGIL_SPINE_ARCHIVE_DIR=None).stdout.splitlines()[-1])
    assert "error" not in res and res["pruned"] is True and res["unit_verified"] is True, res
    seen = read_home(host, fold_cache=fold_cache)
    assert seen["verify_checkpoint"][0] is True, seen
    assert seen["verify_archive"][0] is True, seen
    assert seen["killswitch_engaged"] is True and seen["wallet_acme"] == 100, seen
    assert (host / "spine" / "keys" / "owner.priv").is_file() and (host / "sigil.env").exists() is False


def test_a_pruned_backup_restores_into_another_dir_from_any_process(world, tmp_path, flag):
    new = tmp_path / "restored"
    res = _restore(world["good"], new)
    assert res["verified"] is True and res["pruned"] is True and res["archive_dir"] == str(new / "spine" / "archive")
    seen = read_home(new)
    assert seen["verify_checkpoint"][0] and seen["verify_archive"][0] and seen["wallet_acme"] == 100, seen


def test_a_backup_whose_head_and_floor_are_broken_is_refused_by_the_restoring_home(world, tmp_path):
    """A backup of a pruned spine with a garbage head and no floor, restored by a process whose OWN head happens to
    corroborate that window, is refused — the staged unit is verified against its own members, never the
    restoring process's."""
    bad = _rewrite(world["flag_off"], tmp_path / "bad.sglbk", world["priv"],
                   files={"spine/head.json": b"{garbage", "floor.json": None})
    own = tmp_path / "own"
    shutil.copytree(world["src"], own)                       # the restoring process's home: the same spine, valid
    new = tmp_path / "restored"
    res = json.loads(run_in_home(own, RESTORE, json.dumps({"src": str(bad), "home": str(new)}),
                                 SIGIL_PRUNED_RESTORE="1", SIGIL_SPINE_ARCHIVE_DIR=None).stdout.splitlines()[-1])
    assert "error" in res and "head" in res["error"], res
    assert not (new / "spine").exists()


# ---- the flag ------------------------------------------------------------------------------------------------------
def _flag_off_backup(world, tmp_path, which) -> Path:
    if which == "no head":                     # only the segment manifest shows the prune
        return _rewrite(world["flag_off"], tmp_path / "nohead.sglbk", world["priv"], files={"spine/head.json": None})
    if which == "prune_unit only":             # only the signed prune_unit block declares one
        pu = open_backup(world["good"])["manifest"]["prune_unit"]
        return _rewrite(world["unpruned"], tmp_path / "pu.sglbk", world["pre_priv"],
                        manifest=lambda m: m.update(prune_unit=pu, schema=4))
    return world[which]


@pytest.mark.parametrize("which", ["good", "flag_off", "crash", "no head", "prune_unit only"])
def test_with_the_flag_off_a_pruned_backup_is_refused_before_anything_is_written(world, tmp_path, monkeypatch,
                                                                                  which):
    """Read from the signed file table before anything is staged: a prune_unit block, a head that commits a prune
    (also in a prune's crash window, where the live window still starts at genesis), or a live window that starts
    above seq 0."""
    monkeypatch.delenv("SIGIL_PRUNED_RESTORE", raising=False)
    bk = _flag_off_backup(world, tmp_path, which)
    monkeypatch.setattr(backup, "_new_staging_dir", lambda d: pytest.fail("staged before the flag was checked"))
    new = tmp_path / "restored"
    new.mkdir()
    (new / "keep.txt").write_text("existing")
    before, parent_before = _tree(new), sorted(p.name for p in tmp_path.iterdir())
    with pytest.raises(BackupError, match="SIGIL_PRUNED_RESTORE=1"):
        _restore(bk, new)
    assert _tree(new) == before and sorted(p.name for p in tmp_path.iterdir()) == parent_before


def test_a_crash_window_backup_restores_as_a_pruned_unit(world, tmp_path, flag):
    new = tmp_path / "restored"
    res = _restore(world["crash"], new)
    assert res["pruned"] is True and res["unit_verified"] is True
    seen = read_home(new)
    assert seen["verify_checkpoint"][0] and seen["verify_archive"][0] and seen["wallet_acme"] == 100, seen


def test_a_prune_unit_block_on_a_spine_that_is_not_pruned_is_refused(world, tmp_path, flag):
    bk = _flag_off_backup(world, tmp_path, "prune_unit only")
    new = tmp_path / "restored"
    with pytest.raises(BackupError, match="declares a hard-pruned spine"):
        _restore(bk, new)
    assert not (new / "spine").exists()


# ---- a partial or mismatched set is refused, the target untouched ------------------------------------------------
def _older_floor(world):
    return world["foreign_floor"]


SET = "not a complete, matching set: "
PARTIAL = {
    "no floor": (dict(files={"floor.json": None}), SET + "floor.json"),
    "no archive": (dict(files="drop-archive"), SET + "no archive manifest"),
    "no head": (dict(files={"spine/head.json": None}), "head.json) is missing"),
    "head from before the prune": (dict(files="pre-head"), "declares no prune"),
    "floor from another home": (dict(files="foreign-floor"), SET + "floor.json records neither"),
    "archived segment altered": (dict(files="alter-archive"), "sha256 mismatch"),
    "owner.pub of another key": (dict(files="foreign-pub"), "signed head"),
    "owner private key not the owner.pub's": (dict(body="foreign-priv"), "owner private key"),
    "prune_unit disagrees": (dict(manifest="pu-head"), "prune_unit disagrees"),
    "prune_unit archive disagrees": (dict(manifest="pu-archive"), "archive.segments"),
}


def _partial_backup(world, tmp_path, how) -> Path:
    good, priv = world["good"], world["priv"]
    files = how.get("files")
    if files == "drop-archive":
        files = {r: None for r in open_backup(good)["files"] if r.startswith("spine/archive/")}
    elif files == "pre-head":
        files = {"spine/head.json": world["pre_head"]}
    elif files == "foreign-floor":
        files = {"floor.json": world["foreign_floor"]}
    elif files == "alter-archive":
        rel = sorted(r for r in open_backup(good)["files"] if r.startswith("spine/archive/segments/"))[0]
        raw = bytearray(base64.b64decode(open_backup(good)["files"][rel]))
        raw[len(raw) // 2] ^= 0x01
        files = {rel: bytes(raw)}
    elif files == "foreign-pub":
        files = {"spine/keys/owner.pub": world["foreign_pub"]}
    body = manifest = None
    if how.get("body") == "foreign-priv":
        def body(b):
            b["owner_priv_b64"] = world["foreign_priv"]
    if how.get("manifest") == "pu-head":
        def manifest(m):
            m["prune_unit"]["head_sig_hash"] = "0" * 64
    elif how.get("manifest") == "pu-archive":
        def manifest(m):
            m["prune_unit"]["archive"]["segments"] = 7
    return _rewrite(good, tmp_path / "partial.sglbk", priv, files=files, manifest=manifest, body=body)


@pytest.mark.parametrize("case", sorted(PARTIAL))
def test_a_partial_or_mismatched_set_is_refused_with_the_target_untouched(world, tmp_path, flag, case):
    how, phrase = PARTIAL[case]
    bk = _partial_backup(world, tmp_path, how)
    new = tmp_path / "restored"
    new.mkdir()
    (new / "keep.txt").write_text("existing")
    before = _tree(new)
    with pytest.raises(BackupError) as ei:
        _restore(bk, new, force=True)
    assert phrase in str(ei.value), str(ei.value)
    assert _tree(new) == before
    assert not [p for p in tmp_path.iterdir() if p.name.startswith((".restore-staging-", ".restore-verify-"))]


def test_a_restored_key_that_is_not_the_succession_tip_is_refused(world, tmp_path, flag):
    """A rotated home's backup whose key files were swapped back to the retired pair: the staged unit's owner key is
    not the validated succession tip, so it could never re-anchor its pruned head."""
    bk = _rewrite(world["rotated"], tmp_path / "retired.sglbk", world["rot_priv"],
                  files={"spine/keys/owner.pub": world["retired_pub"]}, body=lambda b: b.pop("owner_priv_b64"))
    new = tmp_path / "restored"
    with pytest.raises(BackupError, match="succession tip"):
        _restore(bk, new)
    assert not (new / "spine").exists()
    assert _restore(world["rotated"], tmp_path / "ok")["verified"] is True


# ---- held-back members ---------------------------------------------------------------------------------------------
def test_private_keys_and_sigil_env_are_held_back_until_the_unit_verifies(world, tmp_path, flag, monkeypatch):
    bk = _rewrite(world["good"], tmp_path / "env.sglbk", world["priv"],
                  files={"sigil.env": b"SIGIL_SPINE_ARCHIVE_DIR=/nowhere\n"})
    import sigil.spine.home_unit as hu
    seen = {}
    real = hu.verify_unit_isolated

    def spy(unit, **kw):
        seen["keys"] = sorted(p.name for p in unit.keys_dir.iterdir())
        seen["env"] = (unit.home / "sigil.env").exists()
        seen["sealed"] = (unit.home / "secrets.sealed").exists()
        return real(unit, **kw)
    monkeypatch.setattr(hu, "verify_unit_isolated", spy)
    new = tmp_path / "restored"
    res = _restore(bk, new)
    assert res["verified"] is True
    assert seen == {"keys": ["owner.pub"], "env": False, "sealed": False}, seen
    assert (new / "spine" / "keys" / "owner.priv").is_file()
    assert (new / "sigil.env").read_text().startswith("SIGIL_SPINE_ARCHIVE_DIR")
    assert (new / "sigil.env").stat().st_mode & 0o777 == 0o600


def test_a_restored_sigil_env_naming_another_archive_dir_is_reported(world, tmp_path, flag):
    """The restored home's services read their archive dir from its sigil.env: when that names another dir than the
    one this restore placed the archive in (a source home whose archive was relocated), the restore says so and names
    the fix."""
    src_arch = tmp_path / "source-ebs" / "archive"
    bk = _rewrite(world["good"], tmp_path / "env.sglbk", world["priv"],
                  files={"sigil.env": f"# relocated\nSIGIL_SPINE_ARCHIVE_DIR={src_arch}\nX=1\n".encode()})
    res = _restore(bk, tmp_path / "default-placed")
    assert res["archive_env"] == str(src_arch) and res["archive_env_mismatch"] is True, res
    res = _restore(bk, tmp_path / "placed-there", archive_dir=src_arch)
    assert res["archive_env"] == str(src_arch) and res["archive_env_mismatch"] is False, res
    assert _restore(world["good"], tmp_path / "no-env")["archive_env_mismatch"] is False
    cli = run_in_home(tmp_path, "import sys\nfrom sigil.cli import main\nmain(sys.argv[1:])\n", "restore", str(bk),
                      str(tmp_path / "via-cli"), check=False, SIGIL_PRUNED_RESTORE="1", SIGIL_SPINE_ARCHIVE_DIR=None,
                      SIGIL_BACKUP_PASSPHRASE=PW)
    assert cli.returncode == 0, cli.stderr
    assert (f"sets SIGIL_SPINE_ARCHIVE_DIR={src_arch}" in cli.stdout
            and f"SIGIL_SPINE_ARCHIVE_DIR={tmp_path / 'via-cli' / 'spine' / 'archive'}" in cli.stdout), cli.stdout


# ---- archive placement ------------------------------------------------------------------------------------------------
def test_the_archive_lands_in_the_given_dir_and_never_where_the_environment_points(world, tmp_path, flag,
                                                                                   monkeypatch):
    sentinel = tmp_path / "live-archive"
    sentinel.mkdir()
    (sentinel / "marker").write_text("the live archive of this process's own home")
    monkeypatch.setenv("SIGIL_SPINE_ARCHIVE_DIR", str(sentinel))
    sent_before = _tree(sentinel)
    new, arch = tmp_path / "restored", tmp_path / "ebs" / "archive"
    res = _restore(world["good"], new, archive_dir=arch)
    assert res["verified"] is True and res["archive_dir"] == str(arch)
    assert (arch / "archive.manifest.json").is_file() and not (new / "spine" / "archive").exists()
    assert _tree(sentinel) == sent_before
    assert not [p for p in arch.parent.iterdir() if p.name.startswith(".restore-")]
    seen = read_home(new, archive_dir=arch)
    assert seen["verify_archive"][0] is True and seen["wallet_acme"] == 100, seen
    # with no --archive-dir the archive travels inside the spine unit, whatever the environment says
    res = _restore(world["good"], tmp_path / "plain")
    assert (tmp_path / "plain" / "spine" / "archive" / "archive.manifest.json").is_file()
    assert _tree(sentinel) == sent_before


@pytest.mark.parametrize("where", ["home", "inside-home", "spine-dir", "captured-unit", "process-home",
                                   "process-archive"])
def test_an_archive_dir_overlapping_another_unit_or_this_home_is_refused(world, tmp_path, flag, monkeypatch, where):
    import sigil.config as cfg
    live = tmp_path / "live-archive"
    monkeypatch.setenv("SIGIL_SPINE_ARCHIVE_DIR", str(live))
    new = tmp_path / "restored"
    target = {"home": new, "inside-home": tmp_path, "spine-dir": new / "spine", "captured-unit": new / "warden" / "arch",
              "process-home": cfg.SIGIL_HOME / "arch", "process-archive": live}[where]
    if where == "captured-unit":
        bk = _rewrite(world["good"], tmp_path / "w.sglbk", world["priv"], files={"warden/tools.json": b"{}"})
    else:
        bk = world["good"]
    phrase = {"home": "the restored home", "inside-home": "the restored home", "spine-dir": "the restored spine dir",
              "captured-unit": "restored unit", "process-home": "own SIGIL_HOME",
              "process-archive": "archive dir this process's own home uses"}[where]
    with pytest.raises(BackupError, match="refusing the archive dir") as ei:
        _restore(bk, new, archive_dir=target)
    assert phrase in str(ei.value), str(ei.value)
    assert not (new / "spine").exists()


def test_a_unit_that_cannot_be_searched_for_mount_points_is_refused(world, tmp_path, flag, monkeypatch):
    """Whether an entry the swap replaces holds a mount point is read off the whole of it: a dir inside it that cannot
    be listed refuses the restore (and `--verify-only`) before anything is written."""
    home = tmp_path / "home"
    _restore(world["good"], home)
    before = _tree(tmp_path)
    real = os.scandir
    unreadable = str(home / "spine" / "keys")

    def scandir(p=".", *a, **kw):
        if not isinstance(p, int) and os.fspath(p) == unreadable:
            raise PermissionError(13, "Permission denied", unreadable)
        return real(p, *a, **kw)
    monkeypatch.setattr(os, "scandir", scandir)
    for verify_only in (True, False):
        with pytest.raises(BackupError, match="cannot check that the restore's renames"):
            restore_backup(world["good"], home, PW, vault=None if verify_only else Vault(tmp_path / "vault"),
                           force=True, verify_only=verify_only)
    monkeypatch.undo()
    assert _tree(tmp_path) == before


def _on_another_filesystem(monkeypatch, path: Path) -> None:
    """``path`` reads as a mount point to os.stat: its device is another than its parent's (a home that is a mount
    point has its restore staging beside it, on the parent's filesystem)."""
    real = os.stat

    def stat(p, *a, **kw):
        st = real(p, *a, **kw)
        if os.fspath(p) == str(path):
            st = os.stat_result((*tuple(st)[:2], st.st_dev + 1, *tuple(st)[3:10]))
        return st
    monkeypatch.setattr(os, "stat", stat)


@pytest.mark.parametrize("which,pruned_restore", [("good", "1"), ("unpruned", "1"), ("unpruned", None)])
def test_a_home_on_another_filesystem_than_its_parent_is_refused_before_anything_is_written(world, tmp_path, flag,
                                                                                            monkeypatch, which,
                                                                                            pruned_restore):
    """A home that is a mount point (its parent on another filesystem): no rename can move a unit into it from the
    staging dir beside it. The restore — and `--verify-only` into it — refuses before anything is written: no journal,
    no unit touched, no staging left; the home is its old self and signs. Whether the backup is pruned or not, and
    whether SIGIL_PRUNED_RESTORE is on or off."""
    if pruned_restore is None:
        monkeypatch.delenv("SIGIL_PRUNED_RESTORE")
    home = tmp_path / "home"
    _restore(world[which], home)
    before = _tree(home)
    _on_another_filesystem(monkeypatch, home)
    for verify_only in (True, False):
        with pytest.raises(BackupError, match="not on the filesystem of the restore's staging dir"):
            restore_backup(world[which], home, PW, vault=None if verify_only else Vault(tmp_path / "vault"),
                           force=True, verify_only=verify_only)
    assert _tree(home) == before
    assert not [p for p in tmp_path.iterdir() if p.name.startswith(".restore-")]
    monkeypatch.undo()
    r = run_in_home(home, "import sys\nfrom sigil.cli import main\nmain(sys.argv[1:])\n", "sign", check=False,
                    SIGIL_PRUNED_RESTORE="1", SIGIL_SPINE_ARCHIVE_DIR=None)
    assert r.returncode == 0, (r.returncode, r.stderr)


@pytest.mark.parametrize("where", ["the archive dir", "the archive inside the spine"])
def test_an_entry_the_swap_replaces_that_is_or_holds_a_mount_point_is_refused(world, tmp_path, flag, monkeypatch,
                                                                             where):
    """A restore renames whole units aside and drops them: one whose archive dir is a mount point, or whose old spine
    holds one (an archive volume mounted inside it), is refused — `--verify-only` too — before anything is written."""
    home = tmp_path / "home"
    if where == "the archive dir":
        arch = tmp_path / "vol" / "archive"
        shutil.copytree(world["src"] / "spine" / "archive", arch)
        mount, archive_dir = arch, arch
    else:
        _restore(world["good"], home)
        mount, archive_dir = home / "spine" / "archive", None
    before = _tree(tmp_path)
    real = os.path.ismount
    monkeypatch.setattr(os.path, "ismount", lambda p: os.fspath(p) == str(mount) or real(p))
    for verify_only in (True, False):
        with pytest.raises(BackupError, match=re.escape(f"{mount} is a mount point")):
            restore_backup(world["good"], home, PW, vault=None if verify_only else Vault(tmp_path / "vault"),
                           force=True, archive_dir=archive_dir, verify_only=verify_only)
    assert _tree(tmp_path) == before


def test_adopt_an_existing_archive_for_a_backup_that_carries_none(world, tmp_path, flag):
    """A backup taken before the archive was captured (relocated archive, flag off at backup time): restoring it
    against the archive already at --archive-dir adopts that archive only if it verifies against the staged head."""
    no_arch = _rewrite(world["flag_off"], tmp_path / "noarch.sglbk", world["priv"],
                       files={r: None for r in open_backup(world["flag_off"])["files"] if r.startswith("spine/archive/")})
    arch = tmp_path / "ebs" / "archive"
    shutil.copytree(world["src"] / "spine" / "archive", arch)
    arch_before = _tree(arch)
    with pytest.raises(BackupError, match="--archive-dir"):
        _restore(no_arch, tmp_path / "r0")                                 # nowhere to find the archive
    res = _restore(no_arch, tmp_path / "r1", archive_dir=arch)
    assert res["verified"] is True and res["archive_mode"] == "adopt"
    assert _tree(arch) == arch_before                                      # adopted in place, never replaced
    seg = sorted((arch / "segments").iterdir())[0]
    raw = bytearray(seg.read_bytes())
    raw[len(raw) // 2] ^= 0x01
    seg.write_bytes(bytes(raw))
    with pytest.raises(BackupError, match="does not verify"):
        _restore(no_arch, tmp_path / "r2", archive_dir=arch)
    assert not (tmp_path / "r2" / "spine").exists()


def test_an_existing_archive_at_the_target_needs_force(world, tmp_path, flag):
    arch = tmp_path / "ebs" / "archive"
    shutil.copytree(world["src"] / "spine" / "archive", arch)              # an archive already there
    (arch / "old").write_text("old archive")
    with pytest.raises(BackupError, match="existing archive"):
        _restore(world["good"], tmp_path / "r", archive_dir=arch)
    assert (arch / "old").read_text() == "old archive"
    res = _restore(world["good"], tmp_path / "r2", archive_dir=arch, force=True)
    assert res["verified"] is True and not (arch / "old").exists() and (arch / "archive.manifest.json").is_file()


def test_an_archive_dir_holding_something_else_is_never_replaced(world, tmp_path, flag):
    """``--force`` replaces an archive (or an empty dir) at --archive-dir with the backup's — never a dir that holds
    something else."""
    other = tmp_path / "ebs" / "data"
    other.mkdir(parents=True)
    (other / "settlement.json").write_text("live state")
    before = _tree(other)
    with pytest.raises(BackupError, match="holds no archive"):
        _restore(world["good"], tmp_path / "r", archive_dir=other, force=True)
    assert _tree(other) == before and not (tmp_path / "r" / "spine").exists()
    empty = tmp_path / "ebs" / "empty"
    empty.mkdir()
    res = _restore(world["good"], tmp_path / "r2", archive_dir=empty, force=True)
    assert res["verified"] is True and (empty / "archive.manifest.json").is_file()


@pytest.mark.parametrize("entry", ["credit-lease", "vault"])
def test_an_archive_dir_on_live_home_state_the_backup_does_not_capture_is_refused(world, tmp_path, flag, entry):
    """An archive dir inside the restored home goes under its spine: one on an entry the backup does not capture
    (the cross-plane seam, the vault) is refused, even with --force, and that entry is left as it was."""
    new = tmp_path / "restored"
    _restore(world["good"], new)
    live = new / entry
    live.mkdir()
    (live / "archive.manifest.json").write_text("{}")                     # even one that looks like an archive
    (live / "marker").write_text("live")
    before = _tree(new)
    with pytest.raises(BackupError, match="does not capture"):
        _restore(world["good"], new, archive_dir=live, force=True)
    assert _tree(new) == before


# ---- verify-only -------------------------------------------------------------------------------------------------------
def test_verify_only_checks_the_unit_and_swaps_nothing(world, tmp_path, flag):
    new = tmp_path / "restored"
    res = restore_backup(world["good"], new, PW, vault=None, verify_only=True)
    assert res["verified"] is True and res["swapped"] is False and res["pruned"] is True
    assert not new.exists()
    assert not [p for p in tmp_path.iterdir() if p.name.startswith(".restore-")]
    bad = _partial_backup(world, tmp_path, PARTIAL["no floor"][0])
    with pytest.raises(BackupError, match="floor.json"):
        restore_backup(bad, None, PW, vault=None, verify_only=True)


def test_verify_only_into_a_home_refuses_what_the_restore_into_it_would(world, tmp_path, flag):
    """`--verify-only SRC HOME` (what `vigil restore` runs before the offense leg) refuses exactly what the restore into
    HOME with the same --force would: existing units, an interrupted restore, an existing archive dir, a dir that holds
    no archive. It writes nothing either way."""
    home = tmp_path / "home"
    _restore(world["good"], home)
    before = _tree(home)

    def vo(target, **kw):
        return restore_backup(world["good"], target, PW, vault=None, verify_only=True, **kw)
    with pytest.raises(BackupError, match="refusing to overwrite existing SIGIL state"):
        vo(home)
    assert vo(home, force=True)["swapped"] is False
    assert _tree(home) == before
    cli = run_in_home(tmp_path, "import sys\nfrom sigil.cli import main\nmain(sys.argv[1:])\n", "restore",
                      "--verify-only", str(world["good"]), str(home), check=False, SIGIL_PRUNED_RESTORE="1",
                      SIGIL_SPINE_ARCHIVE_DIR=None, SIGIL_BACKUP_PASSPHRASE=PW)
    assert cli.returncode == 1 and "refusing to overwrite existing SIGIL state" in cli.stderr, cli.stderr
    interrupted = tmp_path / "interrupted"
    interrupted.mkdir()
    (interrupted / "restore-journal.json").write_text("{}")
    with pytest.raises(BackupError, match="was interrupted"):
        vo(interrupted)
    fresh, ext = tmp_path / "fresh", tmp_path / "ext" / "archive"
    shutil.copytree(world["src"] / "spine" / "archive", ext)
    with pytest.raises(BackupError, match="existing archive"):
        vo(fresh, archive_dir=ext)
    assert vo(fresh, archive_dir=ext, force=True)["archive_mode"] == "relocated"
    other = tmp_path / "ext" / "data"
    other.mkdir()
    (other / "keep").write_text("live")
    with pytest.raises(BackupError, match="holds no archive"):
        vo(fresh, archive_dir=other, force=True)
    assert not fresh.exists() and (other / "keep").read_text() == "live"
    assert not [p for p in tmp_path.iterdir() if p.name.startswith(".restore-")]


def test_an_archive_dir_inside_the_spine_travels_with_the_spine_unit(world, tmp_path, flag):
    new = tmp_path / "restored"
    res = _restore(world["good"], new, archive_dir=new / "spine" / "cold")
    assert res["archive_mode"] == "in-spine"
    assert (new / "spine" / "cold" / "archive.manifest.json").is_file() and not (new / "spine" / "archive").exists()
    assert read_home(new, archive_dir=new / "spine" / "cold")["verify_archive"][0] is True


def test_the_swap_waits_for_the_floor_lock(world, tmp_path, flag):
    """A restore swaps under the target's floor lock (the lock a signer takes to write the head and the floor): while
    another holder has it, the verified restore waits — nothing is journaled or swapped — and goes ahead once it is
    released."""
    import fcntl
    import threading
    import time
    new = tmp_path / "restored"
    _restore(world["good"], new)

    def state() -> dict:
        return {k: v for k, v in _tree(new).items() if not k.endswith(".lock")}
    before = state()
    fd = os.open(str(new / "floor.json.lock"), os.O_RDWR | os.O_CREAT, 0o600)
    fcntl.flock(fd, fcntl.LOCK_EX)
    out: dict = {}
    t = threading.Thread(target=lambda: out.update(res=_restore(world["good"], new, force=True)), daemon=True)
    try:
        t.start()
        deadline = time.monotonic() + 120
        while not list(tmp_path.glob(".restore-staging-*/spine/keys/owner.priv")) and time.monotonic() < deadline:
            time.sleep(0.05)                                   # verified and re-sealed: next is the locked swap
        assert list(tmp_path.glob(".restore-staging-*/spine/keys/owner.priv")), "the restore never got to its swap"
        time.sleep(2)
        assert t.is_alive() and "res" not in out
        assert state() == before                               # nothing journaled, nothing swapped
    finally:
        os.close(fd)
    t.join(120)
    assert not t.is_alive() and out["res"]["verified"] is True
    assert not list(tmp_path.glob(".restore-*"))


def test_a_spine_being_written_is_not_restored_over(world, tmp_path, flag):
    """Restoring onto a home whose spine writer lock is held (the services are running) is refused."""
    import fcntl
    new = tmp_path / "restored"
    _restore(world["good"], new)
    (new / "spine" / "spine.lock").touch()                  # a writer's lockfile (writers create it on append)
    before = _tree(new)
    fd = os.open(str(new / "spine" / "spine.lock"), os.O_RDONLY)
    try:
        fcntl.flock(fd, fcntl.LOCK_SH)
        with pytest.raises(BackupError, match="stop the sigil services"):
            _restore(world["good"], new, force=True)
    finally:
        os.close(fd)
    assert _tree(new) == before
    assert _restore(world["good"], new, force=True)["verified"] is True
