"""A restore that swaps a HARD-PRUNED unit in — and any restore that replaces a unit the home already holds — is
journaled: the journal is durable before the first swap, every unit is marked done after it lands, and the journal
goes only after the last. A restore killed at any point between leaves
a home that fails closed (signed-head verification and signing refuse, the CLI refuses everything but `sigil restore`
and `sigil doctor`) until `sigil restore --resume` completes it — or, before any unit is in, `--abort` discards it.

Every restore here runs in a child process killed (``os._exit``) at a barrier of ``backup._crash_hook``; the target is
read back in a child whose SIGIL_HOME is that home.

Run: SIGIL_HOME=$(mktemp -d) python -m pytest tests/test_restore_pruned_crash.py
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
from pathlib import Path

import pytest

from sigil.spine.consistent_copy import unit_digest
from tests._real_home import backup_home, read_home, run_in_home, signed_home  # type: ignore

KILLED = 77

RESTORE_KILLED = """
import json, os, sys
from pathlib import Path
from sigil import backup
from vigil_core.vault import Vault
a = json.loads(sys.argv[1])
def hook(name):
    if name == a["barrier"]:
        os._exit(77)
backup._crash_hook = hook
home = Path(a["home"])
kw = {"archive_dir": a["archive_dir"]} if a.get("archive_dir") else {}
res = backup.restore_backup(a["src"], home, "pw-test-only", vault=Vault(home / "vault"), force=True, **kw)
print(json.dumps(res, default=str))
"""

CLI = "import sys\nfrom sigil.cli import main\nmain(sys.argv[1:])\n"

SIGN_IN_PROCESS = """
import json
from sigil.spine import checkpoint as cp
from sigil.spine.store import SpineStore
try:
    cp.checkpoint(SpineStore())
    print(json.dumps({"signed": True}))
except cp.CheckpointRefused as e:
    print(json.dumps({"refused": str(e)}))
"""


@pytest.fixture(scope="module")
def world(tmp_path_factory):
    root = tmp_path_factory.mktemp("crash")
    src = signed_home(root, pruned=True, world=True, name="src")
    bk = root / "bk.sglbk"
    assert "error" not in backup_home(src, bk, SIGIL_SPINE_ARCHIVE_DIR=None)
    old = signed_home(root, pruned=True, name="old")                # the target's OLD home: another pruned home
    plain = signed_home(root, pruned=False, world=True, name="plain")  # a home that was never pruned
    bk_plain = root / "plain.sglbk"
    assert "error" not in backup_home(plain, bk_plain, SIGIL_SPINE_ARCHIVE_DIR=None)
    # a pruned home that also holds budget caps and model meters (money data), and an OLD home that holds its own
    metered = signed_home(root, pruned=True, world=True, name="metered")
    (metered / "budgets.json").write_text('{"caps": "at backup time"}')
    (metered / "model_meter").mkdir()
    (metered / "model_meter" / "run-1.jsonl").write_text('{"meter": "at backup time"}\n')
    bk_metered = root / "metered.sglbk"
    assert "error" not in backup_home(metered, bk_metered, SIGIL_SPINE_ARCHIVE_DIR=None)
    old_metered = root / "old-metered"
    shutil.copytree(old, old_metered)
    (old_metered / "budgets.json").write_text('{"caps": "old home"}')
    (old_metered / "model_meter").mkdir()
    (old_metered / "model_meter" / "run-1.jsonl").write_text('{"meter": "old home"}\n')
    old_plain = signed_home(root, pruned=False, name="old-plain")    # an OLD home that was never pruned either
    return {"bk": bk, "old": old, "plain": plain, "bk_plain": bk_plain, "bk_metered": bk_metered,
            "old_metered": old_metered, "old_plain": old_plain}


def _tree(root: Path) -> dict:
    """The home's content (read sidecars, lockfiles and the install manifest any `sigil` command writes excluded)."""
    return {str(p.relative_to(root)): (hashlib.sha256(p.read_bytes()).hexdigest() if p.is_file() else "dir")
            for p in sorted(root.rglob("*"))
            if not p.name.endswith((".idx", ".lock")) and p.name != "install-manifest.json"}


def _target(world, tmp_path) -> Path:
    t = tmp_path / "target"
    shutil.copytree(world["old"], t)
    return t


def _kill_at(world, target: Path, barrier: str, archive_dir: "Path | None" = None, backup: str = "bk"):
    host = target.parent / "restoring-host"
    host.mkdir(exist_ok=True)
    r = run_in_home(host, RESTORE_KILLED, json.dumps({"src": str(world[backup]), "home": str(target),
                                                      "barrier": barrier,
                                                      "archive_dir": str(archive_dir) if archive_dir else None}),
                    check=False, SIGIL_PRUNED_RESTORE="1", SIGIL_SPINE_ARCHIVE_DIR=None)
    return r


def _cli(home: Path, *args: str):
    return run_in_home(home, CLI, *args, check=False, SIGIL_PRUNED_RESTORE="1", SIGIL_SPINE_ARCHIVE_DIR=None)


def _assert_fails_closed(target: Path) -> None:
    seen = read_home(target)
    assert seen["verify_checkpoint"][0] is False and "sigil restore --resume" in seen["verify_checkpoint"][1], seen
    assert seen["verify_archive"][0] is False, seen
    r = _cli(target, "sign")
    assert r.returncode == 3 and "sigil restore --resume" in r.stderr, (r.returncode, r.stderr)
    r = _cli(target, "verify")
    assert r.returncode == 3, (r.returncode, r.stderr)
    signed = json.loads(run_in_home(target, SIGN_IN_PROCESS, SIGIL_SPINE_ARCHIVE_DIR=None).stdout.splitlines()[-1])
    assert "refused" in signed and "interrupted" in signed["refused"], signed


def _assert_restored(target: Path, archive_dir: "Path | None" = None) -> None:
    assert not (target / "restore-journal.json").exists()
    assert not [p for p in target.parent.iterdir() if p.name.startswith(".restore-")]
    assert not [p for p in target.iterdir() if p.name.startswith(".restore-old-")]
    if archive_dir is not None:
        assert not [p for p in archive_dir.parent.iterdir() if p.name.startswith(".restore-")]
    for fold_cache in (False, True):
        seen = read_home(target, fold_cache=fold_cache, archive_dir=archive_dir)
        assert seen["verify_checkpoint"][0] and seen["verify_archive"][0], seen
        assert seen["killswitch_engaged"] is True and seen["wallet_acme"] == 100, seen


# Every barrier of the journaled swap, in order: the journal is durable; the spine unit is marked started (nothing
# moved yet); its old copy is moved aside; the new copy is renamed in (not yet marked); it is marked done (its old
# copy not yet dropped); the floor is marked done; every unit is certified, the journal not yet deleted.
BARRIERS = ["restore_after_journal", "restore_unit_started:spine", "restore_moved_aside:spine",
            "restore_swapped_in:spine", "restore_after_unit:spine", "restore_after_unit:floor.json",
            "restore_before_journal_delete"]
# The barriers at which the spine unit's swap has begun: abort must refuse there.
TOUCHED = ["restore_unit_started:spine", "restore_moved_aside:spine", "restore_swapped_in:spine",
           "restore_after_unit:spine"]


@pytest.mark.parametrize("barrier", BARRIERS)
def test_a_restore_killed_at_any_barrier_fails_closed_and_resumes(world, tmp_path, barrier):
    target = _target(world, tmp_path)
    r = _kill_at(world, target, barrier)
    assert r.returncode == KILLED, (r.returncode, r.stderr[-800:])
    assert (target / "restore-journal.json").is_file()
    if barrier == "restore_moved_aside:spine":
        assert not (target / "spine").exists() and (target / ".restore-old-spine").is_dir()
    _assert_fails_closed(target)
    assert not (target / "spine" / "keys" / "owner.priv").exists() or barrier != "restore_moved_aside:spine"
    r = _cli(target, "doctor")
    assert r.returncode != 3                                          # doctor is never gated by the journal
    r = _cli(target, "restore", "--resume", str(target))
    assert r.returncode == 0 and "completed" in r.stdout, (r.returncode, r.stdout, r.stderr)
    _assert_restored(target)


def test_a_restore_that_was_not_killed_leaves_no_journal(world, tmp_path):
    target = _target(world, tmp_path)
    r = _kill_at(world, target, "never")
    assert r.returncode == 0, r.stderr[-800:]
    _assert_restored(target)


def test_abort_before_any_unit_is_in_leaves_the_old_home(world, tmp_path):
    target = _target(world, tmp_path)
    before = _tree(target)
    assert _kill_at(world, target, "restore_after_journal").returncode == KILLED
    r = _cli(target, "restore", "--abort", str(target))
    assert r.returncode == 0 and "discarded" in r.stdout, r.stderr
    assert _tree(target) == before
    assert not [p for p in target.parent.iterdir() if p.name.startswith(".restore-")]
    assert read_home(target)["verify_checkpoint"][0] is True


# `sigil restore --abort` killed at a barrier, or while it removes the staging (part of it already gone).
ABORT_KILLED = """
import os, shutil, sys
from pathlib import Path
from sigil import backup
barrier = sys.argv[1]
def hook(name):
    if name == barrier:
        os._exit(77)
backup._crash_hook = hook
real = shutil.rmtree
def rmtree(p, *k, **kw):
    if barrier == "mid-drop" and ".restore-staging-" in str(p):
        real(Path(p) / "spine", ignore_errors=True)
        os._exit(77)
    return real(p, *k, **kw)
shutil.rmtree = rmtree
from sigil.cli import main
main(sys.argv[2:])
"""


@pytest.mark.parametrize("killed,then", [("restore_abort_marked", "abort again"), ("mid-drop", "abort again"),
                                         ("mid-drop", "replace and abort")])
def test_an_interrupted_abort_is_finished_by_running_it_again(world, tmp_path, killed, then):
    """An abort that found the home untouched marks the journal before it drops anything: killed after that (even with
    part of the staging already gone) the home is still its old self and stays fail-closed, `--resume` refuses and
    names `--abort`, and running the abort again — or aborting a --force restore that replaced it — finishes it,
    leaving the old home and no staging behind."""
    target = _target(world, tmp_path)
    before = _tree(target)
    assert _kill_at(world, target, "restore_after_journal").returncode == KILLED
    r = run_in_home(target, ABORT_KILLED, killed, "restore", "--abort", str(target), check=False,
                    SIGIL_PRUNED_RESTORE="1", SIGIL_SPINE_ARCHIVE_DIR=None)
    assert r.returncode == KILLED, (r.returncode, r.stderr[-800:])
    assert (target / "restore-journal.json").is_file()
    assert {k: v for k, v in _tree(target).items() if k != "restore-journal.json"} == before
    r = _cli(target, "restore", "--resume", str(target))
    assert r.returncode == 1 and "itself interrupted" in r.stderr and "--abort" in r.stderr, r.stderr
    _assert_fails_closed(target)
    if then == "replace and abort":
        assert _kill_at(world, target, "restore_after_journal", backup="bk_plain").returncode == KILLED
        assert json.loads((target / "restore-journal.json").read_text())["replaced"]["touched"] == []
    r = _cli(target, "restore", "--abort", str(target))
    assert r.returncode == 0 and "discarded" in r.stdout, r.stderr
    assert _tree(target) == before
    assert not [p for p in tmp_path.iterdir() if p.name.startswith(".restore-")]
    assert read_home(target)["verify_checkpoint"][0] is True


@pytest.mark.parametrize("barrier", TOUCHED)
def test_abort_is_refused_once_a_unit_swap_has_begun_and_resume_completes_it(world, tmp_path, barrier):
    """Killed while the spine unit was being swapped in — marked started, its old copy moved aside, the new copy
    renamed in before it was marked done, or marked done before its old copy was dropped: `--abort` refuses and
    deletes nothing (the journal, the staging and the old copy stay), the home stays fail-closed, and `--resume`
    makes it entirely the backup's."""
    target = _target(world, tmp_path)
    old_head = (target / "spine" / "head.json").read_bytes()
    assert _kill_at(world, target, barrier).returncode == KILLED
    before = _tree(tmp_path)          # the target, its staging and the old copy aside
    r = _cli(target, "restore", "--abort", str(target))
    assert r.returncode == 1 and "--resume" in r.stderr and "nothing was discarded" in r.stderr, r.stderr
    assert _tree(tmp_path) == before
    if barrier in ("restore_moved_aside:spine", "restore_swapped_in:spine", "restore_after_unit:spine"):
        assert (target / ".restore-old-spine" / "head.json").read_bytes() == old_head      # the old unit is kept
    _assert_fails_closed(target)
    r = _cli(target, "restore", "--resume", str(target))
    assert r.returncode == 0 and "completed" in r.stdout, (r.returncode, r.stdout, r.stderr)
    _assert_restored(target)


@pytest.mark.parametrize("evidence", ["old copy moved aside", "staged copy gone"])
def test_abort_reads_the_swap_off_the_disk_even_when_the_journal_marks_nothing(world, tmp_path, evidence):
    """Abort trusts the journal's marks only to refuse: an old copy moved aside beside a destination, or a staged
    copy that has left the staging, is a swap that began, whatever the marks say."""
    target = _target(world, tmp_path)
    barrier = "restore_moved_aside:spine" if evidence == "old copy moved aside" else "restore_swapped_in:spine"
    assert _kill_at(world, target, barrier).returncode == KILLED
    jp = target / "restore-journal.json"
    j = json.loads(jp.read_text())
    for u in j["units"]:
        u["started"] = u["done"] = False
    jp.write_text(json.dumps(j))
    if evidence == "staged copy gone":
        shutil.rmtree(target / ".restore-old-spine")              # only the staging shows the swap now
    r = _cli(target, "restore", "--abort", str(target))
    assert r.returncode == 1 and "had begun swapping ['spine']" in r.stderr, r.stderr
    assert jp.is_file()


def test_abort_is_refused_while_a_relocated_archive_is_swapped_and_the_old_archive_is_kept(world, tmp_path):
    """The relocated archive unit is swapped first: killed after the target's existing archive was moved aside,
    abort refuses and the old archive stays on disk; resume completes the restore."""
    target = _target(world, tmp_path)
    arch = tmp_path / "ebs" / "archive"
    shutil.copytree(world["old"] / "spine" / "archive", arch)              # the archive already at --archive-dir
    old_manifest = (arch / "archive.manifest.json").read_bytes()
    assert _kill_at(world, target, "restore_moved_aside:archive", archive_dir=arch).returncode == KILLED
    assert not arch.exists()
    r = _cli(target, "restore", "--abort", str(target))
    assert r.returncode == 1 and "had begun swapping ['archive']" in r.stderr, r.stderr
    assert (arch.parent / ".restore-old-archive" / "archive.manifest.json").read_bytes() == old_manifest
    _assert_fails_closed(target)
    r = _cli(target, "restore", "--resume", str(target))
    assert r.returncode == 0 and "completed" in r.stdout, (r.returncode, r.stdout, r.stderr)
    _assert_restored(target, archive_dir=arch)


def test_abort_is_refused_once_a_unit_is_in(world, tmp_path):
    target = _target(world, tmp_path)
    assert _kill_at(world, target, "restore_after_unit:floor.json").returncode == KILLED
    r = _cli(target, "restore", "--abort", str(target))
    assert r.returncode == 1 and "--resume" in r.stderr
    assert (target / "restore-journal.json").is_file()
    assert _cli(target, "restore", "--resume", str(target)).returncode == 0
    _assert_restored(target)


def _staging(target: Path) -> Path:
    j = json.loads((target / "restore-journal.json").read_text())
    return Path(j["staging"])


def test_resume_refuses_a_staged_unit_that_changed_after_it_was_verified(world, tmp_path):
    target = _target(world, tmp_path)
    assert _kill_at(world, target, "restore_after_journal").returncode == KILLED
    seg = sorted((_staging(target) / "spine" / "spine.segments").iterdir())[0]
    raw = bytearray(seg.read_bytes())
    raw[len(raw) // 2] ^= 0x01
    seg.write_bytes(bytes(raw))
    r = _cli(target, "restore", "--resume", str(target))
    assert r.returncode == 1 and "changed since the restore verified it" in r.stderr, r.stderr
    assert (target / "restore-journal.json").is_file()
    _assert_fails_closed(target)


def test_resume_refuses_when_the_staging_is_gone_with_units_pending(world, tmp_path):
    target = _target(world, tmp_path)
    assert _kill_at(world, target, "restore_after_unit:spine").returncode == KILLED
    shutil.rmtree(_staging(target))
    r = _cli(target, "restore", "--resume", str(target))
    assert r.returncode == 1 and "is gone" in r.stderr and "re-run the restore with --force" in r.stderr, r.stderr
    assert (target / "restore-journal.json").is_file()


def test_resume_refuses_a_swapped_unit_that_changed_before_it_completed(world, tmp_path):
    """A unit already swapped in that something then wrote into (a service left running) is not certified: the
    journal is kept."""
    target = _target(world, tmp_path)
    assert _kill_at(world, target, "restore_after_unit:spine").returncode == KILLED
    (target / "spine" / "stray-write.jsonl").write_text("{}")
    r = _cli(target, "restore", "--resume", str(target))
    assert r.returncode == 1 and "changed after they were swapped in" in r.stderr, r.stderr
    assert (target / "restore-journal.json").is_file()
    _assert_fails_closed(target)


FORGED = {"dst": "destination outside", "src": "outside its staging", "unit name": "a backup never captures",
          "staging dir": "not a restore's own", "archive dst": "not beside its staging dir",
          "symlinked unit": "destination outside", "archive dst '..'": "not beside its staging dir"}


@pytest.mark.parametrize("forgery", sorted(FORGED))
def test_resume_and_abort_refuse_a_journal_that_names_paths_outside_the_restore(world, tmp_path, forgery):
    """Every rename a journal names stays inside the restore's own dirs: a unit of the home is one captured top-level
    entry of THIS home (never a path like ``../x``), staged in a ``.restore-staging-*`` dir; a relocated archive is
    staged in its own staging dir beside its destination. A journal that says otherwise is refused, and nothing is
    renamed or removed."""
    target = _target(world, tmp_path)
    arch = tmp_path / "ebs" / "archive" if forgery.startswith("archive dst") else None
    assert _kill_at(world, target, "restore_after_journal", archive_dir=arch).returncode == KILLED
    jp = target / "restore-journal.json"
    j = json.loads(jp.read_text())
    elsewhere = tmp_path / "elsewhere"
    floor = next(u for u in j["units"] if u["name"] == "floor.json")
    if forgery in ("dst", "src"):
        floor[forgery] = str(elsewhere / "floor.json")
    elif forgery == "unit name":
        floor["name"], floor["dst"] = "../elsewhere", str(elsewhere)        # resolves to (home / name)
    elif forgery == "staging dir":
        j["staging"] = str(tmp_path)                                         # still holds every staged unit
    elif forgery == "symlinked unit":                                        # the unit's entry points elsewhere
        elsewhere.mkdir()
        (elsewhere / "keep").write_text("not the restore's")
        (target / "floor.json").unlink()
        (target / "floor.json").symlink_to(elsewhere)
        floor["dst"] = str(elsewhere.resolve())
    elif forgery == "archive dst '..'":                                     # beside its staging dir, but not a name
        next(u for u in j["units"] if u["name"] == "archive")["dst"] = str(tmp_path / "ebs" / "..")
    else:
        next(u for u in j["units"] if u["name"] == "archive")["dst"] = str(elsewhere / "archive")
    jp.write_text(json.dumps(j))
    before = _tree(tmp_path)
    for action in ("--resume", "--abort"):
        r = _cli(target, "restore", action, str(target))
        assert r.returncode == 1 and "refusing" in r.stderr and FORGED[forgery] in r.stderr, (action, r.stderr)
    assert _tree(tmp_path) == before
    assert (elsewhere / "keep").read_text() == "not the restore's" if forgery == "symlinked unit" else not elsewhere.exists()


ALIASED = {"'..' in a staged unit": "outside its staging", "staging dir is a symlink": "not a restore's own",
           "staged unit is a symlink": "outside its staging", "staging dir not beside the home": "not beside",
           "archive staging is a symlink": "not a restore's own", "archive dst holds no archive": "holds no archive"}


@pytest.mark.parametrize("forgery", sorted(ALIASED))
def test_resume_and_abort_compare_the_real_entries_a_journal_names(world, tmp_path, forgery):
    """A journal's paths are compared as the real directory entries they name, never as spelled: a staging dir is a
    real dir beside its destination (not a symlink, no ``..``), a staged unit is exactly <staging>/<name> and not a
    symlink, and a relocated archive replaces only an archive. A planted journal whose rows would reach a dir outside
    the restore (moving it into the home, or replacing it with content from the home) is refused, and nothing outside
    is moved, replaced or removed."""
    target = _target(world, tmp_path)
    assert _kill_at(world, target, "restore_after_journal").returncode == KILLED
    etc = tmp_path / "etc"                                       # dirs outside the home and outside any staging
    (etc / "default").mkdir(parents=True)
    victim = etc / "sshd_config.d"
    victim.mkdir()
    (victim / "10-hardening.conf").write_text("PasswordAuthentication no\n")
    profile = etc / "profile.d"
    profile.mkdir()
    (profile / "vendor.sh").write_text("# sourced at login\n")
    payload = target / "payload"                                  # content a writer of the home controls
    payload.mkdir()
    (payload / "evil.sh").write_text("echo replaced\n")
    jp = target / "restore-journal.json"
    j = json.loads(jp.read_text())
    home_row = {"name": "qdrant", "dst": str(target.resolve() / "qdrant"), "digest": unit_digest(victim),
                "started": False, "done": False}
    planted = target.parent / ".restore-staging-planted"
    if forgery == "'..' in a staged unit":
        planted.mkdir()
        j["staging"] = str(planted.resolve())
        home_row["src"] = str(planted.resolve() / ".." / "etc" / "sshd_config.d")
        j["units"] = [home_row]
    elif forgery == "staging dir is a symlink":
        planted.symlink_to(etc)
        j["staging"] = str(planted)
        home_row["src"] = str(planted / "sshd_config.d")
        j["units"] = [home_row]
    elif forgery == "staged unit is a symlink":
        planted.mkdir()
        (planted / "qdrant").symlink_to(victim)
        j["staging"] = str(planted.resolve())
        home_row["src"] = str(planted.resolve() / "qdrant")
        j["units"] = [home_row]
    elif forgery == "staging dir not beside the home":
        elsewhere = etc / ".restore-staging-elsewhere"
        elsewhere.mkdir()
        shutil.move(str(victim), str(elsewhere / "qdrant"))
        victim = elsewhere / "qdrant"
        j["staging"] = str(elsewhere.resolve())
        home_row["src"] = str(elsewhere.resolve() / "qdrant")
        j["units"] = [home_row]
    else:                                                         # a relocated-archive row aimed at etc/profile.d
        ast = target / ".restore-staging-archive-planted"
        if forgery == "archive staging is a symlink":
            ast.symlink_to(etc / "default")                       # resolves beside profile.d
            src = ast / ".." / os.path.relpath(payload, etc)
        else:
            ast = etc / ".restore-staging-archive-planted"        # a real staging dir beside profile.d
            ast.mkdir()
            shutil.move(str(payload), str(ast / "archive"))
            ast = ast.resolve()
            payload = ast / "archive"
            src = ast / "archive"
        j["archive_staging"] = str(ast)
        j["units"] = [{"name": "archive", "src": str(src), "dst": str(profile.resolve()),
                       "digest": unit_digest(payload), "started": False, "done": False}]
        victim = profile
    jp.write_text(json.dumps(j))
    before = _tree(tmp_path)
    for action in ("--resume", "--abort"):
        r = _cli(target, "restore", action, str(target))
        assert r.returncode == 1 and "refusing" in r.stderr and ALIASED[forgery] in r.stderr, (action, r.stderr)
    assert _tree(tmp_path) == before
    assert jp.is_file() and victim.is_dir() and any(victim.iterdir())
    assert (profile / "vendor.sh").is_file() and not (profile / "evil.sh").exists()
    assert not (target / "qdrant").exists()


def test_a_unit_entry_that_is_a_symlink_is_replaced_never_its_target(world, tmp_path):
    """A journaled swap replaces the unit's entry in the home: a symlink there is replaced by the restored unit, and
    the dir it pointed to is left as it was (also when the restore is resumed)."""
    target = _target(world, tmp_path)
    outside = tmp_path / "outside-floor"
    (target / "floor.json").rename(outside)
    (target / "floor.json").symlink_to(outside)
    before = outside.read_bytes()
    assert _kill_at(world, target, "restore_after_journal").returncode == KILLED
    assert _cli(target, "restore", "--resume", str(target)).returncode == 0
    assert not (target / "floor.json").is_symlink() and outside.read_bytes() == before
    _assert_restored(target)


def test_a_new_restore_over_an_interrupted_one_needs_force(world, tmp_path):
    target = _target(world, tmp_path)
    assert _kill_at(world, target, "restore_after_unit:spine").returncode == KILLED
    host = tmp_path / "restoring-host"
    plain = run_in_home(host, RESTORE_KILLED.replace("force=True", "force=False"),
                        json.dumps({"src": str(world["bk"]), "home": str(target), "barrier": "never"}),
                        check=False, SIGIL_PRUNED_RESTORE="1", SIGIL_SPINE_ARCHIVE_DIR=None)
    assert plain.returncode != 0 and "was interrupted" in plain.stderr
    assert _kill_at(world, target, "never").returncode == 0
    _assert_restored(target)


def _units_of(home: Path) -> dict:
    """Each captured top-level unit of ``home`` (and the restore journal) by content."""
    return {n: (hashlib.sha256((home / n).read_bytes()).hexdigest() if (home / n).is_file()
                else _tree(home / n) if (home / n).is_dir() else None)
            for n in ("spine", "floor.json", "budgets.json", "model_meter", "restore-journal.json")}


def _assert_is_the_plain_backup(world, target: Path) -> None:
    """``target`` is entirely the never-pruned backup's: no journal, no staging or old copy left in the home's dir,
    its spine and floor are that backup's, and its signed head verifies and signs."""
    assert not (target / "restore-journal.json").exists()
    assert not [p for p in target.parent.iterdir() if p.name.startswith(".restore-")]
    assert not [p for p in target.iterdir() if p.name.startswith(".restore-old-")]
    plain = _units_of(world["plain"])
    now = _units_of(target)
    assert now["spine"] == plain["spine"] and now["floor.json"] == plain["floor.json"]
    seen = read_home(target)
    assert seen["verify_checkpoint"][0] is True and seen["wallet_acme"] == 100, seen
    r = _cli(target, "sign")
    assert r.returncode == 0, (r.returncode, r.stderr)


# How the interrupted restore had already touched the home when a --force restore replaced it: its spine landed
# and its floor did not (its spine's old copy already dropped); its spine and floor landed and a third unit had not;
# its relocated archive was moved aside (a unit the replacing restore has no row for).
REPLACED_TOUCHED = {"spine in, floor pending": ("restore_unit_started:floor.json", "old", None, ["spine"]),
                    "spine and floor in, budgets pending": ("restore_unit_started:budgets.json", "old_metered", None,
                                                            ["spine", "floor.json"]),
                    "relocated archive moved aside": ("restore_moved_aside:archive", "old", "ebs", ["archive"])}


@pytest.mark.parametrize("case", sorted(REPLACED_TOUCHED))
def test_a_restore_that_replaced_a_touched_one_cannot_be_aborted_and_resumes_entirely(world, tmp_path, case):
    """A --force restore that replaces an interrupted restore which had already swapped units in records that in its
    own journal before it replaces the interrupted one's. Killed before it touched anything itself, its abort is
    refused — the home is no longer its old self — and deletes nothing; the home fails closed until `--resume` makes it
    entirely the new backup's (verified and signable). Nothing the interrupted restore moved aside is removed."""
    barrier, old, ext, names = REPLACED_TOUCHED[case]
    target = tmp_path / "target"
    shutil.copytree(world[old], target)
    arch = None
    if ext:
        arch = tmp_path / ext / "archive"
        shutil.copytree(world["old"] / "spine" / "archive", arch)
    old_archive = (arch / "archive.manifest.json").read_bytes() if arch else None
    backup = "bk_metered" if old == "old_metered" else "bk"
    assert _kill_at(world, target, barrier, archive_dir=arch, backup=backup).returncode == KILLED
    r = _cli(target, "restore", "--abort", str(target))
    assert r.returncode == 1, r.stderr                                    # the interrupted restore had touched it
    assert _kill_at(world, target, "restore_after_journal", backup="bk_plain").returncode == KILLED
    j = json.loads((target / "restore-journal.json").read_text())
    assert j["backup_sha256"] == hashlib.sha256(world["bk_plain"].read_bytes()).hexdigest()
    assert all(n in j["replaced"]["touched"] for n in names), j["replaced"]
    before = _tree(tmp_path)
    r = _cli(target, "restore", "--abort", str(target))
    assert r.returncode == 1 and "no longer its old self" in r.stderr and "--resume" in r.stderr, r.stderr
    assert all(repr(n) in r.stderr for n in names) and "nothing was discarded" in r.stderr, r.stderr
    assert _tree(tmp_path) == before
    _assert_fails_closed(target)
    r = _cli(target, "restore", "--resume", str(target))
    assert r.returncode == 0 and "completed" in r.stdout, (r.returncode, r.stdout, r.stderr)
    _assert_is_the_plain_backup(world, target)
    if old == "old_metered":                       # not in the new backup, never renamed: left as the restore found it
        assert (target / "budgets.json").read_text() == '{"caps": "old home"}'
        assert (target / "model_meter" / "run-1.jsonl").read_text() == '{"meter": "old home"}\n'
    if arch is not None:                                                  # the old archive is kept, never removed
        assert (arch.parent / ".restore-old-archive" / "archive.manifest.json").read_bytes() == old_archive


def test_a_restore_that_replaced_an_untouched_one_aborts_to_the_old_home(world, tmp_path):
    """The restore it replaced had touched nothing: aborting the replacing restore leaves the home exactly its old
    self and drops both restores' staging dirs."""
    target = tmp_path / "target"
    shutil.copytree(world["old_metered"], target)
    before = _tree(target)
    assert _kill_at(world, target, "restore_after_journal", backup="bk_metered").returncode == KILLED
    assert _kill_at(world, target, "restore_after_journal", backup="bk_plain").returncode == KILLED
    assert json.loads((target / "restore-journal.json").read_text())["replaced"]["touched"] == []
    assert len([p for p in tmp_path.iterdir() if p.name.startswith(".restore-staging-")]) == 2
    r = _cli(target, "restore", "--abort", str(target))
    assert r.returncode == 0 and "discarded" in r.stdout, r.stderr
    assert _tree(target) == before
    assert not [p for p in tmp_path.iterdir() if p.name.startswith(".restore-")]
    assert read_home(target)["verify_checkpoint"][0] is True


@pytest.mark.parametrize("first", ["touched", "unreadable journal"])
def test_what_a_replaced_restore_did_is_carried_through_every_later_replacement(world, tmp_path, first):
    """A restore replaced, in turn, by another: the units the first one had swapped in are carried by every journal
    that follows, and a journal that cannot be read counts as one that touched the home — the last restore's abort
    is refused and its resume makes the home entirely its backup's."""
    target = _target(world, tmp_path)
    if first == "touched":
        assert _kill_at(world, target, "restore_unit_started:floor.json").returncode == KILLED
    else:
        assert _kill_at(world, target, "restore_after_journal").returncode == KILLED
        (target / "restore-journal.json").write_text("{}")
    assert _kill_at(world, target, "restore_after_journal", backup="bk_plain").returncode == KILLED
    assert _kill_at(world, target, "restore_after_journal", backup="bk_plain").returncode == KILLED
    touched = json.loads((target / "restore-journal.json").read_text())["replaced"]["touched"]
    r = _cli(target, "restore", "--abort", str(target))
    assert r.returncode == 1 and "no longer its old self" in r.stderr, r.stderr
    if first == "touched":
        assert "spine" in touched and "['spine'" in r.stderr, (touched, r.stderr)
    else:
        assert touched is None and "could not be read" in r.stderr, (touched, r.stderr)
    r = _cli(target, "restore", "--resume", str(target))
    assert r.returncode == 0 and "completed" in r.stdout, (r.returncode, r.stdout, r.stderr)
    assert (target / "spine" / "head.json").read_bytes() == (world["plain"] / "spine" / "head.json").read_bytes()
    assert not (target / "restore-journal.json").exists()
    assert read_home(target)["verify_checkpoint"][0] is True


@pytest.mark.parametrize("barrier", ["restore_after_journal", "restore_after_unit:spine",
                                     "restore_before_journal_delete", "never"])
def test_a_force_restore_over_an_interrupted_one_is_resumed_into_itself(world, tmp_path, barrier):
    """A backup of a home that was never pruned, force-restored over an interrupted (hard-pruned) restore: its own
    journal replaces the interrupted one's before its first swap and the interrupted one's staging is dropped, so
    killed anywhere after that, `--resume` completes THIS restore, never the one it replaced; uninterrupted, it leaves
    no journal and no staging behind."""
    target = _target(world, tmp_path)
    assert _kill_at(world, target, "restore_after_journal").returncode == KILLED      # the restore it replaces
    r = _kill_at(world, target, barrier, backup="bk_plain")
    plain_head = (world["plain"] / "spine" / "head.json").read_bytes()
    if barrier != "never":
        assert r.returncode == KILLED, (r.returncode, r.stderr[-800:])
        j = json.loads((target / "restore-journal.json").read_text())
        assert j["backup_sha256"] == hashlib.sha256(world["bk_plain"].read_bytes()).hexdigest()
        _assert_fails_closed(target)
        r = _cli(target, "restore", "--resume", str(target))
        assert r.returncode == 0 and "completed" in r.stdout, (r.returncode, r.stdout, r.stderr)
    else:
        assert r.returncode == 0, r.stderr[-800:]
    assert (target / "spine" / "head.json").read_bytes() == plain_head
    assert not (target / "restore-journal.json").exists()
    assert not [p for p in tmp_path.iterdir() if p.name.startswith(".restore-")]
    assert not [p for p in target.iterdir() if p.name.startswith(".restore-old-")]
    seen = read_home(target)
    assert seen["verify_checkpoint"][0] is True and seen["wallet_acme"] == 100, seen


@pytest.mark.parametrize("old", ["old", "old_plain"])
@pytest.mark.parametrize("flag", ["1", None])
def test_every_restore_that_replaces_existing_units_is_journaled(world, tmp_path, flag, old):
    """A --force restore of a backup that was never pruned, over a home that already holds its units (pruned or not,
    SIGIL_PRUNED_RESTORE on or off), is journaled too. Killed between moving the old spine aside and renaming the new
    one in, the home fails closed: nothing signs and no owner key is minted in the spine's place; abort refuses, the
    old spine is kept aside, and `--resume` makes the home entirely the backup's, signing under the backup's key."""
    target = tmp_path / "target"
    shutil.copytree(world[old], target)
    old_pub = (target / "spine" / "keys" / "owner.pub").read_text()
    host = tmp_path / "restoring-host"
    host.mkdir()
    r = run_in_home(host, RESTORE_KILLED, json.dumps({"src": str(world["bk_plain"]), "home": str(target),
                                                      "barrier": "restore_moved_aside:spine", "archive_dir": None}),
                    check=False, SIGIL_PRUNED_RESTORE=flag, SIGIL_SPINE_ARCHIVE_DIR=None)
    assert r.returncode == KILLED, (r.returncode, r.stderr[-800:])
    assert (target / "restore-journal.json").is_file() and not (target / "spine").exists()
    assert (target / ".restore-old-spine" / "keys" / "owner.pub").read_text() == old_pub

    def cli(*args):
        return run_in_home(target, CLI, *args, check=False, SIGIL_PRUNED_RESTORE=flag, SIGIL_SPINE_ARCHIVE_DIR=None)
    r = cli("sign")
    assert r.returncode == 3 and "sigil restore --resume" in r.stderr, (r.returncode, r.stderr)
    _assert_fails_closed(target)
    assert not (target / "spine" / "keys" / "owner.pub").exists()          # no owner key minted in its place
    assert not (target / "spine" / "keys" / "owner.priv").exists()
    r = cli("restore", "--abort", str(target))
    assert r.returncode == 1 and "had begun swapping ['spine']" in r.stderr, r.stderr
    r = cli("restore", "--resume", str(target))
    assert r.returncode == 0 and "completed" in r.stdout, (r.returncode, r.stdout, r.stderr)
    assert ((target / "spine" / "keys" / "owner.pub").read_text()
            == (world["plain"] / "spine" / "keys" / "owner.pub").read_text())
    _assert_is_the_plain_backup(world, target)


def test_cli_verify_only_and_usage(world, tmp_path):
    caller = tmp_path / "caller"
    caller.mkdir()

    def cli(*args):
        return run_in_home(caller, CLI, *args, check=False, SIGIL_PRUNED_RESTORE="1", SIGIL_SPINE_ARCHIVE_DIR=None,
                           SIGIL_BACKUP_PASSPHRASE="pw-test-only")
    r = cli("restore", "--verify-only", str(world["bk"]))
    assert r.returncode == 0 and "verifies as one unit" in r.stdout and "nothing was written" in r.stdout, r.stderr
    r = cli("restore", "--verify-only", str(world["bk"]), str(tmp_path / "would-be-home"))
    assert r.returncode == 0 and not (tmp_path / "would-be-home").exists(), r.stderr
    r = run_in_home(caller, CLI, "restore", "--verify-only", str(world["bk"]), check=False,
                    SIGIL_PRUNED_RESTORE=None, SIGIL_SPINE_ARCHIVE_DIR=None, SIGIL_BACKUP_PASSPHRASE="pw-test-only")
    assert r.returncode == 1 and "SIGIL_PRUNED_RESTORE=1" in r.stderr
    assert cli("restore", str(world["bk"])).returncode == 2                          # no home
    assert cli("restore", "--resume", str(tmp_path / "h"), str(world["bk"])).returncode == 2
    r = cli("restore", "--resume", str(tmp_path / "h"))
    assert r.returncode == 1 and "no interrupted restore" in r.stderr
    new = tmp_path / "restored"
    r = cli("restore", str(world["bk"]), str(new), "--archive-dir", str(tmp_path / "ebs" / "archive"))
    assert r.returncode == 0 and f"SIGIL_SPINE_ARCHIVE_DIR={tmp_path / 'ebs' / 'archive'}" in r.stdout, r.stderr
