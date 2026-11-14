"""A restore that swaps a HARD-PRUNED unit in is journaled: the journal is durable before the first swap, every unit
is marked done after it lands, and the journal goes only after the last. A restore killed at any point between leaves
a home that fails closed (signed-head verification and signing refuse, the CLI refuses everything but `sigil restore`
and `sigil doctor`) until `sigil restore --resume` completes it — or, before any unit is in, `--abort` discards it.

Every restore here runs in a child process killed (``os._exit``) at a barrier of ``backup._crash_hook``; the target is
read back in a child whose SIGIL_HOME is that home.

Run: SIGIL_HOME=$(mktemp -d) python -m pytest tests/test_restore_pruned_crash.py
"""
from __future__ import annotations

import hashlib
import json
import shutil
from pathlib import Path

import pytest

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
if a["barrier"] == "mid-swap:spine":
    real = backup._atomic_swap_unit
    def swap(staged, dest):
        if dest.name == "spine" and dest.exists():
            os.replace(str(dest), str(dest.parent / (".restore-old-" + dest.name)))   # moved aside, then killed
            os._exit(77)
        return real(staged, dest)
    backup._atomic_swap_unit = swap
home = Path(a["home"])
res = backup.restore_backup(a["src"], home, "pw-test-only", vault=Vault(home / "vault"), force=True)
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
    return {"bk": bk, "old": old}


def _tree(root: Path) -> dict:
    """The home's content (read sidecars, lockfiles and the install manifest any `sigil` command writes excluded)."""
    return {str(p.relative_to(root)): (hashlib.sha256(p.read_bytes()).hexdigest() if p.is_file() else "dir")
            for p in sorted(root.rglob("*"))
            if not p.name.endswith((".idx", ".lock")) and p.name != "install-manifest.json"}


def _target(world, tmp_path) -> Path:
    t = tmp_path / "target"
    shutil.copytree(world["old"], t)
    return t


def _kill_at(world, target: Path, barrier: str):
    host = target.parent / "restoring-host"
    host.mkdir(exist_ok=True)
    r = run_in_home(host, RESTORE_KILLED, json.dumps({"src": str(world["bk"]), "home": str(target),
                                                      "barrier": barrier}),
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


def _assert_restored(target: Path) -> None:
    assert not (target / "restore-journal.json").exists()
    assert not [p for p in target.parent.iterdir() if p.name.startswith(".restore-")]
    assert not [p for p in target.iterdir() if p.name.startswith(".restore-old-")]
    for fold_cache in (False, True):
        seen = read_home(target, fold_cache=fold_cache)
        assert seen["verify_checkpoint"][0] and seen["verify_archive"][0], seen
        assert seen["killswitch_engaged"] is True and seen["wallet_acme"] == 100, seen


BARRIERS = ["restore_after_journal", "mid-swap:spine", "restore_after_unit:spine", "restore_after_unit:floor.json",
            "restore_before_journal_delete"]


@pytest.mark.parametrize("barrier", BARRIERS)
def test_a_restore_killed_at_any_barrier_fails_closed_and_resumes(world, tmp_path, barrier):
    target = _target(world, tmp_path)
    r = _kill_at(world, target, barrier)
    assert r.returncode == KILLED, (r.returncode, r.stderr[-800:])
    assert (target / "restore-journal.json").is_file()
    if barrier == "mid-swap:spine":
        assert not (target / "spine").exists() and (target / ".restore-old-spine").is_dir()
    _assert_fails_closed(target)
    assert not (target / "spine" / "keys" / "owner.priv").exists() or barrier != "mid-swap:spine"
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


def test_abort_is_refused_once_a_unit_is_in(world, tmp_path):
    target = _target(world, tmp_path)
    assert _kill_at(world, target, "restore_after_unit:spine").returncode == KILLED
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


@pytest.mark.parametrize("field", ["dst", "src"])
def test_resume_refuses_a_journal_that_names_paths_outside_the_restore(world, tmp_path, field):
    target = _target(world, tmp_path)
    assert _kill_at(world, target, "restore_after_journal").returncode == KILLED
    jp = target / "restore-journal.json"
    j = json.loads(jp.read_text())
    unit = next(u for u in j["units"] if u["name"] == "floor.json")
    unit[field] = str(tmp_path / "elsewhere" / "floor.json")
    jp.write_text(json.dumps(j))
    r = _cli(target, "restore", "--resume", str(target))
    assert r.returncode == 1 and "refusing" in r.stderr and ("destination outside" if field == "dst"
                                                              else "outside its staging") in r.stderr, r.stderr
    assert not (tmp_path / "elsewhere").exists()


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
