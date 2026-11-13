"""DEP-3 (#73) — the on-box upgrade/rollback drill (``sigil.spine.upgrade_drill``).

It must (a) PASS on a healthy real spine (legacy or already-migrated) — upgrade under this build, detect a
corrupted deployment, roll back intact; (b) NEVER modify the real spine directory — isolation comes from the
consistent snapshot plus the child process scoped to its own copy (and, under systemd, ``ReadOnlyPaths=``); the
after-digest is only REPORTED (``source_changed_during_drill``: a busy box's live appends are expected and never
fail the drill), while owner key material that changes in the real home, or a private key in the work dir, does
FAIL it; (c) FAIL honestly when any step does not hold (source does not verify, negative control does not bite,
rollback not intact); (d) report NOT-RUN (exit 3), never green, when there is no data to drill.
"""
from __future__ import annotations

import json

import pytest

from sigil.spine import upgrade_drill as ud
from sigil.spine.store import SpineStore
from sigil.spine.upgrade import upgrade


def _real_spine(tmp_path, n=8, migrate=False):
    path = tmp_path / "home" / "spine" / "spine.jsonl"
    s = SpineStore(str(path))
    for i in range(n):
        s.append(kind="event", source="drill-test", actor="op", payload={"i": i, "note": f"entry {i}"})
    if migrate:
        upgrade(SpineStore(str(path)), backup_dir=tmp_path / "pre-backups")
    return path


def _step_drill(tmp_path, path):
    """Run the drill STEPS in-process on a scratch-home snapshot (so a test can monkeypatch them); the
    end-to-end run_upgrade_drill runs them in the isolated child."""
    home = tmp_path / "work" / "home"
    assert ud._snapshot(path.parent, path.name, home) is not None
    return ud.drill_copy(home / "spine" / path.name, tmp_path / "work")


@pytest.mark.parametrize("migrate", [False, True])
def test_healthy_real_spine_passes_and_the_source_is_untouched(tmp_path, migrate):
    path = _real_spine(tmp_path, migrate=migrate)
    before = ud._tree_digest(path.parent)
    v = ud.run_upgrade_drill(path, tmp_path / "work")
    assert v["status"] == ud.PASS and v["ok"] is True, v
    assert v["source_changed_during_drill"] is False and ud._tree_digest(path.parent) == before
    steps = {s["step"]: s for s in v["steps"]}
    assert steps["negative_control"]["detected"] is True
    assert steps["rollback"]["ok"] is True and steps["rollback"]["intact"] is True
    assert v["count"] == 8


def test_no_data_is_not_run_never_green(tmp_path):
    v = ud.run_upgrade_drill(tmp_path / "empty" / "spine.jsonl", tmp_path / "work")
    assert v["status"] == ud.NOT_RUN and v["ok"] is False


def test_a_source_that_does_not_verify_fails(tmp_path):
    path = _real_spine(tmp_path)
    assert ud.corrupt_one_record(path.parent)
    v = ud.run_upgrade_drill(path, tmp_path / "work")
    assert v["status"] == ud.FAIL and v["detail"].startswith("the real spine (copied) does not verify")
    assert not any(st["step"] == "upgrade" for st in v["steps"])   # never even attempts to upgrade it


def test_an_upgrade_that_changes_the_record_set_fails(tmp_path, monkeypatch):
    path = _real_spine(tmp_path)
    real_upgrade = ud.upgrade

    def lossy_upgrade(store, **kw):
        rep = real_upgrade(store, **kw)
        SpineStore(str(store.path)).append(kind="event", source="rogue", actor="x", payload={"extra": 1})
        return rep                                                           # "ok" — but not the same data
    monkeypatch.setattr(ud, "upgrade", lossy_upgrade)
    v = _step_drill(tmp_path, path)
    assert v["status"] == ud.FAIL and "upgraded copy is not intact" in v["detail"]


def test_a_negative_control_that_does_not_bite_fails(tmp_path, monkeypatch):
    path = _real_spine(tmp_path)
    monkeypatch.setattr(ud, "corrupt_one_record", lambda d, verify=None: False)
    v = _step_drill(tmp_path, path)
    assert v["status"] == ud.FAIL and "negative control" in v["detail"]


def test_a_rollback_that_does_not_restore_fails(tmp_path, monkeypatch):
    path = _real_spine(tmp_path)
    monkeypatch.setattr(ud, "restore_from_backup", lambda d, b: None)       # rollback is a no-op
    v = _step_drill(tmp_path, path)
    assert v["status"] == ud.FAIL and "rollback" in v["detail"]


def test_a_source_changed_during_the_drill_still_gets_a_verdict(tmp_path, monkeypatch):
    """A busy box: the real spine changes AFTER the consistent snapshot. The drill verified the snapshot, so it
    still gets a verdict (not a weekly INCONCLUSIVE); the change is reported, never hidden."""
    path = _real_spine(tmp_path)
    real = ud._run_isolated

    def busy(data, work):
        SpineStore(str(path)).append(kind="event", source="live", actor="w", payload={"live": 1})
        return real(data, work)
    monkeypatch.setattr(ud, "_run_isolated", busy)
    v = ud.run_upgrade_drill(path, tmp_path / "work")
    assert v["status"] == ud.PASS and v["source_changed_during_drill"] is True, v
    assert "concurrent writes" in v["detail"] and v["count"] == 8           # the SNAPSHOT's records


@pytest.mark.parametrize("keys_dir_existed", [False, True])
def test_a_drill_that_changes_the_real_owner_keys_fails(tmp_path, monkeypatch, keys_dir_existed):
    """Tripwire for the defect class (a mint into the REAL home while the drill runs): a new owner keypair over
    an existing owner.pub (the key kept off-box), or a keys dir that appears, FAILS the drill."""
    from sigil.reuse import generate_keypair
    if keys_dir_existed:
        home = _signed_home(tmp_path, pruned=False)
        (home / "spine" / "keys" / "owner.priv").unlink()                   # the owner keeps the key off-box
        path = home / "spine" / "spine.jsonl"
    else:
        path = _real_spine(tmp_path)
    real = ud._run_isolated

    def minting(data, work):
        kd = path.parent / "keys"
        kd.mkdir(exist_ok=True)
        kp = generate_keypair()
        (kd / "owner.priv").write_text(kp.private_key_b64)
        (kd / "owner.pub").write_text(kp.public_key_b64)
        return real(data, work)
    monkeypatch.setattr(ud, "_run_isolated", minting)
    v = ud.run_upgrade_drill(path, tmp_path / "work")
    assert v["status"] == ud.FAIL and "owner key material" in v["detail"], v


@pytest.mark.parametrize("field", ["mtime", "inode", "size", "mode"])
def test_a_drill_that_rewrites_the_real_owner_keys_under_the_same_names_fails(tmp_path, monkeypatch, field):
    """A mint can also rewrite owner.priv / owner.pub IN PLACE under the same names (an unreadable or empty
    owner.priv regenerates both). Each fingerprint field on its own must catch it: the rewrite changes exactly
    one of mtime, inode, size or mode and leaves the other three as they were."""
    import os
    home = _signed_home(tmp_path, pruned=False)
    kd = home / "spine" / "keys"
    old_ns = 1_600_000_000 * 10**9
    for p in kd.iterdir():
        os.utime(p, ns=(old_ns, old_ns))
    path = home / "spine" / "spine.jsonl"
    real = ud._run_isolated

    def rekey(data, work):
        for p in sorted(kd.iterdir()):
            st, raw = p.stat(), p.read_bytes()
            if field == "mtime":
                p.write_bytes(raw[::-1])                              # same inode, size, mode; new mtime
            elif field == "inode":
                tmp = p.with_name(p.name + ".new")
                tmp.write_bytes(raw[::-1])
                os.chmod(tmp, st.st_mode & 0o7777)
                os.replace(tmp, p)
                os.utime(p, ns=(st.st_atime_ns, st.st_mtime_ns))
            elif field == "size":
                p.write_bytes(raw + b"=")
                os.utime(p, ns=(st.st_atime_ns, st.st_mtime_ns))
            else:
                os.chmod(p, (st.st_mode & 0o7777) ^ 0o040)
        return real(data, work)
    monkeypatch.setattr(ud, "_run_isolated", rekey)
    v = ud.run_upgrade_drill(path, tmp_path / "work")
    assert v["status"] == ud.FAIL and "owner key material" in v["detail"], v


def test_an_unexpected_error_is_a_failed_drill_not_a_crash(tmp_path, monkeypatch):
    path = _real_spine(tmp_path)

    def boom(*a, **k):
        raise RuntimeError("disk vanished")
    monkeypatch.setattr(ud, "upgrade", boom)
    v = _step_drill(tmp_path, path)
    assert v["status"] == ud.FAIL and "RuntimeError" in v["detail"]


def test_a_crashed_isolated_child_is_a_failed_drill(tmp_path, monkeypatch):
    import subprocess
    path = _real_spine(tmp_path)
    monkeypatch.setattr(ud.subprocess, "run",
                        lambda *a, **k: subprocess.CompletedProcess(a, 1, stdout="", stderr="Traceback: boom"))
    v = ud.run_upgrade_drill(path, tmp_path / "work")
    assert v["status"] == ud.FAIL and "isolated drill process failed" in v["detail"] and "boom" in v["detail"]


def test_corrupt_one_record_reaches_sealed_gz_segments(tmp_path):
    path = _real_spine(tmp_path, migrate=True)                               # migrated + compacted ⇒ gz
    for p in path.parent.rglob("*.jsonl"):
        if p.stat().st_size:                                                 # only sealed segments hold data
            pytest.skip("layout kept an open plaintext segment; gz path covered by the healthy test")
    assert ud.corrupt_one_record(path.parent) is True
    assert SpineStore(str(path)).verify()[0] is False


@pytest.mark.parametrize("make,rc,status", [("healthy", 0, "PASS"), ("empty", 3, "NOT-RUN"), ("bad", 1, "FAIL")])
def test_main_exit_codes(tmp_path, capsys, make, rc, status):
    if make == "empty":
        spine = tmp_path / "none" / "spine.jsonl"
    else:
        spine = _real_spine(tmp_path)
        if make == "bad":
            ud.corrupt_one_record(spine.parent)
    assert ud.main(["--spine", str(spine), "--work-dir", str(tmp_path), "--json"]) == rc
    assert json.loads(capsys.readouterr().out)["status"] == status


# --- red-pen folds --------------------------------------------------------------------------------------

def _archive_a_segment(path):
    """Put a plaintext record file under spine/archive/segments/ (where prune's cold-archive lives, sorting
    BEFORE the live segment dir) — live verification never reads it."""
    arch = path.parent / "archive" / "segments"
    arch.mkdir(parents=True)
    line = next(ln for ln in path.read_text().splitlines() if ln.strip()) if path.exists() else \
        json.dumps({"seq": 0, "payload": {"x": 1}, "cert_digest": "00"})
    (arch / "seg-000000.jsonl").write_text(line + "\n")
    return arch


def test_an_archive_dir_is_neither_copied_nor_the_corruption_target(tmp_path):
    path = _real_spine(tmp_path)
    arch = _archive_a_segment(path)
    v = ud.run_upgrade_drill(path, tmp_path / "work")
    assert v["status"] == ud.PASS, v                     # the negative control still bites the LIVE data
    assert (tmp_path / "work" / "home" / "spine").is_dir()
    assert not (tmp_path / "work" / "home" / "spine" / "archive").exists()   # pruned history is never copied
    assert (arch / "seg-000000.jsonl").exists()                         # and the real archive is untouched


def test_corruption_reverts_a_candidate_that_verification_does_not_read(tmp_path):
    path = _real_spine(tmp_path)
    decoy = path.parent / "aaa-decoy.jsonl"              # sorts first; not on the live verify path
    decoy.write_text(json.dumps({"seq": 0, "payload": {"d": 1}}) + "\n")
    before = decoy.read_bytes()
    assert ud.corrupt_one_record(path.parent, verify=lambda: SpineStore(str(path)).verify()) is True
    assert decoy.read_bytes() == before                   # reverted, then the real data was corrupted
    assert SpineStore(str(path)).verify()[0] is False


@pytest.mark.parametrize("where", ["inside", "around", "same"])
def test_a_work_dir_overlapping_the_real_spine_is_refused(tmp_path, where):
    path = _real_spine(tmp_path)
    before = ud._tree_digest(path.parent)
    work = {"inside": path.parent / "w", "around": tmp_path / "home", "same": path.parent}[where]
    v = ud.run_upgrade_drill(path, work)
    assert v["status"] == ud.FAIL and "overlaps the real spine" in v["detail"]
    assert ud._tree_digest(path.parent) == before and not (path.parent / "w").exists()


def test_a_copy_error_is_a_failed_verdict_not_a_traceback(tmp_path, monkeypatch):
    """A PERSISTENT copy error (every attempt) is the real FAIL, reported — never a crash, never INCONCLUSIVE."""
    path = _real_spine(tmp_path)

    def boom(*a, **k):
        raise OSError("a spine file is unreadable")
    monkeypatch.setattr(ud.shutil, "copytree", boom)
    monkeypatch.setattr(ud.time, "sleep", lambda s: None)
    v = ud.run_upgrade_drill(path, tmp_path / "work")
    assert v["status"] == ud.FAIL and "OSError" in v["detail"]


@pytest.mark.parametrize("where", ["copytree", "digest"])
def test_a_snapshot_that_trips_over_a_concurrently_renamed_file_is_retried(tmp_path, monkeypatch, where):
    """A concurrent ``sigil sign`` renames its head temp file away between the listing and the open: copytree
    raises ``shutil.Error`` / the digest raises FileNotFoundError. That attempt is inconsistent, so it is retried —
    a healthy busy box gets its verdict, not a false FAIL."""
    import shutil
    path = _real_spine(tmp_path)
    real = {"copytree": ud.shutil.copytree, "digest": ud._tree_digest}[where]
    calls = []

    def once(*a, **k):
        calls.append(a)
        if len(calls) == 1:
            if where == "copytree":
                raise shutil.Error([("/spine/.head-x.tmp", "/copy/.head-x.tmp", "No such file or directory")])
            raise FileNotFoundError("/spine/.head-x.tmp")
        return real(*a, **k)
    monkeypatch.setattr(ud.shutil if where == "copytree" else ud, "copytree" if where == "copytree" else "_tree_digest",
                        once)
    monkeypatch.setattr(ud.time, "sleep", lambda s: None)
    v = ud.run_upgrade_drill(path, tmp_path / "work")
    assert v["status"] == ud.PASS, v


def test_an_atomic_write_temp_file_is_neither_copied_nor_digested(tmp_path):
    """The transient temp file of an atomic write (``.head-*.tmp`` / ``.tmp-*.tmp``) is renamed away at any moment
    by a concurrent sign and never read by verify: the snapshot neither copies nor digests it."""
    path = _real_spine(tmp_path)
    src = path.parent
    clean = ud._tree_digest(src)
    for name in (".head-abc123.tmp", ".tmp-xyz789.tmp"):
        (src / name).write_text("half-written head\n")
    assert ud._tree_digest(src) == clean
    home = tmp_path / "work" / "home"
    assert ud._snapshot(src, path.name, home) == clean
    assert not [p for p in (home / "spine").iterdir() if p.name.endswith(".tmp")]


def _floor_and_sleeps(path, monkeypatch):
    floor = path.parent.parent / "floor.json"
    floor.write_text('{"floor": 1}\n')
    sleeps = []
    monkeypatch.setattr(ud.time, "sleep", lambda s: sleeps.append(s))
    return floor, sleeps


@pytest.mark.parametrize("race", ["floor_moved_during_copy", "floor_copy_unfaithful", "tree_copy_unfaithful",
                                  "source_moved_after_copy"])
def test_each_snapshot_consistency_guard_forces_a_retry(tmp_path, monkeypatch, race):
    """Each digest guard on its own: exactly ONE component diverges on the first attempt — the source floor
    (rewritten mid-copy), the floor COPY, the spine-dir COPY, or the source spine dir after the copy — and the
    snapshot is retried once, ending byte-faithful to the source (spine dir AND floor)."""
    from pathlib import Path
    path = _real_spine(tmp_path)
    floor, sleeps = _floor_and_sleeps(path, monkeypatch)
    home = tmp_path / "work" / "home"
    real_copytree, real_copyfile, first = ud.shutil.copytree, ud.shutil.copyfile, []

    def copytree(src, dst, **kw):
        out = real_copytree(src, dst, **kw)
        if not first:
            first.append(1)
            if race == "tree_copy_unfaithful":
                with open(Path(dst) / path.name, "ab") as f:
                    f.write(b"\n")
            elif race == "source_moved_after_copy":
                with open(Path(src) / path.name, "ab") as f:    # raw bytes: the store lock is held SHARED here
                    f.write(b"\n")
        return out

    def copyfile(src, dst, **kw):
        if race == "floor_moved_during_copy" and len(first) == 1:
            first.append(2)
            floor.write_text('{"floor": 2}\n')                  # a concurrent sign advanced the floor
        out = real_copyfile(src, dst, **kw)
        if race == "floor_copy_unfaithful" and len(first) == 1:
            first.append(2)
            Path(dst).write_text("garbage")
        return out
    monkeypatch.setattr(ud.shutil, "copytree", copytree)
    monkeypatch.setattr(ud.shutil, "copyfile", copyfile)
    assert ud._snapshot(path.parent, path.name, home) is not None
    assert len(sleeps) == 1, sleeps                                   # retried exactly once
    assert ud._tree_digest(home / "spine") == ud._tree_digest(path.parent)
    assert (home / "floor.json").read_bytes() == floor.read_bytes()


def test_an_inconsistent_snapshot_is_inconclusive_not_a_fail(tmp_path, monkeypatch):
    path = _real_spine(tmp_path)
    digests = iter(str(i) for i in range(100))            # every digest differs ⇒ a writer never lets it settle
    monkeypatch.setattr(ud, "_tree_digest", lambda root: next(digests))
    monkeypatch.setattr(ud.time, "sleep", lambda s: None)
    v = ud.run_upgrade_drill(path, tmp_path / "work")
    assert v["status"] == ud.INCONCLUSIVE and "consistent snapshot" in v["detail"]


def test_a_snapshot_that_races_a_writer_twice_is_retried_not_inconclusive(tmp_path, monkeypatch):
    """head.json / floor.json are rewritten by a concurrent ``sigil sign`` OUTSIDE the store's writer lock, so an
    attempt can race. Bounded retries (at least three attempts) still yield a consistent snapshot and a verdict."""
    path = _real_spine(tmp_path)
    real, calls = ud._tree_digest, []

    def racing(root):
        calls.append(root)
        return "raced" if len(calls) in (2, 5) else real(root)   # attempts 1 + 2: the mid-copy digest moved
    monkeypatch.setattr(ud, "_tree_digest", racing)
    monkeypatch.setattr(ud.time, "sleep", lambda s: None)
    v = ud.run_upgrade_drill(path, tmp_path / "work")
    assert v["status"] == ud.PASS, v


def test_the_snapshot_holds_a_shared_lock_on_the_writer_lockfile(tmp_path, monkeypatch):
    import fcntl
    path = _real_spine(tmp_path)
    lock = path.parent / "spine.lock"
    assert lock.exists()
    seen = []
    real = fcntl.flock

    def spy(fd, op):
        seen.append(op)
        return real(fd, op)
    monkeypatch.setattr(fcntl, "flock", spy)
    v = ud.run_upgrade_drill(path, tmp_path / "work")
    assert v["status"] == ud.PASS and fcntl.LOCK_SH in seen


def test_a_concurrent_writer_never_yields_a_false_accusation(tmp_path):
    import threading
    path = _real_spine(tmp_path, n=40)
    stop = threading.Event()

    def writer():
        i = 0
        while not stop.is_set():
            SpineStore(str(path)).append(kind="event", source="live", actor="w", payload={"live": i})
            i += 1
    t = threading.Thread(target=writer, daemon=True)
    t.start()
    try:
        v = ud.run_upgrade_drill(path, tmp_path / "work")
    finally:
        stop.set()
        t.join(5)
    assert v["status"] == ud.PASS, v                  # a busy box still gets a verdict on a consistent snapshot
    assert "investigate" not in v["detail"]


_LIVE_WRITER = """
import sys, time
from pathlib import Path
from sigil.spine.store import SpineStore
stop, i = Path(sys.argv[2]), 0
while not stop.exists():
    SpineStore(sys.argv[1]).append(kind="event", source="live", actor="w", payload={"live": i})
    i += 1
    time.sleep(0.005)
"""


def test_a_busy_box_with_a_live_writer_process_still_gets_a_verdict(tmp_path):
    """The audit repro (weekly INCONCLUSIVE on a busy box): a SEPARATE writer process appends to the real spine
    the whole time the drill runs. The drill still concludes (PASS on its consistent snapshot), and says the live
    spine moved on."""
    import subprocess
    import time
    path = _real_spine(tmp_path, n=40)
    stop = tmp_path / "stop-writer"
    env, py = _env(path.parent.parent)
    w = subprocess.Popen([py, "-c", _LIVE_WRITER, str(path), str(stop)], env=env)
    try:
        start = SpineStore(str(path)).count()
        deadline = time.monotonic() + 30
        while SpineStore(str(path)).count() < start + 5 and time.monotonic() < deadline:
            time.sleep(0.05)                                    # the writer is demonstrably live before we start
        v = ud.run_upgrade_drill(path, tmp_path / "work")
        during = SpineStore(str(path)).count()
    finally:
        stop.touch()
        w.wait(30)
    assert v["status"] == ud.PASS, v
    assert v["source_changed_during_drill"] is True and "concurrent writes" in v["detail"]
    assert start + 5 <= v["count"] < during                     # the drill verified a point-in-time snapshot


def test_pass_message_is_honest_about_an_already_migrated_spine(tmp_path):
    v = ud.run_upgrade_drill(_real_spine(tmp_path, migrate=True), tmp_path / "work")
    assert v["status"] == ud.PASS and "already migrated" in v["detail"]
    v2 = ud.run_upgrade_drill(_real_spine(tmp_path / "b"), tmp_path / "work2")
    assert v2["status"] == ud.PASS and "migrated to the segment layout" in v2["detail"]


def test_main_exit_code_for_inconclusive(tmp_path, monkeypatch, capsys):
    path = _real_spine(tmp_path)
    monkeypatch.setattr(ud, "run_upgrade_drill", lambda s, w: {"status": ud.INCONCLUSIVE, "detail": "x", "steps": []})
    assert ud.main(["--spine", str(path), "--work-dir", str(tmp_path)]) == 4


# --- audit E4: the drill never holds the owner key and never writes outside its work dir -----------------

_MAKE_HOME = """
import sys
from sigil import config
from sigil.spine import checkpoint as cp, prune
from sigil.spine.store import SpineStore
s = SpineStore(config.SPINE_PATH)
s.migrate()
seq = 0
for _seg in range(4):
    for _i in range(5):
        s.append(kind="event", source="t", actor="u", payload={"i": seq}); seq += 1
    s.rotate()
for _i in range(3):
    s.append(kind="event", source="t", actor="u", payload={"i": seq}); seq += 1
cp.checkpoint(s)
if sys.argv[1] == "prune":
    prune.commit_prune(s, 10, confirm=True)
"""


def _env(home):
    import os
    import sys
    from pathlib import Path

    import sigil
    env = dict(os.environ)
    env["SIGIL_HOME"] = str(home)
    root = str(Path(sigil.__file__).resolve().parent.parent)
    env["PYTHONPATH"] = os.pathsep.join([root] + ([env["PYTHONPATH"]] if env.get("PYTHONPATH") else []))
    return env, sys.executable


def _signed_home(tmp_path, *, pruned: bool):
    """A REAL sovereign home (its own SIGIL_HOME, built in a child process): a segmented spine with an
    owner-signed head + floor + owner keypair under ``home/spine/keys`` — optionally cold-archive PRUNED."""
    import subprocess
    home = tmp_path / "realhome"
    home.mkdir()
    env, py = _env(home)
    subprocess.run([py, "-c", _MAKE_HOME, "prune" if pruned else "keep"], env=env, check=True)
    assert (home / "spine" / "keys" / "owner.priv").is_file() and (home / "spine" / "head.json").is_file()
    return home


def _whole_tree(root):
    """Every path under ``root`` with its bytes digest + mode — a full monitor (owner.priv included)."""
    import hashlib
    out = {}
    for p in sorted(root.rglob("*")):
        st = p.lstat()
        out[str(p.relative_to(root))] = (hashlib.sha256(p.read_bytes()).hexdigest() if p.is_file() else "dir",
                                         st.st_mode, st.st_size)
    return out


def _assert_no_owner_key_under(work, priv_text):
    import gzip
    import io
    import tarfile
    needle = priv_text.strip().encode()
    for p in work.rglob("*"):
        assert not p.name.endswith(".priv"), f"an owner private key file is in the drill work dir: {p}"
        if not p.is_file():
            continue
        raw = p.read_bytes()
        assert needle not in raw, f"owner private key BYTES found in {p}"
        if p.name.endswith(".gz"):
            body = gzip.decompress(raw)
            assert needle not in body, f"owner private key bytes inside compressed {p}"
            if p.name.endswith(".tar.gz"):
                with tarfile.open(fileobj=io.BytesIO(raw), mode="r:gz") as tar:
                    for m in tar.getmembers():
                        assert not m.name.endswith(".priv"), f"{m.name} packed into the drill tarball {p}"
                        f = tar.extractfile(m) if m.isfile() else None
                        if f is not None:
                            member = f.read()
                            assert needle not in member and needle not in (
                                gzip.decompress(member) if m.name.endswith(".gz") else b"")


@pytest.mark.parametrize("pruned", [False, True])
def test_the_owner_private_key_is_never_copied_into_the_drill(tmp_path, pruned):
    home = _signed_home(tmp_path, pruned=pruned)
    priv = (home / "spine" / "keys" / "owner.priv").read_text()
    work = tmp_path / "work"
    v = ud.run_upgrade_drill(home / "spine" / "spine.jsonl", work)
    assert v["status"] == ud.PASS, v
    assert list(work.rglob("*.tar.gz")), "the upgrade's backup tarball is under the work dir (and was scanned)"
    assert (work / "home" / "spine" / "keys" / "owner.pub").is_file()        # the PUBLIC key IS carried
    _assert_no_owner_key_under(work, priv)


def test_no_secret_key_file_of_any_kind_reaches_the_drill(tmp_path):
    """Every secret under ``keys/`` stays behind — the owner private key, the spine DEK and a crash-leftover temp
    file of the private key (``owner.priv.tmp``, the vault's atomic-write name) — and so does a stray ``*.priv`` /
    ``*.dek`` elsewhere in the spine dir, while exactly the PUBLIC key files are carried. Proven by walking the
    work dir AND every tarball for each secret's bytes."""
    import os
    home = _signed_home(tmp_path, pruned=False)
    kd = home / "spine" / "keys"
    priv = (kd / "owner.priv").read_text()
    dek = os.urandom(48).hex()
    (kd / "spine.dek").write_text(dek)
    (kd / "owner.priv.tmp").write_text(priv)
    (kd / "owner.genesis.pub").write_text((kd / "owner.pub").read_text())
    (home / "spine" / "owner-copy.priv").write_text(priv)        # outside keys/: excluded by its suffix
    (home / "spine" / "old-spine.dek").write_text(dek)
    work = tmp_path / "work"
    v = ud.run_upgrade_drill(home / "spine" / "spine.jsonl", work)
    assert v["status"] == ud.PASS, v
    assert list(work.rglob("*.tar.gz"))
    for secret in (priv, dek):
        _assert_no_owner_key_under(work, secret)
    assert sorted(p.name for p in (work / "home" / "spine" / "keys").iterdir()) == ["owner.genesis.pub", "owner.pub"]
    assert not [p for p in work.rglob("*") if p.name.endswith((".priv", ".dek", ".priv.tmp"))]


def test_the_owner_private_key_is_not_in_the_work_dir_after_a_failed_drill(tmp_path, monkeypatch):
    home = _signed_home(tmp_path, pruned=False)
    priv = (home / "spine" / "keys" / "owner.priv").read_text()
    monkeypatch.setattr(ud, "restore_from_backup", lambda d, b: None)        # fail AFTER the backup tarball
    v = _step_drill(tmp_path, home / "spine" / "spine.jsonl")
    assert v["status"] == ud.FAIL and "rollback" in v["detail"]
    assert list((tmp_path / "work").rglob("*.tar.gz"))
    _assert_no_owner_key_under(tmp_path / "work", priv)


@pytest.mark.parametrize("key_offline", [False, True])
def test_a_drill_of_a_pruned_spine_writes_nothing_outside_its_work_dir(tmp_path, key_offline):
    """The audit repro: verifying a PRUNED copy consults a signed head + the owner key. It must use the COPY's
    head and PUBLIC key — never the process's global KEYS_DIR, never mint a keypair (the old path minted a new
    owner keypair into the real home when the private key was kept off-box)."""
    import sigil.config as cfg
    home = _signed_home(tmp_path, pruned=True)
    if key_offline:
        (home / "spine" / "keys" / "owner.priv").unlink()                   # the owner keeps the key OFF-box
    real_before = _whole_tree(home)
    proc_home_before = _whole_tree(cfg.SIGIL_HOME) if cfg.SIGIL_HOME.exists() else {}
    v = ud.run_upgrade_drill(home / "spine" / "spine.jsonl", tmp_path / "work")
    assert v["status"] == ud.PASS, v
    assert _whole_tree(home) == real_before, "the drill changed the REAL home"
    assert (_whole_tree(cfg.SIGIL_HOME) if cfg.SIGIL_HOME.exists() else {}) == proc_home_before, \
        "the drill wrote into this process's own SIGIL_HOME (global KEYS_DIR/HEAD_PATH)"
    assert not list((tmp_path / "work").rglob("*.priv")), "the drill minted a keypair"


def test_the_manual_cli_drill_on_its_own_pruned_home_never_mints_a_key(tmp_path):
    """Exactly the manual operator run: ``SIGIL_HOME=<real> python -m sigil.spine.upgrade_drill`` with the owner
    private key kept off-box — PASS, and the real keys dir is byte-identical afterwards."""
    import subprocess
    home = _signed_home(tmp_path, pruned=True)
    (home / "spine" / "keys" / "owner.priv").unlink()
    before = _whole_tree(home)
    env, py = _env(home)
    work = tmp_path / "w"
    work.mkdir()
    r = subprocess.run([py, "-m", "sigil.spine.upgrade_drill", "--work-dir", str(work), "--json"],
                       env=env, capture_output=True, text=True)
    assert r.returncode == 0, r.stdout + r.stderr
    assert json.loads(r.stdout)["status"] == ud.PASS
    assert _whole_tree(home) == before and not (home / "spine" / "keys" / "owner.priv").exists()


@pytest.mark.parametrize("how", ["verify_checkpoint", "sigil verify"])
def test_verify_never_mints_over_an_existing_owner_public_key(tmp_path, how):
    """The lowest layer of the mint: ``trust_root`` (every verify, plain ``sigil verify`` included) read the
    PRIVATE key and generated a new keypair when it was absent — re-keying the trust root over the existing
    owner.pub and then reporting the genuine head as TAMPERING. It now reads only the public key."""
    import subprocess
    home = _signed_home(tmp_path, pruned=False)
    (home / "spine" / "keys" / "owner.priv").unlink()
    before = _whole_tree(home / "spine" / "keys")
    env, py = _env(home)
    if how == "sigil verify":
        r = subprocess.run([py, "-m", "sigil", "verify"], env=env, capture_output=True, text=True)
        assert r.returncode == 0 and "head  OK" in r.stdout, r.stdout + r.stderr
    else:
        code = ("from sigil.spine.checkpoint import verify_checkpoint\n"
                "from sigil.spine.store import SpineStore\nfrom sigil import config\n"
                "print(verify_checkpoint(SpineStore(config.SPINE_PATH))[0])")
        r = subprocess.run([py, "-c", code], env=env, capture_output=True, text=True)
        assert r.stdout.strip() == "True", r.stdout + r.stderr
    assert _whole_tree(home / "spine" / "keys") == before          # byte-identical: no mint, owner.pub kept


@pytest.mark.parametrize("case", ["no_public_key", "public_key_unreadable"])
def test_verify_with_no_readable_owner_public_key_fails_closed_and_never_mints(tmp_path, case):
    """A signed head exists, so a missing owner.pub is never a first use: ``sigil verify`` must not mint a keypair
    (re-keying the trust root and calling the genuine head TAMPERING). It fails closed naming the missing key, and
    a public key that exists but cannot be read is reported as that read error, never as absent."""
    import subprocess
    home = _signed_home(tmp_path, pruned=False)
    kd = home / "spine" / "keys"
    (kd / "owner.priv").unlink()
    (kd / "owner.pub").unlink()
    if case == "public_key_unreadable":
        (kd / "owner.pub").mkdir()                     # present but unreadable (EISDIR): not "absent"
    before = _whole_tree(kd)
    env, py = _env(home)
    r = subprocess.run([py, "-m", "sigil", "verify"], env=env, capture_output=True, text=True)
    if case == "no_public_key":
        assert "head  FAIL: no owner public key" in r.stdout, r.stdout + r.stderr
    else:
        assert "head  FAIL" in r.stdout and "Is a directory" in r.stdout, r.stdout + r.stderr
        assert "no owner public key" not in r.stdout
    assert _whole_tree(kd) == before                   # nothing minted: no owner.priv, owner.pub untouched


def test_a_drill_of_a_home_with_no_owner_public_key_names_it_and_never_mints(tmp_path):
    """Verifying the PRUNED copy of a home that lost owner.pub minted a keypair into the scratch home and then
    blamed an 'isolation fault'. The drill now fails on the real cause, and no private key appears anywhere."""
    home = _signed_home(tmp_path, pruned=True)
    (home / "spine" / "keys" / "owner.pub").unlink()
    before = _whole_tree(home)
    v = ud.run_upgrade_drill(home / "spine" / "spine.jsonl", tmp_path / "work")
    assert v["status"] == ud.FAIL and "no owner public key" in v["detail"], v
    assert "isolation fault" not in v["detail"]
    assert not [p for p in (tmp_path / "work").rglob("*") if p.name.endswith(".priv")]
    assert _whole_tree(home) == before


@pytest.mark.parametrize("leak", ["owner.priv", "tmp/spine.dek", "home/spine/keys/owner.priv.tmp"])
def test_a_private_key_in_the_work_dir_fails_the_drill(tmp_path, monkeypatch, leak):
    path = _real_spine(tmp_path)
    real = ud._run_isolated

    def leaky(data, work):
        res = real(data, work)
        (work / leak).parent.mkdir(parents=True, exist_ok=True)
        (work / leak).write_text("leaked")
        return res
    monkeypatch.setattr(ud, "_run_isolated", leaky)
    v = ud.run_upgrade_drill(path, tmp_path / "work")
    assert v["status"] == ud.FAIL and "secret key material" in v["detail"], v


def test_the_drill_steps_refuse_a_copy_holding_a_private_key(tmp_path):
    path = _real_spine(tmp_path)
    home = tmp_path / "work" / "home"
    assert ud._snapshot(path.parent, path.name, home) is not None
    (home / "spine" / "keys").mkdir()
    (home / "spine" / "keys" / "owner.priv").write_text("x")
    v = ud.drill_copy(home / "spine" / path.name, tmp_path / "work")
    assert v["status"] == ud.FAIL and "secret key material" in v["detail"]
    assert not any(st["step"] == "upgrade" for st in v["steps"])


@pytest.mark.parametrize("scope", ["foreign_home", "foreign_tmp", "data_outside_copy", "no_nonce", "wrong_nonce",
                                   "scoped"])
def test_the_isolated_child_refuses_unless_scoped_to_its_copy(tmp_path, capsys, monkeypatch, scope):
    """The child runs the steps only on a copy its parent made: the parent's one-shot nonce matches (and is consumed),
    the data path is the work dir's scratch copy, its SIGIL_HOME is the scratch home, and its temp dir (where the
    upgrade's backup-verify extract lands) is inside the work dir."""
    from sigil import config
    path = _real_spine(tmp_path)
    work = tmp_path / "work"
    home = work / "home"
    assert ud._snapshot(path.parent, path.name, home) is not None
    if scope != "no_nonce":
        (work / ud._NONCE_FILE).write_text("a" * 32)
        monkeypatch.setenv(ud._NONCE_ENV, "b" * 32 if scope == "wrong_nonce" else "a" * 32)
    if scope != "foreign_home":
        monkeypatch.setattr(config, "SIGIL_HOME", home)
    if scope != "foreign_tmp":
        (work / "tmp").mkdir()
        monkeypatch.setattr(ud.tempfile, "tempdir", str(work / "tmp"))
    data = path if scope == "data_outside_copy" else home / "spine" / path.name
    before = ud._tree_digest(path.parent)
    assert ud.main([ud._CHILD_FLAG, str(data), "--work-dir", str(work)]) == 0
    res = json.loads(capsys.readouterr().out)
    assert not (work / ud._NONCE_FILE).exists()                            # one-shot: consumed either way
    if scope == "scoped":
        assert res["status"] == ud.PASS, res                               # positive control
    else:
        assert res["status"] == ud.FAIL and "not scoped to its copy" in res["detail"], res
        assert not list(work.rglob("*.tar.gz"))                            # refused before any step ran
        assert ud._tree_digest(path.parent) == before


@pytest.mark.parametrize("work", ["the_real_home", "the_real_homes_parent"])
def test_the_hidden_child_entry_point_never_runs_on_a_real_home(tmp_path, work):
    """The audit repro: ``SIGIL_HOME=$H TMPDIR=$H/x python -m sigil.spine.upgrade_drill --isolated-copy
    $H/spine/spine.jsonl --work-dir $H`` ran upgrade(), the corruption and the rollback on the REAL spine. Run with
    the real home as the work dir, or with its parent (the real home is then literally ``<work>/home``, so every
    path check passes and only the parent's nonce stops it), it refuses and the real home is byte-identical."""
    import subprocess
    path = _real_spine(tmp_path)                                           # the real home is <tmp>/home
    real_home = path.parent.parent
    wd = real_home if work == "the_real_home" else tmp_path
    (wd / "x").mkdir()
    before = _whole_tree(real_home)
    env, py = _env(real_home)
    env["TMPDIR"] = str(wd / "x")
    r = subprocess.run([py, "-m", "sigil.spine.upgrade_drill", ud._CHILD_FLAG, str(path), "--work-dir", str(wd)],
                       env=env, capture_output=True, text=True)
    res = json.loads(r.stdout.strip().splitlines()[-1])
    assert res["status"] == ud.FAIL and "not scoped to its copy" in res["detail"], res
    assert _whole_tree(real_home) == before and not (real_home / "backups").exists()


def test_the_copy_is_verified_against_the_boxs_own_anti_rollback_floor(tmp_path):
    """The snapshot carries the sibling anti-rollback floor, so the copy is verified exactly as the box verifies
    itself: a durable floor the real head violates FAILS the drill (as ``sigil verify`` would) — it is not
    silently dropped from the copy."""
    home = _signed_home(tmp_path, pruned=True)
    floor = json.loads((home / "floor.json").read_text())
    floor["entry_count"] += 1000                                   # the signed head is now BELOW the floor
    (home / "floor.json").write_text(json.dumps(floor))
    v = ud.run_upgrade_drill(home / "spine" / "spine.jsonl", tmp_path / "work")
    assert v["status"] == ud.FAIL and v["detail"].startswith("the real spine (copied) does not verify"), v
    assert "TAMPERING" in v["detail"], v
