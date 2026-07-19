"""SIGIL spine rotation — Slice 3 CRASH-FUZZ GATE (required before merge).

Rotation moves data + swaps a manifest, so its cutover must be crash-atomic: after a crash at ANY barrier
the spine must reconstruct verify()-clean, with every ACKED record present, no duplicate seq, and no seq-0
fork. This harness forks a child that migrates + appends with a tiny rotation threshold (sealing every few
records) and crashes it BOTH deterministically (at each labelled cutover barrier via SIGIL_SPINE_CRASH_AT)
and non-deterministically (SIGKILL at a random instant). The parent then proves recovery. A child records
every acked seq to an fsync'd ack-log BEFORE the parent may require it, so "an acked seq is missing" is a
provable data-loss failure.

Run: ~/.sigil/venv/bin/python -m pytest tests/test_spine_crashfuzz.py -q
"""
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import pytest

# The child: migrate a fresh store, then append forever (bounded) with a 4-record seal threshold, writing
# each ACKED seq to an fsync'd ack-log. A cutover-barrier crash (os._exit) or a SIGKILL ends it.
_CHILD = r"""
import os, sys
from pathlib import Path
from sigil.spine.store import SpineStore
d = Path(sys.argv[1])
ack = open(d / "acks.log", "w")
s = SpineStore(d / "spine.jsonl", seg_max_bytes=0, seg_max_records=4)
s.migrate()
for i in range(400):
    seq = s.append(kind="event", source="fuzz", actor="u", payload={"n": i})
    ack.write(str(seq) + "\n"); ack.flush(); os.fsync(ack.fileno())
"""


def _fresh_dir() -> Path:
    return Path(tempfile.mkdtemp(prefix="sigil-crashfuzz-"))


def _run_child(d: Path, *, crash_at: str | None = None, crash_skip: int = 0,
               kill_after: float | None = None) -> tuple[list[int], int]:
    env = dict(os.environ)
    if crash_at:
        env["SIGIL_SPINE_CRASH_AT"] = crash_at
        env["SIGIL_SPINE_CRASH_SKIP"] = str(crash_skip)
    proc = subprocess.Popen([sys.executable, "-c", _CHILD, str(d)], env=env,
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    if kill_after is not None:
        time.sleep(kill_after)
        proc.kill()                                  # SIGKILL — the un-catchable crash
    rc = proc.wait(timeout=30)
    ackf = d / "acks.log"
    acked = [int(x) for x in ackf.read_text().split()] if ackf.exists() else []
    return acked, rc


def _assert_recovers(d: Path, acked: list[int]) -> None:
    """The spine MUST reconstruct verify()-clean with every acked seq present, no dup, contiguous from
    genesis, and it must keep working (append + re-verify)."""
    from sigil.spine.store import SpineStore

    s = SpineStore(d / "spine.jsonl")                # __init__ must not crash (reconciler handles orphans)
    ok, reason = s.verify()
    assert ok, f"verify() FAILED after crash: {reason}"
    seqs = [r.seq for r in s.iter_records()]
    assert len(seqs) == len(set(seqs)), f"duplicate seq after crash: {seqs}"
    assert seqs == list(range(len(seqs))), f"non-contiguous / seq-0 fork after crash: {seqs[:4]}..{seqs[-4:]}"
    spine = set(seqs)
    for a in acked:
        assert a in spine, f"ACKED seq {a} LOST after crash (data loss)"
    # the store must remain writable + verifiable after recovery
    s.append(kind="event", source="recover", actor="u", payload={"recovered": True})
    ok2, reason2 = SpineStore(d / "spine.jsonl").verify()
    assert ok2, f"verify() FAILED after a recovery append: {reason2}"


@pytest.mark.parametrize("barrier", ["append_after_fsync", "seal_after_new_active", "seal_after_manifest"])
@pytest.mark.parametrize("skip", [0, 2, 5])
def test_crash_at_each_cutover_barrier(barrier, skip):
    """Deterministic: crash at each labelled cutover barrier, after `skip` prior occurrences (so the crash
    lands with 0, ~1, and several sealed segments already present). Recovery must be clean every time."""
    d = _fresh_dir()
    acked, rc = _run_child(d, crash_at=barrier, crash_skip=skip)
    assert rc == 137, f"child did not crash at barrier {barrier} (skip {skip}); rc={rc}"
    _assert_recovers(d, acked)


@pytest.mark.parametrize("trial", range(6))
def test_random_sigkill_during_rotation(trial):
    """Non-deterministic: SIGKILL the child at a random instant during a rotation-heavy append loop. Over
    several trials this lands mid-append and mid-seal; recovery must be clean every time."""
    d = _fresh_dir()
    delay = 0.03 + 0.02 * trial                      # 30ms .. 130ms — spans the first several seals
    acked, rc = _run_child(d, kill_after=delay)
    assert rc in (-9, 137), f"child exited unexpectedly (rc={rc})"
    _assert_recovers(d, acked)
