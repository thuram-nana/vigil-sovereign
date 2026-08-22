"""W11-4 — resource exhaustion MUST fail closed on the audit/spine writer.

The single most load-bearing safety claim VIGIL makes about its audit trail is *fail-closed on an
unwritable audit*: when the append-only, signed spine cannot durably accept a record, the writer must
REFUSE (raise) rather than return as if the action were audited. A silent success there means an action
proceeds with no tamper-evident record — the exact failure mode the sovereign contract forbids.

:class:`vigil_integration.live.spine_vigilcore.VigilCoreSpine` is that audit/spine writer (a real
Ed25519-signed, hash-chained, append-only file bound to the F2 checkpoint seams). Its
:meth:`VigilCoreSpine.writer` / :meth:`VigilCoreSpine.write_state` contract is explicit: *errors are NOT
swallowed (durability must surface)* and the in-memory append point is advanced ONLY after a successful
durable write. Until this file, that claim had no test under the conditions it names.

This module puts the writer into each named exhaustion state and asserts it fails CLOSED — it raises and
does NOT advance the append point, so a caller can never mistake the failed write for a persisted one —
each paired with a negative control that the SAME operation succeeds when the resource is available (so
the refusal is the condition, not a broken code path):

  1. UNWRITABLE audit sink — the spine path's parent is a regular file, so ``open(path, "a")`` raises
     ``ENOTDIR`` (uid-independent: it does not rely on filesystem permissions, which ``root`` bypasses).
  2. DISK-FULL (``ENOSPC``) — the append write is monkeypatched to raise ``OSError(ENOSPC)``. This is the
     test that PINS the "fail-closed on an unwritable audit" claim (registered in the W0-3 #398 registry).
  3. FD EXHAUSTION (``RLIMIT_NOFILE``) — in a forked child we lower ``RLIMIT_NOFILE`` and exhaust the fd
     table, so the append's ``open`` raises ``EMFILE``; the child reports whether the writer failed closed.
  4. OOM (bounded ``MemoryError`` simulation) — the append write is monkeypatched to raise ``MemoryError``
     (a deterministic stand-in for ``RLIMIT_AS``/OOM, which real setrlimit reproduces only flakily). The
     writer must propagate it, never a silent success.

FATAL-2 aware: imports only ``vigil_core`` + ``vigil_integration`` (checkpoint/state/spine); no ``sigil``
and no ``framework``. Runs in the required ``integration two-env boundary (P5)`` CI job.
"""

from __future__ import annotations

import builtins
import errno
import os

import pytest

from vigil_core import generate_keypair
from vigil_integration.agent.state import AgentState, Finding, Phase
from vigil_integration.live.spine_vigilcore import VigilCoreSpine

# --- helpers ----------------------------------------------------------------------------------------


def _kp():
    return generate_keypair()


def _state(slug: str = "eng-exhaust") -> AgentState:
    """A realistic snapshot: one oracle-confirmed FACT with a signed evidence ref, so the record that
    would be persisted is non-trivial (the writer serialises + signs it before the durable append)."""
    st = AgentState(engagement_slug=slug, phase=Phase.EXPLOITATION, iteration=1, objective="own the box")
    st.record_fact(Finding(ref="f-sqli", bug_class="sqli", title="auth bypass", severity="critical"),
                   evidence_ref="cert:evi-1")
    return st


def _assert_failed_closed(spine: VigilCoreSpine) -> None:
    """After a refused append the writer must NOT have advanced its append point and must have persisted
    nothing — otherwise a failed write is indistinguishable from a durable one (fail-OPEN)."""
    assert spine._last_entry is None, "append point advanced despite a refused write (fail-open on durability)"
    assert spine.head_seq() == 0, "a record surfaced on the spine despite a refused write (silent success)"


# ============================================================================================
# (1) UNWRITABLE audit sink — the load-bearing kernel claim, tested directly.
# ============================================================================================


def test_unwritable_audit_sink_refuses_the_action(tmp_path):
    """The spine's parent path is a regular FILE, so the durable append cannot open its target and the
    writer RAISES rather than returning as if audited. Negative control (same run): a writable sink
    accepts the identical write and the record is durably persisted."""
    # unwritable: parent-is-a-file -> ENOTDIR on open("a"), independent of uid/permissions.
    blocker = tmp_path / "blocker"
    blocker.write_text("i am a file, not a directory\n", encoding="utf-8")
    bad = VigilCoreSpine(_kp(), str(blocker / "sub" / "eng.spine"))
    with pytest.raises(OSError) as ei:
        bad.write_state(_state(), seq=1)
    assert ei.value.errno == errno.ENOTDIR
    _assert_failed_closed(bad)

    # negative control: a writable sink succeeds -> proving the refusal is the unwritable condition,
    # not a code path that never persists.
    (tmp_path / "ok").mkdir()
    good = VigilCoreSpine(_kp(), str(tmp_path / "ok" / "eng.spine"))
    good.write_state(_state(), seq=1)
    assert good.head_seq() == 1
    assert good.verify() is True


# ============================================================================================
# (2) DISK-FULL (ENOSPC) — pins "fail-closed on an unwritable audit" (registered in W0-3 #398).
# ============================================================================================


class _NoSpaceFile:
    """A file-like whose write raises ENOSPC — a faithful, deterministic disk-full at the exact moment
    the audit record is written to the sink."""

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def write(self, *_a, **_k):
        raise OSError(errno.ENOSPC, "No space left on device")

    def flush(self):  # pragma: no cover — never reached; write raises first
        pass

    def fileno(self):  # pragma: no cover — never reached
        return -1


def test_disk_full_enospc_refuses_and_does_not_advance(tmp_path, monkeypatch):
    """Simulate ENOSPC on the durable append: the writer must RAISE and must not advance the append
    point (never a silent success). Negative control (same run): with the patch lifted, the SAME writer
    on the SAME file persists the record, so the refusal is the disk-full condition, not a dead path.

    This is the test the claims registry (W0-3 #398) pins the 'fail-closed on an unwritable audit'
    claim to."""
    spine_path = str(tmp_path / "eng.spine")
    spine = VigilCoreSpine(_kp(), spine_path)

    real_open = builtins.open

    def fake_open(file, mode="r", *a, **k):
        if os.fspath(file) == spine_path and "a" in mode:
            return _NoSpaceFile()
        return real_open(file, mode, *a, **k)

    monkeypatch.setattr(builtins, "open", fake_open)
    with pytest.raises(OSError) as ei:
        spine.write_state(_state(), seq=1)
    assert ei.value.errno == errno.ENOSPC
    _assert_failed_closed(spine)

    # negative control: disk-full lifted -> the identical append now succeeds durably.
    monkeypatch.undo()
    spine.write_state(_state(), seq=1)
    assert spine.head_seq() == 1
    assert spine.verify() is True


# ============================================================================================
# (3) FD EXHAUSTION (RLIMIT_NOFILE) — a real, lowered rlimit in a forked child.
# ============================================================================================


def _run_in_child(fn) -> int:
    """Run ``fn`` in a forked child and return its exit code. ``fn`` returns the code to exit with,
    computed from what it observed. Forking isolates the destructive rlimit/fd changes from the parent
    pytest process entirely (the parent's fd table and limits are never touched)."""
    if not hasattr(os, "fork"):  # pragma: no cover — POSIX only; CI is Linux
        pytest.skip("os.fork unavailable on this platform")
    pid = os.fork()
    if pid == 0:  # child
        code = 99
        try:
            code = int(fn())
        except BaseException:  # noqa: BLE001 — any unexpected escape in the child is a distinct failure code
            code = 98
        finally:
            os._exit(code)
    _pid, status = os.waitpid(pid, 0)
    return os.WEXITSTATUS(status) if os.WIFEXITED(status) else 97


# child exit codes (shared vocabulary between child and parent assertions)
_FAILED_CLOSED = 0     # the writer raised under exhaustion — correct
_SILENT_SUCCESS = 10   # the writer RETURNED under exhaustion — the bug this test guards against
_SETUP_FAILED = 11     # could not reach the exhausted state (e.g. could not exhaust fds) — inconclusive
_CONTROL_BROKEN = 12   # the pre-exhaustion control write did not persist — the path is dead, not gated


def _fd_exhaustion_child(spine_path: str, kp_pub: str, kp_priv: str) -> int:
    import resource
    from types import SimpleNamespace

    kp = SimpleNamespace(public_key_b64=kp_pub, private_key_b64=kp_priv)
    spine = VigilCoreSpine(kp, spine_path)

    # negative control INSIDE the child, BEFORE exhaustion: a normal append persists.
    spine.write_state(_state(), seq=1)
    if spine.head_seq() != 1:
        return _CONTROL_BROKEN

    # lower the soft fd limit, then exhaust the table so any further open() raises EMFILE.
    _soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    resource.setrlimit(resource.RLIMIT_NOFILE, (64, hard))
    held = []
    try:
        while True:
            held.append(os.open(os.devnull, os.O_RDONLY))
    except OSError:
        pass  # table exhausted
    # confirm we really are out of fds, else the test is inconclusive.
    try:
        probe = os.open(os.devnull, os.O_RDONLY)
        os.close(probe)
        return _SETUP_FAILED
    except OSError:
        pass

    try:
        spine.write_state(_state(), seq=2)   # the audit append's open() must now fail (EMFILE)
    except Exception:  # noqa: BLE001 — any raised append is fail-closed (what we want)
        return _FAILED_CLOSED
    finally:
        for fd in held:
            try:
                os.close(fd)
            except OSError:
                pass
    return _SILENT_SUCCESS   # the writer returned despite fd exhaustion — the durability bug


def test_fd_exhaustion_rlimit_nofile_refuses(tmp_path):
    """Under a lowered RLIMIT_NOFILE with the fd table exhausted, the audit append cannot open its file
    and the writer fails closed. The child also runs the negative control (a normal append persists
    before exhaustion), so a passing test proves the refusal is caused by fd exhaustion, not a dead
    path."""
    kp = _kp()
    code = _run_in_child(
        lambda: _fd_exhaustion_child(str(tmp_path / "eng.spine"), kp.public_key_b64, kp.private_key_b64)
    )
    assert code != _CONTROL_BROKEN, "pre-exhaustion control write did not persist (dead path, not a gate)"
    assert code != _SETUP_FAILED, "could not exhaust the fd table — test inconclusive"
    assert code != _SILENT_SUCCESS, "the audit writer RETURNED under fd exhaustion (fail-OPEN on durability)"
    assert code == _FAILED_CLOSED, f"unexpected child outcome code {code}"


# ============================================================================================
# (4) OOM — bounded MemoryError simulation on the durable append.
# ============================================================================================


class _OOMFile:
    """A file-like whose write raises MemoryError — a deterministic, bounded stand-in for an OOM /
    RLIMIT_AS failure at the moment the audit record is written (real setrlimit(RLIMIT_AS) reproduces
    OOM only flakily and can kill the interpreter unpredictably)."""

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def write(self, *_a, **_k):
        raise MemoryError("cannot allocate memory for the audit append")

    def flush(self):  # pragma: no cover
        pass

    def fileno(self):  # pragma: no cover
        return -1


def test_oom_memoryerror_on_append_refuses_and_does_not_advance(tmp_path, monkeypatch):
    """A MemoryError raised while writing the audit record must PROPAGATE out of the writer (never a
    silent success) and must not advance the append point. Negative control (same run): with memory
    available the identical append persists."""
    spine_path = str(tmp_path / "eng.spine")
    spine = VigilCoreSpine(_kp(), spine_path)

    real_open = builtins.open

    def fake_open(file, mode="r", *a, **k):
        if os.fspath(file) == spine_path and "a" in mode:
            return _OOMFile()
        return real_open(file, mode, *a, **k)

    monkeypatch.setattr(builtins, "open", fake_open)
    with pytest.raises(MemoryError):
        spine.write_state(_state(), seq=1)
    _assert_failed_closed(spine)

    # negative control: memory available -> the identical append persists durably.
    monkeypatch.undo()
    spine.write_state(_state(), seq=1)
    assert spine.head_seq() == 1
    assert spine.verify() is True
