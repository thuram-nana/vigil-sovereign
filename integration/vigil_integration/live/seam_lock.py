"""seam_lock — the ONE hardened cross-process file lock behind the money seam's locks (E3bc).

``locked_file(path)`` holds an advisory ``flock`` on ``path`` for the duration of a ``with`` block. Every
cross-process lock on the settle path goes through it: the launch settle lock beside the spine
(``sigil.governor.launch_settlement.settle_lock``), the per-slug settlement / pause / paused-past-expiry marker
locks (``credit_lease_broker._marker_lock``) and the completion spool lock (``<spool>/.spool.lock``). It is
hardened against a hostile or broken seam directory, so a lock can never hang a holder of the global settle
lock and never follows an attacker's link:

  * opened ``O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK`` (a planted symlink fails, a FIFO never blocks the open), then
    ``fstat``-ed: anything but a regular file raises ``OSError``;
  * the wait is BOUNDED: ``flock(... | LOCK_NB)`` is polled every 20 ms until ``wait_s``, then :class:`LockBusy`
    (an ``OSError``) is raised — the caller turns it into a retry or a refusal, never a block;
  * FAIL-CLOSED: without ``fcntl`` (non-POSIX) it raises ``OSError`` instead of silently degrading to an
    in-process lock.

``create=False`` is for a reader that must not leave a lock file the owner of the directory cannot open: an
absent lock file is created ``O_EXCL`` and, when this process is root, ``fchown``-ed to ``chown_like``'s owner
(so a ``sudo ops-sweep`` never strands the drain's own lock).

LEAF-LOCK RULES (the settle lock order is ``_publish_lock`` -> ``spine_lock`` -> the settle lock -> leaves):
  * R2 — a holder of a leaf lock (a marker, pause, past-expiry or spool lock) never requests ``spine_lock`` or the
    settle lock, and leaves are never nested in each other;
  * R4 — the completion drain's file moves, the sweep's snapshot spool read and the pricing meter closes run
    outside the spine and settle locks, each taking at most one leaf at a time.

STDLIB ONLY and import-clean: safe to import on BOTH planes (no ``vigil_core``, no ``framework``).
"""

from __future__ import annotations

import os
import stat
import time
from contextlib import contextmanager
from typing import Any, Iterator, Optional

try:
    import fcntl  # POSIX advisory locks
except ImportError:  # pragma: no cover — non-POSIX: every lock fails closed (see locked_file)
    fcntl = None  # type: ignore[assignment]

__all__ = ["LockBusy", "locked_file", "POLL_S"]

#: How often a busy lock is re-tried while waiting.
POLL_S = 0.02


class LockBusy(OSError):
    """The lock is held by someone else for longer than the bounded wait (retry later; nothing was done)."""


def _open_flags(base: int) -> int:
    return base | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NONBLOCK", 0)


def _open(path: str, *, shared: bool, create: bool, chown_like: Any) -> int:
    if create:
        return os.open(path, _open_flags(os.O_RDWR | os.O_CREAT), 0o600)
    try:
        return os.open(path, _open_flags(os.O_RDONLY if shared else os.O_RDWR))
    except FileNotFoundError:
        pass
    try:
        fd = os.open(path, _open_flags(os.O_RDWR | os.O_CREAT | os.O_EXCL), 0o600)
    except FileExistsError:                      # another opener created it first: open theirs
        return os.open(path, _open_flags(os.O_RDONLY if shared else os.O_RDWR))
    try:
        if chown_like is not None and hasattr(os, "geteuid") and os.geteuid() == 0:
            st = os.stat(os.fspath(chown_like))
            os.fchown(fd, st.st_uid, st.st_gid)  # a root opener never leaves a lock the directory's owner cannot open
    except OSError:
        os.close(fd)
        raise
    return fd


@contextmanager
def locked_file(path: Any, *, shared: bool = False, wait_s: float = 5.0, create: bool = True,
                chown_like: Optional[Any] = None) -> Iterator[None]:
    """Hold ``flock(path)`` (``LOCK_SH`` when ``shared``, else ``LOCK_EX``) for the ``with`` block; see the module
    docstring. Raises :class:`LockBusy` after ``wait_s`` seconds of contention and ``OSError`` for an unusable lock
    file (a symlink, a FIFO, a directory, an unreadable path) or a platform without ``fcntl``; nothing is held when
    it raises."""
    if fcntl is None:
        raise OSError("cross-process lock unavailable on this platform (fail-closed)")
    p = os.fspath(path)
    fd = _open(p, shared=shared, create=create, chown_like=chown_like)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise OSError(f"lock path is not a regular file (fail-closed): {os.path.basename(p)}")
        op = (fcntl.LOCK_SH if shared else fcntl.LOCK_EX) | fcntl.LOCK_NB
        deadline = time.monotonic() + max(0.0, float(wait_s))
        while True:
            try:
                fcntl.flock(fd, op)
                break
            except BlockingIOError:
                if time.monotonic() >= deadline:
                    raise LockBusy(f"lock busy after {float(wait_s):g}s: {os.path.basename(p)}") from None
                time.sleep(POLL_S)
        yield
    finally:
        os.close(fd)                             # closing the fd releases the flock
