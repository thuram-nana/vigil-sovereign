"""xproc_lock — cross-process file-lock + on-disk counter primitives for fleet concurrency (Lane O / O1).

The fleet concurrency controls in :mod:`framework.v2.authority.fleet` (``ProofSerializer``,
``HostRateLimiter``, ``TenantBudget``) were built on ``threading.Lock`` — which coordinates only threads
WITHIN ONE PROCESS. The engagement scheduler (:mod:`framework.v2.engagement_scheduler`) is a MULTI-PROCESS
queue: N worker processes each claim and run engagements concurrently. So two worker processes could each
run a TIMING proof against the SAME target host at the same instant, phase-lock their baseline/treatment
alternation, and manufacture a FALSE ``time_based_sqli`` FACT (the ``timing-concurrency-phase-lock`` hazard)
— an in-process lock does nothing across processes, so the serial-proof-per-target invariant held only
within one worker and was INERT across the fleet.

This module supplies the cross-process substitutes, built on the same stdlib-only, ``crucible_root``-rooted,
``sha256``-keyed discipline proven in :mod:`framework.v2.slug_lease` /
``vigil_integration.live.nonce_ledger``:

  * :class:`XProcMutex` — a BLOCKING, cross-process, crash-safe exclusive lock per key, built on
    ``fcntl.flock``. A holder in process A blocks a would-be holder in process B until A releases; the
    kernel releases the lock automatically if the holder process dies, so a crashed proof never wedges a
    host. ``flock`` — NOT the ``O_CREAT | O_EXCL`` single-winner marker of ``slug_lease`` / ``nonce_ledger``
    — because PROOF serialization needs BLOCKING-QUEUE semantics (peers WAIT their turn; they are not
    refused) plus automatic release on crash, which is exactly ``flock``'s contract. The O_EXCL marker is
    the right primitive for a single-winner NON-blocking reservation (a single-use nonce, one live holder
    per slug with a refusal); a proof serializer is the other shape. Same filesystem discipline, the lock
    verb that fits the need.

  * :class:`XProcCounter` — a small on-disk JSON record keyed by key, read-modify-WRITTEN under its own
    ``flock`` so the whole read→modify→write is atomic across processes. It backs the per-host rate window
    and the per-tenant budget so N worker processes share ONE window / ONE budget, instead of each process
    keeping a private in-memory one that would multiply the real load / budget by the worker count.

Keys are hashed to a fixed ``[0-9a-f]{64}`` filename (no separators, no ``..``, no newline), so a key can
neither escape the marker directory nor collide with another. Stdlib only (``fcntl``, ``hashlib``, ``json``,
``os``) — no framework / strix / sigil import — so :mod:`framework.v2.authority.fleet` can use it without
crossing the two-env boundary.
"""
from __future__ import annotations

import fcntl
import hashlib
import json
import os
from contextlib import contextmanager
from pathlib import Path
from typing import Callable, Iterator

__all__ = ["XProcMutex", "XProcCounter"]


def _digest(key: str) -> str:
    # sha256 → fixed [0-9a-f]{64}: the key can neither escape the directory (no separators / '..') nor, via
    # any metacharacter/newline, name anything but its own file; distinct keys never collide.
    return hashlib.sha256(str(key).encode("utf-8")).hexdigest()


@contextmanager
def _flocked(path: Path) -> Iterator[int]:
    """Open ``path`` (creating it), take an EXCLUSIVE ``flock`` on it — blocking until no other process
    holds it — and yield the fd. On exit the lock is dropped and the fd closed; the kernel would also drop
    the lock automatically if this process died while holding it (crash-safe, no stale-reclaim needed)."""
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd = os.open(str(path), os.O_RDWR | os.O_CREAT, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)   # BLOCKS until exclusive across all processes
        yield fd
    finally:
        try:
            fcntl.flock(fd, fcntl.LOCK_UN)
        except OSError:
            pass
        os.close(fd)


class XProcMutex:
    """A blocking, cross-process, crash-safe exclusive lock per ``key``, under marker directory ``dir``.

    :meth:`hold` is a context manager: it blocks until no OTHER process holds this key's lock, then runs the
    body exclusively, releasing on exit even if the body raises. Because the lock is an ``flock`` on a per-key
    file, a holder that crashes mid-body has its lock released by the kernel — a dead proof never wedges the
    host, unlike an O_EXCL marker that would need explicit stale-reclaim."""

    def __init__(self, dir: "str | os.PathLike", key: str) -> None:
        self._path = Path(dir) / (_digest(key) + ".lock")

    @contextmanager
    def hold(self) -> Iterator[None]:
        with _flocked(self._path):
            yield


class XProcCounter:
    """A small durable JSON record keyed by ``key`` under ``dir``, read-modify-written atomically across
    processes. The record is an arbitrary JSON object; :meth:`mutate` applies a pure function under the
    key's own ``flock`` so of N concurrent processes each sees a consistent before-state and no update is
    lost. Used for the shared sliding-window rate counter and the shared tenant budget."""

    def __init__(self, dir: "str | os.PathLike", key: str) -> None:
        self._path = Path(dir) / (_digest(key) + ".ctr")

    @staticmethod
    def _load(fd: int) -> dict:
        os.lseek(fd, 0, os.SEEK_SET)
        chunks: list[bytes] = []
        while True:
            b = os.read(fd, 65536)
            if not b:
                break
            chunks.append(b)
        raw = b"".join(chunks).strip()
        if not raw:
            return {}
        try:
            obj = json.loads(raw.decode("utf-8", "replace"))
        except ValueError:
            return {}                       # a torn record reads as empty — the RMW rebuilds it
        return obj if isinstance(obj, dict) else {}

    @staticmethod
    def _store(fd: int, doc: dict) -> None:
        data = (json.dumps(doc, sort_keys=True) + "\n").encode("utf-8")
        os.ftruncate(fd, 0)
        os.lseek(fd, 0, os.SEEK_SET)
        os.write(fd, data)
        os.fsync(fd)

    def mutate(self, fn: Callable[[dict], "tuple[dict, object]"]) -> object:
        """Apply ``fn(current_doc) -> (new_doc, result)`` under this key's cross-process lock and persist
        ``new_doc``. Returns ``result``. The whole read→modify→write is atomic across processes."""
        with _flocked(self._path) as fd:
            doc = self._load(fd)
            new_doc, result = fn(doc)
            self._store(fd, new_doc)
            return result

    def read(self) -> dict:
        """The current record (``{}`` if absent/torn), read under the lock. Total."""
        with _flocked(self._path) as fd:
            return self._load(fd)
