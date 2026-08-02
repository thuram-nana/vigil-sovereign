"""Durable, file-backed anti-rollback high-water floor (namespace-pure core, VF-1b).

A tiny, dependency-minimal twin of the sovereign spine floor (``apps/sigil/sigil/spine/floor.py``) and the
offense evidence twin (``framework/v2/evidence/cli.py:_load_highwater``), promoted into ``vigil_core`` so an
offense-side, framework-free consumer (the Continuous Attestation Log, VF-1b) can persist a monotonic floor
WITHOUT importing either app. It stores exactly the two monotonic quantities a :class:`SignedChainHead`
anchors::

    {"schema_version": 1, "entry_count": N, "last_seq": M}

``entry_count`` is the **PRIMARY** monotonic guard. ``last_seq`` is 0-indexed, so it reads 0 for BOTH an
empty chain AND a one-record chain — a 1→0 truncation would slip past a ``last_seq``-only check but is
caught by ``entry_count`` (this is the exact lesson the sovereign floor's docstring records). Both are
checked; ``entry_count`` is the one that cannot be fooled by the 0-index degeneracy.

Deterministic (no wallclock / rng), stdlib + ``vigil_core`` only, so it stays importable in BOTH the
sovereign and offense process without co-loading ``framework`` or ``sigil`` (the P5 two-env boundary).

HONEST LIMIT (do NOT overclaim, mirrors the sovereign floor §1.3): this is a **LOCAL** floor — an UNSIGNED
file at 0600. A SAME-HOST attacker with the owner's UID (or root) defeats the local verify path by rewriting
the log AND this floor together (a local verifier re-reads the floor from that same attacker-controlled
disk). The floor's real anti-rollback guarantee therefore holds only against (i) an attacker who can
overwrite the log/head but NOT this floor, and (ii) an OUT-OF-BAND verifier that retained a newer floor. A
fully-dishonest producer that rewrites everything is closed only by the out-of-band witness (VF-1c), not by
this file. What this module DOES give, unconditionally, is last-writer-MONOTONIC, downgrade-refusing,
crash-safe advance under a cross-process lock — so no honest process ever lowers the floor, even racing.
"""
from __future__ import annotations

import json
import os
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator, Optional, Union

try:
    import fcntl
except ImportError:  # pragma: no cover — non-POSIX; the advance degrades to best-effort (single host)
    fcntl = None  # type: ignore[assignment]

_PathLike = Union[str, os.PathLike]
_SCHEMA_VERSION = 1


class HighWaterError(ValueError):
    """A PRESENT-but-unreadable / malformed floor. Raised (never silently treated as absent) so a corrupt
    floor fails CLOSED — reading it as "no floor" would fail-OPEN the whole anti-rollback guarantee."""


class HighWaterDowngrade(HighWaterError):
    """The INTENDED refusal: an advance whose head would lower a monotonic field of the floor (a stale
    concurrent writer, or a rolled-back head). Typed distinctly from a load/write FAILURE so a caller can
    treat this one as a benign 'someone already advanced higher' while surfacing a real IO error loudly."""


def _is_nonneg_int(x: object) -> bool:
    # bool is an int subclass — reject it explicitly so a JSON `true` cannot masquerade as a count.
    return isinstance(x, int) and not isinstance(x, bool) and x >= 0


def _lock_path(p: Path) -> Path:
    return p.parent / (p.name + ".lock")


def load_highwater(path: _PathLike) -> Optional[dict]:
    """Read the durable floor at ``path``. ``None`` iff ABSENT (pre-floor / never-advanced — floor checks are
    then skipped, byte-identical to no floor). RAISES :class:`HighWaterError` on a PRESENT-but-corrupt or
    shape-invalid floor: that is suspicious (tamper / a partial write that survived) and must fail CLOSED,
    never read as absent. Returns the normalised ``{"entry_count": N, "last_seq": M}`` (both non-negative
    ints); extra persisted fields (schema_version) are dropped from the returned view."""
    p = Path(path)
    if not p.exists():
        return None
    try:
        raw = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as e:
        raise HighWaterError(f"durable high-water at {p} is present but unreadable/corrupt: {e}") from e
    if not isinstance(raw, dict):
        raise HighWaterError(f"durable high-water at {p} is not a JSON object (possible tamper)")
    ec, ls = raw.get("entry_count"), raw.get("last_seq")
    if not (_is_nonneg_int(ec) and _is_nonneg_int(ls)):
        raise HighWaterError(f"durable high-water at {p} has a missing/invalid entry_count/last_seq "
                             f"(possible tamper): entry_count={ec!r} last_seq={ls!r}")
    return {"entry_count": int(ec), "last_seq": int(ls)}


def check_highwater(head, hw: Optional[dict]) -> tuple[bool, str]:
    """Reject rule (pure, side-effect-free, so it is shared by the write path's downgrade guard AND every
    read path). A validly-signed ``head`` that nonetheless sits below the floor is a ROLLBACK (stale-head
    replay / truncated log). ``hw is None`` ⇒ pass (byte-identical to no floor). ``entry_count`` is checked
    FIRST because it is the sound guard (``last_seq`` is 0 for both an empty and a 1-record chain)."""
    if hw is None:
        return True, "no durable high-water floor"
    if int(head.entry_count) < int(hw["entry_count"]):
        return False, (f"ROLLBACK: head entry_count {head.entry_count} < durable floor entry_count "
                       f"{hw['entry_count']} (truncated log / stale head replay)")
    if int(head.last_seq) < int(hw["last_seq"]):
        return False, (f"ROLLBACK: head last_seq {head.last_seq} < durable floor last_seq "
                       f"{hw['last_seq']} (stale head / truncated log replay)")
    return True, "within durable high-water floor"


@contextmanager
def highwater_lock(path: _PathLike) -> Iterator[None]:
    """Exclusive CROSS-PROCESS lock serializing a floor advance (and any log/head write a caller wants inside
    the same critical section) so the load→check→write triple is ATOMIC and last-writer-MONOTONIC, not
    last-writer-wins. Without it two racing advances each read a STALE prior floor, both pass the downgrade
    guard, and the later ``os.replace`` rolls the floor BACKWARDS — a false-clean window for a stale replay.
    The flock binds to a sibling ``<name>.lock`` inode so it survives the atomic replace of the floor file.
    Best-effort where ``fcntl`` is absent / the lockfile is unwritable (single-host assumption)."""
    p = Path(path)
    lockp = _lock_path(p)
    fd = None
    try:
        try:
            lockp.parent.mkdir(parents=True, exist_ok=True)
            fd = os.open(str(lockp), os.O_RDWR | os.O_CREAT, 0o600)
            if fcntl is not None:
                try:
                    fcntl.flock(fd, fcntl.LOCK_EX)
                except OSError:  # pragma: no cover — lock unsupported on this fs; degrade best-effort
                    pass
        except OSError:
            # Cannot create/open the lockfile (read-only dir, root-owned stray lock, ENOSPC). DEGRADE to
            # best-effort UNLOCKED rather than brick the append; a genuinely unwritable dir then fails loudly
            # at the atomic write below, never silently.
            fd = None
        yield
    finally:
        if fd is not None:
            os.close(fd)


def _atomic_write_0600(p: Path, text: str) -> None:
    """Crash-safe, owner-only write: temp → fsync → os.replace → dir-fsync, 0600 throughout. A partial write
    can only ever leave the ``.tmp-*`` file (never a half-written floor), and the rename is atomic."""
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.parent / (f".{p.name}.tmp-{os.getpid()}")
    fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(fd, text.encode("utf-8"))
        os.fsync(fd)
    finally:
        os.close(fd)
    os.replace(str(tmp), str(p))
    try:
        os.chmod(p, 0o600)
    except OSError:  # pragma: no cover — non-POSIX / unusual fs; content is non-secret, mode is best-effort
        pass
    try:
        dfd = os.open(str(p.parent), os.O_RDONLY)
        try:
            os.fsync(dfd)
        finally:
            os.close(dfd)
    except OSError:  # pragma: no cover — dir fsync unsupported; the os.replace already committed the name
        pass


def _floor_dict(head) -> dict:
    return {"schema_version": _SCHEMA_VERSION,
            "entry_count": int(head.entry_count), "last_seq": int(head.last_seq)}


def advance_highwater(path: _PathLike, head, *, _locked: bool = False) -> dict:
    """Advance the durable floor to a just-committed ``head`` — UPWARD-ONLY. The load→check→write runs under
    :func:`highwater_lock` and the prior floor is RE-LOADED inside the lock, so a concurrent advance that
    already wrote a HIGHER floor is observed and this stale write is REFUSED (raises :class:`HighWaterDowngrade`)
    — making the floor last-writer-MONOTONIC, never last-writer-wins. Refuses to lower any monotonic field —
    the exact thing the floor exists to prevent. Written atomically at 0600 only after the check passes.
    ``_locked=True`` when the caller already holds :func:`highwater_lock` for the same critical section
    (append_tick does) — the re-load + downgrade guard still run (defense in depth), the lock is not re-taken.
    Returns the persisted floor dict."""
    p = Path(path)
    if _locked:
        return _advance_locked(p, head)
    with highwater_lock(p):
        return _advance_locked(p, head)


def _advance_locked(p: Path, head) -> dict:
    prior = load_highwater(p)                       # RE-LOAD under the lock — sees a racing advance / tamper
    if prior is not None:
        ok, msg = check_highwater(head, prior)
        if not ok:
            raise HighWaterDowngrade(f"refusing to advance the durable high-water DOWNWARD: {msg}")
    new = _floor_dict(head)
    _atomic_write_0600(p, json.dumps(new, sort_keys=True))
    return new
