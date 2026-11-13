"""Fail-closed publication of owner-sealed revocable records to the cross-plane seam.

The keyless offense plane cannot fold the sovereign spine: for an eval-capability grant or an eval-offense
attestation it trusts the owner-sealed record list the sovereign PUBLISHES to the seam. A publish that fails
must therefore never leave an older publication in place, because that older list may still grant what the
spine has since revoked. Two helpers keep every publish fail-closed:

* :func:`encodable_or_revoke` - a record that cannot be canonicalised (a lone surrogate is only possible
  through a raw spine-file write) can be neither sealed nor written. Dropping it could drop a REVOKE, so it
  is replaced, in place, by an UNSIGNED revoke placeholder. The offense plane honours a revoke whoever signs
  it, so the placeholder can only ever un-grant.
* :func:`withdraw_publication` - on any publish failure the existing seam file is removed (or, when its
  directory cannot be written, emptied in place), so the offense plane falls back to default-ungranted /
  default-unattested instead of trusting a stale list. If even that is impossible it says so, and the caller
  must then fail LOUDLY rather than report a revoke the offense plane never saw. A withdrawal first raises the
  rollback floor, so the withdrawn file cannot be replayed onto the seam later (and is refused even if it could
  not be removed).
* :func:`publish_lock` - one publish at a time per spine (threads AND processes), across snapshot, seal seq,
  write and withdrawal, so an older record list can never be sealed with a newer seq and overwrite a revoke.
* :func:`retract_for_revoke` - a revoke raises the floor and removes the publication BEFORE it waits for the
  publish lock, so a revoke killed while it waits has already un-granted the offense plane.
* :func:`raise_close_alarm` / :func:`clear_close_alarm` - a durable alarm `vigil doctor` reports when a grant
  revoke could not be confirmed on the seam (an unreadable spine, or a publication that could be neither
  re-published nor withdrawn); only an offense close that reconciles every published grant clears it.
"""
from __future__ import annotations

import contextlib
import json
import logging
import os
import threading
import time
from pathlib import Path
from typing import Callable, Iterable, Iterator, Optional

from ..reuse import canonical_json
from ..spine.store import spine_lock

_log = logging.getLogger(__name__)

PLACEHOLDER_NOTE = "unencodable spine record (fail-closed revoke placeholder)"


def encodable_or_revoke(records: Iterable[dict], *, signal: str, engagement_slug: str) -> list:
    """``records`` with every record that cannot be canonicalised replaced by an unsigned revoke placeholder."""
    out = []
    for rec in records:
        try:
            canonical_json(rec)
        except (TypeError, ValueError):
            _log.error("seam publish: a %s record for %r cannot be canonicalised (tampered spine?); "
                       "publishing a revoke in its place", signal, engagement_slug)
            rec = {"signal": signal, "engagement_slug": engagement_slug, "state": "revoked",
                   "note": PLACEHOLDER_NOTE}
        out.append(rec)
    return out


def withdraw_publication(path_fn: Callable[[], Optional[Path]], *, what: str,
                         cause: Optional[BaseException] = None,
                         floor_fn: Optional[Callable[[], None]] = None) -> bool:
    """After a failed publish, make sure the offense plane can no longer honour the previous publication, so it
    falls back to default-ungranted rather than trusting a stale list. ``floor_fn`` FIRST raises the rollback floor
    above the previous file's seal seq: on its own that already makes the offense plane refuse the file as a
    rollback, so it covers a file that cannot be removed and a crash before the removal. The file is then removed;
    when its directory cannot be written (EACCES, an immutable directory) it is emptied in place instead, which
    needs only write access to the file the sovereign itself created, and the offense reader treats an
    unparseable file as no publication. Returns True only when the floor was raised AND no previous publication
    remains readable; False otherwise. Never raises: the caller is already handling ``cause``."""
    floor_ok = True
    if floor_fn is not None:
        try:
            floor_fn()
        except Exception:  # noqa: BLE001 - must not mask the original failure
            _log.critical("seam publish of %s FAILED and the offense rollback floor could NOT be raised, so a "
                          "replay of the previous publication would still be accepted", what, exc_info=True)
            floor_ok = False
    file_ok = _withdraw_file(path_fn, what=what, cause=cause)
    return floor_ok and file_ok


def retract_for_revoke(path_fn: Callable[[], Optional[Path]], *, what: str,
                       floor_fn: Callable[[], None]) -> bool:
    """The revoke direction, BEFORE waiting for the publish lock: raise the rollback floor, then remove the current
    publication. Always safe (it can only un-grant), and it means a revoke whose process is killed while it waits
    for the lock (the cockpit ceremonies kill a CLI after 60 s) has already left the offense plane ungranted. The
    publish that follows re-sends the full list and fails loudly if it cannot. Never raises; returns True when both
    steps succeeded."""
    ok = True
    try:
        floor_fn()
    except Exception:  # noqa: BLE001 - best effort; the publish that follows is the guarantee
        _log.error("revoke of %s: the rollback floor could not be raised ahead of the publish", what, exc_info=True)
        ok = False
    try:
        path = path_fn()
        if path is not None:
            path.unlink(missing_ok=True)
    except Exception:  # noqa: BLE001 - best effort; the publish that follows is the guarantee
        _log.error("revoke of %s: the publication could not be removed ahead of the publish", what, exc_info=True)
        ok = False
    return ok


def _withdraw_file(path_fn: Callable[[], Optional[Path]], *, what: str, cause: Optional[BaseException]) -> bool:
    try:
        path = path_fn()
    except Exception:  # noqa: BLE001 - must not mask the original failure
        _log.critical("seam publish of %s FAILED and its seam path could not be resolved: the previous "
                      "publication could NOT be withdrawn", what, exc_info=True)
        return False
    if path is None:
        _log.error("seam publish of %s FAILED; it has no seam path, so there is no publication to withdraw",
                   what, exc_info=cause)
        return True
    try:
        path.unlink()
    except FileNotFoundError:
        _log.error("seam publish of %s FAILED; there was no previous publication to withdraw", what,
                   exc_info=cause)
        return True
    except OSError:
        try:
            fd = os.open(str(path), os.O_WRONLY | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0))
            os.close(fd)
        except FileNotFoundError:
            return True
        except OSError:
            _log.critical("seam publish of %s FAILED and the previous publication could NOT be withdrawn "
                          "(neither removed nor emptied): the offense plane may still trust a stale list",
                          what, exc_info=True)
            return False
        _log.error("seam publish of %s FAILED: the previous publication was emptied in place (its directory is "
                   "not writable); the offense plane falls back to ungranted", what, exc_info=cause)
        return True
    _log.error("seam publish of %s FAILED: the previous publication was withdrawn (offense plane falls back to "
               "ungranted); the spine record stands and the next publish re-sends the full list", what,
               exc_info=cause)
    return True


# ---- one publish at a time per spine ------------------------------------------------------------------------
_HELD = threading.local()


@contextlib.contextmanager
def publish_lock(store) -> Iterator[None]:
    """Serialize seam publishes for ``store``: the process-wide spine lock (threads) plus an exclusive ``flock``
    on ``<spine>.seam-publish.lock`` (processes: the CLI and the cockpit). Re-entrant within a thread. Held across
    the record snapshot, the seal seq, the write and any withdrawal, so whichever publish runs last carries the
    newest list AND the newest seq. Fails closed: if the lock cannot be taken, this raises, and the caller's
    failure path withdraws the publication."""
    path = getattr(store, "path", None)
    rlock = spine_lock(path) if path is not None else _FALLBACK_RLOCK
    with rlock:
        depth = getattr(_HELD, "depth", 0)
        if depth or path is None:
            _HELD.depth = depth + 1
            try:
                yield
            finally:
                _HELD.depth = depth
            return
        import fcntl
        lock_path = Path(str(path) + ".seam-publish.lock")
        fd = os.open(str(lock_path), os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            _HELD.depth = 1
            try:
                yield
            finally:
                _HELD.depth = 0
        finally:
            os.close(fd)                   # closing the descriptor releases the flock


_FALLBACK_RLOCK = threading.RLock()


# ---- the offense-close alarm `vigil doctor` reports ----------------------------------------------------------
CLOSE_ALARM_NAME = "eval-grant-close-revoke.json"


def close_alarm_path() -> Path:
    """``$SIGIL_HOME/alarms/eval-grant-close-revoke.json`` (resolved at call time; doctor reads the same path)."""
    home = Path(os.path.expanduser(os.environ.get("SIGIL_HOME", "~/.sigil")))
    return home / "alarms" / CLOSE_ALARM_NAME


def raise_close_alarm(detail: str, *, cause: str = "spine_unreadable", failed: Iterable[str] = ()) -> None:
    """Record, durably, that a grant revoke could not be confirmed on the seam. ``cause`` is ``spine_unreadable``
    (an offense close could not read the spine; every published grant was withdrawn instead) or
    ``seam_unreconciled`` (one or more published grants could be neither re-published from the spine nor
    withdrawn, so they may still authorize; ``failed`` names them). Only an offense close that reconciles every
    published grant clears it. Never raises (logged CRITICAL instead): the close itself must still complete."""
    names = sorted({str(f)[:96] for f in failed})
    try:
        p = close_alarm_path()
        p.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        tmp = p.parent / (p.name + ".tmp")
        tmp.write_text(json.dumps({"detail": str(detail)[:500], "cause": str(cause)[:32], "failed": names[:50],
                                   "at": time.time()}), encoding="utf-8")
        os.chmod(tmp, 0o600)
        os.replace(tmp, p)
    except Exception:  # noqa: BLE001
        _log.critical("could not record the eval-capability grant revoke alarm (%s; unconfirmed: %s): %s", cause,
                      names, detail, exc_info=True)


def clear_close_alarm() -> None:
    """An offense close that revoked from a readable spine AND reconciled every published grant clears the alarm.
    Never raises."""
    try:
        close_alarm_path().unlink(missing_ok=True)
    except OSError:
        _log.error("could not clear the offense-close revoke alarm", exc_info=True)
