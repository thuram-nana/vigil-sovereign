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
                         floor_fn: Optional[Callable[[], object]] = None) -> bool:
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
                       floor_fn: Callable[[], Optional[int]]) -> bool:
    """The revoke direction, BEFORE waiting for the publish lock: raise the rollback floor, then remove the current
    publication if it is sealed BELOW that floor (or is unsealed / unparseable). Always safe (it can only un-grant),
    and it means a revoke whose process is killed while it waits for the lock (the cockpit ceremonies kill a CLI
    after 60 s) has already left the offense plane ungranted. A publication sealed at or above the floor was
    written after this revoke's record, under the publish lock, so it already carries the revoke or a newer state:
    it is left in place. ``floor_fn`` returns the floor it raised. The publish that follows re-sends the full list
    and fails loudly if it cannot. Never raises; returns True when both steps succeeded."""
    ok = True
    floor: Optional[int] = None
    try:
        floor = floor_fn()
    except Exception:  # noqa: BLE001 - best effort; the publish that follows is the guarantee
        _log.error("revoke of %s: the rollback floor could not be raised ahead of the publish", what, exc_info=True)
        ok = False
    try:
        path = path_fn()
        if path is not None:
            seq, ino = _published_seal_seq(path)
            if ino is not None and (seq is None or floor is None or seq < floor):
                with contextlib.suppress(FileNotFoundError):
                    st = os.lstat(path)
                    if st.st_ino == ino:          # still the file this check read (not a newer publication)
                        path.unlink()
    except Exception:  # noqa: BLE001 - best effort; the publish that follows is the guarantee
        _log.error("revoke of %s: the publication could not be removed ahead of the publish", what, exc_info=True)
        ok = False
    return ok


def _published_seal_seq(path: Path) -> "tuple[Optional[int], Optional[int]]":
    """``(seal seq, inode)`` of the publication at ``path``: ``(None, None)`` when there is no file, ``(None, ino)``
    when it is unsealed or unparseable."""
    try:
        fd = os.open(str(path), os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except FileNotFoundError:
        return None, None
    try:
        ino = os.fstat(fd).st_ino
        with os.fdopen(fd, "rb", closefd=False) as fh:
            raw = fh.read(4 * 1024 * 1024)
    finally:
        os.close(fd)
    try:
        seq = json.loads(raw.decode("utf-8")).get("seal", {}).get("seq")
    except (ValueError, AttributeError, UnicodeDecodeError):
        return None, ino
    if isinstance(seq, int) and not isinstance(seq, bool) and seq >= 0:
        return seq, ino
    return None, ino


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


def published_slugs(root: Path, path_for: Callable[[str], Optional[Path]]) -> list:
    """The engagement slugs with a publication under ``root``: regular ``<slug>.json`` files whose name is exactly
    what ``path_for(slug)`` resolves to (a stray or unsafe name is skipped with a warning). A missing directory is
    "no publications"; any OTHER listing failure (EACCES, EIO, ESTALE) RAISES, so a seam that cannot be listed is
    never mistaken for an empty one."""
    try:
        entries = list(os.scandir(root))
    except FileNotFoundError:
        return []
    out = []
    for ent in entries:
        if not ent.name.endswith(".json") or ent.name.endswith(".tmp"):
            continue
        slug = ent.name[:-5]
        try:
            expected = path_for(slug)
        except Exception:  # noqa: BLE001 - an unsafe name is not a publication the offense plane can read
            expected = None
        if expected is None or Path(expected).name != ent.name or not ent.is_file(follow_symlinks=False):
            _log.warning("seam: skipping %r (not a publication the offense plane can read)", ent.name)
            continue
        out.append(slug)
    return sorted(out)


def granted_after_last_revoke(store, *, signal: str, engagement_slug: str) -> bool:
    """STRUCTURAL liveness, with no signature check: True when any ``granted`` record for ``engagement_slug``
    appears after its last ``revoked`` record. Revoke decisions use it (a revoke is the safe direction, honoured
    whoever signs it), so a key resolver that rejects every signature can never make a live publication look
    revoked."""
    live = False
    for record in store.iter_records():
        p = record.payload if isinstance(record.payload, dict) else {}
        if p.get("signal") != signal or p.get("engagement_slug") != engagement_slug:
            continue
        st = p.get("state")
        if st == "revoked":
            live = False
        elif st == "granted":
            live = True
    return live


IN_PROGRESS = "(reconcile in progress)"


def settle_close_alarm(failed: Iterable[str], *, checked: Iterable[str], detail: str) -> bool:
    """Finish a full reconcile's alarm, under the alarm lock: the result is ``failed`` plus any name another revoke
    added while the reconcile ran (it was not in ``checked``, so it was not re-checked). With nothing left the alarm
    is cleared. Returns True when the alarm now says what the reconcile found."""
    done = {str(c)[:96] for c in checked} | {IN_PROGRESS}
    names = {str(f)[:96] for f in failed}
    try:
        p = close_alarm_path()
        p.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        with _alarm_lock(p):
            cur = read_close_alarm() or {}
            names |= {str(f)[:96] for f in cur.get("failed") or [] if isinstance(f, str) and str(f)[:96] not in done}
            if not names:
                p.unlink(missing_ok=True)
                return True
            ordered = sorted(names)
            tmp = p.parent / (p.name + ".tmp")
            tmp.write_text(json.dumps({"detail": str(detail)[:500], "cause": "seam_unreconciled",
                                       "failed": ordered[:200], "failed_total": len(ordered), "at": time.time()}),
                           encoding="utf-8")
            os.chmod(tmp, 0o600)
            os.replace(tmp, p)
        return True
    except Exception:  # noqa: BLE001
        _log.critical("could not record the eval seam reconcile result (unconfirmed: %s)", sorted(names),
                      exc_info=True)
        return False


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


def raise_close_alarm(detail: str, *, cause: str = "spine_unreadable", failed: Iterable[str] = (),
                      replace: bool = False) -> bool:
    """Record, durably, that an eval-capability grant or eval-offense attestation revoke could not be confirmed on
    the seam. ``failed`` names the publications (``grant:<slug>`` / ``attestation:<slug>``, or a parenthesised
    condition) that may still authorize. By default the names are MERGED into any existing alarm (a revoke or a
    cascade never drops what an earlier one named); only a full reconcile, which re-checked every name, passes
    ``replace=True``. Returns True when the alarm was written. Never raises (logged CRITICAL instead)."""
    names = {str(f)[:96] for f in failed}
    try:
        p = close_alarm_path()
        p.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        with _alarm_lock(p):
            if not replace:
                prior = read_close_alarm()
                if prior:
                    names |= {str(f)[:96] for f in prior.get("failed") or [] if isinstance(f, str)}
            tmp = p.parent / (p.name + ".tmp")
            ordered = sorted(names)
            tmp.write_text(json.dumps({"detail": str(detail)[:500], "cause": str(cause)[:32], "failed": ordered[:200],
                                       "failed_total": len(ordered), "at": time.time()}), encoding="utf-8")
            os.chmod(tmp, 0o600)
            os.replace(tmp, p)
        return True
    except Exception:  # noqa: BLE001
        _log.critical("could not record the eval seam revoke alarm (%s; unconfirmed: %s): %s", cause,
                      sorted(names), detail, exc_info=True)
        return False


def read_close_alarm() -> Optional[dict]:
    """The current alarm record, or None when there is none (an unreadable record reads as an alarm naming
    nothing, so it is never mistaken for 'no alarm')."""
    p = close_alarm_path()
    try:
        raw = p.read_text(encoding="utf-8")
    except FileNotFoundError:
        return None
    except OSError:
        return {"detail": "the alarm record is unreadable", "cause": "unreadable", "failed": []}
    try:
        rec = json.loads(raw)
        return rec if isinstance(rec, dict) else {"detail": "the alarm record is malformed", "failed": []}
    except ValueError:
        return {"detail": "the alarm record is malformed", "cause": "unreadable", "failed": []}


@contextlib.contextmanager
def _alarm_lock(p: Path) -> Iterator[None]:
    import fcntl
    fd = os.open(str(p.parent / (p.name + ".lock")), os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        os.close(fd)


def clear_close_alarm() -> bool:
    """A reconcile that confirmed every published grant and attestation against the spine clears the alarm.
    Never raises; returns True when no alarm remains."""
    try:
        p = close_alarm_path()
        with _alarm_lock(p) if p.parent.is_dir() else contextlib.nullcontext():
            p.unlink(missing_ok=True)
        return True
    except OSError:
        _log.error("could not clear the eval seam revoke alarm", exc_info=True)
        return False
