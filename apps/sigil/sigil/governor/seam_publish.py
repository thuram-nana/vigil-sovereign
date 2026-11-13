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
  must then fail LOUDLY rather than report a revoke the offense plane never saw.
"""
from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Callable, Iterable, Optional

from ..reuse import canonical_json

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
                         cause: Optional[BaseException] = None) -> bool:
    """After a failed publish, make sure the offense plane can no longer read the previous publication, so it
    falls back to default-ungranted rather than trusting a stale list. The file is removed; when its directory
    cannot be written (EACCES, an immutable directory) it is emptied in place instead, which needs only write
    access to the file the sovereign itself created, and the offense reader treats an unparseable file as no
    publication. Returns True when no previous publication remains readable, False when it could not be
    withdrawn. Never raises: the caller is already handling ``cause``."""
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
