"""Fail-closed publication of owner-sealed revocable records to the cross-plane seam.

The keyless offense plane cannot fold the sovereign spine: for an eval-capability grant or an eval-offense
attestation it trusts the owner-sealed record list the sovereign PUBLISHES to the seam. A publish that fails
must therefore never leave an older publication in place, because that older list may still grant what the
spine has since revoked. Two helpers keep every publish fail-closed:

* :func:`encodable_or_revoke` - a record that cannot be canonicalised (a lone surrogate is only possible
  through a raw spine-file write) can be neither sealed nor written. Dropping it could drop a REVOKE, so it
  is replaced, in place, by an UNSIGNED revoke placeholder. The offense plane honours a revoke whoever signs
  it, so the placeholder can only ever un-grant.
* :func:`withdraw_publication` - on any publish failure the existing seam file is removed, so the offense
  plane falls back to default-ungranted / default-unattested instead of trusting a stale list.
"""
from __future__ import annotations

import logging
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


def withdraw_publication(path_fn: Callable[[], Optional[Path]], *, what: str) -> None:
    """Remove the published seam file after a failed publish, so the offense plane reads NOTHING (default
    ungranted) rather than a stale list. Never raises: the caller is already handling a failure."""
    try:
        path = path_fn()
        if path is not None:
            path.unlink(missing_ok=True)
        _log.error("seam publish of %s FAILED: the previous publication was withdrawn (offense plane falls "
                   "back to ungranted); the spine record stands and the next publish re-sends the full list", what)
    except Exception:  # noqa: BLE001 - must not mask the original failure
        _log.critical("seam publish of %s FAILED and the previous publication could NOT be withdrawn: the "
                      "offense plane may still trust a stale list until the next successful publish", what,
                      exc_info=True)
