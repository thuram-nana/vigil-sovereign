"""onboarding_store — has a customer finished or skipped the onboarding tour? Kept SERVER-SIDE, per account.

The customer app opens its onboarding tour after a person's first sign-in and keeps opening it, on any device, until
they finish it or skip it (owner request, 2026-11-16). This is where that answer lives: the provisioner reads it for
the SESSION's account (``GET api/customer/onboarding``) and records it when the tour closes
(``POST api/customer/onboarding``); the edge only relays, and the account is always the hop-bound session principal,
never a request field.

It is a UI preference, not money and not authority, so it is not a signed spine record: one small JSON file per
account under ``config.CUSTOMER_ONBOARDING_DIR`` (``$SIGIL_HOME/customer/onboarding``), named by a domain-separated
sha256 of the username (no username or email in a path), written atomically (``spine.atomicio``; the temp file is
0600) in a 0700 directory. A missing, unreadable or malformed file reads as ``pending`` — the safe direction for a
tour is to show it once more. Like the rest of ``customer/`` it is not in a backup (``backup._EXCLUSION_REASONS``):
a restore shows the tour once more; nothing else depends on it.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

from ..reuse import assert_no_offense

assert_no_offense()

PENDING = "pending"
#: what a closed tour records: finished (``done``) or dismissed (``skipped``)
STATES = ("done", "skipped")
_MAX_BYTES = 4096


def _dir() -> Path:
    from .. import config
    return Path(config.CUSTOMER_ONBOARDING_DIR)


def _name(username: str) -> str:
    return hashlib.sha256(b"vigil-onboarding\x00" + username.encode("utf-8")).hexdigest() + ".json"


def read_state(username: str) -> str:
    """``done`` / ``skipped`` once the account closed the tour, else ``pending`` (never raises)."""
    u = str(username or "")
    if not u:
        return PENDING
    try:
        fd = os.open(str(_dir() / _name(u)), os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        try:
            raw = os.read(fd, _MAX_BYTES + 1)
        finally:
            os.close(fd)
        if len(raw) > _MAX_BYTES:
            return PENDING
        doc = json.loads(raw.decode("utf-8"))
    except (OSError, ValueError, UnicodeDecodeError):
        return PENDING
    state = doc.get("state") if isinstance(doc, dict) else None
    return state if state in STATES else PENDING


def write_state(username: str, state: str, *, now: float) -> str:
    """Record that ``username`` finished (``done``) or skipped (``skipped``) the tour; the latest answer stands (a
    replayed tour records again). Raises ``ValueError`` on an empty username or any other state, ``OSError`` when
    the directory cannot be written."""
    u = str(username or "")
    if not u:
        raise ValueError("an onboarding record needs the account")
    if state not in STATES:
        raise ValueError(f"onboarding state must be one of {', '.join(STATES)}")
    d = _dir()
    d.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(d, 0o700)
    except OSError:
        pass
    from ..spine.atomicio import atomic_write_text
    atomic_write_text(d / _name(u), json.dumps({"state": state, "at": float(now)}, sort_keys=True))
    return state
