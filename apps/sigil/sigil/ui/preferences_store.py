"""preferences_store — a customer's General settings preferences (the legal-entity / contact profile fields the
settings shell's General tab captures), kept SERVER-SIDE, per account.

The customer settings shell (VIGIL_CUSTOMER_SETTINGS) has a General tab where a workspace records who it is on paper:
the customer legal entity name, the registered / operating address, the primary contractual contact email, and an
emergency operational contact (name, phone, email). This is where that answer lives: the provisioner reads it for the
SESSION's account (``GET api/customer/preferences``) and records it when the tab is saved
(``POST api/customer/preferences``); the edge only relays, and the account is always the hop-bound session principal,
never a request field.

It is a UI preference, not money and not authority — the authoritative, owner-signed org profile is a separate,
later concern — so it is NOT a signed spine record: one small JSON file per account under
``config.CUSTOMER_PREFERENCES_DIR`` (``$SIGIL_HOME/customer/preferences``), named by a domain-separated sha256 of the
username (no username or email in a path), written atomically (``spine.atomicio``; the temp file is 0600) in a 0700
directory. Only the CLOSED ``PREFERENCE_KEYS`` allowlist is ever stored (never a secret, authority or money key), and
only string values. A missing, unreadable, malformed or oversized file reads as the documented ``DEFAULTS`` (an empty
profile — the safe direction, never a guessed value), never an error. Like the rest of ``customer/`` it is not in a
backup (``backup._EXCLUSION_REASONS``): a restore shows the documented defaults; nothing else depends on it.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

from ..reuse import assert_no_offense

assert_no_offense()

#: the CLOSED preference-key allowlist — plain legal-entity / contact profile fields the General tab captures. Every
#: one is a non-secret string; nothing here is a secret, an authority grant, or a money value, and a key outside this
#: set is refused (never an arbitrary field).
PREFERENCE_KEYS = (
    "legal_entity_name",            # Customer Legal Entity Name
    "registered_address",           # Registered / Operating Address
    "contractual_contact_email",    # Primary Contractual Contact Email
    "emergency_contact_name",       # Emergency Operational Contact — name
    "emergency_contact_phone",      # Emergency Operational Contact — phone
    "emergency_contact_email",      # Emergency Operational Contact — email
)
#: the documented defaults a missing / unreadable / malformed / oversized file reads as: an empty profile. The safe
#: direction is to show nothing captured, never a guessed value.
DEFAULTS = {k: "" for k in PREFERENCE_KEYS}
_MAX_BYTES = 8192
_MAX_VALUE_LEN = 1024


def _dir() -> Path:
    from .. import config
    return Path(config.CUSTOMER_PREFERENCES_DIR)


def _name(username: str) -> str:
    return hashlib.sha256(b"vigil-preferences\x00" + username.encode("utf-8")).hexdigest() + ".json"


def read_prefs(username: str) -> dict:
    """The account's saved General preferences — each ``PREFERENCE_KEYS`` field present, defaulting to ``""``. A
    missing, unreadable, malformed, oversized or symlinked file reads as the documented ``DEFAULTS`` (never raises)."""
    out = dict(DEFAULTS)
    u = str(username or "")
    if not u:
        return out
    try:
        fd = os.open(str(_dir() / _name(u)), os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        try:
            raw = os.read(fd, _MAX_BYTES + 1)
        finally:
            os.close(fd)
        if len(raw) > _MAX_BYTES:
            return out
        doc = json.loads(raw.decode("utf-8"))
    except (OSError, ValueError, UnicodeDecodeError):
        return out
    saved = doc.get("prefs") if isinstance(doc, dict) else None
    if not isinstance(saved, dict):
        return out
    for k in PREFERENCE_KEYS:                       # only allowlisted string fields are ever surfaced
        v = saved.get(k)
        if isinstance(v, str):
            out[k] = v
    return out


def write_prefs(username: str, prefs: dict, *, now: float) -> dict:
    """Record the account's General preferences, merging ``prefs`` onto what is stored (an unnamed field is left as
    it was), and return the full stored profile. Only ``PREFERENCE_KEYS`` string values are accepted: any other key,
    a non-string value, or a value longer than ``_MAX_VALUE_LEN`` raises ``ValueError`` and nothing is written —
    never an arbitrary field, never a secret / authority / money key. An empty username raises ``ValueError``;
    ``OSError`` is raised when the directory cannot be written."""
    u = str(username or "")
    if not u:
        raise ValueError("a preferences record needs the account")
    if not isinstance(prefs, dict):
        raise ValueError("preferences must be an object")
    clean = {}
    for k, v in prefs.items():
        if k not in PREFERENCE_KEYS:
            raise ValueError(f"unknown preference key: {k!r}")
        if not isinstance(v, str):
            raise ValueError(f"preference {k!r} must be a string")
        if len(v) > _MAX_VALUE_LEN:
            raise ValueError(f"preference {k!r} is too long")
        clean[k] = v
    merged = read_prefs(u)                          # start from the stored profile; a partial save keeps the rest
    merged.update(clean)
    d = _dir()
    d.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(d, 0o700)
    except OSError:
        pass
    from ..spine.atomicio import atomic_write_text
    atomic_write_text(d / _name(u), json.dumps({"prefs": merged, "at": float(now)}, sort_keys=True))
    return merged
