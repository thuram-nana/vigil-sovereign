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
``config.CUSTOMER_PREFERENCES_DIR`` (``$SIGIL_HOME/customer_preferences``), named by a domain-separated sha256 of the
username (no username or email in a path), written atomically (``spine.atomicio``; the temp file is 0600) in a 0700
directory. Only the CLOSED ``PREFERENCE_KEYS`` allowlist is ever stored (never a secret, authority or money key), and
only string values that are valid text (a lone UTF-16 surrogate has no UTF-8 form: it is refused, never stored).

A save merges ONLY the keys it names onto what is stored, one save at a time (``_SAVE_LOCK``: two concurrent saves
naming different fields both land). It is refused — nothing written — rather than ever losing a field: when the record
it would write is larger than ``_MAX_BYTES``, the bound the store reads (measured on the SERIALISED bytes, so an
accepted save always reads back exactly as it was accepted, never as the empty defaults), and when a file is there but
cannot be read as a whole profile (``ProfileUnreadable``: an I/O error, not a regular file, more than ``_MAX_BYTES``,
bytes that are not UTF-8, or not the record this store writes) — merging onto the empty defaults would write blanks
over the fields the save does not name. The same STRICT read serves the General tab (``read_prefs(..., strict=True)``),
so the tab reports such a file instead of showing an empty form. Opening the file never blocks (``O_NONBLOCK``, and
anything but a regular file is refused), so no special file at an account's path can hold ``_SAVE_LOCK``.

A missing or symlinked file holds no stored profile: it reads as the documented ``DEFAULTS`` (an empty profile — the
safe direction, never a guessed value), and a save replaces a symlink (the atomic rename), never writes through it.
The lenient ``read_prefs`` (the default) never raises: a file it cannot read reads as ``DEFAULTS`` too.

The customer entered it and nothing regenerates it, so it IS in a backup: it has its own top-level directory, outside
the ``customer/`` tree of operational markers a backup excludes, and ``backup`` captures it like any other state
directory (``backup._STATE_DIRS``; restored 0600 in a 0700 directory) — a restore brings the profile back.
"""
from __future__ import annotations

import errno
import hashlib
import json
import os
import stat
import threading
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
#: the documented defaults a missing or symlinked file reads as (and, in the lenient read, a file that cannot be read):
#: an empty profile. The safe direction is to show nothing captured, never a guessed value.
DEFAULTS = {k: "" for k in PREFERENCE_KEYS}
#: the largest record the store reads, in SERIALISED bytes (a larger file is not a profile it wrote) — so write_prefs
#: refuses a save whose record would be larger: an accepted save must read back as it was accepted
_MAX_BYTES = 8192
_MAX_VALUE_LEN = 1024               # per value, in characters
# What opening a symlink with O_NOFOLLOW fails with (ELOOP on Linux, EMLINK on the BSDs): a symlink where an account's
# file goes never holds a stored profile, so a save replaces it (the atomic rename), never writes through it.
_SYMLINK_ERRNOS = frozenset({errno.ELOOP, errno.EMLINK})
# One save at a time, PROCESS-WIDE: the cockpit (the one process that writes this store) serves requests on threads and
# builds a fresh Provisioner for each, so only a module-level lock serializes them. A save's read -> merge -> write is
# then never interleaved with another's, and two saves naming different fields both land — never the later one writing
# back over the earlier one's field the stale value it had read.
_SAVE_LOCK = threading.Lock()


class ProfileUnreadable(OSError):
    """An account's profile file is there but could not be read as a whole profile: an I/O error, not a regular file,
    more than ``_MAX_BYTES``, bytes that are not UTF-8, or not the record this store writes. What it holds is unknown,
    so it is never taken for the empty defaults by a strict read: a save is refused, nothing written (a merge onto them
    would blank every field the save does not name), and the General tab's read reports it (never an empty form)."""


def _dir() -> Path:
    from .. import config
    return Path(config.CUSTOMER_PREFERENCES_DIR)


def _name(username: str) -> str:
    return hashlib.sha256(b"vigil-preferences\x00" + username.encode("utf-8")).hexdigest() + ".json"


def _is_text(v: object) -> bool:
    """Whether ``v`` is a string that is valid text, i.e. has a UTF-8 form. A lone UTF-16 surrogate (U+D800..U+DFFF on
    its own, which a JSON ``\\ud800`` escape decodes to) has none: stored, it would break every page that shows it."""
    if not isinstance(v, str):
        return False
    try:
        v.encode("utf-8")
    except UnicodeEncodeError:
        return False
    return True


def _read_stored(path: Path) -> "bytes | None":
    """The bytes of the account's file, read in full — ``None`` when it holds no stored profile (no file, or a symlink:
    never followed). Raises ``ProfileUnreadable`` for a file that is there but cannot be read: any other ``OSError``,
    anything but a regular file, or more than ``_MAX_BYTES``. The open never blocks (``O_NONBLOCK``: a FIFO or a device
    at the path is refused, never waited on), and the read loops to the end (a short read is never taken for the
    whole file)."""
    try:
        fd = os.open(str(path), os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
    except FileNotFoundError:
        return None                                 # nothing stored yet
    except OSError as e:
        if e.errno in _SYMLINK_ERRNOS:
            return None                             # a symlink holds no stored profile (a save replaces it)
        raise ProfileUnreadable(e.errno, "the stored preferences could not be opened") from None
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise ProfileUnreadable(errno.EINVAL, "the stored preferences are not a regular file")
        chunks, size = [], 0
        while size <= _MAX_BYTES:
            chunk = os.read(fd, _MAX_BYTES + 1 - size)
            if not chunk:
                break
            chunks.append(chunk)
            size += len(chunk)
    except ProfileUnreadable:
        raise
    except OSError as e:
        raise ProfileUnreadable(e.errno, "the stored preferences could not be read") from None
    finally:
        os.close(fd)
    if size > _MAX_BYTES:
        raise ProfileUnreadable(errno.EFBIG, "the stored preferences are larger than this store writes")
    return b"".join(chunks)


def _load(username: str, *, strict: bool) -> dict:
    """The account's stored profile, every ``PREFERENCE_KEYS`` field present and defaulting to ``""``; only allowlisted
    fields that are valid text are surfaced. A missing or symlinked file reads as ``DEFAULTS``. A file that is there but
    cannot be read as a whole profile (``_read_stored``; bytes that are not UTF-8, or not the record this store writes)
    reads as ``DEFAULTS`` too — unless ``strict``, which raises ``ProfileUnreadable``: a save merges onto this, and the
    General tab shows it, so neither may take an unread profile for an empty one."""
    out = dict(DEFAULTS)
    try:
        raw = _read_stored(_dir() / _name(username))
        if raw is None:
            return out
        try:
            doc = json.loads(raw.decode("utf-8"))
        except ValueError:                          # UnicodeDecodeError and JSONDecodeError are both ValueErrors
            raise ProfileUnreadable(errno.EINVAL, "the stored preferences are not valid") from None
        saved = doc.get("prefs") if isinstance(doc, dict) else None
        if not isinstance(saved, dict):
            raise ProfileUnreadable(errno.EINVAL, "the stored preferences are not a preferences record")
    except ProfileUnreadable:
        if strict:
            raise
        return out
    for k in PREFERENCE_KEYS:                       # only allowlisted fields that are valid text are ever surfaced
        v = saved.get(k)
        if _is_text(v):
            out[k] = v
    return out


def read_prefs(username: str, *, strict: bool = False) -> dict:
    """The account's saved General preferences — each ``PREFERENCE_KEYS`` field present, defaulting to ``""``. A
    missing or symlinked file reads as the documented ``DEFAULTS``, and a stored value that is not valid text reads as
    ``""``. A file that is there but cannot be read as a whole profile reads as ``DEFAULTS`` too (this lenient read
    never raises) — unless ``strict``, which raises ``ProfileUnreadable`` for it: the General tab reads strictly, so it
    reports such a file rather than show an empty form for a stored profile. An account name with no UTF-8 form (a lone
    surrogate) can hold no stored profile: it reads as ``DEFAULTS``."""
    u = str(username or "")
    if not u or not _is_text(u):
        return dict(DEFAULTS)
    return _load(u, strict=strict)


def write_prefs(username: str, prefs: dict, *, now: float) -> dict:
    """Record the account's General preferences, merging ``prefs`` onto what is stored — ONLY the keys it names; every
    other stored field is kept as it was — and return the full stored profile.

    Only ``PREFERENCE_KEYS`` keys with string values that are valid text, at most ``_MAX_VALUE_LEN`` characters each,
    are accepted. Refused with ``ValueError``, nothing written: any other key (never an arbitrary field, never a secret
    / authority / money key), a non-string, a lone UTF-16 surrogate, an over-long value, a profile whose SERIALISED
    record would be larger than ``_MAX_BYTES`` (``read_prefs`` would read it back as the empty defaults), and an empty
    username (or one with no UTF-8 form). Refused with ``OSError``, nothing written: a stored file that is there but
    cannot be read as a whole profile (``ProfileUnreadable``: a merge onto the empty defaults would blank every field
    this save does not name), and a directory that cannot be written."""
    u = str(username or "")
    if not u:
        raise ValueError("a preferences record needs the account")
    if not _is_text(u):
        raise ValueError("a preferences record needs an account name that is valid text")
    if not isinstance(prefs, dict):
        raise ValueError("preferences must be an object")
    clean = {}
    for k, v in prefs.items():
        if k not in PREFERENCE_KEYS:
            raise ValueError(f"unknown preference key: {k!r}")
        if not isinstance(v, str):
            raise ValueError(f"preference {k!r} must be a string")
        if not _is_text(v):
            raise ValueError(f"preference {k!r} is not valid text")
        if len(v) > _MAX_VALUE_LEN:
            raise ValueError(f"preference {k!r} is too long")
        clean[k] = v
    from ..spine.atomicio import atomic_write_text
    with _SAVE_LOCK:                                # the read, the merge and the write as one step (see _SAVE_LOCK)
        merged = _load(u, strict=True)              # what is stored; a partial save keeps every field it does not name
        merged.update(clean)
        data = json.dumps({"prefs": merged, "at": float(now)}, sort_keys=True)
        if len(data.encode("utf-8")) > _MAX_BYTES:  # read_prefs would read it back as the defaults: never write it
            raise ValueError("the profile is too long to store: shorten a field")
        d = _dir()
        d.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(d, 0o700)
        except OSError:
            pass
        atomic_write_text(d / _name(u), data)
    return merged
