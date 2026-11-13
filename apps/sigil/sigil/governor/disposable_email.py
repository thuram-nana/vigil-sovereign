"""Disposable-email domains for the free trial, from a VENDORED, sha256-pinned blocklist.

A sign-up from a disposable mailbox domain gets NO free trial (the account is still created and can buy). The
list is the CC0 disposable-email-domains blocklist (apps/sigil/sigil/governor/data/
disposable_email_blocklist.conf); update it by replacing the file and the pin together.

FAIL-CLOSED: if the vendored list is missing or its sha256 does not match the pin, no address can be shown to be
non-disposable, so no preview trial is granted. Only consulted while the trial preview is on.
FATAL-2: sovereign-side, stdlib only, `assert_no_offense` at import.
"""
from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Optional

from ..reuse import assert_no_offense

assert_no_offense()

LIST_PATH = Path(__file__).resolve().parent / "data" / "disposable_email_blocklist.conf"
LIST_SHA256 = "8a303e28fe2704fc20e73bd320cb9f47e8b3658adc0ebb046260d5acf59c27c2"

_CACHE: "dict[str, frozenset]" = {}


def load_domains(path: Path = LIST_PATH, pin: str = LIST_SHA256) -> Optional[frozenset]:
    """The blocklisted domains, or None when the list is missing or fails its pin. Only a good load is cached."""
    key = f"{path}:{pin}"
    if key in _CACHE:
        return _CACHE[key]
    try:
        data = Path(path).read_bytes()
    except OSError:
        return None
    if hashlib.sha256(data).hexdigest() != pin:
        return None
    domains = frozenset(ln.strip().lower() for ln in data.decode("utf-8").splitlines()
                        if ln.strip() and not ln.lstrip().startswith("#"))
    _CACHE[key] = domains
    return domains


def is_disposable(email: str, *, domains: "Optional[frozenset]" = None) -> Optional[bool]:
    """True when the address's domain (or a parent domain) is blocklisted, False when it is not, None when the
    list is unavailable (the caller treats None as "no trial")."""
    if domains is None:
        domains = load_domains()
    if domains is None:
        return None
    _, sep, domain = str(email or "").strip().lower().rpartition("@")
    if not sep or not domain:
        return None
    labels = domain.rstrip(".").split(".")
    return any(".".join(labels[i:]) in domains for i in range(len(labels) - 1))
