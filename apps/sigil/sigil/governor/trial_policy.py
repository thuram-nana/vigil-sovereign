"""Free-trial policy helpers (pure, sovereign-side): the canonical mailbox key and the trial-size bound.

`canonical_email` is the CLAIM key for "one trial per mailbox" only — account identity is unchanged (an
account is still keyed by the address the customer verified). It folds the common aliases of one mailbox:
  * strip + lower-case (as `customers` does);
  * drop a "+tag" from the local part;
  * for gmail.com / googlemail.com also drop dots and map the domain to gmail.com.
Dots are NOT folded for other domains (they are distinct mailboxes there).

FATAL-2: sovereign-side, stdlib only, `assert_no_offense` at import.
"""
from __future__ import annotations

from ..reuse import assert_no_offense

assert_no_offense()

# A sanity ceiling on the configured trial grant, so a typo cannot mint an unbounded free balance. It is a
# bound on a setting, not a price: the trial size itself is the owner's VIGIL_TRIAL_CREDITS.
TRIAL_MAX = 1_000_000
_GMAIL = frozenset({"gmail.com", "googlemail.com"})


def canonical_email(email: str) -> str:
    """The canonical mailbox key, or "" when `email` is not a usable address (no claim can be keyed on it)."""
    e = str(email or "").strip().lower()
    local, sep, domain = e.rpartition("@")
    if not sep or not local or not domain:
        return ""
    local = local.split("+", 1)[0]
    if domain in _GMAIL:
        local = local.replace(".", "")
        domain = "gmail.com"
    if not local:
        return ""
    return f"{local}@{domain}"


def check_trial_credits(value: object) -> int:
    """The configured trial size, validated at construction: an int in [0, TRIAL_MAX]. 0 means no trial."""
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= TRIAL_MAX:
        raise ValueError(f"trial credits must be an integer in [0, {TRIAL_MAX}] (0 = no trial)")
    return value
