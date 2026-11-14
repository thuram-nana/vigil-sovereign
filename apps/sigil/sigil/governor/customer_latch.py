"""The owner's customer latches — instant switches over NEW customer reservations, sign-ups and checkouts.

Five owner-signed latches ride the governed capability latch (``capability.py``: same record shape, fold, snapshot
carry across a hard prune, and per-latch anti-replay):

  ``customer_launch``  a new launch reservation (``LaunchGate.reserve_launch``)
  ``customer_signup``  a new self-serve sign-up (an email sign-up request or confirmation, a first Google sign-in)
  ``checkout``         a new hosted checkout
  ``trial``            a new sign-up trial grant and a new trial scan
  ``founder_tester``   the founder tester role for a new sign-up, where the deployment offers that role

Each gates only the NEW act. Cancel, settle, pause, resume and release of an existing launch, a webhook for a payment
already made, logging in, and finishing a sign-up or a trial grant that already started stay open, so held credits
are never stranded and nothing half-made is left behind.

Direction and authority are the latch's: turning a latch OFF takes effect at once (the next read, no restart) from
any governor-written record, signed or not — off is the safe direction, so the paired phone's off-button records it
with no private key. Turning it back ON counts only as an owner-signed record whose ``issued_at`` is newer than every
earlier ON for that latch (a captured ON can never be replayed). With no record a latch is ON, so an upgrade changes
nothing. A read that fails answers OFF (fail-closed: no new money act on an unreadable spine).

The environment flag of each act stays its ceiling: a latch can only narrow what the environment allows, never widen
it (``CEILINGS`` names the flag, where the act has one).
"""
from __future__ import annotations

import os
from typing import Optional

from .capability import CUSTOMER_LATCHES, CapabilityGate, append_disable

LATCHES = tuple(sorted(CUSTOMER_LATCHES))

#: The environment setting that is each act's ceiling (None: the act has no environment switch of its own).
CEILINGS: "dict[str, Optional[str]]" = {
    "customer_launch": None,
    "customer_signup": None,
    "checkout": "VIGIL_CUSTOMER_CHECKOUT_ENABLED",
    "trial": "VIGIL_TRIAL_CREDITS",
    "founder_tester": "VIGIL_SIGNUP_FOUNDER_TESTER_ENABLED",
}

#: What a customer is told when a latch refuses a new act (no internal detail, no other tenant named).
PAUSED: "dict[str, str]" = {
    "customer_launch": "new assessment launches are paused right now; your existing launches can still be "
                       "started, cancelled, paused and resumed — please try again later",
    "customer_signup": "new sign-ups are paused right now — please try again later",
    "checkout": "new purchases are paused right now — please try again later",
    "trial": "trial scans are paused right now — buy credits to scan, or try again later",
    "founder_tester": "the founder tester role is paused right now",
}


def _check(name: str) -> str:
    if name not in CUSTOMER_LATCHES:
        raise ValueError(f"unknown customer latch {name!r} (expected one of {list(LATCHES)})")
    return name


def is_open(store, name: str, *, trusted_pubkey: Optional[str] = None) -> bool:
    """True iff customer latch ``name`` is ON. Needs no private key. FAIL-CLOSED: any read error answers False."""
    _check(name)
    try:
        return bool(CapabilityGate.reader(store, trusted_pubkey=trusted_pubkey).is_enabled(name))
    except Exception:  # noqa: BLE001 — an unreadable spine never green-lights a new money act
        return False


def refusal(store, name: str, *, trusted_pubkey: Optional[str] = None) -> Optional[str]:
    """None when latch ``name`` is ON, else the customer-facing reason the new act is refused."""
    return None if is_open(store, name, trusted_pubkey=trusted_pubkey) else PAUSED[name]


def state_all(store, *, trusted_pubkey: Optional[str] = None) -> "dict[str, str]":
    """{latch: "on" | "off"} for every customer latch (status, doctor, the cockpit and phone reads)."""
    return {n: ("on" if is_open(store, n, trusted_pubkey=trusted_pubkey) else "off") for n in LATCHES}


def ceiling_state(name: str, env: "Optional[dict]" = None) -> str:
    """The environment ceiling of latch ``name`` as this process sees it: "none" (the act has no switch of its
    own), or "<SETTING>=<value>" ("unset" when absent)."""
    setting = CEILINGS[_check(name)]
    if setting is None:
        return "none"
    e = os.environ if env is None else env
    raw = e.get(setting)
    return f"{setting}={raw.strip() if isinstance(raw, str) and raw.strip() else 'unset'}"


def turn_off(store, name: str, *, owner_key=None, by: str = "owner", reason: str = "", actor: str = "WARDEN") -> int:
    """Turn latch ``name`` OFF (the safe direction: honoured at once, signed or not). Returns the spine seq."""
    return append_disable(store, _check(name), owner_key=owner_key, by=by, reason=reason, actor=actor)


def turn_on(store, name: str, *, owner_key, issued_at: float, by: str = "owner", reason: str = "") -> int:
    """Turn latch ``name`` back ON — counts only as an owner-signed record with a fresh ``issued_at``."""
    if owner_key is None:
        raise ValueError("turning a customer latch on needs the owner key")
    return CapabilityGate(store, owner_key=owner_key).enable(_check(name), issued_at=issued_at, by=by,
                                                             reason=reason)
