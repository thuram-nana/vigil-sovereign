"""gesture.navmode (S3) — the owner-toggled GESTURE NAV-MODE latch.

Nav-mode is OPT-IN (default OFF, never auto-entered): while it is on, a live owner-armed gesture session's
DISCRETE gestures NAVIGATE the UI (an A1 ``sigil.nav`` signal that injects NOTHING) instead of scrolling /
clicking. It is a MODE, not a safety capability, so — unlike the default-enabled ``voice``/``gesture``
capability latches — it defaults OFF and is enabled only by an explicit owner toggle.

Represented as a latest-wins spine SIGNAL (``sigil.gesture_nav_mode`` = on|off); default (no record) OFF,
fail-closed OFF on any read error. The payload carries no CONTENT_FIELDS, so it is fully plaintext (no vault
dependency). Nav-mode changes only which harmless A1 signal a gesture emits — it grants no authority and
injects nothing — so the record is audited on the append-only spine but needs no cryptographic gate.
"""

from __future__ import annotations

import threading
from pathlib import Path
from typing import Any

GESTURE_NAV_SIGNAL = "sigil.gesture_nav_mode"

# Per-store cache keyed on the rotation-aware change token, mirroring `killswitch`/`capability`: nav_mode_on
# is read once per DISCRETE gesture (a `move` short-circuits before it), so a full O(spine) scan every time
# would be wasteful on a large spine. A matching token ⇒ no new records ⇒ the cached verdict is exact; a
# changed token re-scans (no rescan-floor staleness, so a toggle is visible immediately — nav reads are rare
# discrete events, not the 30fps loop the sibling floors defend). The fail-closed error path is never cached.
_CACHE: dict[str, tuple[Any, bool]] = {}
_GUARD = threading.Lock()


def set_nav_mode(store, on: bool, *, by: str = "owner", reason: str = "") -> int:
    """Append the latest-wins nav-mode toggle. Returns the seq."""
    return store.append(
        kind="event", source="governor", actor="OWNER",
        payload={"signal": GESTURE_NAV_SIGNAL, "state": "on" if on else "off",
                 "tier": "A1", "decision": "auto", "by": by, "reason": reason,
                 "summary": f"gesture nav-mode {'ON' if on else 'OFF'}"})


def _scan_on(store) -> bool:
    """The authoritative latest-wins scan: True iff the last ``sigil.gesture_nav_mode`` record is ``on``."""
    state = "off"
    for r in store.iter_records(since_seq=-1):
        pay: Any = getattr(store.decrypted_or_raw(r), "payload", None) or {}
        if isinstance(pay, dict) and pay.get("signal") == GESTURE_NAV_SIGNAL:
            state = str(pay.get("state") or "off")
    return state == "on"


def nav_mode_on(store) -> bool:
    """True iff the latest ``sigil.gesture_nav_mode`` record is ``on``. Default OFF (no record); fail-closed
    OFF on any error (a nav gesture then behaves byte-identically to the normal scroll/click path). Cached
    on the rotation-aware change token + a rescan floor (see ``_CACHE``)."""
    try:
        path = str(Path(store.path).resolve())
        token = store.change_token()
    except Exception:  # noqa: BLE001 — cannot even read the store ⇒ fail-closed toward OFF (never cached)
        return False
    with _GUARD:
        cached = _CACHE.get(path)
        if cached is not None and cached[0] == token:
            return cached[1]                      # token match ⇒ no new records ⇒ the cached verdict is exact
    try:
        val = _scan_on(store)
    except Exception:  # noqa: BLE001 — a corrupt spine must never crash the gesture loop; fail-closed OFF
        return False
    with _GUARD:
        _CACHE[path] = (token, val)
    return val
