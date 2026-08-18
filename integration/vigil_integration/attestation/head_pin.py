"""
attestation.head_pin — the durable OUT-OF-BASE head/count anchor (W10-4 #476).

:func:`ledger.verify_ledger` proves the presented records are a self-consistent chain rooted at genesis,
but a valid PREFIX of a chain is itself self-consistent — so internal consistency ALONE cannot detect that
the TAIL was truncated (the most-recent records dropped) or the whole file WIPED. ``verify_ledger`` already
accepts ``expected_head`` / ``expected_count`` pins to catch exactly that; this module is where those pins
are PERSISTED so an offline verifier can supply them.

The pin is stored in the HOST-LEVEL attestation dir (:data:`anchor.DEFAULT_STATE_DIR`, the same host home as
the monotonic counter) — OUTSIDE the engagement base dir. That placement is the whole point: ``rm -rf <base>``
erases the ledger but NOT its pin, so a recreated/truncated ledger then DISAGREES with the surviving pin and
verify FAILS closed. It is keyed by the absolute path of the ledger file so each ledger has its own pin.

Honest residual (documented, not hidden): the pin shares the host filesystem with the owner UID; an attacker
with that UID can locate and rewrite it. This does not make the ledger tamper-proof — it RAISES THE BAR from
"delete the base dir" to "also find and rewrite the host-level pin", and pairs with the floor-signing
follow-up (W16-11). A MISSING or malformed pin degrades HONESTLY to "unpinned" (the ledger is verified on
internal consistency only, and the caller reports that it has no truncation protection) — it is never treated
as a pass that implies protection it does not have. A pin that DISAGREES with a present ledger fails closed.

Total on malformed input: every read/coerce path degrades to "no pin", never an exception. Writes are
best-effort + atomic (write-temp then ``os.replace``); a write failure leaves the previous pin in place — a
stale (lower) pin causes a CONSERVATIVE verify failure (fail toward detection), self-healed by the next
successful attest, never a silent pass.
"""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Union

from . import anchor as _anchor

# The host-level subdirectory (under DEFAULT_STATE_DIR) that holds per-ledger head/count pins.
_PIN_SUBDIR = "head-pins"
# Optional operational override of the host attestation dir (tests redirect DEFAULT_STATE_DIR instead).
_ENV_STATE_DIR = "VIGIL_ATTEST_STATE_DIR"


@dataclass(frozen=True)
class HeadPin:
    """A persisted external anchor for one ledger: the ``record_hash`` its highest-``seq`` record must carry
    (``head``) and the number of records it must contain (``count``), bound to the ledger's absolute path."""

    head: str
    count: int
    ledger_path: str


def _state_dir() -> Path:
    """The host-level pin directory, resolved at CALL time. Honors the ``VIGIL_ATTEST_STATE_DIR`` env
    override; otherwise tracks :data:`anchor.DEFAULT_STATE_DIR` (read live so a test that redirects the
    anchor state dir redirects the pins too)."""
    override = os.environ.get(_ENV_STATE_DIR, "").strip()
    base = Path(override) if override else _anchor.DEFAULT_STATE_DIR
    return base / _PIN_SUBDIR


def _abs(ledger_path: Union[str, Path]) -> str:
    return os.path.abspath(str(ledger_path))


def _pin_file(ledger_path: Union[str, Path]) -> Path:
    key = hashlib.sha256(_abs(ledger_path).encode("utf-8")).hexdigest()
    return _state_dir() / (key + ".json")


def write_head_pin(ledger_path: Union[str, Path], *, head: str, count: int) -> bool:
    """Persist/overwrite the durable head+count pin for ``ledger_path``, atomically. Best-effort: returns
    True on a durable write, False on any failure (a failed write leaves the previous pin untouched — never
    a crash, so an attest is never broken by a pin-store disk error). ``head`` must be a non-empty str and
    ``count`` a non-negative int (``bool`` excluded), else no pin is written (returns False)."""
    if not isinstance(head, str) or not head:
        return False
    if isinstance(count, bool) or not isinstance(count, int) or count < 0:
        return False
    try:
        pf = _pin_file(ledger_path)
        pf.parent.mkdir(parents=True, exist_ok=True)
        payload = json.dumps(
            {"head": head, "count": count, "ledger_path": _abs(ledger_path)},
            sort_keys=True, separators=(",", ":"),
        )
        tmp = pf.with_name(pf.name + ".tmp")
        tmp.write_text(payload, encoding="utf-8")
        os.replace(tmp, pf)
        return True
    except Exception:  # noqa: BLE001 — pin persistence is best-effort; never break an attest on a disk error
        return False


def read_head_pin(ledger_path: Union[str, Path]) -> Optional[HeadPin]:
    """Read the durable pin for ``ledger_path``, total. Returns None (⇒ UNPINNED, degrade honestly) when the
    pin is absent, unreadable, malformed, has a bad type, or was written for a DIFFERENT ledger path (hash
    collision / stale). A well-formed pin returns a :class:`HeadPin`. Never raises."""
    try:
        raw = _pin_file(ledger_path).read_text(encoding="utf-8")
    except Exception:  # noqa: BLE001 — no pin file / unreadable → unpinned
        return None
    try:
        obj = json.loads(raw)
    except Exception:  # noqa: BLE001 — a torn/corrupt pin is treated as no pin (honest degrade, never a pass)
        return None
    if not isinstance(obj, dict):
        return None
    head = obj.get("head")
    count = obj.get("count")
    stored_path = obj.get("ledger_path")
    if not isinstance(head, str) or not head:
        return None
    if isinstance(count, bool) or not isinstance(count, int) or count < 0:
        return None
    # bind the pin to THIS ledger's absolute path — a stored path that does not match is not our pin.
    if not isinstance(stored_path, str) or stored_path != _abs(ledger_path):
        return None
    return HeadPin(head=head, count=count, ledger_path=stored_path)


__all__ = ["HeadPin", "write_head_pin", "read_head_pin"]
