"""
attestation.anchor — the monotonic WHEN anchor that makes a record un-back-datable (VIGIL WS6).

An attestation's non-repudiation rests on time that can only move forward. Wallclock time cannot: it is
settable, it is not signed by hardware, and a back-dated ``at`` would let an operator deny an action was
recent. So each record additionally carries a MONOTONIC anchor whose value never decreases across the
ledger:

  * **TPM-grounded (preferred).** If ``/dev/tpm0`` is present and the ``tpm2_readclock`` tool is on PATH,
    read the TPM's monotonic clock via an argv-list subprocess (NO shell, no interpolation) and parse its
    integer. A hardware monotonic counter cannot be rewound by software.
  * **Software-grounded (fallback).** Otherwise (no TPM, no tooling, any read failure) advance a persisted
    integer counter file — read the floor, increment, atomically rewrite. Best-effort persistence: a write
    failure still yields an increasing value THIS run; it degrades durability, never correctness-in-run.

Unified floor: the returned value is always strictly greater than the persisted floor (either a TPM read
that exceeds it, or ``floor + 1``), and the floor is re-persisted to the new value — so even switching
grounding source, a stuck TPM, or a regressed TPM read can never make the anchor go backwards.

Total by construction: the TPM probe is injectable and every branch (probe, file read, file write) is
guarded, so ``read_monotonic_anchor`` never raises — an unreadable/unwritable substrate degrades to a
plain software increment, never a crash. No wallclock, no RNG: the counter is a pure floor-advance.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path
from typing import Callable, Optional

from .models import MonotonicAnchor

# Default on-disk home for the ledger's persisted state (software counter + operator keypair). Under the
# operator's home so it survives across runs and is theirs alone; every path is injectable for tests.
DEFAULT_STATE_DIR: Path = Path.home() / ".vigil" / "attestation"
_COUNTER_FILE: str = "monotonic.counter"

# The injectable TPM probe: returns the TPM monotonic clock as an int, or None if unavailable/unreadable.
TpmProbe = Callable[[], Optional[int]]


def _default_tpm_probe() -> Optional[int]:
    """Best-effort TPM monotonic-clock read via ``tpm2_readclock``. Returns None on ANY of: no
    ``/dev/tpm0``, no tooling on PATH, a non-zero exit, a timeout, or an unparseable output. Argv-list
    invocation only (no ``shell=True``, no string interpolation). Never raises."""
    if not os.path.exists("/dev/tpm0"):
        return None
    exe = shutil.which("tpm2_readclock")
    if not exe:
        return None
    try:
        proc = subprocess.run(  # noqa: S603 — fixed argv (resolved exe, no args), no shell, no interpolation
            [exe], capture_output=True, text=True, timeout=5, check=False,
        )
    except Exception:  # noqa: BLE001 — a spawn/timeout failure means "no TPM signal", never a crash
        return None
    if proc.returncode != 0:
        return None
    # tpm2_readclock emits a YAML-ish block; the monotonic field is the ``clock:`` line (milliseconds).
    for line in proc.stdout.splitlines():
        s = line.strip()
        if s.startswith("clock:"):
            frag = s.split(":", 1)[1].strip()
            if frag.isdigit():
                return int(frag)
    return None


def _read_floor(path: Path) -> int:
    """Read the persisted software floor, total. A missing/torn/negative value reads as 0 (a fresh
    counter), never an exception."""
    try:
        v = int(path.read_text().strip())
    except Exception:  # noqa: BLE001 — no file / non-int / unreadable → start the floor at 0
        return 0
    return v if v >= 0 else 0


def _write_floor(path: Path, value: int) -> None:
    """Atomically persist the new floor (write-temp then ``os.replace``), best-effort. A write failure is
    swallowed — the in-run value still advances; only cross-run durability is affected."""
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_name(path.name + ".tmp")
        tmp.write_text(str(value))
        os.replace(tmp, path)
    except Exception:  # noqa: BLE001 — persistence is best-effort; never break minting on a disk error
        pass


def read_monotonic_anchor(
    *,
    state_path: Optional[str] = None,
    tpm_probe: Optional[TpmProbe] = None,
) -> MonotonicAnchor:
    """Return the next monotonic anchor — a value STRICTLY greater than the persisted floor, plus its
    grounding.

    TPM first: if the (injectable) probe returns an int greater than the floor, that TPM value is used
    (``grounded="tpm"``). Otherwise the value is ``floor + 1`` (``grounded="software"``) — this covers no
    TPM, a stuck TPM, or a TPM read at/below the floor, and guarantees the anchor never decreases even
    across a grounding switch. The floor is then re-persisted to the returned value. Total: never raises."""
    path = Path(state_path) if state_path else (DEFAULT_STATE_DIR / _COUNTER_FILE)
    probe = tpm_probe if tpm_probe is not None else _default_tpm_probe
    floor = _read_floor(path)
    tpm_val: Optional[int]
    try:
        tpm_val = probe()
    except Exception:  # noqa: BLE001 — a misbehaving injected probe is treated as "no TPM signal"
        tpm_val = None
    # bool is an int subclass but is NOT a counter value — reject it so ``True`` can't read as 1.
    if isinstance(tpm_val, bool):
        tpm_val = None
    if isinstance(tpm_val, int) and tpm_val > floor:
        value, grounded = tpm_val, "tpm"
    else:
        value, grounded = floor + 1, "software"
    _write_floor(path, value)
    return MonotonicAnchor(value=value, grounded=grounded)
