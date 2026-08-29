"""Runtime configuration + mode state for the MERIDIAN range.

The vulnerable/hardened MODE is read from a small state file at request time (not frozen at start) so
`target harden on|off` can flip every sink live — which is exactly what the Range Control HARDEN → re-prove
step needs (no restart between the OPEN scan and the CLOSED re-prove).
"""

from __future__ import annotations

import os
from dataclasses import dataclass

DEFAULT_TARGET_PORT = 19010
DEFAULT_CONTROL_PORT = 19011
LOOPBACK_HOST = "127.0.0.1"

# The readiness marker asserted by tools/livefire/range_targets.json — a scan/harness that comes up against
# something else fails to match rather than quietly proceeding.
READY_MARKER = "MERIDIAN National Permits"

MODE_VULN = "vuln"
MODE_HARDENED = "hardened"


@dataclass(frozen=True)
class Config:
    """Where the range keeps its state. base_dir holds the pidfile, the mode file, logs and the DB."""

    base_dir: str
    target_port: int = DEFAULT_TARGET_PORT
    control_port: int = DEFAULT_CONTROL_PORT
    host: str = LOOPBACK_HOST

    # --- derived paths -----------------------------------------------------------------------------
    @property
    def logs_dir(self) -> str:
        return os.path.join(self.base_dir, "logs")

    @property
    def access_log(self) -> str:
        return os.path.join(self.logs_dir, "access.log")

    @property
    def auth_log(self) -> str:
        return os.path.join(self.logs_dir, "auth.log")

    @property
    def conn_log(self) -> str:
        return os.path.join(self.logs_dir, "conn.log")

    @property
    def pidfile(self) -> str:
        return os.path.join(self.base_dir, "target.pid")

    @property
    def mode_file(self) -> str:
        return os.path.join(self.base_dir, "mode")

    @property
    def db_path(self) -> str:
        return os.path.join(self.base_dir, "meridian.sqlite3")

    def ensure_dirs(self) -> None:
        os.makedirs(self.logs_dir, exist_ok=True)


def default_base_dir() -> str:
    """The range's state dir. Overridable with $TARGET_BASE_DIR; defaults to ./.target-live."""
    return os.environ.get("TARGET_BASE_DIR") or os.path.join(os.getcwd(), ".target-live")


def read_mode(base_dir: str) -> str:
    """Return the current mode ('vuln' | 'hardened'); default 'vuln'. A missing/garbage file → vuln
    (fail-VULNERABLE is the safe default for a LAB: a broken mode file must never silently claim the app
    is hardened when it is not)."""
    try:
        with open(os.path.join(base_dir, "mode"), encoding="utf-8") as fh:
            val = fh.read().strip().lower()
    except OSError:
        return MODE_VULN
    return MODE_HARDENED if val == MODE_HARDENED else MODE_VULN


def write_mode(base_dir: str, mode: str) -> str:
    """Persist the mode; returns the normalized value actually written."""
    norm = MODE_HARDENED if str(mode).strip().lower() == MODE_HARDENED else MODE_VULN
    os.makedirs(base_dir, exist_ok=True)
    tmp = os.path.join(base_dir, ".mode.tmp")
    with open(tmp, "w", encoding="utf-8") as fh:
        fh.write(norm)
    os.replace(tmp, os.path.join(base_dir, "mode"))
    return norm


def is_hardened(base_dir: str) -> bool:
    return read_mode(base_dir) == MODE_HARDENED
