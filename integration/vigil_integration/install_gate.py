"""vigil_integration.install_gate — the offense-plane wiring of the shared W5-4 install manifest (#448).

Boundary-minimal by construction: imports ONLY ``vigil_core`` + stdlib — never ``framework`` / ``strix`` /
``sigil`` — so it stays on the offense side of FATAL-2 and the offense CI leg (where ``framework`` is not
importable) collects its test cleanly. It writes-if-absent + verifies-if-present the ``.vigil-live`` data
directory at ``vigil`` startup, failing closed on a directory this build does not understand.

The refuse-newer decision, the manifest format, and the fail-closed integrity check all live in
``vigil_core.install_manifest`` (shared with the sovereign plane). This module supplies only the OFFENSE
plane's product version, its ``.vigil-live`` schema map, and the CLI-startup glue (exit code + which verbs
stay runnable against a not-understood directory so the operator can recover)."""
from __future__ import annotations

import sys
from pathlib import Path
from typing import Optional

from vigil_core.install_manifest import InstallManifestRefused, ensure_operable

#: The ``.vigil-live`` data-dir LAYOUT version this offense build writes/understands. A future layout change
#: bumps this; an older build then refuses-newer a ``.vigil-live`` written by a build that bumped it. Kept
#: offense-owned (here, next to the plane that owns the directory) so a bump is a one-line change.
VIGIL_LIVE_LAYOUT_SCHEMA = 1

#: Offense recovery/diagnostic verbs stay runnable against a data directory this build does not understand,
#: so the operator can upgrade the binary / inspect / recover — mirrors the sovereign migration gate's
#: exemption set. Every OTHER verb refuses (exit 2) on a not-understood ``.vigil-live``.
_EXEMPT = frozenset({
    "doctor", "verify-integrity", "down", "panic", "emergency-stop",
    "backup", "restore", "upgrade", "alerts", "unit-heartbeat",
})


def offense_product_version() -> str:
    """This offense build's product version. Prefer installed package metadata; fall back to the repo-root
    ``VERSION`` file (source tree), then a marked sentinel. Never raises."""
    try:
        from importlib.metadata import version
        return version("vigil-integration")
    except Exception:  # noqa: BLE001 — metadata absent (source tree / odd install): fall back, never crash
        return _version_from_repo() or "0.0.0+unknown"


def _version_from_repo() -> Optional[str]:
    here = Path(__file__).resolve()
    for parent in here.parents:
        vf = parent / "VERSION"
        if vf.is_file():
            try:
                for line in vf.read_text(encoding="utf-8").splitlines():
                    if line.strip():
                        return line.strip()
            except OSError:
                return None
    return None


def offense_schema_versions() -> "dict[str, int]":
    """The versioned artifacts THIS offense build writes into ``.vigil-live`` and the max schema of each it
    understands — the map that drives the fail-closed startup verify (W5-4)."""
    return {"vigil_live_layout": int(VIGIL_LIVE_LAYOUT_SCHEMA)}


def ensure_operable_or_exit(base_dir, cmd: str, *, exempt=_EXEMPT) -> Optional[int]:
    """Write-if-absent + verify-if-present the ``.vigil-live`` install manifest at ``vigil`` startup.

    Returns ``None`` to continue, or an integer exit code to abort with (matching the offense CLI's
    ``main() -> int`` contract). A data directory this build does not understand is REFUSED (exit 2) for a
    normal command; for a recovery/diagnostic command it WARNS and continues so the operator can recover. A
    transient FS error never aborts a command (the command surfaces its own errors)."""
    try:
        ensure_operable(base_dir, product_version=offense_product_version(),
                        schema_versions=offense_schema_versions())
    except InstallManifestRefused as e:
        if cmd in exempt:
            print(f"vigil: WARNING — {e} (allowed for `{cmd}` so you can fix it)", file=sys.stderr)
            return None
        print(f"vigil: refusing to run `{cmd}` — {e}", file=sys.stderr)
        return 2
    except Exception:  # noqa: BLE001 — a transient marker/FS error is the COMMAND's to surface, not the gate's
        return None
    return None
