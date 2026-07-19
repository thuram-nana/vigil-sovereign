"""Safe operator runner to convert a legacy single-file spine to the retain-all segment layout and reclaim
disk via gzip compaction, with a full-integrity gate at every step.

The conversion is retain-all (no record is ever removed), but migrate() is a one-way rename and compaction
rewrites sealed segments, so this runner refuses to proceed on a spine that does not already verify(), takes
a tar.gz backup OUTSIDE the spine dir first, and asserts — before AND after — that verify() is clean and the
record count is preserved (a changed count would mean a bug ate a record). It is idempotent: on an
already-migrated spine migrate() is a no-op and compact() only compresses what is still plaintext.
"""
from __future__ import annotations

import tarfile
import time
from pathlib import Path

from ..config import SIGIL_HOME
from .store import SpineError, SpineStore


def _backup_spine_dir(spine_dir: Path) -> Path:
    """tar.gz the whole spine dir to SIGIL_HOME/backups/ (OUTSIDE the spine dir, so it is not itself
    migrated/compacted). Returns the backup path. Uses wallclock only for the file name (this is a one-shot
    operator tool, not the deterministic enforcement path)."""
    backups = SIGIL_HOME / "backups"
    backups.mkdir(parents=True, exist_ok=True)
    dest = backups / f"spine-backup-{int(time.time())}.tar.gz"
    with tarfile.open(dest, "w:gz") as tar:
        tar.add(str(spine_dir), arcname=spine_dir.name)
    return dest


def backup_migrate_compact(store: SpineStore | None = None, *, backup: bool = True) -> dict:
    """Verify → backup → migrate → verify → compact → verify, with a record-count-preserved guard. Returns
    a report dict. RAISES SpineError and stops (leaving the backup) if verify() ever fails or the record
    count changes — retain-all must preserve every record. Safe to re-run."""
    store = store or SpineStore()
    report: dict = {"spine_dir": str(store._layout.spine_dir)}

    ok, reason = store.verify()
    report["verify_before"] = {"ok": ok, "reason": reason}
    if not ok:
        raise SpineError(f"refusing to convert a spine that does not verify: {reason}")
    report["count_before"] = store.count()

    if backup:
        report["backup"] = str(_backup_spine_dir(store._layout.spine_dir))

    report["migrated"] = store.migrate()
    # A fresh migration puts ALL records in one ACTIVE seg-0; seal it so compaction can gzip it (compact
    # only touches SEALED segments). Only on the first conversion — a re-run leaves the current active alone
    # and just gzips any sealed plaintext left by natural rotation.
    report["sealed"] = SpineStore(store.path).rotate() if report["migrated"] else False
    ok, reason = SpineStore(store.path).verify()
    report["verify_after_migrate"] = {"ok": ok, "reason": reason}
    if not ok:
        raise SpineError(f"verify FAILED after migrate — backup at {report.get('backup')}: {reason}")

    report["compacted"] = SpineStore(store.path).compact()
    fresh = SpineStore(store.path)
    ok, reason = fresh.verify()
    report["verify_after_compact"] = {"ok": ok, "reason": reason}
    report["count_after"] = fresh.count()
    if not ok:
        raise SpineError(f"verify FAILED after compact — backup at {report.get('backup')}: {reason}")
    if report["count_after"] != report["count_before"]:
        raise SpineError(
            f"record count changed {report['count_before']} -> {report['count_after']} — retain-all must "
            f"preserve every record; backup at {report.get('backup')}")
    report["ok"] = True
    return report
