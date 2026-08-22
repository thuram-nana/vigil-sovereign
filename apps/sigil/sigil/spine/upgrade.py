"""The `vigil upgrade` / `sigil upgrade` data-migration orchestrator (W5-5, #449).

The defect this closes: ``sigil spine migrate`` is manual and invoked by NO automated path. Only
``prune`` hard-fails on a legacy (pre-segment) spine, so an operator who upgrades the binary and just
runs will keep operating on an UN-migrated store until something happens to hit ``prune`` — a silent
degraded state. This module ships the missing automated, crash-safe, ROLLING-BACK path:

    verify(before) -> backup -> verify(backup) -> migrate -> verify(after) -> report

with a hard invariant: **on ANY failure between taking the backup and a clean post-migration verify, the
store is ROLLED BACK to the verified backup**, so an interrupted upgrade never leaves a half-migrated
store. It is fail-closed at every seam:

* it REFUSES to upgrade a store that does not already ``verify()`` (never migrate corruption forward);
* it VERIFIES the backup is itself restorable (open + verify + record-count match) BEFORE mutating
  anything — a backup that cannot be restored is not a safety net, so we stop rather than proceed;
* the actual migration (legacy single-file -> retain-all segment layout, then seal + gzip compact) runs
  under the store's own cross-process lock, and is guarded before AND after by ``verify()`` and a
  record-count-preserved assertion (retain-all must never lose a record);
* if any of that raises, we restore the whole spine directory from the verified backup, re-verify the
  restored store, and re-raise ``UpgradeFailed`` carrying the report (the CLI aborts non-zero).

It also supplies the STARTUP gate: ``migration_needed`` / ``assert_operable`` — a legacy single-file
spine that already holds records is refused with the exact command to run, so a degraded store cannot be
operated on unnoticed.

Builds on W5-1 (#445, the per-record ``schema_version`` + enforced ``kind``) and the existing
segment-layout migration primitives in ``store.py`` / ``migrate_runner.py``. The schema/payload
evolution is additive by contract (``schema_version`` is informational, not digested — see
``models.py``), so the migration here is the STRUCTURAL legacy->segment conversion; a future non-additive
migration plugs into the same orchestrator between the two ``verify()`` gates without changing the
backup/rollback frame.
"""
from __future__ import annotations

import os
import shutil
import tarfile
import tempfile
import time
from pathlib import Path

from .manifest import read_manifest
from .store import SpineError, SpineStore


class UpgradeFailed(SpineError):
    """An upgrade step failed. The store has been ROLLED BACK to the verified backup (or, if the rollback
    itself failed, the backup path is named so the operator can restore by hand). Carries the partial
    ``report`` so the caller can print exactly what happened and where the backup lives."""

    def __init__(self, message: str, report: dict) -> None:
        self.report = report
        super().__init__(message)


class MigrationRequired(SpineError):
    """Fail-closed startup gate: the store is in the legacy (pre-segment) layout and must be migrated
    before it is operated on. Names the command that fixes it."""


def migration_needed(store: SpineStore) -> tuple[bool, str]:
    """Is this store in a state this build must migrate before operating on it?

    True iff it is a LEGACY single-file spine (no segment manifest published) that ALREADY HOLDS DATA —
    the exact 'operator upgraded onto a pre-segment store' case. A store with a manifest is migrated; a
    fresh install whose legacy data file does not exist yet, or exists but is empty, is NOT 'degraded' —
    it will get a manifest the first time ``vigil upgrade`` / ``sigil spine migrate`` runs, which the
    install flow does once. Reads only; touches nothing.

    Detection is by the DATA FILE'S SIZE, not a full record scan, so the startup gate stays O(1) even on a
    large spine (a non-empty legacy file with no manifest is, unambiguously, a store with history that
    predates the segment layout)."""
    layout = store._layout
    if read_manifest(layout) is not None:
        return False, ""                                    # already migrated
    data = layout.data_path
    try:
        if not data.exists() or data.stat().st_size == 0:
            return False, ""                                # fresh / empty legacy store — nothing to migrate
    except OSError:
        return False, ""
    return True, (
        "the spine is in the LEGACY single-file layout (pre-segment) and must be migrated before use — "
        "run `vigil upgrade` (or, sovereign-side, `sigil upgrade`)")


def assert_operable(store: SpineStore | None = None) -> None:
    """Fail-closed startup gate. Raise ``MigrationRequired`` (naming the fix command) if the store needs
    migration; return quietly otherwise. Call this at CLI startup for any command that operates on the
    spine, EXEMPTING the recovery commands that fix it (``upgrade``/``spine``/``doctor``/``restore``/…)."""
    store = store or SpineStore()
    needed, reason = migration_needed(store)
    if needed:
        raise MigrationRequired(reason)


# ----------------------------------------------------------------------------------------------------
# backup + rollback (whole-spine-dir tar.gz, OUTSIDE the spine dir so it is never itself migrated)
# ----------------------------------------------------------------------------------------------------
def _default_backup_dir(spine_dir: Path) -> Path:
    """Where a backup lands by default: a sibling of the spine dir (``…/backups``), so it is OUTSIDE the
    spine dir and can never be swept into a migrate/compact/rollback of the spine dir itself."""
    return spine_dir.parent / "backups"


def _backup_spine_dir(spine_dir: Path, backup_dir: Path) -> Path:
    """tar.gz the WHOLE spine dir into ``backup_dir`` (which MUST be outside ``spine_dir``). Returns the
    backup path. The archive's single root member is ``spine_dir.name`` so a rollback can extract it back
    into ``spine_dir.parent`` and exactly reconstitute the spine dir."""
    spine_dir = spine_dir.resolve()
    backup_dir = backup_dir.resolve()
    if backup_dir == spine_dir or spine_dir in backup_dir.parents:
        raise SpineError(f"refusing to write the backup INSIDE the spine dir ({backup_dir} under {spine_dir}) "
                         "— it would be swept into the migrate/rollback of that dir")
    backup_dir.mkdir(parents=True, exist_ok=True)
    dest = backup_dir / f"spine-upgrade-backup-{int(time.time())}-{os.getpid()}.tar.gz"
    with tarfile.open(dest, "w:gz") as tar:
        tar.add(str(spine_dir), arcname=spine_dir.name)
    return dest


def _safe_extract(tar: tarfile.TarFile, dest: Path) -> None:
    """Extract ``tar`` into ``dest``, refusing any member that would escape ``dest`` (path traversal /
    absolute path / symlink escape). Uses the stdlib 'data' filter when available (3.12+), and always
    applies an explicit belt-and-braces membership check so the guard holds on older interpreters too."""
    dest = dest.resolve()
    for member in tar.getmembers():
        target = (dest / member.name).resolve()
        if target != dest and dest not in target.parents:
            raise SpineError(f"refusing to extract backup member outside the target dir: {member.name!r}")
    try:
        tar.extractall(str(dest), filter="data")            # py3.12+: strips absolute/.. and unsafe links
    except TypeError:                                       # pragma: no cover — older Python without `filter`
        tar.extractall(str(dest))


def _open_store_over(spine_dir: Path, data_name: str, **store_kw) -> SpineStore:
    """Open a SpineStore over a spine dir at ``spine_dir`` whose identity data-file is ``data_name`` (e.g.
    ``spine.jsonl``). The manifest/segments are found by the stem, so this reads a migrated OR legacy layout
    identically — the data-file path need not exist (a migrated store renamed it away)."""
    return SpineStore(spine_dir / data_name, **store_kw)


def verify_backup(backup_tar: Path, data_name: str, *, expect_count: int) -> tuple[bool, str, int]:
    """Prove the backup is RESTORABLE before we mutate anything: extract it to a scratch dir, open the
    store over the extracted spine dir, ``verify()`` it, and assert its record count matches ``expect_count``.
    Returns ``(ok, reason, count)``. A backup that cannot be opened / does not verify / has a different count
    is NOT a safety net, so the caller stops rather than proceeding to migrate."""
    backup_tar = Path(backup_tar)
    with tempfile.TemporaryDirectory(prefix="sigil-upgrade-verify-") as tmp:
        tmpp = Path(tmp)
        try:
            with tarfile.open(backup_tar, "r:gz") as tar:
                _safe_extract(tar, tmpp)
        except (OSError, tarfile.TarError, SpineError) as e:
            return False, f"backup could not be extracted: {e}", -1
        roots = [d for d in tmpp.iterdir() if d.is_dir()]
        if len(roots) != 1:
            return False, f"backup archive has {len(roots)} root dirs (expected 1)", -1
        try:
            store = _open_store_over(roots[0], data_name)
            ok, reason = store.verify()
            count = store.count()
        except Exception as e:  # noqa: BLE001 — a broken backup must fail closed, never crash the upgrade
            return False, f"backup could not be opened/verified: {type(e).__name__}: {e}", -1
        if not ok:
            return False, f"backup does not verify: {reason}", count
        if count != expect_count:
            return False, f"backup record count {count} != live count {expect_count}", count
        return True, "ok", count


def restore_from_backup(spine_dir: Path, backup_tar: Path) -> None:
    """Roll the spine dir back to the (already-verified) backup. Crash-safe: move the current (possibly
    half-migrated) spine dir ASIDE to a quarantine, extract the backup in its place, and only remove the
    quarantine after a successful extract. If the extract fails, the quarantine is moved back so the caller
    is never left with NO spine dir. Raises on failure (the caller wraps it in ``UpgradeFailed``).

    Callers MUST hold the store's cross-process lock / run this as an offline operator step — no other
    process may be appending while the whole dir is swapped."""
    spine_dir = Path(spine_dir).resolve()
    backup_tar = Path(backup_tar)
    parent = spine_dir.parent
    quarantine = parent / f"{spine_dir.name}.rollback-quarantine-{int(time.time() * 1000)}-{os.getpid()}"

    moved_aside = False
    if spine_dir.exists():
        os.replace(spine_dir, quarantine)                   # atomic within the same dir
        moved_aside = True
    try:
        with tarfile.open(backup_tar, "r:gz") as tar:
            _safe_extract(tar, parent)                      # recreates parent/<spine_dir.name>/…
        if not spine_dir.exists():
            raise SpineError(f"rollback extract did not recreate the spine dir at {spine_dir}")
    except BaseException:
        # extract failed — put the original (quarantined) dir back so we never leave NO spine dir at all.
        if moved_aside:
            if spine_dir.exists():
                shutil.rmtree(spine_dir, ignore_errors=True)
            try:
                os.replace(quarantine, spine_dir)
            except OSError:
                pass                                        # last resort: the quarantine still holds the data
        raise
    # success: drop the quarantined half-migrated dir.
    if moved_aside:
        shutil.rmtree(quarantine, ignore_errors=True)


# ----------------------------------------------------------------------------------------------------
# the orchestrator
# ----------------------------------------------------------------------------------------------------
def upgrade(store: SpineStore | None = None, *, backup_dir: Path | None = None,
            backup: bool = True) -> dict:
    """Run the full upgrade: verify(before) -> backup -> verify(backup) -> migrate -> verify(after) ->
    report, ROLLING BACK to the verified backup on ANY failure. Returns the report dict on success.

    Raises:
      * ``SpineError`` (no mutation done) if the store does not verify before we start, or the backup is
        not restorable — in both cases NOTHING was migrated, so there is nothing to roll back;
      * ``UpgradeFailed`` (store rolled back) if a step AFTER the verified backup fails — the store has
        been restored to the backup and ``exc.report`` carries the details.

    ``backup=False`` (tests / a store known to be disposable) skips the backup+rollback frame and just runs
    the verified migrate; it will still refuse to migrate a non-verifying store."""
    store = store or SpineStore()
    spine_dir = store._layout.spine_dir
    data_name = store._layout.data_path.name
    report: dict = {"spine_dir": str(spine_dir), "steps": [], "rolled_back": False,
                    "rollback_verified": None, "ok": False}

    def _step(name: str, **kw) -> None:
        report["steps"].append({"step": name, **kw})

    # 1. verify BEFORE — never migrate a corrupt/non-verifying store forward.
    ok, reason = store.verify()
    report["verify_before"] = {"ok": ok, "reason": reason}
    _step("verify_before", ok=ok, reason=reason)
    if not ok:
        raise SpineError(f"refusing to upgrade a spine that does not verify: {reason}")
    count_before = store.count()
    report["count_before"] = count_before

    # 2. backup + 3. verify the backup is RESTORABLE (before touching anything).
    backup_path: Path | None = None
    if backup:
        backup_path = _backup_spine_dir(spine_dir, backup_dir or _default_backup_dir(spine_dir))
        report["backup"] = str(backup_path)
        _step("backup", path=str(backup_path))
        bok, breason, bcount = verify_backup(backup_path, data_name, expect_count=count_before)
        report["verify_backup"] = {"ok": bok, "reason": breason, "count": bcount}
        _step("verify_backup", ok=bok, reason=breason, count=bcount)
        if not bok:
            # nothing migrated yet — no rollback needed; refuse to proceed without a restorable backup.
            raise SpineError(f"refusing to upgrade: the backup is not restorable ({breason}); "
                             f"backup left at {backup_path}")
    else:
        report["backup"] = "(skipped)"

    # 4. migrate + 5. verify AFTER, with ROLLBACK on any failure.
    try:
        migrated = store.migrate()
        report["migrated"] = migrated
        _step("migrate", migrated=migrated)
        # A fresh conversion drops every record into one ACTIVE seg-0; seal it so compaction can gzip it
        # (compact only touches SEALED segments). On a re-run (already migrated) leave the active alone and
        # just gzip any sealed plaintext.
        sealed = SpineStore(store.path).rotate() if migrated else False
        report["sealed"] = sealed
        _step("seal", sealed=sealed)

        fresh = SpineStore(store.path)
        ok, reason = fresh.verify()
        report["verify_after_migrate"] = {"ok": ok, "reason": reason}
        _step("verify_after_migrate", ok=ok, reason=reason)
        if not ok:
            raise UpgradeFailed(f"verify FAILED after migrate: {reason}", report)

        compacted = SpineStore(store.path).compact()
        report["compacted"] = compacted
        _step("compact", segments=compacted)

        final = SpineStore(store.path)
        ok, reason = final.verify()
        count_after = final.count()
        report["verify_after"] = {"ok": ok, "reason": reason}
        report["count_after"] = count_after
        _step("verify_after", ok=ok, reason=reason, count=count_after)
        if not ok:
            raise UpgradeFailed(f"verify FAILED after compact: {reason}", report)
        if count_after != count_before:
            raise UpgradeFailed(
                f"record count changed {count_before} -> {count_after} — retain-all must preserve every "
                f"record", report)
    except BaseException as exc:  # includes KeyboardInterrupt — a Ctrl-C mid-migrate MUST still roll back
        if backup and backup_path is not None:
            report["rolled_back"] = True
            _step("rollback", backup=str(backup_path))
            try:
                restore_from_backup(spine_dir, backup_path)
                restored = SpineStore(store.path)
                rok, rreason = restored.verify()
                rcount = restored.count()
                report["rollback_verified"] = bool(rok and rcount == count_before)
                report["rollback_verify"] = {"ok": rok, "reason": rreason, "count": rcount}
                _step("rollback_verify", ok=rok, reason=rreason, count=rcount)
            except Exception as rexc:  # noqa: BLE001 — surface the rollback failure loudly, keep the backup
                report["rollback_verified"] = False
                report["rollback_error"] = f"{type(rexc).__name__}: {rexc}"
                _step("rollback_error", error=report["rollback_error"])
                raise UpgradeFailed(
                    f"upgrade FAILED and the automatic rollback ALSO failed ({rexc}); the verified backup "
                    f"is at {backup_path} — restore it by hand. Original error: {exc}", report) from exc
        # Re-raise as UpgradeFailed carrying the report (unless it already is one).
        if isinstance(exc, UpgradeFailed):
            raise
        raise UpgradeFailed(
            f"upgrade FAILED ({type(exc).__name__}: {exc}); "
            + ("rolled back to the verified backup" if report["rolled_back"] else "no backup was taken"),
            report) from exc

    report["ok"] = True
    return report
