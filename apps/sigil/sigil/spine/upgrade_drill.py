"""DEP-3 (#73) — the on-box UPGRADE / ROLLBACK DRILL: prove THIS box's real spine still upgrades and rolls back.

``vigil upgrade`` (W5-5, ``spine/upgrade.py``) is crash-safe and rolls back on failure, and ``deploy_verify``
(W11-8) proves the deploy -> smoke -> auto-rollback pipeline — but both are exercised in CI against a
SYNTHETIC N-1 spine. Nothing periodically proved that the box's OWN data, at its current size and shape,
still migrates under the installed build and that the rollback target actually restores it. An upgrade you
have never drilled against your real data is a hope, the same way an un-restored backup is.

:func:`run_upgrade_drill` is that drill (mirrors ``tools/backup/recovery_drill.sh`` + ``vigil-backup-drill``):

  1. COPY the real spine directory into a throwaway work dir — the real home is NEVER opened for write; a
     content digest of the source tree taken before and after must match (proven, not assumed);
  2. verify the copy (chain) and record its count + sequence set;
  3. run the REAL ``upgrade()`` orchestrator on the copy (it takes + verifies its own pre-upgrade backup);
  4. verify the upgraded copy: chain OK, count and sequence set preserved;
  5. NEGATIVE CONTROL — corrupt one record of the upgraded copy and prove verification now FAILS (a drill that
     cannot detect a broken deployment is a rubber stamp);
  6. ROLL BACK with ``restore_from_backup`` and prove the restored copy verifies with the pre-upgrade count +
     sequence set exactly.

``ok`` iff every step held. Honest tiering: a box with no spine data is ``NOT-RUN`` (exit 3), never green; a
real spine that a concurrent writer changed while the drill ran is ``INCONCLUSIVE`` (exit 4), never green and
never an accusation (the drill writes only inside its work dir, which it REFUSES to place inside — or around —
the real spine dir). The copy is a CONSISTENT snapshot: taken under a SHARED flock on the store's own
cross-process lockfile (writers hold it exclusively per append) and proven byte-faithful by digest. The
cold-archive (``spine/archive/``, pruned history the live chain no longer reads) is not copied.
DEFAULT-OFF: nothing runs unless an operator invokes ``python -m sigil.spine.upgrade_drill`` or installs the
opt-in ``vigil-upgrade-drill`` timer. Sovereign plane; imports no offense code.
"""
from __future__ import annotations

import gzip
import hashlib
import json
import os
import shutil
import sys
import tempfile
from contextlib import contextmanager
from pathlib import Path
from typing import Callable, Iterator, Optional

from .store import SpineStore
from .upgrade import restore_from_backup, upgrade

PASS = "PASS"
FAIL = "FAIL"
NOT_RUN = "NOT-RUN"
INCONCLUSIVE = "INCONCLUSIVE"

_SKIP_DIRS = {"archive"}             # cold-archive of pruned segments — never read by live verify/upgrade


def _skipped(rel: Path) -> bool:
    return bool(rel.parts) and (rel.parts[0] in _SKIP_DIRS or rel.name.endswith(".lock"))


def _iter_files(root: Path) -> Iterator["tuple[Path, Path]"]:
    for p in sorted(root.rglob("*")):
        rel = p.relative_to(root)
        if _skipped(rel) or p.is_symlink() or not p.is_file():
            continue
        yield p, rel


def _tree_digest(root: Path) -> str:
    """A streamed content digest of every regular file under ``root`` (relative path + bytes); lockfiles and the
    cold-archive excluded. Proves the copy is faithful and that the real spine dir was not changed."""
    h = hashlib.sha256()
    for p, rel in _iter_files(root):
        h.update(str(rel).encode("utf-8", "surrogateescape") + b"\0")
        with open(p, "rb") as f:
            for chunk in iter(lambda: f.read(1 << 20), b""):
                h.update(chunk)
        h.update(b"\0")
    return h.hexdigest()


def _has_data(spine_dir: Path) -> bool:
    for p, rel in _iter_files(spine_dir):
        if (p.name.endswith(".jsonl") or p.name.endswith(".jsonl.gz")) and p.stat().st_size > 0:
            return True
    return False


@contextmanager
def _shared_writer_lock(spine_dir: Path, data_name: str) -> Iterator[None]:
    """Hold a SHARED flock on the store's cross-process lockfile (``<ns>.lock``; writers take it EXCLUSIVELY per
    append) so a snapshot is consistent. Opened READ-ONLY and never created (the real home may be read-only);
    best-effort: no lockfile ⇒ no writer has ever run here ⇒ nothing to exclude."""
    fd = None
    lock = spine_dir / f"{Path(data_name).stem}.lock"
    try:
        if lock.is_file():
            import fcntl
            fd = os.open(str(lock), os.O_RDONLY)
            fcntl.flock(fd, fcntl.LOCK_SH)
    except Exception:  # noqa: BLE001 — best effort (non-POSIX / unreadable lock): the digest still proves it
        if fd is not None:
            os.close(fd)
        fd = None
    try:
        yield
    finally:
        if fd is not None:
            try:
                import fcntl
                fcntl.flock(fd, fcntl.LOCK_UN)
            finally:
                os.close(fd)


def _overlaps(a: Path, b: Path) -> bool:
    a, b = a.resolve(), b.resolve()
    return a == b or a in b.parents or b in a.parents


def corrupt_one_record(spine_dir: Path, verify: Optional[Callable[[], "tuple[bool, str]"]] = None) -> bool:
    """Wrap one record's payload so it no longer matches its ``cert_digest`` (works on any real record — no
    reliance on particular payload words). Candidates: open ``*.jsonl`` first, then sealed ``*.jsonl.gz``,
    never the cold-archive. With ``verify``, a corruption the live chain does NOT read (verify still passes) is
    REVERTED and the next candidate tried, so the negative control always lands on data the store verifies.
    Returns True IFF a record was corrupted (and, with ``verify``, verification now fails)."""
    def _mutate(raw: bytes) -> Optional[bytes]:
        lines = raw.split(b"\n")
        for i, line in enumerate(lines):
            if not line.strip():
                continue
            try:
                obj = json.loads(line)
            except ValueError:
                continue
            if isinstance(obj, dict) and "payload" in obj:
                obj["payload"] = {"__upgrade_drill_corruption__": obj.get("payload")}
                lines[i] = json.dumps(obj, sort_keys=True).encode("utf-8")
                return b"\n".join(lines)
        return None

    files = [p for p, _rel in _iter_files(spine_dir)]
    for p in [f for f in files if f.name.endswith(".jsonl")] + [f for f in files if f.name.endswith(".jsonl.gz")]:
        orig = p.read_bytes()
        gz = p.name.endswith(".gz")
        out = _mutate(gzip.decompress(orig) if gz else orig)
        if out is None:
            continue
        p.write_bytes(gzip.compress(out) if gz else out)
        if verify is None or not verify()[0]:
            return True
        p.write_bytes(orig)                   # not on the live verify path — revert, try the next candidate
    return False


def run_upgrade_drill(spine_path: Path, work_dir: Path) -> dict:
    """Drill the spine whose stable data path is ``spine_path`` (``…/spine.jsonl``) inside ``work_dir``.
    Returns a JSON-safe verdict ``{status, ok, detail, steps, ...}``; never modifies ``spine_path``'s dir."""
    spine_path = Path(spine_path)
    src_dir = spine_path.parent
    steps: list = []
    verdict: dict = {"status": FAIL, "ok": False, "detail": "", "source": str(src_dir), "steps": steps}

    def done(status: str, detail: str) -> dict:
        verdict["status"], verdict["ok"], verdict["detail"] = status, status == PASS, detail
        return verdict

    if not src_dir.is_dir() or not _has_data(src_dir):
        return done(NOT_RUN, f"no spine data at {src_dir} — nothing to drill (NOT-RUN is never green)")
    work_dir = Path(work_dir)
    if _overlaps(work_dir, src_dir):
        # a work dir INSIDE the spine would copy into the real spine; one AROUND it would be deleted on cleanup
        return done(FAIL, f"refusing: the work dir {work_dir} overlaps the real spine dir {src_dir}")

    copy_dir = work_dir / "spine"
    data = copy_dir / spine_path.name
    before: Optional[str] = None

    def _ignore(dirpath: str, names: list) -> set:
        rel = Path(dirpath).resolve().relative_to(src_dir.resolve())
        return {n for n in names if _skipped(rel / n)}

    try:
        for _attempt in range(3):
            if copy_dir.exists():
                shutil.rmtree(copy_dir)
            with _shared_writer_lock(src_dir, spine_path.name):
                before = _tree_digest(src_dir)
                shutil.copytree(src_dir, copy_dir, symlinks=False, ignore=_ignore, ignore_dangling_symlinks=True)
                mid = _tree_digest(src_dir)
            if before == mid and _tree_digest(copy_dir) == before:
                break
        else:
            before = None
            return done(INCONCLUSIVE, "could not take a consistent snapshot of the real spine (a concurrent "
                                      "writer kept changing it) — re-run when the spine is idle")
        steps.append({"step": "copy", "to": str(copy_dir), "consistent": True})

        pre = SpineStore(str(data))
        ok, why = pre.verify()
        count, seqs = pre.count(), [r.seq for r in pre.iter_records()]
        steps.append({"step": "verify_copy", "ok": ok, "why": why, "count": count})
        if not ok:
            return done(FAIL, f"the real spine (copied) does not verify — fix that before any upgrade: {why}")

        rep = upgrade(SpineStore(str(data)), backup_dir=Path(work_dir) / "backups")
        backup = Path(rep["backup"])
        steps.append({"step": "upgrade", "ok": bool(rep.get("ok")), "migrated": rep.get("migrated"),
                      "backup": str(backup)})

        up = SpineStore(str(data))
        uok, uwhy = up.verify()
        u_intact = up.count() == count and [r.seq for r in up.iter_records()] == seqs
        steps.append({"step": "verify_upgraded", "ok": uok, "why": uwhy, "intact": u_intact})
        if not (uok and u_intact):
            return done(FAIL, f"the upgraded copy is not intact (verify={uok}: {uwhy}; intact={u_intact})")

        corrupted = corrupt_one_record(copy_dir, verify=lambda: SpineStore(str(data)).verify())
        cok, cwhy = SpineStore(str(data)).verify() if corrupted else (True, "")
        steps.append({"step": "negative_control", "corrupted": corrupted, "detected": corrupted and not cok,
                      "why": cwhy})
        if not corrupted or cok:
            return done(FAIL, "negative control did not bite: a corrupted upgraded spine was NOT detected")

        restore_from_backup(copy_dir, backup)
        rs = SpineStore(str(data))
        rok, rwhy = rs.verify()
        r_intact = rs.count() == count and [r.seq for r in rs.iter_records()] == seqs
        steps.append({"step": "rollback", "ok": rok, "why": rwhy, "intact": r_intact})
        if not (rok and r_intact):
            return done(FAIL, f"rollback did not restore the pre-upgrade spine (verify={rok}: {rwhy}; "
                              f"intact={r_intact})")
    except Exception as exc:  # noqa: BLE001 — any drill fault is a FAILED drill, reported, never a crash
        steps.append({"step": "error", "error": f"{type(exc).__name__}: {exc}"})
        return done(FAIL, f"drill error: {type(exc).__name__}: {exc}")
    finally:
        if before is not None:
            after: Optional[str]
            try:
                with _shared_writer_lock(src_dir, spine_path.name):
                    after = _tree_digest(src_dir)
            except Exception:  # noqa: BLE001
                after = None
            verdict["source_unchanged"] = after == before
            steps.append({"step": "source_unchanged", "ok": after == before})

    if not verdict.get("source_unchanged"):
        return done(INCONCLUSIVE, "the real spine changed while the drill ran — most likely a concurrent writer "
                                  "appended (the drill writes only inside its work dir, verified to be outside the "
                                  f"spine dir: {work_dir}). Re-run when the spine is idle.")
    verdict["count"] = count
    migrated = bool(next((st.get("migrated") for st in steps if st["step"] == "upgrade"), False))
    what = ("migrated to the segment layout under this build" if migrated else
            "already migrated — the verify → backup → compact → restore path was exercised")
    return done(PASS, f"real spine ({count} records): {what}; a corrupted deployment was detected and rollback "
                      f"restored it intact; the real spine was not modified")


def main(argv: "Optional[list[str]]" = None) -> int:
    """``python -m sigil.spine.upgrade_drill [--spine PATH] [--work-dir DIR] [--json]`` — exit 0 PASS,
    1 FAIL, 3 NOT-RUN (no data), 4 INCONCLUSIVE (a concurrent writer changed the real spine)."""
    import argparse

    from ..config import SPINE_PATH

    ap = argparse.ArgumentParser(description="VIGIL on-box upgrade/rollback drill (DEP-3) — never touches the "
                                             "real spine; drills a throwaway copy")
    ap.add_argument("--spine", default=str(SPINE_PATH), help="the spine data path (default: this home's)")
    ap.add_argument("--work-dir", default="", help="parent for the throwaway work dir (default: $TMPDIR)")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args(argv)
    with tempfile.TemporaryDirectory(prefix="vigil-upgrade-drill-", dir=a.work_dir or None) as tmp:
        v = run_upgrade_drill(Path(a.spine), Path(tmp))
    if a.json:
        print(json.dumps(v, indent=2, sort_keys=True))
    else:
        print(f"upgrade_drill: {v['status']} — {v['detail']}")
        for s in v["steps"]:
            print(f"  - {s}")
    return {PASS: 0, NOT_RUN: 3, INCONCLUSIVE: 4}.get(v["status"], 1)


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
