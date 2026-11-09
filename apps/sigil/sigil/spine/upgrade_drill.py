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

``ok`` iff every step held. Honest tiering: a box with no spine data is ``NOT-RUN`` (exit 3), never green.
DEFAULT-OFF: nothing runs unless an operator invokes ``python -m sigil.spine.upgrade_drill`` or installs the
opt-in ``vigil-upgrade-drill`` timer. Sovereign plane; imports no offense code.
"""
from __future__ import annotations

import gzip
import hashlib
import json
import shutil
import sys
import tempfile
from pathlib import Path
from typing import Optional

from .store import SpineStore
from .upgrade import restore_from_backup, upgrade

PASS = "PASS"
FAIL = "FAIL"
NOT_RUN = "NOT-RUN"

_SKIP_NAMES = {"spine.lock"}


def _tree_digest(root: Path) -> str:
    """A content digest of every regular file under ``root`` (relative path + bytes), lock files excluded.
    Used to PROVE the drill never modified the real spine directory."""
    h = hashlib.sha256()
    for p in sorted(root.rglob("*")):
        if p.is_file() and not p.is_symlink() and p.name not in _SKIP_NAMES:
            h.update(str(p.relative_to(root)).encode("utf-8", "surrogateescape") + b"\0")
            h.update(p.read_bytes())
            h.update(b"\0")
    return h.hexdigest()


def _has_data(spine_dir: Path) -> bool:
    for p in spine_dir.rglob("*"):
        if p.is_file() and (p.name.endswith(".jsonl") or p.name.endswith(".jsonl.gz")) and p.stat().st_size > 0:
            return True
    return False


def corrupt_one_record(spine_dir: Path) -> bool:
    """Wrap the payload of the FIRST record found (open ``*.jsonl`` first, else a sealed ``*.jsonl.gz``) so it
    no longer matches its ``cert_digest``. Works on any real record (no reliance on particular payload words).
    Returns True IFF a record was actually corrupted."""
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

    for p in sorted(spine_dir.rglob("*.jsonl")):
        out = _mutate(p.read_bytes())
        if out is not None:
            p.write_bytes(out)
            return True
    for p in sorted(spine_dir.rglob("*.jsonl.gz")):
        out = _mutate(gzip.decompress(p.read_bytes()))
        if out is not None:
            p.write_bytes(gzip.compress(out))
            return True
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

    before = _tree_digest(src_dir)
    copy_dir = Path(work_dir) / "spine"
    shutil.copytree(src_dir, copy_dir, symlinks=False,
                    ignore=shutil.ignore_patterns(*_SKIP_NAMES))
    data = copy_dir / spine_path.name
    steps.append({"step": "copy", "to": str(copy_dir)})

    try:
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

        corrupted = corrupt_one_record(copy_dir)
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
        after = _tree_digest(src_dir)
        verdict["source_untouched"] = after == before
        steps.append({"step": "source_untouched", "ok": after == before})

    if not verdict["source_untouched"]:
        return done(FAIL, "the REAL spine directory changed during the drill — investigate immediately")
    verdict["count"] = count
    return done(PASS, f"real spine ({count} records) upgraded under this build, a corrupted deployment was "
                      f"detected, and rollback restored it intact; the real home was not modified")


def main(argv: "Optional[list[str]]" = None) -> int:
    """``python -m sigil.spine.upgrade_drill [--spine PATH] [--work-dir DIR] [--json]`` — exit 0 PASS,
    1 FAIL, 3 NOT-RUN (no data)."""
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
    return {PASS: 0, NOT_RUN: 3}.get(v["status"], 1)


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
