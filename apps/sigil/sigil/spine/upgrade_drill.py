"""DEP-3 (#73) — the on-box UPGRADE / ROLLBACK DRILL: prove THIS box's real spine still upgrades and rolls back.

``vigil upgrade`` (W5-5, ``spine/upgrade.py``) is crash-safe and rolls back on failure, and ``deploy_verify``
(W11-8) proves the deploy -> smoke -> auto-rollback pipeline — but both are exercised in CI against a
SYNTHETIC N-1 spine. Nothing periodically proved that the box's OWN data, at its current size and shape,
still migrates under the installed build and that the rollback target actually restores it. An upgrade you
have never drilled against your real data is a hope, the same way an un-restored backup is.

:func:`run_upgrade_drill` is that drill (mirrors ``tools/backup/recovery_drill.sh`` + ``vigil-backup-drill``):

  1. SNAPSHOT the real spine directory (and its sibling anti-rollback floor) into a scratch HOME inside a
     throwaway work dir. The snapshot is CONSISTENT: taken under a SHARED flock on the store's own
     cross-process lockfile (writers hold it exclusively per append) and proven byte-faithful by a content
     digest taken before and after the copy; an attempt that raced something outside that lock (a concurrent
     ``sigil sign`` rewriting the head / floor, or renaming its temp file away mid-copy) is retried, a bounded
     number of times;
  2. the remaining steps run in a CHILD process whose ``SIGIL_HOME`` is that scratch home and whose ``TMPDIR``
     is inside the work dir (it refuses to run otherwise, and refuses any copy its parent did not make — a
     one-shot nonce), so every path the spine code derives — the signed head, the owner PUBLIC key, the
     anti-rollback floor, the upgrade's backup-verify extract — resolves INSIDE the work dir. The child is never
     told where the real home is;
  3. verify the copy (chain; a pruned window is corroborated by the COPY's own signed head with the owner
     PUBLIC key) and record its count + sequence set;
  4. run the REAL ``upgrade()`` orchestrator on the copy (it takes + verifies its own pre-upgrade backup);
  5. verify the upgraded copy: chain OK, count and sequence set preserved;
  6. NEGATIVE CONTROL — corrupt one record of the upgraded copy and prove verification now FAILS (a drill that
     cannot detect a broken deployment is a rubber stamp);
  7. ROLL BACK with ``restore_from_backup`` and prove the restored copy verifies with the pre-upgrade count +
     sequence set exactly.

SECRETS ARE NEVER COPIED. The owner PRIVATE key (and the spine DEK, and anything else under ``keys/`` that is
not a ``*.pub``) is excluded from the snapshot, so it never lands in the scratch tree or in the backup tarball
the upgrade writes there. Verification is keyless or public-key-only, so nothing in the drill needs it. A
private key that nevertheless appears anywhere under the work dir, or owner key material in the REAL ``keys/``
that changed while the drill ran, FAILS the drill.

VERDICTS (exit codes): ``PASS`` (0) iff every step held on the consistent snapshot. ``FAIL`` (1) on any step
that did not hold. ``NOT-RUN`` (3) — no spine data — never green. ``INCONCLUSIVE`` (4) ONLY when no
consistent snapshot could be taken (something kept changing the spine even under the shared lock) — never
green. A real spine that a concurrent writer APPENDED to after the snapshot is EXPECTED on a busy box and does
not change the verdict (the drill verified a consistent point-in-time copy and, by construction, writes only
inside its work dir — which it REFUSES to place inside or around the real spine dir); it is reported as
``source_changed_during_drill``. The cold-archive (``spine/archive/``, pruned history the live chain no longer
reads) is not copied. DEFAULT-OFF: nothing runs unless an operator invokes ``python -m sigil.spine.upgrade_drill``
or installs the opt-in ``vigil-upgrade-drill`` timer. Sovereign plane; imports no offense code.
"""
from __future__ import annotations

import gzip
import hashlib
import hmac
import json
import os
import secrets
import shutil
import subprocess
import sys
import tempfile
import time
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
_KEYS_DIR = "keys"                   # <spine>/keys: owner.priv|pub, owner.genesis.pub, spine.dek
_SNAPSHOT_ATTEMPTS = 5
_CHILD_FLAG = "--isolated-copy"      # internal: run the drill steps on an already-taken scratch-home snapshot
_CHILD_TIMEOUT_S = 6 * 3600
_NONCE_FILE = ".isolated-copy-nonce"  # <work_dir>/…: the parent's one-shot proof that it made the copy
_NONCE_ENV = "VIGIL_UPGRADE_DRILL_NONCE"


def _is_secret(rel: Path) -> bool:
    """Key material the drill must NEVER copy: anything under ``keys/`` that is not a public key, plus any
    ``*.priv`` / ``*.dek`` file wherever it sits. Verification is keyless / public-key-only."""
    name = rel.name
    if name.endswith(".priv") or name.endswith(".dek"):
        return True
    return bool(rel.parts) and rel.parts[0] == _KEYS_DIR and len(rel.parts) > 1 and not name.endswith(".pub")


def _skipped(rel: Path) -> bool:
    """Never copied or digested: the cold-archive, lockfiles, and the transient temp file of an atomic write
    (``.head-*.tmp`` / ``.tmp-*.tmp`` / a segment's ``.*.gz.tmp``) — a concurrent ``sigil sign`` renames it away
    at any moment, and nothing ever reads it."""
    name = rel.name
    return bool(rel.parts) and (rel.parts[0] in _SKIP_DIRS or name.endswith(".lock")
                                or (name.startswith(".") and name.endswith(".tmp")))


def _iter_files(root: Path) -> Iterator["tuple[Path, Path]"]:
    for p in sorted(root.rglob("*")):
        rel = p.relative_to(root)
        if _skipped(rel) or _is_secret(rel) or p.is_symlink() or not p.is_file():
            continue
        yield p, rel


def _tree_digest(root: Path) -> str:
    """A streamed content digest of every regular file under ``root`` (relative path + bytes); lockfiles, the
    cold-archive and secret key files excluded (their bytes are never read). Proves the copy is faithful."""
    h = hashlib.sha256()
    for p, rel in _iter_files(root):
        h.update(str(rel).encode("utf-8", "surrogateescape") + b"\0")
        with open(p, "rb") as f:
            for chunk in iter(lambda: f.read(1 << 20), b""):
                h.update(chunk)
        h.update(b"\0")
    return h.hexdigest()


def _key_fingerprint(spine_dir: Path) -> str:
    """A METADATA fingerprint of the real ``keys/`` dir (name, size, mtime, inode, mode — the private key's
    bytes are never read). Ordinary appends never touch owner key material, so a change while the drill ran
    is a key mint/rotation that must not pass unnoticed."""
    kd = spine_dir / _KEYS_DIR
    rows = []
    try:
        for p in sorted(kd.iterdir()):
            st = p.lstat()
            rows.append(f"{p.name}:{st.st_size}:{st.st_mtime_ns}:{st.st_ino}:{st.st_mode}")
    except FileNotFoundError:
        rows.append("<absent>")
    except OSError as e:
        rows.append(f"<unreadable:{type(e).__name__}>")
    return hashlib.sha256("\n".join(rows).encode("utf-8", "surrogateescape")).hexdigest()


def _private_keys_under(root: Path) -> "list[str]":
    """Every secret key file anywhere under ``root``, by NAME (contents never read) — the :func:`_is_secret` rule
    wherever it sits: a ``*.priv`` / ``*.dek``, or any non-``*.pub`` file inside a ``keys/`` dir."""
    out = []
    for p in root.rglob("*"):
        if p.is_file() and (p.name.endswith((".priv", ".dek"))
                            or (p.parent.name == _KEYS_DIR and not p.name.endswith(".pub"))):
            out.append(str(p.relative_to(root)))
    return sorted(out)


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


def drill_copy(data: Path, work_dir: Path) -> dict:
    """Steps 3-7 on an ALREADY-TAKEN snapshot whose data path is ``data`` (``<scratch home>/spine/spine.jsonl``).
    Runs in the isolated child (``SIGIL_HOME`` == the scratch home) — every write lands under ``work_dir``.
    Returns ``{status, detail, steps, count, migrated}``; any fault is a FAIL, never a crash."""
    data, work_dir = Path(data), Path(work_dir)
    copy_dir = data.parent
    steps: list = []
    out: dict = {"status": FAIL, "detail": "", "steps": steps, "count": None, "migrated": None}

    def done(status: str, detail: str) -> dict:
        out["status"], out["detail"] = status, detail
        return out

    try:
        leaked = _private_keys_under(copy_dir.parent)
        if leaked:
            return done(FAIL, f"refusing: secret key material is present in the drill copy ({leaked})")

        pre = SpineStore(str(data))
        ok, why = pre.verify()
        count, seqs = pre.count(), [r.seq for r in pre.iter_records()]
        steps.append({"step": "verify_copy", "ok": ok, "why": why, "count": count})
        if not ok:
            return done(FAIL, f"the real spine (copied) does not verify — fix that before any upgrade: {why}")

        rep = upgrade(SpineStore(str(data)), backup_dir=work_dir / "backups")
        backup = Path(rep["backup"])
        out["migrated"] = rep.get("migrated")
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
    out["count"] = count
    return done(PASS, "ok")


def _run_isolated(data: Path, work_dir: Path) -> dict:
    """Run :func:`drill_copy` in a CHILD process scoped to the scratch home (``SIGIL_HOME`` = ``data``'s home,
    ``TMPDIR`` inside the work dir). The child's import-time config therefore derives the head, key and floor
    paths from the COPY — the real home is never named to it."""
    import sigil
    pkg_root = str(Path(sigil.__file__).resolve().parent.parent)
    tmp = work_dir / "tmp"
    tmp.mkdir(parents=True, exist_ok=True)
    env = dict(os.environ)
    env["SIGIL_HOME"] = str(data.parent.parent)
    env["TMPDIR"] = str(tmp)
    env["PYTHONPATH"] = os.pathsep.join([pkg_root] + ([env["PYTHONPATH"]] if env.get("PYTHONPATH") else []))
    nonce, nonce_file = secrets.token_hex(16), work_dir / _NONCE_FILE
    nonce_file.unlink(missing_ok=True)
    fd = os.open(str(nonce_file), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.write(fd, nonce.encode("ascii"))
    finally:
        os.close(fd)
    env[_NONCE_ENV] = nonce
    try:
        proc = subprocess.run(
            [sys.executable, "-m", "sigil.spine.upgrade_drill", _CHILD_FLAG, str(data), "--work-dir", str(work_dir)],
            cwd=str(work_dir), env=env, capture_output=True, text=True, timeout=_CHILD_TIMEOUT_S)
    finally:
        nonce_file.unlink(missing_ok=True)
    try:
        res = json.loads(proc.stdout.strip().splitlines()[-1])
        if not isinstance(res, dict) or "status" not in res:
            raise ValueError("no verdict")
        return res
    except (ValueError, IndexError):
        tail = (proc.stderr or proc.stdout or "").strip()[-600:]
        return {"status": FAIL, "detail": f"the isolated drill process failed (rc={proc.returncode}): {tail}",
                "steps": [{"step": "error", "error": f"isolated child rc={proc.returncode}"}],
                "count": None, "migrated": None}


def _snapshot(src_dir: Path, data_name: str, home: Path) -> "Optional[str]":
    """Copy the real spine dir (minus secrets / archive / lockfiles) to ``home/spine`` and the sibling floor to
    ``home/floor.json`` under the shared writer lock. Returns the source spine-dir digest of a CONSISTENT
    snapshot (spine dir AND floor unchanged across the copy, copy byte-faithful), or None if every attempt raced
    a writer."""
    copy_dir = home / "spine"
    floor_src = src_dir.parent / "floor.json"

    def _ignore(dirpath: str, names: list) -> set:
        rel = Path(dirpath).resolve().relative_to(src_dir.resolve())
        return {n for n in names
                if _skipped(rel / n) or (not (Path(dirpath) / n).is_dir() and _is_secret(rel / n))}

    def _floor_digest() -> str:
        try:
            return hashlib.sha256(floor_src.read_bytes()).hexdigest()
        except OSError:
            return "<absent>"

    for attempt in range(_SNAPSHOT_ATTEMPTS):
        if home.exists():
            shutil.rmtree(home)
        home.mkdir(parents=True)
        try:
            with _shared_writer_lock(src_dir, data_name):
                tree = _tree_digest(src_dir)
                before = tree + _floor_digest()
                shutil.copytree(src_dir, copy_dir, symlinks=False, ignore=_ignore, ignore_dangling_symlinks=True)
                if floor_src.is_file():
                    shutil.copyfile(floor_src, home / "floor.json")
                mid = _tree_digest(src_dir) + _floor_digest()
            copied = _tree_digest(copy_dir) + (hashlib.sha256((home / "floor.json").read_bytes()).hexdigest()
                                               if (home / "floor.json").is_file() else "<absent>")
        except OSError:              # (shutil.Error is one) a file renamed away mid-walk by a concurrent sign:
            if attempt == _SNAPSHOT_ATTEMPTS - 1:          # an inconsistent attempt — but a PERSISTENT error
                raise                                       # (unreadable file) is reported as the real FAIL
            time.sleep(0.2 * (attempt + 1))
            continue
        if before == mid == copied:
            return tree
        time.sleep(0.2 * (attempt + 1))
    return None


def run_upgrade_drill(spine_path: Path, work_dir: Path) -> dict:
    """Drill the spine whose stable data path is ``spine_path`` (``…/spine.jsonl``) inside ``work_dir``.
    Returns a JSON-safe verdict ``{status, ok, detail, steps, ...}``; never writes outside ``work_dir``."""
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

    home = work_dir / "home"
    data = home / "spine" / spine_path.name
    keys_before = _key_fingerprint(src_dir)
    try:
        before = _snapshot(src_dir, spine_path.name, home)
    except Exception as exc:  # noqa: BLE001 — a copy fault is a FAILED drill, reported, never a crash
        steps.append({"step": "error", "error": f"{type(exc).__name__}: {exc}"})
        return done(FAIL, f"drill error: {type(exc).__name__}: {exc}")
    if before is None:
        return done(INCONCLUSIVE, "could not take a consistent snapshot of the real spine (it kept changing even "
                                  "under the shared writer lock) — re-run when the spine is idle")
    steps.append({"step": "copy", "to": str(data.parent), "consistent": True, "secrets_copied": False})

    try:
        res = _run_isolated(data, work_dir)
    except Exception as exc:  # noqa: BLE001
        res = {"status": FAIL, "detail": f"drill error: {type(exc).__name__}: {exc}",
               "steps": [{"step": "error", "error": f"{type(exc).__name__}: {exc}"}]}
    steps.extend(res.get("steps") or [])

    leaked = _private_keys_under(work_dir)
    steps.append({"step": "no_secrets_in_work_dir", "ok": not leaked, "found": leaked})
    keys_unchanged = _key_fingerprint(src_dir) == keys_before
    steps.append({"step": "real_keys_unchanged", "ok": keys_unchanged})
    try:
        with _shared_writer_lock(src_dir, spine_path.name):
            after: Optional[str] = _tree_digest(src_dir)
    except Exception:  # noqa: BLE001
        after = None
    changed = after != before
    verdict["source_changed_during_drill"] = changed
    steps.append({"step": "source_changed_during_drill", "changed": changed})

    if leaked:
        return done(FAIL, f"secret key material appeared under the drill work dir ({leaked}) — an isolation "
                          "fault; the drill must never hold a private key")
    if not keys_unchanged:
        return done(FAIL, f"owner key material in the REAL {src_dir / _KEYS_DIR} changed while the drill ran "
                          "(a key mint/rotation) — investigate before trusting this box's trust root")
    if res.get("status") != PASS:
        return done(str(res.get("status") or FAIL), str(res.get("detail") or "drill failed"))
    count = res.get("count")
    verdict["count"] = count
    what = ("migrated to the segment layout under this build" if res.get("migrated") else
            "already migrated — the verify → backup → compact → restore path was exercised")
    busy = ("; the live spine took concurrent writes during the drill (expected on a busy box — the drill "
            "verified a consistent snapshot)" if changed else "")
    return done(PASS, f"real spine ({count} records, consistent snapshot): {what}; a corrupted deployment was "
                      f"detected and rollback restored it intact; the drill wrote only inside its work dir{busy}")


def _child_main(data: str, work_dir: str) -> int:
    """The isolated child runs the (destructive) steps ONLY on a copy its parent made. It refuses unless the
    parent's one-shot nonce (env) matches the nonce file the parent wrote into the work dir (consumed here, so it
    never authorizes a second run), the data path is exactly ``<work_dir>/home/spine/<name>``, this process's
    SIGIL_HOME IS ``<work_dir>/home``, and its temp dir (the upgrade's backup-verify extract lands there) is
    inside the work dir — so a hand-run of this hidden entry point against a real home never touches it."""
    from .. import config
    d, w = Path(data), Path(work_dir).resolve()
    home = (w / "home").resolve()
    nonce_file = w / _NONCE_FILE
    try:
        made = nonce_file.read_text(encoding="ascii").strip()
        nonce_file.unlink()
    except (OSError, UnicodeDecodeError):
        made = ""
    sent = os.environ.get(_NONCE_ENV, "").encode("utf-8", "surrogateescape")
    tmp = Path(tempfile.gettempdir()).resolve()
    why = ("no matching one-shot nonce from the parent drill" if not (made and hmac.compare_digest(made.encode(), sent))
           else f"the data path {d} is not the work dir's scratch copy" if d.parent.resolve() != home / "spine"
           else f"SIGIL_HOME={config.SIGIL_HOME} is not the scratch home" if config.SIGIL_HOME.resolve() != home
           else f"TMPDIR={tmp} is outside the work dir" if not tmp.is_relative_to(w)
           else "")
    if why:
        res = {"status": FAIL, "detail": f"refusing: the isolated drill is not scoped to its copy ({why})",
               "steps": []}
    else:
        res = drill_copy(d, Path(work_dir))
    print(json.dumps(res, sort_keys=True, default=str))
    return 0


def main(argv: "Optional[list[str]]" = None) -> int:
    """``python -m sigil.spine.upgrade_drill [--spine PATH] [--work-dir DIR] [--json]`` — exit 0 PASS,
    1 FAIL, 3 NOT-RUN (no data), 4 INCONCLUSIVE (no consistent snapshot could be taken)."""
    import argparse

    from ..config import SPINE_PATH

    ap = argparse.ArgumentParser(description="VIGIL on-box upgrade/rollback drill (DEP-3) — never touches the "
                                             "real spine; drills a throwaway copy")
    ap.add_argument("--spine", default=str(SPINE_PATH), help="the spine data path (default: this home's)")
    ap.add_argument("--work-dir", default="", help="parent for the throwaway work dir (default: $TMPDIR)")
    ap.add_argument("--json", action="store_true")
    ap.add_argument(_CHILD_FLAG, default="", help=argparse.SUPPRESS)
    a = ap.parse_args(argv)
    if a.isolated_copy:
        return _child_main(a.isolated_copy, a.work_dir)
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
