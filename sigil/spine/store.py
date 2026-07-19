"""Append-only, hash-chained JSONL spine (SIGIL §6.1, D1).

Reuses CRUCIBLE's tamper-evident chain verbatim (`sigil.reuse`): each line carries
`{seq, prev_hash, entry_hash}` where `entry_hash` links prev+cert_digest+seq. The
`cert_digest` is over the record's CONTENT only (scope/kind/source/actor/payload/
parent/supersedes) — NOT the wallclock `ts` — so the chain is replay-stable. Appends
are O(1): read the last line's entry, `append_entry`, write.
"""
from __future__ import annotations

import gzip
import json
import logging
import os
import shutil
import tempfile
import threading
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator

from ..config import SCOPE, SPINE_PATH, SPINE_SEG_MAX_BYTES, SPINE_SEG_MAX_RECORDS
from ..reuse import ChainEntry, append_entry, build_chain, digest_payload, verify_chain
from .atomicio import atomic_write_text, fsync_dir
from .manifest import (
    Manifest,
    Segment,
    SpineLayout,
    initial_manifest,
    read_manifest,
    segment_filename,
    write_manifest,
)
from .models import SpineRecord, now_iso

try:
    import fcntl  # POSIX advisory file lock — cross-PROCESS append serialization
except ImportError:  # pragma: no cover — non-POSIX
    fcntl = None  # type: ignore[assignment]

_log = logging.getLogger(__name__)


class SpineError(Exception):
    """A structural spine fault — a corrupt/degenerate manifest or a manifest-referenced segment that
    cannot be read. Raised so the caller fails CLOSED rather than silently reading a truncated/empty
    chain (invariant 15: a state-scanner must never fail open)."""


# Test-only fault-injection HOOK. Production ships it as None, so `_maybe_crash` is a single `is None`
# check on the append/seal path and CANNOT be armed by an ambient environment variable (an env-triggered
# os._exit in the durability-critical write path would be a footgun / local-DoS). The crash-fuzz harness
# installs its own hook (which reads its private env + hard-exits) into THIS module, so the barrier logic
# lives in the test, never in the shipped writer.
_crash_hook: "Any" = None


def _maybe_crash(name: str) -> None:
    """Invoke the installed test fault-injection hook (if any) at a named cutover barrier. No-op in
    production (`_crash_hook is None`)."""
    if _crash_hook is not None:
        _crash_hook(name)


# The record fields SpineRecord.from_dict needs; a line missing any of these is corrupt (skipped by
# reads, so a mid-file gap still surfaces via verify()).
_REQUIRED_KEYS = ("seq", "scope", "kind", "source", "actor", "cert_digest", "prev_hash", "entry_hash")

_LOCKS_GUARD = threading.Lock()
_LOCKS: dict[str, "threading.RLock"] = {}


def spine_lock(path: Path | str) -> "threading.RLock":
    """A process-wide RE-ENTRANT lock per resolved spine path. Serializes `append` (read-tip → write)
    across threads so concurrent writers can't fork the hash chain, and — being re-entrant — lets a
    caller make a check-then-append atomic (e.g. the nonce replay gate) while its inner `append` still
    acquires the same lock. Cross-PROCESS serialization is added by an flock inside `append`."""
    key = str(Path(path).resolve())
    with _LOCKS_GUARD:
        lk = _LOCKS.get(key)
        if lk is None:
            lk = _LOCKS[key] = threading.RLock()
        return lk


def _last_nonempty_line(path: Path) -> str | None:
    """Read the last VALID record line without loading the file (seek-from-end). A torn/garbage tail
    line — a partial write from a crash — is SKIPPED so a read/restart never blows up on it: we return
    the last line that JSON-parses and carries the chain fields (FIX 2). None if no valid line exists.
    For a clean file this returns exactly the last non-empty line, byte-for-byte as before."""
    try:
        size = path.stat().st_size
    except OSError:
        return None
    if size == 0:
        return None
    window = 8192
    while True:
        start = max(0, size - window)
        with path.open("rb") as f:
            f.seek(start)
            buf = f.read(size - start)
        lines = [ln for ln in buf.split(b"\n") if ln.strip()]
        if start > 0 and lines:
            lines = lines[1:]                       # the first line may be partial unless we are at BOF
        for raw in reversed(lines):
            try:
                d = json.loads(raw)
            except ValueError:
                d = None
            if isinstance(d, dict) and all(k in d for k in _REQUIRED_KEYS):
                return raw.decode("utf-8")
            _log.warning("spine: skipping malformed tail line while seeking the tip (%s)", path)
        if start == 0:
            return None                             # scanned the whole file, no valid line
        window *= 4                                 # a torn tail bigger than the window (rare) — widen


def _last_valid_boundary(path: Path) -> "tuple[int, ChainEntry | None]":
    """Return (byte offset just past the last VALID record line, its ChainEntry) — bytes BEYOND that
    offset are a torn tail from an interrupted write, which `append` truncates before writing so the new
    record cannot merge with them and be silently lost (BLOCK-1). (0, None) for an empty / all-torn file.
    For a clean file the offset equals the file size (nothing to truncate)."""
    try:
        size = path.stat().st_size
    except OSError:
        return 0, None
    if size == 0:
        return 0, None
    window = 8192
    while True:
        start = max(0, size - window)
        with path.open("rb") as f:
            f.seek(start)
            buf = f.read(size - start)
        segs: list[tuple[int, bytes]] = []          # (byte offset just past this line's \n, line bytes)
        i = 0
        while True:
            nl = buf.find(b"\n", i)
            if nl == -1:
                break
            segs.append((start + nl + 1, buf[i:nl]))
            i = nl + 1
        for end, raw in reversed(segs):             # near-EOF first; front partials (start>0) never win
            if not raw.strip():
                continue
            try:
                d = json.loads(raw)
            except ValueError:
                d = None
            if isinstance(d, dict) and all(k in d for k in _REQUIRED_KEYS):
                return end, ChainEntry(seq=d["seq"], prev_hash=d["prev_hash"],
                                       cert_digest=d["cert_digest"], entry_hash=d["entry_hash"])
            _log.warning("spine: skipping malformed tail segment while seeking the tip (%s)", path)
        if start == 0:
            return 0, None
        window *= 4


class SpineStore:
    def __init__(self, path: Path | str = SPINE_PATH, *,
                 seg_max_bytes: int | None = None, seg_max_records: int | None = None) -> None:
        # Rotation thresholds (0 on a bound disables it; both disabled = never rotate). Injectable so tests
        # can force frequent rotation; default from config. CLAMPED to >= 0: a negative value (e.g. an
        # operator using -1 to mean "off") must not read as `size >= -1` == always-true, which would seal on
        # EVERY append — a self-DoS (one segment + full manifest rewrite per record).
        self._seg_max_bytes = max(0, SPINE_SEG_MAX_BYTES if seg_max_bytes is None else seg_max_bytes)
        self._seg_max_records = max(0, SPINE_SEG_MAX_RECORDS if seg_max_records is None else seg_max_records)
        # `self.path` is the STABLE identity + lock token (…/spine.jsonl). After a migration it is renamed
        # away and no longer a data file, but it remains the key for the in-process RLock and the anchor
        # the whole layout derives from — so the RLock that `envelope.consume` shares with `append` stays
        # the same object across a rotation (invariant 14). All DATA I/O targets `self._active` (the
        # manifest's active segment, or — with no manifest yet — the legacy single file in place, which is
        # byte-identical to the pre-rotation store).
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._layout = SpineLayout.for_path(self.path)
        # NB: `segments/` is created only when actually migrating/rotating (not on every construction), so a
        # legacy/fresh store leaves the spine dir byte-identical to today (no stray empty dirs).
        self._manifest: Manifest | None = read_manifest(self._layout)
        self._reconcile_orphan_migration()          # complete a migrate() interrupted before the manifest write
        self._active: Path = self._resolve_active_path()
        # SEGMENT-AWARE seq -> (segment file, byte offset) index (Slice 1). Sealed segments are immutable,
        # so each is indexed once and its offsets kept forever; the active segment's tail extends on our own
        # appends (O(1)) or on the next read (over just the newly-appended bytes — offsets never move). Full
        # scans (verify/count/entries/iter_records(-1)) never touch the index, staying a single pass across
        # segments. Invalidation is EPOCH-based (`change_token`: manifest generation + active dev/ino/size),
        # so a rotation/migration is detected — a same-size in-place rewrite can no longer fool a size-only
        # heuristic (invariant 9). `_index_lock` guards the dicts against concurrent read+append.
        self._index_lock = threading.Lock()
        self._offsets: dict[int, tuple[str, int]] = {}   # seq -> (segment path str, byte offset in it)
        self._seg_scanned: dict[str, int] = {}           # segment path str -> bytes indexed so far
        self._index_epoch: tuple | None = None           # change_token when the index was last reconciled
        self._max_seq = -1
        self._last: ChainEntry | None = self._read_last_entry()

    # --- segment layout / manifest ------------------------------------------------
    def _resolve_active_path(self) -> Path:
        """The current append/read target. With a manifest, the active segment's absolute path; without
        one (a fresh or not-yet-migrated legacy spine), the legacy single file in place — byte-identical
        to the pre-rotation store, so nothing destructive happens until an explicit `migrate()`. A manifest
        that exists but names NO active segment is a corrupt/degenerate state and RAISES rather than
        silently falling back to `spine.jsonl` (which would resurrect a data file OUTSIDE the segment set —
        a fork; the guard also removes the same landmine for Slice-3 sealing, which must always leave an
        active segment)."""
        if self._manifest is not None:
            act = self._manifest.active()
            if act is None:
                raise SpineError("manifest has no active segment (corrupt/degenerate) — refusing to "
                                 "resurrect spine.jsonl outside the segment set")
            return self._layout.seg_path(act)
        return self.path

    def _read_target(self) -> Path:
        """The file to read for THIS operation. Normally the cached active segment; if it has VANISHED (a
        migrate()/rotation in another process renamed it away), resolve the current active from the
        manifest for this read only — WITHOUT mutating shared state (lock-free reads must not race
        append's active update). Prevents a false-EMPTY read during the migrate instant, which for the
        nonce-highwater scan would regress the replay floor. In Slice 0 the only mover is migrate(), which
        RENAMES (byte-preserving), so the current index offsets stay valid for the resolved file. Fully
        epoch-invalidated, segment-spanning reads land in Slice 1."""
        a = self._active
        if a.exists():
            return a
        m = read_manifest(self._layout)
        act = m.active() if m is not None else None
        if act is not None:
            r = self._layout.seg_path(act)
            if r.exists():
                return r
        # PRE-manifest migrate window: the atomic rename has already placed the data at seg-0 but the
        # manifest is not published yet (so `m is None`). Read it there — otherwise a lock-free reader in
        # exactly this instant sees a false-EMPTY spine (kill-switch un-halt / nonce-floor regression) and
        # the indexed read path can hit a bare FileNotFoundError. seg-0 is byte-identical (rename), so the
        # index built over the vanished file stays valid on it.
        if m is None:
            seg0 = self._layout.segments_dir / segment_filename(0)
            if seg0.exists() and not self.path.exists():
                return seg0
        return a

    def _segments_in_order(self) -> list[Path]:
        """The segment files to read, in seq order (sealed by first_seq, then the active tail). With no
        manifest this is the single legacy/active file. Resolved fresh each call so a rotation/migration by
        another process is seen. RAISES SpineError on a manifest-referenced segment file that is MISSING —
        a read must never silently yield a short chain (invariant 15: no state-scanner fail-open)."""
        m = read_manifest(self._layout)
        if m is None:
            t = self._read_target()
            return [t] if t.exists() else []
        out: list[Path] = []
        for seg in m.ordered():
            p = self._layout.seg_path(seg)
            if not p.exists():
                raise SpineError(
                    f"spine manifest (generation {m.generation}) references a missing segment: {seg.file}")
            out.append(p)
        return out

    def _seam_tip_for_active(self) -> "ChainEntry | None":
        """When the ACTIVE segment is empty, the chain tip its first append must extend so the seam stays
        contiguous: the prior SEALED segment's real last record (its boundary). Returns None ONLY when the
        active is the GENESIS segment (first_seq == 0) — a genuinely fresh spine correctly starts at seq 0.
        For a rotated (first_seq > 0) empty active whose seam boundary cannot be read, it FAILS CLOSED
        (raises) rather than returning None — because append treats None as 'genesis' and would otherwise
        fork the chain at seq 0 (invariant 13). The WRITE path must fail closed exactly like the read path.
        MUST be consulted under the append lock (reads the manifest fresh). No-op in Slices 0-2 (genesis)."""
        m = read_manifest(self._layout)
        if m is None:
            return None
        act = m.active()
        if act is None or act.first_seq == 0:
            return None                              # genesis: a fresh spine correctly starts at seq 0
        sealed = m.sealed_in_order()
        if sealed:
            entry = self._entry_from_line(self._last_line_of(self._layout.seg_path(sealed[-1])))
            if entry is not None:
                return entry
        raise SpineError(
            f"active segment first_seq={act.first_seq} is non-genesis but its seam boundary (the prior "
            f"sealed segment) is unreadable — refusing to fork the chain at seq 0")

    @contextmanager
    def _crossproc_lock(self) -> "Iterator[None]":
        """Cross-process exclusion on the inode-stable lockfile (invariant 14 / D3). flock binds to the
        open file DESCRIPTION, not the path, so an os.replace of the manifest/segments cannot move the
        lock out from under a concurrent writer — which the prior flock-on-the-data-fd could not survive.
        Best-effort exactly as before (fcntl absent on non-POSIX; a flock failure is swallowed). NOT
        re-entrant across fds — never nest a second `_crossproc_lock` inside one (a second LOCK_EX on the
        same file from a different fd self-deadlocks); the seal-swap that runs inside append reuses the
        already-held lock rather than re-acquiring."""
        if fcntl is None:  # pragma: no cover — non-POSIX
            yield
            return
        self._layout.lockfile_path.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(str(self._layout.lockfile_path), os.O_RDWR | os.O_CREAT, 0o600)
        try:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX)
            except OSError:  # pragma: no cover
                pass
            yield
        finally:
            os.close(fd)

    def _complete_orphan_migration_locked(self) -> bool:
        """MUST hold `_crossproc_lock`, and be called only when the manifest is currently ABSENT. If we are
        in the migrate() crash window — seg-0 present, `spine.jsonl` gone (the rename is atomic + durable),
        no manifest — finish the interrupted migration by publishing the manifest. Returns True iff it
        completed one. Called from BOTH __init__'s reconciler AND append's `_refresh_active_under_lock`, so
        a LIVE appender completes the orphan under the lock instead of re-creating `spine.jsonl` and forking
        the log (the critical review finding)."""
        seg0 = self._layout.segments_dir / segment_filename(0)
        if seg0.exists() and not self.path.exists():
            write_manifest(self._layout, initial_manifest(SCOPE, active_file=self._layout.segment_rel(0)))
            _log.warning("spine: completed an interrupted migration — published the manifest for %s", seg0)
            return True
        return False

    def _refresh_active_under_lock(self) -> None:
        """MUST hold `_crossproc_lock`. FIRST complete any interrupted migration (so a live appender never
        resurrects `spine.jsonl`), THEN re-resolve the active segment from the manifest so an appender
        constructed before a concurrent migrate()/rotation writes to the CURRENT target — never a stale
        path (fork) or a renamed-away file (resurrection). One manifest read in the steady state."""
        m = read_manifest(self._layout)
        if m is None and self._complete_orphan_migration_locked():
            m = read_manifest(self._layout)
        new_active = self.path
        act = m.active() if m is not None else None
        if act is not None:
            new_active = self._layout.seg_path(act)
        changed = new_active != self._active or (m is not None) != (self._manifest is not None)
        self._manifest = m                          # keep fresh so the rotation check reuses it (no 2nd read)
        if changed:
            self._active = new_active
            self._invalidate_index()
            self._last = self._read_last_entry()

    def _invalidate_index(self) -> None:
        """Drops the segment-aware index so the next read rebuilds it against the (possibly changed)
        segment set."""
        with self._index_lock:
            self._offsets = {}
            self._seg_scanned = {}
            self._index_epoch = None
            self._max_seq = -1

    def _reconcile_orphan_migration(self) -> None:
        """Close the migrate() crash window at CONSTRUCTION. migrate() does an ATOMIC
        `os.replace(spine.jsonl → segments/seg-00000000.jsonl)` and THEN publishes the manifest; a crash
        BETWEEN them leaves seg-0 present, `spine.jsonl` gone, and no manifest — at which point the legacy
        fallback (active = spine.jsonl) would read the spine as EMPTY and silently hide all history. If we
        observe exactly that state, finish the (already-durable) migration under the lock. (A live appender
        does the same via `_refresh_active_under_lock`; a construction-time pass just recovers faster.)"""
        if self._manifest is not None:
            return
        seg0 = self._layout.segments_dir / segment_filename(0)
        if not (seg0.exists() and not self.path.exists()):
            return
        with self._crossproc_lock():
            if read_manifest(self._layout) is None:          # re-check under the lock
                self._complete_orphan_migration_locked()
            self._manifest = read_manifest(self._layout)

    def change_token(self) -> tuple:
        """A cheap, rotation-aware epoch token — (manifest generation, active file, size, inode) — that
        changes on ANY append (size), a migration/rotation (generation + active path/inode), or a reset.
        THE unified replacement for the size-only 'has the spine changed?' heuristic at every site
        (invariant 9 / A4) — notably the kill-switch verdict caches in `governor/killswitch.py` and
        `gesture/session.py`. Because it reads the manifest FRESH and keys on the resolved active segment
        (not the legacy `store.path`, which a migration renames away), a same-size rotation — or a
        migration performed by another process — can never serve a stale (un-halting) kill-switch verdict."""
        m = read_manifest(self._layout)
        gen = m.generation if m is not None else -1
        active = self.path
        act = m.active() if m is not None else None
        if act is not None:
            active = self._layout.seg_path(act)
        try:
            st = active.stat()
            return (gen, str(active), st.st_size, st.st_ino)
        except OSError:
            return (gen, str(active), -1, -1)

    def migrate(self) -> bool:
        """Move a legacy single-file spine into the segment layout: rename `spine.jsonl` →
        `<stem>.segments/seg-00000000.jsonl` (atomic, same filesystem — O(1), no byte copy) and publish a
        single-active-segment manifest. Idempotent (a no-op once a manifest exists). Returns True iff it
        migrated. SPLIT-BRAIN SAFETY: run this only after every spine writer is on code that flocks the
        path-stable lockfile (this Slice-0 code) and re-resolves the active segment under that lock — a
        stale appender then completes/observes the migration instead of resurrecting `spine.jsonl`. After
        migration `spine.jsonl` is absent and is NEVER re-created as a data file (all data I/O targets the
        active segment)."""
        with spine_lock(self.path):
            with self._crossproc_lock():
                if read_manifest(self._layout) is not None:
                    self._refresh_active_under_lock()
                    return False
                self._layout.segments_dir.mkdir(parents=True, exist_ok=True)
                seg0_abs = self._layout.segments_dir / segment_filename(0)
                if self.path.exists():
                    os.replace(self.path, seg0_abs)         # atomic rename (same fs); O(1), no copy
                    fsync_dir(self._layout.spine_dir)       # persist the SOURCE-dir unlink of spine.jsonl
                else:
                    seg0_abs.touch()                        # fresh spine: create the empty active segment
                fsync_dir(self._layout.segments_dir)        # persist the TARGET-dir creation of seg-0
                write_manifest(self._layout, initial_manifest(SCOPE, active_file=self._layout.segment_rel(0)))
                self._manifest = read_manifest(self._layout)
                self._active = self._resolve_active_path()
                self._invalidate_index()
                self._last = self._read_last_entry()
                return True

    def reset(self) -> None:
        """Delete EVERY spine artifact for this store — the legacy data file, the manifest, all segments,
        the trash, and the lockfile — for `sigil ingest --reset` (a full rebuild). Under the cross-process
        lock so it can't race an append. Idempotent; leaves the store readable (empty) afterward. Replaces
        the old `SPINE_PATH.unlink()`, which left the manifest + rotated segments behind (stale)."""
        with spine_lock(self.path):
            with self._crossproc_lock():
                # NB: do NOT unlink the lockfile — we hold its flock. flock binds to the INODE, not the
                # path (invariant 14), so unlinking it would let a concurrent cross-process appender open a
                # NEW inode at the same path and acquire the flock during our destructive rmtree — losing an
                # acked record and dangling the (re-published) manifest at a deleted segment. It is a tiny
                # 0-byte token whose entire purpose is path-stability; keep it so reset() truly excludes
                # appenders for its whole critical section.
                for pth in (self._layout.manifest_path, self.path):
                    try:
                        pth.unlink(missing_ok=True)
                    except OSError:
                        pass
                for dpath in (self._layout.segments_dir, self._layout.trash_dir):
                    if dpath.exists():
                        shutil.rmtree(dpath, ignore_errors=True)
                self._manifest = None
                self._active = self._resolve_active_path()
                self._invalidate_index()
                self._last = self._read_last_entry()

    def generation(self) -> int:
        """The manifest generation (monotonic rotation epoch); -1 for a legacy (un-migrated) spine."""
        m = read_manifest(self._layout)
        return m.generation if m is not None else -1

    def segment_info(self) -> list[dict]:
        """A CLI/human summary of the segment set: one dict per segment in seq order. Empty list for a
        legacy (un-migrated) single-file spine."""
        m = read_manifest(self._layout)
        if m is None:
            return []
        out: list[dict] = []
        for seg in m.ordered():
            p = self._layout.seg_path(seg)
            out.append({"id": seg.id, "codec": seg.codec, "sealed": seg.sealed,
                        "first_seq": seg.first_seq, "last_seq": seg.last_seq,
                        "bytes": p.stat().st_size if p.exists() else 0, "file": seg.file})
        return out

    # --- rotation (retain-all seal-swap) ------------------------------------------
    def _maybe_rotate_locked(self) -> None:
        """MUST hold the flock (called at the end of append, after the ack). Seal the active segment + start
        a fresh one if it hit a size/record threshold. Only for a MIGRATED store (a legacy single-file spine
        never auto-rotates — the owner runs `sigil spine migrate` first). Write-then-rotate: the triggering
        record is already durable in the active before we seal, so a panic append is never blocked by
        rotation for more than the bounded (O(1)+O(tail)) seal-swap (D1)."""
        if not (self._seg_max_bytes or self._seg_max_records):
            return
        m = self._manifest                          # kept fresh by _refresh_active_under_lock
        if m is None:
            return
        act = m.active()
        if act is None:
            return
        ap = self._layout.seg_path(act)
        try:
            size = ap.stat().st_size
        except OSError:
            return
        tip = self._last.seq if self._last is not None else -1
        records = (tip - act.first_seq + 1) if tip >= act.first_seq else 0
        if ((self._seg_max_bytes and size >= self._seg_max_bytes)
                or (self._seg_max_records and records >= self._seg_max_records)):
            self._seal_active_locked(m, act, ap)

    def _seal_active_locked(self, m: Manifest, act: Segment, ap: Path) -> bool:
        """MUST hold the flock. Seal the active segment `act` and start a fresh empty active, publishing a
        new-generation manifest ATOMICALLY (the single commit instant). Retain-all: no record is removed, so
        the signed head + verify are untouched and entry_count stays absolute. Bounded (O(1)+O(tail)).
        Ordering is crash-consistent: build the new active durably FIRST, then the manifest swap is the
        commit — a crash before it leaves the pre-rotation spine intact (the triggering record already
        durable in the old active); a crash after it leaves the post-rotation set. Returns True if sealed."""
        # R2: seal-time torn-tail truncate (A2). The append-path truncate never revisits a sealed segment,
        # so this is the ONLY place a just-sealed file is cleaned; usually already clean (we just fsync'd).
        clean_end, boundary = _last_valid_boundary(ap)
        if boundary is None:
            return False                            # empty active — nothing to seal
        try:
            pre = ap.stat().st_size
        except OSError:
            return False
        if pre > clean_end:
            with ap.open("r+b") as f:
                f.truncate(clean_end)
                f.flush()
                os.fsync(f.fileno())
        seq_hi, boundary_hash = boundary.seq, boundary.entry_hash
        new_id = act.id + 1
        new_abs = self._layout.segments_dir / segment_filename(new_id)
        # R1: GC an orphan next-segment left by a prior CRASHED seal (created but never committed to a
        # manifest). Safe: it is not in the committed segment set, so it holds no acked record.
        if new_abs.exists():
            new_abs.unlink()
        # R3: create the empty new active durably (it EXISTS before the manifest names it, so a reader that
        # sees the new manifest always finds the active — no "active absent" window).
        fd = os.open(str(new_abs), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        os.fsync(fd)
        os.close(fd)
        fsync_dir(self._layout.segments_dir)
        _maybe_crash("seal_after_new_active")       # crash-fuzz: new active created, manifest NOT yet swapped
        # R4: publish the new-generation manifest — the ATOMIC COMMIT INSTANT (temp→fsync→replace→dir-fsync).
        sealed = Segment(id=act.id, file=act.file, codec=act.codec, sealed=True,
                         first_seq=act.first_seq, last_seq=seq_hi, count=seq_hi - act.first_seq + 1,
                         first_prev_hash=act.first_prev_hash, boundary_hash=boundary_hash, bytes=clean_end)
        new_active = Segment(id=new_id, file=self._layout.segment_rel(new_id), codec="none", sealed=False,
                             first_seq=seq_hi + 1, first_prev_hash=boundary_hash)
        others = [s for s in m.segments if s.id != act.id]
        write_manifest(self._layout, Manifest(generation=m.generation + 1, scope=m.scope,
                                              segments=others + [sealed, new_active]))
        _maybe_crash("seal_after_manifest")         # crash-fuzz: committed; in-memory state not yet updated
        self._manifest = read_manifest(self._layout)
        self._active = self._layout.seg_path(new_active)
        # A seal moves NO bytes (retain-all): the just-sealed segment keeps its path + content, so its
        # indexed offsets stay valid. Do NOT clear the whole index (that would force an O(whole-spine)
        # re-scan every ~12000 records); just drop the epoch so the next read reconciles — which finds every
        # sealed segment already indexed (skip) and only registers the new empty active.
        with self._index_lock:
            self._index_epoch = None
        self._last = boundary                       # tip preserved; the next append seeds from the seam
        return True

    def rotate(self) -> bool:
        """Force a seal of the active segment now (for `sigil spine rotate` / an opportunistic seal at
        checkpoint). No-op on a legacy (un-migrated) or empty active. Returns True if it sealed."""
        with spine_lock(self.path):
            with self._crossproc_lock():
                self._refresh_active_under_lock()
                m = self._manifest
                if m is None:
                    return False
                act = m.active()
                if act is None:
                    return False
                return self._seal_active_locked(m, act, self._layout.seg_path(act))

    # --- compaction (gzip-on-seal; retain-all — no record removed) -----------------
    def compact(self) -> int:
        """Compress every SEALED plaintext segment to gzip. Retain-all: no record is removed, and a `.gz` is
        byte-decompress-identical, so verify()/the signed head are unaffected. Reclaims ~5-8x on JSONL. The
        heavy gzip runs LOCK-FREE (a sealed segment is immutable — no append is blocked); only the tiny
        per-segment manifest codec-flip takes the flock. After the flip the superseded plaintext is UNLINKED
        (immediate reclaim). Readers are protected NOT by lingering the plaintext but by (a) POSIX open-fd
        survival for a reader mid-scan, and (b) the manifest-reread retry in iter_records/tail/get for a
        reader that resolved the path but opens it after the unlink. On a non-POSIX FS where unlinking an
        in-use file fails, the unlink is deferred to the next compact() (no crash). Idempotent. Returns the
        number compressed."""
        m = read_manifest(self._layout)
        if m is None:
            return 0
        n = 0
        for seg in m.sealed_in_order():
            if seg.codec == "none" and self._compress_one_sealed(seg.id):
                n += 1
        self._remove_superseded_plaintext()          # immediate reclaim + backstop for a crash before this
        return n

    def _compress_one_sealed(self, seg_id: int) -> bool:
        """P1 (lock-free gzip of the immutable sealed segment) + P2 (brief-locked manifest codec flip).
        Crash-safe: the .gz is built to a UNIQUE temp (so two concurrent compactors never clobber a shared
        temp) then atomically renamed; the codec flip is the atomic commit. A crash before the flip leaves an
        orphan .gz the next run overwrites — the plaintext (still referenced) is never at risk."""
        m = read_manifest(self._layout)
        seg = next((s for s in (m.segments if m else []) if s.id == seg_id and s.sealed and s.codec == "none"), None)
        if seg is None:
            return False
        plain = self._layout.seg_path(seg)
        if not plain.exists():
            return False
        gz_rel = self._layout.segment_rel(seg_id, "gzip")
        gz_abs = self._layout.spine_dir / gz_rel
        fd, tmp_name = tempfile.mkstemp(dir=str(self._layout.segments_dir),
                                        prefix=f".{segment_filename(seg_id)}.", suffix=".gz.tmp")
        os.close(fd)                                 # unique temp per process — no shared-temp clobber
        tmp = Path(tmp_name)
        try:
            with plain.open("rb") as fin, gzip.open(tmp, "wb", compresslevel=6) as fout:
                shutil.copyfileobj(fin, fout)
            with open(tmp, "rb") as f:
                os.fsync(f.fileno())
            os.replace(tmp, gz_abs)
        except BaseException:
            try:
                tmp.unlink(missing_ok=True)
            except OSError:
                pass
            raise
        fsync_dir(self._layout.segments_dir)
        with spine_lock(self.path):
            with self._crossproc_lock():
                m2 = read_manifest(self._layout)
                if m2 is None:
                    return False
                flipped, segs2 = False, []
                for s in m2.segments:
                    if s.id == seg_id and s.sealed and s.codec == "none":
                        segs2.append(s.model_copy(update={"codec": "gzip", "file": gz_rel,
                                                          "bytes": gz_abs.stat().st_size}))
                        flipped = True
                    else:
                        segs2.append(s)
                if not flipped:
                    return False                     # another process already flipped it
                write_manifest(self._layout, Manifest(generation=m2.generation + 1, scope=m2.scope, segments=segs2))
                self._manifest = read_manifest(self._layout)
                with self._index_lock:
                    self._index_epoch = None         # segment path+codec changed -> reconcile offsets
        return True

    def _remove_superseded_plaintext(self) -> None:
        """Unlink the plaintext seg-k.jsonl of every segment the manifest now marks GZIP — the superseded
        copy after a codec flip (or one stranded by a crash between the flip and this call). Immediate disk
        reclaim. A reader mid-read keeps its POSIX open-fd; a reader that resolved the path re-resolves via
        the read-path retry. On a non-POSIX FS an in-use unlink raises and is deferred to the next compact().
        Idempotent."""
        m = read_manifest(self._layout)
        if m is None:
            return
        for seg in m.segments:
            if seg.codec != "gzip":
                continue
            plain = self._layout.segments_dir / segment_filename(seg.id, "none")
            try:
                plain.unlink(missing_ok=True)
                plain.with_name(plain.name + ".idx").unlink(missing_ok=True)   # its now-stale Slice-5 sidecar
            except OSError:                          # in use on a non-POSIX FS -> the next compact() retries
                pass

    # --- write --------------------------------------------------------------------
    def append(
        self, *, kind: str, source: str, actor: str, payload: dict[str, Any],
        parent_id: int | None = None, supersedes_id: int | None = None,
        ts: str | None = None,
    ) -> int:
        content = {
            "scope": SCOPE, "kind": kind, "source": source, "actor": actor,
            "payload": payload, "parent_id": parent_id, "supersedes_id": supersedes_id,
        }
        cert_digest = digest_payload(content)  # wallclock-free
        # Serialize the whole read-tip → write so concurrent writers (threaded bridge server, gesture
        # daemon) can't both fork off a stale tip and break the chain. The in-process RLock is keyed on
        # the STABLE `self.path` (unchanged), so the check-then-append gate `envelope.consume` builds on
        # top of it stays atomic across a rotation. Re-read the TRUE tip from disk under the lock.
        with spine_lock(self.path):
            with self._crossproc_lock():                 # cross-process guard on the path-stable lockfile
                self._refresh_active_under_lock()        # pick up a concurrent migrate()/rotation; never fork
                active = self._active
                # binary append+read: lets us TRUNCATE a torn tail before writing (BLOCK-1 fix). `a+b`
                # creates the file if absent and — in append mode — every write still lands at EOF.
                with active.open("a+b") as f:
                    # BLOCK-1: an interrupted write can leave torn bytes PAST the last valid record. Appending
                    # after them would MERGE (torn + new) into one unparseable line → the new record is silently
                    # lost, verify() stays green, and a lost kill-switch panic never halts the mesh. Truncate the
                    # dead tail back to the last valid record FIRST (this only removes never-committed garbage
                    # from an interrupted write; committed records are untouched). Evaluated on the ACTIVE
                    # segment under the lock (invariant 7 — the append target is always the true chain tip).
                    clean_end, last = _last_valid_boundary(active)
                    pre_size = os.fstat(f.fileno()).st_size
                    if pre_size > clean_end:
                        f.truncate(clean_end)
                        _log.warning("spine: truncated a %d-byte torn tail (interrupted write) before append (%s)",
                                     pre_size - clean_end, active)
                    if last is not None:
                        entry = append_entry([last], cert_digest)          # extend the active segment's tip
                    else:
                        # active is EMPTY: seed from the prior sealed segment's boundary if this is a rotated
                        # (non-genesis) segment, else start the genesis chain at seq 0. Never build_chain a
                        # non-genesis segment from GENESIS (that would fork the chain at seq 0 — invariant 13).
                        seam = self._seam_tip_for_active()
                        entry = append_entry([seam], cert_digest) if seam is not None else build_chain([cert_digest])[0]
                    record = {
                        "seq": entry.seq, **content, "ts": ts or now_iso(),
                        "cert_digest": cert_digest, "prev_hash": entry.prev_hash, "entry_hash": entry.entry_hash,
                    }
                    line = json.dumps(record, ensure_ascii=False) + "\n"
                    offset = clean_end                      # after any truncate, EOF == clean_end (where the line lands)
                    f.write(line.encode("utf-8"))
                    f.flush()
                    os.fsync(f.fileno())                    # FIX 3: an ack'd append is durable across a crash
                    _maybe_crash("append_after_fsync")      # crash-fuzz: record durable, not yet acked/sealed
                    # FIX 1: keep the index current with NO re-scan when the ACTIVE segment is already
                    # indexed exactly up to this record's offset. If another PROCESS appended in between,
                    # `_seg_scanned[active] < offset` and we skip — the next read's `_ensure_index` extends
                    # the active over the gap bytes AND this one. `_index_epoch` is intentionally left stale
                    # so that next read refreshes it (its extend then finds nothing to do — O(1)).
                    with self._index_lock:
                        active_str = str(active)
                        if self._seg_scanned.get(active_str) == offset:
                            self._offsets[entry.seq] = (active_str, offset)
                            if entry.seq > self._max_seq:
                                self._max_seq = entry.seq
                            self._seg_scanned[active_str] = offset + len(line.encode("utf-8"))
                self._last = entry
                # write-then-rotate: the record is durable (fsync'd) above BEFORE any seal, so a panic
                # append is never blocked by rotation for more than the bounded seal-swap (D1). No-op unless
                # a migrated active hit a threshold.
                self._maybe_rotate_locked()
        return entry.seq

    # --- read ---------------------------------------------------------------------
    def _open_segment(self, p: Path):
        """Open a segment for a forward byte read, transparently decompressing a gzip-sealed segment. For a
        `.gz` the index stores DECOMPRESSED byte offsets, which is exactly what `gzip.GzipFile.seek()` (used
        by get()) consumes, so the offset semantics match. The active segment is always plaintext."""
        if p.suffix == ".gz":
            return gzip.open(p, "rb")
        return p.open("rb")

    def iter_records(self, *, since_seq: int = -1) -> Iterator[SpineRecord]:
        """Records with seq > `since_seq`, in seq order, ACROSS ALL SEGMENTS (sealed segments then the
        active) as ONE contiguous chain, so every full-scanning consumer keeps seeing the whole log. For
        since_seq >= 0 the index seeks straight to the first wanted line in its owning segment
        (O(records-returned), not O(spine)); a full read (since_seq < 0) streams every segment from the
        first. A line that fails to parse or lacks required keys is SKIPPED (a torn active tail can't crash
        the read; a torn MIDDLE line becomes a seq gap that verify() fails on). RAISES SpineError if the
        manifest references a segment that cannot be read — a read must NEVER silently yield a short chain
        (invariant 15: no state-scanner fail-open)."""
        yielded_upto = since_seq
        for _attempt in range(6):                        # D2 reader-grace: tolerate a few compaction moves
            segs = self._segments_in_order()             # RAISES on a genuinely missing referenced segment
            if not segs:
                return
            start_i, start_off = self._start_locus(yielded_upto, segs)
            try:
                for i in range(start_i, len(segs)):
                    p = segs[i]
                    with self._open_segment(p) as f:
                        if i == start_i and start_off:
                            f.seek(start_off)
                        for raw in f:
                            if not raw.strip():
                                continue
                            try:
                                rec = SpineRecord.from_dict(json.loads(raw))
                            except (ValueError, KeyError, TypeError):
                                _log.warning("spine: skipping malformed line during iter_records (%s)", p)
                                continue
                            if rec.seq > yielded_upto:
                                yield rec
                                yielded_upto = rec.seq
                return                                    # completed cleanly
            except FileNotFoundError:
                # a concurrent compaction moved a plaintext segment to trash AFTER we resolved it — re-read
                # the manifest (now pointing at the .gz) and continue from where we left off. Retain-all
                # means the same seqs are still covered, so no record is skipped or repeated.
                _log.debug("spine: a segment moved during read (compaction); re-resolving from seq %d", yielded_upto)
                continue
        raise SpineError("spine segments kept moving during read (compaction churn) — giving up")

    def get(self, seq: int) -> SpineRecord | None:
        """A single record by seq via the segment-aware index (resolves the OWNING segment + offset),
        byte-identical to a full scan. O(1) for a plaintext segment; for a gzip-sealed segment the offset is
        a DECOMPRESSED offset, so `gzip.seek()` decompresses up to it (bounded by the seal threshold — not a
        full-spine scan). Falls back to a bounded forward scan (spanning segments) when the seq is not
        indexed (beyond the tip, or a corrupt line was skipped)."""
        if seq < 0:
            return None
        self._ensure_index()
        with self._index_lock:
            loc = self._offsets.get(seq)
        if loc is not None:
            path_str, off = loc
            try:
                with self._open_segment(Path(path_str)) as f:
                    f.seek(off)
                    raw = f.readline()
                rec = SpineRecord.from_dict(json.loads(raw))
                if rec.seq == seq:
                    return rec
            except (OSError, ValueError, KeyError, TypeError):
                pass                                     # stale/moved offset — fall through to the scan
        for r in self.iter_records(since_seq=seq - 1):
            if r.seq == seq:
                return r
            if r.seq > seq:
                break
        return None

    def tail(self, n: int) -> list[SpineRecord]:
        """The last `n` records, walking segments backward from the ACTIVE across the seam (O(n) bytes,
        NOT O(spine)) — a bounded RECENT-window read on a large spine. Fewer than `n` if the spine is
        shorter. FIXES B3: the pre-Slice-1 version read only the active file, so right after a rotation it
        returned < n. NOTE (unchanged): a bounded window collapses a rapid recent replay flood but does NOT
        bound AGGREGATE replay bloat — pair `tail()`-based dedup with a record-time freshness gate."""
        if n <= 0:
            return []
        for _attempt in range(6):                        # D2 reader-grace: a concurrent compaction may
            try:                                         # unlink a plaintext between resolve and read
                recs: list[SpineRecord] = []
                for p in reversed(self._segments_in_order()):
                    recs = self._read_segment_tail(p, n - len(recs)) + recs
                    if len(recs) >= n:
                        break
                return recs[-n:]
            except FileNotFoundError:
                _log.debug("spine: a segment moved during tail() (compaction); re-resolving")
                continue
        raise SpineError("spine segments kept moving during tail() (compaction churn) — giving up")

    def _read_segment_tail(self, p: Path, k: int) -> list[SpineRecord]:
        """The last `k` records of a single segment. Plaintext: seek-from-end (O(k) bytes). Gzip: decompress
        (bounded by the seal threshold) and take the last k lines — no random access into a gz stream.
        Opening a segment that was resolved from the manifest but has since VANISHED (a concurrent
        compaction unlinked the plaintext) RAISES FileNotFoundError so tail() re-resolves — NOT a silent []
        (which would drop a whole segment from the window and hole the chain; the arm replay-dedup gate
        depends on a complete window)."""
        if k <= 0:
            return []
        if p.suffix == ".gz":
            with gzip.open(p, "rb") as f:                # raises FileNotFoundError if it vanished -> tail() retries
                lines = [x for x in f.read().split(b"\n") if x.strip()]
        else:
            with p.open("rb") as f:                      # raises FileNotFoundError if it vanished -> tail() retries
                f.seek(0, os.SEEK_END)
                pos = f.tell()
                buf = b""
                while pos > 0 and buf.count(b"\n") <= k:
                    step = min(65536, pos)
                    pos -= step
                    f.seek(pos)
                    buf = f.read(step) + buf
            lines = [x for x in buf.split(b"\n") if x.strip()]
        out: list[SpineRecord] = []
        for ln in lines[-k:]:
            try:
                out.append(SpineRecord.from_dict(json.loads(ln)))
            except (ValueError, KeyError, TypeError):
                continue
        return out

    @property
    def next_seq(self) -> int:
        return (self._last.seq + 1) if self._last else 0

    def count(self) -> int:
        return sum(1 for _ in self.iter_records())

    # --- integrity ----------------------------------------------------------------
    def entries(self) -> list[ChainEntry]:
        return [
            ChainEntry(seq=r.seq, prev_hash=r.prev_hash, cert_digest=r.cert_digest, entry_hash=r.entry_hash)
            for r in self.iter_records()
        ]

    def verify(self) -> tuple[bool, str]:
        """Two-layer UNKEYED integrity: (1) BINDING — each record's payload still hashes to its
        stored cert_digest (catches silent payload edits); (2) CHAIN — the entries link cleanly
        (catches delete/reorder/entry tamper). This proves internal CONSISTENCY, not authenticity:
        a naive payload edit fails (1), and a mid-chain digest edit cascades an entry_hash/prev_hash
        break caught by (2) — BUT a writer who recomputes cert_digest+entry_hash for the tip (no
        successor to cascade into) or forward-cascades a fork produces a self-consistent chain that
        passes here. Resistance to a recompute-capable writer is the owner-SIGNED head's job
        (`checkpoint.verify_checkpoint`, Ed25519 + monotonic last_seq). Use this for corruption/
        naive-tamper detection; use the signed head for tamper-EVIDENCE."""
        entries: list[ChainEntry] = []
        for r in self.iter_records():
            content = {
                "scope": r.scope, "kind": r.kind, "source": r.source, "actor": r.actor,
                "payload": r.payload, "parent_id": r.parent_id, "supersedes_id": r.supersedes_id,
            }
            if digest_payload(content) != r.cert_digest:
                return False, f"binding break at seq {r.seq}: payload does not match cert_digest (record tampered)"
            entries.append(ChainEntry(seq=r.seq, prev_hash=r.prev_hash, cert_digest=r.cert_digest, entry_hash=r.entry_hash))
        return verify_chain(entries)

    @staticmethod
    def _entry_from_line(line: str | None) -> "ChainEntry | None":
        if not line:
            return None
        d = json.loads(line)
        return ChainEntry(seq=d["seq"], prev_hash=d["prev_hash"], cert_digest=d["cert_digest"],
                          entry_hash=d["entry_hash"])

    def _last_line_of(self, p: Path) -> str | None:
        """The last VALID record line of a segment, codec-aware. Plaintext: seek-from-end (O(tail)). Gzip:
        decompress (bounded by the seal threshold) and take the last well-formed line — used only for the
        seam boundary of an already-compressed sealed segment (a rare empty-active edge)."""
        if not p.exists():
            return None
        if p.suffix == ".gz":
            last = None
            with gzip.open(p, "rt", encoding="utf-8") as f:
                for line in f:
                    s = line.rstrip("\n")
                    if not s.strip():
                        continue
                    try:
                        d = json.loads(s)
                    except ValueError:
                        continue
                    if all(k in d for k in _REQUIRED_KEYS):
                        last = s
            return last
        return _last_nonempty_line(p)

    def _read_last_entry(self) -> ChainEntry | None:
        """The chain tip = the last valid record of the ACTIVE segment. If the active is EMPTY (a freshly
        rotated segment before its first append), the tip is the last SEALED segment's real last record
        (the seam boundary), so next_seq never regresses / reuses a seq across a rotation (invariant 13).
        Skips a torn/garbage tail, so a crash mid-write can't block a restart."""
        m = read_manifest(self._layout)
        if m is None:
            t = self._read_target()
            return self._entry_from_line(_last_nonempty_line(t) if t.exists() else None)
        act = m.active()
        if act is not None:
            ap = self._layout.seg_path(act)
            line = _last_nonempty_line(ap) if ap.exists() else None   # active is always plaintext
            if line:
                return self._entry_from_line(line)
        for seg in reversed(m.sealed_in_order()):        # active empty/absent -> last sealed segment's tail
            line = self._last_line_of(self._layout.seg_path(seg))     # may be gz-compressed
            if line:
                return self._entry_from_line(line)
        return None

    # --- segment-aware seq -> (segment, byte-offset) index ------------------------
    def _start_locus(self, since_seq: int, segs: list[Path]) -> tuple[int, int]:
        """(starting segment index in `segs`, byte offset within it) so a forward read yields exactly
        seq > since_seq. A full read (since_seq < 0) → (0, 0). Otherwise the index seeks to seq
        (since_seq + 1) in its owning segment; if that seq is beyond the tip, return a past-the-end index
        so nothing is yielded; if not resolvable (below the min, or a skipped/corrupt gap), fall back to a
        safe full span from segment 0."""
        if since_seq < 0:
            return (0, 0)
        self._ensure_index()
        want = since_seq + 1
        with self._index_lock:
            loc = self._offsets.get(want)
            max_seq = self._max_seq
        if loc is not None:
            path_str, off = loc
            for i, p in enumerate(segs):
                if str(p) == path_str:
                    return (i, off)
            return (0, 0)                           # segment set changed under us → safe full span
        if want > max_seq:
            return (len(segs), 0)                   # nothing beyond the tip → yield nothing
        return (0, 0)                               # below min / gap → safe full span

    def _ensure_index(self) -> None:
        """Build/reconcile the segment-aware index lazily, keyed on the epoch (`change_token`). On an epoch
        change (an append grew the active, or a rotation/migration changed the segment set) reconcile each
        segment: the ACTIVE extends over the new bytes (or re-scans if it shrank in place — a truncation);
        a SEALED segment is immutable and indexed exactly once. Thread-safe under `_index_lock`."""
        tok = self.change_token()
        segs = self._segments_in_order()            # RAISES on a missing referenced segment, so get() (which
        #                                             calls _ensure_index) fails CLOSED too — never a
        #                                             fail-OPEN point read from a surviving segment while the
        #                                             chain is provably truncated (invariant 15).
        active_str = str(segs[-1]) if segs else None
        with self._index_lock:
            if tok == self._index_epoch:
                return
            for p in segs:
                ps = str(p)
                try:
                    size = p.stat().st_size
                except OSError:
                    continue
                scanned = self._seg_scanned.get(ps, 0)
                if ps == active_str:
                    if size > scanned:
                        self._scan_segment(ps, p, scanned, size)     # extend the active over new bytes
                    elif size < scanned:                             # active shrank in place (truncation)
                        self._purge_segment(ps)
                        self._scan_segment(ps, p, 0, size)
                elif scanned < size:                                 # sealed: immutable → index once
                    self._index_sealed(ps, p, size)
            self._index_epoch = tok

    def _index_sealed(self, ps: str, p: Path, size: int) -> None:
        """Index a SEALED (immutable) segment. First try its persisted `.idx` sidecar (Slice 5) so a cold
        start LOADS the seq→offset map instead of re-scanning up to a full segment (a gz segment would
        otherwise decompress fully). On a miss/stale/corrupt sidecar, scan the segment and write a fresh one
        (best-effort). The sidecar is a pure CACHE derived from the segment bytes — never a tamper input —
        validated against the segment's current size on load, so a changed segment regenerates it. MUST hold
        `_index_lock`."""
        if self._load_sidecar(ps, p):
            return
        self._scan_segment(ps, p, self._seg_scanned.get(ps, 0), size)
        self._write_sidecar(ps, p)

    def _load_sidecar(self, ps: str, p: Path) -> bool:
        """Populate `_offsets` for a sealed segment from its `.idx` sidecar iff it exists and matches the
        segment's current byte size. Returns True if loaded. A stale/corrupt/absent sidecar → False (the
        caller scans + rewrites)."""
        idx = p.with_name(p.name + ".idx")
        try:
            if not idx.exists():
                return False
            d = json.loads(idx.read_text(encoding="utf-8"))
            if d.get("v") != 1 or d.get("seg_bytes") != p.stat().st_size:
                return False                                 # different segment bytes → the sidecar is stale
            first, offsets = int(d["first_seq"]), d["offsets"]
            if not isinstance(offsets, list):
                return False
            # Cheap validity spot-check: the first offset must point to the record with seq == first_seq.
            # Catches a wholesale-wrong / shifted / tampered sidecar without re-scanning (one read; a gz
            # decompresses cheaply to its start). The sidecar only ACCELERATES a seek — verify()/count()/the
            # security state-scanners full-scan WITHOUT the index, and get() re-checks rec.seq==seq per
            # lookup, so a bad sidecar can at worst slow a read, never make a floor under-count.
            if offsets:
                with self._open_segment(p) as f:
                    f.seek(int(offsets[0]))
                    rec = SpineRecord.from_dict(json.loads(f.readline()))
                    if rec.seq != first:
                        return False
        except (OSError, ValueError, KeyError, TypeError):
            return False
        for i, off in enumerate(offsets):
            seq = first + i
            self._offsets[seq] = (ps, int(off))
            if seq > self._max_seq:
                self._max_seq = seq
        self._seg_scanned[ps] = p.stat().st_size             # mark fully indexed → the reconcile skips it
        return True

    def _write_sidecar(self, ps: str, p: Path) -> None:
        """Persist a sealed segment's seq→offset map as `<segment>.idx` (best-effort, atomic). Offsets are
        collected from `_offsets` in seq order — a segment holds a CONTIGUOUS seq range, so only the offset
        array + first_seq are stored. Validated on load against the segment size. MUST hold `_index_lock`."""
        entries = sorted((seq, off) for seq, (q, off) in self._offsets.items() if q == ps)
        if not entries:
            return
        try:
            data = json.dumps({"v": 1, "first_seq": entries[0][0], "seg_bytes": p.stat().st_size,
                               "offsets": [off for _, off in entries]}, separators=(",", ":"))
            atomic_write_text(p.with_name(p.name + ".idx"), data, prefix=".idx-")
        except OSError:                                      # read-only FS etc. — the index still works by scanning
            pass

    def _purge_segment(self, ps: str) -> None:
        """Drop a segment's offsets (the active shrank in place — a truncation). MUST hold `_index_lock`."""
        self._offsets = {s: loc for s, loc in self._offsets.items() if loc[0] != ps}
        self._seg_scanned.pop(ps, None)
        self._max_seq = max(self._offsets, default=-1)

    def _scan_segment(self, ps: str, p: Path, start: int, size: int) -> None:
        """Index every COMPLETE (newline-terminated) record line of segment `p` as
        `_offsets[seq] = (ps, line_offset)`. MUST hold `_index_lock`. Plaintext: index bytes [start, size)
        (append-only ⇒ extend-forward). Gzip (sealed, immutable): index the whole DECOMPRESSED stream once
        (offsets are decompressed byte offsets, matching `gzip.GzipFile.seek()` in get()). A malformed
        complete line is left OUT (a mid-file gap still surfaces via verify()); a trailing partial line is
        left for the next extend."""
        if p.suffix == ".gz":
            with gzip.open(p, "rb") as gf:
                chunk = gf.read()
            base = 0                                    # decompressed offsets; a sealed gz is indexed once
        else:
            if size <= start:
                return
            with p.open("rb") as f:
                f.seek(start)
                chunk = f.read(size - start)
            base = start
        consumed = 0
        while True:
            nl = chunk.find(b"\n", consumed)
            if nl == -1:
                break                                       # trailing partial line — not complete yet
            raw = chunk[consumed:nl]
            line_off = base + consumed
            consumed = nl + 1
            if not raw.strip():
                continue
            try:
                d = json.loads(raw)
                if not all(k in d for k in _REQUIRED_KEYS):
                    raise KeyError
                seq = d["seq"]
            except (ValueError, KeyError, TypeError):
                continue                                    # corrupt complete line — do not index it
            self._offsets[seq] = (ps, line_off)
            if seq > self._max_seq:
                self._max_seq = seq
        self._seg_scanned[ps] = base + consumed
