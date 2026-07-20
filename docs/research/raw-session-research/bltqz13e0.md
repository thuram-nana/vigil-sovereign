commit 15e5844d94530aea264c330fc4d76ad1dad576b2
Author: Water Hacker <satoshinakamotobull@gmail.com>
Date:   Sun Jul 19 11:47:14 2026 -0400

    Spine rotation Slice 0: manifest + path-stable lockfile + split-brain-safe migration
    
    First slice of retain-all segment rotation (design: judge-panel synthesis; hard-prune deferred as an
    explicit operator decision). Behavior stays BYTE-IDENTICAL until an explicit migrate() — with no
    manifest the store reads/writes the legacy single file in place.
    
    - spine/atomicio.py (new): the one shared temp→fsync→os.replace→dir-fsync routine; checkpoint's
      _atomic_write_text now delegates to it (no drift — head, manifest, and every future cutover share it).
    - spine/manifest.py (new): Segment/Manifest models (unsigned, non-load-bearing — order/count/tamper all
      re-derive from record BYTES, so a doctored manifest fails CLOSED), SpineLayout (derives the whole
      layout from the store path so temp stores stay isolated), atomic read/write.
    - config.py: SEGMENTS_DIR / MANIFEST_PATH / LOCKFILE_PATH / TRASH_DIR / ARCHIVE_DIR (no I/O).
    - store.py: all DATA I/O now targets self._active (the manifest's active segment, or the legacy file in
      place); the cross-process flock moves from the data fd to the inode-stable spine.lock (invariant 14 /
      D3 — survives an os.replace); the in-process RLock stays keyed on the STABLE self.path so the lock
      envelope.consume shares with append is the same object across a rotation. append re-resolves the active
      segment UNDER the lock (_refresh_active_under_lock) so a stale appender never forks the log. New
      migrate() renames spine.jsonl -> segments/seg-00000000.jsonl (O(1), atomic) + publishes a manifest;
      idempotent; spine.jsonl is never re-created as a data file.
    
    Tests (test_spine_rotation.py, 6): legacy byte-identical; RLock keyed-on-stable-path survives migration;
    migrate preserves chain/next_seq/verify and moves to a segment; idempotent; fresh-migrate creates an
    empty active; and the split-brain test — a stale appender re-resolves under the lock and never resurrects
    spine.jsonl.
    
    354 passed (348 + 6); ruff + mypy clean. Rotation stays OFF (no seal/rotate yet — Slice 3).
    
    Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>

diff --git a/sigil/config.py b/sigil/config.py
index b493d1d..f218ce9 100644
--- a/sigil/config.py
+++ b/sigil/config.py
@@ -55,6 +55,20 @@ HEAD_PATH = _spine / "head.json"
 KEYS_DIR = _spine / "keys"
 CACHE_DIR = SIGIL_HOME / "cache"
 
+# --- segment rotation (retain-all) layout ------------------------------------------------
+# The spine grows into size-bounded, immutable segments under SEGMENTS_DIR governed by MANIFEST_PATH
+# (the sole linearization point). After migration SPINE_PATH is renamed into SEGMENTS_DIR and is never a
+# data file again — it survives only as the stable lock/identity token. LOCKFILE_PATH is an inode-stable
+# cross-process flock target (never renamed/unlinked), so it excludes appenders across an os.replace of
+# the manifest/segments. These are the DEFAULTS for the SPINE_PATH deployment; SpineStore derives the
+# same layout relative to whatever `path` it is constructed with, so tests stay isolated. config.py does
+# no I/O — it only names paths.
+SEGMENTS_DIR = _spine / "segments"
+MANIFEST_PATH = _spine / "manifest.json"
+LOCKFILE_PATH = _spine / "spine.lock"
+TRASH_DIR = _spine / "trash"          # superseded plaintext awaiting the reader-grace reaper (Slice 4)
+ARCHIVE_DIR = _spine / "archive"      # optional cold-move target (Slice 5, default-OFF)
+
 # --- ingestion sources ----------------------------------------------------------------
 CLAUDE_PROJECTS = Path(os.environ.get("SIGIL_CLAUDE_PROJECTS", str(Path.home() / ".claude" / "projects")))
 # Phase-0a thin slice: PENTEST-main only. Slugified cwd = dir name under ~/.claude/projects.
diff --git a/sigil/spine/atomicio.py b/sigil/spine/atomicio.py
new file mode 100644
index 0000000..8891cfb
--- /dev/null
+++ b/sigil/spine/atomicio.py
@@ -0,0 +1,48 @@
+"""Durable, atomic file replacement — the one implementation the spine's crash-safe swaps share.
+
+Extracted verbatim from `checkpoint._atomic_write_text` (FIX 3) so the signed head, the manifest, and
+any future single-file cutover all use ONE audited routine rather than drifting copies. The contract:
+a reader observes either the whole old file or the whole new file (never a torn one), and the new
+content survives a crash at any point — a crash mid-write leaves the PREVIOUS valid file intact.
+"""
+from __future__ import annotations
+
+import os
+import tempfile
+from pathlib import Path
+
+
+def fsync_dir(directory: Path | str) -> None:
+    """fsync a directory so a rename/create inside it is itself durable across a crash. A no-op-on-error
+    on filesystems that don't support directory fsync (the rename still lands; only its durability window
+    widens)."""
+    try:
+        dfd = os.open(str(directory), os.O_DIRECTORY)
+        try:
+            os.fsync(dfd)
+        finally:
+            os.close(dfd)
+    except OSError:  # pragma: no cover — dir fsync unsupported on some filesystems
+        pass
+
+
+def atomic_write_text(path: Path | str, data: str, *, prefix: str = ".tmp-") -> None:
+    """Durably + atomically replace `path` with `data`: write a temp file in the SAME dir, fsync it,
+    `os.replace()` over the target (atomic on POSIX), then fsync the directory so the rename survives a
+    crash. A crash at any point leaves the previous valid file intact, never a partially-written one."""
+    path = Path(path)
+    path.parent.mkdir(parents=True, exist_ok=True)
+    fd, tmp = tempfile.mkstemp(dir=str(path.parent), prefix=prefix, suffix=".tmp")
+    try:
+        with os.fdopen(fd, "w", encoding="utf-8") as f:
+            f.write(data)
+            f.flush()
+            os.fsync(f.fileno())
+        os.replace(tmp, path)
+    except BaseException:
+        try:
+            os.unlink(tmp)
+        except OSError:
+            pass
+        raise
+    fsync_dir(path.parent)
diff --git a/sigil/spine/checkpoint.py b/sigil/spine/checkpoint.py
index b2dfa98..dc26460 100644
--- a/sigil/spine/checkpoint.py
+++ b/sigil/spine/checkpoint.py
@@ -12,7 +12,6 @@ added later by raising the trust-root threshold.
 from __future__ import annotations
 
 import os
-import tempfile
 from pathlib import Path
 
 from ..config import HEAD_PATH, KEYS_DIR, OWNER_KEY_ID, SCOPE
@@ -24,6 +23,7 @@ from ..reuse import (
     sign_head,
     verify_head,
 )
+from .atomicio import atomic_write_text
 from .store import SpineStore
 
 _PRIV = KEYS_DIR / "owner.priv"
@@ -31,33 +31,11 @@ _PUB = KEYS_DIR / "owner.pub"
 
 
 def _atomic_write_text(path: Path, data: str) -> None:
-    """Durably + atomically replace `path` with `data` (FIX 3): write a temp file in the SAME dir,
-    fsync it, `os.replace()` over the target (atomic on POSIX — a reader sees either the old or the
-    new head, never a torn one), then fsync the directory so the rename itself survives a crash. A
-    crash at any point leaves the previous valid signed head intact, never a partially-written one."""
-    path = Path(path)
-    path.parent.mkdir(parents=True, exist_ok=True)
-    fd, tmp = tempfile.mkstemp(dir=str(path.parent), prefix=".head-", suffix=".tmp")
-    try:
-        with os.fdopen(fd, "w", encoding="utf-8") as f:
-            f.write(data)
-            f.flush()
-            os.fsync(f.fileno())
-        os.replace(tmp, path)
-    except BaseException:
-        try:
-            os.unlink(tmp)
-        except OSError:
-            pass
-        raise
-    try:                                     # fsync the directory so the rename is durable
-        dfd = os.open(str(path.parent), os.O_DIRECTORY)
-        try:
-            os.fsync(dfd)
-        finally:
-            os.close(dfd)
-    except OSError:  # pragma: no cover — dir fsync unsupported on some filesystems
-        pass
+    """Durably + atomically replace `path` with `data` (FIX 3) — a reader sees either the whole old or
+    the whole new head, never a torn one, and a crash leaves the previous valid head intact. Delegates to
+    the one shared `spine.atomicio.atomic_write_text` so the head, the manifest, and every cutover use the
+    same audited routine (no drift)."""
+    atomic_write_text(path, data, prefix=".head-")
 
 
 def _owner_keys() -> tuple[str, str]:
diff --git a/sigil/spine/manifest.py b/sigil/spine/manifest.py
new file mode 100644
index 0000000..ce88a68
--- /dev/null
+++ b/sigil/spine/manifest.py
@@ -0,0 +1,127 @@
+"""The spine's segment MANIFEST — the sole linearization point for the retain-all segment set.
+
+The spine is stored as a sequence of size-bounded, immutable **sealed** segments plus exactly one
+**active** (append) segment; the manifest names them in seq order. It is deliberately UNSIGNED and
+NON-LOAD-BEARING: record order, count, and every tamper decision are re-derived from the segment BYTES
+(via `verify_chain`/`classify_head`), never from the manifest's convenience fields. A doctored manifest
+therefore fails CLOSED — dropping/reordering an interior segment breaks `prev_hash`/seq contiguity, a
+dropped tail shortens `entries()` (the signed head's `n < entry_count` gate fires), a dropped front fails
+the genesis check. (A future signed-manifest tier would set `manifest_sig` — reserved `null` — because it
+would then attest pruned ranges; retain-all needs no such trust.)
+
+`SpineLayout` derives the whole on-disk layout from the spine data-file path a `SpineStore` is constructed
+with, so a store on a temp path is fully isolated. This module does no locking — the caller (`SpineStore`)
+holds the cross-process flock while reading/writing/migrating.
+"""
+from __future__ import annotations
+
+from dataclasses import dataclass
+from pathlib import Path
+
+from pydantic import BaseModel, ConfigDict, Field
+
+from ..reuse.chain import _GENESIS_PREV
+from .atomicio import atomic_write_text
+
+SEGMENT_STEM = "seg-"
+_SCHEMA_VERSION = 1
+
+
+def segment_filename(seg_id: int, codec: str = "none") -> str:
+    """Zero-padded segment file name; `.gz` suffix when gzip-sealed (Slice 4)."""
+    base = f"{SEGMENT_STEM}{seg_id:08d}.jsonl"
+    return base + ".gz" if codec == "gzip" else base
+
+
+class Segment(BaseModel):
+    """One segment in the manifest. `first_prev_hash`/`boundary_hash` are the chain-linkage the reader
+    CROSS-CHECKS against the segment's real first/last records — they are convenience, not authority."""
+    model_config = ConfigDict(extra="ignore")   # forward-compatible: tolerate fields a newer writer added
+    id: int = Field(ge=0)
+    file: str                                    # path RELATIVE to the spine dir, e.g. "segments/seg-00000000.jsonl"
+    codec: str = "none"                          # "none" | "gzip"
+    sealed: bool = False
+    first_seq: int = Field(ge=0)
+    last_seq: int | None = None                  # null while active
+    count: int | None = None                     # null while active; CONVENIENCE ONLY — never a tamper input
+    first_prev_hash: str = _GENESIS_PREV         # == the prior segment's boundary_hash (seg 0 == genesis)
+    boundary_hash: str | None = None             # == entry_hash(last_seq); null while active
+    bytes: int = 0
+    sha256: str | None = None                    # at-rest file integrity; NOT a chain digest
+
+
+class Manifest(BaseModel):
+    model_config = ConfigDict(extra="ignore")
+    schema_version: int = _SCHEMA_VERSION
+    generation: int = Field(default=0, ge=0)     # monotonic epoch; ++ on EVERY swap — the unified change token
+    scope: str = ""
+    segments: list[Segment] = Field(default_factory=list)
+    manifest_sig: str | None = None              # reserved for the deferred signed-manifest tier
+
+    def active(self) -> Segment | None:
+        """The single unsealed (append) segment, if any. There is at most one."""
+        act = [s for s in self.segments if not s.sealed]
+        return act[-1] if act else None
+
+    def sealed_in_order(self) -> list[Segment]:
+        return sorted((s for s in self.segments if s.sealed), key=lambda s: s.first_seq)
+
+    def ordered(self) -> list[Segment]:
+        """All segments in seq order (sealed by first_seq, then the active tail)."""
+        out = self.sealed_in_order()
+        act = self.active()
+        if act is not None:
+            out.append(act)
+        return out
+
+
+@dataclass(frozen=True)
+class SpineLayout:
+    """The on-disk layout derived from a spine data-file path (…/spine.jsonl). Every path is relative to
+    that file's directory so a store on a temp path is isolated from the real ~/.sigil deployment."""
+    data_path: Path            # the legacy/identity path (…/spine.jsonl) — the stable lock/identity token
+    spine_dir: Path
+    segments_dir: Path
+    manifest_path: Path
+    lockfile_path: Path
+    trash_dir: Path
+
+    @classmethod
+    def for_path(cls, data_path: Path | str) -> "SpineLayout":
+        p = Path(data_path)
+        d = p.parent
+        return cls(
+            data_path=p, spine_dir=d, segments_dir=d / "segments",
+            manifest_path=d / "manifest.json", lockfile_path=d / "spine.lock", trash_dir=d / "trash",
+        )
+
+    def seg_path(self, seg: Segment) -> Path:
+        """Absolute path of a segment's file (its `file` is stored relative to the spine dir)."""
+        return self.spine_dir / seg.file
+
+
+def read_manifest(layout: SpineLayout) -> Manifest | None:
+    """Load the manifest, or None if absent. A present-but-unparseable manifest RAISES (fail closed) —
+    the atomic write path guarantees it is never torn, so a parse failure means genuine corruption, not a
+    partial write, and must never be silently treated as 'no manifest' (which would strand the segments)."""
+    mp = layout.manifest_path
+    if not mp.exists():
+        return None
+    return Manifest.model_validate_json(mp.read_text(encoding="utf-8"))
+
+
+def write_manifest(layout: SpineLayout, manifest: Manifest) -> None:
+    """Atomically publish the manifest (temp→fsync→os.replace→dir-fsync). THE cutover commit instant."""
+    layout.manifest_path.parent.mkdir(parents=True, exist_ok=True)
+    atomic_write_text(layout.manifest_path, manifest.model_dump_json(), prefix=".manifest-")
+
+
+def initial_manifest(scope: str, *, active_file: str, first_seq: int = 0,
+                     first_prev_hash: str = _GENESIS_PREV) -> Manifest:
+    """A single-active-segment manifest (generation 0) — the shape produced by a fresh store or a
+    migration of an existing single-file spine."""
+    return Manifest(
+        generation=0, scope=scope,
+        segments=[Segment(id=0, file=active_file, codec="none", sealed=False,
+                          first_seq=first_seq, first_prev_hash=first_prev_hash)],
+    )
diff --git a/sigil/spine/store.py b/sigil/spine/store.py
index 0ce9a79..1092567 100644
--- a/sigil/spine/store.py
+++ b/sigil/spine/store.py
@@ -12,11 +12,21 @@ import json
 import logging
 import os
 import threading
+from contextlib import contextmanager
 from pathlib import Path
 from typing import Any, Iterator
 
 from ..config import SCOPE, SPINE_PATH
 from ..reuse import ChainEntry, append_entry, build_chain, digest_payload, verify_chain
+from .atomicio import fsync_dir
+from .manifest import (
+    Manifest,
+    SpineLayout,
+    initial_manifest,
+    read_manifest,
+    segment_filename,
+    write_manifest,
+)
 from .models import SpineRecord, now_iso
 
 try:
@@ -123,13 +133,27 @@ def _last_valid_boundary(path: Path) -> "tuple[int, ChainEntry | None]":
 
 class SpineStore:
     def __init__(self, path: Path | str = SPINE_PATH) -> None:
+        # `self.path` is the STABLE identity + lock token (…/spine.jsonl). After a migration it is renamed
+        # away and no longer a data file, but it remains the key for the in-process RLock and the anchor
+        # the whole layout derives from — so the RLock that `envelope.consume` shares with `append` stays
+        # the same object across a rotation (invariant 14). All DATA I/O targets `self._active` (the
+        # manifest's active segment, or — with no manifest yet — the legacy single file in place, which is
+        # byte-identical to the pre-rotation store).
         self.path = Path(path)
         self.path.parent.mkdir(parents=True, exist_ok=True)
+        self._layout = SpineLayout.for_path(self.path)
+        # NB: `segments/` is created only when actually migrating/rotating (not on every construction), so a
+        # legacy/fresh store leaves the spine dir byte-identical to today (no stray empty dirs).
+        self._manifest: Manifest | None = read_manifest(self._layout)
+        self._reconcile_orphan_migration()          # complete a migrate() interrupted before the manifest write
+        self._active: Path = self._resolve_active_path()
         # seq -> byte-offset index (FIX 1). Built lazily on the first TARGETED read (get / iter_records
         # with since_seq >= 0) and then kept current: maintained O(1) on our own appends, and extended
         # (never rewritten — an append-only file's offsets never move) when a stat shows another PROCESS
         # grew the file. Full scans (verify/count/entries/iter_records(-1)) never touch it, staying a
         # single byte-identical pass. `_index_lock` guards the dict against concurrent read+append.
+        # Slice 0/1: the index is single-segment (over `self._active`); it is (segment, offset)-aware in
+        # a later slice. It is invalidated whenever the active segment changes under us.
         self._index_lock = threading.Lock()
         self._index_built = False
         self._offsets: dict[int, int] = {}
@@ -137,6 +161,113 @@ class SpineStore:
         self._scan_pos = 0                          # byte offset just past the last COMPLETE line indexed
         self._last: ChainEntry | None = self._read_last_entry()
 
+    # --- segment layout / manifest ------------------------------------------------
+    def _resolve_active_path(self) -> Path:
+        """The current append/read target. With a manifest, the active segment's absolute path; without
+        one (a fresh or not-yet-migrated legacy spine), the legacy single file in place — byte-identical
+        to the pre-rotation store, so nothing destructive happens until an explicit `migrate()`."""
+        if self._manifest is not None:
+            act = self._manifest.active()
+            if act is not None:
+                return self._layout.seg_path(act)
+        return self.path
+
+    @contextmanager
+    def _crossproc_lock(self) -> "Iterator[None]":
+        """Cross-process exclusion on the inode-stable lockfile (invariant 14 / D3). flock binds to the
+        open file DESCRIPTION, not the path, so an os.replace of the manifest/segments cannot move the
+        lock out from under a concurrent writer — which the prior flock-on-the-data-fd could not survive.
+        Best-effort exactly as before (fcntl absent on non-POSIX; a flock failure is swallowed)."""
+        if fcntl is None:  # pragma: no cover — non-POSIX
+            yield
+            return
+        self._layout.lockfile_path.parent.mkdir(parents=True, exist_ok=True)
+        fd = os.open(str(self._layout.lockfile_path), os.O_RDWR | os.O_CREAT, 0o600)
+        try:
+            try:
+                fcntl.flock(fd, fcntl.LOCK_EX)
+            except OSError:  # pragma: no cover
+                pass
+            yield
+        finally:
+            os.close(fd)
+
+    def _refresh_active_under_lock(self) -> None:
+        """MUST hold `_crossproc_lock`. Re-resolve the active segment from the manifest so an appender
+        constructed BEFORE a concurrent migrate()/rotation writes to the CURRENT active target, never a
+        stale path — which would fork the log or resurrect a renamed-away file (the split-brain the
+        two-step migration guards against). Cheap: the manifest is tiny (Slice 1 gates this on a change
+        token)."""
+        m = read_manifest(self._layout)
+        new_active = self.path
+        act = m.active() if m is not None else None
+        if act is not None:
+            new_active = self._layout.seg_path(act)
+        if new_active != self._active or (m is not None) != (self._manifest is not None):
+            self._manifest = m
+            self._active = new_active
+            self._invalidate_index()
+            self._last = self._read_last_entry()
+
+    def _invalidate_index(self) -> None:
+        """MUST hold `_index_lock` OR be on a path with no concurrent index use. Drops the single-segment
+        index so the next read rebuilds it against the (possibly changed) active segment."""
+        with self._index_lock:
+            self._index_built = False
+            self._offsets = {}
+            self._max_seq = -1
+            self._scan_pos = 0
+
+    def _reconcile_orphan_migration(self) -> None:
+        """Close the migrate() crash window. migrate() does an ATOMIC `os.replace(spine.jsonl →
+        segments/seg-00000000.jsonl)` and THEN publishes the manifest; a crash BETWEEN them leaves seg-0
+        present, `spine.jsonl` gone, and no manifest — at which point the legacy fallback (active =
+        spine.jsonl) would read the spine as EMPTY and silently hide all history. The rename is atomic and
+        already durable, so if we observe exactly that state we simply finish the interrupted migration by
+        publishing the manifest (idempotent, under the cross-process lock). (os.replace is atomic, so
+        spine.jsonl and seg-0 are never both present or both absent from a torn rename — this one state is
+        the whole window.)"""
+        if self._manifest is not None:
+            return
+        seg0 = self._layout.segments_dir / segment_filename(0)
+        if not (seg0.exists() and not self.path.exists()):
+            return
+        with self._crossproc_lock():
+            if read_manifest(self._layout) is None and seg0.exists() and not self.path.exists():
+                write_manifest(self._layout,
+                               initial_manifest(SCOPE, active_file=f"segments/{segment_filename(0)}"))
+                _log.warning("spine: completed an interrupted migration — published the manifest for %s", seg0)
+            self._manifest = read_manifest(self._layout)
+
+    def migrate(self) -> bool:
+        """Move a legacy single-file spine into the segment layout: rename `spine.jsonl` →
+        `segments/seg-00000000.jsonl` (atomic, same filesystem — O(1), no byte copy) and publish a
+        single-active-segment manifest. Idempotent (a no-op once a manifest exists). Returns True iff it
+        migrated. SPLIT-BRAIN SAFETY: run this only after every spine writer is on code that flocks the
+        path-stable lockfile (this Slice-0 code) and re-resolves the active segment under that lock — so
+        no old-style appender writes to `spine.jsonl` through the former data-fd flock while this runs.
+        After migration `spine.jsonl` is absent and is NEVER re-created as a data file (all data I/O
+        targets the active segment)."""
+        with spine_lock(self.path):
+            with self._crossproc_lock():
+                if read_manifest(self._layout) is not None:
+                    self._refresh_active_under_lock()
+                    return False
+                self._layout.segments_dir.mkdir(parents=True, exist_ok=True)
+                seg0_rel = f"segments/{segment_filename(0)}"
+                seg0_abs = self._layout.segments_dir / segment_filename(0)
+                if self.path.exists():
+                    os.replace(self.path, seg0_abs)         # atomic rename (same fs); O(1), no copy
+                else:
+                    seg0_abs.touch()                        # fresh spine: create the empty active segment
+                fsync_dir(self._layout.segments_dir)
+                write_manifest(self._layout, initial_manifest(SCOPE, active_file=seg0_rel))
+                self._manifest = read_manifest(self._layout)
+                self._active = self._resolve_active_path()
+                self._invalidate_index()
+                self._last = self._read_last_entry()
+                return True
+
     # --- write --------------------------------------------------------------------
     def append(
         self, *, kind: str, source: str, actor: str, payload: dict[str, Any],
@@ -149,48 +280,48 @@ class SpineStore:
         }
         cert_digest = digest_payload(content)  # wallclock-free
         # Serialize the whole read-tip → write so concurrent writers (threaded bridge server, gesture
-        # daemon) can't both fork off a stale tip and break the chain. Re-read the TRUE tip from disk
-        # under the lock — `self._last` may be stale if another instance/process appended.
+        # daemon) can't both fork off a stale tip and break the chain. The in-process RLock is keyed on
+        # the STABLE `self.path` (unchanged), so the check-then-append gate `envelope.consume` builds on
+        # top of it stays atomic across a rotation. Re-read the TRUE tip from disk under the lock.
         with spine_lock(self.path):
-            # binary append+read: lets us TRUNCATE a torn tail before writing (BLOCK-1 fix). `a+b` creates
-            # the file if absent and — in append mode — every write still lands at EOF.
-            with self.path.open("a+b") as f:
-                if fcntl is not None:
-                    try:
-                        fcntl.flock(f.fileno(), fcntl.LOCK_EX)   # cross-process guard (advisory)
-                    except OSError:  # pragma: no cover
-                        pass
-                # BLOCK-1: an interrupted write can leave torn bytes PAST the last valid record. Appending
-                # after them would MERGE (torn + new) into one unparseable line → the new record is silently
-                # lost, verify() stays green, and a lost kill-switch panic never halts the mesh. Truncate the
-                # dead tail back to the last valid record FIRST (this only removes never-committed garbage
-                # from an interrupted write; committed records are untouched).
-                clean_end, last = _last_valid_boundary(self.path)
-                pre_size = os.fstat(f.fileno()).st_size
-                if pre_size > clean_end:
-                    f.truncate(clean_end)
-                    _log.warning("spine: truncated a %d-byte torn tail (interrupted write) before append (%s)",
-                                 pre_size - clean_end, self.path)
-                entry = append_entry([last], cert_digest) if last else build_chain([cert_digest])[0]
-                record = {
-                    "seq": entry.seq, **content, "ts": ts or now_iso(),
-                    "cert_digest": cert_digest, "prev_hash": entry.prev_hash, "entry_hash": entry.entry_hash,
-                }
-                line = json.dumps(record, ensure_ascii=False) + "\n"
-                offset = clean_end                      # after any truncate, EOF == clean_end (where the line lands)
-                f.write(line.encode("utf-8"))
-                f.flush()
-                os.fsync(f.fileno())                    # FIX 3: an ack'd append is durable across a crash
-                # FIX 1: keep the index current with NO re-scan when it is already exactly up to date.
-                # If another PROCESS appended in between, `_scan_pos < offset` and we skip here — the next
-                # read's `_ensure_index` extends from `_scan_pos`, picking up the gap records AND this one.
-                with self._index_lock:
-                    if self._index_built and self._scan_pos == offset:
-                        self._offsets[entry.seq] = offset
-                        if entry.seq > self._max_seq:
-                            self._max_seq = entry.seq
-                        self._scan_pos = offset + len(line.encode("utf-8"))
-            self._last = entry
+            with self._crossproc_lock():                 # cross-process guard on the path-stable lockfile
+                self._refresh_active_under_lock()        # pick up a concurrent migrate()/rotation; never fork
+                active = self._active
+                # binary append+read: lets us TRUNCATE a torn tail before writing (BLOCK-1 fix). `a+b`
+                # creates the file if absent and — in append mode — every write still lands at EOF.
+                with active.open("a+b") as f:
+                    # BLOCK-1: an interrupted write can leave torn bytes PAST the last valid record. Appending
+                    # after them would MERGE (torn + new) into one unparseable line → the new record is silently
+                    # lost, verify() stays green, and a lost kill-switch panic never halts the mesh. Truncate the
+                    # dead tail back to the last valid record FIRST (this only removes never-committed garbage
+                    # from an interrupted write; committed records are untouched). Evaluated on the ACTIVE
+                    # segment under the lock (invariant 7 — the append target is always the true chain tip).
+                    clean_end, last = _last_valid_boundary(active)
+                    pre_size = os.fstat(f.fileno()).st_size
+                    if pre_size > clean_end:
+                        f.truncate(clean_end)
+                        _log.warning("spine: truncated a %d-byte torn tail (interrupted write) before append (%s)",
+                                     pre_size - clean_end, active)
+                    entry = append_entry([last], cert_digest) if last else build_chain([cert_digest])[0]
+                    record = {
+                        "seq": entry.seq, **content, "ts": ts or now_iso(),
+                        "cert_digest": cert_digest, "prev_hash": entry.prev_hash, "entry_hash": entry.entry_hash,
+                    }
+                    line = json.dumps(record, ensure_ascii=False) + "\n"
+                    offset = clean_end                      # after any truncate, EOF == clean_end (where the line lands)
+                    f.write(line.encode("utf-8"))
+                    f.flush()
+                    os.fsync(f.fileno())                    # FIX 3: an ack'd append is durable across a crash
+                    # FIX 1: keep the index current with NO re-scan when it is already exactly up to date.
+                    # If another PROCESS appended in between, `_scan_pos < offset` and we skip here — the next
+                    # read's `_ensure_index` extends from `_scan_pos`, picking up the gap records AND this one.
+                    with self._index_lock:
+                        if self._index_built and self._scan_pos == offset:
+                            self._offsets[entry.seq] = offset
+                            if entry.seq > self._max_seq:
+                                self._max_seq = entry.seq
+                            self._scan_pos = offset + len(line.encode("utf-8"))
+                self._last = entry
         return entry.seq
 
     # --- read ---------------------------------------------------------------------
@@ -200,10 +331,10 @@ class SpineStore:
         at byte 0 exactly as before. FIX 2: a line that fails to parse or lacks required keys is SKIPPED
         (a torn tail no longer crashes the read); a torn MIDDLE line becomes a seq gap that verify() fails
         on, so mid-file tampering is never silently hidden."""
-        if not self.path.exists():
+        if not self._active.exists():
             return
         start_off = self._start_offset_for(since_seq)
-        with self.path.open("rb") as f:
+        with self._active.open("rb") as f:
             if start_off:
                 f.seek(start_off)
             for raw in f:
@@ -212,20 +343,20 @@ class SpineStore:
                 try:
                     rec = SpineRecord.from_dict(json.loads(raw))
                 except (ValueError, KeyError, TypeError):
-                    _log.warning("spine: skipping malformed line during iter_records (%s)", self.path)
+                    _log.warning("spine: skipping malformed line during iter_records (%s)", self._active)
                     continue
                 if rec.seq > since_seq:
                     yield rec
 
     def get(self, seq: int) -> SpineRecord | None:
         """A single record by seq — O(1) via the index (FIX 1), byte-identical to a full scan."""
-        if seq < 0 or not self.path.exists():
+        if seq < 0 or not self._active.exists():
             return None
         self._ensure_index()
         with self._index_lock:
             off = self._offsets.get(seq)
         if off is not None:
-            with self.path.open("rb") as f:
+            with self._active.open("rb") as f:
                 f.seek(off)
                 raw = f.readline()
             try:
@@ -248,9 +379,9 @@ class SpineStore:
         distinct bodies larger than the window each ages out and re-records. Only pair `tail()`-based
         dedup with a record-time freshness gate (or an independent bound); do not rely on it alone to
         close a bloat sink."""
-        if n <= 0 or not self.path.exists():
+        if n <= 0 or not self._active.exists():
             return []
-        with self.path.open("rb") as f:
+        with self._active.open("rb") as f:
             f.seek(0, os.SEEK_END)
             pos = f.tell()
             buf = b""
@@ -305,7 +436,7 @@ class SpineStore:
     def _read_last_entry(self) -> ChainEntry | None:
         # `_last_nonempty_line` skips a torn/garbage tail and returns the last VALID line (FIX 2), so a
         # crash mid-write can no longer block a restart. The returned line is guaranteed parseable.
-        line = _last_nonempty_line(self.path) if self.path.exists() else None
+        line = _last_nonempty_line(self._active) if self._active.exists() else None
         if not line:
             return None
         d = json.loads(line)
@@ -332,7 +463,7 @@ class SpineStore:
         (our own or another PROCESS's appends — append-only ⇒ offsets never move, so we only EXTEND) and
         a file that SHRANK / was rewritten in place smaller (rebuild). Thread-safe under `_index_lock`."""
         try:
-            size = self.path.stat().st_size if self.path.exists() else 0
+            size = self._active.stat().st_size if self._active.exists() else 0
         except OSError:
             return
         with self._index_lock:
@@ -356,7 +487,7 @@ class SpineStore:
         surfaces via verify()); a trailing partial line (no newline yet) is left for the next extend."""
         if size <= start:
             return
-        with self.path.open("rb") as f:
+        with self._active.open("rb") as f:
             f.seek(start)
             chunk = f.read(size - start)
         consumed = 0
