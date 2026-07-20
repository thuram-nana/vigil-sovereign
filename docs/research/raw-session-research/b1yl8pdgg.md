commit 0b4ac6a0e91952c71fa05fb61cc3dff786e45fe2
Author: Water Hacker <satoshinakamotobull@gmail.com>
Date:   Sun Jul 19 11:47:14 2026 -0400

    Spine rotation Slice 0: manifest + path-stable lockfile + split-brain-safe migration
    
    First slice of retain-all segment rotation (design: judge-panel synthesis; hard-prune deferred as an
    explicit operator decision). Behavior stays BYTE-IDENTICAL until an explicit migrate() — with no
    manifest the store reads/writes the legacy single file in place.
    
    - spine/atomicio.py (new): the one shared temp→fsync→os.replace→dir-fsync routine; checkpoint's
      _atomic_write_text delegates to it (no drift).
    - spine/manifest.py (new): Segment/Manifest models (unsigned, non-load-bearing — a doctored manifest
      fails CLOSED; segment `file` is validated to a contained relative path so reads can't be steered at
      /etc/*), SpineLayout NAMESPACED BY the data-file stem (spine.manifest.json / spine.lock /
      spine.segments/) so co-located stores never collide, atomic read/write.
    - config.py: layout is derived by SpineLayout, not fixed constants (no drift / no "dir is private" bug).
    - store.py: DATA I/O targets self._active (manifest active, or legacy file in place); cross-process flock
      moved to the inode-stable spine.lock (survives os.replace); in-process RLock stays keyed on the stable
      self.path (the lock envelope.consume shares with append is the same object across a rotation). append
      re-resolves the active UNDER the lock AND completes an interrupted migration there, so a live appender
      never resurrects spine.jsonl / forks. migrate() renames spine.jsonl -> seg-0 (O(1), fsync BOTH dirs) +
      publishes a manifest; a reconciler (construction AND live-append paths) closes the rename↔manifest
      crash window. change_token() (unified A4 epoch) replaces the size-only kill-switch tokens in
      killswitch.py and gesture/session.py — a migration that renames spine.jsonl away can no longer freeze a
      stale (un-halting) verdict. Reads re-resolve a vanished active for the migrate instant (F3).
      Degenerate "manifest with no active" RAISES rather than resurrecting spine.jsonl (Slice-3 landmine).
    
    Dual adversarial review (concurrency/durability + behavior-parity) BEFORE building further: caught and
    fixed a CRITICAL live-appender-resurrects-spine.jsonl fork (reconciler now runs on the append path too),
    a layout cross-store contamination (stem namespacing), a kill-switch un-halting regression after migrate
    (change_token), a half-fsynced cross-dir rename, a manifest path-escape, and a no-active resurrection
    landmine — each with a regression test.
    
    Tests (test_spine_rotation.py, 11): legacy byte-identical; RLock stable across migration; migrate
    preserves chain/next_seq/verify; idempotent; fresh-migrate; orphan reconcile (construction + live
    appender); change_token moves on append/migrate; kill-switch panic observed after migration; manifest
    path-escape rejected; split-brain re-resolve.
    
    359 passed (348 + 11); ruff + mypy clean. Rotation stays OFF (no seal/rotate yet — Slice 3).
    
    Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>

 sigil/config.py              |   5 +
 sigil/gesture/session.py     |  25 ++--
 sigil/governor/killswitch.py |  43 +++---
 sigil/spine/atomicio.py      |  48 +++++++
 sigil/spine/checkpoint.py    |  34 +----
 sigil/spine/manifest.py      | 151 +++++++++++++++++++++
 sigil/spine/store.py         | 303 +++++++++++++++++++++++++++++++++++--------
 tests/test_spine_rotation.py | 247 +++++++++++++++++++++++++++++++++++
 8 files changed, 742 insertions(+), 114 deletions(-)
=====FULL DIFF=====
commit 0b4ac6a0e91952c71fa05fb61cc3dff786e45fe2
Author: Water Hacker <satoshinakamotobull@gmail.com>
Date:   Sun Jul 19 11:47:14 2026 -0400

    Spine rotation Slice 0: manifest + path-stable lockfile + split-brain-safe migration
    
    First slice of retain-all segment rotation (design: judge-panel synthesis; hard-prune deferred as an
    explicit operator decision). Behavior stays BYTE-IDENTICAL until an explicit migrate() — with no
    manifest the store reads/writes the legacy single file in place.
    
    - spine/atomicio.py (new): the one shared temp→fsync→os.replace→dir-fsync routine; checkpoint's
      _atomic_write_text delegates to it (no drift).
    - spine/manifest.py (new): Segment/Manifest models (unsigned, non-load-bearing — a doctored manifest
      fails CLOSED; segment `file` is validated to a contained relative path so reads can't be steered at
      /etc/*), SpineLayout NAMESPACED BY the data-file stem (spine.manifest.json / spine.lock /
      spine.segments/) so co-located stores never collide, atomic read/write.
    - config.py: layout is derived by SpineLayout, not fixed constants (no drift / no "dir is private" bug).
    - store.py: DATA I/O targets self._active (manifest active, or legacy file in place); cross-process flock
      moved to the inode-stable spine.lock (survives os.replace); in-process RLock stays keyed on the stable
      self.path (the lock envelope.consume shares with append is the same object across a rotation). append
      re-resolves the active UNDER the lock AND completes an interrupted migration there, so a live appender
      never resurrects spine.jsonl / forks. migrate() renames spine.jsonl -> seg-0 (O(1), fsync BOTH dirs) +
      publishes a manifest; a reconciler (construction AND live-append paths) closes the rename↔manifest
      crash window. change_token() (unified A4 epoch) replaces the size-only kill-switch tokens in
      killswitch.py and gesture/session.py — a migration that renames spine.jsonl away can no longer freeze a
      stale (un-halting) verdict. Reads re-resolve a vanished active for the migrate instant (F3).
      Degenerate "manifest with no active" RAISES rather than resurrecting spine.jsonl (Slice-3 landmine).
    
    Dual adversarial review (concurrency/durability + behavior-parity) BEFORE building further: caught and
    fixed a CRITICAL live-appender-resurrects-spine.jsonl fork (reconciler now runs on the append path too),
    a layout cross-store contamination (stem namespacing), a kill-switch un-halting regression after migrate
    (change_token), a half-fsynced cross-dir rename, a manifest path-escape, and a no-active resurrection
    landmine — each with a regression test.
    
    Tests (test_spine_rotation.py, 11): legacy byte-identical; RLock stable across migration; migrate
    preserves chain/next_seq/verify; idempotent; fresh-migrate; orphan reconcile (construction + live
    appender); change_token moves on append/migrate; kill-switch panic observed after migration; manifest
    path-escape rejected; split-brain re-resolve.
    
    359 passed (348 + 11); ruff + mypy clean. Rotation stays OFF (no seal/rotate yet — Slice 3).
    
    Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>

diff --git a/sigil/gesture/session.py b/sigil/gesture/session.py
index ad26079..13554b1 100644
--- a/sigil/gesture/session.py
+++ b/sigil/gesture/session.py
@@ -100,7 +100,7 @@ class SessionGate:
         self._trusted_pubkey = trusted_pubkey
         self.session: Optional[Session] = None
         self._ks_engaged = False
-        self._ks_size = -1                # last-scanned spine size; -1 forces a fresh check on the first consult
+        self._ks_token: tuple | None = None   # last-scanned spine change token; None forces a fresh check first
         self._ks_checked_at = -1e9
 
     def _trusted(self):
@@ -111,20 +111,19 @@ class SessionGate:
 
     def _killswitch_engaged(self, now: float) -> bool:
         """Kill-switch state for the per-intent gate. Re-scans the AUTHORITATIVE `KillSwitch` (which
-        verifies the owner-signed release — never re-implemented here) ONLY when the append-only spine
-        has GROWN since the last scan: a panic APPENDS a record → the file grows → the halt is honored
-        within ~1-2 frames (≤ the rescan floor + one frame, ≈66 ms worst case), not a fixed 0.5 s. A
-        pure-movement gesture appends nothing, so this is
-        O(1) (a `stat`) with NO scan at all. A short `_KS_MIN_RESCAN` floor stops a churning spine from
-        forcing a per-frame O(spine) scan (worst-case latency ≤ the floor). The arm path checks FRESH."""
-        try:
-            size = self.store.path.stat().st_size
-        except OSError:
-            size = self._ks_size
-        if size != self._ks_size and (now - self._ks_checked_at) >= _KS_MIN_RESCAN:
+        verifies the owner-signed release — never re-implemented here) ONLY when the store's ROTATION-AWARE
+        change token has moved since the last scan: a panic APPENDS a record → the token changes → the halt
+        is honored within ~1-2 frames (≈66 ms worst case), not a fixed 0.5 s. A pure-movement gesture
+        appends nothing, so the token is unchanged and this is cheap with NO scan. Using the change token
+        (invariant 9 / A4) rather than `store.path.stat()` is what keeps a panic observable AFTER a
+        migration — a bare size check would raise/freeze once spine.jsonl is renamed away, silently
+        stranding a device-armed session in the un-halted state. A short `_KS_MIN_RESCAN` floor caps a
+        churning spine at per-floor scanning. The arm path checks FRESH."""
+        token = self.store.change_token()
+        if token != self._ks_token and (now - self._ks_checked_at) >= _KS_MIN_RESCAN:
             from ..governor.killswitch import KillSwitch
             self._ks_engaged = KillSwitch(self.store).is_engaged()
-            self._ks_size = size
+            self._ks_token = token
             self._ks_checked_at = now
         return self._ks_engaged
 
diff --git a/sigil/governor/killswitch.py b/sigil/governor/killswitch.py
index bf20da9..1548ecc 100644
--- a/sigil/governor/killswitch.py
+++ b/sigil/governor/killswitch.py
@@ -20,12 +20,14 @@ _CORE = ("signal", "state")
 
 # FIX 4 (audit CRITICAL): `is_engaged()` full-scans the spine on EVERY governor decision, so a batch of
 # proposals is O(proposals × spine). Cache the authoritative verdict keyed by (resolved spine path,
-# trusted pubkey) with the file size it was computed at. An append-only spine only changes by GROWTH,
-# and every engage/release APPENDS a record → the size grows → the cache invalidates and we re-run the
-# real, owner-signed-release-verifying scan. A matching size ⇒ no new records ⇒ the cached verdict is
-# exact (O(1), a single `stat`). Keyed on the pubkey too, so instances with different trust roots (which
-# would verify a signed release differently) never share an entry. Shared across ALL callers on a path.
-_STATE_CACHE: dict[tuple[str, Optional[str]], tuple[int, bool]] = {}
+# trusted pubkey) with the store's ROTATION-AWARE CHANGE TOKEN it was computed at. Every engage/release
+# APPENDS a record → the token changes → the cache invalidates and we re-run the real, owner-signed-
+# release-verifying scan. A matching token ⇒ no new records ⇒ the cached verdict is exact. The token
+# (invariant 9 / A4) keys on the manifest generation + the resolved ACTIVE segment (size, inode), NOT a
+# bare `store.path.stat()` — which would raise/freeze once a migration renames spine.jsonl away and then
+# serve a STALE (un-halting) verdict indefinitely. Keyed on the pubkey too, so instances with different
+# trust roots never share an entry. Shared across ALL callers on a path.
+_STATE_CACHE: dict[tuple[str, Optional[str]], tuple[tuple, bool]] = {}
 _CACHE_GUARD = threading.Lock()
 
 
@@ -48,24 +50,21 @@ class KillSwitch:
         return self.store.append(kind="event", source="governor", actor="WARDEN", payload=payload)
 
     def is_engaged(self) -> bool:
-        """Cheap, correct kill-switch verdict (FIX 4). O(1) `stat` when the spine is unchanged since the
-        last authoritative scan; a grown (or first-seen / shrunk) file re-runs the real scan below and
-        refreshes the shared cache. Semantics are IDENTICAL to a fresh scan — a new engage/release grows
-        the file, so it is always honored on the next call."""
+        """Cheap, correct kill-switch verdict (FIX 4). Cheap when the spine is unchanged since the last
+        authoritative scan (a matching rotation-aware change token); a changed token — a new engage/release
+        record, or a migration/rotation that moved the active segment — re-runs the real scan below and
+        refreshes the shared cache. Semantics are IDENTICAL to a fresh scan, and (unlike a bare file-size
+        check) a migration that renames spine.jsonl away can never freeze the token and serve a stale
+        un-halting verdict."""
         key = (str(Path(self.store.path).resolve()), self.trusted_pubkey)
-        try:
-            size = self.store.path.stat().st_size
-        except OSError:
-            size = -1
-        if size >= 0:
-            with _CACHE_GUARD:
-                cached = _STATE_CACHE.get(key)
-                if cached is not None and cached[0] == size:
-                    return cached[1]
+        token = self.store.change_token()
+        with _CACHE_GUARD:
+            cached = _STATE_CACHE.get(key)
+            if cached is not None and cached[0] == token:
+                return cached[1]
         engaged = self._scan_engaged()
-        if size >= 0:
-            with _CACHE_GUARD:
-                _STATE_CACHE[key] = (size, engaged)
+        with _CACHE_GUARD:
+            _STATE_CACHE[key] = (token, engaged)
         return engaged
 
     def _scan_engaged(self) -> bool:
diff --git a/sigil/spine/manifest.py b/sigil/spine/manifest.py
new file mode 100644
index 0000000..e0883b3
--- /dev/null
+++ b/sigil/spine/manifest.py
@@ -0,0 +1,151 @@
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
+from pathlib import PurePosixPath, Path
+
+from pydantic import BaseModel, ConfigDict, Field, field_validator
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
+    @field_validator("file")
+    @classmethod
+    def _file_is_contained_relative(cls, v: str) -> str:
+        """A segment `file` must be a plain relative path under the spine dir — never absolute and never
+        `..`-escaping. `get()`/`iter_records()`/`tail()` open segment files WITHOUT running verify(), so a
+        doctored manifest pointing `file` at `/etc/passwd` or `../../secret` would otherwise surface that
+        file's bytes AS spine records. Reject it at the model boundary so the read path stays fail-closed
+        even though the manifest itself is unsigned."""
+        pp = PurePosixPath(v)
+        if not v or pp.is_absolute() or PurePosixPath(v.replace("\\", "/")).is_absolute() or ".." in pp.parts:
+            raise ValueError(f"segment file must be a contained relative path, got {v!r}")
+        return v
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
+    """The on-disk layout derived from a spine data-file path (…/spine.jsonl). Every artifact is
+    NAMESPACED BY THE DATA FILE'S STEM (`spine.manifest.json`, `spine.lock`, `spine.segments/`) so two
+    stores whose data files merely SHARE a directory — e.g. the `tempfile.mktemp()` idiom that drops files
+    straight into /tmp — never collide on a manifest/lock/segments set. Without this, one migrated store's
+    `manifest.json` would be read by every other store in that directory and silently steer it onto the
+    wrong segment (a real cross-store contamination the review caught)."""
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
+        ns = p.stem or p.name       # "spine.jsonl" -> "spine"; namespaces every derived artifact
+        return cls(
+            data_path=p, spine_dir=d, segments_dir=d / f"{ns}.segments",
+            manifest_path=d / f"{ns}.manifest.json", lockfile_path=d / f"{ns}.lock", trash_dir=d / f"{ns}.trash",
+        )
+
+    def seg_path(self, seg: Segment) -> Path:
+        """Absolute path of a segment's file (its `file` is stored relative to the spine dir). The
+        `Segment.file` validator guarantees it is a plain relative path that cannot escape spine_dir."""
+        return self.spine_dir / seg.file
+
+    def segment_rel(self, seg_id: int, codec: str = "none") -> str:
+        """The manifest `file` value (relative to spine_dir) for a segment id — under the namespaced
+        segments dir, e.g. 'spine.segments/seg-00000000.jsonl'."""
+        return f"{self.segments_dir.name}/{segment_filename(seg_id, codec)}"
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
index 0ce9a79..2b8af2a 100644
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
@@ -26,6 +36,13 @@ except ImportError:  # pragma: no cover — non-POSIX
 
 _log = logging.getLogger(__name__)
 
+
+class SpineError(Exception):
+    """A structural spine fault — a corrupt/degenerate manifest or a manifest-referenced segment that
+    cannot be read. Raised so the caller fails CLOSED rather than silently reading a truncated/empty
+    chain (invariant 15: a state-scanner must never fail open)."""
+
+
 # The record fields SpineRecord.from_dict needs; a line missing any of these is corrupt (skipped by
 # reads, so a mid-file gap still surfaces via verify()).
 _REQUIRED_KEYS = ("seq", "scope", "kind", "source", "actor", "cert_digest", "prev_hash", "entry_hash")
@@ -123,13 +140,27 @@ def _last_valid_boundary(path: Path) -> "tuple[int, ChainEntry | None]":
 
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
@@ -137,6 +168,172 @@ class SpineStore:
         self._scan_pos = 0                          # byte offset just past the last COMPLETE line indexed
         self._last: ChainEntry | None = self._read_last_entry()
 
+    # --- segment layout / manifest ------------------------------------------------
+    def _resolve_active_path(self) -> Path:
+        """The current append/read target. With a manifest, the active segment's absolute path; without
+        one (a fresh or not-yet-migrated legacy spine), the legacy single file in place — byte-identical
+        to the pre-rotation store, so nothing destructive happens until an explicit `migrate()`. A manifest
+        that exists but names NO active segment is a corrupt/degenerate state and RAISES rather than
+        silently falling back to `spine.jsonl` (which would resurrect a data file OUTSIDE the segment set —
+        a fork; the guard also removes the same landmine for Slice-3 sealing, which must always leave an
+        active segment)."""
+        if self._manifest is not None:
+            act = self._manifest.active()
+            if act is None:
+                raise SpineError("manifest has no active segment (corrupt/degenerate) — refusing to "
+                                 "resurrect spine.jsonl outside the segment set")
+            return self._layout.seg_path(act)
+        return self.path
+
+    def _read_target(self) -> Path:
+        """The file to read for THIS operation. Normally the cached active segment; if it has VANISHED (a
+        migrate()/rotation in another process renamed it away), resolve the current active from the
+        manifest for this read only — WITHOUT mutating shared state (lock-free reads must not race
+        append's active update). Prevents a false-EMPTY read during the migrate instant, which for the
+        nonce-highwater scan would regress the replay floor. In Slice 0 the only mover is migrate(), which
+        RENAMES (byte-preserving), so the current index offsets stay valid for the resolved file. Fully
+        epoch-invalidated, segment-spanning reads land in Slice 1."""
+        a = self._active
+        if a.exists():
+            return a
+        m = read_manifest(self._layout)
+        act = m.active() if m is not None else None
+        if act is not None:
+            r = self._layout.seg_path(act)
+            if r.exists():
+                return r
+        return a
+
+    @contextmanager
+    def _crossproc_lock(self) -> "Iterator[None]":
+        """Cross-process exclusion on the inode-stable lockfile (invariant 14 / D3). flock binds to the
+        open file DESCRIPTION, not the path, so an os.replace of the manifest/segments cannot move the
+        lock out from under a concurrent writer — which the prior flock-on-the-data-fd could not survive.
+        Best-effort exactly as before (fcntl absent on non-POSIX; a flock failure is swallowed). NOT
+        re-entrant across fds — never nest a second `_crossproc_lock` inside one (a second LOCK_EX on the
+        same file from a different fd self-deadlocks); the seal-swap that runs inside append reuses the
+        already-held lock rather than re-acquiring."""
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
+    def _complete_orphan_migration_locked(self) -> bool:
+        """MUST hold `_crossproc_lock`, and be called only when the manifest is currently ABSENT. If we are
+        in the migrate() crash window — seg-0 present, `spine.jsonl` gone (the rename is atomic + durable),
+        no manifest — finish the interrupted migration by publishing the manifest. Returns True iff it
+        completed one. Called from BOTH __init__'s reconciler AND append's `_refresh_active_under_lock`, so
+        a LIVE appender completes the orphan under the lock instead of re-creating `spine.jsonl` and forking
+        the log (the critical review finding)."""
+        seg0 = self._layout.segments_dir / segment_filename(0)
+        if seg0.exists() and not self.path.exists():
+            write_manifest(self._layout, initial_manifest(SCOPE, active_file=self._layout.segment_rel(0)))
+            _log.warning("spine: completed an interrupted migration — published the manifest for %s", seg0)
+            return True
+        return False
+
+    def _refresh_active_under_lock(self) -> None:
+        """MUST hold `_crossproc_lock`. FIRST complete any interrupted migration (so a live appender never
+        resurrects `spine.jsonl`), THEN re-resolve the active segment from the manifest so an appender
+        constructed before a concurrent migrate()/rotation writes to the CURRENT target — never a stale
+        path (fork) or a renamed-away file (resurrection). One manifest read in the steady state."""
+        m = read_manifest(self._layout)
+        if m is None and self._complete_orphan_migration_locked():
+            m = read_manifest(self._layout)
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
+        """Drops the single-segment index so the next read rebuilds it against the (possibly changed)
+        active segment."""
+        with self._index_lock:
+            self._index_built = False
+            self._offsets = {}
+            self._max_seq = -1
+            self._scan_pos = 0
+
+    def _reconcile_orphan_migration(self) -> None:
+        """Close the migrate() crash window at CONSTRUCTION. migrate() does an ATOMIC
+        `os.replace(spine.jsonl → segments/seg-00000000.jsonl)` and THEN publishes the manifest; a crash
+        BETWEEN them leaves seg-0 present, `spine.jsonl` gone, and no manifest — at which point the legacy
+        fallback (active = spine.jsonl) would read the spine as EMPTY and silently hide all history. If we
+        observe exactly that state, finish the (already-durable) migration under the lock. (A live appender
+        does the same via `_refresh_active_under_lock`; a construction-time pass just recovers faster.)"""
+        if self._manifest is not None:
+            return
+        seg0 = self._layout.segments_dir / segment_filename(0)
+        if not (seg0.exists() and not self.path.exists()):
+            return
+        with self._crossproc_lock():
+            if read_manifest(self._layout) is None:          # re-check under the lock
+                self._complete_orphan_migration_locked()
+            self._manifest = read_manifest(self._layout)
+
+    def change_token(self) -> tuple:
+        """A cheap, rotation-aware epoch token — (manifest generation, active file, size, inode) — that
+        changes on ANY append (size), a migration/rotation (generation + active path/inode), or a reset.
+        THE unified replacement for the size-only 'has the spine changed?' heuristic at every site
+        (invariant 9 / A4) — notably the kill-switch verdict caches in `governor/killswitch.py` and
+        `gesture/session.py`. Because it reads the manifest FRESH and keys on the resolved active segment
+        (not the legacy `store.path`, which a migration renames away), a same-size rotation — or a
+        migration performed by another process — can never serve a stale (un-halting) kill-switch verdict."""
+        m = read_manifest(self._layout)
+        gen = m.generation if m is not None else -1
+        active = self.path
+        act = m.active() if m is not None else None
+        if act is not None:
+            active = self._layout.seg_path(act)
+        try:
+            st = active.stat()
+            return (gen, str(active), st.st_size, st.st_ino)
+        except OSError:
+            return (gen, str(active), -1, -1)
+
+    def migrate(self) -> bool:
+        """Move a legacy single-file spine into the segment layout: rename `spine.jsonl` →
+        `<stem>.segments/seg-00000000.jsonl` (atomic, same filesystem — O(1), no byte copy) and publish a
+        single-active-segment manifest. Idempotent (a no-op once a manifest exists). Returns True iff it
+        migrated. SPLIT-BRAIN SAFETY: run this only after every spine writer is on code that flocks the
+        path-stable lockfile (this Slice-0 code) and re-resolves the active segment under that lock — a
+        stale appender then completes/observes the migration instead of resurrecting `spine.jsonl`. After
+        migration `spine.jsonl` is absent and is NEVER re-created as a data file (all data I/O targets the
+        active segment)."""
+        with spine_lock(self.path):
+            with self._crossproc_lock():
+                if read_manifest(self._layout) is not None:
+                    self._refresh_active_under_lock()
+                    return False
+                self._layout.segments_dir.mkdir(parents=True, exist_ok=True)
+                seg0_abs = self._layout.segments_dir / segment_filename(0)
+                if self.path.exists():
+                    os.replace(self.path, seg0_abs)         # atomic rename (same fs); O(1), no copy
+                    fsync_dir(self._layout.spine_dir)       # persist the SOURCE-dir unlink of spine.jsonl
+                else:
+                    seg0_abs.touch()                        # fresh spine: create the empty active segment
+                fsync_dir(self._layout.segments_dir)        # persist the TARGET-dir creation of seg-0
+                write_manifest(self._layout, initial_manifest(SCOPE, active_file=self._layout.segment_rel(0)))
+                self._manifest = read_manifest(self._layout)
+                self._active = self._resolve_active_path()
+                self._invalidate_index()
+                self._last = self._read_last_entry()
+                return True
+
     # --- write --------------------------------------------------------------------
     def append(
         self, *, kind: str, source: str, actor: str, payload: dict[str, Any],
@@ -149,48 +346,48 @@ class SpineStore:
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
@@ -200,10 +397,11 @@ class SpineStore:
         at byte 0 exactly as before. FIX 2: a line that fails to parse or lacks required keys is SKIPPED
         (a torn tail no longer crashes the read); a torn MIDDLE line becomes a seq gap that verify() fails
         on, so mid-file tampering is never silently hidden."""
-        if not self.path.exists():
+        target = self._read_target()
+        if not target.exists():
             return
         start_off = self._start_offset_for(since_seq)
-        with self.path.open("rb") as f:
+        with target.open("rb") as f:
             if start_off:
                 f.seek(start_off)
             for raw in f:
@@ -212,20 +410,20 @@ class SpineStore:
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
+        if seq < 0 or not self._read_target().exists():
             return None
         self._ensure_index()
         with self._index_lock:
             off = self._offsets.get(seq)
         if off is not None:
-            with self.path.open("rb") as f:
+            with self._read_target().open("rb") as f:
                 f.seek(off)
                 raw = f.readline()
             try:
@@ -248,9 +446,10 @@ class SpineStore:
         distinct bodies larger than the window each ages out and re-records. Only pair `tail()`-based
         dedup with a record-time freshness gate (or an independent bound); do not rely on it alone to
         close a bloat sink."""
-        if n <= 0 or not self.path.exists():
+        target = self._read_target()
+        if n <= 0 or not target.exists():
             return []
-        with self.path.open("rb") as f:
+        with target.open("rb") as f:
             f.seek(0, os.SEEK_END)
             pos = f.tell()
             buf = b""
@@ -305,7 +504,8 @@ class SpineStore:
     def _read_last_entry(self) -> ChainEntry | None:
         # `_last_nonempty_line` skips a torn/garbage tail and returns the last VALID line (FIX 2), so a
         # crash mid-write can no longer block a restart. The returned line is guaranteed parseable.
-        line = _last_nonempty_line(self.path) if self.path.exists() else None
+        target = self._read_target()
+        line = _last_nonempty_line(target) if target.exists() else None
         if not line:
             return None
         d = json.loads(line)
@@ -331,8 +531,9 @@ class SpineStore:
         """Build the index lazily (one unavoidable scan) and keep it current. Detects a file that GREW
         (our own or another PROCESS's appends — append-only ⇒ offsets never move, so we only EXTEND) and
         a file that SHRANK / was rewritten in place smaller (rebuild). Thread-safe under `_index_lock`."""
+        target = self._read_target()
         try:
-            size = self.path.stat().st_size if self.path.exists() else 0
+            size = target.stat().st_size if target.exists() else 0
         except OSError:
             return
         with self._index_lock:
@@ -356,7 +557,7 @@ class SpineStore:
         surfaces via verify()); a trailing partial line (no newline yet) is left for the next extend."""
         if size <= start:
             return
-        with self.path.open("rb") as f:
+        with self._read_target().open("rb") as f:
             f.seek(start)
             chunk = f.read(size - start)
         consumed = 0
