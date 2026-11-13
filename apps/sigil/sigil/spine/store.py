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

from ..config import (SCOPE, SPINE_GROUP_COMMIT_COALESCE, SPINE_PATH, SPINE_SEG_MAX_BYTES,
                      SPINE_SEG_MAX_RECORDS)
from ..reuse import ChainEntry, append_entry, build_chain, canonical_json, digest_payload, verify_chain
from vigil_core.models import _GENESIS_PREV       # defined in vigil_core (the reuse.* shims are runtime-only)
from . import envelope
from .atomicio import atomic_write_text, fsync_dir
from .manifest import (
    SEGMENT_STEM,
    Manifest,
    Segment,
    SpineLayout,
    initial_manifest,
    read_manifest,
    segment_filename,
    write_manifest,
)
from .models import KINDS, KNOWN_SCHEMA_VERSIONS, SCHEMA_VERSION, SpineRecord, now_iso

try:
    import fcntl  # POSIX advisory file lock — cross-PROCESS append serialization
except ImportError:  # pragma: no cover — non-POSIX
    fcntl = None  # type: ignore[assignment]

_log = logging.getLogger(__name__)

_UNSET = object()   # sentinel: the spine-payload DEK has not been loaded yet (distinct from a cached None)

# C-1 reader grace: how many times a lock-free read re-resolves the segment set when a concurrent
# compaction/rotation supersedes the manifest under it. Each swap advances the generation exactly once and
# a reader only ever loses a race to a swap that already COMMITTED, so a handful of attempts absorbs real
# churn; the bound is what keeps a pathological writer from livelocking a reader into a hang (it surfaces
# as a loud SpineError instead). Genuine loss is ALWAYS fail-closed: a segment missing at a STABLE (non-
# forward) generation raises at once ("references a missing segment"); under a writer that is concurrently
# advancing the generation, real loss instead surfaces as the bounded "kept changing" SpineError — still a
# loud raise, never a short chain (invariant 15).
_SEG_RESOLVE_ATTEMPTS = 6


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

# Default look-back window (in records) for opt-in content de-duplication on append. Bounded so dedup is
# O(window) per append, never O(spine); a caller may override per-append via `dedup_window`.
_DEDUP_WINDOW = 256

# SCALE-C1b (commit-coalescing group commit). The max number of INDEPENDENT concurrent appends one
# group-commit leader coalesces into a SINGLE append_many() batch (one fsync). Large enough to amortize the
# fsync hard under 1M-scale load, bounded so one group can never buffer an unbounded write. Latecomers
# beyond the cap simply form the NEXT group, led by the next head after notify_all — so the cap bounds a
# group's size without ever dropping an append.
_GROUP_COMMIT_MAX = 1024


def _maybe_crash(name: str) -> None:
    """Invoke the installed test fault-injection hook (if any) at a named cutover barrier. No-op in
    production (`_crash_hook is None`)."""
    if _crash_hook is not None:
        _crash_hook(name)


# The record fields SpineRecord.from_dict needs; a line missing any of these is corrupt (skipped by
# reads, so a mid-file gap still surfaces via verify()).
_REQUIRED_KEYS = ("seq", "scope", "kind", "source", "actor", "cert_digest", "prev_hash", "entry_hash")
_STR_KEYS = ("scope", "kind", "source", "actor", "cert_digest", "prev_hash", "entry_hash")


def _record_dict(raw: "bytes | str") -> "dict | None":
    """The ONE rule for what a spine line is — every reader, the tip finders and the append check apply it: a JSON
    object carrying every chain field, with an integer seq, string fields, a string ts and integer
    schema_version / parent_id / supersedes_id (the shape `append` writes). Anything else is skipped as malformed,
    never yielded as a record (a mid-file one then surfaces as a gap in verify()).

    The payload's shape is NOT part of this rule. A complete, chained line whose payload is not a JSON object is a
    record: every reader yields it, the chain continues from it, and each consumer that folds it fails closed on it
    (a capability gate answers disabled, the kill switch raises, a cached view poisons)."""
    try:
        d = json.loads(raw)
    except ValueError:                                   # incl. UnicodeDecodeError
        return None
    if not isinstance(d, dict) or not all(k in d for k in _REQUIRED_KEYS):
        return None
    if type(d["seq"]) is not int or not all(isinstance(d[k], str) for k in _STR_KEYS):
        return None
    if not isinstance(d.get("ts", ""), str):
        return None
    if any(d.get(k) is not None and type(d.get(k)) is not int for k in ("schema_version", "parent_id",
                                                                        "supersedes_id")):
        return None
    return d


def _parse_record(raw: "bytes | str") -> "SpineRecord | None":
    d = _record_dict(raw)
    return SpineRecord.from_dict(d) if d is not None else None

# The append path's monotonic-tail check progress per active segment, shared by every store in this process (the
# cockpit and bridge open a fresh store per request): resolved path -> ((st_dev, st_ino), bytes checked, highest seq
# in them, entry_hash of the last record in them). Read and written only under that path's `spine_lock` + flock.
_TAIL_CHECKED: "dict[str, tuple]" = {}


def _lines_between(path: Path, start: int, end: int, *, chunk: int = 1 << 20) -> "Iterator[bytes]":
    """The complete lines of `path` in the byte range [start, end) — `end` is a line boundary — read in bounded
    chunks (never the whole range into memory at once)."""
    with path.open("rb") as f:
        f.seek(start)
        left, carry = end - start, b""
        while left > 0:
            buf = f.read(min(chunk, left))
            if not buf:
                break
            left -= len(buf)
            parts = (carry + buf).split(b"\n")
            carry = parts.pop()
            for ln in parts:
                if ln.strip():
                    yield ln
        if carry.strip():
            yield carry


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
            if _record_dict(raw) is not None:
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
            d = _record_dict(raw)
            if d is not None:
                return end, ChainEntry(seq=d["seq"], prev_hash=d["prev_hash"],
                                       cert_digest=d["cert_digest"], entry_hash=d["entry_hash"])
            _log.warning("spine: skipping malformed tail segment while seeking the tip (%s)", path)
        if start == 0:
            return 0, None
        window *= 4


def _segment_run_break(m: Manifest) -> "str | None":
    """Why the manifest's segments are NOT one contiguous run, or None. Every segment but the last is sealed; at
    most one is unsealed; each next segment starts at the seq after the previous one's last and links from its
    boundary. A manifest that omits (or duplicates, or overlaps) a segment would otherwise make every reader
    yield a short chain."""
    if sum(1 for s in m.segments if not s.sealed) > 1:
        return "more than one unsealed segment"
    if len({s.file for s in m.segments}) != len(m.segments):
        return "two segments name the same file"
    segs = m.ordered()
    for a, b in zip(segs, segs[1:]):
        if not a.sealed or a.last_seq is None:
            return f"segment {a.id} is not sealed but segment {b.id} follows it"
        if b.first_seq != a.last_seq + 1 or b.first_prev_hash != a.boundary_hash:
            return (f"segment {b.id} (first seq {b.first_seq}) does not continue segment {a.id} "
                    f"(last seq {a.last_seq})")
    return None


class SpineOrderError(SpineError):
    """A record line whose seq does not exceed the previous line's (a duplicated or reordered line)."""


class _Waiter:
    """One queued append awaiting a group commit (SCALE-C1b). Guarded ENTIRELY by the owning store's
    `_commit_cv`: `spec` is set at construction (immutable thereafter); `seq`/`error`/`done` are written only
    by the elected leader under `_commit_cv` and read by this waiter's own thread only once it observes
    `done` True (the happens-before the Condition provides). A leader is also a `_Waiter` (its own append is
    in the batch), so the leader's result is published to itself through exactly this struct."""
    __slots__ = ("spec", "seq", "error", "done")

    def __init__(self, spec: "dict[str, Any]") -> None:
        self.spec: "dict[str, Any]" = spec
        self.seq: "int | None" = None
        self.error: "BaseException | None" = None
        self.done: bool = False


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
        # spine-payload DEK (G1 slice-4), loaded lazily on the first content append / decrypted read.
        # `_UNSET` until first use; then the 32-byte DEK, or None when the vault is not provisioned
        # (opt-in passthrough → plaintext, byte-identical to today).
        self._dek_cache: Any = _UNSET
        # SCALE-C1b (commit-coalescing group commit, DEFAULT-OFF). A commit-coalescing FRONT-END that sits IN
        # FRONT OF spine_lock: independent concurrent append() calls are gathered into one group whose actual
        # write is delegated to the UNCHANGED append_many() on a single LEADER thread — one fsync per group.
        # These three fields are guarded ENTIRELY by `_commit_cv`, a SEPARATE, NON-reentrant lock that is
        # NEVER spine_lock (the leader still takes spine_lock + flock FRESH inside append_many, on its own
        # thread, holding neither this cv nor spine_lock while it writes). Flag OFF ⇒ the queue is never
        # touched and append() is byte-identical to today.
        self._group_commit_coalesce: bool = bool(SPINE_GROUP_COMMIT_COALESCE)
        self._commit_cv = threading.Condition(threading.Lock())
        self._commit_queue: "list[_Waiter]" = []
        self._leader_inflight: bool = False

    # --- payload field encryption (G1 slice-4) ------------------------------------
    def _spine_dek(self, *, create: bool) -> "bytes | None":
        """The cached spine-payload DEK. None when the vault is not enabled (payloads stay plaintext).
        `create=True` (write path, content records only) mints it once; `create=False` (read path) never
        mints. A locked vault raises `VaultLocked` (fail-closed) — reached only for a content-bearing
        record, so a pure-metadata / signal append (which never encrypts) is never blocked."""
        if self._dek_cache is _UNSET or self._dek_cache is None:
            # re-resolve while None so a vault provisioned mid-process, or a DEK minted by a prior write,
            # is picked up; a real DEK is cached and never re-read (no per-append TPM unseal).
            from ..platform.vault import owner_vault
            self._dek_cache = envelope.load_or_create_dek(owner_vault(), create=create)
        return self._dek_cache

    def decrypted(self, r: SpineRecord) -> SpineRecord:
        """Return `r` with its sealed CONTENT FIELDS decrypted — the read PROJECTION for content consumers
        (search / index / graph / consolidate / display). A record with no sealed field passes through
        unchanged. A sealed field that cannot be opened raises `SpinePayloadLocked` / `VaultLocked`
        (fail-closed); the KEYLESS integrity path (`iter_records`/`verify`/`entries`) never calls this — it
        reads the stored (ciphertext) form, so the chain verifies without the DEK."""
        import dataclasses
        plain = envelope.open_payload(self._spine_dek(create=False), r.payload, scope=r.scope, seq=r.seq)
        return r if plain is r.payload else dataclasses.replace(r, payload=plain)

    def decrypted_or_raw(self, r: SpineRecord) -> SpineRecord:
        """`decrypted(r)` for a DISPLAY path that must not raise: on a locked / unopenable vault it returns
        the RAW (sealed) record so the feed degrades to ciphertext rather than crashing. FUNCTIONAL
        readers (search/index/graph/consolidate/recall) use `decrypted()` instead — they MUST fail closed,
        never process ciphertext."""
        try:
            return self.decrypted(r)
        except Exception:  # noqa: BLE001 — locked/unopenable vault → show the sealed form (display only)
            return r

    # --- content de-duplication (opt-in; NEVER touches the chain) ------------------
    @staticmethod
    def _content_key(kind: str, source: str, actor: str, payload: dict[str, Any],
                     parent_id: int | None, supersedes_id: int | None) -> str:
        """A digest over the PLAINTEXT content a record carries — the identity two records share iff they
        are the same event. Deliberately over the plaintext payload, NOT the stored `cert_digest`: a
        content-bearing payload is sealed with a seq-bound AEAD, so the stored digest differs per seq even
        for identical plaintext; keying dedup on `cert_digest` would therefore never dedup real content.
        `ts`/`seq`/`schema_version` are excluded (informational), so a genuine re-emit of the same event
        keys identically regardless of when it arrives."""
        return digest_payload({"scope": SCOPE, "kind": kind, "source": source, "actor": actor,
                               "payload": payload, "parent_id": parent_id, "supersedes_id": supersedes_id})

    def _find_dedup(self, kind: str, source: str, actor: str, payload: dict[str, Any],
                    parent_id: int | None, supersedes_id: int | None, *, window: int) -> int | None:
        """MUST hold the append lock (the tip is authoritative). Return the seq of an EXISTING record within
        the last `window` records whose plaintext content is byte-identical to this candidate, or None.

        Bounded + fail-safe: a record whose sealed content cannot be decrypted (locked vault) is SKIPPED, not
        matched — so dedup never mistakes ciphertext for a match and never suppresses a real append it could
        not verify as a duplicate. Scans newest→oldest so the NEAREST duplicate wins (the smallest chain
        rewind); reads only, so it can never alter or gap the chain."""
        if window <= 0 or self._last is None:
            return None
        key = self._content_key(kind, source, actor, payload, parent_id, supersedes_id)
        tip = self._last.seq
        recent = [r for r in self.iter_records(since_seq=max(-1, tip - window))]
        for r in reversed(recent):                       # newest first — the nearest duplicate
            try:
                rr = self.decrypted(r)                   # fail-closed: an unopenable record is NOT a match
                rkey = self._content_key(rr.kind, rr.source, rr.actor, rr.payload, rr.parent_id, rr.supersedes_id)
            except Exception:  # noqa: BLE001 — locked/corrupt/non-canonical content ⇒ skip (no false dedup)
                continue
            if rkey == key:
                return r.seq
        return None

    # --- segment layout / manifest ------------------------------------------------
    @staticmethod
    def _segment_id_of(name: str) -> "int | None":
        """The numeric segment id embedded in a `seg-NNNNNNNN.jsonl[.gz]` filename, or None if `name` is
        not a segment file. Used as the ON-DISK evidence discriminator, so it is deliberately strict about
        the shape rotation/migration actually writes (`segment_filename`)."""
        if not name.startswith(SEGMENT_STEM):
            return None
        if not (name.endswith(".jsonl") or name.endswith(".jsonl.gz")):
            return None
        digits = name[len(SEGMENT_STEM):].split(".", 1)[0]
        return int(digits) if digits.isdigit() else None

    def _segment_files(self) -> list[Path]:
        """Every on-disk segment artifact (`<stem>.segments/seg-*.jsonl[.gz]`) in name order — the READER'S
        physical evidence that this spine was ever segmented, independent of the (removable) manifest.
        Empty for a genuine legacy (pre-migrate) single-file spine, which has no segments dir at all."""
        d = self._layout.segments_dir
        if not d.exists():
            return []
        return sorted(p for p in d.iterdir() if p.is_file() and self._segment_id_of(p.name) is not None)

    def _guard_manifest_absent_segmented(self) -> None:
        """Invariant-15 read guard for the manifest-ABSENT case. A missing manifest is legitimate on a
        genuine legacy (pre-migrate) single-file spine (no segment artifacts at all) AND on the single-seg-0
        window (a fresh migrate() that renamed spine.jsonl → seg-0 but has not published the manifest yet, or
        an un-migrated store constructed before that rename): in every seg-0-ONLY case, seg-0 IS the complete
        chain, so reading it is correct, not a short read.

        A ROTATION is the ONLY thing that ever creates a non-genesis segment (`seg-1`+): it seals seg-k and
        ALWAYS publishes the new-generation manifest as the same atomic commit. So a `seg-1`+ file present on
        disk with the manifest ABSENT is unambiguous ON-DISK evidence of a manifest-REMOVED SEGMENTED spine —
        reading the legacy single file (or a lone genesis-rooted survivor) would drop the sealed tail: a
        SILENT SHORT CHAIN that even verify() cannot catch (the fail-OPEN invariant 15 forbids). Fail CLOSED.
        This does NOT repair, recreate or resurrect anything (READ-PATH ONLY) — it refuses to read an
        ambiguous/lossy state. (Detecting a lone-seg-0 that was ITSELF truncated from a larger spine — segment
        files deleted too — needs the durable signed anchor tracked in W10-4/W16-11, and is out of scope here:
        with no manifest and no seg-1+, there is no on-disk evidence a tail ever existed.)

        The orphan reconciler (`_complete_orphan_migration_locked`) mirrors this exactly: it completes a
        seg-0-ONLY interrupted migration but REFUSES to auto-publish when seg-1+ exists, so the multi-segment
        manifest-removed spine is left manifest-absent for this guard to fail closed on."""
        rotated = [p for p in self._segment_files() if (self._segment_id_of(p.name) or 0) > 0]
        if rotated:
            names = ", ".join(p.name for p in rotated[:4]) + (" …" if len(rotated) > 4 else "")
            raise SpineError(
                "spine manifest is absent but a sealed (non-genesis) segment artifact exists on disk "
                f"({len(rotated)} file(s): {names}) — this is a manifest-REMOVED SEGMENTED spine, not a "
                "legacy single-file spine; refusing to read a silent short chain (invariant 15: no "
                "state-scanner fail-open)")

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

    def _manifest_generation(self) -> int:
        """The manifest generation ON DISK RIGHT NOW (-1 when there is no manifest). Every manifest swap —
        migrate, seal/rotate, compaction's codec flip — publishes atomically with `generation + 1`, so this
        single monotonic token is what lets the read path tell a BENIGN SUPERSESSION (someone committed a
        new segment set under us) apart from REAL CORRUPTION (a segment the current set still names is
        gone). Cheap: one small atomic-written JSON read."""
        m = read_manifest(self._layout)
        return m.generation if m is not None else -1

    def _segments_in_order(self) -> list[Path]:
        """`_resolve_segments()` without the generation — for callers that only need the paths."""
        return self._resolve_segments()[1]

    def _resolve_segments(self) -> tuple[int, list[Path]]:
        """(manifest generation, the segment files to read in seq order — sealed by first_seq, then the
        active tail). With no manifest this is the single legacy/active file at generation -1 (FIRST attempt
        only — see below). Resolved fresh each call so a rotation/migration by another process is seen.

        C-1 (reader vs. compaction TOCTOU). Resolution is inherently two steps — read the manifest, then
        touch the files it names — and compaction's ordering is already the safe one: `_compress_one_sealed`
        COMMITS the new-generation manifest (codec flipped to gzip, `file` -> seg-N.jsonl.gz) BEFORE
        `_remove_superseded_plaintext` unlinks the plaintext it superseded. So a reader can only ever find a
        file missing because its OWN SNAPSHOT is stale — the current manifest no longer references that
        file. That is distinguishable from real loss, and the discriminator is a STRICTLY-FORWARD generation
        move (each swap does exactly `generation + 1`; nothing ever moves it backward). RE-READ the manifest:
          * generation moved STRICTLY FORWARD (`> gen`) -> our snapshot was superseded; re-resolve against
            the new manifest (bounded attempts, so churn can never livelock us into a hang);
          * generation NOT strictly forward (unchanged, regressed, or the manifest VANISHED to -1) -> this is
            NOT a benign supersession; the live segment set genuinely references a file that is gone. RAISE —
            a read must never silently yield a short chain (invariant 15: no state-scanner fail-open).
        The no-manifest branch is therefore FIRST-ATTEMPT-ONLY: a legacy (pre-migrate) spine legitimately has
        no manifest, but a manifest that DISAPPEARS mid-resolve (reset()/an in-flight migrate that has not yet
        republished) went from `gen >= 0` to -1 — not a forward move — so falling back to the legacy single
        file there would be exactly the silent short chain invariant 15 forbids.
        This keeps the fail-closed guarantee exactly as strict as before for every real integrity failure
        while making the benign compaction window a retry instead of an error."""
        missing, gen = "", -1
        for attempt in range(_SEG_RESOLVE_ATTEMPTS):
            m = read_manifest(self._layout)
            if m is None:
                if attempt == 0:
                    # A missing manifest is a LEGACY single-file spine ONLY when no segment artifacts exist
                    # on disk. Segment files + no manifest == a manifest-REMOVED segmented spine → fail
                    # CLOSED (invariant 15) rather than read the legacy file as a silent short chain.
                    self._guard_manifest_absent_segmented()
                    t = self._read_target()              # legacy (pre-manifest) spine: the single file
                    return (-1, [t] if t.exists() else [])
                # We STARTED this resolve holding a manifest (gen >= 0) and it has since VANISHED: the
                # generation went to -1, which is NOT a strictly-forward move. Falling back to the legacy
                # single file here would yield a SHORT chain (invariant 15). RAISE.
                raise SpineError("spine manifest disappeared while resolving segments")
            gen, missing = m.generation, ""
            brk = _segment_run_break(m)
            if brk is not None:                          # an omitted/overlapping segment = a short chain
                raise SpineError(f"spine manifest (generation {gen}) is not a contiguous segment run: {brk}")
            out: list[Path] = []
            for seg in m.ordered():
                p = self._layout.seg_path(seg)
                if not p.exists():
                    missing = seg.file
                    break
                out.append(p)
            if not missing:
                return (gen, out)
            if self._manifest_generation() > gen:        # STRICTLY FORWARD -> superseded; re-resolve
                _log.debug("spine: manifest superseded while resolving segments (was generation %d); "
                           "re-resolving", gen)
                continue
            raise SpineError(                            # not a forward move -> a genuine integrity failure
                f"spine manifest (generation {gen}) references a missing segment: {missing}")
        raise SpineError(
            f"spine manifest kept changing while resolving segments (compaction churn) — giving up; last "
            f"unresolved segment {missing!r} at generation {gen}")

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
                if entry.seq != act.first_seq - 1 or entry.entry_hash != act.first_prev_hash:
                    raise SpineError(
                        f"the sealed segment before the active one ends at seq {entry.seq}, not at the boundary the "
                        f"manifest records (seq {act.first_seq - 1}) — refusing to chain a new record from it; run "
                        f"`sigil verify`")
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
            # An INTERRUPTED single-file migration leaves EXACTLY seg-0 (migrate renames spine.jsonl →
            # seg-0, then publishes the manifest — it never creates seg-1+ before the manifest). If any
            # OTHER segment file is present, this is NOT a migrate crash but a manifest-REMOVED MULTI-segment
            # spine; auto-publishing a seg-0-only manifest here would silently drop the sealed tail (the very
            # short-chain fail-open of #552). Refuse to complete — leave the manifest absent so the READ path
            # (_guard_manifest_absent_segmented) fails CLOSED on a full-chain read. NO auto-repair.
            rotated = [p for p in self._segment_files() if (self._segment_id_of(p.name) or 0) > 0]
            if rotated:
                _log.warning("spine: manifest absent with %d sealed (non-genesis) segment file(s) (%s) — NOT "
                             "an interrupted migration; refusing to auto-publish a short manifest",
                             len(rotated), rotated[0].name)
                return False
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
        if m is not None:                           # the write path refuses a broken run exactly as the readers do
            brk = _segment_run_break(m)
            if brk is not None:
                raise SpineError(f"spine manifest (generation {m.generation}) is not a contiguous segment run: {brk}")
        if m is None:
            # WRITE path fails CLOSED too (mirrors the read guard): if a seg-1+ artifact exists with no
            # manifest, this is a manifest-REMOVED SEGMENTED spine — never fall back to (resurrect)
            # spine.jsonl over it. A legacy single-file spine / lone seg-0 has no seg-1+ so this is a no-op.
            self._guard_manifest_absent_segmented()
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
        # The sealed boundary becomes the seam the next segment chains from: never seal a tail an append refuses.
        self._check_monotonic_tail_locked(ap, clean_end, boundary)
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

    # --- cold-archive hard-prune cutover (Slice E — the ONLY code that drops live records) --------------
    def _committed_prune_base_seq(self) -> int:
        """The prune boundary the on-disk OWNER-SIGNED head has COMMITTED (0 == no prune). A missing /
        unreadable / unverified head returns 0, so the destructive primitives below fail CLOSED. This is the
        internal authorization the drop primitives assert: a live-record drop is authorized ONLY by a valid
        owner signature that already committed the prune (which `commit_prune` mints via `sign_pruned_head`
        after its three gates). Read-only."""
        from ..config import HEAD_PATH
        from ..reuse import SignedChainHead
        from .checkpoint import verify_checkpoint
        try:
            if not HEAD_PATH.exists():
                return 0
            ok, _ = verify_checkpoint(self)                 # Ed25519 + monotonic floor — the crypto gate
            if not ok:
                return 0
            return int(SignedChainHead.model_validate_json(HEAD_PATH.read_text(encoding="utf-8")).base_seq)
        except Exception:  # noqa: BLE001 — ANY failure ⇒ "no committed prune" ⇒ refuse to drop (fail-closed)
            return 0

    def _assert_may_drop_below(self, boundary: int) -> None:
        """Guard on every live-record drop (defence-in-depth, W16-STD-4 red-pen LOW-1): refuse to drop below
        `boundary` unless the owner-signed head has committed a prune reaching at least that far. These
        primitives are reached only from `commit_prune` (after 3 owner gates + signing the pruned head) and
        `finish_prune` (rolling forward an already-committed prune); a DIRECT caller with no committed prune is
        refused here rather than silently deleting owner-signed records."""
        committed = self._committed_prune_base_seq()
        if boundary > committed:
            raise SpineError(
                f"refusing to drop live records below seq {boundary}: the owner-signed head commits a prune "
                f"only through base_seq {committed}. This primitive runs ONLY inside a committed-prune context "
                f"(commit_prune / finish_prune) — never as a standalone delete.")

    def _rebase_manifest_below(self, base_seq: int) -> bool:
        """Publish a new-generation manifest that DROPS every sealed segment lying entirely below `base_seq`
        (last_seq < base_seq). MUST hold the flock, and MUST be inside a committed-prune context (guarded).
        This is the CUTOVER's atomic commit-echo: after it the live window is [base_seq..T]; the dropped
        segment FILES are not touched here (that is a separate, post-commit GC — a crash between the two
        leaves unreferenced orphans, never a torn chain). Idempotent (a no-op when nothing lies below
        base_seq). Returns True iff it changed the segment set.

        Retain-only-forward: the retained segments keep their bytes + chain linkage, so a reader that follows
        the new manifest sees the intact [base_seq..T] window (its first segment's `first_prev_hash` == the
        pruned boundary == the signed head's base_prev_hash)."""
        self._assert_may_drop_below(base_seq)               # LOW-1: no drop without a committed owner signature
        m = self._manifest if self._manifest is not None else read_manifest(self._layout)
        if m is None:
            return False
        keep = [s for s in m.segments if not (s.sealed and s.last_seq is not None and s.last_seq < base_seq)]
        if len(keep) == len(m.segments):
            return False                                # nothing below base_seq — idempotent no-op
        if not any(not s.sealed for s in keep):
            raise SpineError("refusing to rebase away the active segment — base_seq exceeds the live tail")
        write_manifest(self._layout, Manifest(generation=m.generation + 1, scope=m.scope, segments=keep))
        self._manifest = read_manifest(self._layout)
        self._active = self._resolve_active_path()
        with self._index_lock:
            self._index_epoch = None                    # segment set changed -> reconcile offsets on next read
        self._last = self._read_last_entry()
        return True

    def _delete_orphan_segment_files_below(self, base_seq: int) -> int:
        """Unlink every on-disk `seg-*` FILE whose segment lies entirely below `base_seq` and is NOT
        referenced by the CURRENT manifest — the post-cutover reclaim. MUST hold the flock, and MUST be inside
        a committed-prune context (guarded). Safe by construction: a file the committed manifest does not
        reference holds no live record, and the pruned prefix is preserved in the owner-anchored archive, so
        deleting it can never lose live data or break a read. Idempotent (missing_ok); a crash mid-delete just
        leaves fewer/more orphans for the next call. Returns the number of files unlinked."""
        self._assert_may_drop_below(base_seq)               # LOW-1: no delete without a committed owner signature
        m = self._manifest if self._manifest is not None else read_manifest(self._layout)
        referenced = {self._layout.seg_path(s).name for s in (m.segments if m is not None else [])}
        n = 0
        for p in sorted(self._layout.segments_dir.glob(f"{SEGMENT_STEM}*")):
            if self._segment_id_of(p.name) is None or p.name in referenced:
                continue
            # only files strictly below the pruned boundary — never anything the retained window might need.
            if self._segment_below(p, base_seq):
                try:
                    p.unlink(missing_ok=True)
                    p.with_name(p.name + ".idx").unlink(missing_ok=True)
                    n += 1
                except OSError:
                    pass
        if n:
            fsync_dir(self._layout.segments_dir)
        return n

    def _segment_below(self, path: Path, base_seq: int) -> bool:
        """True iff the (unreferenced) segment file at `path` holds only records with seq < base_seq. Reads
        the file's last record seq; a file we cannot read is treated as NOT-below (kept — never delete on a
        read failure)."""
        try:
            last = self._last_line_of(path)
            if last is None:
                return False
            return int(json.loads(last)["seq"]) < base_seq
        except (OSError, ValueError, KeyError, TypeError):
            return False

    def finish_prune(self) -> bool:
        """Idempotently COMPLETE a cold-archive prune whose owner-signed head has already committed
        (head.base_seq > 0) but whose manifest / segment files have not yet caught up — the roll-FORWARD after
        a crash between signing the pruned head (the durable commit) and the manifest rebase / file GC. Reads
        the committed head; if the live manifest still references segments below head.base_seq, rebases them
        away and unlinks the orphaned files. Returns True iff it advanced anything. Best-effort + fail-safe:
        never raises (a completion problem must not brick opening the store), and never rebases past what the
        signed head committed."""
        from ..config import HEAD_PATH
        from ..reuse import SignedChainHead
        try:
            if not HEAD_PATH.exists():
                return False
            head = SignedChainHead.model_validate_json(HEAD_PATH.read_text(encoding="utf-8"))
        except Exception:  # noqa: BLE001 — an unreadable/legacy head means no committed prune to finish
            return False
        if head.base_seq <= 0:
            return False
        with spine_lock(self.path):
            with self._crossproc_lock():
                self._refresh_active_under_lock()
                changed = self._rebase_manifest_below(head.base_seq)
                self._delete_orphan_segment_files_below(head.base_seq)
        return changed

    # --- write --------------------------------------------------------------------
    def _check_monotonic_tail_locked(self, active: Path, clean_end: int, last: "ChainEntry | None") -> None:
        """MUST hold the flock, after the torn-tail truncate. REFUSE to extend (or seal) a tail whose last record
        does not carry the highest seq in the active segment (or sits below the segment's first seq): the next
        record would chain from it — a fork below the true tip that every reader's seq order then hides.

        Lines are judged by the readers' own rule (`_record_dict`). Only bytes not yet checked IN THIS PROCESS are
        read: none after an append by any store of this process, a peer process's appended bytes, or — after a
        truncation, rotation, reset or a new process — the whole active segment, streamed. (An in-place rewrite of
        bytes already checked is not re-read here; `verify()` reports it.)"""
        key = str(active.resolve())
        if last is None:
            _TAIL_CHECKED.pop(key, None)
            return
        try:
            st = active.stat()
            ident = (st.st_dev, st.st_ino)
        except OSError:
            ident = None
        ck = _TAIL_CHECKED.get(key)
        if ck is not None and not (ck[0] == ident and (
                (ck[1] == clean_end and ck[3] == last.entry_hash)
                or (ck[1] < clean_end and self._ends_with_entry(active, ck[1], ck[3])))):
            ck = None                                     # not a continuation of what was checked: re-check all
        if ck is None:
            act = self._manifest.active() if self._manifest is not None else None
            ck = (ident, 0, (act.first_seq if act is not None else 0) - 1, "")
        off, top = ck[1], ck[2]
        if off < clean_end:
            below = top
            prev = None                                    # the last record seen; the tail is the final one
            for raw in _lines_between(active, off, clean_end):
                d = _record_dict(raw)
                if d is None:
                    continue
                if prev is not None:
                    below = max(below, prev)
                prev = d["seq"]
            if last.seq <= below:
                raise SpineError(
                    f"refusing to append: the spine tail (seq {last.seq}) is not above every earlier record in "
                    f"the active segment (highest seq {below}) — a duplicated or reordered line; run `sigil verify`")
            top = max(below, last.seq)
        _TAIL_CHECKED[key] = (ident, clean_end, top, last.entry_hash)

    def _tail_appended_locked(self, active: Path, end: int, entry: ChainEntry) -> None:
        """MUST hold the flock: record that this process's checked bytes now end with its own just-written record."""
        key = str(active.resolve())
        try:
            st = active.stat()
            ident = (st.st_dev, st.st_ino)
        except OSError:
            _TAIL_CHECKED.pop(key, None)
            return
        _TAIL_CHECKED[key] = (ident, end, entry.seq, entry.entry_hash)

    @staticmethod
    def _ends_with_entry(path: Path, off: int, entry_hash: str) -> bool:
        """Whether the bytes of `path` before offset `off` still end with the record whose entry_hash this is."""
        window = 8192
        with path.open("rb") as f:
            while True:
                start = max(0, off - window)
                f.seek(start)
                parts = f.read(off - start).rstrip(b"\n").rsplit(b"\n", 1)
                if len(parts) == 2 or start == 0:
                    break
                window *= 4
        d = _record_dict(parts[-1])
        return d is not None and d["entry_hash"] == entry_hash

    def _write_record_locked(
        self, f, pred: "ChainEntry | None", *, kind: str, source: str, actor: str,
        payload: dict[str, Any], parent_id: int | None, supersedes_id: int | None,
        ts: str | None, schema_version: int,
    ) -> "tuple[ChainEntry, int]":
        """Seal + chain + WRITE one record onto the already-open active-segment file ``f`` at EOF — but do NOT
        flush or fsync (the caller owns the durability barrier). Returns ``(chain entry, bytes written)``.

        MUST hold the spine lock + flock, and ``f`` MUST already be positioned at the true chain tip (the
        caller truncates any torn tail first). ``pred`` is the predecessor chain entry (None ⇒ seed the
        genesis chain at seq 0). ``entry.seq == (pred.seq + 1 if pred else 0)`` by construction, and the
        content fields are AEAD-sealed under the spine DEK bound to that seq exactly as the single-record path
        always did. This is the SHARED write core of ``append`` (one record → one fsync) and ``append_many``
        (N records → one fsync); factoring it out is what lets group commit (SCALE-C1) amortize the fsync
        across a batch WITHOUT duplicating — or drifting from — the seal/chain/record math."""
        seq = pred.seq + 1 if pred is not None else 0
        # G1 slice-4: seal the CONTENT FIELDS at rest under the spine DEK; metadata stays plaintext so keyless
        # folds work. The DEK is loaded ONLY when the record carries a content field (a pure-metadata/signal
        # append is never blocked by a locked vault). cert_digest is over the STORED form, so a keyless
        # verifier still verifies the chain.
        dek = self._spine_dek(create=True) if envelope.has_content(payload) else None
        stored_payload = envelope.seal_payload(dek, payload, scope=SCOPE, seq=seq)
        content = {
            "scope": SCOPE, "kind": kind, "source": source, "actor": actor,
            "payload": stored_payload, "parent_id": parent_id, "supersedes_id": supersedes_id,
        }
        cert_digest = digest_payload(content)  # over the STORED (content fields sealed) payload
        entry = (append_entry([pred], cert_digest) if pred is not None
                 else build_chain([cert_digest])[0])
        # schema_version sits OUTSIDE content (like seq/ts/chain fields), so it is not part of cert_digest —
        # that keeps the change additive and legacy records' chain byte-identical (W5-1).
        record = {
            "seq": entry.seq, **content, "ts": ts or now_iso(),
            "cert_digest": cert_digest, "prev_hash": entry.prev_hash, "entry_hash": entry.entry_hash,
            "schema_version": schema_version,
        }
        line_bytes = (json.dumps(record, ensure_ascii=False) + "\n").encode("utf-8")
        f.write(line_bytes)
        return entry, len(line_bytes)

    def _validate_kind_schema(self, kind: object, schema_version: object) -> None:
        """Fail CLOSED on an out-of-vocabulary kind or unknown schema version BEFORE any lock/byte (W5-1).
        Accepts ``object`` so a batch spec's untyped ``dict.get("kind")`` (``Any | None``) is validated the same
        fail-closed way as append()'s typed ``str`` — a non-str / None / unknown value is simply not in KINDS."""
        if kind not in KINDS:
            raise SpineError(
                f"refusing to append record with unknown kind {kind!r} (not in the enforced KINDS "
                f"vocabulary); add it to sigil.spine.models.KINDS before writing this kind")
        if schema_version not in KNOWN_SCHEMA_VERSIONS:
            raise SpineError(
                f"refusing to append record with unknown schema_version {schema_version!r} "
                f"(known: {sorted(KNOWN_SCHEMA_VERSIONS)}) — upgrade sigil before writing this version")

    # --- SCALE-C1b: concurrent-append coalescing (leader/follower group commit, DEFAULT-OFF) ------------
    def _holds_spine_lock(self) -> bool:
        """True iff THIS thread already holds the re-entrant spine lock for this store (an OUTER
        check-then-append transaction such as envelope.consume's TOCTOU replay gate, ui.provision, or
        ui.launch_gate). Such a caller MUST take the DIRECT append path: if it instead delegated to the
        coalescing front-end it could be elected a FOLLOWER behind a LEADER on another thread, and that
        leader's append_many() would block forever trying to acquire the spine_lock THIS thread holds (a
        deadlock). The probe fails SAFE — any error means we could not PROVE the lock is unheld, so we return
        True and the caller goes direct (which is always correct, never a deadlock)."""
        try:
            # `_is_owned()` is a same-thread re-entrancy probe on the RLock (False when unheld, True after a
            # same-thread acquire). It exists on the runtime lock object but not in threading.RLock's stub, so
            # the attr-defined ignore is a typeshed gap, not a runtime risk (exercised by the C1b tests).
            return bool(spine_lock(self.path)._is_owned())  # type: ignore[attr-defined]
        except Exception:  # noqa: BLE001 — cannot prove the lock is unheld ⇒ treat as held ⇒ direct path
            return True

    def _finalize_batch(self, batch: "list[_Waiter]", seqs: "list[int] | None",
                        err: "BaseException | None") -> None:
        """MUST hold `_commit_cv`. Publish the group-commit outcome to every waiter in `batch`. On SUCCESS,
        map each append_many seq (contiguous, in list order) to its waiter. On FAILURE (append_many RAISED
        and rolled back ATOMICALLY — NOTHING was acked), set the SAME error on EVERY waiter so they all raise
        and may safely retry (at-least-once; append_many's atomic rollback means no partial prefix is left to
        duplicate). Either way each waiter is marked `done` so its thread stops waiting."""
        if err is None:
            assert seqs is not None and len(seqs) == len(batch)
            for b, sq in zip(batch, seqs):
                b.seq = sq
                b.error = None
                b.done = True
        else:
            for b in batch:
                b.error = err
                b.done = True

    def _append_coalesced(self, spec: "dict[str, Any]") -> int:
        """Commit-coalescing front-end for an INDEPENDENT concurrent append() (SCALE-C1b). Enqueue this
        append, elect ONE leader per group, and have that leader write the whole group via the UNCHANGED
        append_many() on its own thread — spine_lock + flock + ONE fsync, acquired FRESH inside append_many,
        contiguous seqs, rotation. Because the real write IS append_many, C1b inherits the full signed-spine
        contract (chain-order / at-least-once / atomic rollback / fail-closed / durable-before-ack) VERBATIM
        and adds only thread coordination. Returns the assigned seq, or raises the batch's error.

        Followers are signaled ONLY after append_many() returns — i.e. after its single fsync — so every
        coalesced ack is durable-before-ack. Latecomers that arrive during the write queue at the tail and are
        led by the next head after notify_all. Only the queue head, and only while no leader is in flight,
        ever leads, so there is never a second concurrent leader."""
        # (a) Pre-flight the payload on THIS caller's own thread, BEFORE enqueue: a payload the real write
        # would REJECT must fail ONLY its owner (raised right here), so the batch the leader hands to
        # append_many is all-writable. Otherwise one poison payload would trip append_many's ATOMIC rollback
        # and fail the ENTIRE group — a poison append must never take its innocent co-batched neighbours down
        # with it. Use canonical_json, NOT plain json.dumps: the write path serializes the payload through
        # canonical_json(sort_keys=True) — seal_payload canonical_json's each content field, and
        # digest_payload canonical_json's the content — so a payload plain json.dumps ACCEPTS but
        # canonical_json REJECTS (e.g. a nested dict with mixed str/int keys that sort_keys cannot order) would
        # pass a plain pre-flight, enter the batch, then raise inside the leader's append_many and poison its
        # neighbours. Mirroring the write's serializer keeps isolation EXACT (rejects iff the write would) and
        # strictly supersets the plain-json non-serializable check.
        canonical_json(spec["payload"])
        w = _Waiter(spec)
        with self._commit_cv:
            self._commit_queue.append(w)
            while not w.done:                                 # re-check under the lock — guards spurious wakeups
                if (not self._leader_inflight and self._commit_queue
                        and self._commit_queue[0] is w):
                    # --- elected LEADER for this group ---
                    # Set the single-leader gate and DETACH the batch from the queue up front, so the NEXT
                    # head is exposed but held OFF by `_leader_inflight` until we clear it (that gate is what
                    # keeps a second leader from running concurrently); latecomers append past it at the tail.
                    self._leader_inflight = True
                    batch = self._commit_queue[:_GROUP_COMMIT_MAX]
                    del self._commit_queue[:len(batch)]
                    self._commit_cv.release()                 # write holding NEITHER _commit_cv NOR spine_lock
                    seqs: "list[int] | None" = None
                    err: "BaseException | None" = None
                    try:
                        seqs = self.append_many([b.spec for b in batch])   # fresh spine_lock+flock, ONE fsync
                    except BaseException as exc:  # noqa: BLE001 — fan the failure out to EVERY batch waiter
                        err = exc
                    finally:
                        # Re-acquire and finalize. append_many has already returned — post-fsync on success,
                        # or rolled-back-atomically on error — so signaling here is strictly DURABLE-BEFORE-ACK
                        # (and ack-NOTHING-on-error). The notify_all wakes this group's followers AND the next
                        # head, which leads the remaining queue + any latecomers.
                        self._commit_cv.acquire()
                        self._finalize_batch(batch, seqs, err)
                        self._leader_inflight = False
                        self._commit_cv.notify_all()
                    # loop re-checks `while not w.done`: our own waiter is in the batch → done → exit below
                else:
                    self._commit_cv.wait()                    # follower / gated next head: park until signaled
        if w.error is not None:
            raise w.error                                     # re-raise for THIS caller (leader or follower)
        assert w.seq is not None                              # done with no error ⇒ a seq was assigned
        return w.seq

    def append_many(self, specs: "list[dict[str, Any]]") -> "list[int]":
        """Append N records under ONE lock acquisition + ONE fsync — group commit (SCALE-C1).

        The per-record ``fsync`` under the write lock is the spine's write-throughput bottleneck, so a caller
        that has several records to write (a snapshot fold, a checkpoint, a drain batch, a group-commit
        leader draining queued concurrent appends) amortizes that single durability barrier across the whole
        batch instead of paying it per record.

        Each spec is ``{kind, source, actor, payload, parent_id?, supersedes_id?, ts?, schema_version?}`` —
        the same fields as :meth:`append` EXCEPT ``dedup`` (a batch is not content-deduped; a caller needing
        dedup uses :meth:`append`). Records are chained in LIST ORDER (record i+1's ``prev_hash`` = record i's
        ``entry_hash``) and share the ONE fsync, after which every record in the batch is durable. Returns the
        assigned seqs, in order. An empty ``specs`` writes nothing and returns ``[]``.

        CRASH SEMANTICS — the SAME at-least-once contract as :meth:`append`, at batch granularity. A crash
        between the writes and the fsync may leave a PREFIX of the batch durable-but-unacked; ``append_many``
        does not return, so the caller retries, and — exactly as for a single append that crashed after fsync
        but before its ack — a caller needing exactly-once relies on content-addressed dedup / processed
        markers (the drains already do). The chain is NEVER corrupted: unacked durable records are valid chain
        records and the next write continues from the true tip (the torn-tail truncation only removes a
        partially-written final line, never a committed one).

        ATOMIC-OR-NOTHING on the IN-PROCESS error path (distinct from a crash): if a spec fails WHILE the
        batch is being written — a missing required field (rejected up front, before any lock/byte) or a
        payload only ``json.dumps`` discovers is non-serializable (caught mid-write) — the partial prefix
        already written is rolled back to the pre-batch chain tip before the error propagates. So a caller
        that catches the error and retries can never silently DUPLICATE the already-written records
        (``append_many`` has no content dedup). This mirrors ``append()``, which writes its one record
        all-or-nothing."""
        if not specs:
            return []
        for i, s in enumerate(specs):
            # Reject a malformed spec BEFORE any lock/byte: a spec missing a required field would otherwise
            # raise a KeyError PARTWAY THROUGH the write loop below, after earlier records were already
            # written — a durable partial prefix on the signed chain. Fail closed here with a clear message.
            missing = [k for k in ("kind", "source", "actor", "payload") if k not in s]
            if missing:
                raise SpineError(
                    f"append_many spec[{i}] is missing required field(s) {missing} — each spec needs "
                    f"kind/source/actor/payload; refusing to write a partial batch")
            self._validate_kind_schema(s.get("kind"), s.get("schema_version", SCHEMA_VERSION))
        with spine_lock(self.path):
            with self._crossproc_lock():
                self._refresh_active_under_lock()
                active = self._active
                entries: "list[ChainEntry]" = []
                placed: "list[tuple[int, int]]" = []       # (offset, nbytes) per record, for the index update
                with active.open("a+b") as f:
                    clean_end, last = _last_valid_boundary(active)
                    pre_size = os.fstat(f.fileno()).st_size
                    if pre_size > clean_end:
                        f.truncate(clean_end)
                        _log.warning("spine: truncated a %d-byte torn tail (interrupted write) before "
                                     "append_many (%s)", pre_size - clean_end, active)
                    self._check_monotonic_tail_locked(active, clean_end, last)
                    pred = last if last is not None else self._seam_tip_for_active()
                    off = clean_end
                    try:
                        for s in specs:
                            entry, n = self._write_record_locked(
                                f, pred, kind=s["kind"], source=s["source"], actor=s["actor"],
                                payload=s["payload"], parent_id=s.get("parent_id"),
                                supersedes_id=s.get("supersedes_id"), ts=s.get("ts"),
                                schema_version=s.get("schema_version", SCHEMA_VERSION))
                            entries.append(entry)
                            placed.append((off, n))
                            off += n
                            pred = entry
                    except BaseException:
                        # ATOMIC-OR-NOTHING (signed ledger): a spec that fails mid-batch — e.g. a payload only
                        # json.dumps finds non-serializable, or any seal/write error — leaves records 0..i-1
                        # already written to the open file. Roll them back to the pre-batch tip so the batch is
                        # all-or-nothing like append(): flush pushes any buffered bytes to the OS, then truncate
                        # to clean_end drops the whole partial prefix. append_many has NO dedup, so a leftover
                        # prefix would be silently DUPLICATED by a caller that retries after catching the error.
                        # No in-memory index/seq/last state was published yet (that happens only after the fsync
                        # below), so truncating the bytes fully restores the chain tip.
                        f.flush()
                        f.truncate(clean_end)
                        raise
                    f.flush()
                    os.fsync(f.fileno())                   # ONE durability barrier for the whole batch
                    _maybe_crash("append_after_fsync")     # crash-fuzz: batch durable, not yet acked/sealed
                    with self._index_lock:
                        active_str = str(active)
                        for entry, (o, n) in zip(entries, placed):
                            if self._seg_scanned.get(active_str) == o:
                                self._offsets[entry.seq] = (active_str, o)
                                if entry.seq > self._max_seq:
                                    self._max_seq = entry.seq
                                self._seg_scanned[active_str] = o + n
                self._last = entries[-1]
                self._tail_appended_locked(active, off, entries[-1])
                self._maybe_rotate_locked()
        return [e.seq for e in entries]

    def append(
        self, *, kind: str, source: str, actor: str, payload: dict[str, Any],
        parent_id: int | None = None, supersedes_id: int | None = None,
        ts: str | None = None, schema_version: int = SCHEMA_VERSION,
        dedup: bool = False, dedup_window: int | None = None,
    ) -> int:
        # W5-1 write-path enforcement: a record with an out-of-vocabulary kind or an unknown schema version is
        # REFUSED before any lock is taken or byte written (fail CLOSED), so nothing junk reaches the immutable
        # chain; layer 2 = verify() re-checks kind on read. Shared with append_many via _validate_kind_schema,
        # so a future caller (e.g. an LLM-emitted cand.kind) can never inject an arbitrary kind on either path.
        self._validate_kind_schema(kind, schema_version)
        # SCALE-C1b: COMMIT-COALESCING FRONT-END (default-OFF). Before taking spine_lock, route INDEPENDENT
        # concurrent appends into one group that a single leader thread writes via the UNCHANGED append_many()
        # (one fsync per group — the 1M-scale concurrent-append throughput lift). Take the DIRECT path (today's
        # UNCHANGED code below) whenever ANY of: the flag is OFF; dedup was requested (append_many has no
        # dedup look-back); the payload CARRIES CONTENT TO SEAL (has_content); or THIS thread already HOLDS
        # spine_lock (a re-entrant check-then-append txn such as envelope.consume's replay gate — it MUST NOT
        # delegate to a leader on another thread, which would then deadlock acquiring the spine_lock this
        # thread holds). A CONTENT append goes DIRECT because its seal needs the spine DEK: on a LOCKED vault
        # _spine_dek raises VaultLocked INSIDE the leader's append_many, and the leader-exception fan-out would
        # then fail EVERY co-batched waiter — blocking an innocent pure-metadata/signal append (e.g. a
        # kill-switch panic) that the direct path guarantees is "never blocked by a locked vault". Routing
        # content direct keeps that fail-safe: a content seal failure stays isolated to its own caller, exactly
        # as today, while only never-encrypting metadata/signal appends coalesce. The _is_owned() probe fails
        # SAFE: if it cannot prove the lock is UNHELD it returns held, so an unprovable case goes direct, never
        # risking the deadlock. The direct-path body below is UNCHANGED.
        if (self._group_commit_coalesce and not dedup and not envelope.has_content(payload)
                and not self._holds_spine_lock()):
            return self._append_coalesced({
                "kind": kind, "source": source, "actor": actor, "payload": payload,
                "parent_id": parent_id, "supersedes_id": supersedes_id,
                "ts": ts, "schema_version": schema_version,
            })
        # Serialize the whole read-tip → write so concurrent writers (threaded bridge server, gesture
        # daemon) can't both fork off a stale tip and break the chain. The in-process RLock is keyed on
        # the STABLE `self.path` (unchanged), so the check-then-append gate `envelope.consume` builds on
        # top of it stays atomic across a rotation. Re-read the TRUE tip from disk under the lock.
        with spine_lock(self.path):
            with self._crossproc_lock():                 # cross-process guard on the path-stable lockfile
                self._refresh_active_under_lock()        # pick up a concurrent migrate()/rotation; never fork
                # CONTENT DE-DUPLICATION (opt-in, issue #530). Under the lock — so the tip is authoritative —
                # look back a bounded window for a record with byte-identical PLAINTEXT content and, on a hit,
                # return ITS seq WITHOUT writing. This NEVER touches the chain: no record is added, removed,
                # or rewritten, so `prev_hash`/seq contiguity and every signed head are byte-identical to a
                # store where the caller simply chose not to re-append. Default off ⇒ append is unchanged.
                if dedup:
                    hit = self._find_dedup(kind, source, actor, payload, parent_id, supersedes_id,
                                           window=_DEDUP_WINDOW if dedup_window is None else dedup_window)
                    if hit is not None:
                        return hit
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
                    self._check_monotonic_tail_locked(active, clean_end, last)
                    # Derive the predecessor BEFORE writing (the SAME chain math as append_entry/build_chain);
                    # _write_record_locked derives seq = pred.seq+1 (genesis 0), seals the content fields under
                    # the spine DEK bound to that seq, and writes the line (no fsync). active EMPTY ⇒ seed from
                    # the prior sealed segment's boundary (a rotated segment) else the genesis chain — never
                    # build_chain a non-genesis segment from GENESIS (that would fork at seq 0 — invariant 13).
                    pred = last if last is not None else self._seam_tip_for_active()
                    entry, nbytes = self._write_record_locked(
                        f, pred, kind=kind, source=source, actor=actor, payload=payload,
                        parent_id=parent_id, supersedes_id=supersedes_id, ts=ts, schema_version=schema_version)
                    offset = clean_end                      # after any truncate, EOF == clean_end (where the line lands)
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
                            self._seg_scanned[active_str] = offset + nbytes
                self._last = entry
                self._tail_appended_locked(active, offset + nbytes, entry)
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

    def iter_records(self, *, since_seq: int = -1, strict_order: bool = False) -> Iterator[SpineRecord]:
        """Records with seq > `since_seq`, in seq order, ACROSS ALL SEGMENTS (sealed segments then the
        active) as ONE contiguous chain, so every full-scanning consumer keeps seeing the whole log. For
        since_seq >= 0 the index seeks straight to the first wanted line in its owning segment
        (O(records-returned), not O(spine)); a full read (since_seq < 0) streams every segment from the
        first. A line that fails to parse or lacks required keys is SKIPPED (a torn active tail can't crash
        the read; a torn MIDDLE line becomes a seq gap that verify() fails on). RAISES SpineError if the
        manifest references a segment that cannot be read — a read must NEVER silently yield a short chain
        (invariant 15: no state-scanner fail-open). A line whose seq does not exceed the one before it (a
        duplicated or reordered line) is not yielded; with `strict_order` (verify()) it RAISES SpineOrderError."""
        yielded_upto = since_seq
        for _attempt in range(_SEG_RESOLVE_ATTEMPTS):    # D2 reader-grace: tolerate a few compaction moves
            segs = self._segments_in_order()             # RAISES on a genuinely missing referenced segment
            if not segs:
                return
            seen = -1                                    # the last seq read in THIS pass (a retry restarts it)
            try:
                # A strict (verify) pass always reads from the first segment: the index keeps only the LAST offset of a
                # duplicated seq, so a seek after a retry could start past the duplicate it must see.
                start_i, start_off = (0, 0) if strict_order else self._start_locus(yielded_upto, segs)
                for i in range(start_i, len(segs)):
                    p = segs[i]
                    with self._open_segment(p) as f:
                        if i == start_i and start_off:
                            f.seek(start_off)
                        for raw in f:
                            if not raw.strip():
                                continue
                            rec = _parse_record(raw)
                            if rec is None:
                                _log.warning("spine: skipping malformed line during iter_records (%s)", p)
                                continue
                            if strict_order and rec.seq <= seen:
                                raise SpineOrderError(
                                    f"duplicate or out-of-order seq {rec.seq} after seq {seen} in {p.name}")
                            seen = rec.seq
                            if rec.seq > yielded_upto:
                                yield rec
                                yielded_upto = rec.seq
                return                                    # completed cleanly
            except FileNotFoundError:
                # A concurrent compaction unlinked a plaintext segment AFTER we resolved it — either in the
                # read loop above OR inside _start_locus's index build (_ensure_index -> _scan_segment, the
                # open the C-1 fix originally left outside this try). Re-read the manifest (now pointing at
                # the .gz) and continue from where we left off; retain-all means the same seqs are still
                # covered, so no record is skipped or repeated. If the segment is GENUINELY gone (not a
                # compaction), the next _segments_in_order() re-resolve RAISES a loud missing-segment
                # SpineError at an unchanged generation, so this retry can never mask real loss as churn.
                _log.debug("spine: a segment moved during read (compaction); re-resolving from seq %d", yielded_upto)
                continue
        raise SpineError("spine segments kept moving during read (compaction churn) — giving up")

    def disk_tip(self) -> "int | None":
        """The last record's seq as the spine's files say NOW (the active segment's tail, or the last sealed one's —
        O(tail), never the seq index), -1 for an empty spine, or None when that is undecidable: the active segment
        the manifest names is missing (the full fold raises there) or the tail cannot be read."""
        m = read_manifest(self._layout)
        if m is not None:
            act = m.active()
            if act is not None and not self._layout.seg_path(act).exists():
                return None
        try:
            last = self._read_last_entry()
        except Exception:  # noqa: BLE001 — undecidable
            return None
        return last.seq if last is not None else -1

    def _segments_present(self, segs) -> bool:
        """True iff every one of `segs` (manifest entries) has its file on disk: one directory listing of the
        segments dir, not a `stat` per segment (a warm read of a large spine stays cheap)."""
        d = self._layout.segments_dir
        try:
            with os.scandir(d) as it:
                names = {e.name for e in it if e.is_file()}     # a dangling link / a directory is not a segment
        except OSError:
            return False
        prefix = d.name + "/"
        for sg in segs:
            f = sg.file
            name = f[len(prefix):] if f.startswith(prefix) else ""
            if name and "/" not in name:
                if name not in names:
                    return False
            elif not self._layout.seg_path(sg).is_file():  # a segment outside the segments dir: stat it
                return False
        return True

    def tail_after(self, seq: int, entry_hash: str, *, max_bytes: int = 4 << 20):
        """Front C S0d — the fold cache's FRESH-STORE fast path. Read-only; never touches the seq index.

        The verified fold cache keeps one folded state per spine across the per-request `SpineStore` objects the
        cockpit builds, and on each read must (1) prove its anchor — the record at `seq` still has `entry_hash` —
        and (2) fold the records appended since. Through `get()` / `iter_records(since_seq=…)` both build this
        object's seq index first: O(the active segment + every sealed segment's sidecar) on a fresh store, i.e.
        per request. This answers both from the END of the ACTIVE segment instead:

          * a list — exactly the records `iter_records(since_seq=seq)` yields (parsed the same way: blank and
            malformed lines skipped, an unterminated final line kept if it parses, strictly increasing seqs),
            PROVIDED the record at `seq` was found in that tail with `entry_hash`, or `seq` is the last record of
            the segment just before the active one and the manifest's `boundary_hash` for it (== its
            `entry_hash`, which `verify()` checks) is `entry_hash` — so an anchor in a sealed / gzip segment is
            proven without decompressing it. `[]`: `seq` is the tip;
          * False — the record at `seq` is provably NOT the anchor (a different hash, or the spine now ends
            before `seq`: a rollback, rewrite or reset);
          * None — undecidable within `max_bytes` of the tail (a large delta, a gap at `seq`, a non-monotonic
            tail, a rotation since the anchor that left more than one segment behind it), a segment the manifest
            names is missing (one listing of the segments dir), or the manifest is gone while a sealed segment is
            still on disk: the caller takes the indexed path, which re-resolves a superseded manifest and raises on
            a lost segment or a removed manifest as the full fold does."""
        if seq < 0:
            return None
        m = read_manifest(self._layout)
        if m is None:
            try:
                self._guard_manifest_absent_segmented()   # invariant 15, as the full fold's resolve runs it
            except SpineError:
                return None                               # the indexed path raises exactly as the full fold does
            target, prev = self._read_target(), None
        else:
            act = m.active()
            if act is None:
                return None
            target = self._layout.seg_path(act)
            sealed = m.sealed_in_order()
            prev = sealed[-1] if sealed else None
            # Every segment the manifest names must still be there. A MISSING one (a lost or deleted file, a
            # partial restore — or a seal + compaction that superseded this manifest while we read it) is
            # undecidable here: the indexed path re-resolves a superseded manifest, and RAISES on a genuinely
            # missing segment exactly as the full fold does (invariant 15) — never "an empty active, so the anchor
            # is the tip", and never a warm answer over a spine the full fold refuses to read.
            if not self._segments_present([act, *sealed]):
                return None
        try:
            size = target.stat().st_size if target.exists() else 0
        except OSError:
            return None
        window = min(size, 1 << 16)
        while True:
            start = size - window
            after: list[SpineRecord] = []                 # the records after `seq`, newest first
            if size:
                with target.open("rb") as f:
                    f.seek(start)
                    buf = f.read(window)
                lines = buf.split(b"\n")
                if start > 0:
                    lines = lines[1:]                     # the first piece may be a partial line
                last = None
                for raw in reversed(lines):               # newest first: stop at the anchor (O(new records))
                    if not raw.strip():
                        continue
                    rec = _parse_record(raw)
                    if rec is None:
                        continue                          # skipped exactly as iter_records skips it
                    if last is not None and rec.seq >= last:
                        return None                       # non-monotonic tail: leave it to the indexed path
                    last = rec.seq
                    if rec.seq > seq:
                        after.append(rec)
                        continue
                    if rec.seq == seq:
                        return after[::-1] if rec.entry_hash == entry_hash else False
                    # the newest record at or below `seq` is BELOW it: the anchor's own line is gone
                    return None if after else False      # a gap at `seq` / the spine now ends before it
                if start > 0:                             # every record read is after `seq`: read further back
                    if window >= max_bytes:
                        return None
                    window = min(size, window * 4)
                    continue
            # Every record of the active segment is after `seq` (or it is empty): the anchor can only be the
            # previous segment's last record, whose entry_hash the manifest carries as its boundary_hash.
            recs = after[::-1]
            if prev is None:
                return False if not recs else None        # an empty spine cannot hold the anchor
            if prev.last_seq != seq or prev.boundary_hash is None or (recs and recs[0].seq != seq + 1):
                return None
            return recs if prev.boundary_hash == entry_hash else False

    def get(self, seq: int) -> SpineRecord | None:
        """A single record by seq via the segment-aware index (resolves the OWNING segment + offset),
        byte-identical to a full scan. O(1) for a plaintext segment; for a gzip-sealed segment the offset is
        a DECOMPRESSED offset, so `gzip.seek()` decompresses up to it (bounded by the seal threshold — not a
        full-spine scan). Falls back to a bounded forward scan (spanning segments) when the seq is not
        indexed (beyond the tip, or a corrupt line was skipped)."""
        if seq < 0:
            return None
        loc = None
        for _attempt in range(_SEG_RESOLVE_ATTEMPTS):    # D2 reader-grace: a concurrent compaction may unlink
            try:                                         # a plaintext between the index resolve and its scan
                self._ensure_index()                     # RAISES a loud SpineError on a GENUINELY missing
                with self._index_lock:                   # segment (unchanged generation); re-resolves a mere
                    loc = self._offsets.get(seq)         # supersession internally via _segments_in_order()
                break
            except FileNotFoundError:
                # _scan_segment opened a plaintext a compaction unlinked after the resolve — re-resolve
                # (the manifest now names the .gz). Genuine loss re-raises loudly on the next resolve.
                _log.debug("spine: a segment moved during get() index build (compaction); re-resolving")
                continue
        else:
            raise SpineError("spine segments kept moving during get() (compaction churn) — giving up")
        if loc is not None:
            path_str, off = loc
            try:
                with self._open_segment(Path(path_str)) as f:
                    f.seek(off)
                    raw = f.readline()
                rec = _parse_record(raw)
                if rec is not None and rec.seq == seq:
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
        for _attempt in range(_SEG_RESOLVE_ATTEMPTS):    # D2 reader-grace: a concurrent compaction may
            segs = self._segments_in_order()             # unlink a plaintext between resolve and read
            try:
                recs: list[SpineRecord] = []
                for p in reversed(segs):
                    recs = self._read_segment_tail(p, n - len(recs)) + recs
                    if len(recs) >= n:
                        break
                return recs[-n:]
            except FileNotFoundError:
                # A superseded plaintext moved under us -> re-resolve (the manifest now names the .gz). A
                # GENUINELY missing segment is caught by the next _segments_in_order() re-resolve, which
                # RAISES a loud missing-segment SpineError at an unchanged generation, not "churn".
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
            rec = _parse_record(ln)
            if rec is not None:
                out.append(rec)
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
        naive-tamper detection; use the signed head for tamper-EVIDENCE.

        W5-1 also enforces the `kind` VOCABULARY on this read/integrity path (layer 2 of the sovereign
        mirror of the offense SQL `CHECK(kind IN (...))`): a record whose `kind` is not in the enforced
        `KINDS` set fails verify. `kind` is inside the digested content, so a hand-edited kind ALSO breaks
        the binding check — this is a defence-in-depth restatement of the same invariant on read."""
        entries: list[ChainEntry] = []
        try:
            for r in self.iter_records(strict_order=True):
                if r.kind not in KINDS:
                    return False, f"unknown kind {r.kind!r} at seq {r.seq}: not in the enforced KINDS vocabulary"
                content = {
                    "scope": r.scope, "kind": r.kind, "source": r.source, "actor": r.actor,
                    "payload": r.payload, "parent_id": r.parent_id, "supersedes_id": r.supersedes_id,
                }
                try:
                    bound = digest_payload(content) == r.cert_digest
                except (ValueError, TypeError) as e:   # a lone surrogate has no canonical form (UnicodeEncodeError)
                    return False, f"binding break at seq {r.seq}: content is not canonicalisable ({type(e).__name__})"
                if not bound:
                    return False, f"binding break at seq {r.seq}: payload does not match cert_digest (record tampered)"
                entries.append(ChainEntry(seq=r.seq, prev_hash=r.prev_hash, cert_digest=r.cert_digest,
                                          entry_hash=r.entry_hash))
        except SpineOrderError as e:
            return False, f"chain break: {e} (a record line was duplicated or reordered)"
        # PRUNE-AWARE ROOTING (hard-prune Slice E). The live window links from GENESIS for an un-pruned spine
        # or from the retained-segment boundary (base_prev_hash) after a cold-archive prune. The first live
        # segment's `first_prev_hash` carries that base (== GENESIS when nothing is pruned, so this stays
        # byte-identical for every non-pruned spine). A NON-genesis base is a claimed prune: accept it ONLY
        # when the owner-SIGNED head corroborates the same base — so a front-truncation of an un-pruned spine
        # (drop seg-0, present the next segment as first) cannot pass this unkeyed check by editing the
        # (unsigned, non-load-bearing) manifest. The authenticity of the base is thus delegated to the signed
        # head, exactly as this method's contract already delegates recompute-resistance.
        base_prev = self._live_base_prev_hash()
        if base_prev != _GENESIS_PREV:
            ok_c, why_c = self._corroborate_pruned_base(entries, base_prev)
            if not ok_c:
                return False, why_c
        return verify_chain(entries, genesis_prev=base_prev)

    def _live_base_prev_hash(self) -> str:
        """The prev_hash the live window links from: GENESIS for an un-pruned spine, or the retained-segment
        boundary (base_prev_hash) after a cold-archive prune. Read from the FIRST live segment's stored
        `first_prev_hash` (a manifest convenience — corroborated against the signed head in verify())."""
        m = read_manifest(self._layout)
        if m is None:
            return _GENESIS_PREV
        segs = m.ordered()
        return segs[0].first_prev_hash if segs else _GENESIS_PREV

    def _corroborate_pruned_base(self, entries: list[ChainEntry], base_prev: str) -> tuple[bool, str]:
        """A non-genesis (pruned) base is accepted by the unkeyed verify() ONLY when the owner-signed head
        agrees on it. Delegates authenticity to `verify_checkpoint` (Ed25519 + floor) and cross-checks that
        the head's committed base (base_seq + base_prev_hash) matches the live window's actual left edge."""
        from ..config import HEAD_PATH
        from ..reuse import SignedChainHead
        from .checkpoint import verify_checkpoint            # function-local: checkpoint imports store
        if not entries:
            return False, "a non-genesis base is claimed but the live window is empty"
        hok, hmsg = verify_checkpoint(self)
        if not hok:
            return False, f"pruned live window is not anchored by a valid signed head: {hmsg}"
        try:
            head = SignedChainHead.model_validate_json(HEAD_PATH.read_text(encoding="utf-8"))
        except Exception as e:  # noqa: BLE001 — an unreadable head over a pruned window fails closed
            return False, f"pruned spine head unreadable — cannot corroborate the base: {e}"
        if head.base_seq != entries[0].seq or head.base_prev_hash != base_prev:
            return False, (f"pruned live window base does not match the signed head (head base "
                           f"{head.base_seq}/{head.base_prev_hash[:12]}…, live starts "
                           f"{entries[0].seq}/{base_prev[:12]}…)")
        return True, "corroborated by the signed head"

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
                    if _record_dict(s) is not None:
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
                    rec = _parse_record(f.readline())
                    if rec is None or rec.seq != first:
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
            d = _record_dict(raw)
            if d is None:
                continue                                    # corrupt complete line — do not index it
            seq = d["seq"]
            self._offsets[seq] = (ps, line_off)
            if seq > self._max_seq:
                self._max_seq = seq
        self._seg_scanned[ps] = base + consumed
