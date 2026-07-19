"""Append-only, hash-chained JSONL spine (SIGIL §6.1, D1).

Reuses CRUCIBLE's tamper-evident chain verbatim (`sigil.reuse`): each line carries
`{seq, prev_hash, entry_hash}` where `entry_hash` links prev+cert_digest+seq. The
`cert_digest` is over the record's CONTENT only (scope/kind/source/actor/payload/
parent/supersedes) — NOT the wallclock `ts` — so the chain is replay-stable. Appends
are O(1): read the last line's entry, `append_entry`, write.
"""
from __future__ import annotations

import json
import logging
import os
import threading
from pathlib import Path
from typing import Any, Iterator

from ..config import SCOPE, SPINE_PATH
from ..reuse import ChainEntry, append_entry, build_chain, digest_payload, verify_chain
from .models import SpineRecord, now_iso

try:
    import fcntl  # POSIX advisory file lock — cross-PROCESS append serialization
except ImportError:  # pragma: no cover — non-POSIX
    fcntl = None  # type: ignore[assignment]

_log = logging.getLogger(__name__)

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


class SpineStore:
    def __init__(self, path: Path | str = SPINE_PATH) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        # seq -> byte-offset index (FIX 1). Built lazily on the first TARGETED read (get / iter_records
        # with since_seq >= 0) and then kept current: maintained O(1) on our own appends, and extended
        # (never rewritten — an append-only file's offsets never move) when a stat shows another PROCESS
        # grew the file. Full scans (verify/count/entries/iter_records(-1)) never touch it, staying a
        # single byte-identical pass. `_index_lock` guards the dict against concurrent read+append.
        self._index_lock = threading.Lock()
        self._index_built = False
        self._offsets: dict[int, int] = {}
        self._max_seq = -1
        self._scan_pos = 0                          # byte offset just past the last COMPLETE line indexed
        self._last: ChainEntry | None = self._read_last_entry()

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
        # daemon) can't both fork off a stale tip and break the chain. Re-read the TRUE tip from disk
        # under the lock — `self._last` may be stale if another instance/process appended.
        with spine_lock(self.path):
            with self.path.open("a", encoding="utf-8") as f:
                if fcntl is not None:
                    try:
                        fcntl.flock(f.fileno(), fcntl.LOCK_EX)   # cross-process guard (advisory)
                    except OSError:  # pragma: no cover
                        pass
                last = self._read_last_entry()
                entry = append_entry([last], cert_digest) if last else build_chain([cert_digest])[0]
                record = {
                    "seq": entry.seq, **content, "ts": ts or now_iso(),
                    "cert_digest": cert_digest, "prev_hash": entry.prev_hash, "entry_hash": entry.entry_hash,
                }
                line = json.dumps(record, ensure_ascii=False) + "\n"
                offset = os.fstat(f.fileno()).st_size   # byte offset where this line lands (append ⇒ EOF)
                f.write(line)
                f.flush()
                os.fsync(f.fileno())                    # FIX 3: an ack'd append is durable across a crash
                # FIX 1: keep the index current with NO re-scan when it is already exactly up to date.
                # If another PROCESS appended in between, `_scan_pos < offset` and we skip here — the next
                # read's `_ensure_index` extends from `_scan_pos`, picking up the gap records AND this one.
                with self._index_lock:
                    if self._index_built and self._scan_pos == offset:
                        self._offsets[entry.seq] = offset
                        if entry.seq > self._max_seq:
                            self._max_seq = entry.seq
                        self._scan_pos = offset + len(line.encode("utf-8"))
            self._last = entry
        return entry.seq

    # --- read ---------------------------------------------------------------------
    def iter_records(self, *, since_seq: int = -1) -> Iterator[SpineRecord]:
        """Records with seq > `since_seq`, in order. FIX 1: for since_seq >= 0 the index seeks straight
        to the first wanted line (O(records-returned), not O(file)); a full read (since_seq < 0) starts
        at byte 0 exactly as before. FIX 2: a line that fails to parse or lacks required keys is SKIPPED
        (a torn tail no longer crashes the read); a torn MIDDLE line becomes a seq gap that verify() fails
        on, so mid-file tampering is never silently hidden."""
        if not self.path.exists():
            return
        start_off = self._start_offset_for(since_seq)
        with self.path.open("rb") as f:
            if start_off:
                f.seek(start_off)
            for raw in f:
                if not raw.strip():
                    continue
                try:
                    rec = SpineRecord.from_dict(json.loads(raw))
                except (ValueError, KeyError, TypeError):
                    _log.warning("spine: skipping malformed line during iter_records (%s)", self.path)
                    continue
                if rec.seq > since_seq:
                    yield rec

    def get(self, seq: int) -> SpineRecord | None:
        """A single record by seq — O(1) via the index (FIX 1), byte-identical to a full scan."""
        if seq < 0 or not self.path.exists():
            return None
        self._ensure_index()
        with self._index_lock:
            off = self._offsets.get(seq)
        if off is not None:
            with self.path.open("rb") as f:
                f.seek(off)
                raw = f.readline()
            try:
                rec = SpineRecord.from_dict(json.loads(raw))
            except (ValueError, KeyError, TypeError):
                return None
            return rec if rec.seq == seq else None
        # not indexed (beyond the tip, or a corrupt line was skipped) — bounded fallback (still index-seeked)
        for r in self.iter_records(since_seq=seq - 1):
            if r.seq == seq:
                return r
            if r.seq > seq:
                break
        return None

    def tail(self, n: int) -> list[SpineRecord]:
        """The last `n` records, seek-from-end (O(n) bytes, NOT O(file)) — for a bounded RECENT-window
        read on a large spine. Fewer than `n` if the spine is shorter. NOTE: a bounded window collapses
        a RAPID (recent) replay flood, but does NOT bound AGGREGATE replay bloat — a rotated pool of
        distinct bodies larger than the window each ages out and re-records. Only pair `tail()`-based
        dedup with a record-time freshness gate (or an independent bound); do not rely on it alone to
        close a bloat sink."""
        if n <= 0 or not self.path.exists():
            return []
        with self.path.open("rb") as f:
            f.seek(0, os.SEEK_END)
            pos = f.tell()
            buf = b""
            while pos > 0 and buf.count(b"\n") <= n:
                step = min(65536, pos)
                pos -= step
                f.seek(pos)
                buf = f.read(step) + buf
        recs: list[SpineRecord] = []
        for ln in [x for x in buf.split(b"\n") if x.strip()][-n:]:
            try:
                recs.append(SpineRecord.from_dict(json.loads(ln)))
            except (ValueError, KeyError, TypeError):
                continue
        return recs

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

    def _read_last_entry(self) -> ChainEntry | None:
        # `_last_nonempty_line` skips a torn/garbage tail and returns the last VALID line (FIX 2), so a
        # crash mid-write can no longer block a restart. The returned line is guaranteed parseable.
        line = _last_nonempty_line(self.path) if self.path.exists() else None
        if not line:
            return None
        d = json.loads(line)
        return ChainEntry(seq=d["seq"], prev_hash=d["prev_hash"], cert_digest=d["cert_digest"], entry_hash=d["entry_hash"])

    # --- seq -> byte-offset index (FIX 1) -----------------------------------------
    def _start_offset_for(self, since_seq: int) -> int:
        """Byte offset to seek so a forward read yields exactly seq > since_seq. A full read
        (since_seq < 0) starts at 0 WITHOUT building the index — full scans stay a single byte-identical
        pass. Otherwise the index gives an O(1) seek to the line of seq (since_seq + 1)."""
        if since_seq < 0:
            return 0
        self._ensure_index()
        with self._index_lock:
            off = self._offsets.get(since_seq + 1)
            if off is not None:
                return off
            if since_seq + 1 > self._max_seq:
                return self._scan_pos              # nothing beyond the tip → the read yields nothing
        return 0                                    # below the min, or a skipped/corrupt gap → safe full scan

    def _ensure_index(self) -> None:
        """Build the index lazily (one unavoidable scan) and keep it current. Detects a file that GREW
        (our own or another PROCESS's appends — append-only ⇒ offsets never move, so we only EXTEND) and
        a file that SHRANK / was rewritten in place smaller (rebuild). Thread-safe under `_index_lock`."""
        try:
            size = self.path.stat().st_size if self.path.exists() else 0
        except OSError:
            return
        with self._index_lock:
            if not self._index_built:
                self._offsets = {}
                self._max_seq = -1
                self._scan_pos = 0
                self._index_built = True
                self._scan_from(0, size)
            elif size > self._scan_pos:
                self._scan_from(self._scan_pos, size)      # extend forward over the newly-appended bytes
            elif size < self._scan_pos:
                self._offsets = {}                          # truncated/rewritten smaller → rebuild
                self._max_seq = -1
                self._scan_pos = 0
                self._scan_from(0, size)

    def _scan_from(self, start: int, size: int) -> None:
        """Index every COMPLETE (newline-terminated) record line in bytes [start, size). MUST hold
        `_index_lock`. A malformed complete line is left OUT of the index (so a mid-file gap still
        surfaces via verify()); a trailing partial line (no newline yet) is left for the next extend."""
        if size <= start:
            return
        with self.path.open("rb") as f:
            f.seek(start)
            chunk = f.read(size - start)
        consumed = 0
        while True:
            nl = chunk.find(b"\n", consumed)
            if nl == -1:
                break                                       # trailing partial line — not complete yet
            raw = chunk[consumed:nl]
            line_off = start + consumed
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
            self._offsets[seq] = line_off
            if seq > self._max_seq:
                self._max_seq = seq
        self._scan_pos = start + consumed
