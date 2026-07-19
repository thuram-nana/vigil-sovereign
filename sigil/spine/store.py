"""Append-only, hash-chained JSONL spine (SIGIL §6.1, D1).

Reuses CRUCIBLE's tamper-evident chain verbatim (`sigil.reuse`): each line carries
`{seq, prev_hash, entry_hash}` where `entry_hash` links prev+cert_digest+seq. The
`cert_digest` is over the record's CONTENT only (scope/kind/source/actor/payload/
parent/supersedes) — NOT the wallclock `ts` — so the chain is replay-stable. Appends
are O(1): read the last line's entry, `append_entry`, write.
"""
from __future__ import annotations

import json
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
    """Read the last non-empty line without loading the file (seek-from-end)."""
    with path.open("rb") as f:
        f.seek(0, os.SEEK_END)
        end = f.tell()
        if end == 0:
            return None
        buf = b""
        pos = end
        while pos > 0:
            step = min(8192, pos)
            pos -= step
            f.seek(pos)
            buf = f.read(step) + buf
            lines = [ln for ln in buf.split(b"\n") if ln.strip()]
            if lines and (pos == 0 or buf.count(b"\n") >= 2):
                return lines[-1].decode("utf-8")
        lines = [ln for ln in buf.split(b"\n") if ln.strip()]
        return lines[-1].decode("utf-8") if lines else None


class SpineStore:
    def __init__(self, path: Path | str = SPINE_PATH) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
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
                f.write(json.dumps(record, ensure_ascii=False) + "\n")
                f.flush()
            self._last = entry
        return entry.seq

    # --- read ---------------------------------------------------------------------
    def iter_records(self, *, since_seq: int = -1) -> Iterator[SpineRecord]:
        if not self.path.exists():
            return
        with self.path.open(encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                d = json.loads(line)
                if d["seq"] > since_seq:
                    yield SpineRecord.from_dict(d)

    def get(self, seq: int) -> SpineRecord | None:
        for r in self.iter_records(since_seq=seq - 1):
            if r.seq == seq:
                return r
            if r.seq > seq:
                break
        return None

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
        line = _last_nonempty_line(self.path) if self.path.exists() else None
        if not line:
            return None
        d = json.loads(line)
        return ChainEntry(seq=d["seq"], prev_hash=d["prev_hash"], cert_digest=d["cert_digest"], entry_hash=d["entry_hash"])
