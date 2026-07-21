"""
fireteam.spine_queue — the single-writer serialization of all member spine writes (VIGIL-FUSION F6).

The critical engineering risk of a parallel fireteam is that concurrent members contend for the
append-only, Ed25519 hash-chained spine: two interleaved appends corrupt the chain and break every
downstream signature. VIGIL's answer is structural — **all** member spine writes go through ONE writer,
serialized:

  * ``submit`` buffers a REDACTED record (the F3 ``redact_tool_args`` scrubber — one secret vocabulary,
    one scrubber path — so no credential ever reaches the spine); a member NEVER calls the writer.
  * ``flush`` drains the buffer through the single injected ``writer`` in DETERMINISTIC order
    ``(seq, member_id, kind)`` — no wallclock — one record at a time. A writer error on one record is
    isolated (that record is skipped) so a single bad member can neither corrupt the chain nor crash
    the wave.
  * the async ``write`` path guards the writer with an ``asyncio.Lock`` AND a re-entrancy flag, so even
    with truly concurrent members (an awaiting writer) no two writes are ever in flight at once — an
    attempted interleave raises inside the guard rather than silently corrupting the chain.

The ``writer`` is injected: ``writer(record: dict) -> ref`` (the appended record's spine hash / id), sync
or async. This keeps the queue fully testable without the live signed spine.
"""

from __future__ import annotations

import asyncio
import inspect
from dataclasses import dataclass
from typing import Any, Callable, Optional

from ..tools.governance import redact_tool_args


def _redact_record(record: Any) -> dict[str, Any]:
    """Scrub secrets from a record before it can touch the spine, reusing the F3 scrubber (ONE secret
    vocabulary). A non-dict record is coerced to ``{"value": str(record)}`` then scrubbed, so the
    queue is total on untrusted input."""
    if not isinstance(record, dict):
        record = {"value": "" if record is None else str(record)}
    return redact_tool_args(record)


@dataclass(frozen=True)
class QueuedWrite:
    seq: int
    member_id: str
    kind: str
    record: dict[str, Any]

    def order_key(self) -> tuple[int, str, str]:
        return (self.seq, self.member_id, self.kind)


class SingleWriterSpineQueue:
    """Serializes every member spine write behind one injected writer. Deterministic drain order; no
    wallclock, no RNG; secret-redacted; append-only (the ``refs`` list only ever grows)."""

    def __init__(self, writer: Optional[Callable[[dict[str, Any]], Any]]) -> None:
        self._writer = writer
        self._buffer: list[QueuedWrite] = []
        self._refs: list[str] = []
        self._lock = asyncio.Lock()
        self._in_writer = False   # re-entrancy tripwire — proves no two writes overlap

    @property
    def refs(self) -> list[str]:
        """The spine refs of the records written so far, in write order (append-only)."""
        return list(self._refs)

    @property
    def pending_count(self) -> int:
        return len(self._buffer)

    def submit(self, *, member_id: str, seq: int, kind: str, record: Any) -> None:
        """Buffer a redacted record for the single writer. A member calls this, never the writer. Total
        on untrusted input (coerces ids/seq/kind)."""
        try:
            s = int(seq)
        except (TypeError, ValueError):
            s = 0
        self._buffer.append(QueuedWrite(seq=s, member_id=str(member_id), kind=str(kind),
                                        record=_redact_record(record)))

    def _write_one(self, q: QueuedWrite) -> Optional[str]:
        if self._in_writer:  # a concurrent write slipped past serialization — refuse, never corrupt
            raise RuntimeError("re-entrant spine write — serialization violated")
        if self._writer is None:
            return None       # no writer wired → nothing is written (fail-closed, never faked)
        self._in_writer = True
        try:
            ref = self._writer({"seq": q.seq, "member_id": q.member_id, "kind": q.kind, **q.record})
        except Exception:  # noqa: BLE001 — isolate one bad write; never crash the wave or corrupt order
            return None
        finally:
            self._in_writer = False
        return str(ref) if ref is not None and str(ref).strip() else None

    def flush(self) -> list[str]:
        """Drain the buffer through the ONE writer in deterministic ``(seq, member_id, kind)`` order,
        one record at a time. Returns the full ordered ref list. Never raises."""
        pending = sorted(self._buffer, key=QueuedWrite.order_key)
        self._buffer = []
        for q in pending:
            try:
                ref = self._write_one(q)
            except RuntimeError:
                # re-entrancy can't occur on the serial flush path; if it somehow does, drop the
                # record rather than corrupt the chain.
                ref = None
            if ref is not None:
                self._refs.append(ref)
        return list(self._refs)

    async def write(self, *, member_id: str, seq: int, kind: str, record: Any) -> Optional[str]:
        """Async single-writer path for truly-concurrent members: acquire the lock, then write exactly
        one (redacted) record. The lock + re-entrancy guard together guarantee no interleave even if the
        injected writer awaits. Returns the record's spine ref (or ``None`` if unwritten)."""
        try:
            s = int(seq)
        except (TypeError, ValueError):
            s = 0
        q = QueuedWrite(seq=s, member_id=str(member_id), kind=str(kind), record=_redact_record(record))
        async with self._lock:
            if self._in_writer:
                raise RuntimeError("re-entrant spine write — serialization violated")
            if self._writer is None:
                return None
            self._in_writer = True
            try:
                result = self._writer({"seq": q.seq, "member_id": q.member_id, "kind": q.kind, **q.record})
                if inspect.isawaitable(result):
                    result = await result
            except Exception:  # noqa: BLE001 — isolate one bad write
                return None
            finally:
                self._in_writer = False
        ref = str(result) if result is not None and str(result).strip() else None
        if ref is not None:
            self._refs.append(ref)
        return ref
