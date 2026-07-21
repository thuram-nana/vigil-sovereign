"""
fsjob.spine — the append-only, signed event log for fs/job mutations (VIGIL-FUSION F9).

Every workspace MUTATION (write/edit/delete/move/mkdir/extract/undo) and every job lifecycle
transition is recorded as a signed :class:`SpineEvent`. This is the "turn the ``_edit_stack`` snapshots
into signed provable-rollback records" integration the SCOUT inventory calls for (SCOUT §361): the
event carries the pre-image and post-image content hashes so a rollback is witnessed, and the signer is
INJECTED so the whole layer is testable without a live kernel.

Sovereign rules enforced here:

  * **Fail-closed.** No signer wired, or a signer that returns a non-string / empty / raises → the event
    is REFUSED (:class:`EventLogError`); the mutation layer treats that as "do not mutate" (or rolls
    back a mutation already applied). An unsigned spine record is never produced.
  * **Append-only.** :meth:`SpineEventLog.append` only ever appends. There is no update/delete of a
    recorded event; a rollback is a NEW compensating event that references the original by id.
  * **Deterministic / spine-safe.** No wallclock, no RNG: the sequence number comes from an injected
    ``next_seq`` callable and the signing bytes are canonical (sorted-key, tight-separator JSON), so the
    same inputs produce byte-identical signing material and a byte-identical event id.
  * **Secret-free.** Event ``meta`` is scrubbed through the ONE F3 redaction path
    (``tools.redact_tool_args``) before signing, and file CONTENT never enters the spine — only its
    sha256 hash. So no credential can land in a signed record.

Import-clean: pydantic + stdlib + the F3 redactor only.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Optional, Tuple

from pydantic import BaseModel, Field

from ..tools import redact_tool_args

# A signer maps canonical event bytes → a signature string (an Ed25519 sig / signed-head ref in prod).
# Fail-closed: returning ``None``/""/non-str or raising means the event is NOT recorded.
Signer = Callable[[bytes], str]
# An injected monotonic sequence source (no wallclock/RNG). Must return a non-decreasing int.
NextSeq = Callable[[], int]


def sha256_hex(data: bytes) -> str:
    """Content hash used for pre/post images. Never the content itself lands on the spine — only this."""
    return hashlib.sha256(data).hexdigest()


class SpineEvent(BaseModel):
    """One signed, append-only mutation record. ``pre_hash``/``post_hash`` are content hashes (never the
    bytes); ``undo_of`` links a compensating (rollback) event to the original. ``meta`` is redacted."""

    seq: int
    kind: str                                   # fs.write | fs.edit | fs.delete | fs.move | fs.mkdir |
    #                                             fs.extract | fs.undo | job.spawn | job.transition
    engagement: str = ""
    paths: list[str] = Field(default_factory=list)
    pre_hash: str = ""                          # sha256 of the pre-image (""=did not exist)
    post_hash: str = ""                         # sha256 of the post-image (""=deleted)
    undo_of: str = ""                           # event_id this event rolls back (compensating events)
    meta: Dict[str, Any] = Field(default_factory=dict)
    signature: str = ""                         # set by the injected signer over ``signing_bytes()``

    def signing_bytes(self) -> bytes:
        """Canonical bytes the signer signs and the event id derives from — deterministic, signature
        excluded. Sorted keys + tight separators, so any two callers derive identical bytes."""
        payload = self.model_dump(mode="json")
        payload.pop("signature", None)
        return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")

    @property
    def event_id(self) -> str:
        """Content id of the event (over the signing bytes). Stable + deterministic."""
        return sha256_hex(self.signing_bytes())


class EventLogError(RuntimeError):
    """A spine event could NOT be signed/recorded. The mutation layer maps this to a fail-closed denial
    (no mutation, or rollback of a mutation already applied)."""


@dataclass
class SpineEventLog:
    """An in-memory append-only log of signed mutation events. In production the ``append`` sink also
    writes to the CRUCIBLE Ed25519 hash-chain spine; here the signer/seq are injected so the F9 tools
    are fully testable. The log itself never mutates or drops a recorded event."""

    signer: Optional[Signer]
    next_seq: NextSeq
    engagement: str = ""
    _events: list[SpineEvent] = field(default_factory=list)

    def append(self, kind: str, *, paths: Optional[list] = None, pre_hash: str = "",
               post_hash: str = "", undo_of: str = "", meta: Optional[dict] = None) -> SpineEvent:
        """Sign and append one event. FAIL-CLOSED: with no signer, or a signer that yields a
        non-string/empty value or raises, this raises :class:`EventLogError` and appends nothing. On
        success the event is appended (append-only) and returned."""
        if self.signer is None:
            raise EventLogError("no signer wired — a spine mutation cannot be recorded (fail-closed)")
        seq = int(self.next_seq())
        safe_meta = redact_tool_args(meta) if isinstance(meta, dict) else {}
        safe_paths = [str(p) for p in (paths or [])]
        event = SpineEvent(seq=seq, kind=str(kind), engagement=self.engagement, paths=safe_paths,
                           pre_hash=pre_hash, post_hash=post_hash, undo_of=undo_of, meta=safe_meta)
        try:
            signature = self.signer(event.signing_bytes())
        except Exception as exc:  # noqa: BLE001 — any signer error is a refusal, never swallowed-and-continued
            raise EventLogError(f"signer raised ({type(exc).__name__}): {exc}") from exc
        if not isinstance(signature, str) or not signature.strip():
            raise EventLogError("signer returned no signature — refusing to record an unsigned event")
        event = event.model_copy(update={"signature": signature})
        self._events.append(event)
        return event

    def events(self) -> Tuple[SpineEvent, ...]:
        """An immutable snapshot of the recorded events, in append order."""
        return tuple(self._events)

    def __len__(self) -> int:
        return len(self._events)
