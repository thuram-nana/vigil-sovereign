"""SpineTailer (Phase 7, P0.2) — a live tail over the append-only, poll-only spine with an HONEST,
two-layer integrity model (red-pen-hardened: unkeyed hashes alone cannot resist a writer who can
recompute them):

  • `integrity_ok` (CHEAP, per-poll, unkeyed) — per-record binding+derivation (`verify_record`) plus
    cross-record LINKAGE (this record's `prev_hash` == the last emitted `entry_hash`). This catches
    ACCIDENTAL corruption, a naive stale-field tamper, a deletion/reorder/gap. It does NOT resist a
    file-writer who recomputes cert_digest+entry_hash (a tip tamper or a forward-cascaded fork stays
    internally consistent) — so it is necessary but not sufficient, and is never presented as proof
    of authenticity on its own.

  • `anchored` (KEYED, via `check_anchor`) — the owner-SIGNED head (`checkpoint.classify_head` /
    `verify_head`, Ed25519 1-of-1 trust root, monotonic `last_seq`) notarizes the prefix
    [0 .. signed_last_seq]. A recompute-fork or truncation AT OR BELOW the signed head is
    unforgeable without the owner key and is caught here; a monotonic high-water catches a rollback
    of even the un-notarized tail. Records with seq > signed_last_seq are the FRESH, not-yet-keyed
    tail — emitted `anchored=False` (well-formed but not tamper-proof), keyed at the next `sigil sign`.

A consumer (UI/mobile) shows `integrity_ok=False` as "integrity broken", and treats only
`anchored=True` records as owner-notarized truth; the un-notarized tail is labelled as such, never
dressed up as proven. One primitive, two consumers — the UI SSE feed and the mobile push notifier —
both drive `poll()` on a tick and fan events out via `Broadcaster`."""
from __future__ import annotations

from collections import deque
from typing import Optional

from ..config import HEAD_PATH
from ..reuse import SignedChainHead
from ..reuse.chain import _GENESIS_PREV
from .checkpoint import _MAX_HEAD_SCHEMA, classify_head, trust_root
from .floor import load_floor
from .store import SpineStore
from .verify import verify_record


def _peek_schema(raw: str) -> int:
    """Lenient read of a head's schema_version even when the strict model rejects it (a future-schema head
    carries fields `extra="forbid"` refuses). 1 on any parse failure."""
    try:
        import json
        return int(json.loads(raw).get("schema_version", 1))
    except (ValueError, TypeError, AttributeError):
        return 1


def _shape(record, *, integrity_ok: bool, integrity_reason: str, anchored: bool) -> dict:
    """The cited atom shape emitted to consumers. `integrity_ok` = unkeyed well-formedness;
    `anchored` = covered by the owner-signed head (keyed). `text` is best-effort, never fabricated."""
    return {
        "seq": record.seq, "kind": record.kind, "source": record.source, "actor": record.actor,
        "ts": record.ts, "entry_hash": record.entry_hash, "text": record.text(),
        "integrity_ok": integrity_ok, "integrity_reason": integrity_reason, "anchored": anchored,
    }


class SpineTailer:
    def __init__(self, store: Optional[SpineStore] = None, *, since_seq: int = -1,
                 signed_head: Optional[SignedChainHead] = None, tr=None):
        """Emit records with seq > `since_seq`. `signed_head`/`tr` may be injected (tests); otherwise
        the owner-signed head is loaded from `HEAD_PATH` + the persisted trust root."""
        self.store = store or SpineStore()
        self.cursor = since_seq
        if since_seq < 0:
            self._last_hash = _GENESIS_PREV
        else:
            anchor = self.store.get(since_seq)
            self._last_hash = anchor.entry_hash if anchor else _GENESIS_PREV
        self._injected_head = signed_head
        self._injected_tr = tr
        self._high_water = -1                           # monotonic anti-rollback water mark
        self._signed_last_seq = -1
        self.check_anchor()                             # establish the initial keyed anchor (reads disk)

    def poll(self) -> list[dict]:
        """Newly-appended records (seq > cursor), each with the cheap `integrity_ok` verdict and the
        `anchored` (keyed) flag from the last `check_anchor`. On an integrity failure the event is
        emitted flagged (not dropped); the cursor still advances so the feed never re-emits or stalls."""
        out: list[dict] = []
        for r in self.store.iter_records(since_seq=self.cursor):
            atom_ok, reason = verify_record(r)
            if r.prev_hash != self._last_hash:
                ok = False
                reason = f"linkage break at seq {r.seq}: prev_hash != last emitted entry_hash (rewind/fork/gap)"
            else:
                ok = atom_ok
            out.append(_shape(r, integrity_ok=ok, integrity_reason=reason,
                              anchored=(r.seq <= self._signed_last_seq)))
            self.cursor = r.seq
            self._last_hash = r.entry_hash
        return out

    def check_anchor(self) -> dict:
        """The KEYED verdict. Verify the owner-signed head over the current chain (unforgeable without
        the owner key): a recompute-fork or truncation at/below the signed head → `anchor_ok=False`;
        a monotonic high-water rollback of even the un-notarized tail → `rollback` set. Updates
        `signed_last_seq` so `poll()` can flag records beyond it as the un-notarized tail."""
        entries = self.store.entries()                  # FRESH read from disk (not the cached head)
        head_seq = entries[-1].seq if entries else -1
        rollback = None
        if head_seq < self._high_water:
            rollback = f"ROLLBACK: on-disk head seq {head_seq} < monotonic high-water {self._high_water}"
        else:
            self._high_water = head_seq
        head, tr, status = self._resolve_head()
        if status == "ahead":
            self._signed_last_seq = -1
            return {"anchor_ok": False, "signed_last_seq": -1, "rollback": rollback, "upgrade_required": True,
                    "reason": "signed head schema is newer than this build understands — upgrade sigil "
                              "(NOT treated as clean)"}
        if head is None:
            self._signed_last_seq = -1
            return {"anchor_ok": False, "signed_last_seq": -1, "rollback": rollback,
                    "reason": "no signed checkpoint — the live tail is well-formed but UN-NOTARIZED "
                              "(run `sigil sign` to anchor)"}
        try:
            floor = load_floor()                            # None if absent -> byte-identical to pre-floor
        except Exception as e:  # noqa: BLE001 — a PRESENT-but-corrupt floor is suspicious; fail CLOSED, never clean
            self._signed_last_seq = -1
            return {"anchor_ok": False, "signed_last_seq": -1, "rollback": rollback,
                    "reason": f"durable anti-rollback floor unreadable ({e})"}
        try:
            ok, reason = classify_head(head, entries, tr, floor=floor)
        except Exception as e:  # noqa: BLE001 — a malformed head must FAIL closed, never crash the feed
            self._signed_last_seq = -1
            return {"anchor_ok": False, "signed_last_seq": -1, "rollback": rollback,
                    "reason": f"anchor unverifiable ({e})"}
        self._signed_last_seq = head.last_seq if ok else -1
        return {"anchor_ok": ok and rollback is None, "signed_last_seq": self._signed_last_seq,
                "rollback": rollback, "reason": reason}

    def _resolve_head(self):
        """(head, trust_root, status) where status is 'ok' | 'none' | 'ahead'. A head whose schema_version
        exceeds what this build understands returns status='ahead' (surfaced by check_anchor as
        anchor_ok=False + upgrade_required) — NEVER the benign 'un-notarized' degrade, which would be a
        false-CLEAN for a too-new head. A v1/v2 head returns 'ok' (byte-identical path)."""
        if self._injected_head is not None:
            return self._injected_head, self._injected_tr, "ok"
        try:
            if not HEAD_PATH.exists():
                return None, None, "none"
            raw = HEAD_PATH.read_text(encoding="utf-8")
            try:
                head = SignedChainHead.model_validate_json(raw)
            except Exception:  # noqa: BLE001 — a future-schema head fails extra="forbid"; distinguish it
                return None, None, ("ahead" if _peek_schema(raw) > _MAX_HEAD_SCHEMA else "none")
            if head.schema_version > _MAX_HEAD_SCHEMA:
                return None, None, "ahead"
            return head, trust_root(), "ok"
        except Exception:  # noqa: BLE001 — no/broken head → unkeyed live tail (honest, fail-closed)
            return None, None, "none"


class Broadcaster:
    """Fan-out of tail events to N subscribers with bounded per-subscriber queues. On overflow the
    oldest events are dropped and the subscriber is marked `lagged` so it resyncs from the cursor
    (never a fabricated 'you saw everything')."""
    def __init__(self, maxlen: int = 512):
        self.maxlen = maxlen
        self._subs: dict[int, deque] = {}
        self._lagged: dict[int, bool] = {}
        self._next_id = 0

    def subscribe(self) -> int:
        sid = self._next_id
        self._next_id += 1
        self._subs[sid] = deque(maxlen=self.maxlen)
        self._lagged[sid] = False
        return sid

    def unsubscribe(self, sid: int) -> None:
        self._subs.pop(sid, None)
        self._lagged.pop(sid, None)

    def publish(self, events: list[dict]) -> None:
        for sid, q in self._subs.items():
            for ev in events:
                if len(q) == self.maxlen:        # would drop the oldest → the subscriber lagged
                    self._lagged[sid] = True
                q.append(ev)

    def drain(self, sid: int) -> tuple[list[dict], bool]:
        """Return (events, lagged) and clear both. `lagged=True` tells the consumer to resync."""
        q = self._subs.get(sid)
        if q is None:
            return [], False
        events = list(q)
        q.clear()
        lagged = self._lagged.get(sid, False)
        self._lagged[sid] = False
        return events, lagged
