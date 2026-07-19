"""PushNotifier (Phase 7, WS-D D-vi) — pushes to the phone when an A2/A3 item QUEUES. The push
carries ONLY `{seq, tier, kind}` — never the subject, never the payload, never a secret — so nothing
sensitive crosses even the WireGuard tunnel; the phone fetches any detail on demand over the daemon
API. No cloud push (that would egress the private subject off owned hardware).

PERF (audit HIGH — double whole-file read): an earlier revision fed a `SpineTailer` and then
RE-FETCHED each surfaced event with `store.get(seq)` to reach its payload. `store.get` scans the
spine from the start (there is no index), so K queued events cost O(K × whole-file) on top of the
tailer's own pass. The refetch existed only because the tailer's shaped output drops the payload
(the tier / decision / status live there). We now read the FULL records ourselves in ONE
cursor-advancing pass and take tier/decision/status straight off each record's own payload — one
whole-file pass per poll, zero per-event re-reads. Output shape and filter are byte-for-byte
unchanged: `{seq, tier, kind}`, only for items that just QUEUED awaiting approval at tier A2/A3."""
from __future__ import annotations

from typing import List, Optional

from ..spine.store import SpineStore


class PushNotifier:
    def __init__(self, store: Optional[SpineStore] = None, *, since_seq: Optional[int] = None):
        self.store = store or SpineStore()
        # Start at the current head (only NEW items push) unless an explicit resume cursor is supplied.
        # `poll()` advances this cursor over EVERY record it walks, so a subsequent poll never re-emits.
        self.cursor = since_seq if since_seq is not None else self.store.next_seq - 1

    def poll(self) -> List[dict]:
        """New pushes since the last poll: one per newly-QUEUED A2/A3 item, minimal fields only.

        ONE pass over the spine (`iter_records(since_seq=cursor)`); each record's tier/decision/status
        is read from its OWN payload — no per-event `store.get` re-scan (the audit-flagged double read).
        The cursor advances over every walked record so the next poll starts strictly after it."""
        out: List[dict] = []
        for rec in self.store.iter_records(since_seq=self.cursor):
            self.cursor = rec.seq
            p = rec.payload or {}
            if (p.get("decision") == "queued" and p.get("status") == "awaiting-approval"
                    and p.get("tier") in ("A2", "A3")):
                out.append({"seq": rec.seq, "tier": p.get("tier"), "kind": rec.kind})   # no subject/secret
        return out
