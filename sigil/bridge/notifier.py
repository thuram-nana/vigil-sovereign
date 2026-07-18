"""PushNotifier (Phase 7, WS-D D-vi) — pushes to the phone when an A2/A3 item QUEUES, fed by the
SHARED P0 `SpineTailer` (the same primitive the UI SSE feed uses). The push carries ONLY
`{seq, tier, kind}` — never the subject, never the payload, never a secret — so nothing sensitive
crosses even the WireGuard tunnel; the phone fetches any detail on demand over the daemon API. No
cloud push (that would egress the private subject off owned hardware)."""
from __future__ import annotations

from typing import List, Optional

from ..spine.store import SpineStore
from ..spine.tail import SpineTailer


class PushNotifier:
    def __init__(self, store: Optional[SpineStore] = None, *, since_seq: Optional[int] = None):
        self.store = store or SpineStore()
        start = since_seq if since_seq is not None else self.store.next_seq - 1
        self.tailer = SpineTailer(self.store, since_seq=start)

    def poll(self) -> List[dict]:
        """New pushes since the last poll: one per newly-QUEUED A2/A3 item, minimal fields only."""
        out: List[dict] = []
        for ev in self.tailer.poll():
            rec = self.store.get(ev["seq"])
            p = rec.payload if rec else {}
            if (p.get("decision") == "queued" and p.get("status") == "awaiting-approval"
                    and p.get("tier") in ("A2", "A3")):
                out.append({"seq": ev["seq"], "tier": p.get("tier"), "kind": ev["kind"]})   # no subject/secret
        return out
