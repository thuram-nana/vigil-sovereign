"""ActorScope (Phase 8, WS-G G-iv) — the origin allowlist that bounds where DELEGATE may act (the
owner's OWN service integrations), mirroring `OperatorScope`: EMPTY = deny-all. A step's origin must
be (1) http/https, (2) public (`sources.is_public_host` — no internal hosts), (3) in the allowlist.
Plus a per-service `creation_cap` (default 1) — mass account creation is out of doctrine; the cap is
checked at preview AND execute."""
from __future__ import annotations

from typing import List, Optional
from urllib.parse import urlsplit

from .sources import is_public_host


def _origin(url: str) -> Optional[str]:
    p = urlsplit(url if "//" in url else "https://" + url)
    if p.scheme not in ("http", "https") or not p.hostname:
        return None
    return f"{p.scheme}://{p.hostname.lower()}"


class ActorScope:
    def __init__(self, allowed_origins: Optional[List[str]] = None, *, creation_cap: int = 1):
        self.allowed = {o for o in (_origin(a) for a in (allowed_origins or [])) if o}
        self.creation_cap = creation_cap

    def origin_allowed(self, url: str) -> bool:
        p = urlsplit(url)
        if p.scheme not in ("http", "https") or not p.hostname or not is_public_host(p.hostname):
            return False
        return bool(self.allowed) and f"{p.scheme}://{p.hostname.lower()}" in self.allowed

    def creation_allowed(self, store, service: str) -> bool:
        n = sum(1 for r in store.iter_records()
                if r.payload.get("signal") == "web.actor.step"
                and r.payload.get("step_kind") == "account.create"
                and r.payload.get("service") == service
                and r.payload.get("status") == "applied")
        return n < self.creation_cap
