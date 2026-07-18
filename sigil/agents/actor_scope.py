"""ActorScope (Phase 8, WS-G G-iv) — the origin allowlist that bounds where DELEGATE may act (the
owner's OWN service integrations), mirroring `OperatorScope`: EMPTY = deny-all. A step's origin must
be (1) http/https, (2) public (`sources.is_public_host` — no internal hosts), (3) in the allowlist
(scheme+host+port — port confusion refused). Plus a `creation_cap` (default 1) bounding account
creations per service label AND per ORIGIN (relabelling the same origin cannot mint extra accounts) —
mass account creation is out of doctrine; the cap is checked at preview AND re-checked at execute."""
from __future__ import annotations

from typing import List, Optional
from urllib.parse import urlsplit

from .sources import is_public_host

_DEFAULT_PORT = {"http": 80, "https": 443}


def _origin(url: str) -> Optional[str]:
    """Canonical scheme://host:port (default port made explicit) — so `https://h` and `https://h:443`
    match, but `https://h:8443` does NOT match `https://h` (port confusion is refused)."""
    try:
        p = urlsplit(url if "//" in url else "https://" + url)
        if p.scheme not in ("http", "https") or not p.hostname:
            return None
        port = p.port or _DEFAULT_PORT[p.scheme]
    except ValueError:                      # malformed / out-of-range port → fail-closed
        return None
    return f"{p.scheme}://{p.hostname.lower()}:{port}"


class ActorScope:
    def __init__(self, allowed_origins: Optional[List[str]] = None, *, creation_cap: int = 1):
        self.allowed = {o for o in (_origin(a) for a in (allowed_origins or [])) if o}
        self.creation_cap = creation_cap

    def origin_allowed(self, url: str) -> bool:
        try:
            p = urlsplit(url)
            if p.scheme not in ("http", "https") or not p.hostname or not is_public_host(p.hostname):
                return False
        except ValueError:                  # malformed (e.g. bad IPv6 literal) → fail-closed, never crash the caller
            return False
        return bool(self.allowed) and _origin(url) in self.allowed

    def creation_allowed(self, store, service: str, url: str = "") -> bool:
        """True while fewer than `creation_cap` accounts have been created for this service label OR at
        this origin — so relabelling the same origin cannot outrun the cap."""
        origin = _origin(url) if url else None
        n = 0
        for r in store.iter_records():
            p = r.payload
            if (p.get("signal") == "web.actor.step" and p.get("step_kind") == "account.create"
                    and p.get("status") == "applied"
                    and (p.get("service") == service
                         or (origin is not None and _origin(p.get("url", "")) == origin))):
                n += 1
        return n < self.creation_cap
