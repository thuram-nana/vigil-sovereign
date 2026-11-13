"""Slice 1c — authentication / session audit events on the sovereign spine.

Login and logout transitions were previously UNRECORDED: a successful or failed owner/teammate login left
no trace on the spine. This appends an append-only, SECRET-FREE audit record for each transition, reusing
the same `store.append(kind="event", ...)` primitive the governor uses for account grants (so it is
chain-hashed and immutable like every other event).

SECRET DISCIPLINE (mirrors the accounts rule that only hashes/booleans reach the spine): a payload carries
ONLY the event name, the username (or "anonymous"), the login METHOD, the OUTCOME, and a coarse reason CODE
— NEVER a bearer, token, challenge, signature, password, or TOTP code.

BOUNDED (failures): a FAILED attempt is recorded through `FailedAuthnCoalescer` — the first per (client, method,
reason) in a window at once, the rest as one counted summary — so anonymous attempts cannot grow the spine without
limit while every attack still leaves a record and a count. Successes and logouts are recorded one by one (a logout
by nobody — no principal, no session — is not recorded at all).

BEST-EFFORT (fail-open on the AUDIT WRITE only): the auth DECISION has already been made and returned by the
caller; a spine hiccup while writing the side-record must NOT turn a valid login into a 500 or deny it. The
write is wrapped so it never raises out of the auth path. (The decision itself is never fail-open — that is
enforced in the login handlers, unchanged.)

Stdlib only — no framework/strix. Offense-free by construction.
"""
from __future__ import annotations

import threading
import time
from collections import OrderedDict
from typing import Callable, Optional

# Coarse, enumerated reason codes (no free-form / secret content ever).
REASON_INVALID_TOKEN = "invalid_token"
REASON_NO_IDENTITY = "no_identity"
REASON_CHALLENGE = "challenge"
REASON_SIGNATURE = "signature"
REASON_BAD_CREDENTIALS = "bad_credentials"
REASON_TOTP = "totp"

_AUTHN_SOURCE = "authn"


def record_authn(store, event: str, *, username: str = "", method: str = "", outcome: str = "",
                 reason: "Optional[str]" = None, source: "Optional[str]" = None,
                 coalesced: "Optional[int]" = None, window_s: "Optional[float]" = None) -> None:
    """Append one secret-free authn audit event (`kind="event", source="authn"`). Never raises: an
    audit-write failure is swallowed so it cannot break the already-decided auth response. `source` (the
    client address a FAILED attempt came from), `coalesced` and `window_s` are set only by
    `FailedAuthnCoalescer`; every other record is byte-identical to before."""
    try:
        # `username` is attacker-controllable (a failed-login submits an arbitrary username under the body
        # cap), so bound every field — a valid username is <=64 chars — so a hostile oversized value cannot
        # bloat the audit record. event/method/outcome/reason are server-chosen literals; capped defensively.
        payload = {
            "signal": "authn.audit",
            "event": str(event)[:64],
            "username": str(username or "anonymous")[:64],
            "method": str(method or "")[:32],
            "outcome": str(outcome or "")[:16],
        }
        if reason:
            payload["reason"] = str(reason)[:32]
        if source is not None:
            payload["client"] = str(source)[:64]
        if coalesced is not None:
            payload["coalesced"] = int(coalesced)
            payload["window_s"] = float(window_s or 0.0)
        store.append(kind="event", source=_AUTHN_SOURCE, actor="cockpit", payload=payload)
    except Exception:  # noqa: BLE001 — a spine hiccup must not break the auth response (best-effort audit)
        pass


class FailedAuthnCoalescer:
    """Bounds how many spine records FAILED authentication attempts can write, without going blind.

    Every failed attempt used to append its own record, so an anonymous client could grow the spine (and every
    later fold) without limit. Now failures are grouped per (client, event, method, reason) — never per username,
    which the client chooses — into windows of `window_s` seconds:

      * the FIRST failure of a group in a window is recorded AT ONCE (with its client): an attack is visible on
        the spine the moment it starts;
      * further failures of that group inside the window are COUNTED, not recorded one by one;
      * when the window has ended, ONE summary record carries the count (`coalesced: n`, `window_s`). Due
        summaries are written on the next failure, and by `flush` (the server calls it on every request), so
        a count is recorded even after the attack stops.

    At most `max_keys` groups are tracked at once; past that, new clients share one aggregate group per
    event/method/reason (client `*`), so a flood of distinct clients still leaves a record and a count."""

    def __init__(self, *, window_s: float = 60.0, max_keys: int = 1024,
                 clock: "Callable[[], float]" = time.monotonic) -> None:
        self.window_s, self.max_keys, self.clock = float(window_s), int(max_keys), clock
        self._lock = threading.Lock()
        self._wins: "OrderedDict[tuple, list]" = OrderedDict()    # group -> [window start, counted since]

    def _take_due(self, now: float) -> list:
        """Pop every window that has ended (oldest first); those that counted failures become summaries."""
        due = []
        while self._wins:
            key, (start, n) = next(iter(self._wins.items()))
            if now - start < self.window_s:
                break
            del self._wins[key]
            if n:
                due.append((key, n))
        return due

    def _write(self, store, due: list) -> None:
        for (client, event, method, reason), n in due:
            record_authn(store, event, username="(coalesced)", method=method, outcome="failure",
                         reason=reason or None, source=client, coalesced=n, window_s=self.window_s)

    def record(self, store, event: str, *, source: str, username: str = "", method: str = "",
               reason: "Optional[str]" = None) -> bool:
        """Count one failed attempt; True iff it was recorded on its own (the first of its group in a window)."""
        now = self.clock()
        key = (str(source or "?")[:64], str(event)[:64], str(method or "")[:32], str(reason or "")[:32])
        with self._lock:
            due = self._take_due(now)
            if key not in self._wins and len(self._wins) >= self.max_keys:
                key = ("*",) + key[1:]
            w = self._wins.get(key)
            first = w is None
            if first:
                self._wins[key] = [now, 0]
            else:
                w[1] += 1
        self._write(store, due)
        if first:
            record_authn(store, event, username=username, method=method, outcome="failure", reason=reason,
                         source=key[0])
        return first

    def due(self) -> bool:
        """Cheap: has the oldest tracked window ended?"""
        with self._lock:
            if not self._wins:
                return False
            start = next(iter(self._wins.values()))[0]
        return self.clock() - start >= self.window_s

    def flush(self, store_factory: "Callable[[], object]") -> None:
        """Write the summaries of every window that has ended (`store_factory` is called only if there are)."""
        if not self.due():
            return
        with self._lock:
            due = self._take_due(self.clock())
        if due:
            try:
                self._write(store_factory(), due)
            except Exception:  # noqa: BLE001 — best-effort, like every audit write
                pass
