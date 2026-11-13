"""Slice 1c — authentication / session audit events on the sovereign spine.

Login and logout transitions were previously UNRECORDED: a successful or failed owner/teammate login left
no trace on the spine. This appends an append-only, SECRET-FREE audit record for each transition, reusing
the same `store.append(kind="event", ...)` primitive the governor uses for account grants (so it is
chain-hashed and immutable like every other event).

SECRET DISCIPLINE (mirrors the accounts rule that only hashes/booleans reach the spine): a payload carries
ONLY the event name, the username (or "anonymous"), the login METHOD, the OUTCOME, and a coarse reason CODE
— NEVER a bearer, token, challenge, signature, password, or TOTP code.

BOUNDED (failures): a FAILED attempt is recorded through `FailedAuthnCoalescer` — the first per (client, method,
reason[, proven username]) in a window at once, the rest as one counted summary — so anonymous attempts cannot grow
the spine without limit while every attack still leaves a record and a count. Successes and logouts are recorded one
by one (a logout that ends no session and has no principal is not recorded at all).

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
from datetime import datetime, timezone
from typing import Callable, Optional

# Coarse, enumerated reason codes (no free-form / secret content ever).
REASON_INVALID_TOKEN = "invalid_token"
REASON_NO_IDENTITY = "no_identity"
REASON_CHALLENGE = "challenge"
REASON_SIGNATURE = "signature"
REASON_BAD_CREDENTIALS = "bad_credentials"
REASON_TOTP = "totp"

_AUTHN_SOURCE = "authn"


def _write_authn(store, event: str, *, username: str = "", method: str = "", outcome: str = "",
                 reason: "Optional[str]" = None, source: "Optional[str]" = None,
                 coalesced: "Optional[int]" = None, window_s: "Optional[float]" = None,
                 since: "Optional[str]" = None) -> None:
    """Append one secret-free authn audit event (`kind="event", source="authn"`); RAISES on a write failure."""
    # `username` is attacker-controllable (a failed-login submits an arbitrary username under the body cap), so
    # bound every field — a valid username is <=64 chars — so a hostile oversized value cannot bloat the audit
    # record. event/method/outcome/reason are server-chosen literals; capped defensively.
    payload: "dict[str, object]" = {
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
        payload["since"] = str(since or "")[:40]
    store.append(kind="event", source=_AUTHN_SOURCE, actor="cockpit", payload=payload)


def record_authn(store, event: str, *, username: str = "", method: str = "", outcome: str = "",
                 reason: "Optional[str]" = None) -> None:
    """Append one secret-free authn audit event (`kind="event", source="authn"`). Never raises: an
    audit-write failure is swallowed so it cannot break the already-decided auth response."""
    try:
        _write_authn(store, event, username=username, method=method, outcome=outcome, reason=reason)
    except Exception:  # noqa: BLE001 — a spine hiccup must not break the auth response (best-effort audit)
        pass


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class FailedAuthnCoalescer:
    """Bounds how many spine records FAILED authentication attempts can write, without going blind.

    Every failed attempt used to append its own record, so an anonymous client could grow the spine (and every
    later fold) without limit. Now failures are grouped per (client, event, method, reason) — never per claimed
    username, which the client chooses; a username PROVEN by a first factor (a second-factor failure) does split
    its group — into windows of `window_s` seconds:

      * the FIRST failure of a group in a window is recorded AT ONCE (with its client): an attack is visible on
        the spine the moment it starts;
      * further failures of that group inside the window are COUNTED, not recorded one by one;
      * when the window has ended, ONE summary record carries the count (`coalesced: n`, `window_s`, and `since`,
        the wall-clock start of the window). Due summaries are written on the next failure, by `flush` (the server
        calls it on every request), by a background flush when the oldest window ends (given a `store_factory`),
        and — ended or not — by `close` (server shutdown). A summary that cannot be written stays owed and is
        retried; a first record that cannot be written is counted into its window's summary.

    At most `max_keys` groups are tracked at once; past that, new clients share one aggregate group per
    event/method/reason (client `*`), so a flood of distinct clients still leaves a record and a count."""

    def __init__(self, *, window_s: float = 60.0, max_keys: int = 1024,
                 clock: "Callable[[], float]" = time.monotonic,
                 store_factory: "Optional[Callable[[], object]]" = None) -> None:
        self.window_s, self.max_keys, self.clock = float(window_s), int(max_keys), clock
        self._store_factory = store_factory
        self._lock = threading.Lock()
        # group -> [window start (clock), failures counted since the first, wall-clock start]
        self._wins: "OrderedDict[tuple, list]" = OrderedDict()
        self._timer: "Optional[threading.Timer]" = None

    def _take_due(self, now: float, *, everything: bool = False) -> list:
        """Pop every window that has ended (oldest first) — or every window — and return those that counted."""
        due = []
        while self._wins:
            key, w = next(iter(self._wins.items()))
            if not everything and now - w[0] < self.window_s:
                break
            del self._wins[key]
            if w[1]:
                due.append((key, w))
        return due

    def _owe(self, items: list) -> None:
        """Put summaries that could not be written back, still owed (merged into a newer window of the same group),
        at the front: they are retried by the next flush."""
        with self._lock:
            for key, w in reversed(items):
                cur = self._wins.pop(key, None)
                if cur is not None:
                    w = [w[0], w[1] + cur[1], w[2]]
                self._wins[key] = w
                self._wins.move_to_end(key, last=False)

    def _write(self, store, due: list) -> None:
        failed = []
        for key, w in due:
            client, event, method, reason, user = key
            try:
                _write_authn(store, event, username=user or "(coalesced)", method=method, outcome="failure",
                             reason=reason or None, source=client, coalesced=w[1], window_s=self.window_s,
                             since=w[2])
            except Exception:  # noqa: BLE001 — retried later; the count is never dropped
                failed.append((key, w))
        if failed:
            self._owe(failed)

    def record(self, store, event: str, *, source: str, username: str = "", method: str = "",
               reason: "Optional[str]" = None, proven: bool = False) -> bool:
        """Count one failed attempt; True iff it was recorded on its own (the first of its group in a window).
        `proven`: the username was proven by a first factor, so it is part of the group (and of its summary)."""
        now = self.clock()
        key = (str(source or "?")[:64], str(event)[:64], str(method or "")[:32], str(reason or "")[:32],
               str(username or "")[:64] if proven else "")
        with self._lock:
            due = self._take_due(now)
            if key not in self._wins and len(self._wins) >= self.max_keys:
                key = ("*",) + key[1:4] + ("",)
            w = self._wins.get(key)
            first = w is None
            if w is None:
                self._wins[key] = [now, 0, _now_iso()]
            else:
                w[1] += 1
            self._arm_locked()
        self._write(store, due)
        if first:
            try:
                _write_authn(store, event, username=username, method=method, outcome="failure", reason=reason,
                             source=key[0])
            except Exception:  # noqa: BLE001 — not recorded on its own: count it into its window's summary
                with self._lock:
                    cur = self._wins.get(key)
                    if cur is not None:
                        cur[1] += 1
                if cur is None:                          # its window already ended and was taken: owe it
                    self._owe([(key, [now, 1, _now_iso()])])
        return first

    def due(self) -> bool:
        """Cheap: has the oldest tracked window ended?"""
        with self._lock:
            if not self._wins:
                return False
            start = next(iter(self._wins.values()))[0]
        return self.clock() - start >= self.window_s

    def flush(self, store_factory: "Callable[[], object]", *, everything: bool = False) -> None:
        """Write the summaries of every window that has ended — or, with `everything`, of every window — calling
        `store_factory` only if there are any. Never raises; what cannot be written stays owed."""
        if not everything and not self.due():
            return
        with self._lock:
            due = self._take_due(self.clock(), everything=everything)
        if not due:
            return
        try:
            store = store_factory()
        except Exception:  # noqa: BLE001 — best-effort, like every audit write; the counts stay owed
            self._owe(due)
            return
        self._write(store, due)

    def close(self) -> None:
        """Server shutdown: stop the background flush and write every pending count now, ended or not."""
        with self._lock:
            if self._timer is not None:
                self._timer.cancel()
                self._timer = None
        if self._store_factory is not None:
            self.flush(self._store_factory, everything=True)

    def _arm_locked(self) -> None:
        """MUST hold `_lock`. Schedule ONE background flush for when the oldest window ends, so its count is
        written even if no request follows (only with a `store_factory`)."""
        if self._store_factory is None or self._timer is not None or not self._wins:
            return
        start = next(iter(self._wins.values()))[0]
        delay = min(self.window_s, max(0.05, start + self.window_s - self.clock()))
        t = threading.Timer(delay, self._on_timer)
        t.daemon = True
        self._timer = t
        t.start()

    def _on_timer(self) -> None:
        with self._lock:
            self._timer = None
        if self._store_factory is not None:
            self.flush(self._store_factory)
        with self._lock:
            self._arm_locked()
