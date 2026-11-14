"""Google sign-in that completes inside an INSTALLED customer app (the app hand-off) — the keyless edge's half.

Why it exists: an app installed to an iPhone Home Screen runs standalone, and iOS opens Google (and the redirect
back to the edge's callback) in a separate browser context with its own cookies. The normal flow binds the login
`state` to a short-lived cookie set in the browser that started it (the sid_hash binding) and sets the session
cookie at the callback — in the standalone app neither cookie is in the right jar, so the binding fails and the
session would land in a browser that is not the app.

The hand-off, used only when the app runs standalone:
  1. the app makes a random 32-byte VERIFIER (base64url, 43 characters), keeps it in the app's own storage
     (never a cookie, never a URL), and starts the login with `handoff=<base64url(sha256(verifier))>`;
  2. the edge binds that CHALLENGE to the single-use OIDC state instead of the sid cookie;
  3. at the callback, after the provisioner verified the Google sign-in, the edge sets no cookie in that browser:
     it stores a COMPLETED-LOGIN record keyed by the challenge, with a random 6-digit PAIRING CODE, and shows the
     code on a page that tells the person to type it into the VIGIL app on this phone and nowhere else;
  4. the app posts {verifier, code}; the edge finds the record by sha256(verifier), checks the code in constant
     time, consumes the record, and mints the session cookie in the app's own cookie jar.

Why both secrets: the verifier alone would let a person who starts a hand-off on their own device and gets
someone else to finish the Google sign-in redeem that person's session; the code is shown only where the Google
sign-in actually happened. Redeeming needs the app that started the flow AND the person who signed in.

Properties of this store (one 0600 file per completed login, under a directory the edge owns):
  * the file NAME is sha256 of the challenge (fixed [0-9a-f]{64}: no traversal) — the raw challenge, verifier
    and code are never written. The code is kept as HMAC-SHA256 keyed by the challenge over a per-record salt
    and the code, so a reader of the directory alone cannot test codes against it;
  * a record lives `ttl_s` (about 2 minutes) and is used once: a right code removes it; a wrong code counts,
    and the `max_attempts`-th wrong code removes it, so a guess at the code is at most 5 in 1,000,000 per
    completed sign-in;
  * a second completion for a challenge that already has a live record is refused (first one wins);
  * the directory is bounded: expired records are swept on every write, and a write at `max_records` live
    records is refused;
  * every read-modify-write runs under one exclusive flock, so concurrent redemptions of one record yield
    exactly one session, and concurrent wrong codes all count. Without flock (non-POSIX) redemption refuses.

Stdlib only (FATAL-2): the edge holds no owner key and imports no framework.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator, NamedTuple, Optional

try:
    import fcntl
except ImportError:  # pragma: no cover - non-POSIX: redemption then refuses (fail closed)
    fcntl = None  # type: ignore[assignment]

#: The verifier and the challenge are both base64url without padding of 32 bytes: 43 characters.
_B64U43 = re.compile(r"^[A-Za-z0-9_-]{43}$")
_CODE_RE = re.compile(r"^[0-9]{6}$")
_LOCK_NAME = ".handoff.lock"
DEFAULT_TTL_S = 120.0
DEFAULT_MAX_RECORDS = 4096
DEFAULT_MAX_ATTEMPTS = 5


def valid_challenge(value: str) -> bool:
    return isinstance(value, str) and bool(_B64U43.match(value))


def valid_verifier(value: str) -> bool:
    return isinstance(value, str) and bool(_B64U43.match(value))


def normalize_code(value) -> str:
    """The code as the person typed it, without spaces ("123 456" -> "123456"); "" when it is not 6 digits."""
    raw = "".join(str(value or "").split())
    return raw if _CODE_RE.match(raw) else ""


def challenge_of(verifier: str) -> str:
    """base64url(sha256(verifier)) without padding — the PKCE S256 shape (RFC 7636 §4.2)."""
    digest = hashlib.sha256(str(verifier).encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def format_code(code: str) -> str:
    """The code as shown on the page: two groups of three digits."""
    return f"{code[:3]} {code[3:]}"


class HandoffBusy(Exception):
    """The store is at capacity, or could not be written; the person should try again shortly."""


class HandoffExists(Exception):
    """A completed login for this challenge is already waiting (the first completion wins)."""


class Redeemed(NamedTuple):
    username: str
    org_id: Optional[str]


class WrongCode(NamedTuple):
    remaining: int          # wrong codes left before the record is removed (0: it has just been removed)


class Gone(NamedTuple):
    """No live record for this verifier: unknown, expired, already used, or removed after too many wrong codes."""


class HandoffStore:
    def __init__(self, path, *, ttl_s: float = DEFAULT_TTL_S, max_records: int = DEFAULT_MAX_RECORDS,
                 max_attempts: int = DEFAULT_MAX_ATTEMPTS) -> None:
        self.dir = Path(path)
        self.ttl_s = float(ttl_s)
        self.max_records = int(max_records)
        self.max_attempts = int(max_attempts)

    # -- internals ---------------------------------------------------------------------------------------------
    def _name(self, challenge: str) -> Path:
        return self.dir / hashlib.sha256(("handoff\x00" + challenge).encode("ascii")).hexdigest()

    @staticmethod
    def _mac(challenge: str, salt: str, code: str) -> str:
        return hmac.new(challenge.encode("ascii"), (salt + "\x00" + code).encode("ascii"), hashlib.sha256).hexdigest()

    @contextmanager
    def _locked(self) -> Iterator[None]:
        if fcntl is None:
            raise OSError("no flock on this platform")
        self.dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        fd = os.open(str(self.dir / _LOCK_NAME), os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            yield
        finally:
            os.close(fd)                                   # closing the descriptor releases the lock

    @staticmethod
    def _read(p: Path) -> "Optional[dict]":
        try:
            rec = json.loads(p.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return None
        return rec if isinstance(rec, dict) else None

    def _write(self, p: Path, rec: dict, *, exclusive: bool) -> None:
        """Write `rec` to `p` (temp + rename). `exclusive` refuses when `p` already exists (checked under the
        store lock, so no other writer can slip in between)."""
        if exclusive and p.exists():
            raise HandoffExists("a completed sign-in is already waiting for this hand-off")
        tmp = p.with_name(f".{p.name}.{secrets.token_hex(8)}.tmp")
        fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        try:
            os.write(fd, json.dumps(rec).encode("utf-8"))
            os.fsync(fd)
        finally:
            os.close(fd)
        os.replace(tmp, p)

    @staticmethod
    def _unlink(p) -> None:
        try:
            os.unlink(p)
        except OSError:
            pass

    def _sweep(self, now: float) -> int:
        """Remove every expired, unreadable or stray file; return how many live records remain."""
        live = 0
        try:
            entries = list(os.scandir(self.dir))
        except OSError:
            return 0
        for e in entries:
            if e.name == _LOCK_NAME:
                continue
            rec = self._read(Path(e.path)) if not e.name.startswith(".") else None
            exp = rec.get("exp") if rec else None
            if not isinstance(exp, (int, float)) or isinstance(exp, bool) or now >= float(exp):
                self._unlink(e.path)
            else:
                live += 1
        return live

    # -- the two operations --------------------------------------------------------------------------------------
    def complete(self, challenge: str, username: str, org_id: "Optional[str]", *,
                 now: "Optional[float]" = None) -> str:
        """Record a verified Google sign-in for `challenge` and return the 6-digit pairing code to show. Raises
        ValueError on a malformed challenge or empty username, HandoffExists when a live record for the challenge
        is already waiting, HandoffBusy at capacity or on a write error."""
        if not valid_challenge(challenge):
            raise ValueError("malformed hand-off challenge")
        if not username:
            raise ValueError("a completed sign-in needs a username")
        t = time.time() if now is None else float(now)
        code = f"{secrets.randbelow(1_000_000):06d}"
        salt = secrets.token_hex(16)
        rec = {"exp": t + self.ttl_s, "username": str(username), "org_id": org_id, "salt": salt,
               "mac": self._mac(challenge, salt, code), "attempts": 0}
        try:
            with self._locked():
                if self._sweep(t) >= self.max_records:
                    raise HandoffBusy("too many sign-ins are waiting; try again shortly")
                self._write(self._name(challenge), rec, exclusive=True)
        except (HandoffExists, HandoffBusy):
            raise
        except OSError as e:
            raise HandoffBusy("the sign-in could not be recorded") from e
        return code

    def redeem(self, verifier: str, code: str, *, now: "Optional[float]" = None):
        """Redeem a completed sign-in with the app's `verifier` and the person's `code`. Returns Redeemed (the
        record is consumed), WrongCode (the attempt counted; at the last attempt the record is removed) or Gone.
        Never raises for a bad input or an I/O error: those are Gone (fail closed)."""
        if not valid_verifier(verifier):
            return Gone()
        typed = normalize_code(code)
        challenge = challenge_of(verifier)
        p = self._name(challenge)
        t = time.time() if now is None else float(now)
        try:
            with self._locked():
                rec = self._read(p)
                if rec is None:
                    return Gone()
                exp, salt, mac = rec.get("exp"), rec.get("salt"), rec.get("mac")
                if (not isinstance(exp, (int, float)) or isinstance(exp, bool) or t >= float(exp)
                        or not isinstance(salt, str) or not isinstance(mac, str)):
                    self._unlink(p)
                    return Gone()
                if typed and hmac.compare_digest(self._mac(challenge, salt, typed), mac):
                    username, org_id = rec.get("username"), rec.get("org_id")
                    self._unlink(p)                        # single use: consumed before the session is minted
                    if not isinstance(username, str) or not username:
                        return Gone()
                    return Redeemed(username, org_id if isinstance(org_id, str) and org_id else None)
                attempts = rec.get("attempts")
                attempts = (attempts if isinstance(attempts, int) and not isinstance(attempts, bool) else 0) + 1
                if attempts >= self.max_attempts:
                    self._unlink(p)
                    return WrongCode(0)
                rec["attempts"] = attempts
                try:
                    self._write(p, rec, exclusive=False)
                except OSError:
                    self._unlink(p)                        # a wrong code that cannot be counted ends the record
                    return Gone()
                return WrongCode(self.max_attempts - attempts)
        except OSError:
            return Gone()
