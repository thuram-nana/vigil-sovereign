"""Program Slice E1 — a pluggable, OFF-by-default email channel + purpose-bound verification tokens.

Customer email verification and password recovery need two things that must NOT grant any authority by
themselves:
  * a SENDER that is OFF by default (`NullEmailSender` — a sovereign/dev deploy sends no mail and never
    silently depends on an external SMTP relay), with an opt-in stdlib `SmtpEmailSender` behind config;
  * an `EmailTokenLedger` of single-use, TTL-bounded, PURPOSE-bound tokens, each bound to an email
    context. Consuming a token proves control of that mailbox and nothing more — it only UNLOCKS an
    owner-signed provision / password-set performed elsewhere (the provisioner). A token carries no role,
    no org, no money.

Security properties (a false-green would let a token be replayed, used cross-purpose, or outlive its
TTL — each a path to account takeover / trial-credit farming):
  * SINGLE-USE: `consume` atomically CLAIMS the marker (rename) before returning, so a replay finds
    nothing. A wrong-PURPOSE attempt does NOT consume the token (no DoS on a legitimate verify token
    probed as a recover token) — it is rejected before the claim.
  * TTL: an expired token is refused (and reaped), fail-closed on a missing/non-numeric deadline.
  * The raw token is NEVER written to disk — only `sha256(token)` names the marker (mirrors
    `sessions.SessionLedger`), so a read of the ledger directory cannot recover a live token.

EMAIL CODES (`EmailCodeLedger`, OFF unless the provisioner is given one): a 6-digit code sent in the same email as
the token, so a person in the installed app can type it instead of following the email into a browser. A code is
bound to the email address and the purpose, used once, lives 10 minutes, and is gone after 5 wrong codes; one live
code per (email, purpose) — a new email replaces the previous code and inherits its count of wrong codes, so
re-sending does not buy more guesses. A guess is compared only with the code it was hashed for: a code replaced
while a guess was being hashed answers "gone". Stored hash-named only: the record name is sha256 of (purpose,
email) and the code is kept as a salted scrypt hash, never the raw code. Every check costs one scrypt whether or
not a code exists (no timing tell), and every hash runs on one small pool of `_HASH_CONCURRENCY` worker threads,
so a burst of checks cannot make the process hold many 16 MiB hash buffers: at most that many run at once, and only
those threads ever allocate one (the C allocator keeps a freed buffer in the arena of the thread that used it, so
hashing on each request's own thread would leave one per thread). A code proves the same thing as the token in
that email — control of the mailbox — and nothing more.

Stdlib only — no framework/strix/vigil_core/sigil. Offense-free and plane-pure by construction.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import smtplib
import time
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as _FutureTimeout
from contextlib import contextmanager
from email.message import EmailMessage
from pathlib import Path
from typing import Iterator, NamedTuple, Optional

try:
    import fcntl
except ImportError:  # pragma: no cover - non-POSIX: code checks then refuse (fail closed)
    fcntl = None  # type: ignore[assignment]

# Purposes a token may be minted/consumed for. A token minted for one is refused for the other.
PURPOSE_VERIFY = "verify"
PURPOSE_RECOVER = "recover"
_PURPOSES = frozenset({PURPOSE_VERIFY, PURPOSE_RECOVER})

_DEFAULT_TOKEN_TTL_S = 60 * 60.0        # 1 hour — a verify/recovery link is short-lived
_DEFAULT_MAX_TOKENS = 65536            # directory bound (anti-exhaustion)


class EmailSender:
    """The send interface. `send` returns True iff the message was accepted for delivery; False means
    'not sent' (not configured, or a transient failure) — the CALLER decides how to surface a dev token
    when nothing was sent. Never raises out of the signup/recovery path."""

    def send(self, to: str, subject: str, body: str) -> bool:  # pragma: no cover - interface
        raise NotImplementedError


class NullEmailSender(EmailSender):
    """The DEFAULT sender: sends nothing and reports it (False). A sovereign/dev deployment runs with
    this, so signup/recovery never silently depends on an external relay; the provisioner surfaces the
    token through a dev-only channel and NEVER in production."""

    def send(self, to: str, subject: str, body: str) -> bool:
        return False


class SmtpEmailSender(EmailSender):
    """An opt-in stdlib SMTP sender (configured via SIGIL_EMAIL_* by the caller). Fail-SOFT: any SMTP /
    socket error returns False rather than raising into the auth path (the caller treats False as
    'not delivered'). STARTTLS is used unless explicitly disabled."""

    def __init__(self, host: str, port: int, *, from_addr: str, username: "Optional[str]" = None,
                 password: "Optional[str]" = None, use_starttls: bool = True, timeout: float = 10.0) -> None:
        self.host = str(host)
        self.port = int(port)
        self.from_addr = str(from_addr)
        self.username = username
        self.password = password
        self.use_starttls = bool(use_starttls)
        self.timeout = float(timeout)

    def send(self, to: str, subject: str, body: str) -> bool:
        msg = EmailMessage()
        msg["From"] = self.from_addr
        msg["To"] = str(to)
        msg["Subject"] = str(subject)
        msg.set_content(str(body))
        try:
            with smtplib.SMTP(self.host, self.port, timeout=self.timeout) as smtp:
                if self.use_starttls:
                    smtp.starttls()
                if self.username:
                    smtp.login(self.username, self.password or "")
                smtp.send_message(msg)
            return True
        except (OSError, smtplib.SMTPException):
            return False


class EmailTokenLedger:
    """Single-use, TTL-bounded, purpose-bound email tokens on the filesystem (one 0600 marker per token
    named `sha256(token)`, mirroring `sessions.SessionLedger`). A token binds an `email` + a `purpose`;
    consuming it returns the bound email exactly once."""

    def __init__(self, path: "str | os.PathLike", *, ttl_s: float = _DEFAULT_TOKEN_TTL_S,
                 max_tokens: int = _DEFAULT_MAX_TOKENS) -> None:
        self.dir = Path(path)
        self.ttl_s = float(ttl_s)
        self.max_tokens = int(max_tokens)

    def _marker(self, token: str) -> Path:
        digest = hashlib.sha256(str(token).encode("utf-8")).hexdigest()   # fixed [0-9a-f]{64}: no traversal
        return self.dir / digest

    @staticmethod
    def _unlink(path: "str | os.PathLike") -> None:
        try:
            os.unlink(path)
        except OSError:
            pass

    def _read(self, marker: Path) -> "Optional[dict]":
        try:
            rec = json.loads(marker.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return None
        return rec if isinstance(rec, dict) else None

    def _write_atomic(self, marker: Path, rec: dict) -> bool:
        try:
            self.dir.mkdir(parents=True, exist_ok=True, mode=0o700)
            tmp = marker.with_name(f"{marker.name}.{secrets.token_hex(8)}.tmp")
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
            fd = os.open(str(tmp), flags, 0o600)
            try:
                os.write(fd, json.dumps(rec).encode("utf-8"))
            finally:
                os.close(fd)
            os.replace(tmp, marker)
            return True
        except OSError:
            return False

    def _sweep(self, now: float) -> int:
        """Remove every expired/corrupt marker; return the count of LIVE markers remaining (the bound)."""
        live = 0
        try:
            entries = list(os.scandir(self.dir))
        except OSError:
            return 0
        for entry in entries:
            if entry.name.endswith(".tmp") or ".claiming." in entry.name:
                continue
            rec = self._read(Path(entry.path))
            exp = rec.get("expires_at") if isinstance(rec, dict) else None
            if rec is None or not isinstance(exp, (int, float)) or isinstance(exp, bool) or now >= float(exp):
                self._unlink(entry.path)
            else:
                live += 1
        return live

    def issue(self, email: str, purpose: str, *, now: "Optional[float]" = None) -> "Optional[str]":
        """Mint a fresh single-use token bound to (`email`, `purpose`) and return the RAW token (only its
        hash is persisted). Sweeps + caps first; returns None if the ledger is full or the write failed.
        Refuses an unknown purpose fail-closed."""
        if purpose not in _PURPOSES:
            raise ValueError(f"purpose must be one of {sorted(_PURPOSES)}")
        if not isinstance(email, str) or not email:
            raise ValueError("email must be a non-empty string")
        t = time.time() if now is None else float(now)
        self.dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        if self._sweep(t) >= self.max_tokens:
            return None
        token = secrets.token_urlsafe(32)
        rec = {"email": str(email), "purpose": str(purpose), "expires_at": t + self.ttl_s}
        if not self._write_atomic(self._marker(token), rec):
            return None
        return token

    def consume(self, token: str, purpose: str, *, now: "Optional[float]" = None) -> "Optional[str]":
        """Atomically consume `token` for `purpose`, returning the bound email, or None (fail-closed). A
        token is single-use (the marker is CLAIMED by rename before the email is returned, so a replay or
        a concurrent consume loses the race → None), TTL-checked (an expired token is refused + reaped),
        and PURPOSE-bound (a mismatched purpose is refused WITHOUT consuming, so a cross-purpose probe
        cannot burn a valid token)."""
        if not isinstance(token, str) or not token or purpose not in _PURPOSES:
            return None
        t = time.time() if now is None else float(now)
        marker = self._marker(token)
        rec = self._read(marker)
        if rec is None:
            return None
        exp = rec.get("expires_at")
        if not isinstance(exp, (int, float)) or isinstance(exp, bool) or t >= float(exp):
            self._unlink(marker)                       # expired/poisoned deadline → reap + refuse
            return None
        if rec.get("purpose") != purpose:
            return None                                # WRONG PURPOSE → refuse WITHOUT consuming (no DoS)
        email = rec.get("email")
        if not isinstance(email, str) or not email:
            self._unlink(marker)
            return None
        # CLAIM atomically: the rename is the single-use point — only one caller can move the marker.
        claimed = marker.with_name(f"{marker.name}.claiming.{secrets.token_hex(8)}")
        try:
            os.replace(marker, claimed)
        except OSError:
            return None                                # someone else already claimed/consumed it
        self._unlink(claimed)
        return email

    def peek(self, token: str, purpose: str, *, now: "Optional[float]" = None) -> "Optional[str]":
        """Validate a token and return its bound email WITHOUT consuming it (read-only) — the basis for a
        commit-marker transaction: a caller peeks, performs its idempotent work, then `consume`s LAST so a
        crash before the consume leaves the token valid for an idempotent retry. Same TTL + purpose checks
        as `consume`, but it never claims/reaps the marker."""
        if not isinstance(token, str) or not token or purpose not in _PURPOSES:
            return None
        t = time.time() if now is None else float(now)
        rec = self._read(self._marker(token))
        if rec is None:
            return None
        exp = rec.get("expires_at")
        if not isinstance(exp, (int, float)) or isinstance(exp, bool) or t >= float(exp):
            return None                                # expired (consume will reap; peek stays read-only)
        if rec.get("purpose") != purpose:
            return None                                # wrong purpose
        email = rec.get("email")
        return email if isinstance(email, str) and email else None

    def revoke_for_email(self, email: str) -> int:
        """Invalidate every outstanding token bound to `email` (e.g. on successful verification, or when
        a customer account is revoked). Returns the count removed. Linear scan (the ledger is small)."""
        n = 0
        try:
            entries = list(os.scandir(self.dir))
        except OSError:
            return 0
        for entry in entries:
            if entry.name.endswith(".tmp") or ".claiming." in entry.name:
                continue
            rec = self._read(Path(entry.path))
            if isinstance(rec, dict) and rec.get("email") == email:
                self._unlink(entry.path)
                n += 1
        return n


# --- 6-digit email codes ----------------------------------------------------------------------------------------
_DEFAULT_CODE_TTL_S = 10 * 60.0         # a code is typed while the email is open: 10 minutes
_DEFAULT_CODE_ATTEMPTS = 5              # wrong codes per CODE before that code is destroyed
# A per-(email, purpose) hard ceiling on CUMULATIVE wrong codes across re-sends: destroying a code and re-sending
# only costs the per-email send limit (a few an hour), so without a cumulative cap the guess budget grows without
# bound over days (NIST 800-63B caps consecutive failures at 100 per authenticator). Once the ceiling is reached,
# code entry for that (email, purpose) is DISABLED (`CodeBlocked`) until a token-based success clears it
# (`revoke_for_email`, called when the sign-up/reset completes by either path) — the person uses the email LINK
# instead. The block is carried in a strike record under the same name as the code, kept this long since its last
# wrong code so it survives re-sends and a destroyed code but a long-abandoned strike is still reaped.
_DEFAULT_CODE_HARD_CEILING = 30
_STRIKE_TTL_S = 30 * 24 * 3600.0
_CODE_LOCK = ".codes.lock"
# scrypt for the stored code: a 6-digit code has 1,000,000 values, so a fast hash of it would hand a reader of the
# directory the code at once; this costs ~16 MiB and tens of milliseconds per try.
_SCRYPT_N, _SCRYPT_R, _SCRYPT_P = 2 ** 14, 8, 1
# Every code hash runs on this pool: at most _HASH_CONCURRENCY at once in one process (each holds a ~16 MiB buffer),
# and only these threads ever allocate one. The others wait their turn, up to _HASH_WAIT_S, and then fail closed (a
# check answers "gone", an issue returns no code); a hash still queued then is dropped.
_HASH_CONCURRENCY = 4
_HASH_POOL = ThreadPoolExecutor(max_workers=_HASH_CONCURRENCY, thread_name_prefix="email-code-hash")
_HASH_WAIT_S = 30.0
# The salt a check hashes with when there is no code to compare with: the same work as a real check, so the answer
# takes as long for an address with a code as for one without.
_ABSENT_SALT = "0" * 32


def normalize_code(value) -> str:
    """The code as typed, without spaces ("123 456" -> "123456"); "" unless it is exactly 6 digits."""
    raw = "".join(str(value or "").split())
    return raw if len(raw) == 6 and raw.isascii() and raw.isdigit() else ""


def format_code(code: str) -> str:
    return f"{code[:3]} {code[3:]}"


class CodeOk(NamedTuple):
    bind: dict              # what the issuer bound to the code (e.g. the sign-up's derived username/org id)


class CodeWrong(NamedTuple):
    remaining: int          # wrong codes left; 0 means the code has just been destroyed


class CodeGone(NamedTuple):
    """No live code for this (email, purpose): never issued, expired, used, replaced or destroyed."""


class CodeBlocked(NamedTuple):
    """Code entry for this (email, purpose) is disabled: too many cumulative wrong codes. The person must follow the
    email LINK (the token) instead; a token-based success clears the block."""


class EmailCodeLedger:
    """6-digit, single-use, 10-minute codes bound to (email, purpose); see the module docstring."""

    def __init__(self, path: "str | os.PathLike", *, ttl_s: float = _DEFAULT_CODE_TTL_S,
                 max_attempts: int = _DEFAULT_CODE_ATTEMPTS, max_records: int = _DEFAULT_MAX_TOKENS,
                 hard_ceiling: int = _DEFAULT_CODE_HARD_CEILING) -> None:
        self.dir = Path(path)
        self.ttl_s = float(ttl_s)
        self.max_attempts = int(max_attempts)
        self.max_records = int(max_records)
        self.hard_ceiling = int(hard_ceiling)

    def _name(self, email: str, purpose: str) -> Path:
        return self.dir / hashlib.sha256(("code\x00" + purpose + "\x00" + email).encode("utf-8")).hexdigest()

    @staticmethod
    def _hash(code: str, salt: str, email: str, purpose: str) -> str:
        """The salted scrypt of `code` bound to (purpose, email), computed on `_HASH_POOL`. Raises TimeoutError (an
        OSError) when it has not run within `_HASH_WAIT_S` (the pool is busy): the caller fails closed."""
        job = _HASH_POOL.submit(hashlib.scrypt, code.encode("ascii"),
                                salt=(salt + "\x00" + purpose + "\x00" + email).encode("utf-8"),
                                n=_SCRYPT_N, r=_SCRYPT_R, p=_SCRYPT_P, dklen=32)
        try:
            return job.result(timeout=_HASH_WAIT_S).hex()
        except _FutureTimeout:
            job.cancel()                                   # still queued: dropped; already running: result discarded
            raise TimeoutError("too many email-code checks at once") from None

    @contextmanager
    def _locked(self) -> Iterator[None]:
        if fcntl is None:
            raise OSError("no flock on this platform")
        self.dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        fd = os.open(str(self.dir / _CODE_LOCK), os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            yield
        finally:
            os.close(fd)

    @staticmethod
    def _read(p: Path) -> "Optional[dict]":
        try:
            rec = json.loads(p.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return None
        return rec if isinstance(rec, dict) else None

    def _write(self, p: Path, rec: dict) -> None:
        tmp = p.with_name(f".{p.name}.{secrets.token_hex(8)}.tmp")
        fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        try:
            os.write(fd, json.dumps(rec).encode("utf-8"))
        finally:
            os.close(fd)
        os.replace(tmp, p)

    @staticmethod
    def _unlink(p) -> None:
        try:
            os.unlink(p)
        except OSError:
            pass

    @staticmethod
    def _live(rec: "Optional[dict]", now: float) -> bool:
        if not rec:
            return False
        exp = rec.get("exp")
        return (isinstance(exp, (int, float)) and not isinstance(exp, bool) and now < float(exp)
                and isinstance(rec.get("salt"), str) and isinstance(rec.get("hash"), str))

    @staticmethod
    def _wrongs(rec: "Optional[dict]") -> int:
        """The cumulative count of wrong codes for this (email, purpose), carried across destroyed/re-sent codes."""
        w = rec.get("wrongs") if rec else 0
        return w if isinstance(w, int) and not isinstance(w, bool) and w > 0 else 0

    @staticmethod
    def _strike_live(rec: "Optional[dict]", now: float) -> bool:
        """A non-expired strike record (the block kept after a code is destroyed, so it outlives re-sends)."""
        if not rec:
            return False
        se = rec.get("strike_exp")
        return isinstance(se, (int, float)) and not isinstance(se, bool) and now < float(se)

    def _blocking(self, rec: "Optional[dict]", now: float) -> bool:
        """Code entry is disabled for this (email, purpose): the cumulative wrong count has reached the hard ceiling
        and the record is still live (a live code, or a non-expired strike). An expired strike no longer blocks."""
        return (self._wrongs(rec) >= self.hard_ceiling
                and (self._live(rec, now) or self._strike_live(rec, now)))

    def _sweep(self, now: float) -> int:
        live = 0
        try:
            entries = list(os.scandir(self.dir))
        except OSError:
            return 0
        for e in entries:
            if e.name == _CODE_LOCK:
                continue
            rec = self._read(Path(e.path)) if not e.name.startswith(".") else None
            if self._live(rec, now) or self._strike_live(rec, now):   # a live code OR a still-blocking strike
                live += 1
            else:
                self._unlink(e.path)
        return live

    def issue(self, email: str, purpose: str, *, bind: "Optional[dict]" = None,
              now: "Optional[float]" = None) -> "Optional[str]":
        """A fresh code for (`email`, `purpose`), replacing any earlier one, with `bind` stored beside it (returned by
        a right `check`). A live earlier code hands its count of wrong codes on to the new one (re-sending the email
        does not reset the 5). Returns the raw code (never stored), or None when the ledger is full or cannot be
        written."""
        if purpose not in _PURPOSES:
            raise ValueError(f"purpose must be one of {sorted(_PURPOSES)}")
        if not isinstance(email, str) or not email:
            raise ValueError("email must be a non-empty string")
        t = time.time() if now is None else float(now)
        code = f"{secrets.randbelow(1_000_000):06d}"
        salt = secrets.token_hex(16)
        try:
            rec = {"exp": t + self.ttl_s, "salt": salt, "hash": self._hash(code, salt, email, purpose),
                   "attempts": 0, "wrongs": 0, "bind": dict(bind or {})}
            with self._locked():
                p = self._name(email, purpose)
                prev = self._read(p)
                # The cumulative wrong-code count carries across a re-send AND across a destroyed code's strike, so
                # re-sending never resets the hard ceiling (a re-sent code over a reached ceiling is born blocked).
                # It carries ONLY while the record is still live: a strike older than _STRIKE_TTL_S no longer blocks
                # (an abandoned block is reaped), so a code issued after it starts the count fresh.
                if self._live(prev, t) or self._strike_live(prev, t):
                    rec["wrongs"] = self._wrongs(prev)
                if self._live(prev, t):
                    rec["attempts"] = self._attempts(prev)   # a live code also hands on its per-code attempt count
                elif not self._strike_live(prev, t) and self._sweep(t) >= self.max_records:
                    return None
                self._write(p, rec)
        except OSError:
            return None
        return code

    @staticmethod
    def _attempts(rec: "Optional[dict]") -> int:
        a = rec.get("attempts") if rec else 0
        return a if isinstance(a, int) and not isinstance(a, bool) and a > 0 else 0

    def check(self, email: str, purpose: str, code, *, consume: bool = False,
              now: "Optional[float]" = None):
        """Check a typed code for (`email`, `purpose`). Right: CodeOk(bind), and the code is removed when `consume`
        (a caller that commits later removes it with `consume_code`). Wrong: the attempt is counted and the
        `max_attempts`-th wrong code removes the code (CodeWrong(0)). No live code, or a code replaced while the guess
        was hashed: CodeGone — after the same scrypt a real check costs. A malformed code counts as wrong. Never
        raises; an I/O error, or no free hash slot, is CodeGone (fail closed)."""
        if purpose not in _PURPOSES or not isinstance(email, str) or not email:
            return CodeGone()
        typed = normalize_code(code)
        t = time.time() if now is None else float(now)
        p = self._name(email, purpose)
        first = self._read(p)
        if self._blocking(first, t):
            return CodeBlocked()     # too many cumulative wrong codes: entry disabled until a token-based success
        try:
            if first is None or not self._live(first, t):
                self._hash(typed or "000000", _ABSENT_SALT, email, purpose)    # the same work: no timing tell
                return CodeGone()
            # the slow hash outside the lock (so one check does not hold up every other), compared under it; a
            # malformed code is hashed too (as "000000", never a match), so it costs what a real check costs
            guess = self._hash(typed or "000000", str(first["salt"]), email, purpose)
            with self._locked():
                rec = self._read(p)
                if self._blocking(rec, t):             # crossed the ceiling via a concurrent guess: never compared
                    return CodeBlocked()
                if rec is None or not self._live(rec, t):
                    self._unlink(p)
                    return CodeGone()
                if rec["salt"] != first["salt"]:
                    return CodeGone()          # replaced meanwhile: the guess was hashed for a code that is gone
                if typed and hmac.compare_digest(guess, str(rec["hash"])):
                    if consume:
                        self._unlink(p)
                    bind = rec.get("bind")
                    return CodeOk(dict(bind) if isinstance(bind, dict) else {})
                attempts = self._attempts(rec) + 1
                wrongs = self._wrongs(rec) + 1
                if wrongs >= self.hard_ceiling or attempts >= self.max_attempts:
                    # destroy the live code but KEEP a strike carrying the cumulative wrong count, so re-sending a
                    # code never resets the hard ceiling and a long-abandoned block is still reaped (_strike_live).
                    try:
                        self._write(p, {"strike_exp": t + _STRIKE_TTL_S, "wrongs": wrongs})
                    except OSError:
                        self._unlink(p)
                    return CodeBlocked() if wrongs >= self.hard_ceiling else CodeWrong(0)
                rec["attempts"] = attempts
                rec["wrongs"] = wrongs
                try:
                    self._write(p, rec)
                except OSError:
                    self._unlink(p)                     # a wrong code that cannot be counted ends the code
                    return CodeGone()
                return CodeWrong(self.max_attempts - attempts)
        except OSError:
            return CodeGone()

    def consume_code(self, email: str, purpose: str) -> None:
        """Remove the code for (`email`, `purpose`) — the commit marker of a caller that checked without consuming."""
        if purpose in _PURPOSES and isinstance(email, str) and email:
            self._unlink(self._name(email, purpose))

    def revoke_for_email(self, email: str) -> int:
        """Remove the codes of every purpose for `email` (a sign-up or reset completed by either path)."""
        n = 0
        if not isinstance(email, str) or not email:
            return 0
        for purpose in sorted(_PURPOSES):
            p = self._name(email, purpose)
            if p.exists():
                self._unlink(p)
                n += 1
        return n
