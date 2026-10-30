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

Stdlib only — no framework/strix/vigil_core/sigil. Offense-free and plane-pure by construction.
"""
from __future__ import annotations

import hashlib
import json
import os
import secrets
import smtplib
import time
from email.message import EmailMessage
from pathlib import Path
from typing import Optional

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
