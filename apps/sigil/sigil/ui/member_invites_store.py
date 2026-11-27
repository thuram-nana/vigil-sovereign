"""member_invites_store -- the PENDING team invitations a workspace admin raises for a person who does not already
have a VIGIL account, kept SERVER-SIDE, keyed by the single-use token (never the token itself).

The Team feature (VIGIL_CUSTOMER_TEAM_UI) can today add an EXISTING VIGIL account by email. An INVITE covers the
other case: an org_admin invites a person by email who has no account yet. The invite is a PENDING record plus a
single-use, TTL-bounded token sent in an email; it GRANTS NOTHING by itself. When the invited person signs up or
signs in with that email and presents a valid, unexpired, unused token, the provisioner redeems it to an
owner-signed, role-capped membership grant (``provision.customer_member_invite_accept``) and the token is spent.

Security properties (a false-green here would let a token be replayed, let an invite outlive its TTL, or let an
invite grant authority before acceptance):
  * SINGLE-USE: ``accept`` flips the record from ``pending`` to ``accepted`` under an exclusive ``flock``, so a
    replay (or a concurrent accept) finds it no longer pending and is refused. The provisioner runs accept inside
    its cross-process member critical section too, so the flip and the owner-signed grant never interleave with a
    second redemption.
  * TTL: an invite past ``expires_at`` is never live (``peek``/``pending_for_org`` ignore it; ``accept`` refuses and
    reaps it). Fail-closed on a missing / non-numeric deadline.
  * The raw token is NEVER written to disk -- only ``sha256(token)`` names the 0600 marker (mirrors
    ``email_channel.EmailTokenLedger`` / ``sessions.SessionLedger``), so a read of the directory cannot recover a
    live token, and the email body (which carries the token) is never stored or logged.
  * ROLE CAP: the store refuses any role the provisioner has not already capped to the customer-grantable set, as a
    defence in depth (the provisioner is the authority on the cap).

Shape: one small JSON marker per invite under ``config.CUSTOMER_MEMBER_INVITES_DIR``
(``$SIGIL_HOME/customer/member_invites``), the file named ``sha256(token)`` and holding
``{v, invite_id, org_id, email, role, created_at, expires_at, status}``. ``invite_id`` is a fresh opaque id used to
list / revoke an invite WITHOUT the token. The directory is bounded (``max_total``) and per-org pending invites are
bounded (``max_pending_per_org``); a second pending invite for the same (org, email) is refused (dedupe). Mutations
(create / revoke / accept) take an exclusive ``flock`` on ``.invites.lock``; reads are lenient and never raise.

This is an operational, ephemeral queue, not durable trust state: it lives under the ``customer/`` tree of markers a
backup excludes (``backup`` EXCLUDED_TOP_LEVEL), so a restore drops any pending invite -- the AUTHORITATIVE
membership a redeemed invite produced is owner-signed on the spine, and an un-redeemed invite is simply re-sent.

Stdlib only -- no framework / strix / vigil_core / offense plane. FATAL-2: sovereign-side.
"""
from __future__ import annotations

import hashlib
import json
import os
import secrets
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator, Optional, TypeGuard

try:
    import fcntl
except ImportError:  # pragma: no cover - non-POSIX: the lock refuses, fail closed
    fcntl = None  # type: ignore[assignment]

from ..reuse import assert_no_offense

assert_no_offense()

#: the roles a customer invite may carry -- the SAME customer-grantable set the provisioner enforces, duplicated here
#: as a defence in depth so a store write can never seat a role (operator / founder / owner) a customer cannot grant.
INVITE_ROLES = frozenset({"viewer", "analyst", "org_admin"})

STATUS_PENDING = "pending"
STATUS_ACCEPTED = "accepted"

_DEFAULT_TTL_S = 7 * 24 * 3600.0        # 7 days -- a team invite is short-lived
_DEFAULT_MAX_PENDING_PER_ORG = 100      # a per-org ceiling on outstanding invites (anti-abuse)
_DEFAULT_MAX_TOTAL = 65536              # directory bound (anti-exhaustion), mirrors EmailTokenLedger
_MAX_EMAIL_LEN = 254                    # RFC-ish address cap (the provisioner validates the shape)
_LOCK_NAME = ".invites.lock"


class InviteExists(ValueError):
    """A live pending invite already exists for this (org, email): a second one is refused (dedupe, anti-spam)."""


class InviteCapReached(ValueError):
    """The org already holds the maximum number of pending invites, or the store is full: refused, nothing written."""


def _is_text(v: object) -> bool:
    if not isinstance(v, str):
        return False
    try:
        v.encode("utf-8")
    except UnicodeEncodeError:
        return False
    return True


class MemberInviteLedger:
    """Single-use, TTL-bounded pending team invitations on the filesystem (one 0600 marker per token named
    ``sha256(token)``). An invite binds an ``org_id`` + an ``email`` + a capped ``role``; ``accept`` redeems it
    exactly once. Injected into the ``Provisioner`` like ``EmailTokenLedger``; the factory wires it over
    ``config.CUSTOMER_MEMBER_INVITES_DIR`` and tests pass their own directory."""

    def __init__(self, path: "str | os.PathLike", *, ttl_s: float = _DEFAULT_TTL_S,
                 max_pending_per_org: int = _DEFAULT_MAX_PENDING_PER_ORG,
                 max_total: int = _DEFAULT_MAX_TOTAL) -> None:
        self.dir = Path(path)
        self.ttl_s = float(ttl_s)
        self.max_pending_per_org = int(max_pending_per_org)
        self.max_total = int(max_total)

    # -- paths / io --------------------------------------------------------------------------------
    def _marker(self, token: str) -> Path:
        digest = hashlib.sha256(str(token).encode("utf-8")).hexdigest()   # fixed [0-9a-f]{64}: no traversal
        return self.dir / digest

    @staticmethod
    def _unlink(path: "str | os.PathLike") -> None:
        try:
            os.unlink(path)
        except OSError:
            pass

    @staticmethod
    def _read(marker: Path) -> "Optional[dict]":
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
                os.write(fd, json.dumps(rec, sort_keys=True).encode("utf-8"))
            finally:
                os.close(fd)
            os.replace(tmp, marker)
            return True
        except OSError:
            return False

    @contextmanager
    def _locked(self) -> "Iterator[None]":
        """An exclusive ``flock`` serialising the mutating ops (create / revoke / accept) across threads and
        processes. Fail-closed where ``flock`` is unavailable."""
        if fcntl is None:  # pragma: no cover - non-POSIX
            raise OSError("no flock on this platform")
        self.dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        fd = os.open(str(self.dir / _LOCK_NAME), os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            yield
        finally:
            os.close(fd)

    # -- predicates --------------------------------------------------------------------------------
    @staticmethod
    def _expires_at(rec: "Optional[dict]") -> "Optional[float]":
        exp = rec.get("expires_at") if isinstance(rec, dict) else None
        return float(exp) if isinstance(exp, (int, float)) and not isinstance(exp, bool) else None

    def _live(self, rec: "Optional[dict]", now: float) -> "TypeGuard[dict]":
        """A pending, unexpired, well-formed invite record."""
        if not isinstance(rec, dict) or rec.get("status") != STATUS_PENDING:
            return False
        exp = self._expires_at(rec)
        if exp is None or now >= exp:
            return False
        return (_is_text(rec.get("org_id")) and _is_text(rec.get("email")) and rec.get("role") in INVITE_ROLES
                and _is_text(rec.get("invite_id")))

    @staticmethod
    def _public(rec: dict) -> dict:
        """The record without any token material (there is none stored) -- the shape list / peek / accept return."""
        return {"invite_id": rec["invite_id"], "org_id": rec["org_id"], "email": rec["email"],
                "role": rec["role"], "created_at": float(rec.get("created_at") or 0.0),
                "expires_at": float(rec.get("expires_at") or 0.0), "status": rec.get("status")}

    def _entries(self) -> "list[tuple[Path, Optional[dict]]]":
        out: "list[tuple[Path, Optional[dict]]]" = []
        try:
            entries = list(os.scandir(self.dir))
        except OSError:
            return out
        for e in entries:
            if e.name == _LOCK_NAME or e.name.endswith(".tmp") or e.name.startswith("."):
                continue
            out.append((Path(e.path), self._read(Path(e.path))))
        return out

    def _sweep(self, now: float) -> int:
        """Reap expired / terminal / unreadable markers; return the count of LIVE (pending, unexpired) markers."""
        live = 0
        for path, rec in self._entries():
            if self._live(rec, now):
                live += 1
            else:
                self._unlink(path)
        return live

    # -- writes (flock-guarded) --------------------------------------------------------------------
    def create(self, org_id: str, email: str, role: str, *, now: "Optional[float]" = None) -> dict:
        """Mint a fresh pending invite for (``org_id``, ``email``, ``role``) and return the public record PLUS the raw
        single-use ``token`` (only its sha256 is persisted). Refuses, nothing written: a role outside ``INVITE_ROLES``
        (``ValueError``), a malformed org/email (``ValueError``), a live pending invite already on file for the same
        (org, email) (``InviteExists``), the per-org pending cap or the whole-store cap (``InviteCapReached``)."""
        if role not in INVITE_ROLES:
            raise ValueError(f"invite role must be one of {sorted(INVITE_ROLES)}")
        oid, mail = str(org_id or ""), str(email or "").strip().lower()
        if not oid or not _is_text(oid):
            raise ValueError("an invite needs the org")
        if not mail or not _is_text(mail) or len(mail) > _MAX_EMAIL_LEN:
            raise ValueError("an invite needs a valid email")
        t = time.time() if now is None else float(now)
        with self._locked():
            total = self._sweep(t)                      # reap first, so caps count only live invites
            if total >= self.max_total:
                raise InviteCapReached("the invite store is full")
            org_live = [rec for _p, rec in self._entries() if self._live(rec, t) and rec.get("org_id") == oid]
            if any(rec.get("email") == mail for rec in org_live):
                raise InviteExists("an invitation to that email is already pending for this workspace")
            if len(org_live) >= self.max_pending_per_org:
                raise InviteCapReached("this workspace has too many pending invitations")
            token = secrets.token_urlsafe(32)           # high-entropy single-use value, never stored raw
            rec = {"v": 1, "invite_id": secrets.token_hex(8), "org_id": oid, "email": mail, "role": role,
                   "created_at": t, "expires_at": t + self.ttl_s, "status": STATUS_PENDING}
            if not self._write_atomic(self._marker(token), rec):
                raise InviteCapReached("the invite could not be stored")
        out = self._public(rec)
        out["token"] = token                            # returned ONCE for the email; never persisted, never logged
        return out

    def revoke(self, org_id: str, invite_id: str, *, now: "Optional[float]" = None) -> "Optional[dict]":
        """Remove the org's live pending invite named by ``invite_id`` and return its public record, or ``None`` when
        there is no such live invite (unknown / already accepted / expired). Scans the bounded directory (the token is
        not known here)."""
        oid, iid = str(org_id or ""), str(invite_id or "")
        if not oid or not iid:
            return None
        t = time.time() if now is None else float(now)
        with self._locked():
            for path, rec in self._entries():
                if (self._live(rec, t) and rec.get("org_id") == oid and rec.get("invite_id") == iid):
                    self._unlink(path)
                    return self._public(rec)
        return None

    def accept(self, token: str, *, now: "Optional[float]" = None) -> "Optional[dict]":
        """Atomically CLAIM the invite named by ``token`` -- flip it ``pending`` -> ``accepted`` under the lock -- and
        return its public record, or ``None`` (fail-closed) when the token names no live pending invite (unknown,
        expired, revoked or already accepted). Single-use: a replay finds it no longer pending. Expired markers are
        reaped. The caller performs the owner-signed grant BEFORE calling this (accept is its commit marker), so a
        crash before the flip leaves the token valid for an idempotent retry."""
        if not isinstance(token, str) or not token:
            return None
        t = time.time() if now is None else float(now)
        marker = self._marker(token)
        with self._locked():
            rec = self._read(marker)
            if rec is None:
                return None
            if not self._live(rec, t):
                exp = self._expires_at(rec)
                if exp is None or t >= exp:
                    self._unlink(marker)                # expired / poisoned: reap + refuse
                return None                             # already accepted / revoked / malformed: refuse
            rec = {**rec, "status": STATUS_ACCEPTED, "accepted_at": t}
            if not self._write_atomic(marker, rec):
                return None                             # could not record the claim: refuse (token stays pending)
            return self._public(rec)

    # -- reads (lenient, never raise) --------------------------------------------------------------
    def peek(self, token: str, *, now: "Optional[float]" = None) -> "Optional[dict]":
        """Validate ``token`` and return its public invite record WITHOUT consuming it (read-only): the basis for the
        commit-marker transaction -- the caller peeks, owner-signs the grant, then ``accept``s. ``None`` for a token
        that names no live pending invite."""
        if not isinstance(token, str) or not token:
            return None
        t = time.time() if now is None else float(now)
        rec = self._read(self._marker(token))
        return self._public(rec) if self._live(rec, t) else None

    def pending_for_org(self, org_id: str, *, now: "Optional[float]" = None) -> "list[dict]":
        """The org's live pending invites (public records, no token), oldest first. Lenient: never raises."""
        oid = str(org_id or "")
        if not oid:
            return []
        t = time.time() if now is None else float(now)
        rows = [self._public(rec) for _p, rec in self._entries()
                if self._live(rec, t) and rec.get("org_id") == oid]
        rows.sort(key=lambda r: (float(r.get("created_at") or 0.0), str(r.get("invite_id"))))
        return rows

    def pending_email_exists(self, org_id: str, email: str, *, now: "Optional[float]" = None) -> bool:
        """True iff the org already has a live pending invite for ``email`` (the provisioner's dedupe pre-check)."""
        oid, mail = str(org_id or ""), str(email or "").strip().lower()
        if not oid or not mail:
            return False
        t = time.time() if now is None else float(now)
        return any(self._live(rec, t) and rec.get("org_id") == oid and rec.get("email") == mail
                   for _p, rec in self._entries())
