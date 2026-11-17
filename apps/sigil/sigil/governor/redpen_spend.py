"""Red-Pen per-repo spend ledger — the per-(org, repo, calendar-month) charged-credits fold + enqueue gate (R2).

A connected repository may carry a monthly spending LIMIT (``monthly_limit_credits`` on its owner-signed
connected-repo record). This module folds what each repository has actually been CHARGED in the current CALENDAR
MONTH (UTC) and is the gate the review enqueue/charge path consults: at the limit it REFUSES NEW reviews and notifies
(decision O-2 — calendar-month reset, refuse-new-let-in-flight-finish, mirroring the wallet's refuse-new-at-limit),
and it RE-ARMS next month automatically (a new month is a new ``month`` key, so its charged total starts at 0).

A charge record is OWNER-SIGNED (``authn`` bare-canonical, like the launch-settled decision record): the money a
review consumed is authoritative, so a forged charge could neither push a repo over its limit (a DoS on reviews) nor
under-report to bypass it. The sovereign settle path appends one charge per settled review (``record_charge`` is the
documented hook R3 calls once a review's exact charge is known from the metered settle); the fold is ADDITIVE and
IDEMPOTENT per (org, repo, nonce), so a retried settle never double-counts. The ``month`` is inside the signed bytes,
pinned at charge time, so a charge always counts for the month it was incurred in.

FATAL-2: SOVEREIGN-only (``assert_no_offense``); imports only ``vigil_core`` + sovereign siblings. The charge is
recorded in CREDITS only (never a currency amount, never an estimate — a review is charged for what it used).
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

from ..reuse import assert_no_offense

assert_no_offense()

from vigil_core import check_connected_repo  # noqa: E402

from . import key_history as _kh  # noqa: E402
from .asset_ownership import _check_org_id  # noqa: E402
from .authn import signed_payload, verify_signed  # noqa: E402
from .identity import owner_keypair, owner_pubkey  # noqa: E402

SIGNAL = "governor.redpen_spend"
_CORE = ("signal", "org_id", "repo", "month", "credits", "nonce", "issued_at")
_LOAD_FROM_VAULT = object()


def month_key(now: float) -> str:
    """The calendar-month bucket (UTC) for ``now`` — ``YYYY-MM``. A charge is pinned to this at record time; a
    read of a later month sees 0 (the limit re-arms each calendar month, decision O-2)."""
    return datetime.fromtimestamp(float(now), tz=timezone.utc).strftime("%Y-%m")


class RedPenSpendLedger:
    def __init__(self, store, *, owner_key=_LOAD_FROM_VAULT, trusted_pubkey: Optional[str] = None):
        self.store = store
        self.owner_key = owner_keypair() if owner_key is _LOAD_FROM_VAULT else owner_key
        self.trusted_pubkey = trusted_pubkey if trusted_pubkey is not None else owner_pubkey()

    # -- owner mutation (the settle hook R3 calls) ----------------------------------------------------
    def record_charge(self, org_id: str, repo: str, credits: int, *, nonce: str, now: float) -> int:
        """Owner-sign ONE review's charge (``credits``, in the calendar month of ``now``) against (org, repo).
        Idempotent per (org, repo, nonce): the fold counts the first record for a nonce and ignores any re-append
        (a retried settle never double-charges). Fail-closed ``ValueError`` on a bad org / repo / credits / nonce or
        a missing signing key. Returns the appended seq."""
        if self.owner_key is None:
            raise ValueError("recording a Red-Pen charge requires the owner signing key")
        oid = _check_org_id(org_id)
        repo_ref = check_connected_repo(repo)
        try:
            c = int(credits)
        except (TypeError, ValueError):
            raise ValueError("credits must be an integer") from None
        if c < 0:
            raise ValueError("credits must be >= 0")
        non = str(nonce or "")
        if not non or ":" in non:
            raise ValueError("nonce must be a non-empty string without ':'")
        core = {"signal": SIGNAL, "org_id": oid, "repo": repo_ref, "month": month_key(now), "credits": c,
                "nonce": non, "issued_at": float(now)}
        payload = {**signed_payload(core, self.owner_key), "by": "owner", "requested_by": "owner",
                   "tier": "A0", "decision": "auto",
                   "reason": f"Red-Pen review charge {c} credit(s) for {repo_ref} (org {oid})"}
        return self.store.append(kind="event", source="governor", actor="WARDEN", payload=payload)

    # -- reads ----------------------------------------------------------------------------------------
    def charged(self, org_id: str, repo: str, *, now: float) -> int:
        """Credits charged to (org, repo) in the CALENDAR MONTH of ``now`` (UTC). DEFAULT 0 (fail-closed) for an
        unknown org/repo. Only VERIFIED owner-signed charges count (a forged charge is inert); each (org, repo,
        nonce) counts once (additive + idempotent)."""
        try:
            oid, repo_ref, month = _check_org_id(org_id), check_connected_repo(repo), month_key(now)
        except ValueError:
            return 0
        resolver = _kh.key_resolver(self.store, current=self.trusted_pubkey)
        total = 0
        seen: set = set()
        for r in self.store.iter_records():
            p = getattr(r, "payload", None)
            if not isinstance(p, dict) or p.get("signal") != SIGNAL:
                continue
            if p.get("org_id") != oid or p.get("repo") != repo_ref or p.get("month") != month:
                continue
            non = p.get("nonce")
            if not isinstance(non, str) or non in seen:
                continue
            if not verify_signed(p, _CORE, resolver.at(r.seq)):
                continue
            c = p.get("credits")
            if not isinstance(c, int) or isinstance(c, bool) or c < 0:
                continue                                 # a non-int / negative credits field is inert, never raises
            seen.add(non)
            total += c
        return total

    def review_refusal(self, org_id: str, repo: str, *, monthly_limit_credits: int, now: float) -> Optional[dict]:
        """The enqueue/charge gate. Returns a refusal ``{refused, reason, notify, charged, limit, month}`` when the
        repo has reached its monthly limit (``charged >= limit``, decision O-2 — the boundary REACHED refuses new
        reviews), else None (allow). ``monthly_limit_credits`` 0 (or less) ⇒ no limit ⇒ always None. ``notify`` is
        True so the caller sends the one at-limit notification; an in-flight review already reserved is unaffected
        (this gate only governs NEW reviews)."""
        try:
            limit = int(monthly_limit_credits)
        except (TypeError, ValueError):
            limit = 0
        if limit <= 0:
            return None
        used = self.charged(org_id, repo, now=now)
        if used < limit:
            return None
        return {"refused": True, "notify": True, "charged": used, "limit": limit, "month": month_key(now),
                "reason": "this repository has reached its monthly review spending limit; new reviews resume next "
                          "month or when the limit is raised"}
