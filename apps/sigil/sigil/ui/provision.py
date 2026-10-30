"""Program Slice E1 — the customer PROVISIONER: the single owner-signed, policy-controlled signing service.

This is the ONLY place the owner key signs on a customer's behalf (the principal's R2 — "the owner key must
not become an ordinary application credential"). The internet-facing customer edge (`custui`, keyless,
:8734) holds NO key; it reaches this service only over the loopback + `VIGIL_PROVISION_HOP_KEY` seam
(wired in the HTTP layer), exactly as the proxy delegates `/api/whoami`. Every authoritative mutation here
is owner‑Ed25519‑signed, authority‑checked, rate‑limited, and audited.

Authority model (maps the principal's table): the TRUST ROOT is the owner key; THIS is the policy signing
service; an ORG ADMIN (an `org_admin` membership) merely *requests*; the AUTHORIZATION ENGINE is
`OrgRegistry.admit_customer` (no global leg); the SECURITY ENGINE (Slice G/G0) independently gates
assessment scope — registering/paying authorizes NO assessment.

Workflows:
  * request_signup / confirm_signup — public self-serve: a verify token proves mailbox control, THEN the
    service owner-signs {customer account, org, `org_admin` membership, trial credit} atomically. The trial
    (real money) is granted ONLY after email verification (anti-Sybil), amount a server constant.
  * login — email+password (constant-time via the decoy), rate-limited + locked out on abuse.
  * request_recover / confirm_recover — single-use recovery token → owner-signed password reset.
  * grant_member / revoke_member — an `org_admin` manages THEIR org's team: the service checks
    `admit_customer(requester, org_id, manage_members)` THEN owner-signs the (capped) membership grant /
    revoke. This is R1's AUTHENTICATED ordinary revocation (never an anonymous unsigned record) and the
    milestone primitive: an org admin invites/manages users without ever touching the owner key, another
    tenant's resources, or any assessment target (the grantable set excludes `operator`/`owner`).

FATAL-2: sovereign-side (`assert_no_offense` at import); no framework/strix.
"""
from __future__ import annotations

import math
import secrets
import threading
import time
from typing import Optional

from ..reuse import assert_no_offense

assert_no_offense()

from .email_channel import PURPOSE_RECOVER, PURPOSE_VERIFY  # noqa: E402

_DEFAULT_TRIAL_CREDITS = 100              # server constant — NO on-the-wire amount decides the trial grant
_ORG_ID_PREFIX = "org_"
# The roles a customer org-admin may grant a teammate: deliberately EXCLUDES `operator` (which carries
# run_engagement) and `owner` — a customer can never hand a teammate any offense‑adjacent or global
# authority (billing-authz != testing-authz). `org_admin` is included so an admin can delegate org admin.
_CUSTOMER_GRANTABLE_ROLES = frozenset({"viewer", "analyst", "org_admin"})


class ProvisionError(Exception):
    """A provisioning request was refused. The HTTP layer maps subclasses to 4xx without leaking internals."""


class ProvisionDenied(ProvisionError):
    """The requester lacks the authority this action requires (fail-closed, before any owner signature)."""


class ProvisionRateLimited(ProvisionError):
    """The per-account/per-IP limiter is locked out. Carries `retry_after` seconds."""

    def __init__(self, retry_after: float):
        super().__init__(f"rate limited; retry after {retry_after:.0f}s")
        self.retry_after = retry_after


def new_org_id() -> str:
    """A fresh, SERVER-generated org id that is a valid `_TENANT_RE` tenant id (canonical, collision-
    resistant, never derived from a customer-supplied label — so an org_id can never collide or traverse).
    `org == tenant_id`, so this is also the CRUCIBLE_TENANT value."""
    return _ORG_ID_PREFIX + secrets.token_hex(12)      # [a-f0-9]{24} after an alpha prefix → safe tenant id


class Provisioner:
    """The owner-signed signing service. Registries + ledgers are INJECTED (the registries carry the owner
    key; the edge never constructs this). `expose_dev_tokens` is a DEV-ONLY escape hatch that returns the
    email token in the response when no real sender is configured — it must stay False in production."""

    def __init__(self, store, *, customers, orgs, wallet, email_tokens, rate_limiter, email_sender,
                 trial_credits: int = _DEFAULT_TRIAL_CREDITS, expose_dev_tokens: bool = False,
                 now_fn=time.time):
        self.store = store
        self.customers = customers
        self.orgs = orgs
        self.wallet = wallet
        self.email_tokens = email_tokens
        self.rate_limiter = rate_limiter
        self.email_sender = email_sender
        self.trial_credits = int(trial_credits)
        self.expose_dev_tokens = bool(expose_dev_tokens)
        self._now = now_fn
        self._lock = threading.Lock()                  # serializes the compound signup transaction (TOCTOU)
        self._last_issued = 0.0

    # -- internals ---------------------------------------------------------------------------------
    def _next_issued(self) -> float:
        """A strictly‑increasing issued_at for every owner-signed grant (the per-key anti-replay high-water
        requires strict monotonicity; two mints in one clock tick must not collide). Caller holds the lock."""
        t = float(self._now())
        nxt = t if t > self._last_issued else math.nextafter(self._last_issued, math.inf)
        self._last_issued = nxt
        return nxt

    def _audit(self, action: str, *, requester: str = "", org_id: str = "", target: str = "",
               outcome: str = "", reason: str = "") -> None:
        """Append one secret-free, field-capped `provision.audit` spine event linking an edge request to the
        owner-signed mint it triggered (the principal's tamper-evident edge→mint audit). Never raises."""
        try:
            self.store.append(kind="event", source="provision", actor="WARDEN", payload={
                "signal": "provision.audit", "action": str(action)[:48], "requester": str(requester)[:64],
                "org_id": str(org_id)[:64], "target": str(target)[:64], "outcome": str(outcome)[:32],
                "reason": str(reason)[:160]})
        except Exception:  # noqa: BLE001 — an audit-write failure must never break the decided action
            pass

    def _rate_guard(self, *keys: str, now: float) -> None:
        locked = self.rate_limiter.check(*keys, now=now)
        if locked is not None:
            raise ProvisionRateLimited(locked)

    # -- signup (two-phase) ------------------------------------------------------------------------
    def request_signup(self, email: str, *, ip: str = "", now: "Optional[float]" = None) -> dict:
        """Phase 1: rate-limit, then issue a single-use verify token and send it. Mints NOTHING yet (no
        account/org/trial), so a flood of requests cannot farm trial credits — only a VERIFIED email in
        phase 2 does. Never reveals whether the email already exists."""
        t = self._now() if now is None else float(now)
        email_l = str(email or "").strip().lower()
        self._rate_guard(f"signup:ip:{ip}", f"signup:email:{email_l}", now=t)
        self.rate_limiter.record_failure(f"signup:ip:{ip}", now=t)   # count every attempt (anti-flood)
        token = self.email_tokens.issue(email_l, PURPOSE_VERIFY, now=t) if email_l else None
        sent = bool(token) and self.email_sender.send(email_l, "Verify your VIGIL email",
                                                      f"Confirm: token {token}") if token else False
        out = {"status": "verification_sent"}          # same response whether or not the email exists
        if token and self.expose_dev_tokens and not sent:
            out["dev_token"] = token                   # DEV ONLY (no real sender) — never populated in prod
        return out

    def confirm_signup(self, token: str, *, password: str, org_name: str, ip: str = "",
                       now: "Optional[float]" = None) -> dict:
        """Phase 2: consume the verify token (proves mailbox control), then OWNER-SIGN
        {customer account, org, `org_admin` membership, trial credit} atomically under the lock. The role is
        SERVER-set to `org_admin` (the signup creator administers their own org); the org_id is
        SERVER-generated (collision-resistant); the trial amount is a server constant. Idempotent via the
        single-use token (a replayed token is already consumed → refused)."""
        t = self._now() if now is None else float(now)
        email = self.email_tokens.consume(str(token or ""), PURPOSE_VERIFY, now=t)
        if not email:
            raise ProvisionDenied("invalid or expired verification token")
        with self._lock:
            if self.customers.by_email(email) is not None:
                raise ProvisionDenied("an account already exists for this email")
            username, _ = self.customers.create(email, password=password, issued_at=self._next_issued())
            org_id = new_org_id()
            self.orgs.create_org(org_id, str(org_name or email), owner=username, issued_at=self._next_issued())
            self.orgs.grant_membership(org_id, username, "org_admin", issued_at=self._next_issued())
            self.wallet.grant(org_id, self.trial_credits, "trial", entry_id=f"trial:{org_id}",
                              source_ref="signup", issued_at=self._next_issued())
        self.email_tokens.revoke_for_email(email)      # drop any other outstanding tokens for this email
        self._audit("signup", requester=username, org_id=org_id, target=username, outcome="created")
        return {"username": username, "org_id": org_id}

    # -- login / recovery --------------------------------------------------------------------------
    def login(self, email: str, password: str, *, ip: str = "", now: "Optional[float]" = None) -> dict:
        """Verify email+password (constant-time via the decoy). Rate-limited + locked out on repeated
        failure (per-email AND per-ip). Returns {username, orgs:[...]} (the orgs the customer is an active
        member of — the edge binds ONE as the session's active org). Raises on lockout / bad credentials."""
        t = self._now() if now is None else float(now)
        email_l = str(email or "").strip().lower()
        self._rate_guard(f"login:email:{email_l}", f"login:ip:{ip}", now=t)
        acct = self.customers.verify_login(email_l, password)
        if acct is None:
            self.rate_limiter.record_failure(f"login:email:{email_l}", now=t)
            self.rate_limiter.record_failure(f"login:ip:{ip}", now=t)
            self._audit("login", target=email_l, outcome="denied")
            raise ProvisionDenied("invalid email or password")
        self.rate_limiter.record_success(f"login:email:{email_l}")
        self.rate_limiter.record_success(f"login:ip:{ip}")
        orgs = [m.org_id for m in self.orgs.memberships() if m.username == acct.username]
        self._audit("login", requester=acct.username, target=acct.username, outcome="ok")
        return {"username": acct.username, "orgs": sorted(orgs)}

    def request_recover(self, email: str, *, ip: str = "", now: "Optional[float]" = None) -> dict:
        """Issue a single-use recovery token for an existing account and send it. Always returns the same
        response (never reveals whether the email exists); only issues a token when the account exists."""
        t = self._now() if now is None else float(now)
        email_l = str(email or "").strip().lower()
        self._rate_guard(f"recover:ip:{ip}", f"recover:email:{email_l}", now=t)
        self.rate_limiter.record_failure(f"recover:ip:{ip}", now=t)
        out = {"status": "recovery_sent"}
        if email_l and self.customers.by_email(email_l) is not None:
            token = self.email_tokens.issue(email_l, PURPOSE_RECOVER, now=t)
            sent = bool(token) and self.email_sender.send(email_l, "Reset your VIGIL password",
                                                          f"Reset: token {token}")
            if token and self.expose_dev_tokens and not sent:
                out["dev_token"] = token               # DEV ONLY
        return out

    def confirm_recover(self, token: str, *, new_password: str, now: "Optional[float]" = None) -> dict:
        """Consume a recovery token (purpose-bound — a verify token is refused here) and OWNER-SIGN the
        password reset. Single-use; the token grants no role by itself."""
        t = self._now() if now is None else float(now)
        email = self.email_tokens.consume(str(token or ""), PURPOSE_RECOVER, now=t)
        if not email:
            raise ProvisionDenied("invalid or expired recovery token")
        with self._lock:
            acct = self.customers.by_email(email)
            if acct is None:
                raise ProvisionDenied("no such account")
            self.customers.set_password(acct.username, new_password, issued_at=self._next_issued())
        self._audit("recover", requester=acct.username, target=acct.username, outcome="password_reset")
        return {"username": acct.username}

    # -- member management (the milestone: an org_admin manages THEIR org) --------------------------
    def grant_member(self, requester: str, requester_org_id: str, member_username: str, role: str, *,
                     ip: str = "", now: "Optional[float]" = None) -> dict:
        """An `org_admin` adds/changes a teammate's role in THEIR org. The service checks
        `admit_customer(requester, org_id, manage_members)` FIRST (fail-closed, before any signature), caps
        the role to the customer-grantable set (never operator/owner → no offense-adjacent authority), then
        OWNER-SIGNS the membership. The requester holds no key — only the authority the gate verifies."""
        t = self._now() if now is None else float(now)
        self._rate_guard(f"member:org:{requester_org_id}", now=t)
        if not self.orgs.admit_customer(username=requester, org_id=requester_org_id, permission="manage_members"):
            self._audit("grant_member", requester=requester, org_id=requester_org_id, target=member_username,
                        outcome="denied")
            raise ProvisionDenied("requester is not an administrator of this org")
        if role not in _CUSTOMER_GRANTABLE_ROLES:
            raise ProvisionDenied(f"role must be one of {sorted(_CUSTOMER_GRANTABLE_ROLES)}")
        with self._lock:
            seq = self.orgs.grant_membership(requester_org_id, member_username, role, issued_at=self._next_issued())
        self._audit("grant_member", requester=requester, org_id=requester_org_id, target=member_username,
                    outcome=f"role={role}")
        return {"org_id": requester_org_id, "username": member_username, "role": role, "seq": seq}

    def revoke_member(self, requester: str, requester_org_id: str, member_username: str, *,
                      ip: str = "", now: "Optional[float]" = None) -> dict:
        """R1 — AUTHENTICATED ordinary revocation: an `org_admin` removes a teammate from THEIR org. The
        service checks `admit_customer(requester, org_id, manage_members)` (so a revoke is never an
        anonymous unsigned record), rate-limits, audits, THEN owner-signs the revoke. The unsigned-honored
        fold stays only as the emergency fail-safe backstop beneath this authenticated path."""
        t = self._now() if now is None else float(now)
        self._rate_guard(f"member:org:{requester_org_id}", now=t)
        if not self.orgs.admit_customer(username=requester, org_id=requester_org_id, permission="manage_members"):
            self._audit("revoke_member", requester=requester, org_id=requester_org_id, target=member_username,
                        outcome="denied")
            raise ProvisionDenied("requester is not an administrator of this org")
        with self._lock:
            seq = self.orgs.revoke_membership(requester_org_id, member_username)
        self._audit("revoke_member", requester=requester, org_id=requester_org_id, target=member_username,
                    outcome="revoked")
        return {"org_id": requester_org_id, "username": member_username, "seq": seq}
