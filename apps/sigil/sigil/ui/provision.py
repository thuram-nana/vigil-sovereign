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

import hashlib
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


def _signup_org_id(token: str) -> str:
    """The org id a signup DETERMINISTICALLY maps to — derived from the (secret, single-use) verify token.
    Being a pure function of the token, a crashed-and-retried `confirm_signup` re-derives the SAME org id,
    so `create_org`/`grant_membership`/`wallet.grant` all re-target the same keys and are idempotent (the
    commit-marker recovery, Finding A). Not guessable without the token; a valid `_TENANT_RE` tenant id."""
    return _ORG_ID_PREFIX + hashlib.sha256(("o:" + str(token)).encode("utf-8")).hexdigest()[:24]


def _signup_username(token: str) -> str:
    """The customer username a signup DETERMINISTICALLY maps to (pure function of the verify token), so a
    retried confirm re-derives the SAME username and reuses the existing account instead of minting a
    second (Finding A idempotency). It also DISTINGUISHES a retry of THIS signup from a genuine duplicate:
    a different signup for the same email derives a different username, so the by-email collision check
    refuses it. Valid `_USERNAME_RE` (alpha-prefixed hex)."""
    return "cust_" + hashlib.sha256(("u:" + str(token)).encode("utf-8")).hexdigest()[:24]


class Provisioner:
    """The owner-signed signing service. Registries + ledgers are INJECTED (the registries carry the owner
    key; the edge never constructs this). `expose_dev_tokens` is a DEV-ONLY escape hatch that returns the
    email token in the response when no real sender is configured — it must stay False in production."""

    def __init__(self, store, *, customers, orgs, wallet, email_tokens, rate_limiter, email_sender,
                 signup_cap_limiter=None, member_limiter=None, trial_credits: int = _DEFAULT_TRIAL_CREDITS,
                 expose_dev_tokens: bool = False, now_fn=time.time):
        self.store = store
        self.customers = customers
        self.orgs = orgs
        self.wallet = wallet
        self.email_tokens = email_tokens
        self.rate_limiter = rate_limiter
        # A SEPARATE, high-ceiling limiter enforcing a GLOBAL signup cap (per window) on top of per-email
        # uniqueness + the per-ip/email rate-limit — a ceiling on trial-credit farming (Finding: trial
        # abuse). None ⇒ no global cap (tests inject a low-cap one; the factory wires a daily cap).
        self.signup_cap_limiter = signup_cap_limiter
        # A SEPARATE per-org member-management limiter (grant/revoke). None ⇒ NO member-mgmt rate limiting
        # (so there is no "checked-but-never-incremented" dead gate — the review's finding); when injected,
        # every member op is both GUARDED and COUNTED against it. The factory wires a per-minute ceiling.
        self.member_limiter = member_limiter
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
               outcome: str = "", reason: str = "", critical: bool = False) -> None:
        """Append one secret-free, field-capped `provision.audit` spine event linking an edge request to the
        owner-signed mint it triggered (the principal's tamper-evident edge→mint audit).

        Finding B — audit durability: for a SECURITY-CRITICAL governance mutation (`critical=True`), the
        audit write is NOT swallowed — a failure PROPAGATES so the operation FAILS CLOSED (the caller sees
        an error and, because the mutations are idempotent, may safely retry). It is written while holding
        the transaction lock, before the signup commit marker, so a committed signup is always audited.
        Only NON-critical telemetry (`critical=False`, e.g. a login outcome) swallows a write failure,
        following a separate availability policy."""
        payload = {
            "signal": "provision.audit", "action": str(action)[:48], "requester": str(requester)[:64],
            "org_id": str(org_id)[:64], "target": str(target)[:64], "outcome": str(outcome)[:32],
            "reason": str(reason)[:160]}
        if critical:
            self.store.append(kind="event", source="provision", actor="WARDEN", payload=payload)  # may raise ⇒ fail-closed
            return
        try:
            self.store.append(kind="event", source="provision", actor="WARDEN", payload=payload)
        except Exception:  # noqa: BLE001 — non-critical telemetry: a write failure never breaks the response
            pass

    def _rate_guard(self, *keys: str, now: float) -> None:
        locked = self.rate_limiter.check(*keys, now=now)
        if locked is not None:
            raise ProvisionRateLimited(locked)

    def _member_rate_guard(self, org_id: str, *, now: float) -> None:
        """Guard-AND-COUNT one member-management op (grant/revoke) against the per-org member limiter. A no-op
        when no `member_limiter` is injected — so there is no dead, never-incremented gate (the review's
        finding). When present: a locked key refuses fail-closed BEFORE the op, and the attempt is RECORDED
        (so the ceiling actually trips — abusive and legitimate calls alike count toward the per-org window)."""
        if self.member_limiter is None:
            return
        locked = self.member_limiter.locked(f"member:org:{org_id}", now=now)
        if locked is not None:
            raise ProvisionRateLimited(locked)
        self.member_limiter.record_failure(f"member:org:{org_id}", now=now)

    def _org_admin_usernames(self, org_id: str) -> "set[str]":
        """The usernames holding an ACTIVE `org_admin` membership in `org_id` (resolved LIVE from the
        membership fold). The basis for last-admin protection: an org must never be left with zero admins, or
        nobody could ever manage its members/billing again (an un-governable, orphaned tenant)."""
        return {m.username for m in self.orgs.memberships(org_id) if m.role == "org_admin"}

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
        """Phase 2 — owner-sign {customer account, org, `org_admin` membership, trial credit} for a VERIFIED
        mailbox as a DURABLE, IDEMPOTENT transaction (Finding A).

        The spine is append-only, so there is no 'rollback'; durability is instead a COMMIT-MARKER
        transaction with idempotent-forward recovery:
          * the verify token is PEEKED (validated, NOT consumed) — proving mailbox control without burning
            the token, so a crash before the commit leaves it valid for a retry;
          * the username and org_id are DETERMINISTIC pure functions of the (secret, single-use) token
            (`_signup_username` / `_signup_org_id`), so every mutation re-targets the SAME keys on a retry
            and each is individually idempotent — `customers.create` is LWW on the fixed username,
            `create_org` / `grant_membership` are LWW on the fixed org_id, and `wallet.grant` dedups on the
            deterministic `entry_id=f"trial:{org_id}"` (wallet._fold's per-(signal,org,entry_id) seen-set),
            so a replayed trial can NEVER double-credit;
          * the owner-signed mutations are appended under the lock, the critical audit is written FAIL-CLOSED
            (Finding B), and ONLY THEN is the token CONSUMED — the consume is the COMMIT MARKER. A crash at
            any point before the consume leaves the token valid; the next attempt re-derives the same ids,
            re-applies every (idempotent) mutation, re-audits, and consumes. A crash AFTER the consume leaves
            a fully-committed, audited signup.
        The role is SERVER-set to `org_admin`; the org_id/username are SERVER-derived (never client values);
        the trial amount is a server constant granted ONLY now (post-verification, anti-Sybil) and bounded by
        the optional GLOBAL signup cap (anti-farming). A DIFFERENT token for an already-registered email
        derives a different username, so the by-email collision check refuses it (no second account)."""
        t = self._now() if now is None else float(now)
        tok = str(token or "")
        email = self.email_tokens.peek(tok, PURPOSE_VERIFY, now=t)   # validate WITHOUT consuming (commit-marker)
        if not email:
            raise ProvisionDenied("invalid or expired verification token")
        username, org_id = _signup_username(tok), _signup_org_id(tok)
        with self._lock:
            # GLOBAL signup cap (anti-trial-farming) — checked under the lock, before any mint. A locked cap
            # refuses fail-closed; the token stays valid (peeked, not consumed), so a legitimate retry after
            # the window succeeds.
            if self.signup_cap_limiter is not None:
                capped = self.signup_cap_limiter.locked("signup:global", now=t)
                if capped is not None:
                    raise ProvisionRateLimited(capped)
            existing = self.customers.by_email(email)
            if existing is not None and existing.username != username:
                # a DIFFERENT signup already owns this email (not an idempotent retry of THIS one) → refuse
                raise ProvisionDenied("an account already exists for this email")
            if existing is None:                            # first attempt — mint the account at the fixed id
                self.customers.create(email, password=password, username=username,
                                      issued_at=self._next_issued())
            # idempotent re-targets: LWW on the deterministic org_id; wallet dedups on the deterministic entry_id
            self.orgs.create_org(org_id, str(org_name or email), owner=username, issued_at=self._next_issued())
            self.orgs.grant_membership(org_id, username, "org_admin", issued_at=self._next_issued())
            self.wallet.grant(org_id, self.trial_credits, "trial", entry_id=f"trial:{org_id}",
                              source_ref="signup", issued_at=self._next_issued())
            # durable audit BEFORE the commit marker (fail-closed): a failure leaves the token valid to retry,
            # and the mutations above are idempotent, so the retry is safe.
            self._audit("signup", requester=username, org_id=org_id, target=username, outcome="created",
                        critical=True)
            # COMMIT MARKER — consume the token LAST (single-use); a replay now finds it already consumed.
            self.email_tokens.consume(tok, PURPOSE_VERIFY, now=t)
            if self.signup_cap_limiter is not None:         # count this signup toward the cap (post-commit)
                self.signup_cap_limiter.record_failure("signup:global", now=t)
        self.email_tokens.revoke_for_email(email)      # drop any other outstanding tokens for this email
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
        password reset. Single-use; the token grants no role by itself.

        SESSION INVALIDATION (second-review Medium): a password reset must also sever any live sessions for
        the account, or a thief who set the new password (or a stale attacker session) survives the reset.
        The `SessionLedger` lives on the KEYLESS customer EDGE, not in this (key-holding) signing service, so
        the division of responsibility is: this service owns the owner-signed credential change and returns
        `{"username", "sessions_must_revoke": True}`; the edge MUST call `SessionLedger.revoke_all(username)`
        on that return before completing the response (wired in the E1 HTTP transport). We also drop every
        outstanding verify/recover token for the email here, so no sibling token survives the reset."""
        t = self._now() if now is None else float(now)
        email = self.email_tokens.consume(str(token or ""), PURPOSE_RECOVER, now=t)
        if not email:
            raise ProvisionDenied("invalid or expired recovery token")
        with self._lock:
            acct = self.customers.by_email(email)
            if acct is None:
                raise ProvisionDenied("no such account")
            self.customers.set_password(acct.username, new_password, issued_at=self._next_issued())
            self._audit("recover", requester=acct.username, target=acct.username, outcome="password_reset",
                        critical=True)
        self.email_tokens.revoke_for_email(email)      # no sibling verify/recover token survives the reset
        return {"username": acct.username, "sessions_must_revoke": True}

    # -- member management (the milestone: an org_admin manages THEIR org) --------------------------
    def grant_member(self, requester: str, requester_org_id: str, member_username: str, role: str, *,
                     ip: str = "", now: "Optional[float]" = None) -> dict:
        """An `org_admin` adds/changes a teammate's role in THEIR org. The service checks
        `admit_customer(requester, org_id, manage_members)` FIRST (fail-closed, before any signature), caps
        the role to the customer-grantable set (never operator/owner → no offense-adjacent authority), then
        OWNER-SIGNS the membership. The requester holds no key — only the authority the gate verifies.

        Hardening (second security review): (D) `requester` is the SERVER-AUTHENTICATED session principal —
        the HTTP edge binds it from the `vigil_customer_session` cookie, NEVER a client-supplied body field —
        so an attacker cannot name another admin's username to borrow authority; (TOCTOU) the authority check
        runs INSIDE the transaction lock, immediately before the owner-signs, so a concurrently-revoked admin
        cannot sign through a stale check; the target must be a real active customer; a change that would
        orphan the org (strip its last `org_admin`) is refused; the op is rate-limited per org."""
        t = self._now() if now is None else float(now)
        if role not in _CUSTOMER_GRANTABLE_ROLES:                        # pure input validation (no state)
            raise ProvisionDenied(f"role must be one of {sorted(_CUSTOMER_GRANTABLE_ROLES)}")
        with self._lock:
            self._member_rate_guard(requester_org_id, now=t)
            if not self.orgs.admit_customer(username=requester, org_id=requester_org_id,
                                            permission="manage_members"):
                self._audit("grant_member", requester=requester, org_id=requester_org_id,
                            target=member_username, outcome="denied")
                raise ProvisionDenied("requester is not an administrator of this org")
            if self.customers.customer(member_username) is None:        # never seat an unknown / foreign id
                raise ProvisionDenied("target is not an active customer account")
            if role != "org_admin" and self._org_admin_usernames(requester_org_id) == {member_username}:
                raise ProvisionDenied("cannot remove the last administrator of the org")   # anti-orphan
            seq = self.orgs.grant_membership(requester_org_id, member_username, role,
                                             issued_at=self._next_issued())
            self._audit("grant_member", requester=requester, org_id=requester_org_id, target=member_username,
                        outcome=f"role={role}", critical=True)
        return {"org_id": requester_org_id, "username": member_username, "role": role, "seq": seq}

    def revoke_member(self, requester: str, requester_org_id: str, member_username: str, *,
                      ip: str = "", now: "Optional[float]" = None) -> dict:
        """R1 — AUTHENTICATED ordinary revocation: an `org_admin` removes a teammate from THEIR org. The
        service checks `admit_customer(requester, org_id, manage_members)` (so a revoke is never an
        anonymous unsigned record), rate-limits, audits, THEN owner-signs the revoke. The unsigned-honored
        fold stays only as the emergency fail-safe backstop beneath this authenticated path.

        Hardening (second security review): `requester` is the server-authenticated session principal (never
        a client field — Finding D); the authority check is INSIDE the lock (no TOCTOU with a concurrent
        revoke of the requester's own admin membership); and the org's SOLE `org_admin` cannot be revoked
        (anti-orphan — the tenant must retain at least one administrator)."""
        t = self._now() if now is None else float(now)
        with self._lock:
            self._member_rate_guard(requester_org_id, now=t)
            if not self.orgs.admit_customer(username=requester, org_id=requester_org_id,
                                            permission="manage_members"):
                self._audit("revoke_member", requester=requester, org_id=requester_org_id,
                            target=member_username, outcome="denied")
                raise ProvisionDenied("requester is not an administrator of this org")
            admins = self._org_admin_usernames(requester_org_id)
            if member_username in admins and len(admins) <= 1:
                raise ProvisionDenied("cannot remove the last administrator of the org")   # anti-orphan
            seq = self.orgs.revoke_membership(requester_org_id, member_username)
            self._audit("revoke_member", requester=requester, org_id=requester_org_id, target=member_username,
                        outcome="revoked", critical=True)
        return {"org_id": requester_org_id, "username": member_username, "seq": seq}


def build_provisioner(store, *, expose_dev_tokens: bool = False, now_fn=time.time) -> Provisioner:
    """Wire a production Provisioner over `store`: the owner-signed registries (their owner key defaults to
    the persisted owner identity — THIS is the only process that holds it), the filesystem email-token +
    login-rate-limit ledgers rooted under SIGIL_HOME (config), and the configured EmailSender
    (OFF-by-default NullEmailSender unless SIGIL_EMAIL_* is set). The keyless customer edge NEVER calls
    this; it reaches the sovereign provisioner routes over loopback + the hop key."""
    from .. import config
    from ..governor.customers import CustomerRegistry
    from ..governor.orgs import OrgRegistry
    from ..governor.wallet import WalletRegistry
    from .email_channel import EmailTokenLedger
    from .login_ratelimit import LoginRateLimiter
    return Provisioner(
        store,
        customers=CustomerRegistry(store),
        orgs=OrgRegistry(store),
        wallet=WalletRegistry(store),
        email_tokens=EmailTokenLedger(config.EMAIL_TOKENS_DIR),
        rate_limiter=LoginRateLimiter(config.LOGIN_RATELIMIT_DIR),
        # the GLOBAL per-rolling-day signup ceiling (anti-trial-farming) and the per-org member-management
        # ceiling — separate limiters under disjoint marker dirs (never couple to the login limiter).
        signup_cap_limiter=LoginRateLimiter(config.SIGNUP_CAP_DIR, max_fails=config.SIGNUP_DAILY_CAP,
                                            window_s=86400.0, base_lock_s=3600.0, max_lock_s=86400.0),
        member_limiter=LoginRateLimiter(config.MEMBER_RATELIMIT_DIR, max_fails=config.MEMBER_OPS_PER_MIN,
                                        window_s=60.0, base_lock_s=60.0, max_lock_s=600.0),
        email_sender=config.email_sender(),
        trial_credits=config.TRIAL_CREDITS,
        expose_dev_tokens=expose_dev_tokens,
        now_fn=now_fn,
    )
