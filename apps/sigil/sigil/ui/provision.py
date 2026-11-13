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

import base64
import hashlib
import math
import secrets
import time
from typing import NoReturn, Optional

from ..reuse import assert_no_offense

assert_no_offense()

from .customer_identity import (CustomerIdentity, IdentityRefused,  # noqa: E402
                                METHOD_GOOGLE_OIDC, METHOD_PASSKEY, PasswordIdentityProvider)
from .email_channel import PURPOSE_RECOVER, PURPOSE_VERIFY  # noqa: E402
from ..spine.store import spine_lock  # noqa: E402  (process-wide, path-keyed RE-ENTRANT txn lock)

_LOCKED_FINDING_BODY = ("Confirmed by the oracle. The proof and the fix are part of the full report: buy credits "
                        "in Billing to unlock it.")
_LOCKED_COMPLETED_BODY = ("An assessment run completed. Every finding is listed in your assessments; buy credits in "
                          "Billing to unlock the full proof and fix.")
_DEFAULT_TRIAL_CREDITS = 100              # server constant — NO on-the-wire amount decides the trial grant
_ORG_ID_PREFIX = "org_"
# The roles a customer org-admin may grant a teammate: deliberately EXCLUDES `operator` (which carries
# run_engagement) and `owner` — a customer can never hand a teammate any offense‑adjacent or global
# authority (billing-authz != testing-authz). `org_admin` is included so an admin can delegate org admin.
_CUSTOMER_GRANTABLE_ROLES = frozenset({"viewer", "analyst", "org_admin"})
# The notification centre returns at most this many items (most-severe-first); ``count`` is the true total
# so the UI badge is honest. A cap bounds the read so a noisy tenant can never return an unbounded list.
_NOTIF_MAX = 100


class ProvisionError(Exception):
    """A provisioning request was refused. The HTTP layer maps subclasses to 4xx without leaking internals."""


class ProvisionDenied(ProvisionError):
    """The requester lacks the authority this action requires (fail-closed, before any owner signature)."""


class ProvisionRateLimited(ProvisionError):
    """The per-account/per-IP limiter is locked out. Carries `retry_after` seconds."""

    def __init__(self, retry_after: float):
        super().__init__(f"rate limited; retry after {retry_after:.0f}s")
        self.retry_after = retry_after


class ProvisionStepUpRequired(ProvisionError):
    """E3c — a sensitive op needs a FRESH step-up second factor (the session's `mfa_at` is absent/stale and
    step-up enforcement is ON). The HTTP layer maps it to 401 with `step_up_required=True` so the SPA prompts
    for a factor and retries. A subclass of ProvisionError (NOT ProvisionDenied) so the transport can map it
    distinctly from an authority denial."""


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


def _federated_username(iss: str, sub: str) -> str:
    """The customer username a Google auto-provision DETERMINISTICALLY maps to — a pure function of the
    STABLE `(iss, sub)` pair (domain-separated `"f:"`, distinct from the `"u:"`/`"o:"` email-signup spaces).
    Determinism makes a crashed-and-retried `oidc_finish` re-target the SAME account/org (idempotent-forward,
    like `confirm_signup`), and lets the anti-takeover collision check distinguish a retry of THIS federated
    provision (same derived username) from a genuine email collision with a different account."""
    return "cust_" + hashlib.sha256(("f:" + str(iss) + "\x00" + str(sub)).encode("utf-8")).hexdigest()[:24]


def _federated_org_id(iss: str, sub: str) -> str:
    """The org id a Google auto-provision DETERMINISTICALLY maps to (pure function of `(iss, sub)`,
    domain-separated `"fo:"`). A valid `_TENANT_RE` tenant id; idempotent re-target on a retry."""
    return _ORG_ID_PREFIX + hashlib.sha256(("fo:" + str(iss) + "\x00" + str(sub)).encode("utf-8")).hexdigest()[:24]


def _trial_ip_bucket(ip) -> "Optional[str]":
    """The per-IP trial-limit bucket for a client address: an IPv4 address as itself, an IPv6 address as its /64
    (one host or VPS usually holds a whole /64, so per-address keys would not limit it), an IPv4-mapped IPv6
    address as the IPv4 address. None when the address is missing or not an IP (the caller withholds the trial)."""
    import ipaddress
    try:
        addr = ipaddress.ip_address(str(ip or "").strip())
    except ValueError:
        return None
    if isinstance(addr, ipaddress.IPv6Address):
        if addr.ipv4_mapped is not None:
            return str(addr.ipv4_mapped)
        return str(ipaddress.IPv6Network((addr, 64), strict=False))
    return str(addr)


class _WithholdAllTrialGrants:
    """The per-IP trial limiter when the limit is ON but `VIGIL_TRIAL_GRANTS_PER_IP` is 0 or less: every preview
    trial is withheld (fail closed), never an unlimited limit."""

    def locked(self, key, *, now=None):
        return 86400.0

    def record_failure(self, key, *, now=None):
        return None


def _sign_monitoring(owner_key, grant):
    """Owner-sign the publishable ``SignedMonitoringAuthority`` for an ACTIVE registry grant. The private key
    is used only inside ``sign_monitoring_authority`` and never written anywhere."""
    from datetime import datetime, timezone
    from vigil_core.monitoring_authority import (MonitoringAuthority, MonitoringMode,
                                                 sign_monitoring_authority)
    if owner_key is None:
        raise ValueError("minting a monitoring authority requires the owner key")
    doc = MonitoringAuthority(
        org_id=grant.org_id, host=grant.host, mode=MonitoringMode(grant.mode),
        not_before=datetime.fromtimestamp(grant.not_before, tz=timezone.utc),
        not_after=datetime.fromtimestamp(grant.not_after, tz=timezone.utc), issued_by="owner")
    return sign_monitoring_authority(doc, {"owner": owner_key.private_key_b64})


def _publish_monitoring(base, org_id: str, host: str, data: bytes):
    """Atomically publish signed public bytes: 0700 dir, 0600 temp file in the same dir, fsync, rename."""
    import os
    from pathlib import Path
    d = Path(base)
    d.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(d, 0o700)
    from ..governor.monitoring_authority import monitoring_filename
    final = d / monitoring_filename(org_id, host)
    tmp = d / (".tmp-" + secrets.token_hex(8))
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, final)
    except BaseException:
        tmp.unlink(missing_ok=True)
        raise
    return final


class Provisioner:
    """The owner-signed signing service. Registries + ledgers are INJECTED (the registries carry the owner
    key; the edge never constructs this). `expose_dev_tokens` is a DEV-ONLY escape hatch that returns the
    email token in the response when no real sender is configured — it must stay False in production."""

    def __init__(self, store, *, customers, orgs, wallet, email_tokens, rate_limiter, email_sender,
                 signup_cap_limiter=None, member_limiter=None, target_fetcher=None, signup_email_limiter=None,
                 customer_credentials=None, oidc_provider=None, mfa_replay=None, signcount=None,
                 trial_credits: int = _DEFAULT_TRIAL_CREDITS, trial_claims=None, trial_launch_limiter=None,
                 trial_ip_limiter=None,
                 expose_dev_tokens: bool = False, now_fn=time.time):
        self.store = store
        self.customers = customers
        self.orgs = orgs
        self.wallet = wallet
        self.email_tokens = email_tokens
        self.rate_limiter = rate_limiter
        # Slice E2a/E2b — the owner-signed customer-credential registry (the (iss,sub) / passkey substrate)
        # and the Google-OIDC identity provider. `customer_credentials` is wired whenever the provisioner is
        # built (cheap, and `finish_login`'s federated branch resolves through it); `oidc_provider` is wired
        # ONLY when `customer_oidc_enabled()` (default OFF ⇒ None ⇒ `oidc_finish` fail-closed, no egress).
        self.customer_credentials = customer_credentials
        self.oidc_provider = oidc_provider
        # Slice E3b — the per-customer TOTP (username, step) replay ledger (a TotpReplayLedger). None ⇒ TOTP
        # verification fail-closed (a broken/absent ledger can never silently DISABLE the replay guard).
        self.mfa_replay = mfa_replay
        # Slice E3b-2 — the per-credential WebAuthn sign-count clone-floor ledger (NON-SIGNED, monotonic).
        # None ⇒ passkey login fail-closed.
        self.signcount = signcount
        # Slice G0 — the ownership-proof FETCHER (reads a customer's published well-known token). None ⇒
        # self-serve ownership verification is OFF (fail-closed: target_verify refuses), the default sovereign
        # egress posture; the factory injects the SSRF-hardened WellKnownFetcher only when the operator opts in.
        self.target_fetcher = target_fetcher
        # A SEPARATE, high-ceiling limiter enforcing a GLOBAL signup cap (per window) on top of per-email
        # uniqueness + the per-ip/email rate-limit — a ceiling on trial-credit farming (Finding: trial
        # abuse). None ⇒ no global cap (tests inject a low-cap one; the factory wires a daily cap).
        self.signup_cap_limiter = signup_cap_limiter
        # Pricing S3 — a SEPARATE per-canonical-mailbox sign-up limiter (its own marker dir, its own threshold).
        # It is checked and counted only AFTER the per-ip guard passed, so a stranger cannot cheaply lock a
        # victim's sign-up from one address. None ⇒ no per-mailbox limit.
        self.signup_email_limiter = signup_email_limiter
        # A SEPARATE per-org member-management limiter (grant/revoke). None ⇒ NO member-mgmt rate limiting
        # (so there is no "checked-but-never-incremented" dead gate — the review's finding); when injected,
        # every member op is both GUARDED and COUNTED against it. The factory wires a per-minute ceiling.
        self.member_limiter = member_limiter
        self.email_sender = email_sender
        # The trial size is validated HERE (fail at boot): an out-of-range value would otherwise half-commit every
        # sign-up — the account/org/membership are appended before wallet.grant refuses it. 0 means "no trial".
        from ..governor.trial_policy import check_trial_credits
        self.trial_credits = check_trial_credits(trial_credits)
        # Pricing S3 — the owner-signed trial-claim ledger (one trial per canonical mailbox). Consulted only while
        # VIGIL_TRIAL_PREVIEW_ENABLED is on; None with the flag on ⇒ no preview trial is granted (fail-closed).
        self.trial_claims = trial_claims
        # Pricing S7 — the GLOBAL daily trial-launch cap (VIGIL_TRIAL_LAUNCH_DAILY_CAP). None ⇒ trial launches are
        # refused (the owner has not set a cap); paid launches never consult it.
        self.trial_launch_limiter = trial_launch_limiter
        # Pricing S3c — an OPT-IN per-client-IP soft limit on preview TRIAL GRANTS (VIGIL_TRIAL_IP_LIMIT_ENABLED).
        # Keyed on the client IP the edge reports (IPv4 /32, IPv6 /64 — `_trial_ip_bucket`); behind Cloudflare
        # that is only the VISITOR's IP when the customer vhost restores it from CF-Connecting-IP (it does, see
        # vigil-customer.nginx.conf). The limiter stores only sha256(key). Over the limit means no trial (the
        # account is still created). The IP is never an identity or a claim key.
        self.trial_ip_limiter = trial_ip_limiter
        self.expose_dev_tokens = bool(expose_dev_tokens)
        self._now = now_fn
        # The compound transactions (confirm_signup / confirm_recover / grant_member / revoke_member) run
        # under the PROCESS-WIDE, path-keyed, RE-ENTRANT spine lock — NOT a per-instance lock. The HTTP
        # transport builds a fresh Provisioner per request (server.py `_provision_post`), so a per-instance
        # `threading.Lock()` would serialize NOTHING across concurrent requests (the keystone red-pen
        # finding): two concurrent confirms could double-mint an account+trial, two concurrent revokes could
        # orphan an org, and the in-lock `admit_customer` TOCTOU guard would be inert. `spine_lock` is shared
        # by every Provisioner over this spine, and its inner `store.append` RE-ENTERS the same lock cleanly
        # (store.py:92), so the read->check->append compound is atomic across request threads.
        self._lock = spine_lock(self.store.path)
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
               outcome: str = "", reason: str = "", critical: bool = False, attestation: bool = False) -> None:
        """Append one secret-free, field-capped `provision.audit` spine event linking an edge request to the
        owner-signed mint it triggered (the principal's tamper-evident edge→mint audit).

        Finding B — audit durability: for a SECURITY-CRITICAL governance mutation (`critical=True`), the
        audit write is NOT swallowed — a failure PROPAGATES so the operation FAILS CLOSED (the caller sees
        an error and, because the mutations are idempotent, may safely retry). It is written while holding
        the transaction lock, before the signup commit marker, so a committed signup is always audited.
        Only NON-critical telemetry (`critical=False`, e.g. a login outcome) swallows a write failure,
        following a separate availability policy."""
        payload: "dict[str, object]" = {
            "signal": "provision.audit", "action": str(action)[:48], "requester": str(requester)[:64],
            "org_id": str(org_id)[:64], "target": str(target)[:64], "outcome": str(outcome)[:32],
            "reason": str(reason)[:160]}
        if attestation:
            # The customer's inline "I am authorized to test this asset" affirmation, recorded on the
            # owner-signed append-only spine as the tamper-evident legal attestation (control of a host is not
            # the same as legal authority to test it) — bound to requester + org + target + this record's ts.
            payload["authorization_affirmed"] = True
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

    def _require_stepup(self, mfa_at, *, now: float) -> None:
        """E3c — refuse a sensitive op unless the session proved a FRESH second factor within the window. A
        NO-OP when enforcement is off (`customer_stepup_required()` False) — BYTE-IDENTICAL to pre-E3c, so the
        existing launch/target/member flows are unchanged by default. When ON, `mfa_at` (the session's step-up
        stamp, carried by the edge from the SERVER-side session — never a client body field) must be present
        and within `CUSTOMER_STEPUP_WINDOW_SECONDS` of `now`; otherwise raise ProvisionStepUpRequired (the edge
        prompts for a factor + retries). Fail-closed: a missing / non-numeric / non-positive mfa_at refuses."""
        from .. import config
        if not config.customer_stepup_required():
            return
        try:
            at = float(mfa_at)
        except (TypeError, ValueError):
            at = 0.0
        if at <= 0.0 or (now - at) > float(config.CUSTOMER_STEPUP_WINDOW_SECONDS):
            raise ProvisionStepUpRequired("a fresh second-factor (step-up) is required for this operation")

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

    def _grant_signup_trial(self, org_id: str, email: str, *, source_ref: str, ip: str = "") -> str:
        """The sign-up trial grant. Caller holds the lock; runs BEFORE the audit and the commit marker, and every
        append is idempotent, so a retry re-applies it safely. Returns "granted", "none" (trial size 0) or
        "unavailable" (preview on and this org / mailbox already had a trial).

        Preview OFF: the legacy grant (entry `trial:<org>`), unchanged — except that an org that already holds a
        `trial-preview:<org>` grant (a retry after the flag was turned off) is not granted a second trial.
        Preview ON: eligible only if the org holds neither trial entry AND the canonical mailbox is unclaimed or
        claimed by this same org; then the mailbox claim is written and the trial granted under
        `trial-preview:<org>`. Not eligible: the account/org/membership still commit, with no trial."""
        if self.trial_credits == 0:
            return "none"
        from .. import config
        legacy, preview = f"trial:{org_id}", f"trial-preview:{org_id}"
        if not config.trial_preview_enabled():
            if self.wallet.has_grant_entry(org_id, preview):
                return "granted"
            self.wallet.grant(org_id, self.trial_credits, "trial", entry_id=legacy, source_ref=source_ref,
                              issued_at=self._next_issued())
            return "granted"
        if self.wallet.has_grant_entry(org_id, preview):
            return "granted"                                    # an idempotent retry of THIS sign-up
        if self.wallet.has_grant_entry(org_id, legacy):
            return self._trial_withheld(org_id, "legacy_trial")
        if self.trial_claims is None:
            return self._trial_withheld(org_id, "no_claim_ledger")
        from ..governor.trial_claim import key_digest
        from ..governor.trial_policy import canonical_email
        ekey = canonical_email(email)
        if not ekey:
            return self._trial_withheld(org_id, "no_mailbox")   # no mailbox to key the one-per-mailbox limit on
        digest = key_digest("email", ekey)
        holder = self.trial_claims.claimant("email", digest)
        if holder is not None and holder != org_id:
            return self._trial_withheld(org_id, "mailbox_claimed")
        ip_key = None
        if holder is None:
            # S3c gates run only for a NEW claim. A mailbox this org already claimed is a retry of a sign-up that
            # stopped between its claim and its grant: it resumes to the grant, whatever the list or the per-IP
            # count says now (re-running them could strand the claim with no trial).
            # A disposable mailbox domain (vendored, sha-pinned list; unavailable list ⇒ no trial) gets no trial.
            from ..governor.disposable_email import is_disposable
            verdict = is_disposable(ekey)
            if verdict is not False:
                return self._trial_withheld(org_id, "disposable" if verdict else "list_unavailable")
            if self.trial_ip_limiter is not None:               # opt-in per-IP soft limit
                bucket = _trial_ip_bucket(ip)
                if bucket is None:
                    return self._trial_withheld(org_id, "ip_unknown")
                ip_key = f"trial:grant:ip:{bucket}"
                if self.trial_ip_limiter.locked(ip_key, now=self._now()) is not None:
                    return self._trial_withheld(org_id, "ip_limit")
            self.trial_claims.claim("email", digest, org_id, issued_at=self._next_issued())
        self.wallet.grant(org_id, self.trial_credits, "trial", entry_id=preview, source_ref=source_ref,
                          issued_at=self._next_issued())
        if self.trial_ip_limiter is not None and ip_key is not None:
            self.trial_ip_limiter.record_failure(ip_key, now=self._now())
        return "granted"

    def _trial_withheld(self, org_id: str, reason: str) -> str:
        """Record why a preview trial was withheld (non-critical telemetry: the operator can see a broken list or
        a mis-set limit instead of trials silently vanishing) and return "unavailable"."""
        self._audit("trial", org_id=org_id, outcome="withheld", reason=reason)
        return "unavailable"

    # -- signup (two-phase) ------------------------------------------------------------------------
    def request_signup(self, email: str, *, ip: str = "", now: "Optional[float]" = None) -> dict:
        """Phase 1: rate-limit, then issue a single-use verify token and send it. Mints NOTHING yet (no
        account/org/trial), so a flood of requests cannot farm trial credits — only a VERIFIED email in
        phase 2 does. Never reveals whether the email already exists."""
        t = self._now() if now is None else float(now)
        email_l = str(email or "").strip().lower()
        self._rate_guard(f"signup:ip:{ip}", f"signup:email:{email_l}", now=t)
        self.rate_limiter.record_failure(f"signup:ip:{ip}", now=t)   # count every attempt (anti-flood)
        if self.signup_email_limiter is not None:
            from ..governor.trial_policy import canonical_email
            ekey = canonical_email(email_l)
            if ekey:
                mkey = f"signup:mailbox:{ekey}"
                locked = self.signup_email_limiter.locked(mkey, now=t)
                if locked is not None:
                    raise ProvisionRateLimited(locked)
                self.signup_email_limiter.record_failure(mkey, now=t)
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
        # NH-2: validate EVERY client-supplied input BEFORE the first owner-signed append. Otherwise an
        # invalid org_name (too long / control chars) would raise inside create_org AFTER customers.create
        # has already minted the account+email binding — a deterministic partial commit that squats the
        # email (a fresh signup derives a different username and is refused). Validating here keeps Finding
        # A's "ONE account / ONE org / ONE trial — or nothing" true for bad input, not only for a crash.
        from ..governor.orgs import _check_org_name
        _check_org_name(str(org_name or email))
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
            trial = self._grant_signup_trial(org_id, email, source_ref="signup", ip=ip)
            # durable audit BEFORE the commit marker (fail-closed): a failure leaves the token valid to retry,
            # and the mutations above are idempotent, so the retry is safe.
            self._audit("signup", requester=username, org_id=org_id, target=username, outcome="created",
                        critical=True)
            # COMMIT MARKER — consume the token LAST (single-use); a replay now finds it already consumed.
            self.email_tokens.consume(tok, PURPOSE_VERIFY, now=t)
            if self.signup_cap_limiter is not None:         # count this signup toward the cap (post-commit)
                self.signup_cap_limiter.record_failure("signup:global", now=t)
        self.email_tokens.revoke_for_email(email)      # drop any other outstanding tokens for this email
        out = {"username": username, "org_id": org_id}
        if trial == "unavailable":
            out["trial"] = "unavailable"                # generic: never says which limit applied
        return out

    # -- login / recovery --------------------------------------------------------------------------
    def login(self, email: str, password: str, *, ip: str = "", now: "Optional[float]" = None) -> dict:
        """Verify email+password (constant-time via the decoy) THROUGH the PasswordIdentityProvider, then the
        shared `finish_login` tail. Rate-limited + locked out on repeated failure (per-email AND per-ip).
        Returns {username, orgs:[...]} (the orgs the customer is an active member of — the edge binds ONE as
        the session's active org). Raises on lockout / bad credentials. Behaviour is identical to the pre-E3a
        inline path; the provider + finish_login seam is what Google-OIDC / passkey login reuse (E2/E3)."""
        t = self._now() if now is None else float(now)
        email_l = str(email or "").strip().lower()
        self._rate_guard(f"login:email:{email_l}", f"login:ip:{ip}", now=t)
        try:
            identity = PasswordIdentityProvider(self.customers).verify(email=email_l, password=password)
        except IdentityRefused:
            self.rate_limiter.record_failure(f"login:email:{email_l}", now=t)
            self.rate_limiter.record_failure(f"login:ip:{ip}", now=t)
            self._audit("login", target=email_l, outcome="denied")
            raise ProvisionDenied("invalid email or password")
        self.rate_limiter.record_success(f"login:email:{email_l}")
        self.rate_limiter.record_success(f"login:ip:{ip}")
        result = self.finish_login(identity)
        self._audit("login", requester=result["username"], target=result["username"], outcome="ok")
        return result

    def finish_login(self, identity: CustomerIdentity) -> dict:
        """The SHARED login tail every method (password / Google-OIDC / passkey) funnels through: resolve a
        provider-verified identity to {username, orgs} — the exact shape the keyless edge mints a customer
        cookie session from (`custui._mint`). Identity is proof of WHO only: the username is resolved from the
        owner-signed CustomerRegistry (NEVER a claim) and the orgs from the owner-signed memberships. No role
        is ever read off `identity`, and a customer never carries a global role (`CustomerPrincipal`). FAIL-
        CLOSED: a verified identity that maps to no ACTIVE customer is refused (mirrors the operator OIDC
        callback's no-owner-signed-account -> refuse)."""
        username = self._resolve_customer_username(identity)
        if username is None or self.customers.customer(username) is None:
            raise ProvisionDenied("no active customer for this verified identity")
        orgs = [m.org_id for m in self.orgs.memberships() if m.username == username]
        return {"username": username, "orgs": sorted(orgs)}

    def _resolve_customer_username(self, identity: CustomerIdentity) -> "Optional[str]":
        """Map a verified CustomerIdentity to a CustomerRegistry username by its resolution key. Password
        resolves by the (already-verified) email. A Google-OIDC identity resolves by the STABLE `(iss, sub)`
        federated binding through the owner-signed customer-credential registry (`by_federated`, fail-closed
        on 0 or an ambiguous >1) — NEVER by the email (an email is only a provisioning hint, so a different
        Google account that happens to share an email can never resolve to someone else's customer). The
        passkey `credential_id` branch arrives in E3b. A method with no wired substrate resolves to None
        (fail-closed, no login) — so the E3a rig (no `customer_credentials`) still refuses an OIDC login."""
        if identity.method == PasswordIdentityProvider.method:
            acct = self.customers.by_email(identity.email or "")
            return acct.username if acct is not None else None
        if identity.method == METHOD_GOOGLE_OIDC:
            if self.customer_credentials is None:
                return None
            return self.customer_credentials.by_federated(identity.federated_iss or "",
                                                          identity.federated_sub or "")
        if identity.method == METHOD_PASSKEY:
            if self.customer_credentials is None:
                return None
            cred = self.customer_credentials.by_credential_id(identity.credential_id or "")
            return cred.username if cred is not None else None
        return None

    # -- Google OIDC login (E2b) -------------------------------------------------------------------
    def oidc_finish(self, *, code: str, code_verifier: str, nonce: str, ip: str = "",
                    now: "Optional[float]" = None) -> dict:
        """E2b — the SECRET-bearing Google-OIDC login tail. The keyless edge already verified the browser
        binding (single-use state + sid-cookie hash) and hops {code, code_verifier, nonce}; THIS owner-key-
        holding service does the secret-bearing token exchange + id_token verification (via
        `GoogleOidcIdentityProvider` — strict `email_verified`, `(iss, sub)` binding, egress host-allowlisted),
        then resolves the verified identity:

          * an EXISTING `(iss, sub)` federated binding → log that customer in (the common case after the
            first sign-in);
          * a FIRST verified sign-in → AUTO-PROVISION a fresh PASSWORDLESS customer + org + trial under the
            SAME global signup cap, and owner-sign the `(iss, sub)` binding. ANTI-TAKEOVER (NON-NEGOTIABLE):
            NEVER auto-attach to an existing PASSWORD account by a matching email — an email collision is
            refused (the human already owns that mailbox's VIGIL account; linking Google to it requires an
            explicit in-session verified link, a later slice). The binding is `(iss, sub)`, never the email.

        Then the SHARED `finish_login` tail → {username, orgs} the keyless edge mints a CUSTOMER cookie from
        (never an operator bearer; `CustomerPrincipal` carries no global role). Fail-closed when customer
        Google sign-in is not enabled/configured (`oidc_provider is None`). The check-then-provision is atomic
        under the spine lock, so two concurrent first-sign-ins of the same Google account mint exactly one
        customer + trial."""
        t = self._now() if now is None else float(now)
        if self.oidc_provider is None or self.customer_credentials is None:
            raise ProvisionError("customer Google sign-in is not enabled on this deployment")
        self._rate_guard(f"oidc:ip:{ip}", now=t)            # best-effort per-ip throttle on the federated attempt
        try:
            identity = self.oidc_provider.verify(code=code, code_verifier=code_verifier, nonce=nonce)
        except IdentityRefused:
            self.rate_limiter.record_failure(f"oidc:ip:{ip}", now=t)
            self._audit("oidc_login", outcome="denied")
            raise ProvisionDenied("google sign-in could not be verified")
        self.rate_limiter.record_success(f"oidc:ip:{ip}")
        iss = identity.federated_iss or ""
        sub = identity.federated_sub or ""
        with self._lock:
            # the (iss,sub) binding is the key — resolved atomically with the potential auto-provision so two
            # concurrent first-sign-ins can't double-mint. An existing binding is a straight login; a missing
            # one auto-provisions (the anti-takeover email-collision gate lives inside).
            if self.customer_credentials.by_federated(iss, sub) is None:
                self._link_or_provision_federated(identity, now=t, ip=ip)
        result = self.finish_login(identity)                # re-resolves by (iss,sub) live; role-free tail
        self._audit("oidc_login", requester=result["username"], target=result["username"], outcome="ok")
        return result

    def _link_or_provision_federated(self, identity: CustomerIdentity, *, now: float, ip: str = "") -> str:
        """Caller holds the lock and has confirmed NO existing `(iss, sub)` binding. AUTO-PROVISION a fresh
        passwordless customer + org + trial for this verified Google identity and owner-sign the `(iss, sub)`
        binding — OR reconcile an in-flight retry (the deterministic federated account already exists, e.g. a
        crash between `create` and `link_federated`). ANTI-TAKEOVER: refuse when the verified email is already
        bound to a DIFFERENT customer (never auto-attach Google to a password account by email); ONLY the
        account this federated identity DETERMINISTICALLY maps to may share the email (the idempotent-retry
        case). Bounded by the GLOBAL signup cap (shared with email signup — one Sybil ceiling on real money).
        Returns the (new or reconciled) username."""
        iss = identity.federated_iss or ""
        sub = identity.federated_sub or ""
        email = (identity.email or "").strip().lower()
        username = _federated_username(iss, sub)
        org_id = _federated_org_id(iss, sub)
        # ANTI-TAKEOVER (NON-NEGOTIABLE): an email already owned by a DIFFERENT customer is NEVER auto-linked.
        # Only THIS federated identity's own deterministic account may carry the email (an idempotent retry).
        if email:
            existing = self.customers.by_email(email)
            if existing is not None and existing.username != username:
                self._audit("oidc_login", target=email, outcome="email_collision")
                raise ProvisionDenied(
                    "an account already exists for this email; sign in with your password, then link Google")
        # GLOBAL signup cap (anti-trial-farming) — the SAME ceiling email signup uses, checked under the lock.
        if self.signup_cap_limiter is not None:
            capped = self.signup_cap_limiter.locked("signup:global", now=now)
            if capped is not None:
                raise ProvisionRateLimited(capped)
        # idempotent-forward mints: LWW on the deterministic ids; wallet dedups on the deterministic entry_id;
        # the passwordless customer is created ONLY if absent (a retry reuses it). password=None ⇒ an
        # OIDC-only customer (no scrypt hash on the spine); the email is the verified Google mailbox.
        if self.customers.customer(username) is None:
            self.customers.create(email or f"{username}@google-oidc.local", password=None, username=username,
                                  issued_at=self._next_issued())
        self.orgs.create_org(org_id, email or username, owner=username, issued_at=self._next_issued())
        self.orgs.grant_membership(org_id, username, "org_admin", issued_at=self._next_issued())
        self._grant_signup_trial(org_id, email, source_ref="signup-google", ip=ip)
        # owner-sign the (iss,sub) binding LAST among the mints (its own global-uniqueness guard refuses a
        # cross-customer rebind): a crash before it leaves by_federated unresolved ⇒ a safe retry re-provisions.
        self.customer_credentials.link_federated(username, iss=iss, sub=sub, issued_at=self._next_issued())
        self._audit("signup", requester=username, org_id=org_id, target=username, outcome="created-google",
                    critical=True)
        if self.signup_cap_limiter is not None:             # count this signup toward the cap (post-commit)
            self.signup_cap_limiter.record_failure("signup:global", now=now)
        return username

    # -- customer MFA: TOTP enroll + verify (E3b) ---------------------------------------------------
    def enroll_totp(self, requester: str, *, ip: str = "", now: "Optional[float]" = None) -> dict:
        """E3b — enroll (or re-enroll) a TOTP second factor for the requesting customer's OWN account. MFA is
        account-level (per customer username), NOT per-org, so the gate is simply that the requester is an
        ACTIVE customer (the edge binds requester from the SESSION, never the body). Generates a fresh secret,
        SEALS it via the owner vault (only the sealed blob reaches the spine — the plaintext is returned ONCE
        for the customer to add to their authenticator app, NEVER persisted), owner-signs the credential (the
        per-(username,"totp") high-water LWW supersedes any prior TOTP), and returns the otpauth:// URI +
        the secret. Fail-closed when customer MFA is not enabled on this deployment."""
        if self.customer_credentials is None:
            raise ProvisionError("customer MFA is not enabled on this deployment")
        acct = self.customers.customer(requester)
        if acct is None:
            raise ProvisionDenied("requester is not an active customer")
        from .. import config
        from ..governor import totp as _totp
        from ..platform.vault import owner_vault
        secret = _totp.generate_secret()
        try:
            blob = owner_vault().seal_secret(secret.encode("utf-8"), context=config.CUSTOMER_TOTP_SEAL_CONTEXT)
        except Exception:  # noqa: BLE001 — VaultLocked (unprovisioned) / seal fault → clean refusal, not a 500
            raise ProvisionError("MFA enrollment is unavailable (the owner vault is not provisioned)") from None
        sealed_b64 = base64.b64encode(blob).decode("ascii")
        with self._lock:
            self.customer_credentials.enroll_totp(requester, sealed_secret=sealed_b64,
                                                  issued_at=self._next_issued())
            self._audit("mfa_enroll_totp", requester=requester, target=requester, outcome="enrolled",
                        critical=True)
        uri = _totp.provisioning_uri(secret, account_name=(acct.email or requester), issuer="VIGIL")
        return {"ok": True, "method": "totp", "provisioning_uri": uri, "secret": secret}

    def verify_mfa(self, requester: str, *, code: str = "", now: "Optional[float]" = None) -> dict:
        """E3b — verify a fresh TOTP code for the requesting customer: the step-up / second-factor PROOF
        primitive E3c consumes. Fail-closed at every step: requester must be an ACTIVE customer with an
        enrolled TOTP; the sealed secret must open under the customer TOTP context; the code must verify
        within the ±1-step skew; and the (username, step) must be UNSPENT in the replay ledger (a TOTP code
        is valid for its whole step, so a sniffed code is otherwise replayable). Returns {ok, method} on
        success; raises ProvisionDenied otherwise. (E3c stamps the session mfa_at from this success and
        enforces freshness at the sensitive ops.)"""
        t = self._now() if now is None else float(now)
        if self.customer_credentials is None or self.mfa_replay is None:
            raise ProvisionError("customer MFA is not enabled on this deployment")
        if self.customers.customer(requester) is None:
            raise ProvisionDenied("requester is not an active customer")
        cred = self.customer_credentials.totp_for(requester)
        if cred is None or not cred.sealed_secret:
            raise ProvisionDenied("no TOTP factor is enrolled")
        from .. import config
        from ..governor import totp as _totp
        from ..platform.vault import owner_vault
        try:
            secret = owner_vault().unseal_secret(base64.b64decode(cred.sealed_secret),
                                                 context=config.CUSTOMER_TOTP_SEAL_CONTEXT).decode("utf-8")
        except Exception:  # noqa: BLE001 — sealed secret unreadable (vault locked / tamper / wrong context)
            raise ProvisionDenied("second-factor verification is unavailable") from None
        step = _totp.verify(secret, code, at=t, window=1)
        if step is None:
            raise ProvisionDenied("invalid or expired TOTP code")
        # Replay guard: consume AFTER a successful verify (an invalid code never touches the ledger), so a
        # code already spent for its (username, step) is refused — mirrors the operator _check_totp ledger.
        if not self.mfa_replay.consume(requester, step):
            raise ProvisionDenied("this TOTP code was already used")
        self._audit("mfa_verify", requester=requester, target=requester, outcome="ok")
        return {"ok": True, "method": "totp"}

    # -- customer passkey: WebAuthn enroll + login (E3b-2) -------------------------------------------
    def enroll_passkey(self, requester: str, *, credential_id: str, public_key_spki_b64: str, cose_alg,
                       uv: bool, client_data_json: str, expected_challenge: str,
                       now: "Optional[float]" = None) -> dict:
        """E3b-2 — register a WebAuthn passkey for the requesting customer's OWN account (account-level; the
        requester is the session/hop principal, never a body field). ``verify_registration`` validates the
        clientDataJSON (type == webauthn.create, challenge, origin in the configured allowlist); the credential
        public key is the WebAuthn-L2 ``getPublicKey()`` DER SubjectPublicKeyInfo the browser supplied (so NO
        attestation-CBOR parse — a bad key only fails that customer's own later login). Owner-signs the
        credential via the E2a ``enroll_passkey`` (its GLOBAL uniqueness refuses a credential_id already bound
        to another customer — the anti-hijack crypto backing). Fail-closed when passkey is not configured."""
        from . import webauthn as _wa
        if self.customer_credentials is None:
            raise ProvisionError("customer passkey is not enabled on this deployment")
        acct = self.customers.customer(requester)
        if acct is None:
            raise ProvisionDenied("requester is not an active customer")
        from .. import config
        origins = config.customer_passkey_origins()
        if not origins:
            raise ProvisionError("customer passkey is not configured (no allowed origins)")
        if not isinstance(cose_alg, int) or isinstance(cose_alg, bool) or int(cose_alg) not in _wa.SUPPORTED_ALGS:
            raise ProvisionDenied("unsupported passkey algorithm")
        try:
            cdj = _wa.b64url_decode(client_data_json)
            spki = base64.b64decode(str(public_key_spki_b64 or ""), validate=True)
        except Exception:  # noqa: BLE001 — malformed registration material → clean refusal
            raise ProvisionDenied("malformed passkey registration") from None
        if not spki:
            raise ProvisionDenied("empty passkey public key")
        reason = _wa.verify_registration(client_data_json=cdj, expected_challenge=expected_challenge,
                                         allowed_origins=origins)
        if reason is not None:
            raise ProvisionDenied(f"passkey registration refused ({reason})")
        with self._lock:
            try:
                self.customer_credentials.enroll_passkey(
                    requester, credential_id, cose_alg=int(cose_alg),
                    public_key_spki_b64=str(public_key_spki_b64), uv=bool(uv), issued_at=self._next_issued())
            except ValueError as e:                            # global-uniqueness / shape refusal
                raise ProvisionDenied(str(e)) from None
            self._audit("passkey_enroll", requester=requester, target=requester, outcome="enrolled",
                        critical=True)
        return {"ok": True, "method": "passkey", "credential_id": credential_id}

    def passkey_login(self, *, credential_id: str, authenticator_data: str, client_data_json: str,
                      signature: str, expected_challenge: str, ip: str = "",
                      now: "Optional[float]" = None) -> dict:
        """E3b-2 — a full passkey LOGIN (a standalone method, like OIDC). Resolve the customer by
        ``credential_id`` (fail-closed on 0 / an ambiguous >1 — A's credential never resolves to B), VERIFY the
        WebAuthn assertion (signature over authenticatorData ‖ sha256(clientDataJSON); clientData
        type/challenge/origin; rpIdHash == sha256(rp_id); user-presence; the sign-count clone-floor), BUMP the
        non-signed floor, then the SHARED ``finish_login`` tail -> {username, orgs} the keyless edge mints a
        CUSTOMER cookie from (never an operator bearer). A PURE signature check — NO owner re-sign. Fail-closed
        when passkey is not enabled/configured."""
        t = self._now() if now is None else float(now)
        from . import webauthn as _wa
        if self.customer_credentials is None or self.signcount is None:
            raise ProvisionError("customer passkey is not enabled on this deployment")
        self._rate_guard(f"passkey:ip:{ip}", now=t)            # best-effort per-ip throttle
        from .. import config
        rp_id, origins = config.customer_passkey_rp_id(), config.customer_passkey_origins()
        if not rp_id or not origins:
            raise ProvisionError("customer passkey is not configured")
        cred = self.customer_credentials.by_credential_id(credential_id)
        if cred is None or not cred.public_key_spki_b64 or cred.cose_alg is None:
            self.rate_limiter.record_failure(f"passkey:ip:{ip}", now=t)
            self._audit("passkey_login", outcome="denied")
            raise ProvisionDenied("passkey not recognised")
        try:
            spki = base64.b64decode(cred.public_key_spki_b64)
            ad = _wa.b64url_decode(authenticator_data)
            cdj = _wa.b64url_decode(client_data_json)
            sig = _wa.b64url_decode(signature)
        except Exception:  # noqa: BLE001 — malformed assertion material → clean refusal
            raise ProvisionDenied("malformed passkey assertion") from None
        res = _wa.verify_assertion(
            spki_der=spki, cose_alg=int(cred.cose_alg), authenticator_data=ad, client_data_json=cdj,
            signature=sig, expected_challenge=expected_challenge, allowed_origins=origins, rp_id=rp_id,
            stored_sign_count=self.signcount.floor(credential_id), require_uv=False)
        if not res.ok:
            self.rate_limiter.record_failure(f"passkey:ip:{ip}", now=t)
            self._audit("passkey_login", outcome=f"denied:{res.reason}")
            raise ProvisionDenied("passkey assertion could not be verified")
        self.rate_limiter.record_success(f"passkey:ip:{ip}")
        self.signcount.bump(credential_id, res.sign_count)       # advance the non-signed clone-floor
        result = self.finish_login(CustomerIdentity(method=METHOD_PASSKEY, credential_id=credential_id))
        self._audit("passkey_login", requester=result["username"], target=result["username"], outcome="ok")
        return result

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
                     ip: str = "", mfa_at: float = 0.0, now: "Optional[float]" = None) -> dict:
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
            if not self.orgs.admit_customer(username=requester, org_id=requester_org_id,
                                            permission="manage_members"):
                self._audit("grant_member", requester=requester, org_id=requester_org_id,
                            target=member_username, outcome="denied")
                raise ProvisionDenied("requester is not an administrator of this org")
            self._require_stepup(mfa_at, now=t)      # E3c: a fresh step-up (no-op unless enforcement is on)
            # P6: meter AUTHORIZED churn only — the rate guard records AFTER admit_customer, so a non-admin
            # cannot burn the per-org member budget and lock the real admin out (the limiter's finding).
            self._member_rate_guard(requester_org_id, now=t)
            if self.customers.customer(member_username) is None:        # never seat an unknown / foreign id
                raise ProvisionDenied("target is not an active customer account")
            if role != "org_admin" and self._org_admin_usernames(requester_org_id) == {member_username}:
                raise ProvisionDenied("cannot remove the last administrator of the org")   # anti-orphan
            # NH-3: durable audit BEFORE the owner-signed mutation — a critical-audit store failure then fails
            # CLOSED with no membership change (committed⟹audited), mirroring the signup audit-before-commit.
            self._audit("grant_member", requester=requester, org_id=requester_org_id, target=member_username,
                        outcome=f"role={role}", critical=True)
            seq = self.orgs.grant_membership(requester_org_id, member_username, role,
                                             issued_at=self._next_issued())
        return {"org_id": requester_org_id, "username": member_username, "role": role, "seq": seq}

    def revoke_member(self, requester: str, requester_org_id: str, member_username: str, *,
                      ip: str = "", mfa_at: float = 0.0, now: "Optional[float]" = None) -> dict:
        """R1 — AUTHENTICATED ordinary revocation: an `org_admin` removes a teammate from THEIR org. The
        service checks `admit_customer(requester, org_id, manage_members)` (so a revoke is never an
        anonymous unsigned record), rate-limits, audits, THEN owner-signs the revoke. The unsigned-honored
        fold stays only as the emergency fail-safe backstop beneath this authenticated path.

        Hardening (second security review): `requester` is the server-authenticated session principal (never
        a client field — Finding D); the authority check is INSIDE the lock (no TOCTOU with a concurrent
        revoke of the requester's own admin membership); and the org's SOLE `org_admin` cannot be revoked
        (anti-orphan — the tenant must retain at least one administrator)."""
        t = self._now() if now is None else float(now)
        from ..governor.orgs import _check_member_username
        _check_member_username(member_username)          # NH-3 prep: validate target shape before any audit
        with self._lock:
            if not self.orgs.admit_customer(username=requester, org_id=requester_org_id,
                                            permission="manage_members"):
                self._audit("revoke_member", requester=requester, org_id=requester_org_id,
                            target=member_username, outcome="denied")
                raise ProvisionDenied("requester is not an administrator of this org")
            self._require_stepup(mfa_at, now=t)      # E3c: a fresh step-up (no-op unless enforcement is on)
            self._member_rate_guard(requester_org_id, now=t)   # P6: meter AUTHORIZED churn only (after admit)
            admins = self._org_admin_usernames(requester_org_id)
            if member_username in admins and len(admins) <= 1:
                raise ProvisionDenied("cannot remove the last administrator of the org")   # anti-orphan
            # NH-3: durable critical audit BEFORE the owner-signed revoke (fail-closed; committed⟹audited).
            self._audit("revoke_member", requester=requester, org_id=requester_org_id, target=member_username,
                        outcome="revoked", critical=True)
            seq = self.orgs.revoke_membership(requester_org_id, member_username)
        return {"org_id": requester_org_id, "username": member_username, "seq": seq}

    # -- asset-ownership target registration (Slice G0 — billing != testing) ------------------------
    def target_challenge(self, requester: str, requester_org_id: str, host: str, *,
                         ip: str = "", now: "Optional[float]" = None) -> dict:
        """Issue an owner-signed ownership CHALLENGE for (org, host) and return the placement instructions the
        customer must publish. Gated on ``admit_customer(requester, org_id, run_engagement)`` — the
        TESTING-authority axis, NOT billing: a pure billing admin (``org_admin``, no ``run_engagement``)
        cannot register assessment targets, so registering/paying is not authorizing a test. The requester +
        org are the SERVER-AUTHENTICATED session principal (never client body fields). A challenge grants
        nothing — it is only the token the later verdict checks against. (``now`` is accepted for API
        symmetry with ``target_verify``; a challenge's anti-replay stamp comes from ``_next_issued``.)"""
        from ..governor.asset_ownership import AssetOwnershipRegistry
        with self._lock:
            if not self.orgs.admit_customer(username=requester, org_id=requester_org_id,
                                            permission="run_engagement"):
                self._audit("target_challenge", requester=requester, org_id=requester_org_id,
                            target=host, outcome="denied")
                raise ProvisionDenied("requester may not register assessment targets for this org")
            try:
                ch = AssetOwnershipRegistry(self.store).issue_challenge(
                    requester_org_id, host, issued_at=self._next_issued())
            except ValueError as e:
                raise ProvisionDenied(str(e)) from None
            self._audit("target_challenge", requester=requester, org_id=requester_org_id,
                        target=host, outcome="issued")
        return {"host": ch.host, "dns_name": ch.dns_name, "dns_value": ch.marker,
                "well_known_url": ch.well_known_url, "well_known_body": ch.marker,
                "meta_tag": ch.meta_tag, "marker": ch.marker}

    def launch_reserve(self, requester: str, requester_org_id: str, host: str, *,
                       product_id: str = "", ip: str = "", mfa_at: float = 0.0,
                       now: "Optional[float]" = None) -> dict:
        """Reserve credits + mint a launch lease for ONE offense launch against (org, host). Delegates to the
        LaunchGate, which composes admit_customer(run_engagement) + a current ownership proof + a verifying
        owner-signed EngagementAuthority + a sufficient credit balance, then reserves + mints under the spine
        lock. requester/org are the SERVER-authenticated session principal (never body fields).

        The credit ``units`` are SERVER-decided and never a customer-supplied amount (money doctrine). EC-7b:
        a customer MAY pick a tiered launch PRODUCT (``product_id`` — e.g. the Quick/Deep scan); the units it
        reserves come from the OWNER CATALOG (``catalog.launch_product``), exactly as ``price_id`` maps to
        credits — the customer names a product, never a number. An unknown / not-offered ``product_id`` is
        REFUSED fail-closed (never a silent fallback to a different tier). No ``product_id`` ⇒ the default
        per-launch units (``config.LAUNCH_UNITS``), byte-identical to pre-EC-7b. The run tier is then DERIVED
        at engage time from these signed units (vigil_core.run_tier), so the product choice flows through the
        already-signed ``units_reserved`` — no new signed field. Returns the signed lease for the edge to
        relay; the offense launch verifies it before any traffic."""
        t = self._now() if now is None else float(now)
        from .. import config
        from ..governor import catalog
        from .launch_gate import LaunchGate
        # E3c red-pen fold: gate step-up AFTER authority, never before (non-negotiable #5 — a non-member is
        # refused by admit, NOT told to step up) and consistent with launch_cancel/launch_start. launch_reserve
        # has no local admit (the authoritative one lives in LaunchGate.reserve_launch), so do a run_engagement
        # admit check here FIRST, then the step-up freshness gate; the LaunchGate then re-runs the full chain
        # (admit + ownership + authority + credits) authoritatively.
        with self._lock:
            if not self.orgs.admit_customer(username=requester, org_id=requester_org_id,
                                            permission="run_engagement"):
                self._audit("launch_reserve", requester=requester, org_id=requester_org_id,
                            target=host, outcome="denied")
                raise ProvisionDenied("requester may not launch assessments for this org")
            self._require_stepup(mfa_at, now=t)      # E3c: AFTER admit (no-op unless enforcement is on)
        # EC-7b: resolve the reserved units from the chosen PRODUCT via the owner catalog (AFTER authz).
        # Fail-closed on an unknown / not-offered product; empty product_id keeps the default units.
        units = int(config.LAUNCH_UNITS)
        pid = str(product_id or "").strip()
        if pid:
            product = catalog.launch_product(pid)    # None when unknown, not offered, or EC-7 flag off
            if product is None:
                self._audit("launch_reserve", requester=requester, org_id=requester_org_id,
                            target=host, outcome="denied")
                raise ProvisionDenied(f"unknown or unavailable launch product: {pid!r}")
            units = int(product.units)
        if self._preview_locked(requester_org_id):
            # Pricing S7: a locked trial org — trial product only, one registrable domain (first claim wins,
            # with proof history), and the global daily cap. The checks AND the reserve run under ONE hold of
            # the re-entrant spine lock (LaunchGate takes the same lock), so nothing lands in between.
            with self._lock:
                domain = self._trial_launch_check(requester, requester_org_id, host, pid, now=t)
                r = LaunchGate(self.store).reserve_launch(
                    requester=requester, org_id=requester_org_id, host=host, units=units, now=t)
                if r.get("ok"):
                    self._trial_launch_commit(requester_org_id, domain, now=t)
        else:
            r = LaunchGate(self.store).reserve_launch(
                requester=requester, org_id=requester_org_id, host=host, units=units, now=t)
        if not r.get("ok"):
            self._audit("launch_reserve", requester=requester, org_id=requester_org_id,
                        target=host, outcome="denied")
            raise ProvisionDenied(str(r.get("error") or "launch reservation refused"))
        self._audit("launch_reserve", requester=requester, org_id=requester_org_id, target=host,
                    outcome="reserved", critical=True)
        out = {k: r[k] for k in ("slug", "host", "units_reserved", "nonce", "not_before", "not_after",
                                 "lease", "trust_root") if k in r}
        if pid:
            out["product_id"] = pid                  # echo the resolved product for the edge/UI
        return out

    def _trial_launch_refuse(self, requester: str, org_id: str, host: str, reason: str, text: str) -> "NoReturn":
        self._audit("launch_reserve", requester=requester, org_id=org_id, target=host,
                    outcome="trial_refused", reason=reason)
        raise ProvisionDenied(text)

    def _trial_launch_check(self, requester: str, org_id: str, host: str, pid: str, *, now: float) -> str:
        """Caller holds the lock. Refuses (generic text, never naming another org) unless: the trial product is
        configured and is the one requested; the host has an ICANN registrable domain (not an IP, localhost, or
        a free-subdomain platform under a PRIVATE suffix; the vendored list's sha256 matches); no other org
        claims that domain, or — with no claim yet — no other org has EVER held a signed proof in it; this org
        claims no other domain; and the daily cap is configured and not reached. Returns the domain."""
        from .. import config
        from ..governor.asset_ownership import AssetOwnershipRegistry
        from ..governor.registrable_domain import TrialDomainRefused, load_rules, same_domain, trial_domain
        from ..governor.trial_claim import key_digest
        product = config.trial_product_id()
        if not product or self.trial_claims is None or self.trial_launch_limiter is None:
            self._trial_launch_refuse(requester, org_id, host, "trial_not_configured",
                                      "trial scans are not available yet — buy credits to scan")
        if pid != product:
            self._trial_launch_refuse(requester, org_id, host, "trial_product_only",
                                      "your trial covers the trial scan only — buy credits for other scans")
        rules = load_rules()
        try:
            domain = trial_domain(host, rules=rules)
        except TrialDomainRefused as exc:
            self._trial_launch_refuse(requester, org_id, host, exc.reason,
                                      "trial scans need your own registered domain — buy credits to scan it")
        digest = key_digest("domain", domain)
        holder = self.trial_claims.claimant("domain", digest)
        if holder is not None and holder != org_id:
            self._trial_launch_refuse(requester, org_id, host, "domain_claimed",
                                      "trial scans are limited to one workspace per domain — buy credits to "
                                      "scan it")
        if any(k == "domain" and d != digest for k, d in self.trial_claims.claims_of(org_id)):
            self._trial_launch_refuse(requester, org_id, host, "second_domain",
                                      "your trial covers one domain — buy credits to scan another")
        if holder is None:
            for o, h in AssetOwnershipRegistry(self.store, owner_key=None).ever_proven_pairs():
                if o != org_id and same_domain(h, domain, rules=rules):
                    self._trial_launch_refuse(requester, org_id, host, "domain_history",
                                              "trial scans are limited to one workspace per domain — buy "
                                              "credits to scan it")
        if self.trial_launch_limiter.locked("trial:launch:global", now=now) is not None:
            self._trial_launch_refuse(requester, org_id, host, "daily_cap",
                                      "trial scans are paused for today — try again later or buy credits")
        return domain

    def _trial_launch_commit(self, org_id: str, domain: str, *, now: float) -> None:
        """After a successful trial reserve (lock held): write the domain claim (first wins) and count the cap."""
        from ..governor.trial_claim import key_digest
        digest = key_digest("domain", domain)
        if self.trial_claims.claimant("domain", digest) is None:
            self.trial_claims.claim("domain", digest, org_id, issued_at=self._next_issued())
        self.trial_launch_limiter.record_failure("trial:launch:global", now=now)

    # CHK-1 red-pen MED: every checkout is an OUTBOUND POST signed with the owner's processor key (and the webhook
    # drain's /verify shares that key's quota), so creation is rate-limited per ORG and per REQUESTER. In-memory
    # (a restart resets the window) — a bound on abuse, not an accounting record.
    _CHECKOUT_MAX = 10
    _CHECKOUT_WINDOW_S = 600.0

    def _checkout_rate_ok(self, keys, now: float) -> bool:
        """Sliding-window limiter (call under ``self._lock``). True + records the attempt iff EVERY key is under
        ``_CHECKOUT_MAX`` attempts in the last ``_CHECKOUT_WINDOW_S`` seconds."""
        win = self.__dict__.setdefault("_checkout_attempts", {})
        cutoff = now - self._CHECKOUT_WINDOW_S
        for k in keys:
            win[k] = [t for t in win.get(k, []) if t > cutoff]
        if any(len(win[k]) >= self._CHECKOUT_MAX for k in keys):
            return False
        for k in keys:
            win[k].append(now)
        return True

    def _checkout_provider(self):
        """The outbound hosted-checkout provider (Front B CHK-1), or None when the owner has not provisioned the
        processor secrets. Overridable (tests inject a fake: ``self._checkout_provider = lambda: provider``). The
        verif-hash secret and the processor key are read from the environment and never logged or returned.

        ``VIGIL_BILLING_PROVIDER`` picks the processor: unset or ``flutterwave`` is the Flutterwave provider below;
        ``stripe`` is :meth:`_stripe_checkout_provider`; any other value is "not configured" (None) — never a
        fallback to the other processor, which would take a payment the configured drain does not credit."""
        import os as _os
        choice = (_os.environ.get("VIGIL_BILLING_PROVIDER") or "").strip().lower()
        if choice == "stripe":
            return self._stripe_checkout_provider()
        if choice not in ("", "flutterwave"):
            return None
        secret = (_os.environ.get("VIGIL_BILLING_WEBHOOK_SECRET") or "").strip()
        if not secret or not (_os.environ.get("VIGIL_FLW_SECRET_KEY") or "").strip():
            return None
        from ..governor import flutterwave_egress as fe
        from ..governor.billing import FlutterwaveBillingProvider
        return FlutterwaveBillingProvider(secret, fe.make_transaction_verifier(),
                                          checkout_creator=fe.make_checkout_creator())

    @staticmethod
    def _stripe_checkout_provider():
        """The Stripe hosted-checkout provider, or None unless every precondition of the Stripe lane holds: the
        adapter opt-in (``VIGIL_BILLING_ENABLE_STRIPE``), the Stripe webhook secret (the drain that credits these
        payments needs it), the API key with a recognisable live/test mode, and a pinned API version. Plan
        periods come from the owner catalog. Secrets are read from the environment and never logged or returned."""
        import os as _os
        if (_os.environ.get("VIGIL_BILLING_ENABLE_STRIPE") or "").strip().lower() not in ("1", "true", "yes"):
            return None
        whsec = (_os.environ.get("VIGIL_STRIPE_WEBHOOK_SECRET") or "").strip()
        from ..governor import stripe_egress as se
        mode = se.stripe_key_mode()
        if not whsec or not se.stripe_secret_configured() or mode is None:
            return None
        try:
            se._api_version()
        except se.StripeEgressError:
            return None
        from ..governor import catalog
        from ..governor.billing import EVENT_SUBSCRIPTION_ACTIVE, StripeBillingProvider
        periods = {pid: ent.period_s for pid, ent in catalog.entitlements().items()
                   if ent.kind == EVENT_SUBSCRIPTION_ACTIVE}
        return StripeBillingProvider(whsec, fetcher=se.make_object_fetcher(), expected_mode=mode,
                                     checkout_creator=se.make_checkout_creator(), plan_periods=periods)

    @staticmethod
    def _checkout_offered() -> "tuple[dict, dict]":
        """The ONE definition of what a customer may buy through hosted checkout: ``(offered, entitlements)``
        where ``offered`` is ``{price_id: (amount_minor, currency)}`` from the OWNER catalog. Shared by
        ``billing_checkout`` (which refuses anything outside it) and the ``billing_offers`` read (which lists
        exactly it), so the UI can never show a buy button that checkout would refuse. Top-ups always; credit
        SUBSCRIPTION plans only with the extra plan flag; NEVER the AEGIS monitoring plans (the billing drain
        does not wire the monitoring line, so one would be charged for nothing)."""
        from .. import config
        from ..governor import catalog
        from ..governor.billing import EVENT_SUBSCRIPTION_ACTIVE, EVENT_TOPUP
        ents = catalog.entitlements()
        sellable = {EVENT_TOPUP} | ({EVENT_SUBSCRIPTION_ACTIVE} if config.customer_plan_checkout_enabled() else set())
        monitoring = catalog.monitoring_price_ids()
        offered = {pid: amt for pid, amt in catalog.expected_amounts().items()
                   if getattr(ents.get(pid), "kind", None) in sellable and pid not in monitoring}
        return offered, ents

    def _org_has_live_plan(self, org_id: str, t: float) -> bool:
        """True iff the org already holds a credit plan that is active or past_due and not yet expired — the
        CHK-1b double-billing guard (checkout refuses a second plan; the offers read reports it so the UI does not
        offer one)."""
        from ..governor.subscription import STATUS_ACTIVE, STATUS_PAST_DUE, SubscriptionRegistry
        cur = SubscriptionRegistry(self.store).subscription(org_id)
        return cur is not None and cur.status in (STATUS_ACTIVE, STATUS_PAST_DUE) and t < float(cur.period_end)

    def customer_billing_offers(self, requester: str, requester_org_id: str, *, ip: str = "",
                                now: "Optional[float]" = None) -> dict:
        """Front B CHK-2 — what THIS customer can buy right now, for the billing page's buy buttons. Gated exactly
        like checkout: the checkout flag (default-OFF), then ``admit_customer(manage_billing)`` for the SESSION org
        (a role that cannot spend money is not shown a price list it cannot use). Lists precisely the shared
        ``_checkout_offered`` set (owner catalog prices — never a client-supplied amount) and whether the org
        already holds a live plan (so the UI offers top-ups only, matching checkout's second-plan refusal). Reads
        only: mints nothing, touches no owner key."""
        from .. import config
        if not config.customer_checkout_enabled():
            raise ProvisionDenied("customer checkout is not enabled")
        t = self._now() if now is None else float(now)

        def project(_store, org_id: str) -> dict:
            from ..governor import catalog
            offered, _ents = self._checkout_offered()
            items = [p for p in catalog.plans() if p.get("price_id") in offered]
            return {"offers": items, "has_active_plan": self._org_has_live_plan(org_id, t),
                    "plans_enabled": bool(config.customer_plan_checkout_enabled())}
        return self._customer_read(requester, requester_org_id, "manage_billing", project)

    def billing_checkout(self, requester: str, requester_org_id: str, price_id: str, *, ip: str = "",
                         mfa_at: float = 0.0, now: "Optional[float]" = None) -> dict:
        """Front B CHK-1 — open a HOSTED CHECKOUT so a customer can pay for a catalog item (top-up / plan).

        Gated on ``customer_checkout_enabled()`` (default-OFF → unknown-action 404), then ADMIT-FIRST:
        ``admit_customer(manage_billing)`` binds the requester to THEIR org (``create_checkout`` binds the org into
        the tx_ref but explicitly does NOT authorize — this is the edge it delegates to; an ``operator`` who runs
        tests cannot spend money, a billing ``org_admin`` can, billing-authz != testing-authz), then a fresh
        step-up and a per-org / per-requester rate limit. MONEY DOCTRINE: the customer names only a catalog
        ``price_id``; the AMOUNT is the owner catalog's, an unknown price is refused, and NOTHING is credited here —
        credit comes ONLY from the verified inbound webhook drain. TOP-UPS ONLY (red-pen HIGH): a subscription plan
        sold through this ONE-TIME payment would carry no ``payment_plan``, so the inbound mapper would treat it as a
        top-up of a non-top-up price and mint NOTHING — the customer charged, granted nothing. Plans need the
        recurring payment-plan flow (a separate slice), so only ``topup_purchased`` entries are offered. Fail-closed: flag off, not admitted, no step-up, processor not
        provisioned, an invalid return URL, or any provider refusal raises ``ProvisionDenied``."""
        from .. import config
        if not config.customer_checkout_enabled():
            raise ProvisionDenied("customer checkout is not enabled")
        t = self._now() if now is None else float(now)
        with self._lock:
            if not self.orgs.admit_customer(username=requester, org_id=requester_org_id,
                                            permission="manage_billing"):
                self._audit("billing_checkout", requester=requester, org_id=requester_org_id, outcome="denied")
                raise ProvisionDenied("requester may not manage billing for this org")
            self._require_stepup(mfa_at, now=t)      # E3c: a fresh step-up (no-op unless enforcement is on)
            if not self._checkout_rate_ok((("org", requester_org_id), ("user", requester)), t):
                self._audit("billing_checkout", requester=requester, org_id=requester_org_id, outcome="rate_limited")
                raise ProvisionDenied("too many checkout attempts — try again later")
        try:
            return_url = config.customer_billing_return_url()
        except ValueError as exc:
            raise ProvisionDenied(str(exc)) from None
        provider = self._checkout_provider()
        if provider is None:
            self._audit("billing_checkout", requester=requester, org_id=requester_org_id, outcome="unconfigured")
            raise ProvisionDenied("checkout is not configured (the owner has not provisioned the payment processor)")
        from ..governor.billing import EVENT_SUBSCRIPTION_ACTIVE, UnsupportedCapability
        # The ONE shared offered set (top-ups; plans only with the plan flag; never monitoring) — the
        # billing_offers read lists exactly this, so the UI and checkout cannot disagree.
        offered, ents = self._checkout_offered()
        is_plan = getattr(ents.get(str(price_id or "")), "kind", None) == EVENT_SUBSCRIPTION_ACTIVE
        if is_plan and str(price_id) in offered:
            # CHK-1b red-pen HIGH: a SECOND processor subscription would double-bill (there is no processor-side
            # cancel/upgrade path yet, and the newest charge wins the sovereign plan each renewal). Refuse while the
            # org already holds a credit plan that is active or past_due and not yet expired.
            if self._org_has_live_plan(requester_org_id, t):
                self._audit("billing_checkout", requester=requester, org_id=requester_org_id,
                            target=str(price_id), outcome="refused_existing_plan")
                raise ProvisionDenied("this workspace already has a plan — changing plans is not self-serve yet "
                                      "(contact support), so a second subscription is refused rather than billed")
        # The processor needs the payer's email: take it from the owner-signed customer record (usernames are
        # opaque ids, never emails) — the account's OWN registered address, never a body field.
        acct = self.customers.customer(requester) if self.customers is not None else None
        email = getattr(acct, "email", None) or None
        try:
            sess = provider.create_checkout(requester_org_id, str(price_id or ""), expected=offered,
                                            customer_email=email, redirect_url=return_url,
                                            payment_plan=(str(price_id) if is_plan and price_id in offered else None))
        except (UnsupportedCapability, ValueError) as exc:
            self._audit("billing_checkout", requester=requester, org_id=requester_org_id,
                        target=str(price_id or ""), outcome="refused")
            raise ProvisionDenied(f"checkout refused: {exc}") from None
        self._audit("billing_checkout", requester=requester, org_id=requester_org_id, target=sess.price_id,
                    outcome="created", critical=True)
        return {"checkout_url": sess.hosted_link, "tx_ref": sess.tx_ref, "price_id": sess.price_id,
                "amount_minor": sess.amount_minor, "currency": sess.currency}

    def launch_cancel(self, requester: str, requester_org_id: str, signed_lease, *,
                      ip: str = "", mfa_at: float = 0.0, now: "Optional[float]" = None) -> dict:
        """Cancel a reservation (full refund) — the customer releases a launch they will not run. Gated on
        admit_customer(run_engagement) AND the lease's org MUST match the requester's session org
        (``expect_org_id`` — a customer cannot cancel another tenant's reservation). The refund is bound to the
        owner-signed lease, not a wire amount. The METERED settle (consumed > 0) is driven by offense
        completion, not this customer path."""
        t = self._now() if now is None else float(now)
        from .launch_gate import LaunchGate
        with self._lock:
            if not self.orgs.admit_customer(username=requester, org_id=requester_org_id,
                                            permission="run_engagement"):
                self._audit("launch_cancel", requester=requester, org_id=requester_org_id, outcome="denied")
                raise ProvisionDenied("requester may not manage launches for this org")
            self._require_stepup(mfa_at, now=t)      # E3c: a fresh step-up (no-op unless enforcement is on)
        # K4-5 red-pen fold (MED): a cancel is a FULL refund (consumed=0), valid ONLY for a reserved-but-NOT-
        # STARTED launch ("a launch they will not run"). A STARTED (published) launch has been handed to the
        # offense plane and may already have ARMED (consumed the single-use floor + run); full-refunding it
        # would refund a run that ran (free run). A started launch MUST settle through its own completion
        # (charged) or failure (refunded), never this customer cancel. Refuse once the lease is on the seam.
        from vigil_core import SignedCreditLaunchLease
        try:
            _cdoc = SignedCreditLaunchLease.model_validate(signed_lease).document
        except Exception as e:  # noqa: BLE001 — a malformed lease is a clean refusal
            raise ProvisionDenied("launch cancel requires the signed launch lease from reserve_launch") from e

        def _started() -> Optional[str]:
            try:
                from .target_authorization import _base_dir
                from vigil_integration.live.credit_lease_broker import read_credit_lease
                _pub = read_credit_lease(_base_dir(), str(_cdoc.engagement_slug))
            except Exception:  # noqa: BLE001 — a seam-read failure must not DENY a legitimate pre-start cancel;
                _pub = None     # the settle's settled-check is the hard backstop against a double refund
            if _pub is not None and str(_pub.signed_lease.document.nonce) == str(_cdoc.nonce):
                return "started"
            return None

        # A fast refusal first (main: a started launch never reaches the settle, so its meter is left open), then
        # the decisive check INSIDE the settle's cross-process critical section (``refuse_if``), which
        # ``publish_lease`` (launch_start) also holds — so a start can never land between that check and the refund.
        if _started():
            self._audit("launch_cancel", requester=requester, org_id=requester_org_id,
                        target=str(_cdoc.engagement_slug), outcome="refused_started")
            raise ProvisionDenied(
                "this launch has been started and must settle through its completion; it cannot be cancelled")
        r = LaunchGate(self.store).settle_launch(signed_lease=signed_lease, consumed_units=0, now=t,
                                                 expect_org_id=requester_org_id, refuse_if=_started)
        if r.get("refused"):
            self._audit("launch_cancel", requester=requester, org_id=requester_org_id,
                        target=str(_cdoc.engagement_slug), outcome="refused_started")
            raise ProvisionDenied(
                "this launch has been started and must settle through its completion; it cannot be cancelled")
        if not r.get("ok"):
            raise ProvisionDenied(str(r.get("error") or "launch cancel refused"))
        self._audit("launch_cancel", requester=requester, org_id=requester_org_id,
                    target=str(r.get("slug", "")), outcome="canceled", critical=True)
        return {"slug": r.get("slug"), "refunded": r.get("refunded")}

    def launch_start(self, requester: str, requester_org_id: str, signed_lease, *, ip: str = "",
                     mfa_at: float = 0.0, now: "Optional[float]" = None) -> dict:
        """Start a reserved launch — publish the owner-signed lease to the cross-plane seam so the offense
        plane can run the engagement (Slice K3). Gated on admit_customer(run_engagement) AND the lease's org
        MUST match the requester's session org (``expect_org_id`` — a customer cannot start another tenant's
        reservation). The lease is verified owner-pinned before it reaches the seam; the keyless offense plane
        re-verifies it (K2) before any traffic."""
        from .launch_gate import LaunchGate
        with self._lock:
            if not self.orgs.admit_customer(username=requester, org_id=requester_org_id,
                                            permission="run_engagement"):
                self._audit("launch_start", requester=requester, org_id=requester_org_id, outcome="denied")
                raise ProvisionDenied("requester may not manage launches for this org")
            self._require_stepup(mfa_at, now=(self._now() if now is None else float(now)))  # E3c step-up
        # K4-5d(A) + red-pen fold: provision the per-slug owner-signed OFFENSE_GOVERNANCE_ROLE delegation (that
        # the SOVEREIGN settle/finding drains verify this launch's completion + crossed FACTs against, scoped to
        # the cust_ slug, lapsing with the lease window + a settle grace) BEFORE publishing the runnable lease.
        # Ordering matters: a provisioning failure must leave NO published-but-unsettleable lease (an orphan
        # lease the poller would arm + never settle). An orphan DELEGATION — if the later publish is refused —
        # is harmless (the drains need a published lease to act). Fail-closed: a launch that cannot provision
        # its settle delegation is NOT reported started; a retry re-provisions + re-publishes idempotently.
        from vigil_core import SignedCreditLaunchLease
        from .launch_governance import LAUNCH_DELEGATION_GRACE_SECONDS, provision_launch_governance
        try:
            lease_doc = SignedCreditLaunchLease.model_validate(signed_lease).document
        except Exception as e:  # noqa: BLE001 — a malformed lease is a clean refusal
            raise ProvisionDenied("launch start requires the signed launch lease from reserve_launch") from e
        try:
            deleg_path = provision_launch_governance(
                slug=str(lease_doc.engagement_slug),
                not_after=int(lease_doc.not_after.timestamp()) + LAUNCH_DELEGATION_GRACE_SECONDS)
        except Exception as e:  # noqa: BLE001 — a provisioning failure is a clean refusal, BEFORE any publish
            self._audit("launch_start", requester=requester, org_id=requester_org_id,
                        target=str(lease_doc.engagement_slug), outcome="deleg_failed", critical=True)
            raise ProvisionDenied(
                f"could not provision the launch governance delegation: {type(e).__name__}") from e
        r = LaunchGate(self.store).publish_lease(signed_lease=signed_lease, expect_org_id=requester_org_id)
        if not r.get("ok"):
            raise ProvisionDenied(str(r.get("error") or "launch start refused"))
        self._audit("launch_start", requester=requester, org_id=requester_org_id,
                    target=str(r.get("slug", "")), outcome="started", critical=True)
        return {"slug": r.get("slug"), "scope_host": r.get("scope_host"), "governance_delegation": deleg_path}

    def launch_pause(self, requester: str, requester_org_id: str, signed_lease, *, ip: str = "",
                     mfa_at: float = 0.0, now: "Optional[float]" = None) -> dict:
        """pause/resume PR-4b — PAUSE a customer launch (reversible operator halt). Gated on
        ``customer_pause_resume_enabled()`` (default-OFF → the action is a 404 unknown-action), then
        ``admit_customer(run_engagement)`` + tenant-bind (the lease's org MUST match the session org) + a fresh
        step-up, exactly like ``launch_cancel``/``launch_start``. Records a ``(slug, nonce)`` pause marker via
        ``LaunchGate.pause_launch`` — pausing moves NO money; the money-safety (held, re-admitted on resume) is
        the already-merged PR-1..PR-4a plumbing. Valid at ANY lifecycle stage (reserved / started / running):
        a paused lease is refused at the arm + enqueue chokepoints and held until resume."""
        from .. import config
        if not config.customer_pause_resume_enabled():
            raise ProvisionDenied("customer pause/resume is not enabled")
        t = self._now() if now is None else float(now)
        from .launch_gate import LaunchGate
        with self._lock:
            if not self.orgs.admit_customer(username=requester, org_id=requester_org_id,
                                            permission="run_engagement"):
                self._audit("launch_pause", requester=requester, org_id=requester_org_id, outcome="denied")
                raise ProvisionDenied("requester may not manage launches for this org")
            self._require_stepup(mfa_at, now=t)      # E3c: a fresh step-up (no-op unless enforcement is on)
        r = LaunchGate(self.store).pause_launch(signed_lease=signed_lease, expect_org_id=requester_org_id)
        if not r.get("ok"):
            raise ProvisionDenied(str(r.get("error") or "launch pause refused"))
        self._audit("launch_pause", requester=requester, org_id=requester_org_id,
                    target=str(r.get("slug", "")), outcome="paused", critical=True)
        return {"slug": r.get("slug"), "nonce": r.get("nonce")}

    def launch_resume(self, requester: str, requester_org_id: str, signed_lease, *, ip: str = "",
                      mfa_at: float = 0.0, now: "Optional[float]" = None) -> dict:
        """pause/resume PR-4b — RESUME a paused customer launch: clear the ``(slug, nonce)`` pause marker so the
        SAME lease re-arms and the held delivery re-admits (never re-burning the single-use floor). Same gates as
        ``launch_pause`` (flag + ``admit_customer`` + tenant-bind + step-up). Idempotent: resuming a non-paused
        launch is a harmless no-op. On an EXPIRED lease the pause is still lifted (so a run in progress past
        ``not_after`` is never left halted for good), and the reply carries ``expired: True`` plus a ``detail``
        saying that a launch which has not started will not start; an in-window reply is unchanged."""
        from .. import config
        if not config.customer_pause_resume_enabled():
            raise ProvisionDenied("customer pause/resume is not enabled")
        t = self._now() if now is None else float(now)
        from .launch_gate import LaunchGate
        with self._lock:
            if not self.orgs.admit_customer(username=requester, org_id=requester_org_id,
                                            permission="run_engagement"):
                self._audit("launch_resume", requester=requester, org_id=requester_org_id, outcome="denied")
                raise ProvisionDenied("requester may not manage launches for this org")
            self._require_stepup(mfa_at, now=t)
        r = LaunchGate(self.store).resume_launch(signed_lease=signed_lease, expect_org_id=requester_org_id,
                                                 now=t)
        if not r.get("ok"):
            raise ProvisionDenied(str(r.get("error") or "launch resume refused"))
        self._audit("launch_resume", requester=requester, org_id=requester_org_id,
                    target=str(r.get("slug", "")), outcome="resumed", critical=True)
        out = {"slug": r.get("slug"), "nonce": r.get("nonce")}
        if r.get("expired"):
            out["expired"] = True
            out["detail"] = str(r.get("detail") or "")
        return out

    # -- AEGIS-SaaS AE-1: DEFENSIVE monitoring authority (own != offense-test != observe != block) -------
    def _monitor_admit(self, action: str, requester: str, org_id: str, host: str, permission: str) -> None:
        """Flag gate (default OFF) then ``admit_customer`` on the SESSION org. Caller holds the lock."""
        from .. import config
        if not config.customer_monitoring_enabled():
            raise ProvisionDenied("customer monitoring is not enabled on this deployment")
        if not self.orgs.admit_customer(username=requester, org_id=org_id, permission=permission):
            self._audit(action, requester=requester, org_id=org_id, target=host, outcome="denied")
            raise ProvisionDenied("requester may not manage monitoring for this org")

    def _monitor_plan_admit(self, reg, org_id: str, host: str, mode: str, now: float) -> float:
        """AE-5 billing gate (server-side; the CATALOG decides money): the session org needs an ACTIVE, in-period
        MONITORING subscription (its own line, never the credit plan) with a free host slot (re-authorizing an
        already-granted host reuses its slot; a slot is held only by a grant that is ``active_at`` — window +
        current matching ownership proof), and mode=block needs a plan tier that includes respond. Returns the
        plan's ``period_end`` (the grant is clamped to it). Raises ValueError (refused + audited)."""
        from ..governor.asset_ownership import _check_host
        from ..governor.catalog import monitoring_plan
        from ..governor.monitoring_authority import MODE_BLOCK
        from ..governor.monitoring_subscription import MonitoringSubscriptionRegistry
        sub = MonitoringSubscriptionRegistry(self.store, owner_key=None).active_subscription(org_id, now=now)
        plan = monitoring_plan(sub.plan_id) if sub is not None else None
        if sub is None or plan is None:
            raise ValueError("an active monitoring plan is required")
        if mode == MODE_BLOCK and not plan.respond:
            raise ValueError("block mode requires a monitoring plan that includes respond")
        h = _check_host(host)
        used = {g.host for g in reg.grants(org_id) if reg.active_at(org_id, g.host, now=now) is not None} - {h}
        if len(used) >= plan.host_slots:
            raise ValueError("no free protected-host slot on the monitoring plan")
        return float(sub.period_end)

    def monitor_authorize(self, requester: str, requester_org_id: str, host: str, *, mode: str = "observe",
                          window_s=None, ip: str = "", mfa_at=0.0, now: "Optional[float]" = None) -> dict:
        """Owner-sign + publish a DEFENSIVE monitoring authority for ONE proven (org, host). Order: flag →
        ``admit_customer(manage_monitoring)`` (org_admin; never run_engagement/offense) → step-up → registry
        grant (requires a CURRENT ownership proof, clamped to its expiry) → owner-signed
        ``SignedMonitoringAuthority`` published atomically for the keyless gateway. The window is SERVER-
        decided (``config.MONITORING_WINDOW_SECONDS``); ``window_s`` may only SHORTEN it. A BLOCK grant turns
        on NO enforcement by itself (AE-3 gates enforcement per request)."""
        t = self._now() if now is None else float(now)
        from .. import config
        from ..governor.monitoring_authority import MonitoringAuthorityRegistry, _check_mode
        with self._lock:
            self._monitor_admit("monitor_authorize", requester, requester_org_id, host, "manage_monitoring")
            self._require_stepup(mfa_at, now=t)      # AFTER admit (no-op unless enforcement is on)
            window = float(config.MONITORING_WINDOW_SECONDS)
            if window_s is not None:
                if isinstance(window_s, bool):
                    raise ProvisionError("window_s must be a positive number of seconds")
                try:
                    asked = float(window_s)
                except (TypeError, ValueError):
                    raise ProvisionError("window_s must be a positive number of seconds") from None
                if not math.isfinite(asked) or asked <= 0.0:
                    raise ProvisionError("window_s must be a positive number of seconds")
                window = min(window, asked)          # the client may only ask for SHORTER
            try:
                m = _check_mode(mode)
                reg = MonitoringAuthorityRegistry(self.store)
                period_end = self._monitor_plan_admit(reg, requester_org_id, host, m, t)
                g = reg.grant(requester_org_id, host, mode=m, not_before=t, not_after=min(t + window, period_end),
                              now=t, issued_at=self._next_issued())
            except ValueError as e:
                self._audit("monitor_authorize", requester=requester, org_id=requester_org_id, target=host,
                            outcome="refused", reason=str(e))
                raise ProvisionDenied(str(e)) from None
            try:
                signed = _sign_monitoring(reg.owner_key, g)
                path = _publish_monitoring(config.monitoring_publish_dir(), g.org_id, g.host,
                                           signed.model_dump_json().encode("utf-8"))
            except Exception as e:  # noqa: BLE001 — fail-closed: never leave an active-but-unpublished grant
                reg.revoke(g.org_id, g.host)
                self._audit("monitor_authorize", requester=requester, org_id=requester_org_id, target=g.host,
                            outcome="publish_failed", critical=True)
                raise ProvisionError(f"could not publish the monitoring authority: {type(e).__name__}") from e
            self._audit("monitor_authorize", requester=requester, org_id=requester_org_id, target=g.host,
                        outcome=f"granted_{g.mode}", critical=True)
        return {"org_id": g.org_id, "host": g.host, "mode": g.mode, "not_before": g.not_before,
                "not_after": g.not_after, "published": path.name, "authority": signed.model_dump(mode="json")}

    def monitor_plan_changed(self, org_id: str, *, now: "Optional[float]" = None) -> dict:
        """The monitoring subscription for ``org_id`` changed (new plan / renewal): enforce the CURRENT plan on
        the org's existing grants. Retire (revoke + unpublish) what the plan no longer pays for, then RE-MINT —
        owner key, provisioner path, republished — each surviving grant minted in a PRIOR period, with the new
        window (clamped to the plan's period_end and the ownership proof), so monitoring continues across
        periods. Owner/billing-driven (no tenant session); flag-gated like every monitoring path."""
        from .. import config
        from ..governor.monitoring_authority import MonitoringAuthorityRegistry
        from ..governor.monitoring_subscription import MonitoringSubscriptionRegistry, plan_enforcement
        if not config.customer_monitoring_enabled():
            raise ProvisionDenied("customer monitoring is not enabled on this deployment")
        t = self._now() if now is None else float(now)
        retired: list[str] = []
        renewed: list[str] = []
        with self._lock:
            reg = MonitoringAuthorityRegistry(self.store)
            retire, renew, sub = plan_enforcement(
                self.store, org_id, now=t, subscriptions=MonitoringSubscriptionRegistry(self.store, owner_key=None),
                authority=reg)
            for h in retire:
                reg.retire(org_id, h)
                retired.append(h)
            for old in renew:
                try:
                    g = reg.grant(org_id, old.host, mode=old.mode, not_before=t,
                                  not_after=min(t + float(config.MONITORING_WINDOW_SECONDS), float(sub.period_end)),
                                  now=t, issued_at=self._next_issued())
                    signed = _sign_monitoring(reg.owner_key, g)
                    _publish_monitoring(config.monitoring_publish_dir(), g.org_id, g.host,
                                        signed.model_dump_json().encode("utf-8"))
                except Exception:  # noqa: BLE001 — fail-closed: a grant that cannot be renewed is retired
                    reg.retire(org_id, old.host)
                    retired.append(old.host)
                    continue
                renewed.append(g.host)
            for h in retired:
                self._audit("monitor_plan_enforce", requester="owner", org_id=org_id, target=h,
                            outcome="retired", critical=True)
            for h in renewed:
                self._audit("monitor_plan_enforce", requester="owner", org_id=org_id, target=h,
                            outcome="renewed", critical=True)
        return {"org_id": org_id, "retired": retired, "renewed": renewed}

    def monitor_revoke(self, requester: str, requester_org_id: str, host: str, *, ip: str = "",
                       now: "Optional[float]" = None) -> dict:
        """Revoke (the SAFE direction) + unpublish one (session org, host) grant. Idempotent; admit-gated so
        a tenant can only revoke ITS OWN org's grants. No step-up (revoking only ever reduces authority)."""
        from .. import config
        from ..governor.asset_ownership import _check_host
        from ..governor.monitoring_authority import MonitoringAuthorityRegistry
        with self._lock:
            self._monitor_admit("monitor_revoke", requester, requester_org_id, host, "manage_monitoring")
            try:
                h = _check_host(host)
            except ValueError as e:
                raise ProvisionDenied(str(e)) from None
            reg = MonitoringAuthorityRegistry(self.store, owner_key=None)
            was_active = reg.grant_for(requester_org_id, h) is not None
            from ..governor.monitoring_authority import unpublish
            removed = unpublish(requester_org_id, h, config.monitoring_publish_dir())
            if was_active:
                reg.revoke(requester_org_id, h)
            self._audit("monitor_revoke", requester=requester, org_id=requester_org_id, target=h,
                        outcome="revoked" if was_active else "noop", critical=True)
        return {"org_id": requester_org_id, "host": h, "revoked": was_active, "unpublished": removed}

    def monitor_list(self, requester: str, requester_org_id: str, *, ip: str = "",
                     now: "Optional[float]" = None) -> dict:
        """The SESSION org's monitoring grants (org-scoped read; ``active`` applies window + ownership)."""
        t = self._now() if now is None else float(now)
        from ..governor.monitoring_authority import MonitoringAuthorityRegistry
        with self._lock:
            self._monitor_admit("monitor_list", requester, requester_org_id, "", "read")
            reg = MonitoringAuthorityRegistry(self.store, owner_key=None)
            rows = [{"host": g.host, "mode": g.mode, "not_before": g.not_before, "not_after": g.not_after,
                     "active": reg.active_at(requester_org_id, g.host, now=t) is not None}
                    for g in reg.grants(requester_org_id)]
        return {"org_id": requester_org_id, "grants": rows}

    def monitor_events(self, requester: str, requester_org_id: str, *, ip: str = "", limit: int = 200) -> dict:
        """The SESSION org's drained AEGIS monitoring events (gateway-reported; org-scoped read)."""
        from ..inbound.monitoring_spool import monitoring_events
        with self._lock:
            self._monitor_admit("monitor_events", requester, requester_org_id, "", "read")
        return {"org_id": requester_org_id, "events": monitoring_events(self.store, requester_org_id, limit=limit)}

    # -- customer-plane READS (the Slice-I backend): admit_customer-gated, session-org-scoped ---------
    def _customer_read(self, requester: str, org_id: str, permission: str, projector) -> dict:
        """Shared gate for a customer-plane READ: ``admit_customer(permission)`` for the SESSION org (NO
        global leg — a customer reads ONLY their own tenant, resolved LIVE so a revoked membership dies on the
        next request), then the pure projection. ``requester``/``org_id`` are the hop-bound session principal,
        NEVER a body field. A read takes no lock, mints nothing, and touches no owner key."""
        if not self.orgs.admit_customer(username=requester, org_id=org_id, permission=permission):
            raise ProvisionDenied(f"requester may not read this org ({permission})")
        return projector(self.store, org_id)

    def customer_billing(self, requester: str, requester_org_id: str, *, ip: str = "") -> dict:
        import time as _t
        from . import billing as _billing
        return self._customer_read(requester, requester_org_id, "view_billing",
                                   lambda s, o: _billing.billing_overview(s, o, now=_t.time()))

    def customer_invoices(self, requester: str, requester_org_id: str, *, ip: str = "") -> dict:
        from . import billing as _billing
        return self._customer_read(requester, requester_org_id, "view_invoices",
                                   lambda s, o: _billing.billing_invoices(s, o))

    def customer_assessments(self, requester: str, requester_org_id: str, *, ip: str = "") -> dict:
        import time as _t
        from . import assessments as _assess
        return self._customer_read(requester, requester_org_id, "view_assessments",
                                   lambda s, o: _assess.assessment_summary(s, o, now=_t.time(),
                                                                           preview=self._preview_locked(o)))

    def customer_assessment_findings(self, requester: str, requester_org_id: str, *, ip: str = "") -> dict:
        import time as _t
        from . import assessments as _assess
        return self._customer_read(
            requester, requester_org_id, "view_assessments",
            lambda s, o: _assess.assessment_findings(
                s, o, now=_t.time(), preview=self._preview_locked(o),
                can_buy=self.orgs.admit_customer(username=requester, org_id=o, permission="manage_billing")))

    def _preview_locked(self, org_id: str) -> bool:
        """Pricing S5: is this org's finding detail locked (trial preview, not unlocked)? Server-side only."""
        from .finding_preview import preview_locked
        return preview_locked(self.store, org_id, wallet=self.wallet)

    def customer_assets(self, requester: str, requester_org_id: str, *, ip: str = "") -> dict:
        """Per-host ownership status (verified / pending / expired) for the SESSION org's assets — the read
        behind the customer 'Domains' view (SS-4). Tenant-scoped by ``_customer_read``'s ``admit_customer``
        (NO global leg, live membership re-check); the ``org_id`` is the hop-bound session principal, never a
        body field, so org A can never read org B's assets."""
        import time as _t
        from ..governor import asset_ownership as _own
        return self._customer_read(requester, requester_org_id, "view_assessments",
                                   lambda s, o: _own.assets_overview(s, o, now=_t.time()))

    def customer_notifications(self, requester: str, requester_org_id: str, *, ip: str = "",
                               now: "Optional[float]" = None) -> dict:
        """The SESSION org's actionable notifications, aggregated ACROSS only the surfaces the requester is
        entitled to read and ranked most-severe-first — the read behind the customer notification centre.

        Four sources, each behind its OWN permission (no global leg), skip-on-deny so a role sees exactly
        what it may read and nothing else (a billing-only admin never sees assessment findings, and vice
        versa; a non-member / revoked member gets an empty list, never another tenant's data):
          * oracle-confirmed assessment FINDINGS       (view_assessments)
          * BILLING standing — dunning / lapsed / exhausted, derived from owner-signed spine STATES only
            (past_due & canceled are signed subscription statuses; zero credits is the natural floor — NO
            invented threshold decides a notification)                              (view_billing)
          * confirmed/lead AEGIS MONITORING alerts, only when monitoring is enabled AND permitted (reuses
            ``monitor_events``' own flag+admit gate; its fail-closed refusal simply contributes nothing).
          * assessment OUTCOMES (NTF-3) — a verified completion/cancellation/failure SETTLED a run, so a
            COMPLETED run with ZERO findings and a FAILED/CANCELED run (not charged) are no longer silent (a
            run that never reaches the settle seam is NTF-1/2's stranded-run scope). Written by the settle
            drain, tenant-scoped inside the projector; carries NO amount  (view_assessments)

        Each item is ``{id, kind, severity, title, body, ts}`` with a STABLE id (``finding:<ref>`` /
        ``billing:<state>`` / ``monitor:<report_id>`` / ``outcome:<slug>:<nonce>``) the edge/UI uses for
        read-tracking — no timestamp is invented for a finding (its cert carries none). ``org_id`` is the
        hop-bound session principal, NEVER a body field, so org A can never read org B. A read takes no lock,
        mints nothing, holds no owner key."""
        t = self._now() if now is None else float(now)
        # Display-severity -> rank (most-severe first). Findings carry their cert severity verbatim; billing
        # and monitoring assign from the vocabulary below. Unknown severities rank as "medium" (actionable),
        # never silently last.
        _rank = {"critical": 0, "high": 1, "medium": 2, "moderate": 2, "low": 3, "info": 4, "informational": 4}
        items: list[dict] = []

        # 1) Assessment findings — each confirmed FACT is a notification. admit_customer returns bool (no raise),
        #    so a denied source is simply skipped. Tenant-scoped inside the projector by the org's own slug set.
        locked = self._preview_locked(requester_org_id)
        if self.orgs.admit_customer(username=requester, org_id=requester_org_id, permission="view_assessments"):
            from . import assessments as _assess
            found = _assess.assessment_findings(self.store, requester_org_id, now=t, preview=locked)
            for f in found.get("findings", []):
                ref = str(f.get("finding_ref") or "").strip()
                if not ref:
                    continue
                sev = str(f.get("severity") or "medium").strip().lower() or "medium"
                # Pricing S5: a locked finding's body is fixed copy pointing at Billing (never its summary).
                body = (_LOCKED_FINDING_BODY if f.get("locked") else str(f.get("summary") or ""))
                items.append({"id": "finding:" + ref, "kind": "finding", "severity": sev,
                              "title": str(f.get("title") or ref), "body": body, "ts": None})
        # Pricing S5: a one-time notice when a trial-preview org's reports are unlocked (stable id, so the
        # per-viewer seen-set shows it once). Only for orgs that received the preview trial.
        from .. import config as _cfg
        if (_cfg.trial_preview_enabled() and not locked
                and self.wallet.has_grant_entry(requester_org_id, f"trial-preview:{requester_org_id}")
                and self.orgs.admit_customer(username=requester, org_id=requester_org_id,
                                             permission="view_assessments")):
            items.append({"id": "billing:reports_unlocked", "kind": "billing", "severity": "info",
                          "title": "Full results unlocked",
                          "body": "Your full assessment results, with proof and fix, are now available.",
                          "ts": None})

        # 2) Billing standing — dunning / lapsed / exhausted, from owner-signed STATES only (no money number
        #    decides a notification). past_due (dunning) is the sharpest; a canceled subscription and an
        #    exhausted (zero) credit balance each raise their own one-shot, stable-id notice.
        if self.orgs.admit_customer(username=requester, org_id=requester_org_id, permission="view_billing"):
            from . import billing as _billing
            ov = _billing.billing_overview(self.store, requester_org_id, now=t)
            sub = ov.get("subscription") or {}
            status = str(sub.get("status") or "")
            if status == "past_due":
                items.append({"id": "billing:past_due", "kind": "billing", "severity": "high",
                              "title": "Payment past due",
                              "body": "Your subscription payment is past due. Settle it to keep your plan active.",
                              "ts": None})
            elif status == "canceled":
                items.append({"id": "billing:canceled", "kind": "billing", "severity": "medium",
                              "title": "Subscription canceled",
                              "body": "Your subscription is canceled. Resubscribe to restore plan credits.",
                              "ts": None})
            credits = ov.get("credits") or {}
            try:
                avail = int(credits.get("available") or 0)
            except (TypeError, ValueError):
                avail = 0
            if avail <= 0:
                items.append({"id": "billing:no_credits", "kind": "billing", "severity": "medium",
                              "title": "Out of assessment credits",
                              "body": "You have no assessment credits available. Top up to launch new assessments.",
                              "ts": None})

        # 3) Monitoring alerts — AEGIS-SaaS. monitor_events self-gates on the default-OFF flag AND
        #    admit_customer, raising ProvisionDenied when off or not permitted; we treat that as "no source"
        #    (byte-identical to a build without monitoring). A confirmed attack is high; a lead is low.
        try:
            mon = self.monitor_events(requester, requester_org_id, ip=ip)
        except ProvisionDenied:
            mon = None
        if mon:
            for ev in mon.get("events", []):
                rid = str(ev.get("report_id") or "").strip()
                if not rid:
                    continue
                decision = str(ev.get("decision") or "").strip().lower()
                host = str(ev.get("host") or "")
                klass = str(ev.get("attack_class") or "activity")
                confirmed = decision == "confirmed"
                title = ("Confirmed " + klass if confirmed else "Lead: " + klass) + (" on " + host if host else "")
                body = "AEGIS " + (decision or "event")
                action = str(ev.get("action") or "")
                if action:
                    body += " — action " + action
                items.append({"id": "monitor:" + rid, "kind": "monitoring",
                              "severity": "high" if confirmed else "low", "title": title, "body": body,
                              "ts": ev.get("ts")})

        # 4) Assessment OUTCOMES (NTF-3) — the settle drain projects every verified completion/cancellation/
        #    failure to a tenant-scoped ``assessment_outcome`` record, so a COMPLETED run with ZERO findings and
        #    a FAILED/CANCELED run (not charged) are no longer silent. Same axis as findings (view_assessments),
        #    skip-on-deny; tenant-scoped INSIDE the projector by the org's own server-derived slug set (the IDOR
        #    class — another tenant's outcome is structurally unreachable). Advisory: the record carries NO
        #    amount, so no money figure decides a notification. failed → high / canceled → medium (needs
        #    attention); completed → info (done). Stable id ``outcome:<slug>:<nonce>`` for read-tracking.
        if self.orgs.admit_customer(username=requester, org_id=requester_org_id, permission="view_assessments"):
            from . import assessments as _assess
            outs = _assess.assessment_outcomes(self.store, requester_org_id, now=t)
            for o in outs.get("outcomes", []):
                slug = str(o.get("engagement_slug") or "").strip()
                nonce = str(o.get("nonce") or "").strip()
                if not slug or not nonce:
                    continue
                outcome = str(o.get("outcome") or "").strip().lower()
                if outcome == "failed":
                    sev, head, body = ("high", "Assessment failed",
                                       "An assessment run failed. You were not charged for this run.")
                elif outcome == "canceled":
                    sev, head, body = ("medium", "Assessment canceled",
                                       "An assessment run was canceled. You were not charged for this run.")
                else:  # completed (the only remaining signed outcome; flat-per-run consumed, no refund)
                    sev, head, body = ("info", "Assessment completed",
                                       _LOCKED_COMPLETED_BODY if locked else
                                       "An assessment run completed. View any findings in your assessments.")
                items.append({"id": "outcome:" + slug + ":" + nonce, "kind": "assessment",
                              "severity": sev, "title": head, "body": body, "ts": o.get("ts")})

        # Stable, severity-ranked order; a stable sort keeps within-source order (findings + monitoring are
        # already newest-first). Cap the returned list; ``count`` is the TRUE pre-cap total for the UI badge.
        total = len(items)
        items.sort(key=lambda n: _rank.get(str(n.get("severity") or "").lower(), 2))
        return {"org_id": requester_org_id, "notifications": items[:_NOTIF_MAX], "count": total}

    def target_verify(self, requester: str, requester_org_id: str, host: str, method: str, *,
                      authorized: bool = False, ip: str = "", mfa_at: float = 0.0,
                      now: "Optional[float]" = None) -> dict:
        """Fetch the customer's published token, record the owner-signed ownership PROOF on a pass, and mint
        the owner-signed LIVE non-destructive target authority — the self-serve billing != testing bridge.

        ``authorized`` is the customer's INLINE affirmation ("I am authorized to test this asset"), ticked on
        the same verify screen (option A — one step, no separate ceremony). It is REQUIRED and fail-closed:
        controlling a host's DNS/web-root is not the same as having legal authority to test it, so without the
        affirmation NO authority is minted. The affirmation is recorded on the owner-signed spine (the verify
        audit's ``authorization_affirmed``) as the tamper-evident legal attestation, bound to requester + host.

        Gated on ``admit_customer(requester, org_id, run_engagement)`` (the testing axis, checked BEFORE the
        fetch and AGAIN inside the mint lock — TOCTOU: a membership revoked during the network fetch cannot
        sign through). Fail-closed when no fetcher is configured (ownership verification OFF by default). The
        FETCH happens OUTSIDE the spine lock (network I/O must not hold it); the verdict + proof + mint are
        atomic under the lock. The owner key (``add_customer_target``) still signs the authority — the
        requester holds no key, and the mint is additionally refused unless the just-recorded ownership proof
        is current. ``requester``/``org`` are the server-authenticated principal (never client fields)."""
        t = self._now() if now is None else float(now)
        if self.target_fetcher is None:
            raise ProvisionError("self-serve ownership verification is not enabled on this deployment")
        with self._lock:                                            # authorize BEFORE spending a network fetch
            if not self.orgs.admit_customer(username=requester, org_id=requester_org_id,
                                            permission="run_engagement"):
                self._audit("target_verify", requester=requester, org_id=requester_org_id,
                            target=host, outcome="denied")
                raise ProvisionDenied("requester may not register assessment targets for this org")
            self._require_stepup(mfa_at, now=t)      # E3c: a fresh step-up (no-op unless enforcement is on)
            if not authorized:                       # option A: the inline "I am authorized to test this asset"
                #                                      affirmation is REQUIRED + fail-closed — no authority minted
                #                                      without it (control of a host != legal authority to test it).
                raise ProvisionDenied("confirm that you are authorized to test this asset before verifying it")
        from .ownership_fetch import OwnershipFetchError
        try:
            observed = self.target_fetcher.fetch(method, host, now=t)   # network I/O — NO lock held
        except OwnershipFetchError as e:  # the fetcher's OWN controlled, safe reason (404 / SSRF-refused / TLS)
            self._audit("target_verify", requester=requester, org_id=requester_org_id,
                        target=host, outcome="fetch_failed")
            raise ProvisionDenied(f"could not read the published token: {e}") from None
        except Exception:  # noqa: BLE001 — an unexpected fetcher error fails closed WITHOUT echoing internals
            self._audit("target_verify", requester=requester, org_id=requester_org_id,
                        target=host, outcome="fetch_error")
            raise ProvisionDenied("could not read the published token at the well-known URL") from None
        from ..governor.asset_ownership import AssetOwnershipRegistry
        from .target_authorization import add_customer_target
        with self._lock:
            if not self.orgs.admit_customer(username=requester, org_id=requester_org_id,
                                            permission="run_engagement"):
                raise ProvisionDenied("requester may not register assessment targets for this org")  # TOCTOU
            try:
                AssetOwnershipRegistry(self.store).verify_and_record(
                    requester_org_id, host, method=method, observed=observed, now=t)
            except ValueError as e:
                raise ProvisionDenied(str(e)) from None
            result = add_customer_target(host, org_id=requester_org_id, store=self.store, now=t)
            if not result.get("ok"):
                raise ProvisionError(str(result.get("error") or "could not authorize the target"))
            self._audit("target_verify", requester=requester, org_id=requester_org_id,
                        target=host, outcome="authorized", critical=True, attestation=True)
        return {"host": host, "slug": result["slug"], "scope": result["scope"],
                "environment": result["environment"], "not_before": result["not_before"],
                "not_after": result["not_after"]}


def build_provisioner(store, *, expose_dev_tokens: bool = False, now_fn=time.time,
                      customer_oidc_http_post=None, customer_oidc_jwks_fetcher=None) -> Provisioner:
    """Wire a production Provisioner over `store`: the owner-signed registries (their owner key defaults to
    the persisted owner identity — THIS is the only process that holds it), the filesystem email-token +
    login-rate-limit ledgers rooted under SIGIL_HOME (config), and the configured EmailSender
    (OFF-by-default NullEmailSender unless SIGIL_EMAIL_* is set). The keyless customer edge NEVER calls
    this; it reaches the sovereign provisioner routes over loopback + the hop key.

    `customer_oidc_http_post` / `customer_oidc_jwks_fetcher` are OPTIONAL injection hooks for the customer
    Google-OIDC provider (mirrors the operator `oidc_http_post`/`oidc_jwks_fetcher`): when BOTH are None
    (production) the provider uses the HOST-ALLOWLISTED egress transport; a test injects both (a local fake
    IdP) so no network is touched."""
    from .. import config
    from ..governor.customer_credentials import CustomerCredentialRegistry
    from ..governor.trial_claim import TrialClaimRegistry
    from ..governor.customers import CustomerRegistry
    from ..governor.orgs import OrgRegistry
    from ..governor.wallet import WalletRegistry
    from .email_channel import EmailTokenLedger
    from .login_ratelimit import LoginRateLimiter
    from .signcount import SignCountLedger
    from .totp_replay import TotpReplayLedger
    # E2b — customer Google OIDC, OFF by default. When `customer_oidc_enabled()`, build the IdentityProvider
    # with the host-ALLOWLISTED egress transport; the client secret + the token/JWKS egress live ONLY here
    # (never the keyless edge). A misconfig (missing client_id/redirect) leaves it None ⇒ oidc_finish refuses
    # (fail-closed) WITHOUT breaking password login — build_provisioner must never raise for the common paths.
    oidc_provider = None
    if config.customer_oidc_enabled():
        from .customer_identity import GoogleOidcIdentityProvider
        from .oidc import OidcConfig, OidcError, host_allowlisted_transport
        try:
            oidc_cfg = OidcConfig.from_settings(config.customer_oidc_settings())
        except OidcError:
            oidc_cfg = None
        if oidc_cfg is not None:
            # production ⇒ the allowlisted transport (both hooks None); a test injects BOTH (a fake IdP).
            if customer_oidc_http_post is None and customer_oidc_jwks_fetcher is None:
                poster, fetcher = host_allowlisted_transport(config.CUSTOMER_OIDC_EGRESS_ALLOWLIST)
            else:
                poster, fetcher = customer_oidc_http_post, customer_oidc_jwks_fetcher
            oidc_provider = GoogleOidcIdentityProvider(oidc_cfg, http_post=poster, jwks_fetcher=fetcher,
                                                       now_fn=now_fn)
    return Provisioner(
        store,
        customers=CustomerRegistry(store),
        orgs=OrgRegistry(store),
        wallet=WalletRegistry(store),
        email_tokens=EmailTokenLedger(config.EMAIL_TOKENS_DIR),
        rate_limiter=LoginRateLimiter(config.LOGIN_RATELIMIT_DIR),
        # the GLOBAL per-day signup ceiling (anti-trial-farming) and the per-org member-management ceiling —
        # separate limiters under disjoint marker dirs (never couple to the login limiter). The signup cap's
        # base_lock_s EQUALS its window (86400s): on the CAP-th committed signup the limiter trips and stays
        # locked for the FULL day, so it enforces a true "<= CAP signups per 24h" ceiling. (A shorter
        # base_lock_s would let the lock lapse mid-window and the escalate-and-clear limiter would then admit
        # several times the cap — the red-pen's CO10.)
        signup_cap_limiter=LoginRateLimiter(config.SIGNUP_CAP_DIR, max_fails=config.SIGNUP_DAILY_CAP,
                                            window_s=86400.0, base_lock_s=86400.0, max_lock_s=86400.0),
        signup_email_limiter=(LoginRateLimiter(config.SIGNUP_EMAIL_RATELIMIT_DIR,
                                               max_fails=config.SIGNUP_EMAIL_PER_HOUR, window_s=3600.0,
                                               base_lock_s=3600.0, max_lock_s=3600.0)
                              if config.SIGNUP_EMAIL_PER_HOUR > 0 else None),   # default OFF (0)
        member_limiter=LoginRateLimiter(config.MEMBER_RATELIMIT_DIR, max_fails=config.MEMBER_OPS_PER_MIN,
                                        window_s=60.0, base_lock_s=60.0, max_lock_s=600.0),
        # Slice G0 — the SSRF-hardened ownership fetcher, injected ONLY when the operator opts in
        # (config.ownership_fetcher() returns None otherwise ⇒ target_verify fail-closed). No surprise egress.
        target_fetcher=config.ownership_fetcher(),
        # E2a/E2b — the owner-signed customer-credential registry (always wired; finish_login's federated
        # branch resolves through it) + the Google-OIDC provider (None unless customer_oidc_enabled()).
        customer_credentials=CustomerCredentialRegistry(store),
        oidc_provider=oidc_provider,
        # E3b — the per-customer TOTP replay ledger (its own marker dir under SIGIL_HOME; fail-closed).
        mfa_replay=TotpReplayLedger(config.CUSTOMER_MFA_REPLAY_DIR),
        # E3b-2 — the per-credential WebAuthn sign-count clone-floor ledger (non-signed, monotonic).
        signcount=SignCountLedger(config.CUSTOMER_PASSKEY_SIGNCOUNT_DIR),
        email_sender=config.email_sender(),
        trial_credits=config.TRIAL_CREDITS,
        trial_claims=TrialClaimRegistry(store),
        # Pricing S3c: the opt-in per-IP trial-grant soft limit (off unless VIGIL_TRIAL_IP_LIMIT_ENABLED).
        # A limit of 0 or less with the flag ON withholds every preview trial (fail closed, like the S7 cap).
        trial_ip_limiter=((LoginRateLimiter(config.TRIAL_IP_LIMIT_DIR, max_fails=config.TRIAL_GRANTS_PER_IP,
                                            window_s=86400.0, base_lock_s=86400.0, max_lock_s=86400.0)
                           if config.TRIAL_GRANTS_PER_IP > 0 else _WithholdAllTrialGrants())
                          if config.trial_ip_limit_enabled() else None),
        # Pricing S7: the global daily trial-launch cap; base_lock = window so it holds for the full day.
        trial_launch_limiter=(LoginRateLimiter(config.TRIAL_LAUNCH_CAP_DIR, max_fails=config.TRIAL_LAUNCH_DAILY_CAP,
                                               window_s=86400.0, base_lock_s=86400.0, max_lock_s=86400.0)
                              if config.TRIAL_LAUNCH_DAILY_CAP > 0 else None),
        expose_dev_tokens=expose_dev_tokens,
        now_fn=now_fn,
    )
