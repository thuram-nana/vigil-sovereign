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
    service owner-signs {customer account, org, founding membership, trial credit} atomically. The trial
    (real money) is granted ONLY after email verification (anti-Sybil), amount a server constant. The founding
    membership is `org_admin`, or `founder` (org_admin plus self-serve testing on hosts the org proves) while
    VIGIL_SIGNUP_FOUNDER_TESTER_ENABLED and VIGIL_TRIAL_PREVIEW_ENABLED are both on — server-set, never a client
    value (`_signup_role`).
  * login — email+password (constant-time via the decoy), rate-limited + locked out on abuse.
  * request_recover / confirm_recover — single-use recovery token → owner-signed password reset.
  * confirm_signup_code / confirm_recover_code — the same two confirmations with the 6-digit code from the same
    email instead of its token (when the provisioner has an EmailCodeLedger; off by default): bound to the email
    and the purpose, single use, 10 minutes, 5 wrong codes per email+purpose, plus a per-IP limit.
  * grant_member / revoke_member — an `org_admin` (or the founder) manages THEIR org's team: the service checks
    `admit_customer(requester, org_id, manage_members)` THEN owner-signs the (capped) membership grant /
    revoke. This is R1's AUTHENTICATED ordinary revocation (never an anonymous unsigned record) and the
    milestone primitive: an org admin invites/manages users without ever touching the owner key, another
    tenant's resources, or any assessment target (the grantable set excludes `operator`/`founder`/`owner`).
    A founder's own membership is never changed or revoked here: that is an owner act
    (`owner_set_member_role` / `owner_demote_founders`, the `sigil org` verbs).
  * customer_members / add_member — the customer app's Team screen (VIGIL_CUSTOMER_TEAM_UI): the session org's member
    list, and adding an EXISTING customer by the email of their account. Both are `manage_members` acts. There is no
    invitation flow: a person without a VIGIL account is refused in plain words and nothing is recorded for them.

FATAL-2: sovereign-side (`assert_no_offense` at import); no framework/strix.
"""
from __future__ import annotations

import base64
import hashlib
import math
import secrets
import time
from typing import Any, Callable, NoReturn, Optional

from ..reuse import assert_no_offense

assert_no_offense()

from .customer_identity import (CustomerIdentity, IdentityRefused,  # noqa: E402
                                METHOD_GOOGLE_OIDC, METHOD_PASSKEY, PasswordIdentityProvider)
from .email_channel import PURPOSE_RECOVER, PURPOSE_VERIFY, CodeBlocked, CodeOk, format_code  # noqa: E402
from ..spine.store import spine_lock  # noqa: E402  (process-wide, path-keyed RE-ENTRANT txn lock)
# The PER-ORG predicate (a membership role the org fold resolved) — never the global-role `accounts.role_can`.
from vigil_core.rbac import role_can  # noqa: E402

_LOCKED_FINDING_BODY = ("Confirmed by the oracle. The proof and the fix are part of the full report: buy credits "
                        "in Billing to unlock it.")
_LOCKED_COMPLETED_BODY = ("An assessment run completed. Every finding is listed in your assessments; buy credits in "
                          "Billing to unlock the full proof and fix.")
# A customer cancel whose settle is HELD for the owner (launch_gate.PLAN_DEBIT_PRUNED): nothing moved, and the owner is
# alarmed (`vigil doctor`); the customer is told exactly that.
LAUNCH_REFUND_HELD_DETAIL = ("this reservation cannot be released automatically right now: its credits stay "
                             "reserved, not spent, until the operator returns them (the operator has been alerted)")
_DEFAULT_TRIAL_CREDITS = 100              # server constant — NO on-the-wire amount decides the trial grant
_ORG_ID_PREFIX = "org_"
# The roles a customer org-admin may grant a teammate: deliberately EXCLUDES `operator` and `founder` (which
# carry run_engagement) and `owner` — a customer can never hand a teammate any testing or global authority
# (billing-authz != testing-authz). `org_admin` is included so an admin can delegate org admin.
_CUSTOMER_GRANTABLE_ROLES = frozenset({"viewer", "analyst", "org_admin"})
# The per-org role only the service owner grants or changes (vigil_core.rbac `founder`).
_FOUNDER_ROLE = "founder"
# The Team screen (VIGIL_CUSTOMER_TEAM_UI): the order its member list is shown in (then by name), and the refusals of
# Add member a customer reads. A teammate is named by the email of their VIGIL account; there is no invitation flow,
# so a person without an account is told to create one first. The labels named here are the app's own.
_TEAM_ORDER = {"founder": 0, "org_admin": 1, "operator": 2, "analyst": 3, "viewer": 4}
_ADD_NO_ACCOUNT = ("there is no VIGIL account for that email. Ask your teammate to create one with Create an account "
                   "on the sign-in screen, then add them again")
_ADD_ALREADY_MEMBER = ("that person is already a member of this workspace. To give them another role, use Change role "
                       "on their row")
_ADD_BAD_EMAIL = "enter the email address your teammate signs in to VIGIL with"
# The emails that carry a 6-digit code beside the token (only while the provisioner has an EmailCodeLedger; without
# one the emails are exactly as before). The code and the token prove the same thing: control of the mailbox.
_SIGNUP_CODE_EMAIL = (
    "Your VIGIL verification code is:\n\n    {code}\n\n"
    "Type it into VIGIL within 10 minutes. It works once.\n\n"
    "Or paste this single-use token on the sign-up page (valid for 1 hour):\n\n    {token}\n\n"
    "If you did not ask to create a VIGIL account, ignore this email. VIGIL will never ask you for this code or "
    "token by phone, chat or another email.\n")
_RECOVER_CODE_EMAIL = (
    "Your VIGIL password reset code is:\n\n    {code}\n\n"
    "Type it into VIGIL within 10 minutes to choose a new password. It works once.\n\n"
    "Or paste this single-use token on the password reset page (valid for 1 hour):\n\n    {token}\n\n"
    "If you did not ask to reset your VIGIL password, ignore this email: your password stays as it is. VIGIL will "
    "never ask you for this code or token by phone, chat or another email.\n")
# The notification centre returns at most this many items (most-severe-first); ``count`` is the true total
# so the UI badge is honest. A cap bounds the read so a noisy tenant can never return an unbounded list.
_NOTIF_MAX = 100
# W3 — the notice of an assessment parked for want of prepaid credit. Credits only, no amount, no host, no estimate:
# it says what happened, what to do, and the owner's rule for a pause that is never resumed (the wait is the
# VIGIL_CREDIT_PAUSE_TTL_S grace, stated in whole days — or hours below a day).
_CREDIT_PAUSE_TITLE = "Assessment paused: out of credits"
_CREDIT_PAUSE_BODY = ("An assessment ran out of credits and is paused; the work it has done so far is kept. Top up your "
                      "credits, then resume it from Assessments. If it is not resumed within {wait}, it closes and is "
                      "charged only for what it used.")


def _credit_pause_wait(ttl_s: float) -> str:
    """The credit-pause grace in plain words: whole days, or whole hours (at least one) below a day."""
    if ttl_s >= 86_400:
        days = int(ttl_s // 86_400)
        return f"{days} day" + ("" if days == 1 else "s")
    hours = max(1, int(ttl_s // 3_600))
    return f"{hours} hour" + ("" if hours == 1 else "s")


def _credit_pause_notices(store, org_id: str, *, now: float) -> "list[dict]":
    """W3 — one ``assessment`` notice per launch of ``org_id`` PARKED for want of prepaid credit (the sovereign
    ``credit-pauses`` records on the seam), tenant-scoped by the org's OWN server-derived slug set (``assessments.
    _org_slug_set``: its current ownership proofs — never a seam field); a launch already settled is not listed. A
    stable id ``credit_pause:<slug>:<nonce>`` for read-tracking, ``ts`` = the pause time. READ-ONLY and total: an
    absent / unreadable seam contributes nothing (no record ⇒ no notice, so without metered billing nothing changes)."""
    try:
        from vigil_core.seam_base import resolve_seam_base
        from vigil_integration.live.credit_lease_broker import is_lease_settled
        from vigil_integration.live.credit_lease_pause import (credit_pause_at, credit_pause_ttl_s,
                                                               credit_paused_launches)
        base = resolve_seam_base(None)
        paused = credit_paused_launches(base)
        if not paused:
            return []
        from . import assessments as _assess
        mine = _assess._org_slug_set(store, org_id, now=now)
        body = _CREDIT_PAUSE_BODY.format(wait=_credit_pause_wait(credit_pause_ttl_s()))
        out: "list[dict]" = []
        for slug, nonces in paused:
            if slug not in mine:
                continue
            for nonce in nonces:
                if is_lease_settled(base, slug, nonce):
                    continue
                out.append({"id": f"credit_pause:{slug}:{nonce}", "kind": "assessment", "severity": "high",
                            "title": _CREDIT_PAUSE_TITLE, "body": body, "ts": credit_pause_at(base, slug, nonce)})
        return out
    except Exception:  # noqa: BLE001 — an advisory projection never breaks the notification read
        return []


#: C1b — the sovereign bounded-wait for the keyless offense worker's re-proof outcome. A single-finding re-fire
#: is short; this caps how long ``retest`` blocks before refusing honestly as "not available" (the offense drain
#: must be running in production). Tests override via ``retest(_reproof_wait=(timeout, poll))``.
_RETEST_REPROOF_WAIT_S = 45.0
_RETEST_REPROOF_POLL_S = 0.25


def _retest_reproof_dir(base: "Any", subdir: str) -> "Any":
    """One cross-plane retest seam directory under the shared seam base — through the ONE resolver every plane
    uses (``vigil_core.seam_base``), so the cockpit and the keyless offense worker meet in the same tree."""
    from pathlib import Path

    from vigil_core.seam_base import resolve_seam_base
    return Path(resolve_seam_base(base)) / subdir


def _write_retest_ticket(base: "Any", ticket: "dict") -> None:
    """Publish one owner-signed re-proof TICKET to the ``retest-reproof`` seam (atomic rename), keyed by its
    nonce. The offense trigger reads it, re-fires THAT finding's proof against the verified host under the
    ticket-carried lease, and writes an inert outcome back. FATAL-2: the sovereign only drops the ticket on the
    seam — it never runs the engine."""
    import json as _json

    from vigil_core.retest_reproof import RETEST_REPROOF_SEAM_SUBDIR
    seam = _retest_reproof_dir(base, RETEST_REPROOF_SEAM_SUBDIR)
    seam.mkdir(parents=True, exist_ok=True)
    nonce = str(ticket.get("nonce") or "")
    tmp = seam / f".{nonce}.tmp"
    tmp.write_text(_json.dumps(ticket), encoding="utf-8")
    import os as _os
    _os.replace(tmp, seam / f"{nonce}.json")


def _read_retest_outcome(base: "Any", want: "Any", *, timeout: float, poll: float) -> str:
    """Bounded-wait the ``retest-outcomes`` seam for the offense worker's inert outcome for ``want`` =
    ``(slug, finding_ref, oracle_context_digest, nonce)`` and return its verdict token, or ``"unavailable"`` on
    timeout / a missing / malformed / mis-identified outcome. The outcome's identity MUST match the ticket this
    retest issued (slug + finding_ref + digest + nonce) — a stray or forged outcome for another finding is
    ignored — so a verdict can only ever drive the mapping of the exact finding whose proof was re-fired. Reads
    only (no key); the verdict is MAPPED by the caller (the sovereign is the sole authority on the mapping)."""
    import json as _json
    import time as _time

    from vigil_core.retest_reproof import RETEST_OUTCOME_SEAM_SUBDIR, ticket_identity
    if not (isinstance(want, (tuple, list)) and len(want) == 4):
        return "unavailable"                        # a malformed re-proof context never confirms a fix
    want = tuple(want)
    seam = _retest_reproof_dir(base, RETEST_OUTCOME_SEAM_SUBDIR)
    path = seam / f"{str(want[3])}.json"
    deadline = _time.monotonic() + max(0.0, float(timeout))
    while True:
        try:
            outcome = _json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            outcome = None
        if isinstance(outcome, dict) and ticket_identity(outcome) == tuple(want):
            v = outcome.get("verdict")
            return v if isinstance(v, str) else "unavailable"
        if _time.monotonic() >= deadline:
            return "unavailable"
        _time.sleep(max(0.0, float(poll)))


def _retest_reverify(ctx: "dict") -> str:
    """C1b — the SEAM that produces ONE finding's live re-proof verdict: ``"cleared"`` (the proof DECISIVELY no
    longer works → the finding is marked fixed), ``"still_present"`` (the proof still fires → Still-Vulnerable),
    or ``"inconclusive"``/``"unavailable"`` (nothing is concluded → the retest refuses, and the finding is NEVER
    marked fixed). ``ctx`` carries inert identity (``host``/``engagement_slug``/``finding_ref``/``bug_class``/
    ``oracle_context_digest``) — no secret, no key — plus, on the REAL path, a ``_reproof`` sub-context the
    sovereign :meth:`Provisioner.retest` added (the seam base + the ticket nonce + the bounded-wait budget) after
    it reserved the lease and published the ticket.

    FAIL-CLOSED. Re-collecting fresh evidence from a LIVE host is OFFENSE-plane work, and the sovereign plane must
    never import the engine (FATAL-2). So this seam NEVER runs the engine: on the real path (``_reproof`` present)
    it bounded-waits the ``retest-outcomes`` seam for the keyless offense worker's inert outcome
    (``_read_retest_outcome`` — only an outcome whose identity matches the issued ticket counts) and returns its
    verdict; absent the ``_reproof`` context (the re-proof flag off, or this seam called bare) it returns
    ``"unavailable"`` — a retest then refuses honestly ("not available right now"), sends no traffic and reserves
    no credit, rather than ever guessing a fix. A caller may still inject its own ``reverify=`` into
    :meth:`Provisioner.retest`; the authorization, tenant binding, fail-closed mapping and the hash-chained
    verdict record around this seam are unchanged, and the sovereign remains the sole authority on the mapping."""
    rp = ctx.get("_reproof") if isinstance(ctx, dict) else None
    if not isinstance(rp, dict):
        return "unavailable"
    return _read_retest_outcome(rp.get("base"), rp.get("want"),
                                timeout=rp.get("timeout", 0.0), poll=rp.get("poll", 0.0))

# A1 auto top-up: the newest receipts the billing read returns, and the newest per-charge notices the notification
# centre carries (each with the stable id ``auto_topup:<crossing>``, so a viewer sees each receipt once).
_AUTO_TOPUP_RECEIPTS = 20
_AUTO_TOPUP_NOTICES = 5


def _auto_topup_notice(c) -> dict:
    """The notification-centre item for one auto-top-up charge record (credits only — never a money amount)."""
    credits = int(getattr(c, "credits", 0) or 0)
    status = str(getattr(c, "status", "") or "")
    if status == "charged":
        sev, title = "info", "Automatic top-up"
        body = (f"{credits:,} credits were bought with your saved card. They are added to your balance as soon as "
                "the payment is confirmed.")
    elif status == "cap_blocked":
        sev, title = "medium", "Monthly top-up limit reached"
        body = (f"An automatic top-up of {credits:,} credits was not made because it would pass your monthly limit. "
                "Raise the limit or buy credits on the Billing page.")
    else:
        sev, title = "high", "Automatic top-up failed"
        body = ("Your saved card could not be charged for an automatic top-up. Buy credits on the Billing page to "
                "keep your assessments running.")
    return {"id": "auto_topup:" + str(getattr(c, "crossing_key", "") or ""), "kind": "billing", "severity": sev,
            "title": title, "body": body, "ts": getattr(c, "issued_at", None)}


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


def _signup_role(founder_latch: "Optional[Callable[[], bool]]" = None) -> str:
    """The per-org role a sign-up grants its founding customer, on BOTH sign-up paths (email confirm and Google
    auto-provision): `founder` while VIGIL_SIGNUP_FOUNDER_TESTER_ENABLED AND VIGIL_TRIAL_PREVIEW_ENABLED are both
    on AND the owner's `founder_tester` latch is ON (``founder_latch()``, read only when both flags allow a founder;
    the environment stays the ceiling), else `org_admin` (the default, unchanged). Server-decided at the committing
    attempt — never a client value.

    The founder role needs the preview trial: with the preview on, the only credits a sign-up grants are the
    preview trial, which keeps the trial rules (the trial product only, one registrable domain, the daily cap)
    until the org buys credits. With the preview off a sign-up grants `org_admin`, whose trial credits cannot fund
    a scan; the owner can still grant `founder` to an existing member (`owner_set_member_role`)."""
    from .. import config
    if config.signup_founder_tester_enabled() and config.trial_preview_enabled():
        if founder_latch is None or founder_latch():
            return _FOUNDER_ROLE
    return "org_admin"


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


def _member_target(username) -> str:
    """The CANONICAL member username every member verb uses for all of its checks, its audit row and its
    owner-signed write. It is the value the org registry itself stores and looks up (`_check_member_username`:
    surrounding whitespace removed, then the username charset enforced), so a check can never read a different
    membership than the write changes. Raises ValueError for a value that is no member username."""
    from ..governor.orgs import _check_member_username
    return _check_member_username(username)


#: How long a member verb waits for the membership critical section before it gives up (nothing written).
_MEMBERS_LOCK_WAIT_S = 10.0


def _members_lock(store):
    """The CROSS-PROCESS critical section for membership changes on `store`'s spine: an flock on
    ``<spine dir>/<stem>.members.lock`` (a ``*.lock`` transient the backups skip), taken with the same hardened
    ``locked_file`` as the settle lock. Every member verb that applies the last-admin rule holds it around that
    check AND its audit and owner-signed write — the customer `grant_member`/`revoke_member` in the cockpit and the
    owner verbs in the `sigil` CLI — so two processes always decide against the administrator set the other left,
    never against the same one. Lock order: ``spine_lock`` (in-process) -> this -> the spine's append lock. A
    bounded wait, then ``LockBusy`` with nothing written; an unusable lock file raises ``OSError`` (fail-closed)."""
    from pathlib import Path
    from vigil_integration.live.seam_lock import locked_file
    raw = getattr(store, "path", None)
    if not raw:
        raise ValueError("the membership lock needs a spine store with a path")
    sp = Path(raw)
    path = sp.parent / f"{sp.stem or sp.name}.members.lock"
    return locked_file(path, wait_s=_MEMBERS_LOCK_WAIT_S, create=False, chown_like=path.parent)


def _member_admins(orgs, org_id: str) -> "set[str]":
    """The usernames whose ACTIVE membership in `org_id` carries `manage_members` (per-org predicate on the stored
    role) — `org_admin` and `founder` today. The last-admin (anti-orphan) rules count these."""
    return {m.username for m in orgs.memberships(org_id) if role_can(m.role, "manage_members")}


def _audit_payload(action: str, *, requester: str, org_id: str, target: str, outcome: str,
                   reason: str) -> "dict[str, object]":
    """The secret-free, field-capped core of one `provision.audit` row (shared by the provisioner and the owner
    membership verbs, so both write the same shape)."""
    return {"signal": "provision.audit", "action": str(action)[:48], "requester": str(requester)[:64],
            "org_id": str(org_id)[:64], "target": str(target)[:64], "outcome": str(outcome)[:32],
            "reason": str(reason)[:160]}


def _owner_membership_audit(store, action: str, *, org_id: str, target: str, role: str, reason: str) -> None:
    """A CRITICAL audit row for an owner membership change, written BEFORE the owner-signed grant: a write failure
    propagates, so the change fails closed (committed implies audited)."""
    payload = _audit_payload(action, requester="owner", org_id=org_id, target=target, outcome=f"role={role}",
                             reason=reason)
    payload["role"] = str(role)[:32]
    store.append(kind="event", source="provision", actor="WARDEN", payload=payload)


def _fresh_issued_at(orgs, org_id: str, username: str, issued_at: float) -> float:
    """An issued_at strictly above the member's current grant, so an owner change is never ignored as stale."""
    cur = next((m.issued_at for m in orgs.memberships(org_id) if m.username == username), None)
    at = float(issued_at)
    return at if cur is None or at > cur else math.nextafter(float(cur), math.inf)


def owner_set_member_role(store, org_id: str, username: str, role: str, *, reason: str, issued_at: float,
                          orgs=None, customers=None) -> dict:
    """OWNER act (`sigil org set-member-role`): owner-sign `username`'s per-org role in `org_id` — any assignable
    per-org role, `founder` included. This is how a founder's role is granted or changed (customer member
    management refuses a founder target). Fail-closed: a valid role and username and a non-empty reason are
    required; the org must be active; the target must be an active customer or a current member of the org; a
    change that would leave the org with no member holding `manage_members` is refused. A CRITICAL audit row is
    written before the owner-signed grant. The checks, the audit and the grant run inside the cross-process
    membership lock (`_members_lock`) that the cockpit's member verbs also hold, so the last-admin rule holds
    across processes. Returns {org_id, username, role, previous_role, seq}."""
    from ..governor.customers import CustomerRegistry
    from ..governor.orgs import OrgRegistry, _check_member_role, _check_org_id
    oid, u, r = _check_org_id(org_id), _member_target(username), _check_member_role(role)
    why = str(reason or "").strip()
    if not why:
        raise ValueError("a reason is required (it is recorded in the audit)")
    orgs = orgs if orgs is not None else OrgRegistry(store)
    customers = customers if customers is not None else CustomerRegistry(store)
    with spine_lock(store.path), _members_lock(store):
        if orgs.org(oid) is None:
            raise ValueError(f"no active org {oid!r}")
        prev = orgs.membership_role(u, oid)
        if prev is None and customers.customer(u) is None:
            raise ValueError("the target is neither an active customer nor a member of this org")
        if not role_can(r, "manage_members") and _member_admins(orgs, oid) == {u}:
            raise ValueError("refused: the org would have no administrator left (grant another admin first)")
        at = _fresh_issued_at(orgs, oid, u, issued_at)
        _owner_membership_audit(store, "owner_set_member_role", org_id=oid, target=u, role=r, reason=why)
        seq = orgs.grant_membership(oid, u, r, issued_at=at)
    return {"org_id": oid, "username": u, "role": r, "previous_role": prev, "seq": seq}


def owner_demote_founders(store, *, reason: str, issued_at: float, org_id: "Optional[str]" = None,
                          orgs=None) -> dict:
    """OWNER act (`sigil org demote-founders`): re-grant `org_admin` to every ACTIVE `founder` membership — in one
    org, or in every active org. Idempotent: a second run finds none. Run it before rolling back to a build that
    has no `founder` role (such a build gives the role no permission, so a founder-only org would have no
    administrator there). Each change writes a CRITICAL audit row before its owner-signed grant, inside the
    cross-process membership lock (`_members_lock`). Returns counts only: {demoted, orgs}."""
    from ..governor.orgs import OrgRegistry, _check_org_id
    why = str(reason or "").strip()
    if not why:
        raise ValueError("a reason is required (it is recorded in the audit)")
    oid = _check_org_id(org_id) if org_id is not None else None
    orgs = orgs if orgs is not None else OrgRegistry(store)
    with spine_lock(store.path), _members_lock(store):
        if oid is not None and orgs.org(oid) is None:
            raise ValueError(f"no active org {oid!r}")
        founders = [m for m in orgs.memberships(oid)
                    if m.role == _FOUNDER_ROLE and orgs.org(m.org_id) is not None]
        for m in founders:
            at = _fresh_issued_at(orgs, m.org_id, m.username, issued_at)
            _owner_membership_audit(store, "owner_demote_founder", org_id=m.org_id, target=m.username,
                                    role="org_admin", reason=why)
            orgs.grant_membership(m.org_id, m.username, "org_admin", issued_at=at)
    return {"demoted": len(founders), "orgs": len({m.org_id for m in founders})}


class Provisioner:
    """The owner-signed signing service. Registries + ledgers are INJECTED (the registries carry the owner
    key; the edge never constructs this). `expose_dev_tokens` is a DEV-ONLY escape hatch that returns the
    email token in the response when no real sender is configured — it must stay False in production."""

    def __init__(self, store, *, customers, orgs, wallet, email_tokens, rate_limiter, email_sender,
                 signup_cap_limiter=None, member_limiter=None, target_fetcher=None, signup_email_limiter=None,
                 customer_credentials=None, oidc_provider=None, mfa_replay=None, signcount=None,
                 pending_totp=None, mfa_limiter=None,
                 checkout_limiter=None, pending_checkouts=None,
                 trial_credits: int = _DEFAULT_TRIAL_CREDITS, trial_claims=None, trial_launch_limiter=None,
                 trial_ip_limiter=None, email_codes=None, email_code_limiter=None,
                 expose_dev_tokens: bool = False, now_fn=time.time):
        self.store = store
        self.customers = customers
        self.orgs = orgs
        self.wallet = wallet
        self.email_tokens = email_tokens
        # The 6-digit email codes (an EmailCodeLedger) sent beside the token. None ⇒ off: the emails carry only the
        # token, exactly as before, and the code confirmations refuse. `email_code_limiter` (a LoginRateLimiter) bounds
        # wrong codes per email+purpose ACROSS re-sent codes (each code also dies at its own 5th wrong code); the
        # per-IP leg uses `rate_limiter`.
        self.email_codes = email_codes
        self.email_code_limiter = email_code_limiter
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
        # Enrolment hardening (customer_mfa_enroll_stepup_enabled, default OFF). The PENDING (unconfirmed) TOTP
        # store (confirm-before-activate): with the flag on, enroll_totp parks the SEALED secret here and
        # confirm_totp activates it, so a hijacked session cannot silently swap the active factor. None with the
        # flag ON ⇒ enroll_totp fail-closed (it cannot park a pending secret). Untouched while the flag is off.
        self.pending_totp = pending_totp
        # The per-account MFA limiter (a LoginRateLimiter) bounding TOTP code-guessing (verify + confirm) and
        # enrolment churn (enroll_totp / enroll_passkey), in two key namespaces. USED only while the flag is on
        # (so OFF is byte-identical); None ⇒ no limiting (no dead, never-incremented gate — the member_limiter
        # pattern). The factory always wires it; a test that cares injects one.
        self.mfa_limiter = mfa_limiter
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
        # The DURABLE per-org / per-requester checkout-creation limiter (a LoginRateLimiter, guard-and-count via
        # `admit`). The HTTP transport builds a fresh Provisioner per request, so the limit MUST live on disk,
        # not on this instance. None ⇒ checkout is REFUSED (fail-closed: an unwired limiter can never mean
        # "unlimited" outbound processor calls). The factory wires `_CHECKOUT_MAX` per `_CHECKOUT_WINDOW_S`.
        self.checkout_limiter = checkout_limiter
        # Audit E1b — the owner-signed, expiring, cross-process-exclusive PENDING plan-checkout record (a
        # `pending_checkout.PendingPlanCheckouts`) that bridges the gap before a paid plan's webhook drains. None ⇒
        # PLAN checkout is refused (fail-closed); top-ups never touch it.
        self.pending_checkouts = pending_checkouts
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
               outcome: str = "", reason: str = "", critical: bool = False, attestation: bool = False,
               tx_ref: str = "", expires_at: float = 0.0, role: str = "") -> None:
        """Append one secret-free, field-capped `provision.audit` spine event linking an edge request to the
        owner-signed mint it triggered (the principal's tamper-evident edge→mint audit).

        Finding B — audit durability: for a SECURITY-CRITICAL governance mutation (`critical=True`), the
        audit write is NOT swallowed — a failure PROPAGATES so the operation FAILS CLOSED (the caller sees
        an error and, because the mutations are idempotent, may safely retry). It is written while holding
        the transaction lock, before the signup commit marker, so a committed signup is always audited.
        Only NON-critical telemetry (`critical=False`, e.g. a login outcome) swallows a write failure,
        following a separate availability policy."""
        payload = _audit_payload(action, requester=requester, org_id=org_id, target=target, outcome=outcome,
                                 reason=reason)
        if role:
            payload["role"] = str(role)[:32]        # the per-org role a sign-up or owner membership change granted
        if tx_ref:
            payload["tx_ref"] = str(tx_ref)[:128]   # the processor reference this audit row is about (checkout)
        if expires_at:
            payload["expires_at"] = float(expires_at)   # a created PLAN checkout's pending window (E1b backstop)
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

    # -- enrolment hardening (customer_mfa_enroll_stepup_enabled; default OFF ⇒ all three are no-ops) ----
    def _enroll_hardening_on(self) -> bool:
        from .. import config
        return config.customer_mfa_enroll_stepup_enabled()

    def _has_active_mfa_factor(self, requester: str) -> bool:
        """True iff `requester` ALREADY has an active SECOND FACTOR (an enrolled TOTP or passkey). A federated
        (Google) binding is a primary login method, not a second factor, so it does not count — enrolling the
        first TOTP/passkey over an OIDC-only account is still the bootstrap case. The basis for the step-up
        gate: replacing/adding a factor when one exists needs proof of the current one; the FIRST factor cannot
        (you can't step-up with a factor the account does not have)."""
        if self.customer_credentials is None:
            return False
        from ..governor.customer_credentials import KIND_PASSKEY, KIND_TOTP
        return any(c.kind in (KIND_TOTP, KIND_PASSKEY)
                   for c in self.customer_credentials.for_user(requester))

    def _require_enroll_stepup(self, requester: str, mfa_at, *, now: float) -> None:
        """Enrolment step-up: when the hardening flag is ON and `requester` ALREADY has a second factor, adding
        or replacing one needs a FRESH step-up (`mfa_at` within `CUSTOMER_STEPUP_WINDOW_SECONDS`) — so a hijacked
        session that never proved the CURRENT factor cannot swap it. The FIRST factor (no existing factor) is
        allowed WITHOUT step-up (bootstrap, documented). NO-OP while the flag is off (byte-identical). Fail-
        closed: a missing / non-numeric / non-positive / stale mfa_at refuses with ProvisionStepUpRequired."""
        from .. import config
        if not self._enroll_hardening_on():
            return
        if not self._has_active_mfa_factor(requester):
            return                                       # bootstrap: the first factor needs no step-up
        try:
            at = float(mfa_at)
        except (TypeError, ValueError):
            at = 0.0
        if at <= 0.0 or (now - at) > float(config.CUSTOMER_STEPUP_WINDOW_SECONDS):
            raise ProvisionStepUpRequired("a fresh second-factor (step-up) is required to change your authenticator")

    def _mfa_enroll_rate_guard(self, requester: str, *, now: float) -> None:
        """Guard-AND-COUNT one enrolment attempt (enroll_totp / enroll_passkey) against the per-account MFA
        limiter's `mfa:enroll:` namespace — bounds enrolment churn by a hijacked session. NO-OP while the flag
        is off (byte-identical) or no limiter is wired (no dead gate). A locked key refuses fail-closed BEFORE
        the enrol, and the attempt is recorded (abusive and legitimate alike count toward the window)."""
        if not self._enroll_hardening_on() or self.mfa_limiter is None:
            return
        key = f"mfa:enroll:{requester}"
        locked = self.mfa_limiter.locked(key, now=now)
        if locked is not None:
            raise ProvisionRateLimited(locked)
        self.mfa_limiter.record_failure(key, now=now)

    def _mfa_code_rate_guard(self, requester: str, *, now: float) -> None:
        """Refuse a TOTP code check (verify_mfa / confirm_totp) when the per-account `mfa:code:` budget is
        locked — bounds code-guessing. NO-OP while the flag is off or no limiter is wired. The CALLER records a
        failure on a wrong code and a success on a good one, mirroring the login limiter's failure-counter use."""
        if not self._enroll_hardening_on() or self.mfa_limiter is None:
            return
        locked = self.mfa_limiter.locked(f"mfa:code:{requester}", now=now)
        if locked is not None:
            raise ProvisionRateLimited(locked)

    def _mfa_code_fail(self, requester: str, *, now: float) -> None:
        """Count one WRONG TOTP code against the per-account `mfa:code:` budget (no-op while off / unwired)."""
        if not self._enroll_hardening_on() or self.mfa_limiter is None:
            return
        self.mfa_limiter.record_failure(f"mfa:code:{requester}", now=now)

    def _mfa_code_ok(self, requester: str) -> None:
        """Clear the per-account `mfa:code:` budget after a GOOD code (no-op while off / unwired)."""
        if not self._enroll_hardening_on() or self.mfa_limiter is None:
            return
        self.mfa_limiter.record_success(f"mfa:code:{requester}")

    def _member_admins(self, org_id: str) -> "set[str]":
        """The usernames whose ACTIVE membership in `org_id` carries `manage_members` (resolved LIVE from the
        membership fold) — `org_admin` and `founder` today. The basis for last-admin protection: an org must never
        be left with zero admins, or nobody could ever manage its members/billing again (an un-governable,
        orphaned tenant)."""
        return _member_admins(self.orgs, org_id)

    def _latch_refusal(self, name: str) -> "Optional[str]":
        """The owner's customer latch ``name`` (``governor.customer_latch``), read fresh from the spine (an off-switch
        is honoured at once, no restart; a read that fails refuses): None when it is on, else the customer-facing
        reason. Consulted only before a NEW sign-up, checkout, trial grant or trial scan."""
        from ..governor.customer_latch import refusal
        return refusal(self.store, name, trusted_pubkey=getattr(self.orgs, "trusted_pubkey", None))

    def _founder_latch_open(self) -> bool:
        """The owner's ``founder_tester`` latch, read fresh (fail-closed: a read that fails answers OFF, so the
        sign-up grants `org_admin`). Consulted only by `_signup_role` when the environment allows a founder."""
        return self._latch_refusal("founder_tester") is None

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
            # the owner's `trial` latch withholds a NEW trial; a grant this sign-up already made stands
            if not self.wallet.has_grant_entry(org_id, legacy) and self._latch_refusal("trial") is not None:
                return self._trial_withheld(org_id, "paused")
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
            if self._latch_refusal("trial") is not None:        # the owner's `trial` latch: no NEW trial claim
                return self._trial_withheld(org_id, "paused")
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
        paused = self._latch_refusal("customer_signup")    # the owner's latch: no NEW sign-up is started
        if paused is not None:
            raise ProvisionDenied(paused)
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
        code = None
        if token and self.email_codes is not None:
            # the code is bound to the ids THIS token derives, so the code and the token complete the same sign-up
            # (a crash half-way through one is finished by either); the derived ids are not secrets
            code = self.email_codes.issue(email_l, PURPOSE_VERIFY, now=t,
                                          bind={"u": _signup_username(token), "o": _signup_org_id(token)})
        body = (_SIGNUP_CODE_EMAIL.format(code=format_code(code), token=token) if code
                else f"Confirm: token {token}")
        sent = bool(token) and self.email_sender.send(email_l, "Verify your VIGIL email", body) if token else False
        out: "dict[str, object]" = {"status": "verification_sent"}   # same response whether or not the email exists
        if self.email_codes is not None:
            out["code"] = True                         # the deployment sends codes (the same answer for every request)
        if token and self.expose_dev_tokens and not sent:
            out["dev_token"] = token                   # DEV ONLY (no real sender) — never populated in prod
            if code:
                out["dev_code"] = code
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
        The role is SERVER-set (`_signup_role`: `org_admin`, or `founder` while the founder flag is on, read at
        the committing attempt); the org_id/username are SERVER-derived (never client values);
        the trial amount is a server constant granted ONLY now (post-verification, anti-Sybil) and bounded by
        the optional GLOBAL signup cap (anti-farming). A DIFFERENT token for an already-registered email
        derives a different username, so the by-email collision check refuses it (no second account)."""
        t = self._now() if now is None else float(now)
        tok = str(token or "")
        email = self.email_tokens.peek(tok, PURPOSE_VERIFY, now=t)   # validate WITHOUT consuming (commit-marker)
        if not email:
            raise ProvisionDenied("invalid or expired verification token")
        return self._signup_commit(email, _signup_username(tok), _signup_org_id(tok), password=password,
                                   org_name=org_name, ip=ip, t=t,
                                   commit=lambda: self.email_tokens.consume(tok, PURPOSE_VERIFY, now=t))

    def confirm_signup_code(self, email: str, code: str, *, password: str, org_name: str, ip: str = "",
                            now: "Optional[float]" = None) -> dict:
        """Phase 2 with the 6-digit code from the verification email instead of its token (the installed app types
        the code). The code is checked WITHOUT being consumed (wrong codes count: 5 per email, then it is gone; plus
        the per-IP limit), then the SAME commit-marker transaction runs over the ids bound to the code at issue —
        the ids the email's token derives — and consuming the code is the commit marker."""
        t = self._now() if now is None else float(now)
        email_l, bind = self._code_check(email, PURPOSE_VERIFY, code, ip=ip, t=t, consume=False)
        username, org_id = str(bind.get("u") or ""), str(bind.get("o") or "")
        if not username or not org_id:
            raise ProvisionDenied("invalid or expired code")
        codes = self.email_codes
        return self._signup_commit(email_l, username, org_id, password=password, org_name=org_name, ip=ip, t=t,
                                   commit=lambda: codes.consume_code(email_l, PURPOSE_VERIFY))

    def _code_check(self, email: str, purpose: str, code, *, ip: str, t: float, consume: bool) -> "tuple[str, dict]":
        """Check a typed email code. EVERY attempt is counted BEFORE the code is hashed, in one atomic step per leg
        (`LoginRateLimiter.admit`, under the limiter's flock, across threads and processes): per caller IP
        (`rate_limiter`) and per email+purpose (`email_code_limiter`, 5 an hour across re-sent codes) — so no burst
        of concurrent guesses gets more evaluations than the limit, and a locked leg refuses before any hash. Both
        legs count whether or not the address has a live code: the answer (and the lock) never hint whether it has
        an account. A wrong, malformed, expired or unknown code is one generic refusal. Returns (email, bound
        values)."""
        if self.email_codes is None:
            raise ProvisionError("email codes are not enabled on this deployment")
        from .oidc_handoff import ip_rate_key           # the per-IP leg buckets IPv6 by /64 (one subscriber range)
        email_l = str(email or "").strip().lower()
        ikey, ekey = f"code:ip:{ip_rate_key(ip)}", f"code:{purpose}:{email_l}"
        wait = self.rate_limiter.admit(ikey, now=t)
        if wait is not None:
            raise ProvisionRateLimited(wait)
        if self.email_code_limiter is not None:
            wait = self.email_code_limiter.admit(ekey, now=t)
            if wait is not None:
                raise ProvisionRateLimited(wait)
        res = self.email_codes.check(email_l, purpose, code, consume=consume, now=t) if email_l else None
        if isinstance(res, CodeOk):
            return email_l, res.bind
        if isinstance(res, CodeBlocked):
            # Cumulative hard ceiling reached: code entry for this (email, purpose) is disabled until the email
            # LINK (the token) is used. A distinct message guides the person there; it reveals only that many wrong
            # codes were entered for this address (which the attacker who entered them already knows), not whether
            # an account exists — a sign-up code is issued for any address, and the recover path's existence signal
            # predates codes.
            self._audit(f"{purpose}_code", target=email_l, outcome="blocked")
            raise ProvisionDenied("too many incorrect codes were entered for this email; "
                                  "use the link in the email instead")
        self._audit(f"{purpose}_code", target=email_l, outcome="denied")
        raise ProvisionDenied("invalid or expired code")

    def _signup_commit(self, email: str, username: str, org_id: str, *, password: str, org_name: str, ip: str,
                       t: float, commit) -> dict:
        """The owner-signed sign-up transaction for a verified mailbox (see confirm_signup): idempotent mints over
        the deterministic `username`/`org_id`, the critical audit, then `commit()` (consume the token or the code —
        the commit marker), then every other token and code for the email is dropped."""
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
                # the owner's `customer_signup` latch refuses a NEW sign-up (the token stays valid for later); a
                # retry finishing a sign-up whose account already exists is never refused
                paused = self._latch_refusal("customer_signup")
                if paused is not None:
                    raise ProvisionDenied(paused)
                self.customers.create(email, password=password, username=username,
                                      issued_at=self._next_issued())
            # idempotent re-targets: LWW on the deterministic org_id; wallet dedups on the deterministic entry_id
            self.orgs.create_org(org_id, str(org_name or email), owner=username, issued_at=self._next_issued())
            role = _signup_role(self._founder_latch_open)
            self.orgs.grant_membership(org_id, username, role, issued_at=self._next_issued())
            trial = self._grant_signup_trial(org_id, email, source_ref="signup", ip=ip)
            # durable audit BEFORE the commit marker (fail-closed): a failure leaves the token valid to retry,
            # and the mutations above are idempotent, so the retry is safe.
            self._audit("signup", requester=username, org_id=org_id, target=username, outcome="created",
                        role=role, critical=True)
            # COMMIT MARKER — consume the token (or the code) LAST (single-use); a replay now finds it consumed.
            commit()
            if self.signup_cap_limiter is not None:         # count this signup toward the cap (post-commit)
                self.signup_cap_limiter.record_failure("signup:global", now=t)
        self.email_tokens.revoke_for_email(email)      # drop any other outstanding tokens for this email
        if self.email_codes is not None:
            self.email_codes.revoke_for_email(email)   # ... and its codes: one sign-up, by the token or the code
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
        (never an operator bearer; `CustomerPrincipal` carries no global role), plus `email`, the verified Google
        address, which the installed-app hand-off page shows in the browser that just signed in with it (never
        used to resolve or mint anything). Fail-closed when customer
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
        result["email"] = str(identity.email or "")          # display only (the hand-off page names the account)
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
        # the owner's `customer_signup` latch refuses a NEW federated customer; a retry finishing this identity's own
        # deterministic account (a crash between its mints) is never refused
        if self.customers.customer(username) is None:
            paused = self._latch_refusal("customer_signup")
            if paused is not None:
                raise ProvisionDenied(paused)
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
        role = _signup_role(self._founder_latch_open)
        self.orgs.grant_membership(org_id, username, role, issued_at=self._next_issued())
        self._grant_signup_trial(org_id, email, source_ref="signup-google", ip=ip)
        # owner-sign the (iss,sub) binding LAST among the mints (its own global-uniqueness guard refuses a
        # cross-customer rebind): a crash before it leaves by_federated unresolved ⇒ a safe retry re-provisions.
        self.customer_credentials.link_federated(username, iss=iss, sub=sub, issued_at=self._next_issued())
        self._audit("signup", requester=username, org_id=org_id, target=username, outcome="created-google",
                    role=role, critical=True)
        if self.signup_cap_limiter is not None:             # count this signup toward the cap (post-commit)
            self.signup_cap_limiter.record_failure("signup:global", now=now)
        return username

    # -- customer MFA: TOTP enroll + verify (E3b) ---------------------------------------------------
    def enroll_totp(self, requester: str, *, ip: str = "", mfa_at=0.0,
                    now: "Optional[float]" = None) -> dict:
        """E3b — enroll (or re-enroll) a TOTP second factor for the requesting customer's OWN account. MFA is
        account-level (per customer username), NOT per-org, so the gate is simply that the requester is an
        ACTIVE customer (the edge binds requester from the SESSION, never the body). Generates a fresh secret,
        SEALS it via the owner vault (only the sealed blob reaches the spine — the plaintext is returned ONCE
        for the customer to add to their authenticator app, NEVER persisted), and returns the otpauth:// URI +
        the secret. Fail-closed when customer MFA is not enabled on this deployment.

        Enrolment hardening (`customer_mfa_enroll_stepup_enabled`, default OFF ⇒ BYTE-IDENTICAL to below):
          * STEP-UP — replacing/adding a factor when the account already has one needs a FRESH `mfa_at`
            (the SESSION step-up stamp, never a body field); the first factor is allowed without step-up;
          * RATE-LIMIT — the enrol attempt is counted against the per-account enrolment budget;
          * CONFIRM-BEFORE-ACTIVATE — the sealed secret is PARKED as pending (NOT owner-signed active), so a
            hijacked session cannot silently swap the victim's authenticator; `confirm_totp` (a fresh code)
            activates it. The response then carries `pending: True`.
        With the flag OFF the secret is owner-signed ACTIVE immediately (the per-(username,"totp") high-water
        LWW supersedes any prior TOTP), exactly as before."""
        if self.customer_credentials is None:
            raise ProvisionError("customer MFA is not enabled on this deployment")
        acct = self.customers.customer(requester)
        if acct is None:
            raise ProvisionDenied("requester is not an active customer")
        hardened = self._enroll_hardening_on()
        t = 0.0
        if hardened:                                      # the flag-OFF path never enters (nor reads the clock)
            if self.pending_totp is None:
                raise ProvisionError("MFA enrollment is unavailable (no pending store)")
            t = self._now() if now is None else float(now)
            self._require_enroll_stepup(requester, mfa_at, now=t)
            self._mfa_enroll_rate_guard(requester, now=t)
        from .. import config
        from ..governor import totp as _totp
        from ..platform.vault import owner_vault
        secret = _totp.generate_secret()
        try:
            blob = owner_vault().seal_secret(secret.encode("utf-8"), context=config.CUSTOMER_TOTP_SEAL_CONTEXT)
        except Exception:  # noqa: BLE001 — VaultLocked (unprovisioned) / seal fault → clean refusal, not a 500
            raise ProvisionError("MFA enrollment is unavailable (the owner vault is not provisioned)") from None
        sealed_b64 = base64.b64encode(blob).decode("ascii")
        if hardened:
            # Confirm-before-activate: park the SEALED secret; nothing is owner-signed active until confirm_totp.
            try:
                self.pending_totp.put(requester, sealed_b64, now=t)
            except (OSError, ValueError):
                raise ProvisionError("MFA enrollment could not be saved") from None
            self._audit("mfa_enroll_totp", requester=requester, target=requester, outcome="pending")
            uri = _totp.provisioning_uri(secret, account_name=(acct.email or requester), issuer="VIGIL")
            return {"ok": True, "method": "totp", "provisioning_uri": uri, "secret": secret, "pending": True}
        with self._lock:
            self.customer_credentials.enroll_totp(requester, sealed_secret=sealed_b64,
                                                  issued_at=self._next_issued())
            self._audit("mfa_enroll_totp", requester=requester, target=requester, outcome="enrolled",
                        critical=True)
        uri = _totp.provisioning_uri(secret, account_name=(acct.email or requester), issuer="VIGIL")
        return {"ok": True, "method": "totp", "provisioning_uri": uri, "secret": secret}

    def security_status(self, requester: str) -> dict:
        """The Account security screen's read for the requesting customer's OWN account: whether an authenticator app
        (TOTP) is set up, the passkeys registered (credential id — not a secret: the browser is told it to avoid a
        duplicate — and when each was added), and the name an authenticator shows for the account (its email, as in the
        TOTP setup link). Never a secret, a sealed blob or a public key. Account-level like MFA: the requester is the
        hop-bound session principal, never a body field, and must be an ACTIVE customer. Fail-closed when customer MFA
        is not enabled on this deployment."""
        if self.customer_credentials is None:
            raise ProvisionError("customer MFA is not enabled on this deployment")
        acct = self.customers.customer(requester)
        if acct is None:
            raise ProvisionDenied("requester is not an active customer")
        from ..governor.customer_credentials import KIND_PASSKEY, KIND_TOTP
        creds = self.customer_credentials.for_user(requester)
        passkeys = sorted((c for c in creds if c.kind == KIND_PASSKEY), key=lambda c: (c.issued_at, c.cred_key))
        return {"ok": True, "totp": any(c.kind == KIND_TOTP for c in creds),
                "passkeys": [{"id": c.cred_key, "added_at": c.issued_at} for c in passkeys],
                "account_name": acct.email or requester}

    def confirm_totp(self, requester: str, *, code: str = "", mfa_at=0.0,
                     now: "Optional[float]" = None) -> dict:
        """Enrolment hardening — ACTIVATE a pending TOTP enrolment (`enroll_totp` with the flag on parked it) by
        proving a fresh code from the authenticator the customer just added. Only now is the credential
        owner-signed active (the high-water LWW supersedes any prior TOTP), so a hijacked session that cannot
        produce a live code can never complete a factor swap.

        The STEP-UP gate is re-checked HERE, at activation, not only at enrolment: a secret parked under the
        bootstrap exemption (the account had no factor) must not become active without step-up once the account HAS
        gained a factor (e.g. its owner added a passkey in between) — otherwise a hijacked session could park a
        secret early and add it as a second factor later. `mfa_at` is the SESSION step-up stamp, never a body field.

        Fail-closed at every step: the hardening flag must be ON (else there is no pending flow — refuse);
        requester must be an ACTIVE customer; a fresh step-up when the account already has a factor; the
        per-account code budget must be unlocked; a pending (unexpired) sealed secret must exist and open under
        the customer TOTP context; the code must verify within the ±1-step skew; and the `(requester, step)` must
        be UNSPENT in the replay ledger (the same ledger verify_mfa uses, so a code spent here cannot be replayed
        for step-up and vice-versa). On success the pending secret is cleared. Returns {ok, method}."""
        t = self._now() if now is None else float(now)
        if not self._enroll_hardening_on():
            raise ProvisionDenied("TOTP confirmation is not enabled on this deployment")
        if self.customer_credentials is None or self.mfa_replay is None or self.pending_totp is None:
            raise ProvisionError("customer MFA is not enabled on this deployment")
        if self.customers.customer(requester) is None:
            raise ProvisionDenied("requester is not an active customer")
        self._require_enroll_stepup(requester, mfa_at, now=t)   # re-checked at ACTIVATION (closes the TOCTOU)
        self._mfa_code_rate_guard(requester, now=t)       # bound code-guessing against the pending secret
        sealed = self.pending_totp.peek(requester, now=t)
        if not sealed:
            raise ProvisionDenied("no pending TOTP enrolment to confirm")
        from .. import config
        from ..governor import totp as _totp
        from ..platform.vault import owner_vault
        try:
            secret = owner_vault().unseal_secret(base64.b64decode(sealed),
                                                 context=config.CUSTOMER_TOTP_SEAL_CONTEXT).decode("utf-8")
        except Exception:  # noqa: BLE001 — sealed secret unreadable (vault locked / tamper / wrong context)
            raise ProvisionDenied("TOTP confirmation is unavailable") from None
        step = _totp.verify(secret, code, at=t, window=1)
        if step is None:
            self._mfa_code_fail(requester, now=t)
            raise ProvisionDenied("invalid or expired TOTP code")
        if not self.mfa_replay.consume(requester, step):
            raise ProvisionDenied("this TOTP code was already used")
        with self._lock:
            self.customer_credentials.enroll_totp(requester, sealed_secret=sealed,
                                                  issued_at=self._next_issued())
            self._audit("mfa_confirm_totp", requester=requester, target=requester, outcome="activated",
                        critical=True)
        self.pending_totp.clear(requester)
        self._mfa_code_ok(requester)
        return {"ok": True, "method": "totp"}

    def onboarding_state(self, requester: str) -> dict:
        """The onboarding tour's state for the requesting customer's OWN account (``ui/onboarding_store``): ``pending``
        until they finish (``done``) or skip (``skipped``) it. Account-level, like MFA: the requester is the
        hop-bound session principal, never a body field, and must be an ACTIVE customer."""
        if self.customers.customer(requester) is None:
            raise ProvisionDenied("requester is not an active customer")
        from .onboarding_store import read_state
        return {"ok": True, "state": read_state(requester)}

    def onboarding_record(self, requester: str, state: str, *, now: "Optional[float]" = None) -> dict:
        """Record that the requesting customer finished (``done``) or skipped (``skipped``) the onboarding tour, so it
        does not open again on any device. Refuses any other state and an inactive account; writes nothing else.

        BOUNDED: the same answer again writes nothing, and only the FIRST close (from ``pending``) is audited — one
        ``provision.audit`` row per account — so no customer can grow the signed spine by re-posting the state (a
        replayed tour still updates the stored answer)."""
        if self.customers.customer(requester) is None:
            raise ProvisionDenied("requester is not an active customer")
        from .onboarding_store import PENDING, STATES, read_state, write_state
        if state not in STATES:
            raise ProvisionError(f"state must be one of {', '.join(STATES)}")
        prev = read_state(requester)
        if prev == state:
            return {"ok": True, "state": state}
        t = self._now() if now is None else float(now)
        try:
            write_state(requester, state, now=t)
        except OSError as e:
            raise ProvisionError(f"the onboarding state could not be saved: {type(e).__name__}") from None
        if prev == PENDING:
            self._audit("onboarding_record", requester=requester, target=requester, outcome=state)
        return {"ok": True, "state": state}

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
        self._mfa_code_rate_guard(requester, now=t)       # bound code-guessing (no-op while the flag is off)
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
            self._mfa_code_fail(requester, now=t)         # count a wrong code toward the brute-force budget
            raise ProvisionDenied("invalid or expired TOTP code")
        # Replay guard: consume AFTER a successful verify (an invalid code never touches the ledger), so a
        # code already spent for its (username, step) is refused — mirrors the operator _check_totp ledger.
        if not self.mfa_replay.consume(requester, step):
            raise ProvisionDenied("this TOTP code was already used")
        self._mfa_code_ok(requester)                      # a good code clears the budget (no-op while off)
        self._audit("mfa_verify", requester=requester, target=requester, outcome="ok")
        return {"ok": True, "method": "totp"}

    # -- customer passkey: WebAuthn enroll + login (E3b-2) -------------------------------------------
    def enroll_passkey(self, requester: str, *, credential_id: str, public_key_spki_b64: str, cose_alg,
                       uv: bool, client_data_json: str, expected_challenge: str, mfa_at=0.0,
                       now: "Optional[float]" = None) -> dict:
        """E3b-2 — register a WebAuthn passkey for the requesting customer's OWN account (account-level; the
        requester is the session/hop principal, never a body field). ``verify_registration`` validates the
        clientDataJSON (type == webauthn.create, challenge, origin in the configured allowlist); the credential
        public key is the WebAuthn-L2 ``getPublicKey()`` DER SubjectPublicKeyInfo the browser supplied (so NO
        attestation-CBOR parse — a bad key only fails that customer's own later login). Owner-signs the
        credential via the E2a ``enroll_passkey`` (its GLOBAL uniqueness refuses a credential_id already bound
        to another customer — the anti-hijack crypto backing). Fail-closed when passkey is not configured.

        Enrolment hardening (`customer_mfa_enroll_stepup_enabled`, default OFF ⇒ byte-identical): adding a
        passkey when the account ALREADY has a factor needs a FRESH step-up (`mfa_at`, session-bound), and the
        attempt counts against the per-account enrolment budget. A passkey enrol has NO pending/confirm split —
        its WebAuthn registration ceremony is itself the proof the customer holds the new authenticator."""
        from . import webauthn as _wa
        if self.customer_credentials is None:
            raise ProvisionError("customer passkey is not enabled on this deployment")
        acct = self.customers.customer(requester)
        if acct is None:
            raise ProvisionDenied("requester is not an active customer")
        if self._enroll_hardening_on():                    # the flag-OFF path never enters (nor reads the clock)
            t = self._now() if now is None else float(now)
            self._require_enroll_stepup(requester, mfa_at, now=t)
            self._mfa_enroll_rate_guard(requester, now=t)
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
        out: "dict[str, object]" = {"status": "recovery_sent"}
        if self.email_codes is not None:
            out["code"] = True                         # the deployment sends codes (the same answer for every email)
        if email_l and self.customers.by_email(email_l) is not None:
            token = self.email_tokens.issue(email_l, PURPOSE_RECOVER, now=t)
            code = (self.email_codes.issue(email_l, PURPOSE_RECOVER, now=t)
                    if token and self.email_codes is not None else None)
            body = (_RECOVER_CODE_EMAIL.format(code=format_code(code), token=token) if code
                    else f"Reset: token {token}")
            sent = bool(token) and self.email_sender.send(email_l, "Reset your VIGIL password", body)
            if token and self.expose_dev_tokens and not sent:
                out["dev_token"] = token               # DEV ONLY
                if code:
                    out["dev_code"] = code
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
        from ..governor.accounts import check_password_policy
        check_password_policy(new_password)            # a refused password must not spend the token
        email = self.email_tokens.consume(str(token or ""), PURPOSE_RECOVER, now=t)
        if not email:
            raise ProvisionDenied("invalid or expired recovery token")
        return self._recover_commit(email, new_password)

    def confirm_recover_code(self, email: str, code: str, *, new_password: str, ip: str = "",
                             now: "Optional[float]" = None) -> dict:
        """The password reset with the 6-digit code from the reset email instead of its token. The new password is
        checked first (a refused one does not spend the code), then the code is checked and consumed in one step
        (single use; wrong codes count: 5 per email, then it is gone; plus the per-IP limit), then the same
        owner-signed reset and session-revocation contract as confirm_recover."""
        t = self._now() if now is None else float(now)
        if self.email_codes is None:
            raise ProvisionError("email codes are not enabled on this deployment")
        from ..governor.accounts import check_password_policy
        check_password_policy(new_password)
        email_l, _bind = self._code_check(email, PURPOSE_RECOVER, code, ip=ip, t=t, consume=True)
        return self._recover_commit(email_l, new_password)

    def _recover_commit(self, email: str, new_password: str) -> dict:
        """The owner-signed reset for a mailbox already proven (token or code consumed), then every other token and
        code for the email is dropped; the edge revokes the account's sessions on the answer."""
        with self._lock:
            acct = self.customers.by_email(email)
            if acct is None:
                raise ProvisionDenied("no such account")
            self.customers.set_password(acct.username, new_password, issued_at=self._next_issued())
            self._audit("recover", requester=acct.username, target=acct.username, outcome="password_reset",
                        critical=True)
        self.email_tokens.revoke_for_email(email)      # no sibling verify/recover token survives the reset
        if self.email_codes is not None:
            self.email_codes.revoke_for_email(email)   # ... nor any code
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
        cannot sign through a stale check, and the whole check-then-write also holds the cross-process membership
        lock (`_members_lock`) the owner verbs take; the target must be a real active customer; a change that would
        orphan the org (leave no member holding `manage_members`) is refused; the op is rate-limited per org.
        A target whose CURRENT role is `founder` is refused (the founder included, on themself): changing a
        founder's role is an owner act (`owner_set_member_role`).

        The target is canonicalised ONCE, before anything else (`_member_target`), and only that canonical
        username is used afterwards — by the founder check, the customer lookup, the last-admin rule, the audit
        and the owner-signed grant — so every check reads the exact membership the grant writes."""
        t = self._now() if now is None else float(now)
        if role not in _CUSTOMER_GRANTABLE_ROLES:                        # pure input validation (no state)
            raise ProvisionDenied(f"role must be one of {sorted(_CUSTOMER_GRANTABLE_ROLES)}")
        member_username = _member_target(member_username)
        with self._lock, _members_lock(self.store):
            if not self.orgs.admit_customer(username=requester, org_id=requester_org_id,
                                            permission="manage_members"):
                self._audit("grant_member", requester=requester, org_id=requester_org_id,
                            target=member_username, outcome="denied")
                raise ProvisionDenied("requester is not an administrator of this org")
            self._require_stepup(mfa_at, now=t)      # E3c: a fresh step-up (no-op unless enforcement is on)
            # P6: meter AUTHORIZED churn only — the rate guard records AFTER admit_customer, so a non-admin
            # cannot burn the per-org member budget and lock the real admin out (the limiter's finding).
            self._member_rate_guard(requester_org_id, now=t)
            if self.orgs.membership_role(member_username, requester_org_id) == _FOUNDER_ROLE:
                self._audit("grant_member", requester=requester, org_id=requester_org_id,
                            target=member_username, outcome="denied", reason="founder_owner_only")
                raise ProvisionDenied("the founder's role can only be changed by the service owner")
            if self.customers.customer(member_username) is None:        # never seat an unknown / foreign id
                raise ProvisionDenied("target is not an active customer account")
            if (not role_can(role, "manage_members")
                    and self._member_admins(requester_org_id) == {member_username}):
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
        revoke of the requester's own admin membership), and the check-then-write also holds the cross-process
        membership lock (`_members_lock`) the owner verbs take; the org's SOLE administrator (member holding
        `manage_members`) cannot be revoked (anti-orphan — the tenant must retain at least one administrator);
        and a `founder` membership is never revoked here (the founder included, on themself): that is an
        owner act.

        The target is canonicalised ONCE, before any audit (`_member_target`), and only that canonical username
        is used afterwards — by the founder check, the last-admin rule, the audit and the owner-signed revoke —
        so every check reads the exact membership the revoke removes."""
        t = self._now() if now is None else float(now)
        member_username = _member_target(member_username)   # NH-3 prep: validate target shape before any audit
        with self._lock, _members_lock(self.store):
            if not self.orgs.admit_customer(username=requester, org_id=requester_org_id,
                                            permission="manage_members"):
                self._audit("revoke_member", requester=requester, org_id=requester_org_id,
                            target=member_username, outcome="denied")
                raise ProvisionDenied("requester is not an administrator of this org")
            self._require_stepup(mfa_at, now=t)      # E3c: a fresh step-up (no-op unless enforcement is on)
            self._member_rate_guard(requester_org_id, now=t)   # P6: meter AUTHORIZED churn only (after admit)
            if self.orgs.membership_role(member_username, requester_org_id) == _FOUNDER_ROLE:
                self._audit("revoke_member", requester=requester, org_id=requester_org_id,
                            target=member_username, outcome="denied", reason="founder_owner_only")
                raise ProvisionDenied("the founder can only be removed by the service owner")
            admins = self._member_admins(requester_org_id)
            if member_username in admins and len(admins) <= 1:
                raise ProvisionDenied("cannot remove the last administrator of the org")   # anti-orphan
            # NH-3: durable critical audit BEFORE the owner-signed revoke (fail-closed; committed⟹audited).
            self._audit("revoke_member", requester=requester, org_id=requester_org_id, target=member_username,
                        outcome="revoked", critical=True)
            seq = self.orgs.revoke_membership(requester_org_id, member_username)
        return {"org_id": requester_org_id, "username": member_username, "seq": seq}

    # -- the Team screen (VIGIL_CUSTOMER_TEAM_UI; the cockpit dispatch is absent while it is off) --------------------
    def customer_members(self, requester: str, requester_org_id: str, *, ip: str = "") -> dict:
        """The Team screen's read: the members of the SESSION org. Listing the team is an administrator's act —
        `manage_members` (an `org_admin` or the `founder`) — because no per-org role lets members see each other
        today; any other member, a non-member and a revoked member are refused (403). ``requester`` /
        ``requester_org_id`` are the hop-bound session principal, never a body field, so no org's members are ever read
        but the session's own.

        Each row: the canonical ``username``, the per-org ``role`` as stored (a founder stays ``founder`` whatever the
        founder kill switch admits it as — the app shows that row read-only), ``since`` (when the CURRENT grant was
        signed: a role change restarts it) and ``email`` only when the customer registry holds an ACTIVE account with
        one (an inactive account's member is listed without it). Founder first, then admins, operators, analysts and
        viewers, each by name. A read: no lock, nothing minted, no owner key used."""
        def project(_store, org_id: str) -> dict:
            rows: "list[dict[str, object]]" = []
            for m in self.orgs.memberships(org_id):
                row: "dict[str, object]" = {"username": m.username, "role": m.role, "since": m.issued_at}
                acct = self.customers.customer(m.username)
                if acct is not None and acct.email:
                    row["email"] = acct.email
                rows.append(row)
            rows.sort(key=lambda r: (_TEAM_ORDER.get(str(r["role"]), len(_TEAM_ORDER)),
                                     str(r.get("email") or r["username"])))
            return {"org_id": org_id, "members": rows, "count": len(rows)}
        return self._customer_read(requester, requester_org_id, "manage_members", project)

    def add_member(self, requester: str, requester_org_id: str, email: str, role: str, *, ip: str = "",
                   mfa_at: float = 0.0, now: "Optional[float]" = None) -> dict:
        """The Team screen's Add member: an administrator of THEIR org adds an EXISTING VIGIL customer, named by the
        email of that customer's account, with a customer-grantable role. A member is otherwise identified by their
        opaque server-made username, which no person knows, and there is NO invitation flow: an email with no active
        account is refused in plain words, and nothing is sent to it or recorded about it.

        Order (each step fail-closed, nothing written before the last): the role must be customer-grantable and the
        email well-formed (pure input checks); then, inside the transaction lock and the cross-process membership lock
        `grant_member` holds, the requester must hold `manage_members` in the SESSION org FIRST — so someone who may not
        manage the team learns nothing about whether an email has an account — then the E3c step-up, then the per-org
        rate guard (it counts every authorised attempt, a refused lookup included, so an administrator's probing is
        bounded per org); then the lookup; then a current member of the org is refused (Add never changes an existing
        member's role — that is member/grant); then the critical audit and the owner-signed grant, exactly as
        `grant_member` writes them. Returns {org_id, username, role, seq}."""
        t = self._now() if now is None else float(now)
        if role not in _CUSTOMER_GRANTABLE_ROLES:                        # pure input validation (no state)
            raise ProvisionDenied(f"role must be one of {sorted(_CUSTOMER_GRANTABLE_ROLES)}")
        from ..governor.customers import _check_email
        try:
            email_l = _check_email(email)
        except ValueError:
            raise ProvisionError(_ADD_BAD_EMAIL) from None
        with self._lock, _members_lock(self.store):
            if not self.orgs.admit_customer(username=requester, org_id=requester_org_id,
                                            permission="manage_members"):
                self._audit("add_member", requester=requester, org_id=requester_org_id, outcome="denied")
                raise ProvisionDenied("requester is not an administrator of this org")
            self._require_stepup(mfa_at, now=t)      # E3c: a fresh step-up (no-op unless enforcement is on)
            self._member_rate_guard(requester_org_id, now=t)   # after admit: only authorised churn is metered
            acct = self.customers.by_email(email_l)
            if acct is None:
                raise ProvisionDenied(_ADD_NO_ACCOUNT)
            member_username = _member_target(acct.username)
            if self.orgs.membership_role(member_username, requester_org_id) is not None:
                raise ProvisionDenied(_ADD_ALREADY_MEMBER)
            # durable audit BEFORE the owner-signed grant (fail-closed; committed implies audited), as grant_member
            self._audit("add_member", requester=requester, org_id=requester_org_id, target=member_username,
                        outcome=f"role={role}", critical=True)
            seq = self.orgs.grant_membership(requester_org_id, member_username, role,
                                             issued_at=self._next_issued())
        return {"org_id": requester_org_id, "username": member_username, "role": role, "seq": seq}

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
        relay; the offense launch verifies it before any traffic.

        W2b-3 — with metered billing on (``config.metered_billing_enabled``) a launch selects a DEPTH, never an
        amount: the chosen product's depth (Quick when none is chosen) is named in the owner-signed lease, and the
        launch holds the allowance chunk (``VIGIL_ALLOWANCE_CHUNK_CREDITS``) from the wallet — at most the balance,
        sized by the gate under its lock; the run extends it as it goes, and its settle charges its metered use
        (W2c makes that exact to the milli-credit and retires the per-run floor). The product's units are not used.
        With metered billing off nothing here changes."""
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
        product = None
        if pid:
            product = catalog.launch_product(pid)    # None when unknown, not offered, or EC-7 flag off
            if product is None:
                self._audit("launch_reserve", requester=requester, org_id=requester_org_id,
                            target=host, outcome="denied")
                raise ProvisionDenied(f"unknown or unavailable launch product: {pid!r}")
            units = int(product.units)
        sized: "dict[str, str]" = {}
        if config.metered_billing_enabled():
            # W2b-3: a metered launch selects a DEPTH (the product's, else Quick) and holds the allowance chunk; the
            # gate sizes it to the live balance under its lock. A flat launch passes exactly what it passed before.
            from vigil_core import model_metering as mm
            try:
                units = mm.allowance_chunk_credits()
            except mm.MeteringError as e:
                self._audit("launch_reserve", requester=requester, org_id=requester_org_id,
                            target=host, outcome="denied")
                raise ProvisionDenied("assessments cannot start right now: a billing setting is invalid") from e
            sized["depth"] = product.run_tier if product is not None else "quick"
        if self._preview_locked(requester_org_id):
            # Pricing S7: a locked trial org — trial product only, one registrable domain (first claim wins,
            # with proof history), and the global daily cap. The checks AND the reserve run under ONE hold of
            # the re-entrant spine lock (LaunchGate takes the same lock), so nothing lands in between.
            with self._lock:
                domain = self._trial_launch_check(requester, requester_org_id, host, pid, now=t)
                r = LaunchGate(self.store).reserve_launch(
                    requester=requester, org_id=requester_org_id, host=host, units=units, now=t, **sized)
                if r.get("ok"):
                    self._trial_launch_commit(requester_org_id, domain, now=t)
        else:
            r = LaunchGate(self.store).reserve_launch(
                requester=requester, org_id=requester_org_id, host=host, units=units, now=t, **sized)
        if not r.get("ok"):
            self._audit("launch_reserve", requester=requester, org_id=requester_org_id,
                        target=host, outcome="denied")
            raise ProvisionDenied(str(r.get("error") or "launch reservation refused"))
        self._audit("launch_reserve", requester=requester, org_id=requester_org_id, target=host,
                    outcome="reserved", critical=True)
        self._keep_launch(r["lease"], now=t)          # C1a: the app can start / cancel it after a reload (flag on)
        out = {k: r[k] for k in ("slug", "host", "units_reserved", "nonce", "not_before", "not_after",
                                 "lease", "trust_root") if k in r}
        if pid:
            out["product_id"] = pid                  # echo the resolved product for the edge/UI
        return out

    def _keep_launch(self, signed_lease, *, now: float) -> None:
        """C1a — while VIGIL_CUSTOMER_LAUNCH_UI is on, keep a just-reserved lease so the customer app can start or
        cancel it after a reload (``ui/customer_launches``). Best effort: the reservation stands and its lease is in
        the reply either way, so a failure here is logged and never raised — refusing the reply would strand the
        credits the gate has just reserved."""
        from .. import config
        if not config.customer_launch_ui_enabled():
            return
        from . import customer_launches as _cl
        try:
            with self._lock:
                _cl.remember(signed_lease, now=now)
        except Exception as e:  # noqa: BLE001 — a cache write never fails a reservation that already happened
            import logging
            logging.getLogger(__name__).warning("a reserved launch could not be kept for the customer app (%s)",
                                                type(e).__name__)

    def _drop_launch(self, doc) -> None:
        """C1a — forget the kept lease of a launch that was started (the seam holds it now) or cancelled, so the app
        never offers to start it again. Best effort, like ``_keep_launch``; off with the flag."""
        from .. import config
        if not config.customer_launch_ui_enabled():
            return
        from . import customer_launches as _cl
        try:
            with self._lock:
                _cl.forget(str(doc.org_id), str(doc.engagement_slug), str(doc.nonce))
        except Exception as e:  # noqa: BLE001 — a cache write never fails the start / cancel it follows
            import logging
            logging.getLogger(__name__).warning("a started or cancelled launch could not be dropped from the "
                                                "customer app's kept reservations (%s)", type(e).__name__)

    def _launch_choices(self, org_id: str) -> "list[dict]":
        """C1a — what the app's Launch may offer ``org_id``: exactly what ``launch_reserve`` accepts from it, and never
        an amount. Each offered tiered launch product as ``{product_id, depth}`` (its units are never projected); a
        locked trial-preview org only the trial product (``_trial_launch_check`` refuses every other); with no tiered
        product on offer, the one server-decided default launch (``product_id`` "")."""
        from .. import config
        from ..governor import catalog
        products = catalog.launch_products()
        if self._preview_locked(org_id):
            trial = config.trial_product_id()
            return [{"product_id": p.product_id, "depth": p.run_tier} for p in products if p.product_id == trial]
        if not products:
            return [{"product_id": "", "depth": None}]
        return [{"product_id": p.product_id, "depth": p.run_tier} for p in products]

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
        paused = self._latch_refusal("trial")              # the owner's `trial` latch: no NEW trial scan
        if paused is not None:
            self._trial_launch_refuse(requester, org_id, host, "trial_paused", paused)
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
    # drain's /verify shares that key's quota), so creation is rate-limited per ORG and per REQUESTER: at most
    # `_CHECKOUT_MAX` attempts per `_CHECKOUT_WINDOW_S`, then a lockout of (at least) one window. The state is the
    # injected filesystem `checkout_limiter` (durable across requests, restarts and processes — the transport
    # builds a fresh Provisioner per request, so instance state would limit nothing).
    _CHECKOUT_MAX = 10
    _CHECKOUT_WINDOW_S = 600.0

    def _checkout_rate_ok(self, requester: str, org_id: str, now: float) -> bool:
        """Guard-AND-COUNT one checkout attempt against the per-org AND per-requester keys. True iff admitted
        (and durably recorded). FAIL-CLOSED: no limiter wired, or limiter state that cannot be locked / read /
        written, refuses."""
        if self.checkout_limiter is None:
            return False
        return self.checkout_limiter.admit(f"checkout:org:{org_id}", f"checkout:user:{requester}", now=now) is None

    def _checkout_provider(self):
        """The outbound hosted-checkout provider (Front B CHK-1), or None when the owner has not provisioned the
        processor secrets. Overridable (tests inject a fake: ``self._checkout_provider = lambda: provider``). The
        verif-hash secret and the processor key are read from the environment and never logged or returned.

        The processor is ``config.billing_provider()`` — the one resolver the bare billing drain and tx-refs sweep use
        too, so checkout and the drain that credits its payments agree by construction: ``"stripe"`` (the DEFAULT,
        ``VIGIL_BILLING_PROVIDER`` unset) is :meth:`_stripe_checkout_provider`; ``"flutterwave"`` is the Flutterwave
        provider below (retained and selectable, no longer the default — Flutterwave development is paused); None
        (any other value) is "not configured" — never a fallback to the other processor, which would take a payment
        the configured drain does not credit."""
        import os as _os

        from .. import config
        kind = config.billing_provider()
        if kind == "stripe":
            return self._stripe_checkout_provider()
        if kind != "flutterwave":
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
        """The Stripe hosted-checkout provider (the DEFAULT, served when ``VIGIL_BILLING_PROVIDER`` is unset), or
        None unless every precondition of the Stripe lane holds: the adapter opt-in (``VIGIL_BILLING_ENABLE_STRIPE``,
        a deliberate money-safety belt kept even now that Stripe is the default), the Stripe webhook secret (the
        drain that credits these payments needs it), the API key with a recognisable live/test mode, and a pinned
        API version. Plan periods come from the owner catalog. Secrets are read from the environment and never
        logged or returned."""
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
        SUBSCRIPTION plans only with the extra plan flag; the AEGIS monitoring plans only with the monitoring
        flag (``customer_monitoring_enabled`` — INDEPENDENT of the credit-plan flag: an AEGIS plan is monthly,
        billed on its own line, never credits). With the monitoring flag OFF ``catalog.expected_amounts()``
        excludes the AEGIS prices, so ``offered`` is byte-identical to the pre-AEGIS set."""
        from .. import config
        from ..governor import catalog
        from ..governor.billing import EVENT_SUBSCRIPTION_ACTIVE, EVENT_TOPUP
        ents = catalog.entitlements()
        sellable = {EVENT_TOPUP} | ({EVENT_SUBSCRIPTION_ACTIVE} if config.customer_plan_checkout_enabled() else set())
        monitoring = catalog.monitoring_price_ids()
        monitoring_on = config.customer_monitoring_enabled()
        offered: "dict[str, tuple[int, str]]" = {}
        for pid, amt in catalog.expected_amounts().items():
            if pid in monitoring:
                if monitoring_on:                     # the AEGIS plan's own sale flag (not the credit-plan one)
                    offered[pid] = amt
            elif getattr(ents.get(pid), "kind", None) in sellable:
                offered[pid] = amt
        return offered, ents

    def _org_has_live_plan(self, org_id: str, t: float) -> bool:
        """True iff the org already holds a CREDIT plan that is active or past_due and not yet expired — the
        CHK-1b double-billing guard (checkout refuses a second credit plan; the offers read reports it so the UI
        does not offer one). Reads the credit-plan line (``governor.subscription``) ONLY: a live AEGIS monitoring
        plan is on a different line and never blocks a credit plan (one plan per KIND)."""
        from ..governor.subscription import STATUS_ACTIVE, STATUS_PAST_DUE, SubscriptionRegistry
        cur = SubscriptionRegistry(self.store).subscription(org_id)
        return cur is not None and cur.status in (STATUS_ACTIVE, STATUS_PAST_DUE) and t < float(cur.period_end)

    def _org_has_live_monitoring_plan(self, org_id: str, t: float) -> bool:
        """True iff the org already holds an AEGIS MONITORING plan that is active or past_due and not yet expired
        — the per-KIND twin of ``_org_has_live_plan``. Reads the SEPARATE monitoring line
        (``governor.monitoring_subscription``) ONLY, so a live AEGIS plan blocks a second AEGIS plan but NEVER a
        credit plan, and vice-versa. Keyless read (``owner_key=None``)."""
        from ..governor.monitoring_subscription import MonitoringSubscriptionRegistry
        from ..governor.subscription import STATUS_ACTIVE, STATUS_PAST_DUE
        cur = MonitoringSubscriptionRegistry(self.store, owner_key=None).subscription(org_id)
        return cur is not None and cur.status in (STATUS_ACTIVE, STATUS_PAST_DUE) and t < float(cur.period_end)

    def _spine_plan_checkouts(self, org_id: str, t: float, *, monitoring: bool) -> "tuple[str, list[str]]":
        """Audit E1b backstop — the PLAN checkouts of ONE kind the spine audit shows CREATED for ``org_id`` (a
        created plan row carries its pending window's ``expires_at``): ``(live, lapsed)`` — the tx_ref of one whose
        window is still open at ``t`` (else ""), and the tx_refs of those whose window has ended. The pending
        record is a SIGIL_HOME file a local writer could delete; these rows are on the tamper-evident spine, so a
        deleted record still refuses the second plan while a window is open, or while a lapsed one's webhook waits
        undrained (fail-closed). ``monitoring`` selects the KIND: a created row counts only when its ``target``
        price is (``monitoring=True``) / is not (``monitoring=False``) an AEGIS monitoring price, so an AEGIS
        checkout's backstop never gates a credit checkout and vice-versa (one plan per kind). A spine read fault
        raises (caller refuses). A full scan, but only on a plan checkout (rare, and rate-limited)."""
        from ..governor.catalog import monitoring_price_ids
        mon = {p[:64] for p in monitoring_price_ids()}   # the audit row caps ``target`` at 64 chars (_audit_payload)
        live, lapsed = "", []
        for r in self.store.iter_records():
            pl = r.payload
            if not (isinstance(pl, dict) and pl.get("signal") == "provision.audit"
                    and pl.get("action") == "billing_checkout" and pl.get("outcome") == "created"
                    and pl.get("org_id") == str(org_id)[:64]):
                continue
            ea = pl.get("expires_at")
            if not isinstance(ea, (int, float)) or isinstance(ea, bool):
                continue                                  # a top-up row (no pending window)
            if (str(pl.get("target") or "") in mon) != monitoring:
                continue                                  # a checkout of the OTHER kind does not gate this one
            if t < float(ea):
                live = live or str(pl.get("tx_ref") or "?")
            elif pl.get("tx_ref"):
                lapsed.append(str(pl["tx_ref"]))
        return live, lapsed

    def customer_billing_offers(self, requester: str, requester_org_id: str, *, ip: str = "",
                                now: "Optional[float]" = None) -> dict:
        """Front B CHK-2 — what THIS customer can buy right now, for the billing page's buy buttons. Gated exactly
        like checkout: the checkout flag (default-OFF), then ``admit_customer(manage_billing)`` for the SESSION org
        (a role that cannot spend money is not shown a price list it cannot use). Lists precisely the shared
        ``_checkout_offered`` set (owner catalog prices — never a client-supplied amount) and, PER KIND, whether the
        org already holds a live plan or has a plan checkout in progress (``has_active_plan`` /
        ``plan_checkout_pending`` for the credit plan; with the monitoring flag on, ``has_monitoring_plan`` /
        ``monitoring_checkout_pending`` for the AEGIS plan), so the UI hides exactly what checkout's per-kind
        second-plan refusal would refuse. Reads only: mints nothing, touches no owner key."""
        from .. import config
        if not config.customer_checkout_enabled():
            raise ProvisionDenied("customer checkout is not enabled")
        t = self._now() if now is None else float(now)

        def project(_store, org_id: str) -> dict:
            from ..governor import catalog
            offered, _ents = self._checkout_offered()
            items = [p for p in catalog.plans() if p.get("price_id") in offered]
            plans_on = bool(config.customer_plan_checkout_enabled())
            # E1b: a plan checkout already in progress (paid or not, not yet drained) refuses a second plan OF THE
            # SAME KIND, so the UI must not offer one either. Fail-closed: an unwired / untrusted pending record
            # reads as pending. The CREDIT line and the AEGIS line are tracked per-kind (own pending marker).
            pending = plans_on and (self.pending_checkouts is None
                                    or self.pending_checkouts.pending(org_id, now=t))
            out = {"offers": items, "has_active_plan": self._org_has_live_plan(org_id, t),
                   "plans_enabled": plans_on, "plan_checkout_pending": bool(pending)}
            # AEGIS plan SALE (flag-gated so OFF is byte-identical): the UI's offerShown() hides an AEGIS offer
            # exactly when the workspace has a live AEGIS plan or an AEGIS checkout is in progress — independent of
            # the credit-plan fields above (one plan per kind).
            if config.customer_monitoring_enabled():
                mon_pending = (self.pending_checkouts is None
                               or self.pending_checkouts.pending(org_id, now=t, kind="monitoring"))
                out["has_monitoring_plan"] = self._org_has_live_monitoring_plan(org_id, t)
                out["monitoring_checkout_pending"] = bool(mon_pending)
            return out
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
        paused = self._latch_refusal("checkout")          # the owner's latch narrows the flag: no NEW checkout
        if paused is not None:
            raise ProvisionDenied(paused)
        t = self._now() if now is None else float(now)
        with self._lock:
            if not self.orgs.admit_customer(username=requester, org_id=requester_org_id,
                                            permission="manage_billing"):
                self._audit("billing_checkout", requester=requester, org_id=requester_org_id, outcome="denied")
                raise ProvisionDenied("requester may not manage billing for this org")
            self._require_stepup(mfa_at, now=t)      # E3c: a fresh step-up (no-op unless enforcement is on)
            if not self._checkout_rate_ok(requester, requester_org_id, t):
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
        from ..governor.catalog import monitoring_price_ids
        # The ONE shared offered set (top-ups; credit plans with the plan flag; AEGIS monitoring plans with the
        # monitoring flag) — the billing_offers read lists exactly this, so the UI and checkout cannot disagree.
        offered, ents = self._checkout_offered()
        is_plan = getattr(ents.get(str(price_id or "")), "kind", None) == EVENT_SUBSCRIPTION_ACTIVE
        # PER-KIND: an AEGIS monitoring plan and a credit plan are different processor subscriptions on different
        # sovereign lines, so each kind's second-plan guard (live subscription + pending record + spine backstop)
        # is independent — a live/pending AEGIS plan blocks a second AEGIS plan but NEVER a credit plan, and
        # vice-versa (one plan per kind). The selling flag lives in ``offered`` (monitoring prices appear there
        # only when the monitoring flag is on), so with it off a monitoring price is not in ``offered`` and is
        # refused at ``create_checkout`` exactly as before (byte-identical).
        is_monitoring = str(price_id or "") in monitoring_price_ids()
        _has_live_plan = self._org_has_live_monitoring_plan if is_monitoring else self._org_has_live_plan
        _pending_kind = "monitoring" if is_monitoring else ""
        _already_msg = ("this workspace already has an AEGIS monitoring plan — changing it is not self-serve yet "
                        "(contact support), so a second subscription is refused rather than billed") if is_monitoring \
            else ("this workspace already has a plan — changing plans is not self-serve yet "
                  "(contact support), so a second subscription is refused rather than billed")
        if is_plan and str(price_id) in offered:
            # CHK-1b red-pen HIGH: a SECOND processor subscription would double-bill (there is no processor-side
            # cancel/upgrade path yet, and the newest charge wins the sovereign plan each renewal). Refuse while the
            # org already holds a plan OF THE SAME KIND that is active or past_due and not yet expired.
            if _has_live_plan(requester_org_id, t):
                self._audit("billing_checkout", requester=requester, org_id=requester_org_id,
                            target=str(price_id), outcome="refused_existing_plan")
                raise ProvisionDenied(_already_msg)
        # The processor needs the payer's email: take it from the owner-signed customer record (usernames are
        # opaque ids, never emails) — the account's OWN registered address, never a body field.
        acct = self.customers.customer(requester) if self.customers is not None else None
        email = getattr(acct, "email", None) or None
        nonce: "Optional[str]" = None
        pending_ref = pending_note = ""
        pending_until = 0.0
        if is_plan and str(price_id) in offered:
            # Audit E1b: `_org_has_live_plan` sees only DRAINED plans, so a paid plan whose webhook has not drained
            # yet (a drain tick, NET-2b parking, or a quarantine awaiting an operator) left room for a second
            # processor subscription. Claim the org's owner-signed, expiring PENDING plan-checkout record BEFORE the
            # outbound call (exclusive across processes); a live one — or an expired one whose webhook still waits
            # undrained in the billing spool — refuses this checkout. The tx_ref is fixed up front so the record
            # names it.
            from ..governor.billing import checkout_tx_ref
            from .pending_checkout import UNCONFIRMED_MESSAGE, PendingCheckoutRefused
            nonce = secrets.token_urlsafe(18)
            pending_ref = checkout_tx_ref(requester_org_id, nonce)   # the admitted org: validated like create_checkout
            try:
                if self.pending_checkouts is None:
                    raise PendingCheckoutRefused("plan checkout is unavailable right now (contact support)",
                                                 code="refused_pending_unwired",
                                                 detail="no pending plan-checkout ledger is wired")
                claimed = self.pending_checkouts.claim(requester_org_id, str(price_id), pending_ref, now=t,
                                                       kind=_pending_kind)
                pending_note, pending_until = claimed.get("replaced", ""), float(claimed["record"]["expires_at"])
                # the deletion-proof backstop: a CREATED plan checkout OF THIS KIND still inside its window on the
                # spine audit refuses even if its pending record file is gone (a deleted record must not reopen the
                # window).
                lapsed: "list[str]" = []
                try:
                    live, lapsed = self._spine_plan_checkouts(requester_org_id, t, monitoring=is_monitoring)
                except Exception as exc:  # noqa: BLE001 — a spine read fault is fail-CLOSED, never "no checkout"
                    live, why = "?", f"the spine audit could not be read ({type(exc).__name__})"
                else:
                    why = f"pending record missing but the spine audit shows a live plan checkout {live}"
                if live:
                    self.pending_checkouts.release(requester_org_id, pending_ref, kind=_pending_kind)
                    raise PendingCheckoutRefused(
                        "a plan checkout for this workspace is already in progress — complete it, or wait for it to "
                        "expire (contact support)", code="refused_pending_spine", detail=why[:160])
                # ... and an EARLIER plan checkout whose window ended may still have been PAID: refuse while its
                # webhook waits undrained in the billing spool (quarantine has no time bound), or while its completed
                # Stripe subscription checkout has no drained plan yet, whatever the record.
                unconfirmed = self.pending_checkouts.undrained(lapsed)
                if unconfirmed:
                    self.pending_checkouts.release(requester_org_id, pending_ref, kind=_pending_kind)
                    raise PendingCheckoutRefused(UNCONFIRMED_MESSAGE, code="refused_pending_unconfirmed",
                                                 detail=unconfirmed[:160])
            except PendingCheckoutRefused as exc:
                self._audit("billing_checkout", requester=requester, org_id=requester_org_id,
                            target=str(price_id), outcome=exc.code, reason=exc.detail, tx_ref=pending_ref)
                raise ProvisionDenied(str(exc)) from None
            # The first plan may have DRAINED between the pre-claim check above and the claim (e.g. over a record
            # that had just expired): re-check (same kind) under the claim, so a plan that is now live still refuses.
            if _has_live_plan(requester_org_id, t):
                self.pending_checkouts.release(requester_org_id, pending_ref, kind=_pending_kind)
                self._audit("billing_checkout", requester=requester, org_id=requester_org_id,
                            target=str(price_id), outcome="refused_existing_plan", tx_ref=pending_ref)
                raise ProvisionDenied(_already_msg)
        from .pending_checkout import PLAN_LINK_SESSION_MIN
        # A1: a TOP-UP checkout asks the processor to save the card for off-session auto top-ups ONLY when auto top-up
        # is wired AND this org opted in (its owner-signed auto-top-up settings are enabled). Otherwise the call is
        # exactly the pre-A1 one (the keyword is not even passed), so the checkout payload is byte-identical and no
        # card is saved for an org that never asked.
        create_kw: "dict[str, bool]" = {}
        if not is_plan and self._auto_topup_opted_in(requester_org_id):
            create_kw["save_future_payments"] = True
        try:
            sess = provider.create_checkout(requester_org_id, str(price_id or ""), expected=offered,
                                            customer_email=email, redirect_url=return_url, nonce=nonce,
                                            payment_plan=(str(price_id) if is_plan and price_id in offered else None),
                                            # E1b: a plan link must stop being payable before its pending record
                                            # lapses (top-ups pass None: their payload is unchanged)
                                            session_minutes=(PLAN_LINK_SESSION_MIN if pending_ref else None),
                                            **create_kw)
        except (UnsupportedCapability, ValueError) as exc:
            if pending_ref:
                # the processor refused: the customer never received a link, so free the claim for a retry
                self.pending_checkouts.release(requester_org_id, pending_ref, kind=_pending_kind)
            self._audit("billing_checkout", requester=requester, org_id=requester_org_id,
                        target=str(price_id or ""), outcome="refused", tx_ref=pending_ref)
            raise ProvisionDenied(f"checkout refused: {exc}") from None
        self._audit("billing_checkout", requester=requester, org_id=requester_org_id, target=sess.price_id,
                    outcome="created", reason=pending_note, critical=True, tx_ref=sess.tx_ref,
                    expires_at=pending_until)
        return {"checkout_url": sess.hosted_link, "tx_ref": sess.tx_ref, "price_id": sess.price_id,
                "amount_minor": sess.amount_minor, "currency": sess.currency}

    # -- A1 auto top-up (default-OFF: VIGIL_BILLING_AUTO_TOPUP) ----------------------------------------------------
    def _auto_topup_registry(self, *, signing: bool):
        """The auto-top-up ledger over this provisioner's spine, under the SAME owner identity as the wallet it arms
        (in production the persisted owner identity) — so its records and the wallet grants it anchors on verify
        under one key. A read never holds the private key (``owner_key=None``)."""
        from ..governor.auto_topup import AutoTopUpRegistry
        return AutoTopUpRegistry(self.store, owner_key=getattr(self.wallet, "owner_key", None) if signing else None,
                                 trusted_pubkey=getattr(self.wallet, "trusted_pubkey", None))

    def _auto_topup_opted_in(self, org_id: str) -> bool:
        """True iff auto top-up is wired (the flag) AND ``org_id``'s owner-signed auto-top-up settings are enabled —
        the gate on asking the processor to save a card at checkout. Fail-closed: flag off, no settings, or an
        unreadable ledger → False (no card is saved)."""
        from .. import config
        if not config.billing_auto_topup_enabled():
            return False
        try:
            s = self._auto_topup_registry(signing=False).settings(org_id)
        except Exception:  # noqa: BLE001 — an unreadable ledger never saves a card
            return False
        return bool(s is not None and s.enabled)

    def _auto_topup_packs(self) -> "list[dict]":
        """The packs auto top-up may buy: exactly the OFFERED top-ups (the shared ``_checkout_offered`` set), in CREDITS
        only — ``{price_id, name, credits}``, never a money amount."""
        from ..governor import catalog
        from ..governor.billing import EVENT_TOPUP
        offered, ents = self._checkout_offered()
        names = {p.get("price_id"): str(p.get("name") or "") for p in catalog.plans()}
        return [{"price_id": pid, "name": names.get(pid) or pid, "credits": int(ents[pid].credits)}
                for pid in sorted(offered) if getattr(ents.get(pid), "kind", None) == EVENT_TOPUP]

    def customer_billing_auto_topup(self, requester: str, requester_org_id: str, *, ip: str = "",
                                    now: "Optional[float]" = None) -> dict:
        """A1 — the SESSION org's auto top-up, for the billing page. Gated on the auto-top-up flag (default-OFF → an
        unknown action, 404), then ``admit_customer(view_billing)``. CREDITS ONLY: the packs list their credits, the
        receipts their outcome, credits and time; whether a card is saved is a yes/no (the processor's ids never
        leave the sovereign plane). Reads only: mints nothing, touches no owner key."""
        from .. import config
        if not config.billing_auto_topup_enabled():
            raise ProvisionDenied("auto top-up is not enabled")
        t = self._now() if now is None else float(now)

        def project(_store, org_id: str) -> dict:
            reg = self._auto_topup_registry(signing=False)
            s = reg.settings(org_id)
            receipts = reg.charges(org_id)[-_AUTO_TOPUP_RECEIPTS:]
            return {"settings": None if s is None else {
                        "enabled": s.enabled, "trigger_credits": s.trigger_credits,
                        "pack_price_id": s.pack_price_id, "monthly_cap_credits": s.monthly_cap_credits},
                    "card_saved": reg.payment_method(org_id) is not None,
                    "packs": self._auto_topup_packs(),
                    "month_credits": reg.month_charged_credits(org_id, t),
                    "receipts": [{"status": c.status, "credits": c.credits, "at": c.issued_at}
                                 for c in reversed(receipts)]}
        return self._customer_read(requester, requester_org_id, "view_billing", project)

    def billing_auto_topup_set(self, requester: str, requester_org_id: str, *, enabled: object,
                               trigger_credits: object, pack_price_id: object, monthly_cap_credits: object,
                               ip: str = "", mfa_at: float = 0.0, now: "Optional[float]" = None) -> dict:
        """A1 — set the SESSION org's auto top-up: on/off, the balance that triggers it, the pack it buys (an OFFERED
        top-up — the catalog, never the caller, decides its credits and price) and the monthly limit (credits).

        Gated on the flag (default-OFF → 404), then ADMIT-FIRST ``admit_customer(manage_billing)`` (a role that cannot
        spend money cannot arm an automatic charge), a fresh step-up, and only then does the provisioner OWNER-SIGN
        the settings record (LWW; a captured record cannot be replayed to lift the limit). Fail-closed: a non-bool
        ``enabled``, a trigger / limit that is not a whole number of credits in range, a pack that is not an offered
        top-up, or — when enabling — a monthly limit below one pack is refused. Nothing is charged here: the sweep
        charges the saved card on the next crossing, and credit is minted only by the verified webhook."""
        from .. import config
        from ..governor.auto_topup import check_setting_credits
        if not config.billing_auto_topup_enabled():
            raise ProvisionDenied("auto top-up is not enabled")
        t = self._now() if now is None else float(now)
        with self._lock:
            if not self.orgs.admit_customer(username=requester, org_id=requester_org_id,
                                            permission="manage_billing"):
                self._audit("billing_auto_topup", requester=requester, org_id=requester_org_id, outcome="denied")
                raise ProvisionDenied("requester may not manage billing for this org")
            self._require_stepup(mfa_at, now=t)
            if not isinstance(enabled, bool):
                raise ProvisionDenied("enabled must be true or false")
            try:
                trig = check_setting_credits(trigger_credits, "trigger_credits")
                cap = check_setting_credits(monthly_cap_credits, "monthly_cap_credits")
            except ValueError as exc:
                raise ProvisionDenied(str(exc)) from None
            packs = {p["price_id"]: p["credits"] for p in self._auto_topup_packs()}
            pack = pack_price_id if isinstance(pack_price_id, str) else ""
            if pack not in packs:
                raise ProvisionDenied("pack_price_id must be one of the offered top-up packs")
            if enabled and cap < packs[pack]:
                raise ProvisionDenied("the monthly limit must allow at least one pack")
            try:
                self._auto_topup_registry(signing=True).set_settings(
                    requester_org_id, enabled=enabled, trigger_credits=trig, pack_price_id=pack,
                    monthly_cap_credits=cap, issued_at=self._next_issued())
            except ValueError as exc:
                raise ProvisionDenied(f"auto top-up settings refused: {exc}") from None
            self._audit("billing_auto_topup", requester=requester, org_id=requester_org_id, target=pack,
                        outcome="enabled" if enabled else "disabled", critical=True)
        return {"enabled": enabled, "trigger_credits": trig, "pack_price_id": pack, "monthly_cap_credits": cap}

    def launch_cancel(self, requester: str, requester_org_id: str, signed_lease, *,
                      ip: str = "", mfa_at: float = 0.0, now: "Optional[float]" = None) -> dict:
        """Cancel a reservation (full refund) — the customer releases a launch they will not run. Gated on
        admit_customer(run_engagement) OR admit_customer(manage_billing), AND the lease's org MUST match the
        requester's session org (``expect_org_id`` — a customer cannot cancel another tenant's reservation). The
        refund is bound to the owner-signed lease, not a wire amount. The METERED settle (consumed > 0) is driven
        by offense completion, not this customer path.

        Why billing authority suffices: a cancel only ever releases a reserved, NOT started launch back to the
        org's own balance (a started launch is refused below), so it authorises no traffic. An org admin — and a
        founder while founder testing is switched off, or after the owner changed its role — can therefore always
        release a reservation: credits never stay held because nobody left in the org may run tests."""
        t = self._now() if now is None else float(now)
        from .launch_gate import PLAN_DEBIT_PRUNED, LaunchGate
        with self._lock:
            if not any(self.orgs.admit_customer(username=requester, org_id=requester_org_id, permission=perm)
                       for perm in ("run_engagement", "manage_billing")):
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

        gate = LaunchGate(self.store)

        def _started() -> Optional[str]:
            # the gate's own seam base (== _base_dir() for this cockpit gate), so the started-check reads exactly
            # the tree the settle revokes in
            try:
                from vigil_integration.live.credit_lease_broker import read_credit_lease
                _pub = read_credit_lease(gate._seam_base(), str(_cdoc.engagement_slug))
            except Exception:  # noqa: BLE001 — a seam-read failure must not DENY a legitimate pre-start cancel;
                _pub = None     # the settle's settled-check is the hard backstop against a double refund
            if _pub is not None and str(_pub.signed_lease.document.nonce) == str(_cdoc.nonce):
                return "started"
            return None

        # A fast refusal first (a started launch never reaches the settle at all), then the decisive check INSIDE
        # the settle's cross-process critical section (``refuse_if``), which ``publish_lease`` (launch_start) also
        # holds — so a start can never land between that check and the refund. A refused settle closes no meter.
        if _started():
            self._audit("launch_cancel", requester=requester, org_id=requester_org_id,
                        target=str(_cdoc.engagement_slug), outcome="refused_started")
            raise ProvisionDenied(
                "this launch has been started and must settle through its completion; it cannot be cancelled")
        r = gate.settle_launch(signed_lease=signed_lease, consumed_units=0, now=t,
                               expect_org_id=requester_org_id, refuse_if=_started, basis="cancel")
        if r.get("refused") == PLAN_DEBIT_PRUNED:
            # HELD for the owner (nothing moved): the settle cannot tell this reservation's plan share from its wallet
            # share. The gate has named it in the held-settle alarm `vigil doctor` reports; the customer is told the
            # truth (not "started"), and the audit is critical. The cancel marker goes on the spine first: the
            # customer was told this reservation is cancelled, so it must never start afterwards (publish_lease reads
            # the marker under the settle lock). A marker that cannot be written fails the cancel, to be retried.
            from ..governor.launch_settlement import LAUNCH_CANCEL_HELD_SIGNAL
            try:
                self.store.append(kind="event", source="provision", actor="WARDEN",
                                  payload={"signal": LAUNCH_CANCEL_HELD_SIGNAL, "org_id": str(_cdoc.org_id),
                                           "slug": str(_cdoc.engagement_slug), "nonce": str(_cdoc.nonce)})
            except Exception as e:  # noqa: BLE001 — no marker, no "cancelled" answer: the customer retries
                raise ProvisionDenied("launch cancel could not be recorded (retry)") from e
            self._audit("launch_cancel", requester=requester, org_id=requester_org_id,
                        target=str(_cdoc.engagement_slug), outcome="refund_held", reason=PLAN_DEBIT_PRUNED,
                        critical=True)
            self._drop_launch(_cdoc)                 # C1a: cancelled (no seam marker yet): never offered to start again
            raise ProvisionDenied(LAUNCH_REFUND_HELD_DETAIL)
        if r.get("refused"):
            self._audit("launch_cancel", requester=requester, org_id=requester_org_id,
                        target=str(_cdoc.engagement_slug), outcome="refused_started")
            raise ProvisionDenied(
                "this launch has been started and must settle through its completion; it cannot be cancelled")
        if not r.get("ok"):
            msg = str(r.get("error") or "launch cancel refused")
            raise ProvisionDenied(msg + (" (retry)" if r.get("retry") else ""))
        self._drop_launch(_cdoc)                     # C1a: settled one way or another: no longer a kept reservation
        if r.get("action") == "launch_already_settled":
            if r.get("rolled_forward"):
                # this cancel FINISHED an earlier settle a crash interrupted — at that settle's RECORDED amounts
                self._audit("launch_cancel", requester=requester, org_id=requester_org_id,
                            target=str(r.get("slug", "")), outcome="rolled_forward", critical=True)
                return {"slug": r.get("slug"), "refunded": r.get("refunded")}
            # a LOSING cancel (another settle already decided this launch): nothing moved, and nothing to audit as
            # a cancel (OD-2)
            self._audit("launch_cancel", requester=requester, org_id=requester_org_id,
                        target=str(r.get("slug", "")), outcome="already_settled")
            return {"slug": r.get("slug"), "refunded": 0, "already_settled": True}
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
        self._drop_launch(lease_doc)                 # C1a: the seam holds it now (a later re-lease never revives it)
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
        saying that a launch which has not started will not start; an in-window reply is unchanged.

        W3 — a launch PARKED for want of prepaid credit resumes after a top-up (``LaunchGate.resume_launch`` → its
        credit path) and the reply carries ``credit_resumed: True``; an amount is never part of the reply. Refused —
        nothing changed, still parked — while the wallet still cannot cover one model request, while the org is on a
        billing hold, and once its wait for a top-up has ended."""
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
        if r.get("credit_resumed"):
            out["credit_resumed"] = True
        return out

    def retest(self, requester: str, requester_org_id: str, finding_ref: str, *, engagement_slug: str = "",
               oracle_context_digest: str = "", ip: str = "", mfa_at: float = 0.0, now: "Optional[float]" = None,
               reverify=None, _drive_reproof: "Optional[Callable[[Any], None]]" = None,
               _reproof_wait: "Optional[tuple[float, float]]" = None) -> dict:
        """C1b — RETEST one of the session org's findings: re-run THAT finding's proof against the customer's
        verified host and mark it FIXED only when the proof stops working, else Still-Vulnerable. Behind
        ``customer_retest_ui_enabled`` (default OFF → the edge/cockpit action is a 404 unknown-action, and this
        refuses even if reached). requester/org are the SERVER-authenticated session principal (never body fields);
        the finding is named by its full identity — ``engagement_slug`` + ``finding_ref`` + ``oracle_context_digest``
        (``assessments.finding_identity``; ``finding_ref`` alone is not unique) — exactly as the findings read gave
        it to the customer (their own data, carried in the body like a launch's target host).

        Order (fail-closed at each step):
          1. ``admit_customer(view_assessments)`` on the session org; a trial-preview org whose report is still
             locked is refused (retest re-runs the finding's proof, which is part of the full report — it unlocks
             with the first purchase); then the finding is resolved WITHIN this org's own ever-proven slug set
             (``assessments.find_finding``): another tenant's finding — even named by its exact identity — is
             structurally not found → refused (the IDOR guard).
          2. the LAUNCH-GATE authorization (``LaunchGate.authorize_retest``): the owner kill switch +
             ``customer_launch`` latch, ``admit_customer(run_engagement)``, a CURRENT ownership proof for the
             finding's host, and a CURRENT owner-pinned engagement authority. A lapsed proof/authority refuses
             (the customer re-verifies the host in Assets). This is confirm-by-re-execution against an
             owner-authorized target, never a new open-ended scan — and this action itself reserves and charges NO
             credit (a single-finding re-verify; the re-proof wiring must meter what it uses — see
             ``_retest_reverify``).
          3. a fresh step-up (E3c), AFTER authority (a non-member is refused by admit, not told to step up).
          4. re-fire the finding's retained proof through the injected ``reverify`` seam (default
             ``_retest_reverify``: fail-closed 'unavailable' until the live offense re-proof is wired).
             EXACTLY ``"cleared"`` → FIXED; exactly ``"still_present"`` → Still-Vulnerable; ``"unavailable"`` →
             refused as not available; ANYTHING ELSE (inconclusive, a raised error, a non-string) → refused as
             could-not-confirm. Every refusal leaves the finding UNCHANGED (never marked fixed on a guess).
          5. append a ``finding_retest`` record to the sovereign spine (hash-chained; ``source`` = the
             provisioner, the only writer the findings overlay accepts; written only for this org's own slug) so the
             verdict persists and the findings read can show it; return the verdict.

        Returns ``{"finding_ref", "host", "status"}`` with ``status`` ∈ {``fixed``, ``still_vulnerable``}. Credits
        only — no amount, no units, no estimate, no model name ever appears (money/model doctrine)."""
        from .. import config
        if not config.customer_retest_ui_enabled():
            raise ProvisionDenied("retesting findings from the app is not enabled")
        t = self._now() if now is None else float(now)
        ref = str(finding_ref or "")
        want_slug = str(engagement_slug or "")
        if not ref or not want_slug:
            raise ProvisionError("a finding (its reference and its assessment) is required to retest")
        from . import assessments as _assess
        # 1) READ authority + IDOR-safe finding resolution (the finding must be THIS org's own).
        if not self.orgs.admit_customer(username=requester, org_id=requester_org_id, permission="view_assessments"):
            self._audit("retest", requester=requester, org_id=requester_org_id, outcome="denied")
            raise ProvisionDenied("requester may not read this org (view_assessments)")
        if self._preview_locked(requester_org_id):
            self._audit("retest", requester=requester, org_id=requester_org_id, target=ref, outcome="locked")
            raise ProvisionDenied("retesting unlocks with the full report: buy credits to retest findings")
        finding = _assess.find_finding(self.store, requester_org_id, ref, engagement_slug=want_slug,
                                       oracle_context_digest=str(oracle_context_digest or ""), now=t)
        if finding is None:
            self._audit("retest", requester=requester, org_id=requester_org_id, target=ref, outcome="not_found")
            raise ProvisionDenied("no such finding for this workspace")
        host = str(finding.get("host") or "")
        slug, _ref, digest = _assess.finding_identity(finding)
        # 2) LAUNCH-GATE authorization + 3) step-up, under the spine lock (TOCTOU-consistent with launch_start).
        from .launch_gate import LaunchGate
        with self._lock:
            auth = LaunchGate(self.store).authorize_retest(
                requester=requester, org_id=requester_org_id, host=host, now=t)
            if not auth.get("ok"):
                self._audit("retest", requester=requester, org_id=requester_org_id, target=host, outcome="denied")
                raise ProvisionDenied(str(auth.get("error") or "retest authorization refused"))
            self._require_stepup(mfa_at, now=t)      # E3c: AFTER authority (no-op unless enforcement is on)
        # 4) RE-FIRE the retained proof (confirm-by-re-execution). An injected ``reverify`` is used verbatim (a
        #    custom seam / tests); else, with the live re-proof flag on, the REAL cross-plane path reserves a lease,
        #    publishes the ticket, bounded-waits the keyless offense worker's outcome and settles (full refund); off,
        #    the fail-closed stub returns "unavailable". The default seam NEVER runs the engine (FATAL-2).
        from .. import config
        ctx = {"host": host, "engagement_slug": slug, "finding_ref": ref,
               "bug_class": finding.get("bug_class"), "oracle_context_digest": digest}
        if reverify is None and config.customer_retest_reproof_enabled():
            # A reserve refusal (e.g. too few credits, a lapsed latch) is surfaced as itself (it raises
            # ProvisionDenied); a completed-but-inconclusive re-proof falls through to the mapping below.
            raw = self._retest_reproof(ctx, requester=requester, org_id=requester_org_id, host=host, slug=slug,
                                       now=t, drive=_drive_reproof, wait=_reproof_wait)
        else:
            rv = reverify if reverify is not None else _retest_reverify
            try:
                raw = rv(ctx)
            except Exception as e:  # noqa: BLE001 — a re-proof that did not complete never green-lights a fix
                self._audit("retest", requester=requester, org_id=requester_org_id, target=host,
                            outcome="error", critical=True)
                raise ProvisionDenied("could not confirm the fix: the retest did not complete; the finding is "
                                      "unchanged") from e
        # 5) MAP (fixed ONLY on the EXACT token "cleared" — no case-folding, no str() of an object) + RECORD + return.
        verdict = raw if isinstance(raw, str) else ""
        if verdict == "cleared":
            status = "fixed"
        elif verdict == "still_present":
            status = "still_vulnerable"
        elif verdict == "unavailable":               # no re-proof ran at all: say so, never "could not confirm"
            self._audit("retest", requester=requester, org_id=requester_org_id, target=host, outcome="unavailable")
            raise ProvisionDenied("retest is not available right now; the finding is unchanged")
        else:
            self._audit("retest", requester=requester, org_id=requester_org_id, target=host, outcome="inconclusive")
            raise ProvisionDenied("could not confirm the fix: the retest was inconclusive; the finding is unchanged")
        with self._lock:
            self.store.append(kind=_assess.RETEST_KIND, source=_assess.RETEST_SOURCE, actor="WARDEN",
                              payload={"engagement_slug": slug, "finding_ref": ref, "oracle_context_digest": digest,
                                       "status": status, "nonce": secrets.token_urlsafe(12), "ts": t})
        self._audit("retest", requester=requester, org_id=requester_org_id, target=host,
                    outcome=status, critical=True)
        return {"finding_ref": ref, "host": host, "status": status}

    def _retest_reproof(self, ctx: dict, *, requester: str, org_id: str, host: str, slug: str, now: float,
                        drive: "Optional[Callable[[Any], None]]" = None,
                        wait: "Optional[tuple[float, float]]" = None) -> str:
        """C1b — the REAL cross-plane LIVE re-proof (behind ``customer_retest_reproof_enabled``): reserve an
        owner-signed lease for THIS finding, publish an owner-signed re-proof TICKET to the ``retest-reproof``
        seam, bounded-wait the keyless offense worker's inert OUTCOME, and SETTLE the lease. Returns the raw
        verdict token (``cleared`` / ``still_present`` / ``inconclusive`` / ``unavailable``) for
        :meth:`retest`'s mapping — the sovereign stays the sole authority on that mapping. Raises
        ``ProvisionDenied`` on a RESERVE refusal (surfaced as itself — a credit / latch refusal is never masked
        as "could not confirm").

        FATAL-2: the sovereign only reserves (holds the owner key), publishes the ticket and reads the outcome —
        it NEVER runs the engine. METERING: the lease is settled to ZERO consumption (a full refund) whatever the
        verdict or a bounded-wait timeout — a single-finding re-fire is DETERMINISTIC and MODEL-FREE (no gateway
        spend), so a retest never charges the customer, but it is never an unmetered / unbounded offense run (it
        always holds the reserved, owner-signed, tenant-bound lease the offense worker re-verifies before any
        traffic). ``drive`` is an offline-test seam the harness uses to run the offense worker inline after the
        ticket is published (production relies on the real offense drain); ``wait`` overrides the bounded-wait."""
        from vigil_core.retest_reproof import retest_reproof_ticket
        from vigil_core.seam_base import resolve_seam_base

        from .launch_gate import LaunchGate
        gate = LaunchGate(self.store)
        res = gate.reserve_retest(requester=requester, org_id=org_id, host=host, now=now)
        if not res.get("ok"):
            self._audit("retest", requester=requester, org_id=org_id, target=host, outcome="denied")
            raise ProvisionDenied(str(res.get("error") or "retest reservation refused"))
        signed_lease = res["lease"]
        nonce = str(res["nonce"])
        base = resolve_seam_base(None)
        ref = str(ctx.get("finding_ref") or "")
        digest = str(ctx.get("oracle_context_digest") or "")
        ticket = retest_reproof_ticket(slug=slug, host=host, org_id=org_id, finding_ref=ref, nonce=nonce,
                                       lease=signed_lease, oracle_context_digest=digest,
                                       bug_class=str(ctx.get("bug_class") or ""))
        timeout, poll = wait if wait is not None else (_RETEST_REPROOF_WAIT_S, _RETEST_REPROOF_POLL_S)
        try:
            _write_retest_ticket(base, ticket)
            if drive is not None:
                drive(base)                         # TEST seam: run the offense worker inline (prod: the drain)
            want = (slug, ref, digest, nonce)
            return _retest_reverify({**ctx, "_reproof": {"base": base, "want": want,
                                                         "timeout": timeout, "poll": poll}})
        finally:
            # Settle to ZERO consumption: a FULL refund of the reservation, whatever happened — a model-free
            # re-fire spends nothing, and a bounded-wait timeout must never strand the held credits. Idempotent
            # per the lease's (slug, nonce); a settle hiccup never turns a completed re-proof into a crash.
            try:
                gate.settle_launch(signed_lease=signed_lease, consumed_units=0, now=now, expect_org_id=org_id)
            except Exception:  # noqa: BLE001 — the lease window is tight; a re-settle is idempotent
                pass

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
        """The SESSION org's monitoring grants (org-scoped read; ``active`` applies window + ownership), and whether
        the requester may turn monitoring on or off (``can_manage``: ``manage_monitoring``, decided HERE — the
        founder or an org_admin — never by the client).

        Only for such a requester, what the Monitoring screen needs to turn monitoring on: ``hosts``, the org's hosts
        with a CURRENT ownership proof (host + the proof's expiry; never a challenge token), and ``plan``, the org's
        active monitoring plan (host slots + whether it includes respond + its period end; no price) or None. An
        org_admin cannot read the assets view (``view_assessments``), so the verified hosts come from here. A role that
        cannot manage monitoring reads exactly the grants, as before."""
        t = self._now() if now is None else float(now)
        from ..governor.monitoring_authority import MonitoringAuthorityRegistry
        with self._lock:
            self._monitor_admit("monitor_list", requester, requester_org_id, "", "read")
            reg = MonitoringAuthorityRegistry(self.store, owner_key=None)
            rows = [{"host": g.host, "mode": g.mode, "not_before": g.not_before, "not_after": g.not_after,
                     "active": reg.active_at(requester_org_id, g.host, now=t) is not None}
                    for g in reg.grants(requester_org_id)]
            can_manage = bool(self.orgs.admit_customer(username=requester, org_id=requester_org_id,
                                                       permission="manage_monitoring"))
            out: dict = {"org_id": requester_org_id, "grants": rows, "can_manage": can_manage}
            if can_manage:
                out["hosts"], out["plan"] = self._monitor_setup(requester_org_id, t)
        return out

    def _monitor_setup(self, org_id: str, now: float) -> "tuple[list[dict], Optional[dict]]":
        """For ``monitor_list`` (a monitoring manager only): the org's hosts whose ownership proof is current at ``now``
        (the proof ``grant`` requires) and its ACTIVE monitoring plan as the CATALOG defines it. Caller holds the lock."""
        from ..governor.asset_ownership import AssetOwnershipRegistry
        from ..governor.catalog import monitoring_plan
        from ..governor.monitoring_subscription import MonitoringSubscriptionRegistry
        hosts = [{"host": a["host"], "expires_at": a["expires_at"]}
                 for a in AssetOwnershipRegistry(self.store, owner_key=None).assets_overview(org_id, now=now)
                 if a.get("status") == "verified"]
        sub = MonitoringSubscriptionRegistry(self.store, owner_key=None).active_subscription(org_id, now=now)
        plan = monitoring_plan(sub.plan_id) if sub is not None else None
        if sub is None or plan is None:
            return hosts, None
        return hosts, {"host_slots": plan.host_slots, "respond": plan.respond, "period_end": float(sub.period_end)}

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

    def customer_billing_rates(self, requester: str, requester_org_id: str, *, ip: str = "") -> dict:
        """The published usage rates (credits only), for a member of the session org."""
        from vigil_core.rate_card import RateCardError

        from . import billing as _billing
        try:
            return self._customer_read(requester, requester_org_id, "view_billing", lambda s, o: _billing.billing_rates())
        except RateCardError:
            raise ProvisionDenied("the published rates are unavailable") from None

    def customer_billing_usage(self, requester: str, requester_org_id: str, *, ip: str = "") -> dict:
        """The session org's per-charge usage statement (credits only). ``now`` is the DISPLAY instant — it decides
        which plan tranches have expired for the balance-after timeline (W2c-2), exactly as ``billing_overview``'s
        ``now`` reads a lapsed subscription."""
        import time as _t
        from vigil_core.rate_card import RateCardError

        from .. import config as _config
        from . import billing as _billing
        pub = getattr(self.orgs, "trusted_pubkey", None)
        try:
            return self._customer_read(
                requester, requester_org_id, "view_billing",
                lambda s, o: _billing.billing_usage(s, o, trusted_pubkey=pub, meter_dir=_config.MODEL_METER_DIR,
                                                    now=_t.time()))
        except RateCardError:
            raise ProvisionDenied("the published rates are unavailable") from None

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
        from .. import config
        from . import assessments as _assess
        t = _t.time()
        out = self._customer_read(
            requester, requester_org_id, "view_assessments",
            lambda s, o: _assess.assessment_findings(
                s, o, now=t, preview=self._preview_locked(o),
                can_buy=self.orgs.admit_customer(username=requester, org_id=o, permission="manage_billing")))
        # C1b — overlay each shown finding's newest retest verdict (``f["retest"]``) ONLY while the retest UI is on;
        # off, the findings read is byte-identical (no overlay, no retest scan). Tenant isolation is structural: the
        # overlay is bounded to the slugs of the ALREADY tenant-scoped page and matches a finding's full identity, so
        # no other org's retest (and no sibling sharing a finding_ref) can attach; only provisioner-written count.
        if config.customer_retest_ui_enabled() and isinstance(out, dict) and isinstance(out.get("findings"), list):
            _assess.overlay_retests(self.store, out["findings"], now=t)
        return out

    def customer_launches(self, requester: str, requester_org_id: str, *, ip: str = "",
                          now: "Optional[float]" = None) -> dict:
        """C1a — the SESSION org's assessment launches for the customer app (``ui/customer_launches.launches``): those
        reserved, running or paused with the actions the server would accept, those that finished, and what Launch
        may offer. Absent unless VIGIL_CUSTOMER_LAUNCH_UI is on. Gated like the assessments read
        (``admit_customer(view_assessments)`` on the session org, no global leg); the actions, the launch choices and
        each launch's signed lease (what start / cancel / pause / resume must present) are included only for a member
        who may run assessments (``run_engagement``). Credits only: no amount, no units, no estimate."""
        from .. import config
        if not config.customer_launch_ui_enabled():
            raise ProvisionDenied("launching assessments from the app is not enabled")
        t = self._now() if now is None else float(now)
        from . import customer_launches as _cl

        def project(store, org: str) -> dict:
            control = self.orgs.admit_customer(username=requester, org_id=org, permission="run_engagement")
            return _cl.launches(store, org, now=t, trusted_pubkey=getattr(self.orgs, "trusted_pubkey", None),
                                control=control, pause_resume=config.customer_pause_resume_enabled(),
                                choices=self._launch_choices(org) if control else [])
        return self._customer_read(requester, requester_org_id, "view_assessments", project)

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
            # W5 (VIGIL_BILLING_REVERSALS): a billing HOLD — credits owed after a reversed payment (the overview
            # carries it). Stable id: it is shown once per hold, until a top-up repays it.
            hold = ov.get("hold") or {}
            if hold.get("on_hold"):
                items.append({"id": "billing:hold", "kind": "billing", "severity": "high",
                              "title": "Billing on hold",
                              "body": (f"A payment was reversed and {int(hold.get('owed') or 0)} credits are owed. "
                                       "Top up to repay them; new assessments can start again once they are repaid."),
                              "ts": None})
            # W5 (VIGIL_BILLING_LOW_BALANCE_ALERT): the low-balance notice, once per crossing (its id carries the last
            # top-up, so the next top-up re-arms it). A threshold in credits — never an estimate.
            if _cfg.low_balance_alert_enabled():
                from ..governor.low_balance import low_balance_of
                lb = low_balance_of(self.store, requester_org_id, now=t)
                if lb is not None:
                    items.append({"id": "billing:low_balance:" + lb.key, "kind": "billing", "severity": "medium",
                                  "title": "Low credit balance",
                                  "body": (f"Your available credits are below {lb.threshold}. Top up to keep your "
                                           "assessments running."),
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

        # 5) Assessments PAUSED FOR CREDIT (W3) — a metered run whose prepaid credits ran out is parked with its work
        #    so far kept, waiting for a top-up and a resume. Derived from the sovereign credit-pause records of THIS
        #    org's own server-derived slug set (never a seam field decides the tenant). Shown to a member who can top
        #    up (view_billing) or who follows assessments (view_assessments); it carries NO amount and names no host.
        #    Absent unless a credit pause exists, and only metered billing ever records one.
        if (self.orgs.admit_customer(username=requester, org_id=requester_org_id, permission="view_billing")
                or self.orgs.admit_customer(username=requester, org_id=requester_org_id,
                                            permission="view_assessments")):
            items.extend(_credit_pause_notices(self.store, requester_org_id, now=t))
        # 6) A1 AUTO TOP-UP receipts (view_billing) — one notice per owner-signed per-crossing charge record, so
        #    every automatic charge (and every refused one) reaches the customer exactly once (stable id
        #    ``auto_topup:<crossing>``). Credits only, never a money amount. Only while auto top-up is wired:
        #    with the flag off this source contributes nothing (byte-identical).
        if _cfg.billing_auto_topup_enabled() and self.orgs.admit_customer(
                username=requester, org_id=requester_org_id, permission="view_billing"):
            for c in self._auto_topup_registry(signing=False).charges(requester_org_id)[-_AUTO_TOPUP_NOTICES:]:
                items.append(_auto_topup_notice(c))

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
            #                               goes to the customer; the library error text (e.detail) goes only
            #                               to the operator audit
            self._audit("target_verify", requester=requester, org_id=requester_org_id,
                        target=host, outcome="fetch_failed", reason=e.detail or str(e))
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
    from .email_channel import EmailCodeLedger, EmailTokenLedger
    from .login_ratelimit import LoginRateLimiter
    from .pending_checkout import PendingPlanCheckouts, billing_spool_dirs, stripe_billing_spool_dirs
    from .pending_totp import PendingTotpEnrolments
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
    orgs = OrgRegistry(store)          # resolves the deployment owner identity once (reused for the pending records)
    return Provisioner(
        store,
        customers=CustomerRegistry(store),
        orgs=orgs,
        wallet=WalletRegistry(store),
        email_tokens=EmailTokenLedger(config.EMAIL_TOKENS_DIR),
        rate_limiter=LoginRateLimiter(config.LOGIN_RATELIMIT_DIR),
        # the 6-digit email codes, OFF unless VIGIL_CUSTOMER_EMAIL_CODE: 5 wrong codes per email+purpose per hour
        # across re-sent codes, the lock doubling up to a day (each code also dies at its own 5th wrong code)
        email_codes=EmailCodeLedger(config.EMAIL_CODES_DIR) if config.customer_email_code_enabled() else None,
        email_code_limiter=(LoginRateLimiter(config.EMAIL_CODE_RATELIMIT_DIR, max_fails=5, window_s=3600.0,
                                             base_lock_s=3600.0, max_lock_s=86400.0)
                            if config.customer_email_code_enabled() else None),
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
        # the owner-signed pending plan-checkout records (audit E1b; signed + verified by the deployment owner key),
        # reading the billing-webhook spool (read-only) before an expired one may lapse.
        pending_checkouts=PendingPlanCheckouts(config.PENDING_PLAN_CHECKOUT_DIR, owner_key=orgs.owner_key,
                                               trusted_pubkey=orgs.trusted_pubkey,
                                               billing_spools=billing_spool_dirs(),
                                               stripe_spools=stripe_billing_spool_dirs()),
        # the per-org / per-requester checkout-creation ceiling (its own marker dir; guard-and-count `admit`).
        checkout_limiter=LoginRateLimiter(config.CHECKOUT_RATELIMIT_DIR, max_fails=Provisioner._CHECKOUT_MAX,
                                          window_s=Provisioner._CHECKOUT_WINDOW_S,
                                          base_lock_s=Provisioner._CHECKOUT_WINDOW_S,
                                          max_lock_s=6 * Provisioner._CHECKOUT_WINDOW_S),
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
        # Enrolment hardening (customer_mfa_enroll_stepup_enabled; the stores are INERT while the flag is off).
        # The PENDING (confirm-before-activate) sealed-TOTP store, and the per-account MFA limiter bounding code
        # guessing + enrolment churn (10 wrong codes / enrol attempts per 5-minute window, then a 5-minute lock
        # doubling up to an hour — generous for a human, negligible for a guesser against a ~3-in-1e6 target).
        pending_totp=PendingTotpEnrolments(config.CUSTOMER_MFA_PENDING_TOTP_DIR,
                                           ttl_s=config.CUSTOMER_MFA_PENDING_TTL_SECONDS),
        mfa_limiter=LoginRateLimiter(config.CUSTOMER_MFA_ENROLL_RATELIMIT_DIR, max_fails=10, window_s=300.0,
                                     base_lock_s=300.0, max_lock_s=3600.0),
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
