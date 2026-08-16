"""Enforced multi-user RBAC (Claim 6) — an ADMISSION GATE in front of the owner-signing funnel.

VIGIL stays SINGLE-OWNER-KEY at the trust root. RBAC is not a second key custody: the owner Ed25519 key
(`governor/identity.py`) remains the SOLE signer of every governance mutation, and a non-owner user never
holds a key. Every UI mutation already funnels through one choke point (`ui/actions.py::do_action`, where
the server signs with `ensure_owner_keypair()` on the caller's behalf); RBAC inserts a role→permission
check BEFORE that signing happens, and records the requesting principal for attribution. So "nothing
self-authorizes" holds: a viewer's request never produces an owner signature (the check refuses first), and
a forged/unsigned grant never verifies in the fold.

Accounts and role grants are themselves OWNER-SIGNED spine grants — the owner delegating "principal P has
role R" is the existing killswitch/capability/promotion governance-record idiom, no new trust primitive.

ASYMMETRIC AUTHENTICATION (mirrors killswitch/capability/promotion):
  * create / assign_role = the DANGEROUS direction → honored only if OWNER-SIGNED (`verify_signed`) AND
    its `issued_at` STRICTLY exceeds the per-username high-water.
  * revoke = the SAFE direction → `state="revoked"` is honored even UNSIGNED, with a FIXED `issued_at`
    of 0.0 (a replayed revoke merely re-revokes). Gating the fail-safe direction would make it fail open.

ANTI-REPLAY (per-username LWW high-water — closes the known VIGIL LWW replay-resurrection HIGH): a revoked
account cannot be resurrected by re-appending a captured owner-signed `active` grant, because that grant's
`issued_at <= high-water` → it is ignored. The fold is computed by ONE `_fold()` helper that BOTH read
paths (`resolve()` for auth and `accounts()` for the list) call, so the high-water guard is present at
BOTH surfaces identically (the memory-noted "mirror the fix in both read paths" discipline).

FATAL-2: this module is sovereign-side and imports NO `framework`/`strix` (guarded by `assert_no_offense`
at import); all crypto is the sovereign `reuse`/`vigil_core` primitives.

DEFERRED (honest scope — flagged, not built): the accounts fold is a GENESIS scan (byte-safe under the
Slice-C empty snapshot, exactly as killswitch/capability note). A future cold-archive hard-prune must
extend `SnapshotState` with an accounts seed (per-username LWW state + high-water) AND a referential-floor
assert (no active account below `base_seq` without its grant), mirrored in `resolve()` and `accounts()`.
"""
from __future__ import annotations

import hmac
import re
import secrets
from dataclasses import dataclass
from typing import Optional

from ..reuse import assert_no_offense, sha256_hex

assert_no_offense()

from .authn import NO_HIGHWATER, as_issued_at, signed_payload, verify_signed  # noqa: E402
from .identity import owner_keypair, owner_pubkey  # noqa: E402

SIGNAL = "governor.account"

# Roles, ordered by privilege rank (index = rank). "owner" is the trust-root key-holder — it is NOT a
# grantable bearer role: create/assign_role refuse it (single-owner doctrine), so the only "owner"
# principal is the one holding the legacy embedded shared token (OWNER_PRINCIPAL below).
ROLES = ("viewer", "analyst", "operator", "owner")
_ROLE_RANK = {r: i for i, r in enumerate(ROLES)}
_ASSIGNABLE_ROLES = frozenset(ROLES[:-1])   # viewer / analyst / operator — never "owner"

# The permission vocabulary the action table maps to. owner ⊇ operator ⊇ analyst ⊇ viewer (cumulative).
_VIEWER = frozenset({"read"})
_ANALYST = _VIEWER | {"queue_proposal"}
_OPERATOR = _ANALYST | {"run_engagement", "approve_a2", "toggle_guard", "config_nonsecret"}
_OWNER = _OPERATOR | {"approve_a3", "kill_release", "promote", "secrets", "offense_authority",
                      "manage_users", "toggle_protected_guard"}
PERMISSIONS: dict[str, frozenset[str]] = {
    "viewer": _VIEWER, "analyst": _ANALYST, "operator": _OPERATOR, "owner": _OWNER,
}

# The env whose set_config disables the categorical .gov/.mil/.edu/.int safety floor (Claim 5). Turning
# that floor OFF is OWNER-ONLY (`toggle_protected_guard`), NOT the operator-level `config_nonsecret` the
# rest of set_config uses — do_action special-cases it (see the funnel gate).
PROTECTED_GUARD_ENV = "VIGIL_ALLOW_PROTECTED_DOMAINS"

# action → required permission. A None value or an ABSENT action is DEFAULT-DENY (fail-closed): an
# unmapped future action refuses until it is explicitly mapped here. `approve`/`deny` are resolved
# DYNAMICALLY by the target's tier in `agents/approvals.ApprovalQueue._decide` (A3/destructive ⇒
# approve_a3, else approve_a2), so they carry None here and the funnel defers their check.
PERMISSION_BY_ACTION: dict[str, Optional[str]] = {
    "approve": None, "deny": None,                       # dynamic (tier-resolved downstream)
    "kill": "read", "release": "kill_release",            # halting is safe (any authn'd); un-halting owner-only
    "promote": "promote", "revoke": "promote",
    "queue_learn": "queue_proposal", "start_learn": "run_engagement",
    "disable_gesture": "toggle_guard", "enable_gesture": "toggle_guard",
    "disable_voice": "toggle_guard", "enable_voice": "toggle_guard",
    "disable_autolearn": "toggle_guard", "enable_autolearn": "toggle_guard",
    "disable_both": "toggle_guard", "enable_both": "toggle_guard",
    "set_model": "config_nonsecret", "set_effort": "config_nonsecret",
    "set_provider": "config_nonsecret", "set_config": "config_nonsecret",
    "set_cloud_config": "config_nonsecret",
    "set_secret": "secrets", "check_secret": "secrets", "check_secrets": "secrets",
    "set_cloud_file_secret": "secrets",
    "offense_bind_authority": "offense_authority",
    "offense_approve": "offense_authority", "offense_deny": "offense_authority",
    "create_account": "manage_users", "assign_role": "manage_users", "revoke_account": "manage_users",
}

# The owner-signed authenticated CORE. `issued_at` MUST be inside it (outside, an attacker could re-stamp a
# captured grant's freshness past the high-water without breaking the signature — exactly the replay this
# guard refuses); `cred_hash`/`cred_salt`/`role`/`username` MUST be inside it so an owner-signed grant for
# one principal can never be re-aimed at another or have its role/credential rewritten.
_CORE = ("signal", "username", "role", "cred_hash", "cred_salt", "state", "issued_at")

_USERNAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")


class PermissionDenied(Exception):
    """The requesting principal's role does not carry the permission this action requires. Raised
    fail-closed at the admission gate BEFORE the owner key signs anything; the HTTP layer maps it to 403."""


@dataclass(frozen=True)
class Account:
    username: str
    role: str            # one of ROLES (never "owner" for a bearer account)
    cred_hash: str       # sha256_hex(cred_salt + bearer_token) — the plaintext bearer is NEVER stored
    cred_salt: str       # per-account random (secrets.token_hex(16))
    issued_at: float     # owner-set anti-replay high-water
    state: str           # "active" | "revoked"


@dataclass(frozen=True)
class Principal:
    username: str
    role: str


# The legacy embedded shared owner token maps to this principal — the owner is physically at the host and
# must never be locked out (fail-open is restricted to that EXACT token in `server._principal_for_token`).
OWNER_PRINCIPAL = Principal(username="owner", role="owner")


def role_can(role: Optional[str], perm: Optional[str]) -> bool:
    """True iff `role` carries `perm`. DEFAULT-DENY: an unmapped action (perm is None/"") refuses, and an
    unknown role has no permissions. This is the one predicate the whole gate turns on."""
    if not perm:
        return False
    return perm in PERMISSIONS.get(role or "", frozenset())


def _check_username(username: str) -> str:
    u = str(username or "").strip()
    if not _USERNAME_RE.match(u):
        raise ValueError("username must be 1-64 chars of [A-Za-z0-9._-] and start alphanumeric")
    if u == OWNER_PRINCIPAL.username:
        raise ValueError("'owner' is the reserved trust-root principal — pick another username")
    return u


def _check_role(role: str) -> str:
    r = str(role or "").strip()
    if r not in _ASSIGNABLE_ROLES:
        raise ValueError(f"role must be one of {sorted(_ASSIGNABLE_ROLES)} — 'owner' is not grantable "
                         f"(single-owner-key doctrine)")
    return r


class AccountsRegistry:
    """Owner-signed account grants on the spine. Construction mirrors KillSwitch/PromotionPolicy: the owner
    signing key and trusted pubkey default to the persisted owner identity."""

    def __init__(self, store, *, owner_key=None, trusted_pubkey: Optional[str] = None):
        self.store = store
        self.owner_key = owner_key if owner_key is not None else owner_keypair()
        self.trusted_pubkey = trusted_pubkey if trusted_pubkey is not None else owner_pubkey()

    # -- owner mutations ---------------------------------------------------------------------------
    def create(self, username: str, role: str, *, bearer_token: str, issued_at: float) -> int:
        """Owner-sign a new active account. The caller (the actions layer) generates the bearer token and
        never stores it in plaintext: only `sha256_hex(salt + bearer)` and the per-account salt are
        recorded. Requires the owner signing key (a grant with no owner signature never verifies in the
        fold, so it would be inert)."""
        if self.owner_key is None:
            raise ValueError("account creation requires the owner signing key")
        u, r = _check_username(username), _check_role(role)
        if not isinstance(bearer_token, str) or len(bearer_token) < 16:
            raise ValueError("bearer_token must be a >=16-char string")
        salt = secrets.token_hex(16)
        cred_hash = sha256_hex(salt + bearer_token)
        return self._append_active(u, r, cred_hash=cred_hash, cred_salt=salt, issued_at=float(issued_at))

    def assign_role(self, username: str, role: str, *, issued_at: float) -> int:
        """Owner-sign a role change — the DANGEROUS direction, so it is honored only if it verifies AND is
        FRESH. Keeps the same bearer credential (re-signs the existing cred_hash/salt with the new role and
        a strictly-greater issued_at). Fail-closed on an unknown / non-active account."""
        if self.owner_key is None:
            raise ValueError("assign_role requires the owner signing key")
        u, r = _check_username(username), _check_role(role)
        acct = self._fold().get(u)
        if acct is None:
            raise ValueError(f"no such active account {u!r} (create it first, or it was revoked)")
        return self._append_active(u, r, cred_hash=acct.cred_hash, cred_salt=acct.cred_salt,
                                   issued_at=float(issued_at))

    def revoke(self, username: str) -> int:
        """Revoke an account — the SAFE direction. Owner-signed for provenance/audit, but takes effect
        regardless of the signature (a forged/nuisance revoke is at worst a fail-safe DoS on that account),
        and carries a FIXED `issued_at` of 0.0 (a replayed revoke merely re-revokes)."""
        u = _check_username(username)
        core = {"signal": SIGNAL, "username": u, "role": "", "cred_hash": "", "cred_salt": "",
                "state": "revoked", "issued_at": 0.0}
        payload = {**signed_payload(core, self.owner_key), "by": "owner", "requested_by": "owner",
                   "tier": "A0", "decision": "auto", "reason": f"account {u} REVOKED (governed latch)"}
        return self.store.append(kind="event", source="governor", actor="WARDEN", payload=payload)

    def _append_active(self, username: str, role: str, *, cred_hash: str, cred_salt: str,
                       issued_at: float) -> int:
        core = {"signal": SIGNAL, "username": username, "role": role, "cred_hash": cred_hash,
                "cred_salt": cred_salt, "state": "active", "issued_at": float(issued_at)}
        payload = {**signed_payload(core, self.owner_key), "by": "owner", "requested_by": "owner",
                   "tier": "A0", "decision": "auto",
                   "reason": f"account {username} → {role} (owner-signed grant)"}
        return self.store.append(kind="event", source="governor", actor="WARDEN", payload=payload)

    # -- reads (both go through the ONE fold) -------------------------------------------------------
    def _fold(self) -> dict[str, Account]:
        """THE fold — one implementation, called by BOTH `resolve()` and `accounts()`, so the per-username
        anti-replay high-water is applied IDENTICALLY at both read surfaces (mirror-the-fix discipline).
        Returns {username: Account} for accounts whose latest state is active (revoked ones are dropped).

        GENESIS scan (no snapshot seed): byte-safe under the Slice-C empty snapshot exactly as
        killswitch/capability; a future hard prune must extend SnapshotState (see the module note)."""
        state: dict[str, str] = {}       # username -> "active" | "revoked" (last-write-wins; keep revoked)
        accts: dict[str, Account] = {}   # username -> the latest VERIFIED, FRESH active Account
        issued: dict[str, float] = {}    # username -> per-username high-water (max honored active issued_at)
        for r in self.store.iter_records(since_seq=-1):
            p = r.payload
            if not isinstance(p, dict) or p.get("signal") != SIGNAL:
                continue
            username = p.get("username")
            st = p.get("state")
            if st == "revoked":
                state[username] = "revoked"          # honor ANY revoke (even unsigned) — the safe direction
            elif st == "active":
                if not verify_signed(p, _CORE, self.trusted_pubkey):
                    continue                          # fail-closed: an unsigned/forged grant is not counted
                at = as_issued_at(p.get("issued_at"))
                if at <= issued.get(username, NO_HIGHWATER):
                    continue                          # REPLAY / stale re-append of an already-honored grant
                issued[username] = at                 # consume it so its own replay is refused hereafter
                state[username] = "active"
                accts[username] = Account(
                    username=str(username), role=str(p.get("role") or ""),
                    cred_hash=str(p.get("cred_hash") or ""), cred_salt=str(p.get("cred_salt") or ""),
                    issued_at=at, state="active")
        return {u: a for u, a in accts.items() if state.get(u) == "active"}

    def resolve(self, token: str) -> Optional[Principal]:
        """Map a per-user bearer token to its Principal, or None (fail-closed). Constant-time per account:
        `hmac.compare_digest(sha256_hex(salt + token), cred_hash)`. First match (by username order) wins.
        Never resolves a revoked account (they are absent from the fold). Folds ONCE per call."""
        if not isinstance(token, str) or not token:
            return None
        fold = self._fold()
        for username in sorted(fold):
            a = fold[username]
            if hmac.compare_digest(sha256_hex(a.cred_salt + token), a.cred_hash):
                return Principal(username=a.username, role=a.role)
        return None

    def accounts(self) -> list[Account]:
        """The current active fold (for the owner's Users & Roles list). The cred_hash/cred_salt live on the
        Account object but the HTTP layer never surfaces them — only username/role/state/issued_at."""
        fold = self._fold()
        return [fold[u] for u in sorted(fold)]
