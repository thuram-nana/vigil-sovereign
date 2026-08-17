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

HARD-PRUNE (Slice S2 — BUILT): the fold SEEDS from the committed `SnapshotState` (per-username LWW state +
high-water + the cred fields to rebuild an active `Account`) and then folds forward over the live window,
exactly like promotion/killswitch/capability — so a hard prune below the first `governor.account` grant
neither vanishes an active account (`resolve()`→None) nor resets its per-username anti-replay high-water
(which would re-open the LWW replay-resurrection HIGH). `SnapshotState.build()` carries the account seed, and
`spine.prune.check_prune_safe` refuses a boundary that would strand an active account's only grant. Under the
empty Slice-C snapshot the seed is empty and the window is a full genesis scan (BYTE-IDENTICAL to before).

HONESTY (head coupling): `_fold` now calls `SnapshotState.load` on every read, so per-user auth
(`resolve`/`accounts`) is coupled to `head.json` integrity — a corrupt / future-schema / unverifiable-pruned
head fails CLOSED (`SnapshotError`), exactly as the already-merged promotion/killswitch/capability folds. So
the "BYTE-IDENTICAL" claim is scoped to a VALID head: with an absent or clean no-prune head, load is the
empty identity and the fold is the prior genesis scan; a tampered head now fails auth closed rather than
silently scanning a truncated window (the intended, fail-safe direction).
"""
from __future__ import annotations

import hmac
import math
import re
import secrets
from dataclasses import dataclass
from typing import Optional

from ..reuse import IntegrityError, assert_no_offense, sha256_hex
from ..reuse.crypto import load_public_key

assert_no_offense()

# ONE source of truth for the role→permission vocabulary. `viewer < analyst < operator < owner`, the
# cumulative permission sets, and `role_can` live in `vigil_core.rbac` — a pure, namespace-clean module
# BOTH trust domains import (the offense console per-action gate calls the SAME `role_can`). We RE-EXPORT
# them here so every existing sovereign caller (`from ..governor.accounts import role_can/ROLES/PERMISSIONS`)
# keeps working unchanged; `PERMISSION_BY_ACTION` below stays sovereign-local (it maps the sovereign action
# surface). vigil_core imports no framework/strix/sigil, so this crosses no offense boundary.
from vigil_core.rbac import PERMISSIONS, ROLES, role_can  # noqa: E402,F401  (re-exported)

from ..spine.snapshot import SnapshotState  # noqa: E402
from .authn import NO_HIGHWATER, as_issued_at, signed_payload, verify_signed  # noqa: E402
from .identity import owner_keypair, owner_pubkey  # noqa: E402

SIGNAL = "governor.account"

# "owner" is the trust-root key-holder — it is NOT a grantable bearer role: create/assign_role refuse it
# (single-owner doctrine), so the only "owner" principal is the one holding the legacy embedded shared
# token (OWNER_PRINCIPAL below). Rank/assignability derive from the re-exported ROLES ordering.
_ROLE_RANK = {r: i for i, r in enumerate(ROLES)}
_ASSIGNABLE_ROLES = frozenset(ROLES[:-1])   # viewer / analyst / operator — never "owner"

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
    "enroll_pubkey": "manage_users",
}

# The owner-signed authenticated CORE. `issued_at` MUST be inside it (outside, an attacker could re-stamp a
# captured grant's freshness past the high-water without breaking the signature — exactly the replay this
# guard refuses); `cred_hash`/`cred_salt`/`role`/`username` MUST be inside it so an owner-signed grant for
# one principal can never be re-aimed at another or have its role/credential rewritten.
_BASE_CORE = ("signal", "username", "role", "cred_hash", "cred_salt", "state", "issued_at")


def _core_fields(payload: dict) -> "tuple[str, ...]":
    """The signed core field set for an accounts grant — CONDITIONAL on the payload itself: the 7 base
    fields ALWAYS, plus `user_pubkey` (S3 — the owner-bound Ed25519 login identity) IFF the grant actually
    carries a truthy bound key. Scoped to this module (NOT baked into the shared `authn.verify_signed`), so
    every other record type is untouched.

    This conditional encoding keeps two properties at once:
      * a PRE-SLICE grant AND a new KEYLESS `create_account`/`assign_role` grant both canonicalize to the
        7-field form BYTE-IDENTICALLY to before this slice — so their existing owner signature still verifies
        and no account is silently locked out on upgrade (an UNCONDITIONAL 8-field core would append
        `"user_pubkey":null` to the canonical bytes and break every pre-slice signature);
      * a KEYED `enroll_pubkey` grant signs+verifies over 8 fields, so the binding rides inside the owner
        signature and a forged/unsigned binding is refused.

    It also keeps the malleability inverse CLOSED, because the field set is DERIVED from the payload's actual
    `user_pubkey` presence: STRIPPING a bound key (present the grant without it) verifies over 7 fields and
    the 8-field signature FAILS; ADDING a key to an old grant verifies over 8 fields and the 7-field
    signature FAILS. Neither tamper survives."""
    return _BASE_CORE + (("user_pubkey",) if payload.get("user_pubkey") else ())

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
    user_pubkey: Optional[str] = None   # owner-bound Ed25519 pubkey for challenge/response PoP login (S3);
    #                                     None ⇒ this account authenticates by bearer only (backward-compat)


@dataclass(frozen=True)
class Principal:
    username: str
    role: str


# The legacy embedded shared owner token maps to this principal — the owner is physically at the host and
# must never be locked out (fail-open is restricted to that EXACT token in `server._principal_for_token`).
OWNER_PRINCIPAL = Principal(username="owner", role="owner")


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


def _check_user_pubkey(user_pubkey: str) -> str:
    """Validate a candidate user Ed25519 public key at BINDING time. `load_public_key` rejects malformed,
    non-canonical (y >= p) and low-order (keyless-forgery) keys fail-closed, so binding garbage is a clean
    400 now instead of a silent, always-failing login later. Returns the canonical b64 key string."""
    pk = str(user_pubkey or "").strip()
    if not pk:
        raise ValueError("user_pubkey must be a base64-encoded Ed25519 public key")
    try:
        load_public_key(pk)
    except IntegrityError as e:
        raise ValueError(f"invalid user public key: {e}")
    return pk


class AccountsRegistry:
    """Owner-signed account grants on the spine. Construction mirrors KillSwitch/PromotionPolicy: the owner
    signing key and trusted pubkey default to the persisted owner identity."""

    def __init__(self, store, *, owner_key=None, trusted_pubkey: Optional[str] = None):
        self.store = store
        self.owner_key = owner_key if owner_key is not None else owner_keypair()
        self.trusted_pubkey = trusted_pubkey if trusted_pubkey is not None else owner_pubkey()

    # -- owner mutations ---------------------------------------------------------------------------
    def create(self, username: str, role: str, *, bearer_token: str, issued_at: float,
               user_pubkey: Optional[str] = None) -> int:
        """Owner-sign a new active account. The caller (the actions layer) generates the bearer token and
        never stores it in plaintext: only `sha256_hex(salt + bearer)` and the per-account salt are
        recorded. Requires the owner signing key (a grant with no owner signature never verifies in the
        fold, so it would be inert). `user_pubkey` optionally binds the S3 challenge/response login identity
        at creation (usually bound later via `enroll_pubkey`); it is validated fail-closed when present."""
        if self.owner_key is None:
            raise ValueError("account creation requires the owner signing key")
        u, r = _check_username(username), _check_role(role)
        if not isinstance(bearer_token, str) or len(bearer_token) < 16:
            raise ValueError("bearer_token must be a >=16-char string")
        pk = _check_user_pubkey(user_pubkey) if user_pubkey else None
        salt = secrets.token_hex(16)
        cred_hash = sha256_hex((salt + bearer_token).encode("utf-8"))
        return self._append_active(u, r, cred_hash=cred_hash, cred_salt=salt, issued_at=float(issued_at),
                                   user_pubkey=pk)

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
                                   issued_at=float(issued_at), user_pubkey=acct.user_pubkey)

    def enroll_pubkey(self, username: str, user_pubkey: str, *, issued_at: float) -> int:
        """Owner-bind an Ed25519 PUBLIC key to an existing active account — the S3 stronger login identity.
        This is the DANGEROUS direction (it grants the account a challenge/response proof-of-possession
        login), so it is honored only if it verifies AND is FRESH (`issued_at` strictly exceeds the
        per-username high-water). Re-signs the account KEEPING its role + bearer credential and SETTING the
        key. The OWNER is the sole signer (single-owner doctrine — the user never mints its own trust); the
        key is validated here (`load_public_key` rejects weak/non-canonical keys). Fail-closed on an
        unknown/revoked account. Mirrors `mesh.registry.authorize_device` (owner binds a subject pubkey into
        a fresh, per-key-LWW spine grant) — NOT a governance TrustRoot, a login Principal's identity."""
        if self.owner_key is None:
            raise ValueError("enroll_pubkey requires the owner signing key")
        u = _check_username(username)
        pk = _check_user_pubkey(user_pubkey)
        acct = self._fold().get(u)
        if acct is None:
            raise ValueError(f"no such active account {u!r} (create it first, or it was revoked)")
        return self._append_active(u, acct.role, cred_hash=acct.cred_hash, cred_salt=acct.cred_salt,
                                   issued_at=float(issued_at), user_pubkey=pk)

    def mint_session_bearer(self, username: str, *, issued_at: float) -> "tuple[str, int]":
        """Mint a FRESH owner-signed session bearer for an existing active account, returning
        (bearer, recorded_seq). The PoP login uses this: because the plaintext bearer is NEVER stored (only
        its salted hash), a successful proof-of-possession cannot echo a pre-existing bearer — it hands back
        a freshly-rotated one that flows through the SAME X-SIGIL-Token carrier + `resolve()` path (zero
        change downstream). Preserves the account's role + bound `user_pubkey`; `issued_at` is bumped to
        STRICTLY exceed the per-username high-water so the rotation is always honored (never silently dropped
        as a stale replay under a same-tick clock). Owner-signed (single-owner doctrine)."""
        if self.owner_key is None:
            raise ValueError("mint_session_bearer requires the owner signing key")
        u = _check_username(username)
        acct = self._fold().get(u)
        if acct is None:
            raise ValueError(f"no such active account {u!r}")
        iat = max(float(issued_at), math.nextafter(acct.issued_at, math.inf))
        bearer = secrets.token_urlsafe(32)
        salt = secrets.token_hex(16)
        cred_hash = sha256_hex((salt + bearer).encode("utf-8"))
        seq = self._append_active(u, acct.role, cred_hash=cred_hash, cred_salt=salt,
                                  issued_at=iat, user_pubkey=acct.user_pubkey)
        return bearer, seq

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
                       issued_at: float, user_pubkey: Optional[str] = None) -> int:
        core = {"signal": SIGNAL, "username": username, "role": role, "cred_hash": cred_hash,
                "cred_salt": cred_salt, "state": "active", "issued_at": float(issued_at)}
        if user_pubkey:
            # CONDITIONALLY signed: included ONLY when a key is bound, so a keyless grant canonicalizes to
            # the 7-field form byte-identically to the pre-slice encoding (see `_core_fields`). `signed_payload`
            # signs exactly the dict it is given, and verification re-derives the same field set from the
            # payload — so sign and verify agree without an unconditional `"user_pubkey":null`.
            core["user_pubkey"] = user_pubkey
        payload = {**signed_payload(core, self.owner_key), "by": "owner", "requested_by": "owner",
                   "tier": "A0", "decision": "auto",
                   "reason": f"account {username} → {role} (owner-signed grant)"}
        return self.store.append(kind="event", source="governor", actor="WARDEN", payload=payload)

    # -- reads (both go through the ONE fold) -------------------------------------------------------
    def _fold(self) -> dict[str, Account]:
        """THE fold — one implementation, called by BOTH `resolve()` and `accounts()`, so the per-username
        anti-replay high-water is applied IDENTICALLY at both read surfaces (mirror-the-fix discipline).
        Returns {username: Account} for accounts whose latest state is active (revoked ones are dropped).

        HARD-PRUNE SEED (mirrors PromotionPolicy._fold EXACTLY): seed the per-username state / high-water /
        active-Account set from the committed `SnapshotState`, then fold forward over the LIVE window only —
        so an active account whose only grant was pruned SURVIVES and its anti-replay high-water is NOT reset.

        Pubkey-DEPENDENT: the pre-folded prefix (and its high-water) is valid ONLY under the pubkey it was
        folded with. If our anchor differs (rotated key / the empty Slice-C identity whose tp=="") BYPASS the
        snapshot and full-scan from genesis. BYTE-IDENTICAL under the empty snapshot: base_seq==0 =>
        since_seq=-1 => the full genesis scan, and an empty seed either way."""
        snap = SnapshotState.load(self.store)
        if self.trusted_pubkey != snap.trusted_pubkey:
            state, accts, issued, since = {}, {}, {}, -1
        else:
            # PER-USERNAME state / high-water / Account, seeded from the SAME snapshot under the SAME pubkey
            # condition — otherwise the first hard prune would reset them and re-open the replay HIGH.
            state = dict(snap.account_state_map())        # username -> "active"|"revoked" (LWW; keep revoked)
            issued = dict(snap.account_issued_map())      # username -> per-username high-water
            accts = {row[0]: Account(                     # rebuild the honored-active Accounts from the seed
                        username=str(row[0]), role=str(row[1] or ""), cred_hash=str(row[2] or ""),
                        cred_salt=str(row[3] or ""), issued_at=issued.get(row[0], 0.0), state="active",
                        # 5th seed field = user_pubkey (None for a legacy/bearer-only row) — carried so a KEYED
                        # account pruned below base_seq keeps its PoP login capability.
                        user_pubkey=(str(row[4]) if len(row) > 4 and row[4] else None))
                     for row in snap.account_cred}
            since = snap.base_seq - 1
        for r in self.store.iter_records(since_seq=since):
            p = r.payload
            if not isinstance(p, dict) or p.get("signal") != SIGNAL:
                continue
            username = p.get("username")
            rec_state = p.get("state")
            if rec_state == "revoked":
                state[username] = "revoked"          # honor ANY revoke (even unsigned) — the safe direction
            elif rec_state == "active":
                if not verify_signed(p, _core_fields(p), self.trusted_pubkey):
                    continue                          # fail-closed: an unsigned/forged grant is not counted
                    #                                   (field set derived from the payload — see _core_fields)
                at = as_issued_at(p.get("issued_at"))
                if at <= issued.get(username, NO_HIGHWATER):
                    continue                          # REPLAY / stale re-append of an already-honored grant
                issued[username] = at                 # consume it so its own replay is refused hereafter
                state[username] = "active"
                upk = p.get("user_pubkey")
                accts[username] = Account(
                    username=str(username), role=str(p.get("role") or ""),
                    cred_hash=str(p.get("cred_hash") or ""), cred_salt=str(p.get("cred_salt") or ""),
                    issued_at=at, state="active",
                    user_pubkey=(str(upk) if upk else None))   # carried through unchanged (None ⇒ bearer-only)
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
            if hmac.compare_digest(sha256_hex((a.cred_salt + token).encode("utf-8")), a.cred_hash):
                return Principal(username=a.username, role=a.role)
        return None

    def account(self, username: str) -> Optional[Account]:
        """The current active `Account` for `username` (carrying its bound `user_pubkey`), or None
        (fail-closed — a revoked/unknown username is absent from the fold). Folds ONCE. Used by the PoP
        login to look up the account's owner-bound login key before verifying the challenge signature."""
        if not isinstance(username, str) or not username:
            return None
        return self._fold().get(username)

    def accounts(self) -> list[Account]:
        """The current active fold (for the owner's Users & Roles list). The cred_hash/cred_salt live on the
        Account object but the HTTP layer never surfaces them — only username/role/state/issued_at."""
        fold = self._fold()
        return [fold[u] for u in sorted(fold)]
