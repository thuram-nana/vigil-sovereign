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

import base64
import hashlib
import hmac
import math
import re
import secrets
import time
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
from . import key_history as _kh  # noqa: E402  (W9-1 succession-aware owner-key resolver)
from .authn import NO_HIGHWATER, as_issued_at, signed_payload, verify_signed  # noqa: E402
from .identity import owner_keypair, owner_pubkey  # noqa: E402

SIGNAL = "governor.account"

# "owner" is the trust-root key-holder — it is NOT a grantable bearer role: create/assign_role refuse it
# (single-owner doctrine), so the only "owner" principal is the one holding the legacy embedded shared
# token (OWNER_PRINCIPAL below). Rank/assignability derive from the re-exported ROLES ordering.
_ROLE_RANK = {r: i for i, r in enumerate(ROLES)}
_ASSIGNABLE_ROLES = frozenset(ROLES[:-1])   # viewer / analyst / operator — never "owner"

# Upper bound on a per-token TTL (10 years, in seconds), mirroring the delegate-offense `--hours` cap
# (`cli.py`'s (0, 24*365*10] bound). A create with a larger/non-finite/non-positive ttl is refused
# fail-closed. A token's expiry is the ABSOLUTE `Account.expires_at` derived here from `issued_at + ttl`.
MAX_ACCOUNT_TTL = 24 * 365 * 10 * 3600

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
    "revoke_all_teammates": "manage_users",                            # bulk revoke every non-owner account
    "rotate_bootstrap_token": "manage_users", "revoke_bootstrap_token": "manage_users",   # owner session (1b)
    "revoke_sessions": "manage_users",                                 # sign out ALL cookie sessions (1c-ii)
    "enroll_webauthn": "manage_users", "revoke_webauthn": "manage_users",   # owner passkey (1c-iii)
    "enroll_pubkey": "manage_users",
    "enroll_totp": "manage_users", "set_password": "manage_users",     # S4 MFA / password enrollment
}

# The AEAD context that binds a sealed TOTP secret to its purpose (domain separation vs the owner key / DEK /
# other sealed secrets). The enroll path seals under THIS context and login unseals under it; a blob sealed
# for any other purpose can never be opened as a TOTP secret and vice-versa.
TOTP_SEAL_CONTEXT = b"sigil/account.totp"

# scrypt work factors for the OPTIONAL password login (S4). n=2^15 (32 MiB) is a strong interactive KDF;
# a fresh 16-byte salt per password is stored in the self-describing hash string.
_SCRYPT_N, _SCRYPT_R, _SCRYPT_P = 2 ** 15, 8, 1
_SCRYPT_MAXMEM = 132 * _SCRYPT_N * _SCRYPT_R           # headroom over scrypt's 128*n*r working set

# A DECOY password hash with the SAME scrypt params (a fixed all-zero salt/dk) — no scrypt runs to BUILD it
# (just base64 of zeros), but `verify_password(pw, DECOY_PASSWORD_HASH)` pays exactly ONE scrypt of the real
# cost and always returns False. The login path verifies against this when the account is unknown / has no
# password, so the endpoint's timing is INDEPENDENT of whether the username exists or has a password enrolled
# — closing the ~59× user-enumeration timing oracle a short-circuit would open (a real verify is ~125 ms; a
# short-circuit ~2 ms). The auth decision still requires a real, matching password.
DECOY_PASSWORD_HASH = "scrypt${}${}${}${}${}".format(
    _SCRYPT_N, _SCRYPT_R, _SCRYPT_P,
    base64.b64encode(b"\x00" * 16).decode("ascii"),
    base64.b64encode(b"\x00" * 32).decode("ascii"))


def hash_password(password: str) -> str:
    """Salted-scrypt hash of a password, as a self-describing ``scrypt$n$r$p$salt_b64$dk_b64`` string. The
    plaintext password is never stored — only this one-way hash reaches the spine. Refuses a password
    shorter than 8 chars. NOTE: a password is the WEAKER, optional convenience login; the per-user KEYPAIR
    (S3 ``enroll_pubkey`` + PoP) is the stronger path."""
    if not isinstance(password, str) or len(password) < 8:
        raise ValueError("password must be a string of at least 8 characters")
    salt = secrets.token_bytes(16)
    dk = hashlib.scrypt(password.encode("utf-8"), salt=salt, n=_SCRYPT_N, r=_SCRYPT_R, p=_SCRYPT_P,
                        maxmem=_SCRYPT_MAXMEM, dklen=32)
    return "scrypt${}${}${}${}${}".format(_SCRYPT_N, _SCRYPT_R, _SCRYPT_P,
                                          base64.b64encode(salt).decode("ascii"),
                                          base64.b64encode(dk).decode("ascii"))


def verify_password(password: str, stored: str) -> bool:
    """Constant-time verify of ``password`` against a :func:`hash_password` string. Fail-closed (False) on
    any malformed/absent stored value or decode error — never raises out of the login path."""
    try:
        scheme, n, r, p, salt_b64, dk_b64 = str(stored or "").split("$")
        if scheme != "scrypt":
            return False
        salt = base64.b64decode(salt_b64)
        expected = base64.b64decode(dk_b64)
        cand = hashlib.scrypt(str(password or "").encode("utf-8"), salt=salt,
                              n=int(n), r=int(r), p=int(p), maxmem=132 * int(n) * int(r),
                              dklen=len(expected))
    except Exception:  # noqa: BLE001 — malformed hash / bad b64 / bad params → NOT a match (fail-closed)
        return False
    return hmac.compare_digest(cand, expected)

# The owner-signed authenticated CORE. `issued_at` MUST be inside it (outside, an attacker could re-stamp a
# captured grant's freshness past the high-water without breaking the signature — exactly the replay this
# guard refuses); `cred_hash`/`cred_salt`/`role`/`username` MUST be inside it so an owner-signed grant for
# one principal can never be re-aimed at another or have its role/credential rewritten.
_BASE_CORE = ("signal", "username", "role", "cred_hash", "cred_salt", "state", "issued_at")


def _core_fields(payload: dict) -> "tuple[str, ...]":
    """The signed core field set for an accounts grant — CONDITIONAL on the payload itself: the 7 base
    fields ALWAYS, plus each OPTIONAL field IFF the grant actually carries a truthy value for it —
    `user_pubkey` (S3, the owner-bound Ed25519 login identity), `totp_secret` (S4, the SEALED TOTP shared
    secret), `password_hash` (S4, the salted-scrypt password login), and `expires_at` (the ABSOLUTE
    wallclock deadline after which this bearer no longer authenticates). Scoped to this module (NOT baked
    into the shared `authn.verify_signed`), so every other record type is untouched.

    This conditional encoding keeps two properties at once:
      * a PRE-SLICE grant AND any new grant MISSING a given optional field canonicalize to exactly the field
        set they were signed over — BYTE-IDENTICALLY to before that field existed — so an existing owner
        signature still verifies and no account is silently locked out on upgrade (an UNCONDITIONAL core
        would append e.g. `"totp_secret":null` to the canonical bytes and break every prior signature);
      * a grant that DOES carry an optional field signs+verifies over the larger field set, so the binding
        rides inside the owner signature and a forged/unsigned binding is refused.

    It also keeps the malleability inverse CLOSED for EACH optional field, because the set is DERIVED from
    the payload's actual presence: STRIPPING a bound value verifies over the smaller set and the larger-set
    signature FAILS; ADDING a value to an old grant verifies over the larger set and the smaller-set
    signature FAILS. No tamper survives. (Field ORDER here is irrelevant — `canonical_json` sorts keys — so
    only the SET matters.)"""
    fields = _BASE_CORE
    if payload.get("user_pubkey"):
        fields += ("user_pubkey",)
    if payload.get("totp_secret"):
        fields += ("totp_secret",)
    if payload.get("password_hash"):
        fields += ("password_hash",)
    if payload.get("expires_at"):
        fields += ("expires_at",)
    return fields

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
    totp_secret: Optional[str] = None   # S4 second factor: the SEALED TOTP shared secret (base64 of a
    #                                     vigil_core seal), NOT the plaintext — the server unseals it via the
    #                                     owner vault to verify codes. None ⇒ no second factor enrolled.
    password_hash: Optional[str] = None  # S4 OPTIONAL weaker login: a salted-scrypt hash (see hash_password).
    #                                      None ⇒ no password login. Keypairs (S3) are the stronger path.
    expires_at: Optional[float] = None  # ABSOLUTE wallclock deadline (issued_at + ttl at create time). None ⇒
    #                                     never expires (backward-compat: a legacy grant carries no such field).
    #                                     Read-time ONLY: expiry filters auth in resolve()/account(); it is
    #                                     NOT a durable state and NEVER touches the anti-replay high-water.

    def expired(self, now: float) -> bool:
        """True iff this account carries a deadline that `now` has reached. `None` ⇒ never expires."""
        return self.expires_at is not None and now >= self.expires_at

    def remaining(self, now: float) -> Optional[float]:
        """Seconds until this account's deadline (may be negative once past it), or None if it never expires."""
        return None if self.expires_at is None else self.expires_at - now


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


def _derive_expires_at(issued_at: float, ttl_seconds: Optional[float]) -> Optional[float]:
    """Derive the ABSOLUTE expiry deadline for a NEW grant from a chosen TTL, or None for never-expires.
    Validates fail-closed at BINDING time: a non-finite, non-positive, or over-cap `ttl_seconds` is a clean
    ValueError (400) now, never silently coerced. The deadline is anchored to the server-stamped `issued_at`
    (the token's lifetime is measured from when the owner minted it). The returned value is the absolute
    `expires_at` carried UNCHANGED through every later re-sign, so it never slides forward on a role change
    or a login rotation (mirrors the gesture-arm `expires_at`, not a use-renewing idle timer)."""
    if ttl_seconds is None:
        return None
    try:
        ttl = float(ttl_seconds)
    except (TypeError, ValueError):
        raise ValueError("ttl_seconds must be a positive number of seconds, or None for no expiry")
    if not math.isfinite(ttl) or ttl <= 0:
        raise ValueError("ttl_seconds must be a positive, finite number of seconds")
    if ttl > MAX_ACCOUNT_TTL:
        raise ValueError(f"ttl_seconds must be <= {MAX_ACCOUNT_TTL} seconds (10 years)")
    return float(issued_at) + ttl


def _as_deadline(value) -> float:
    """Coerce a TRUTHY signed-payload `expires_at` into an absolute float deadline FAIL-CLOSED. A genuine
    grant always carries a finite float (`create` writes `float(expires_at)`); a numeric STRING, a bool, a
    non-finite, or any non-number is POISON and maps to 0.0 (already expired ⇒ denied) — never a live future
    deadline. Unlike `as_issued_at` (which tolerantly `float()`s a numeric string, the right call for the
    anti-replay high-water), a deadline must reject a string so a corrupt/owner-fat-fingered value fails
    CLOSED rather than open. Called only for a truthy value; None/absent is 'never expires' at the caller."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return 0.0
    f = float(value)
    return f if math.isfinite(f) else 0.0


class AccountsRegistry:
    """Owner-signed account grants on the spine. Construction mirrors KillSwitch/PromotionPolicy: the owner
    signing key and trusted pubkey default to the persisted owner identity."""

    def __init__(self, store, *, owner_key=None, trusted_pubkey: Optional[str] = None):
        self.store = store
        self.owner_key = owner_key if owner_key is not None else owner_keypair()
        self.trusted_pubkey = trusted_pubkey if trusted_pubkey is not None else owner_pubkey()

    # -- owner mutations ---------------------------------------------------------------------------
    def create(self, username: str, role: str, *, bearer_token: str, issued_at: float,
               user_pubkey: Optional[str] = None, ttl_seconds: Optional[float] = None) -> int:
        """Owner-sign a new active account. The caller (the actions layer) generates the bearer token and
        never stores it in plaintext: only `sha256_hex(salt + bearer)` and the per-account salt are
        recorded. Requires the owner signing key (a grant with no owner signature never verifies in the
        fold, so it would be inert). `user_pubkey` optionally binds the S3 challenge/response login identity
        at creation (usually bound later via `enroll_pubkey`); it is validated fail-closed when present.
        `ttl_seconds` optionally bounds the token's lifetime: the absolute `expires_at = issued_at + ttl` is
        signed INTO the grant (tamper-evident) and enforced at read time; None ⇒ the token never expires."""
        if self.owner_key is None:
            raise ValueError("account creation requires the owner signing key")
        u, r = _check_username(username), _check_role(role)
        if not isinstance(bearer_token, str) or len(bearer_token) < 16:
            raise ValueError("bearer_token must be a >=16-char string")
        pk = _check_user_pubkey(user_pubkey) if user_pubkey else None
        expires_at = _derive_expires_at(float(issued_at), ttl_seconds)
        salt = secrets.token_hex(16)
        cred_hash = sha256_hex((salt + bearer_token).encode("utf-8"))
        return self._append_active(u, r, cred_hash=cred_hash, cred_salt=salt, issued_at=float(issued_at),
                                   user_pubkey=pk, expires_at=expires_at)

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
                                   issued_at=float(issued_at), user_pubkey=acct.user_pubkey,
                                   totp_secret=acct.totp_secret, password_hash=acct.password_hash,
                                   expires_at=acct.expires_at)

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
                                   issued_at=float(issued_at), user_pubkey=pk,
                                   totp_secret=acct.totp_secret, password_hash=acct.password_hash,
                                   expires_at=acct.expires_at)

    def enroll_totp(self, username: str, sealed_totp_b64: str, *, issued_at: float) -> int:
        """Owner-bind a SEALED TOTP secret to an existing active account — the S4 second factor. The caller
        (the actions layer) generates the plaintext secret, shows its provisioning URI once, and SEALS it
        via the owner vault BEFORE calling this, so only the sealed blob (base64) ever reaches the spine —
        the plaintext TOTP secret is NEVER stored (mirrors how `create` stores only a bearer HASH). This is
        the DANGEROUS direction (it ADDS a factor), so it is honored only if it verifies AND is FRESH
        (`issued_at` strictly exceeds the per-username high-water). Owner is the sole signer. Preserves the
        account's role + bearer credential + bound user_pubkey + password. Fail-closed on unknown/revoked."""
        if self.owner_key is None:
            raise ValueError("enroll_totp requires the owner signing key")
        u = _check_username(username)
        blob = str(sealed_totp_b64 or "").strip()
        if not blob:
            raise ValueError("enroll_totp requires a non-empty sealed TOTP secret")
        acct = self._fold().get(u)
        if acct is None:
            raise ValueError(f"no such active account {u!r} (create it first, or it was revoked)")
        return self._append_active(u, acct.role, cred_hash=acct.cred_hash, cred_salt=acct.cred_salt,
                                   issued_at=float(issued_at), user_pubkey=acct.user_pubkey,
                                   totp_secret=blob, password_hash=acct.password_hash,
                                   expires_at=acct.expires_at)

    def disable_totp(self, username: str, *, issued_at: float) -> int:
        """Remove the TOTP second factor from an active account — the SAFE direction (drops a factor). This
        is the documented RECOVERY path (issue W17-1) for an account whose authenticator was lost: the owner
        re-signs the grant KEEPING role + bearer + user_pubkey + password and CLEARING `totp_secret`, so the
        next fold sees no second factor (a clear grant omits the key entirely, byte-identical to a
        never-enrolled account's core). `issued_at` is bumped to STRICTLY exceed the per-username high-water
        (mirrors `mint_session_bearer`) so the clear is always honored — never silently dropped as a stale
        replay under a same-tick clock. Owner is the sole signer. Idempotent (re-disabling a TOTP-less
        account just re-writes it without the factor). Fail-closed on an unknown / revoked account."""
        if self.owner_key is None:
            raise ValueError("disable_totp requires the owner signing key")
        u = _check_username(username)
        acct = self._fold().get(u)
        if acct is None:
            raise ValueError(f"no such active account {u!r} (create it first, or it was revoked)")
        iat = max(float(issued_at), math.nextafter(acct.issued_at, math.inf))
        return self._append_active(u, acct.role, cred_hash=acct.cred_hash, cred_salt=acct.cred_salt,
                                   issued_at=iat, user_pubkey=acct.user_pubkey,
                                   totp_secret=None, password_hash=acct.password_hash,
                                   expires_at=acct.expires_at)

    def set_password(self, username: str, password: str, *, issued_at: float) -> int:
        """Owner-set a scrypt password hash for an existing active account — the S4 OPTIONAL weaker login.
        Hashes internally (salted scrypt); the plaintext password NEVER reaches the spine (only its one-way
        hash, mirroring the bearer). DANGEROUS direction (adds a login credential) → owner-signed + FRESH.
        Preserves role + bearer + user_pubkey + TOTP. Keypairs (S3) remain the STRONGER path — a password is
        a convenience for operators who cannot manage a key. Fail-closed on unknown/revoked."""
        if self.owner_key is None:
            raise ValueError("set_password requires the owner signing key")
        u = _check_username(username)
        ph = hash_password(str(password or ""))
        acct = self._fold().get(u)
        if acct is None:
            raise ValueError(f"no such active account {u!r} (create it first, or it was revoked)")
        return self._append_active(u, acct.role, cred_hash=acct.cred_hash, cred_salt=acct.cred_salt,
                                   issued_at=float(issued_at), user_pubkey=acct.user_pubkey,
                                   totp_secret=acct.totp_secret, password_hash=ph,
                                   expires_at=acct.expires_at)

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
                                  issued_at=iat, user_pubkey=acct.user_pubkey,
                                  totp_secret=acct.totp_secret, password_hash=acct.password_hash,
                                  expires_at=acct.expires_at)
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

    def revoke_all(self, *, exclude: "frozenset[str]" = frozenset()) -> "list[tuple[str, int]]":
        """Bulk-revoke every currently-active account (the SAFE direction, applied one-by-one via `revoke`).
        The owner is NEVER an `Account` (the fold carries no "owner" row — `OWNER_PRINCIPAL` is the legacy
        embedded token / a passkey session), so this structurally cannot lock the owner out. Idempotent and
        replay-safe: each `revoke` writes a FIXED `issued_at=0.0` and never bumps a high-water, so re-running
        it merely re-revokes. Returns [(username, recorded_seq), ...] in username order; `exclude` skips
        named usernames (e.g. a break-glass service account the owner wants to keep)."""
        out: "list[tuple[str, int]]" = []
        for username in sorted(self._fold()):
            if username in exclude:
                continue
            out.append((username, self.revoke(username)))
        return out

    def _append_active(self, username: str, role: str, *, cred_hash: str, cred_salt: str,
                       issued_at: float, user_pubkey: Optional[str] = None,
                       totp_secret: Optional[str] = None, password_hash: Optional[str] = None,
                       expires_at: Optional[float] = None) -> int:
        core = {"signal": SIGNAL, "username": username, "role": role, "cred_hash": cred_hash,
                "cred_salt": cred_salt, "state": "active", "issued_at": float(issued_at)}
        # CONDITIONALLY signed: each optional field is included ONLY when set, so a grant MISSING it
        # canonicalizes byte-identically to the encoding before that field existed (see `_core_fields`).
        # `signed_payload` signs exactly the dict it is given, and verification re-derives the same field
        # set from the payload — so sign and verify agree without an unconditional `"<field>":null`.
        if user_pubkey:
            core["user_pubkey"] = user_pubkey
        if totp_secret:
            core["totp_secret"] = totp_secret
        if password_hash:
            core["password_hash"] = password_hash
        if expires_at:
            core["expires_at"] = float(expires_at)   # ABSOLUTE deadline, inside the owner-signed core
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
        # W9-1: succession-aware owner-key resolver. An `active` grant is authenticated under the owner key
        # valid AT ITS SEQ (`resolver.at(r.seq)`), so a grant signed by a since-rotated key still verifies
        # (not orphaned) while a forged grant minted with a retired key at a later seq is refused. With no
        # rotation the resolver is a single open window over the current key -> byte-identical to before.
        resolver = _kh.key_resolver(self.store, current=self.trusted_pubkey)
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
                        # seed fields 5/6/7/8 = user_pubkey / totp_secret / password_hash / expires_at (each
                        # None for a legacy/shorter row) — carried so a KEYED / TOTP-enrolled / password /
                        # EXPIRING account pruned below base_seq keeps its PoP login, its second factor, its
                        # password, and its DEADLINE (else a pruned+seeded account silently never-expires).
                        user_pubkey=(str(row[4]) if len(row) > 4 and row[4] else None),
                        totp_secret=(str(row[5]) if len(row) > 5 and row[5] else None),
                        password_hash=(str(row[6]) if len(row) > 6 and row[6] else None),
                        expires_at=(_as_deadline(row[7]) if len(row) > 7 and row[7] else None))
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
                if not verify_signed(p, _core_fields(p), resolver.at(r.seq)):
                    continue                          # fail-closed: an unsigned/forged grant is not counted,
                    #                                   nor one signed by a key not valid at this grant's seq
                    #                                   (field set derived from the payload — see _core_fields)
                at = as_issued_at(p.get("issued_at"))
                if at <= issued.get(username, NO_HIGHWATER):
                    continue                          # REPLAY / stale re-append of an already-honored grant
                issued[username] = at                 # consume it so its own replay is refused hereafter
                state[username] = "active"
                upk = p.get("user_pubkey")
                tsec = p.get("totp_secret")
                phash = p.get("password_hash")
                exp = p.get("expires_at")
                accts[username] = Account(
                    username=str(username), role=str(p.get("role") or ""),
                    cred_hash=str(p.get("cred_hash") or ""), cred_salt=str(p.get("cred_salt") or ""),
                    issued_at=at, state="active",
                    user_pubkey=(str(upk) if upk else None),   # each carried through unchanged (None ⇒ absent):
                    totp_secret=(str(tsec) if tsec else None),  # the SEALED TOTP secret (S4 second factor)
                    password_hash=(str(phash) if phash else None),  # the scrypt password hash (S4 optional)
                    # ABSOLUTE deadline. It is in the signed core, so a tampered value fails verify above; and
                    # _as_deadline is fail-closed — a poisoned value (non-finite, a numeric STRING, a bool, any
                    # non-number) maps to 0.0 ⇒ always-expired ⇒ denied, never a live future deadline.
                    expires_at=(_as_deadline(exp) if exp else None))
        return {u: a for u, a in accts.items() if state.get(u) == "active"}

    def resolve(self, token: str, *, now: Optional[float] = None) -> Optional[Principal]:
        """Map a per-user bearer token to its Principal, or None (fail-closed). Constant-time per account:
        `hmac.compare_digest(sha256_hex(salt + token), cred_hash)`. First match (by username order) wins.
        Never resolves a revoked account (absent from the fold) NOR an EXPIRED one (its absolute `expires_at`
        has passed `now`) — expiry is a read-time filter here, never a durable state, so it can only
        SUBTRACT access. `now` defaults to the live clock. Folds ONCE per call."""
        if not isinstance(token, str) or not token:
            return None
        now = time.time() if now is None else now
        fold = self._fold()
        for username in sorted(fold):
            a = fold[username]
            if hmac.compare_digest(sha256_hex((a.cred_salt + token).encode("utf-8")), a.cred_hash):
                # A bearer is unique to one account (per-account salt + 32-byte secret), so a match is the
                # only match — an expired match is a hard None, not a fall-through to another account.
                return None if a.expired(now) else Principal(username=a.username, role=a.role)
        return None

    def account(self, username: str, *, now: Optional[float] = None) -> Optional[Account]:
        """The current active, NON-EXPIRED `Account` for `username` (carrying its bound `user_pubkey`), or
        None (fail-closed — a revoked/unknown/EXPIRED username is treated as absent). Folds ONCE. Used by the
        PoP / password login to look up the account before verifying — so an expired account cannot mint a
        fresh session bearer via `mint_session_bearer` (the login-bypass guard). `now` defaults to the live
        clock."""
        if not isinstance(username, str) or not username:
            return None
        now = time.time() if now is None else now
        acct = self._fold().get(username)
        if acct is None or acct.expired(now):
            return None
        return acct

    def accounts(self) -> list[Account]:
        """The current active fold (for the owner's Users & Roles list) — INCLUDING expired-but-active
        accounts, each carrying its `expires_at`, so the UI can show an "expired"/"expires soon" pill and
        the owner can revoke it. The cred_hash/cred_salt live on the Account object but the HTTP layer never
        surfaces them — only username/role/state/issued_at + expires_at/remaining/expired."""
        fold = self._fold()
        return [fold[u] for u in sorted(fold)]
