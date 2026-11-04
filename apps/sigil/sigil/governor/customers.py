"""Program Slice E1 — the CUSTOMER identity namespace (owner-signed, LWW), DISJOINT from operator accounts.

A self-serve CUSTOMER is NOT an operator teammate. This module is a structural TWIN of
`governor/accounts.py` under a DIFFERENT signal (`governor.customer`), so a customer identity and an
operator `governor.account` can never resolve into each other's fold: a customer bearer returns None from
`AccountsRegistry.resolve`/`server._principal`, and an operator bearer returns None here. That disjoint-
signal separation is the structural guard the design-pass isolation critic required (E2/mint-reuse
findings) — a customer is NEVER a `governor.account` row and therefore never carries a global role.

A `CustomerAccount` carries a bound, UNIQUE `email` (operator accounts have none) and NO role. A
customer's capability is ONLY its owner-signed per-org membership (`governor/orgs.py`), gated via the
no-global-leg `OrgRegistry.admit_customer`; `CustomerPrincipal.global_role` is structurally None.

Trust construction MIRRORS `accounts.py` EXACTLY (do not diverge — the anti-replay invariant is shared):
  * create / set_password = the DANGEROUS direction → honored only if OWNER-SIGNED (`verify_signed`) AND
    `issued_at` STRICTLY exceeds the per-username high-water;
  * revoke = the SAFE direction → `state="revoked"` honored even UNSIGNED, fixed `issued_at` of 0.0;
  * per-username LWW high-water closes the replay-resurrection HIGH (a captured owner-signed `active`
    grant cannot resurrect a revoked customer);
  * owner-key succession-aware verify (`key_history.key_resolver(...).at(seq)`);
  * HARD-PRUNE SEED from `SnapshotState` (customer_state/customer_issued/customer_cred), folded by the ONE
    `_fold()` both read paths call, with `spine.prune.stranded_active_customers` the fail-closed tripwire
    that refuses a prune stranding an active customer's only grant.

The customer `username` is a SERVER-GENERATED stable id (`cust_…`) — an email can't be a username
(`@` is outside the id charset), and the email is a separate unique attribute. Email uniqueness is
enforced at provision time (`by_email` check) over this fold.

FATAL-2: sovereign-side (`assert_no_offense` at import); crypto is the sovereign `reuse`/`vigil_core`
primitives + the account module's own scrypt helpers (same plane). No framework/strix.
"""
from __future__ import annotations

import math
import re
import secrets
from dataclasses import dataclass
from typing import Optional

from ..reuse import assert_no_offense

assert_no_offense()

# Reuse the account module's scrypt KDF + the constant-time decoy VERBATIM (same sovereign plane) — the
# password hashing must be byte-identical to operators' so there is ONE KDF of record, and the decoy
# gives customer login the same user-enumeration-timing defense.
from .accounts import DECOY_PASSWORD_HASH, hash_password, verify_password  # noqa: E402,F401
from ..spine.snapshot import SnapshotState  # noqa: E402
from . import key_history as _kh  # noqa: E402  (succession-aware owner-key resolver, mirrors accounts._fold)
from .authn import NO_HIGHWATER, as_issued_at, signed_payload, verify_signed  # noqa: E402
from .identity import owner_keypair, owner_pubkey  # noqa: E402

SIGNAL = "governor.customer"

# The SERVER-GENERATED customer id charset — identical to accounts._USERNAME_RE so the two id spaces share
# a validator shape, but a customer id is minted here (never chosen by the client) with a `cust_` prefix.
_USERNAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
_USERNAME_PREFIX = "cust_"

# A conservative email shape. This is NOT an RFC-5322 parser and proves nothing about deliverability — the
# mailbox-control PROOF is the single-use verification token (ui/email_channel.py), never this regex. It
# exists only to reject control chars / obvious garbage and bound the length fail-closed at binding time.
_EMAIL_MAX = 254
_EMAIL_RE = re.compile(r"^[^@\s]{1,64}@[A-Za-z0-9.-]{1,255}\.[A-Za-z]{2,24}$")

# The owner-signed authenticated CORE. `issued_at` is inside it (else a captured grant's freshness could
# be re-stamped past the high-water without breaking the signature — the replay this guard refuses);
# `username`/`email` are inside it so an owner-signed grant can never be re-aimed at another id/mailbox.
_BASE_CORE = ("signal", "username", "email", "state", "issued_at")


def _core_fields(payload: dict) -> "tuple[str, ...]":
    """The signed core field set for a customer grant — CONDITIONAL on the payload: the 5 base fields
    ALWAYS, plus `password_hash` IFF the grant carries one (an OIDC-only customer — Slice E2 — has none).
    Mirrors `accounts._core_fields`: a grant missing the optional field canonicalizes byte-identically to
    the encoding before that field existed, so an existing owner signature still verifies and the
    malleability inverse stays closed (stripping/adding the field flips the verified set and fails)."""
    fields: "tuple[str, ...]" = _BASE_CORE
    if payload.get("password_hash"):
        fields += ("password_hash",)
    return fields


def _check_username(username: str) -> str:
    u = str(username or "").strip()
    if not _USERNAME_RE.match(u):
        raise ValueError("customer username must be 1-64 chars of [A-Za-z0-9._-], alphanumeric start")
    return u


def _normalize_email(email: str) -> str:
    """Lowercase + strip. Returns "" for a non-str / empty value (the caller treats "" as invalid)."""
    return str(email or "").strip().lower()


def _check_email(email: str) -> str:
    e = _normalize_email(email)
    if not e or len(e) > _EMAIL_MAX or not _EMAIL_RE.match(e):
        raise ValueError("email must be a valid, <=254-char address (local@domain.tld)")
    return e


def new_customer_username() -> str:
    """A fresh, server-generated stable customer id. The client NEVER chooses it (an email is not a valid
    username — `@` is outside the charset — and a client-chosen id would be a tenancy/collision hazard)."""
    return _USERNAME_PREFIX + secrets.token_urlsafe(18)


@dataclass(frozen=True)
class CustomerAccount:
    username: str                       # server-generated stable id (cust_…)
    email: str                          # bound, unique (normalized lowercase) login key
    issued_at: float                    # owner-set anti-replay high-water
    state: str                          # "active" | "revoked"
    password_hash: Optional[str] = None  # salted-scrypt (email/password login); None ⇒ OIDC/passkey-only (E2/E3)


@dataclass(frozen=True)
class CustomerPrincipal:
    """The per-request customer identity. `org_id` is the session-bound ACTIVE org (server-side, never a
    client field). `global_role` is STRUCTURALLY None — a customer has no global role, so every customer
    op must gate via `OrgRegistry.admit_customer` (no global leg), never the operator `admit`."""
    username: str
    org_id: Optional[str] = None

    @property
    def global_role(self) -> None:
        """Always None — a customer never carries a global role (capability is per-org membership only)."""
        return None


class CustomerRegistry:
    """Owner-signed customer identity grants on the spine, under `governor.customer`. Construction mirrors
    `AccountsRegistry`: the owner signing key + trusted pubkey default to the persisted owner identity."""

    def __init__(self, store, *, owner_key=None, trusted_pubkey: Optional[str] = None):
        self.store = store
        self.owner_key = owner_key if owner_key is not None else owner_keypair()
        self.trusted_pubkey = trusted_pubkey if trusted_pubkey is not None else owner_pubkey()

    # -- owner mutations ---------------------------------------------------------------------------
    def create(self, email: str, *, issued_at: float, password: Optional[str] = None,
               username: Optional[str] = None) -> "tuple[str, int]":
        """Owner-sign a new active customer identity, returning (username, recorded_seq). The username is
        SERVER-GENERATED (`new_customer_username`) unless the caller supplies one (also server-side, e.g.
        the provisioner reusing a pending id) — never a client value. `password` (optional) is hashed via
        the account module's scrypt; the plaintext NEVER reaches the spine (only the one-way hash). An
        OIDC/passkey-only customer (Slice E2/E3) is created with `password=None`. Requires the owner key
        (an unsigned grant never verifies in the fold → inert). Email uniqueness is the PROVISIONER's
        responsibility (`by_email` check before create); this mint does not itself scan for a dup."""
        if self.owner_key is None:
            raise ValueError("customer creation requires the owner signing key")
        e = _check_email(email)
        u = _check_username(username) if username else new_customer_username()
        ph = hash_password(password) if password is not None else None
        return u, self._append_active(u, e, issued_at=float(issued_at), password_hash=ph)

    def set_password(self, username: str, password: str, *, issued_at: float) -> int:
        """Owner-set a new scrypt password hash for an existing active customer (the recovery / set-password
        path). DANGEROUS direction → owner-signed + FRESH. Preserves the email. `issued_at` is bumped to
        STRICTLY exceed the per-username high-water (mirrors `accounts.mint_session_bearer`) so the change
        is always honored, never silently dropped as a same-tick replay. Fail-closed on unknown/revoked."""
        if self.owner_key is None:
            raise ValueError("set_password requires the owner signing key")
        u = _check_username(username)
        acct = self._fold().get(u)
        if acct is None:
            raise ValueError(f"no such active customer {u!r} (create it first, or it was revoked)")
        ph = hash_password(str(password or ""))
        iat = max(float(issued_at), math.nextafter(acct.issued_at, math.inf))
        return self._append_active(u, acct.email, issued_at=iat, password_hash=ph)

    def revoke(self, username: str) -> int:
        """Revoke a customer identity — the SAFE direction. Owner-signed for provenance, but honored
        regardless of signature (a forged/nuisance revoke is at worst a fail-safe DoS on that customer),
        with a FIXED `issued_at` of 0.0 (a replayed revoke merely re-revokes)."""
        u = _check_username(username)
        core = {"signal": SIGNAL, "username": u, "email": "", "state": "revoked", "issued_at": 0.0}
        payload = {**signed_payload(core, self.owner_key), "by": "owner", "requested_by": "owner",
                   "tier": "A0", "decision": "auto", "reason": f"customer {u} REVOKED (governed latch)"}
        return self.store.append(kind="event", source="governor", actor="WARDEN", payload=payload)

    def _append_active(self, username: str, email: str, *, issued_at: float,
                       password_hash: Optional[str] = None) -> int:
        core = {"signal": SIGNAL, "username": username, "email": email, "state": "active",
                "issued_at": float(issued_at)}
        if password_hash:                      # CONDITIONAL — omitted when absent (see `_core_fields`)
            core["password_hash"] = password_hash
        payload = {**signed_payload(core, self.owner_key), "by": "owner", "requested_by": "owner",
                   "tier": "A0", "decision": "auto",
                   "reason": f"customer {username} ({email}) active (owner-signed grant)"}
        return self.store.append(kind="event", source="governor", actor="WARDEN", payload=payload)

    # -- reads (both go through the ONE fold — mirrors AccountsRegistry._fold) -----------------------
    def _fold(self) -> dict[str, CustomerAccount]:
        """THE fold — called by every read path, so the per-username anti-replay high-water is applied
        identically everywhere. Returns {username: CustomerAccount} for customers whose latest state is
        active. HARD-PRUNE SEED from `SnapshotState` (customer_state/customer_issued/customer_cred), then
        fold forward over the LIVE window only — so a customer whose only grant was pruned SURVIVES and its
        high-water is NOT reset. Pubkey-DEPENDENT bypass (rotated key / empty identity) is byte-identical
        to a full genesis scan, exactly as `accounts._fold`."""
        snap = SnapshotState.load(self.store)
        resolver = _kh.key_resolver(self.store, current=self.trusted_pubkey)
        if self.trusted_pubkey != snap.trusted_pubkey:
            state, custs, issued, since = {}, {}, {}, -1
        else:
            state = dict(snap.customer_state_map())       # username -> "active"|"revoked" (LWW; keep revoked)
            issued = dict(snap.customer_issued_map())     # username -> per-username high-water
            custs = {row[0]: CustomerAccount(             # rebuild honored-active CustomerAccounts from the seed
                        username=str(row[0]), email=str(row[1] or ""),
                        issued_at=issued.get(row[0], 0.0), state="active",
                        password_hash=(str(row[2]) if len(row) > 2 and row[2] else None))
                     for row in snap.customer_cred}
            since = snap.base_seq - 1
        for r in self.store.iter_records(since_seq=since):
            p = r.payload
            if not isinstance(p, dict) or p.get("signal") != SIGNAL:
                continue
            username = p.get("username")
            rec_state = p.get("state")
            if rec_state == "revoked":
                state[username] = "revoked"              # honor ANY revoke (even unsigned) — safe direction
            elif rec_state == "active":
                if not verify_signed(p, _core_fields(p), resolver.at(r.seq)):
                    continue                             # fail-closed: unsigned/forged/wrong-epoch-key grant
                at = as_issued_at(p.get("issued_at"))
                if at <= issued.get(username, NO_HIGHWATER):
                    continue                             # REPLAY / stale re-append of an already-honored grant
                issued[username] = at
                state[username] = "active"
                phash = p.get("password_hash")
                custs[username] = CustomerAccount(
                    username=str(username), email=str(p.get("email") or ""), issued_at=at, state="active",
                    password_hash=(str(phash) if phash else None))
        return {u: c for u, c in custs.items() if state.get(u) == "active"}

    def customer(self, username: str) -> Optional[CustomerAccount]:
        """The current active `CustomerAccount` for `username`, or None (fail-closed — revoked/unknown
        treated as absent). Folds ONCE."""
        if not isinstance(username, str) or not username:
            return None
        return self._fold().get(username)

    def by_email(self, email: str) -> Optional[CustomerAccount]:
        """The current active customer bound to `email` (normalized), or None. Used by the provisioner for
        the uniqueness check and by `verify_login`. Deterministic (username order) if more than one somehow
        shares an email — though the provisioner's pre-create `by_email` check keeps email unique."""
        e = _normalize_email(email)
        if not e:
            return None
        fold = self._fold()
        for u in sorted(fold):
            if fold[u].email == e:
                return fold[u]
        return None

    def customers(self) -> list[CustomerAccount]:
        """The current active customer fold, in username order (the owner's customer list; the HTTP layer
        never surfaces the password_hash)."""
        fold = self._fold()
        return [fold[u] for u in sorted(fold)]

    def verify_login(self, email: str, password: str) -> Optional[CustomerAccount]:
        """Verify an email+password login, returning the `CustomerAccount` on a match, else None. CONSTANT-
        time w.r.t. existence: an unknown email / passwordless customer still pays exactly ONE scrypt against
        `DECOY_PASSWORD_HASH` and returns None, so the endpoint's timing never reveals whether the email
        exists (mirrors the operator `_login_password` decoy). A match requires a real, enrolled password."""
        acct = self.by_email(email)
        stored = acct.password_hash if (acct is not None and acct.password_hash) else DECOY_PASSWORD_HASH
        ok = verify_password(str(password or ""), stored)
        if ok and acct is not None and acct.password_hash:
            return acct
        return None
