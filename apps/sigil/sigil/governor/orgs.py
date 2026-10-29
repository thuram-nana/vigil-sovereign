"""Enterprise TENANCY/IDENTITY — owner-signed ORG/WORKSPACE entities + per-org memberships (slice 1).

This is the greenfield org/workspace layer built DIRECTLY on the existing owner-signed accounts model
(`governor/accounts.py`). It mirrors that module's trust construction EXACTLY and reuses the ONE shared role
vocabulary (`vigil_core.rbac`) — it invents no new roles and holds no new key custody.

WHAT THIS SLICE IS:
  * an Org/Workspace entity (`org_id`, `name`, `owner`, `created_at`, `state`);
  * a Membership = (`org_id`, `username`, `role`) where `role` is a `vigil_core.rbac` role SCOPED PER-ORG —
    a user may be `analyst` in org A and have NO role in org B (default-deny everywhere else);
  * org creation + membership grant/revoke as OWNER-SIGNED spine grants (owner Ed25519 signature,
    per-record LWW anti-replay high-water, fail-closed verify) — a grant with no valid owner signature is
    REFUSED (inert in the fold);
  * the authoritative org -> tenant_id mapping (`org_tenant_id`) that derives/validates a `CRUCIBLE_TENANT`
    value satisfying the engine's `_TENANT_RE`, so `org == tenant_id` (the contract the KB + ticketing
    enterprise waves key on);
  * the per-org admission primitive (`OrgRegistry.org_role_can`) the UI/proxy auth boundary will later call.

SINGLE-OWNER DOCTRINE (unchanged — this is NOT a second key custody): VIGIL stays SINGLE-OWNER-KEY at the
trust root. Exactly as in `accounts.py`, the owner Ed25519 key is the SOLE signer of every org/membership
mutation; a non-owner principal never holds a key. "org P grants user U role R" is the existing
killswitch/capability/promotion/account owner-signed governance-record idiom aimed at a new signal — no new
trust primitive. Consequently "owner" is NOT a grantable per-org membership role (just as it is not a
grantable account role): per-org roles are drawn from `viewer < analyst < operator` only. See the DESIGN
TENSIONS note below for how a true per-org "org-admin" would be introduced in a later slice.

ASYMMETRIC AUTHENTICATION (mirrors accounts / killswitch / capability / promotion):
  * create_org / grant_membership = the DANGEROUS direction -> honored only if OWNER-SIGNED (`verify_signed`)
    AND its `issued_at` STRICTLY exceeds the per-record high-water.
  * revoke_org / revoke_membership = the SAFE direction -> `state="revoked"` is honored even UNSIGNED, with a
    FIXED `issued_at` of 0.0 (a replayed revoke merely re-revokes). Gating the fail-safe direction would make
    it fail OPEN.

ANTI-REPLAY (per-record LWW high-water — the same resurrection guard `accounts.py` carries): a revoked org or
membership cannot be resurrected by re-appending a captured owner-signed `active` grant, because that grant's
`issued_at <= high-water` -> it is ignored. The high-water is keyed PER-ORG for orgs and PER-(org_id,
username) for memberships, so the LWW state of org A's membership for `alice` is fully independent of org B's.

OWNER-KEY SUCCESSION: the fold authenticates each `active` grant under the owner pubkey valid AT ITS SEQ
(`key_history.key_resolver(...).at(seq)`), identical to `accounts._fold`. With no rotation this is a single
open window over `trusted_pubkey` — byte-identical to a plain `verify_signed(p, core, trusted_pubkey)`. So an
org grant signed before an owner-key rotation keeps verifying, and a forged grant minted with a retired key at
a later seq is refused.

FATAL-2: this module is SOVEREIGN-side and imports NO `framework`/`strix` (guarded by `assert_no_offense` at
import). The only shared substrate it reuses is `vigil_core.rbac` (the role vocabulary) + the sovereign
`reuse`/`authn`/`identity`/`key_history` crypto primitives. The engine's `_TENANT_RE` is REPLICATED here
(not imported — importing `engine/crucible/framework/...` would breach FATAL-2) and a test keeps the two
literals in lockstep.

DEFERRED (explicitly OUT of this slice):
  * HARD-PRUNE SEED: unlike `accounts._fold`, this fold does a full genesis scan and does NOT seed from
    `spine.snapshot.SnapshotState` (which carries no org rows yet). This is byte-identical to how `accounts`
    behaved BEFORE its snapshot slice (Claim 6 shipped first; the seed was a later slice). A hard prune below
    an org's first grant would therefore currently strand it — closing that needs org rows added to the
    snapshot leaf module + a `spine.prune` safety check, a self-contained follow-up slice.
  * SSO / SCIM: NOT built here, and in direct TENSION with the core invariant "a role is NEVER taken from an
    IdP claim; an identity with no owner-signed account is REFUSED". SCIM auto-provisioning would mint
    memberships/accounts from IdP group claims WITHOUT an owner signature — exactly what this fold refuses.
    A later slice must resolve it by having the owner (or an owner-signed delegation) SIGN each provisioned
    membership, never by trusting an IdP assertion as authority. Admit-by-INVITE only: an owner adds members;
    there is no self-service signup path here (the open self-serve portal is a refused safety line).
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional, Union

from ..reuse import assert_no_offense

assert_no_offense()

# ONE source of truth for the role vocabulary (`viewer < analyst < operator < owner`, cumulative permission
# sets, `role_can`), shared by both trust domains. We reuse it verbatim and scope it PER-ORG — we do NOT
# define a new vocabulary. vigil_core imports no framework/strix/sigil, so this crosses no offense boundary.
from vigil_core.rbac import ROLES, role_can  # noqa: E402

from . import key_history as _kh  # noqa: E402  (succession-aware owner-key resolver, mirrors accounts._fold)
from .authn import NO_HIGHWATER, as_issued_at, signed_payload, verify_signed  # noqa: E402
from .identity import owner_keypair, owner_pubkey  # noqa: E402

# Dedicated payload signals under the generic enforced `kind="event"` record (mirrors accounts' SIGNAL),
# so a NEW kind need not be registered with the W5-1 write-path guard — the signal disambiguates the fold.
ORG_SIGNAL = "governor.org"
MEMBERSHIP_SIGNAL = "governor.org_membership"

# "owner" is the trust-root key-holder, never a grantable per-org bearer role (single-owner doctrine), so the
# assignable per-org roles are exactly viewer / analyst / operator — IDENTICAL to accounts._ASSIGNABLE_ROLES,
# derived from the SAME shared ROLES ordering so the two can never drift.
_ASSIGNABLE_ROLES = frozenset(ROLES[:-1])   # viewer / analyst / operator — never "owner"

# A username charset IDENTICAL to accounts._USERNAME_RE (1-64 chars of [A-Za-z0-9._-], alphanumeric start).
# Replicated here (not imported) so this module stays independently importable; a lockstep test asserts the
# two literals match. A member username of "owner" is refused (the trust-root principal is not an org member).
_USERNAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")

# The org "owner" attribution field uses the SAME charset but DOES allow the literal "owner" (the trust-root
# owner commonly owns the workspace). It is attribution only — it grants nothing on its own.
_OWNER_FIELD_RE = _USERNAME_RE

# A human-readable workspace label. Bounded; must be a non-control, non-empty string. Not a path / id, so the
# charset is permissive — the SECURITY-bearing identifier is org_id (validated against _TENANT_RE below).
_MAX_ORG_NAME = 200

# CRITICAL CONTRACT — this MUST stay byte-identical to `engine/crucible/framework/v2/common/paths.py`:
#   _TENANT_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}")   (matched with .fullmatch)
# It CANNOT be imported (that module is offense/framework-side; importing it would breach FATAL-2), so it is
# replicated verbatim and `test_orgs.py::test_tenant_re_matches_engine_paths_literal` reads both source files
# and asserts the two pattern strings are identical (mirror-drift guard). A tenant id is ONE path component
# (alphanumeric start then [A-Za-z0-9._-], max 64) — forbidding separators / `.`/`..` traversal / absolute
# paths / NUL by construction, so an org can never map to a tenant shard that escapes its parent.
_TENANT_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}")

# The owner-signed authenticated CORE of each grant. `issued_at` MUST be inside it (else an attacker could
# re-stamp a captured grant's freshness past the high-water without breaking the signature — the replay this
# guard refuses). For orgs, `name`/`owner` are inside it so an owner-signed org grant cannot be re-labelled or
# re-owned. For memberships, `org_id`/`username`/`role` are inside it so a grant for (orgA, alice, analyst)
# can never be re-aimed at another org/user or have its role rewritten.
_ORG_CORE = ("signal", "org_id", "name", "owner", "state", "issued_at")
_MEMBERSHIP_CORE = ("signal", "org_id", "username", "role", "state", "issued_at")


# ---------------------------------------------------------------------------------------------------
# Validation (fail-closed at BINDING time — a clean ValueError now, never a silent bad grant later).
# ---------------------------------------------------------------------------------------------------

def _check_org_id(org_id: str) -> str:
    """Validate an org_id. It MUST satisfy `_TENANT_RE` (fullmatch) because `org == tenant_id`: the org_id is
    the authoritative `CRUCIBLE_TENANT` value, so a org_id that could not be a safe single-path-component
    tenant id is refused at creation (fail-closed) rather than producing an unmappable org later."""
    oid = str(org_id or "").strip()
    if not _TENANT_RE.fullmatch(oid):
        raise ValueError("org_id must be a valid tenant id: an alphanumeric start then [A-Za-z0-9._-], "
                         "max 64 chars, no separators / traversal (org_id == CRUCIBLE_TENANT)")
    return oid


def _check_org_name(name: str) -> str:
    n = str(name or "").strip()
    if not n or len(n) > _MAX_ORG_NAME:
        raise ValueError(f"org name must be a non-empty string of <= {_MAX_ORG_NAME} chars")
    if any(ord(c) < 0x20 or ord(c) == 0x7f for c in n):
        raise ValueError("org name must not contain control characters")
    return n


def _check_owner(owner: str) -> str:
    o = str(owner or "").strip()
    if not _OWNER_FIELD_RE.match(o):
        raise ValueError("org owner must be 1-64 chars of [A-Za-z0-9._-] and start alphanumeric")
    return o


def _check_member_username(username: str) -> str:
    u = str(username or "").strip()
    if not _USERNAME_RE.match(u):
        raise ValueError("username must be 1-64 chars of [A-Za-z0-9._-] and start alphanumeric")
    if u == "owner":
        raise ValueError("'owner' is the reserved trust-root principal — it is not an org member")
    return u


def _check_member_role(role: str) -> str:
    r = str(role or "").strip()
    if r not in _ASSIGNABLE_ROLES:
        raise ValueError(f"per-org role must be one of {sorted(_ASSIGNABLE_ROLES)} — 'owner' is not "
                         f"grantable (single-owner-key doctrine)")
    return r


# ---------------------------------------------------------------------------------------------------
# Entities
# ---------------------------------------------------------------------------------------------------

@dataclass(frozen=True)
class Org:
    org_id: str          # == the CRUCIBLE_TENANT id (satisfies _TENANT_RE)
    name: str            # human workspace label
    owner: str           # attribution: the principal the workspace belongs to
    created_at: float    # issued_at of the owner-signed create grant (this slice has no rename, so stable)
    state: str           # "active" | "revoked"


@dataclass(frozen=True)
class Membership:
    org_id: str
    username: str
    role: str            # one of _ASSIGNABLE_ROLES (viewer/analyst/operator) — never "owner"
    issued_at: float     # owner-set anti-replay high-water for this (org_id, username)
    state: str           # "active" | "revoked"


# ---------------------------------------------------------------------------------------------------
# org -> tenant_id mapping (the authoritative contract: org == tenant_id).
# ---------------------------------------------------------------------------------------------------

def _derive_tenant_id(org_id: str) -> str:
    """Derive + validate the `CRUCIBLE_TENANT` id for an org_id, FAIL-CLOSED. The mapping is identity
    (tenant_id == org_id) so `active_tenant()` reads back exactly the org that owns the shard — but it is
    RE-VALIDATED against `_TENANT_RE.fullmatch` here (defence in depth: an `Org` may be reconstructed from a
    replayed/corrupt grant or built directly), and an org_id that cannot be a safe single path component
    raises rather than yielding a shard path that could escape its parent."""
    oid = str(org_id or "").strip()
    if not _TENANT_RE.fullmatch(oid):
        raise ValueError(f"org_id {org_id!r} does not map to a valid CRUCIBLE_TENANT id "
                         f"(allowed: an alphanumeric start then [A-Za-z0-9._-], max 64 chars, no "
                         f"separators / traversal) — fail-closed")
    return oid


def org_tenant_id(org: "Union[Org, str]") -> str:
    """The authoritative `CRUCIBLE_TENANT` value for an `Org` (or a raw org_id string). `org == tenant_id`:
    the KB + ticketing enterprise waves set `CRUCIBLE_TENANT = org_tenant_id(org)` and key `(tenant_id, slug)`
    on the value `active_tenant()` reads back. Fail-closed (raises ValueError) on an org_id that cannot
    produce a valid tenant id."""
    org_id = org.org_id if isinstance(org, Org) else org
    return _derive_tenant_id(org_id)


# ---------------------------------------------------------------------------------------------------
# The registry — owner-signed org + membership grants on the spine. Construction mirrors AccountsRegistry
# (and KillSwitch/PromotionPolicy): the owner signing key and trusted pubkey default to the persisted owner
# identity, and tests inject explicit keypairs.
# ---------------------------------------------------------------------------------------------------

class OrgRegistry:
    def __init__(self, store, *, owner_key=None, trusted_pubkey: Optional[str] = None):
        self.store = store
        self.owner_key = owner_key if owner_key is not None else owner_keypair()
        self.trusted_pubkey = trusted_pubkey if trusted_pubkey is not None else owner_pubkey()

    # -- owner mutations: orgs ----------------------------------------------------------------------
    def create_org(self, org_id: str, name: str, *, owner: str, issued_at: float) -> int:
        """Owner-sign a new active org/workspace — the DANGEROUS direction, honored only if it verifies AND is
        FRESH (`issued_at` strictly exceeds the per-org high-water). Requires the owner signing key (a grant
        with no owner signature never verifies in the fold, so it would be inert). `org_id` is validated as a
        tenant id (org == tenant_id). Legitimately re-activating a revoked org_id is a FRESH create with a
        strictly-greater issued_at (mirrors accounts)."""
        if self.owner_key is None:
            raise ValueError("org creation requires the owner signing key")
        oid, nm, ow = _check_org_id(org_id), _check_org_name(name), _check_owner(owner)
        return self._append_active_org(oid, nm, ow, issued_at=float(issued_at))

    def revoke_org(self, org_id: str) -> int:
        """Revoke an org — the SAFE direction. Owner-signed for provenance/audit, but takes effect regardless
        of the signature (a forged/nuisance revoke is at worst a fail-safe DoS on that org), and carries a
        FIXED `issued_at` of 0.0 (a replayed revoke merely re-revokes). A revoked org admits NO members: its
        memberships become inert at the admission primitive (see `org_role_can`)."""
        oid = _check_org_id(org_id)
        core = {"signal": ORG_SIGNAL, "org_id": oid, "name": "", "owner": "",
                "state": "revoked", "issued_at": 0.0}
        payload = {**signed_payload(core, self.owner_key), "by": "owner", "requested_by": "owner",
                   "tier": "A0", "decision": "auto", "reason": f"org {oid} REVOKED (governed latch)"}
        return self.store.append(kind="event", source="governor", actor="WARDEN", payload=payload)

    # -- owner mutations: memberships ---------------------------------------------------------------
    def grant_membership(self, org_id: str, username: str, role: str, *, issued_at: float) -> int:
        """Owner-sign a per-org role grant for `username` in `org_id` — the DANGEROUS direction, honored only
        if it verifies AND is FRESH (`issued_at` strictly exceeds the per-(org_id, username) high-water). The
        org MUST exist and be active (fail-closed on an unknown/revoked org — you cannot seat a member in a
        workspace that does not exist). The role is drawn from the shared vocabulary and scoped to THIS org
        only. Re-granting simply re-signs with the new role + a fresh issued_at (the LWW winner)."""
        if self.owner_key is None:
            raise ValueError("membership grant requires the owner signing key")
        oid = _check_org_id(org_id)
        u = _check_member_username(username)
        r = _check_member_role(role)
        if oid not in self._fold_orgs():
            raise ValueError(f"no such active org {oid!r} (create it first, or it was revoked)")
        return self._append_active_membership(oid, u, r, issued_at=float(issued_at))

    def revoke_membership(self, org_id: str, username: str) -> int:
        """Revoke a user's membership in an org — the SAFE direction (honored even unsigned, fixed
        `issued_at` of 0.0). Idempotent and replay-safe: a replayed revoke merely re-revokes. Does NOT require
        the org to still exist (revoking a membership in an already-revoked org is a harmless no-op)."""
        oid = _check_org_id(org_id)
        u = _check_member_username(username)
        core = {"signal": MEMBERSHIP_SIGNAL, "org_id": oid, "username": u, "role": "",
                "state": "revoked", "issued_at": 0.0}
        payload = {**signed_payload(core, self.owner_key), "by": "owner", "requested_by": "owner",
                   "tier": "A0", "decision": "auto",
                   "reason": f"membership {u}@{oid} REVOKED (governed latch)"}
        return self.store.append(kind="event", source="governor", actor="WARDEN", payload=payload)

    # -- append helpers (owner-signed active grants) ------------------------------------------------
    def _append_active_org(self, org_id: str, name: str, owner: str, *, issued_at: float) -> int:
        core = {"signal": ORG_SIGNAL, "org_id": org_id, "name": name, "owner": owner,
                "state": "active", "issued_at": float(issued_at)}
        payload = {**signed_payload(core, self.owner_key), "by": "owner", "requested_by": "owner",
                   "tier": "A0", "decision": "auto",
                   "reason": f"org {org_id} ({name!r}) created (owner-signed grant)"}
        return self.store.append(kind="event", source="governor", actor="WARDEN", payload=payload)

    def _append_active_membership(self, org_id: str, username: str, role: str, *, issued_at: float) -> int:
        core = {"signal": MEMBERSHIP_SIGNAL, "org_id": org_id, "username": username, "role": role,
                "state": "active", "issued_at": float(issued_at)}
        payload = {**signed_payload(core, self.owner_key), "by": "owner", "requested_by": "owner",
                   "tier": "A0", "decision": "auto",
                   "reason": f"membership {username}@{org_id} -> {role} (owner-signed grant)"}
        return self.store.append(kind="event", source="governor", actor="WARDEN", payload=payload)

    # -- reads (owner-key-succession-aware folds; full genesis scan — see DEFERRED hard-prune note) --
    def _fold_orgs(self) -> dict[str, Org]:
        """Fold the spine into {org_id: Org} for orgs whose latest state is active. Each `active` grant is
        authenticated under the owner pubkey valid AT ITS SEQ (`resolver.at`), and the per-org high-water
        refuses any stale/replayed re-append (the resurrection guard). Mirrors `accounts._fold` minus the
        snapshot seed (deferred)."""
        resolver = _kh.key_resolver(self.store, current=self.trusted_pubkey)
        state: dict[str, str] = {}
        issued: dict[str, float] = {}
        orgs: dict[str, Org] = {}
        for r in self.store.iter_records():
            p = r.payload
            if not isinstance(p, dict) or p.get("signal") != ORG_SIGNAL:
                continue
            org_id = p.get("org_id")
            if not isinstance(org_id, str) or not org_id:
                continue
            rec_state = p.get("state")
            if rec_state == "revoked":
                state[org_id] = "revoked"                 # honor ANY revoke (even unsigned) — safe direction
            elif rec_state == "active":
                if not verify_signed(p, _ORG_CORE, resolver.at(r.seq)):
                    continue                              # fail-closed: unsigned/forged/ wrong-epoch-key grant
                at = as_issued_at(p.get("issued_at"))
                if at <= issued.get(org_id, NO_HIGHWATER):
                    continue                              # REPLAY / stale re-append of an already-honored grant
                issued[org_id] = at                       # consume it so its own replay is refused hereafter
                state[org_id] = "active"
                orgs[org_id] = Org(org_id=org_id, name=str(p.get("name") or ""),
                                   owner=str(p.get("owner") or ""), created_at=at, state="active")
        return {o: org for o, org in orgs.items() if state.get(o) == "active"}

    def _fold_memberships(self) -> dict[tuple, Membership]:
        """Fold the spine into {(org_id, username): Membership} for memberships whose latest state is active.
        The LWW state + anti-replay high-water are keyed PER-(org_id, username), so `alice`'s membership in
        org A is fully independent of her (non-)membership in org B. Owner-key-succession-aware + fail-closed
        exactly like `_fold_orgs`."""
        resolver = _kh.key_resolver(self.store, current=self.trusted_pubkey)
        state: dict[tuple, str] = {}
        issued: dict[tuple, float] = {}
        mems: dict[tuple, Membership] = {}
        for r in self.store.iter_records():
            p = r.payload
            if not isinstance(p, dict) or p.get("signal") != MEMBERSHIP_SIGNAL:
                continue
            org_id = p.get("org_id")
            username = p.get("username")
            if not isinstance(org_id, str) or not org_id or not isinstance(username, str) or not username:
                continue
            key = (org_id, username)
            rec_state = p.get("state")
            if rec_state == "revoked":
                state[key] = "revoked"
            elif rec_state == "active":
                if not verify_signed(p, _MEMBERSHIP_CORE, resolver.at(r.seq)):
                    continue
                at = as_issued_at(p.get("issued_at"))
                if at <= issued.get(key, NO_HIGHWATER):
                    continue
                issued[key] = at
                state[key] = "active"
                mems[key] = Membership(org_id=org_id, username=username, role=str(p.get("role") or ""),
                                       issued_at=at, state="active")
        return {k: m for k, m in mems.items() if state.get(k) == "active"}

    def orgs(self) -> list[Org]:
        """The current active orgs (owner's workspace list), in org_id order."""
        fold = self._fold_orgs()
        return [fold[o] for o in sorted(fold)]

    def org(self, org_id: str) -> Optional[Org]:
        """The current active `Org` for `org_id`, or None (fail-closed — unknown/revoked treated as absent)."""
        if not isinstance(org_id, str) or not org_id:
            return None
        return self._fold_orgs().get(org_id)

    def memberships(self, org_id: Optional[str] = None) -> list[Membership]:
        """The current active memberships, optionally scoped to one org, in (org_id, username) order."""
        fold = self._fold_memberships()
        keys = sorted(fold) if org_id is None else sorted(k for k in fold if k[0] == org_id)
        return [fold[k] for k in keys]

    def membership_role(self, username: str, org_id: str) -> Optional[str]:
        """The per-org role `username` holds in `org_id`, or None (fail-closed) when the user is NOT an active
        member OR the org itself is not active. Revoking the org therefore strips every member's effective
        role. The role is owner-signed (a Tier-1 cryptographic predicate), never self-asserted by the caller
        — so this is not an allowlist self-reference."""
        if not isinstance(username, str) or not username or not isinstance(org_id, str) or not org_id:
            return None
        if org_id not in self._fold_orgs():            # a revoked/unknown org admits no one
            return None
        m = self._fold_memberships().get((org_id, username))
        return m.role if m is not None else None

    def org_role_can(self, username: str, org_id: str, permission: Optional[str]) -> bool:
        """The multi-tenant admission primitive the UI/proxy auth boundary will call: True iff `username`'s
        per-org role in `org_id` carries `permission`. DEFAULT-DENY — a non-member, a member of a DIFFERENT
        org, a revoked org, or an unmapped permission all refuse. Reuses the shared `rbac.role_can` with the
        per-org membership role.

        COMPOSITION NOTE for the later proxy slice: this answers ONLY the per-org membership question. The
        trust-root OWNER principal is not an org member, so an owner-tier global action is NOT granted here —
        the proxy must OR this with the existing GLOBAL account check (`accounts.role_can(principal.role, ...)`)
        so the keyholder is never locked out of their own tenant. Keeping this primitive purely
        membership-scoped is deliberate (single responsibility, soundly default-deny)."""
        role = self.membership_role(username, org_id)
        return role_can(role, permission)
