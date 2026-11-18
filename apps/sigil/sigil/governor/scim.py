"""Consumer PR-H (Area 7) — CAPPED, OWNER-SIGNED SSO/SCIM provisioning (the mint site).

Given a VERIFIED external identity (a SAML assertion checked by `ui.saml`, an OIDC id_token checked by
`ui.oidc`, or a bearer-authenticated SCIM push), this module mints the corresponding per-org membership — and
it is the ONE place SSO/SCIM memberships are created, so the role ceiling is enforced HERE a second and third
time (after `governor.sso_config`'s bind-time gate):

  * REFUSAL #2 (independent): a locally-declared `SCIM_PROVISIONABLE_ROLES = {viewer, analyst, org_admin}` and
    `_assert_ceiling()` — NOT imported from `sso_config`, so neither gate depends on the other; a lockstep test
    asserts the two literals are equal, so drift is caught without coupling. Every role that reaches the mint
    passes `_assert_ceiling` first.
  * REFUSAL #3 (structural): the mint helper `provision_membership` calls `OrgRegistry.grant_membership` ONLY
    with a ceiling role. `grant_membership` itself would accept `founder` (that is the owner's own direct-grant
    path), but the SSO/SCIM code never constructs a non-ceiling grant — so SSO/SCIM can never reach
    `operator`/`founder`/`owner` or any money/offense permission, however the inputs are shaped.

THE ROLE IS NEVER TAKEN FROM THE IdP CLAIM. `resolve_role` reads the role from the OWNER-SIGNED `SsoConfig`
(its `group_role_map` / `default_role`), CLAMPED to the config's `role_cap` and then to the ceiling. The IdP's
asserted groups only SELECT among the owner-authored map entries; they can never introduce a role the owner did
not sign into the config. Clamping is always the fail-SAFE direction (never above the cap/ceiling).

ORG-SCOPED: every function takes an `SsoConfig` (which is per-org) and mints for `config.org_id` — never a
client-supplied org. A SCIM bearer token authenticates against exactly one org's `scim_token_fp`. So one org's
SSO/SCIM can never provision into another.

SECRETS: a SCIM bearer token is wrapped in `BearerToken`, whose `__repr__`/`__str__`/`format` are REDACTED, so
it can never land in a log line, a traceback frame-local dump, an f-string or a `%` format. Authentication is a
constant-time compare of the presented token's sha256 fingerprint against the config's stored fingerprint; the
plaintext is never stored (the config holds only the one-way fingerprint).

FATAL-2: SOVEREIGN-side, imports NO `framework` / `strix` (`assert_no_offense()` at import).
"""
from __future__ import annotations

import hmac
from dataclasses import dataclass
from typing import Iterable, Optional

from ..reuse import assert_no_offense, sha256_hex

assert_no_offense()

from .orgs import OrgRegistry  # noqa: E402  (the owner-signed membership mint — the only membership key custody)
from .sso_config import SsoConfig, token_fingerprint  # noqa: E402

# ===================================================================================================
# THE ROLE CEILING — declared INDEPENDENTLY of `sso_config.SSO_PROVISIONABLE_ROLES` (refusal #2). A lockstep
# test (`test_scim.py::test_ceiling_lockstep_with_sso_config`) asserts the two frozensets are EQUAL, so a drift
# is caught at build time — but neither gate imports the other, so a weakening of one does not silently weaken
# the other. "Prefer two independent refusals."
# ===================================================================================================
SCIM_PROVISIONABLE_ROLES = frozenset({"viewer", "analyst", "org_admin"})

# The clamp order over the ceiling roles (viewer < analyst < org_admin) — a LOCAL ordering for fail-safe
# clamping to the cap, NOT a permission-superset claim (the roles are disjoint capability sets). A role outside
# the ceiling has rank +inf so it can never be selected or pass a cap comparison. Declared locally (mirrors
# sso_config._PROVISION_RANK; the lockstep test over the role set covers drift of the keys).
_PROVISION_RANK = {"viewer": 0, "analyst": 1, "org_admin": 2}


def _provision_rank(role: str) -> float:
    return _PROVISION_RANK.get(str(role or ""), float("inf"))


# The inverse of the rank over the ceiling roles — used to name the role a clamped rank resolves to. A rank with
# no ceiling role (e.g. +inf from a hand-built out-of-ceiling cap) maps to None ⇒ the caller returns None (deny).
_ROLE_AT_RANK = {0.0: "viewer", 1.0: "analyst", 2.0: "org_admin"}


class ScimError(ValueError):
    """A fail-closed SCIM/SSO provisioning refusal (ceiling breach, unauthenticated, no active config)."""


def _assert_ceiling(role: str) -> str:
    """REFUSAL #2 — the independent mint-time ceiling gate. Raises `ScimError` on any role outside
    `SCIM_PROVISIONABLE_ROLES`, so no SSO/SCIM mint can ever name `operator`/`founder`/`owner` or a money/offense
    role, even if a config gate upstream were bypassed."""
    r = str(role or "").strip()
    if r not in SCIM_PROVISIONABLE_ROLES:
        raise ScimError(f"SSO/SCIM provisioning refuses role {role!r}: the ceiling is {sorted(SCIM_PROVISIONABLE_ROLES)} "
                        f"(operator/founder/owner and every money/offense role stay separately owner-signed)")
    return r


# ---------------------------------------------------------------------------------------------------
# BearerToken — a repr-hidden secret (never logged / never in a traceback / never in an f-string).
# ---------------------------------------------------------------------------------------------------

class BearerToken:
    """A SCIM bearer token held so it can NEVER be disclosed by accident. The raw value lives only in a private
    slot; `__repr__`, `__str__` and `__format__` all return a fixed redacted placeholder, so it is inert in a log
    line, a traceback's frame-locals dump, an f-string, a `%`/`.format()` template or a `print`. The only ways
    out are the explicit `fingerprint()` (a one-way digest) and `matches()` (a constant-time compare) — there is
    deliberately NO accessor that returns the plaintext."""

    __slots__ = ("_raw",)
    _REDACTED = "<BearerToken REDACTED>"

    def __init__(self, raw: str) -> None:
        self._raw = str(raw or "")

    def __repr__(self) -> str:
        return self._REDACTED

    __str__ = __repr__

    def __format__(self, _spec: str) -> str:
        return self._REDACTED

    def __bool__(self) -> bool:
        return bool(self._raw)

    def fingerprint(self) -> str:
        """The one-way sha256 fingerprint of the token (what the owner-signed config stores)."""
        return token_fingerprint(self._raw)

    def matches(self, stored_fingerprint: str) -> bool:
        """CONSTANT-TIME: True iff this token's fingerprint equals `stored_fingerprint`. Both the fingerprint
        derivation and the compare are constant-time w.r.t. the token value, and a blank stored fingerprint (SCIM
        not provisioned) always fails — fail-closed."""
        sf = str(stored_fingerprint or "")
        if not sf or not self._raw:
            return False
        return hmac.compare_digest(self.fingerprint(), sf)


def bearer_from_authorization_header(header_value: object) -> Optional[BearerToken]:
    """Extract a `BearerToken` from an HTTP `Authorization: Bearer <token>` header value, or None if the scheme
    is absent/not Bearer or the token is blank. Case-insensitive on the scheme; the token is taken verbatim after
    the single space."""
    v = str(header_value or "")
    if not v:
        return None
    parts = v.split(" ", 1)
    if len(parts) != 2 or parts[0].strip().lower() != "bearer" or not parts[1].strip():
        return None
    return BearerToken(parts[1].strip())


# ---------------------------------------------------------------------------------------------------
# Authentication + role resolution (reads the OWNER-SIGNED config only).
# ---------------------------------------------------------------------------------------------------

def authenticate_scim(config: Optional[SsoConfig], presented: Optional[BearerToken]) -> bool:
    """True iff `presented` is a valid SCIM bearer for `config`'s org. Fail-closed: no config, SCIM disabled, a
    blank stored fingerprint, or no presented token all refuse. Org-scoped — the config IS one org's, so a token
    valid for org A's config can never authenticate org B's (B's config holds a different fingerprint)."""
    if config is None or not getattr(config, "scim_enabled", False):
        return False
    if presented is None:
        return False
    return presented.matches(config.scim_token_fp)


def resolve_role(config: SsoConfig, groups: Iterable[object]) -> Optional[str]:
    """The role to provision for an authenticated identity in `config`'s org, read ENTIRELY from the owner-signed
    config — NEVER from the IdP claim. The IdP-asserted `groups` only SELECT among the owner-authored
    `group_role_map` entries. The candidate roles are the owner-signed `default_role` plus every IN-CEILING group
    mapping the IdP asserts; each candidate is CLAMPED to `role_cap` (fail-safe) and the HIGHEST is chosen, then
    ceiling-checked. So an out-of-ceiling group mapping is IGNORED (never elevates), an in-ceiling mapping above
    the cap is clamped DOWN to the cap, and the result is always within {viewer, analyst, org_admin} or None
    (deny). The group list can never introduce a role the owner did not sign, nor one above the cap/ceiling."""
    cap_rank = _provision_rank(config.role_cap)
    candidates = [config.default_role]
    for g in groups or ():
        mapped = config.group_role_map.get(str(g))
        if mapped in SCIM_PROVISIONABLE_ROLES:           # ONLY owner-authored, in-ceiling mappings may select
            candidates.append(mapped)
    best: Optional[str] = None
    best_rank = -1.0
    for role in candidates:
        eff_rank = min(_provision_rank(role), cap_rank)  # clamp each candidate to the owner's cap (fail-safe)
        if eff_rank > best_rank:
            best_rank, best = eff_rank, _ROLE_AT_RANK.get(eff_rank)
    if best is None or best not in SCIM_PROVISIONABLE_ROLES:   # structural ceiling (defence in depth)
        return None
    return best


def sso_username(config: SsoConfig, external_id: object) -> Optional[str]:
    """The stable, charset-safe per-org membership username for an SSO identity: `sso_<24-hex>` of
    `sha256(org_id\\x00idp\\x00external_id)`. NAMESPACED by org_id AND the IdP (the SAML entity-id / OIDC issuer),
    so the SAME external id under a DIFFERENT org or IdP yields a DIFFERENT username — cross-org / cross-IdP
    identities can never collide into one membership. It satisfies `orgs._USERNAME_RE` (starts alphanumeric, then
    `[0-9a-f]`), and the `sso_` namespace keeps SSO members distinct from password/Google-OIDC customer accounts
    and operator principals. Deterministic, so the same user resolves to the same membership on every login.
    Returns None on a blank external id (fail-closed)."""
    ext = str(external_id or "").strip()
    if not ext:
        return None
    idp = (config.idp_entity_id or config.oidc_issuer or "").strip()
    ns = f"{config.org_id}\x00{idp}\x00{ext}"
    return "sso_" + sha256_hex(ns.encode("utf-8"))[:24]


# ---------------------------------------------------------------------------------------------------
# The mint — CAPPED owner-signed membership (REFUSAL #3: never passes a non-ceiling role to grant_membership).
# ---------------------------------------------------------------------------------------------------

def provision_membership(org_reg: OrgRegistry, config: SsoConfig, *, username: str, role: str,
                         issued_at: float) -> int:
    """Mint an OWNER-SIGNED per-org membership `username -> role` in `config.org_id`, CEILING-GATED. `role` passes
    `_assert_ceiling` (refusal #2) BEFORE it reaches `OrgRegistry.grant_membership`, which is the owner-signed
    mint. The org must exist and be active (grant_membership fails closed otherwise). Returns the record seq.

    This is the ONLY path SSO/SCIM mints a membership, and it is structurally incapable of granting a non-ceiling
    role (refusal #3). `org_reg` holds the owner key (the single owner-key custody is unchanged — this adds no new
    signer)."""
    role = _assert_ceiling(role)                          # refusal #2 — never passes a non-ceiling role onward
    u = str(username or "").strip()
    if not u:
        raise ScimError("provision_membership requires a username")
    try:
        return org_reg.grant_membership(config.org_id, u, role, issued_at=float(issued_at))
    except ValueError as e:
        # grant_membership fails closed on an absent/revoked org or a bad username (e.g. an SSO config outlived
        # its org). Surface it as a clean ScimError so the SCIM/SSO caller returns a 4xx, never a 500.
        raise ScimError(f"cannot provision into org {config.org_id!r}: {e}") from e


def deactivate_membership(org_reg: OrgRegistry, config: SsoConfig, *, username: str) -> int:
    """Revoke an SSO/SCIM-provisioned membership (SCIM deactivate / delete) — the SAFE direction via
    `OrgRegistry.revoke_membership` (honored even unsigned, idempotent, replay-safe). Org-scoped to
    `config.org_id`."""
    u = str(username or "").strip()
    if not u:
        raise ScimError("deactivate_membership requires a username")
    return org_reg.revoke_membership(config.org_id, u)


# ---------------------------------------------------------------------------------------------------
# SCIM 2.0 User resource normalisation (RFC 7643) — the minimal, bounded subset we act on.
# ---------------------------------------------------------------------------------------------------

@dataclass(frozen=True)
class ScimUser:
    user_name: str                 # the IdP-asserted userName (human identifier; attribute only)
    external_id: str               # the IdP's stable id for the user (the membership-key source)
    active: bool                   # SCIM active flag — False ⇒ deactivate (revoke membership)
    groups: tuple                  # asserted group names (used only to SELECT among the owner-signed map)


# The subset of role-carrying attributes a SCIM User may present. SCIM group membership is often read-only on the
# User (RFC 7643 §4.1.2) and managed via the Group resource; to stay bounded + sound we read role selectors from
# whichever of these an IdP populates — `groups[].display|value`, `roles[].value|display`. The SECURITY property
# (ceiling + cap) holds regardless of HOW the selector arrives, because `resolve_role` only ever SELECTS among the
# owner-signed config map and clamps to the ceiling.
def _group_selectors(resource: dict) -> tuple:
    out: list[str] = []
    for key in ("groups", "roles"):
        items = resource.get(key)
        if isinstance(items, list):
            for it in items:
                if isinstance(it, dict):
                    for f in ("display", "value"):
                        v = it.get(f)
                        if isinstance(v, str) and v.strip():
                            out.append(v.strip())
                            break
                elif isinstance(it, str) and it.strip():
                    out.append(it.strip())
    return tuple(out)


def parse_scim_user(resource: object) -> Optional[ScimUser]:
    """Normalise a SCIM 2.0 User resource dict into a `ScimUser`, or None if it is not a usable User (no
    userName/externalId). `active` defaults to True when absent (SCIM create). Fail-closed on a non-dict."""
    if not isinstance(resource, dict):
        return None
    user_name = str(resource.get("userName") or "").strip()
    external_id = str(resource.get("externalId") or "").strip() or user_name
    if not external_id:
        return None
    active_raw = resource.get("active", True)
    active = bool(active_raw) if not isinstance(active_raw, str) else active_raw.strip().lower() in ("true", "1", "yes")
    return ScimUser(user_name=user_name, external_id=external_id, active=active,
                    groups=_group_selectors(resource))
