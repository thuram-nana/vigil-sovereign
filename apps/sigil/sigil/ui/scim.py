"""Consumer PR-H (Area 7) — the SCIM 2.0 protocol handler + the SSO sign-in composition.

This is the END-TO-END glue: it turns a VERIFIED external identity (SAML via `ui.saml`, enterprise-OIDC via the
airtight `ui.oidc`, or a bearer-authenticated SCIM push) into an OWNER-SIGNED, CEILING-CAPPED membership, by:

  1. resolving the org's OWNER-SIGNED `governor.sso_config.SsoConfig` (the delegation),
  2. authenticating / verifying the inbound identity against THAT config (org-scoped),
  3. reading the role FROM the config (capped) via `governor.scim.resolve_role` — NEVER from the IdP claim,
  4. minting the membership through `governor.scim.provision_membership` (the ceiling-gated mint site).

THE HTTP EDGE IS WIRED. The keyless customer edge (`ui.custui` + `ui.sso_edge`) serves the SP-initiated SAML
login + ACS, the enterprise-OIDC callback and the bearer-authenticated SCIM endpoint `/scim/v2/<org_id>/...`, all
behind `config.customer_sso_enabled()` (OFF ⇒ every route 404, byte-identical), and relays each over the hop key
to the provisioner (`ui.sso_provision`), which runs the functions below with the owner-key `OrgRegistry`. What stays
with the OWNER per org is provisioning, not code: registering the customer's IdP (`sigil sso set-saml` /
`set-oidc`, which prints the public URLs to give the IdP) and, for SAML only, installing a vetted XML-DSig backend
in the sovereign venv — without it SAML sign-in fails closed (`ui.saml.signxml_sig_verifier`); enterprise OIDC and
SCIM do not need it.

SCIM IS A RECONCILIATION PROTOCOL, so this handler keeps the IdP's view in the owner-signed per-org directory
(`governor.scim_directory`): a created user reads back with the `userName`/`externalId` the IdP wrote, `filter=
userName eq "..."` answers the IdP's "does this user exist?" correctly, and group membership edges persist. The
directory is BOOKKEEPING — the authority is still the ceiling-capped owner-signed membership:

  * a user's role = `resolve_role(config, <role selectors on the User> + <names of the directory groups it is
    in>)` — the owner-signed config's map/default, clamped to its cap and the ceiling. A group named `founder` or
    a `roles: [{"value": "owner"}]` selects nothing the owner did not sign;
  * SCIM only manages roles INSIDE the ceiling (viewer / analyst / org_admin). A member the owner set by hand to a
    role OUTSIDE it (`sigil org set-member-role`, e.g. founder) is never re-granted by SCIM nor clamped at sign-in;
    deactivation still revokes it (the safe direction wins). An in-ceiling role of a directory user is the
    directory's: the IdP's next write for that user re-resolves it from the config, and a sign-in caps it at what
    the config resolves (below) — a hand-set in-ceiling role does not stick;
  * SCIM can only touch users in ITS OWN org's directory: a password customer, a Google-OIDC customer or another
    org's user is a 404 here, so a SCIM token can never revoke the org's founder;
  * deactivation (`active:false`, PATCH or PUT) and DELETE revoke the membership LIVE — the next request of that
    member is refused by `admit_customer` — and the result names the revoked usernames so the edge also severs
    their sessions at once.

SIGN-IN SEMANTICS:
  * an org whose config has SCIM OFF provisions JUST-IN-TIME: a verified sign-in mints (or updates) the capped
    membership with the role the config resolves for the assertion's groups;
  * in either mode the subject is used EXACTLY as the IdP signed it: one that begins or ends with whitespace (any
    Unicode space) is refused, never trimmed into a member's identifier — and a SCIM write refuses such a
    `userName` / `externalId` likewise (400), so a padded look-alike can neither sign in as nor collide with a member;
  * an org whose config has SCIM ON is DIRECTORY-MANAGED: sign-in links the verified subject to the directory user
    whose `userName` (case-insensitively — by letter case only, never a case-folding look-alike) or `externalId`
    matches it (the SAML NameID; the OIDC `sub`, or Entra's immutable `oid`) and admits only an ACTIVE user with a
    live membership. A subject that matches no directory user is REFUSED — never resolved to a derived username,
    which could name a different member. A user the directory deactivated or deleted can therefore never sign back
    in, even with a still-valid assertion. Sign-in mints nothing in this mode except a CLAMP and its GIVE-BACK:
      - when the current owner-signed config resolves a LOWER role for the user than its membership holds (the
        owner tightened the cap or removed a group mapping), the membership is brought down to it before the person
        is admitted — except the org's LAST administrator, who keeps the role until another one exists (the
        owner's own membership verbs refuse to orphan an org likewise);
      - the clamp notes the role it took in the user's directory record, keyed to the grant it minted, and while
        that grant is still the member's live one a later sign-in gives back what the config resolves again —
        never more than the clamp took — so a transient config mistake (a re-sign that dropped the group map)
        heals at the next sign-in instead of sticking;
      - any other raise waits for the IdP's next SCIM write, so a sign-in never undoes a change the owner (or the
        IdP) made after the clamp; a role the owner set by hand outside the ceiling is left as the owner set it.

ORG-SCOPED EVERYWHERE: the org is resolved from the SCIM bearer's config / the SSO login's server-side state, and
provisioning always targets `config.org_id`. A caller never supplies a target org as a free field.

NO MONEY / NO FACT / NO MODEL-ID: this module provisions IDENTITY→ROLE memberships only. It mints no FACT (only
the oracle does), moves no money, and surfaces no model identifier.

FATAL-2: SOVEREIGN-side, imports NO `framework` / `strix` (`assert_no_offense()` at import).
"""
from __future__ import annotations

import json
import math
import re
import secrets
import urllib.parse
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Callable, Optional

from ..reuse import assert_no_offense

assert_no_offense()

from ..governor import scim as _scim  # noqa: E402
from ..governor.orgs import Membership, OrgRegistry  # noqa: E402
from ..governor.scim import BearerToken, ScimError, bearer_from_authorization_header  # noqa: E402
from ..governor.scim_directory import DirectoryError, DirectoryUser, OrgDirectory, ScimDirectoryRegistry  # noqa: E402
from ..governor.scim_directory import username_key  # noqa: E402
from ..governor.sso_config import SsoConfig  # noqa: E402

# The SCIM message / resource schema urns (RFC 7643 / 7644).
_SCHEMA_ERROR = "urn:ietf:params:scim:api:messages:2.0:Error"
_SCHEMA_LIST = "urn:ietf:params:scim:api:messages:2.0:ListResponse"
_SCHEMA_USER = "urn:ietf:params:scim:schemas:core:2.0:User"
_SCHEMA_GROUP = "urn:ietf:params:scim:schemas:core:2.0:Group"
_SCHEMA_SPC = "urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"
_SCHEMA_RESOURCE_TYPE = "urn:ietf:params:scim:schemas:core:2.0:ResourceType"
_SCHEMA_SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:Schema"

# The OIDC id_token claim an enterprise config reads group membership from (for role SELECTION only — the role
# still comes from the owner-signed config map). The common convention is a `groups` claim.
_OIDC_GROUPS_CLAIM = "groups"
# Entra ID's IMMUTABLE per-tenant object id — an IdP-asserted, admin-controlled link key (never a mutable or
# user-editable claim such as `email`), tried after `sub` when linking a sign-in to a SCIM directory user.
_OIDC_OBJECT_ID_CLAIM = "oid"

# Bounds on one SCIM request (the bodies are IdP-authored; a request is handled under the spine lock).
MAX_RESULTS = 1000            # filter.maxResults advertised in ServiceProviderConfig
MAX_PATCH_OPS = 1000          # Operations per PATCH
MAX_MEMBER_VALUES = 1000      # member references per request

_RESOURCES = ("Users", "Groups", "ServiceProviderConfig", "ResourceTypes", "Schemas")
_MUTATING = frozenset({"POST", "PUT", "PATCH", "DELETE"})


@dataclass(frozen=True)
class ProvisionResult:
    """The outcome of a successful SSO sign-in / SCIM provisioning — identity + the CAPPED role the member holds +
    the spine seq of the owner-signed grant this call minted (None when it minted none: a JIT sign-in whose role did
    not change, or a directory-managed sign-in that neither clamped nor gave back a role). Carries NO secret, NO
    money figure, NO model id."""
    org_id: str
    username: str
    role: str
    external_id: str
    seq: Optional[int] = None


class SsoLoginError(Exception):
    """A fail-closed SSO-login refusal (no active config, verification failed, role denied, not provisioned). The
    route maps it to a refusal; it never leaks assertion / token internals."""


@dataclass(frozen=True)
class ScimResult:
    """One SCIM response: the HTTP status, the JSON body (None for 204) and the membership usernames this request
    revoked (the edge severs their sessions)."""
    status: int
    body: Optional[dict]
    deactivated: tuple = ()


class _ScimFail(Exception):
    def __init__(self, status: int, detail: str, scim_type: str = "") -> None:
        super().__init__(detail)
        self.status = int(status)
        self.detail = str(detail)
        self.scim_type = str(scim_type or "")


AuditFn = Callable[[str, str, str], None]


# ---------------------------------------------------------------------------------------------------
# A per-request view of the org registry (same spine + owner key), with this org's reads memoized for ONE request
# handled under the spine lock and kept in step with the request's own grants / revokes — so a group change that
# touches many members does not re-fold the spine once per member. Grants still go through the inherited,
# validating `OrgRegistry.grant_membership` (the owner-signed mint).
# ---------------------------------------------------------------------------------------------------

class _RequestOrgs(OrgRegistry):
    def __init__(self, base: OrgRegistry, org_id: str) -> None:
        super().__init__(base.store, owner_key=base.owner_key, trusted_pubkey=base.trusted_pubkey)
        self._oid = org_id
        self._org = base.org(org_id)
        self._mems: "dict[str, Membership]" = {m.username: m for m in base.memberships(org_id)}

    def org(self, org_id: str):
        return self._org if org_id == self._oid else super().org(org_id)

    def memberships(self, org_id: Optional[str] = None) -> "list[Membership]":
        if org_id == self._oid:
            return [self._mems[u] for u in sorted(self._mems)]
        return super().memberships(org_id)

    def membership_role(self, username: str, org_id: str) -> Optional[str]:
        if org_id != self._oid:
            return super().membership_role(username, org_id)
        if self._org is None:
            return None
        m = self._mems.get(str(username or ""))
        return m.role if m is not None else None

    def grant_membership(self, org_id: str, username: str, role: str, *, issued_at: float) -> int:
        seq = super().grant_membership(org_id, username, role, issued_at=issued_at)
        if org_id == self._oid:
            u = str(username).strip()
            self._mems[u] = Membership(org_id=org_id, username=u, role=str(role).strip(),
                                       issued_at=float(issued_at), state="active")
        return seq

    def revoke_membership(self, org_id: str, username: str) -> int:
        seq = super().revoke_membership(org_id, username)
        if org_id == self._oid:
            self._mems.pop(str(username).strip(), None)
        return seq


def _directory_registry(directory_registry, org_registry) -> ScimDirectoryRegistry:
    if directory_registry is not None:
        return directory_registry
    return ScimDirectoryRegistry(org_registry.store, owner_key=org_registry.owner_key,
                                 trusted_pubkey=org_registry.trusted_pubkey)


def _clock(issued_at: Optional[float], now: float) -> "Callable[[], float]":
    """A strictly increasing issued_at source for one request (each owner-signed record gets its own instant)."""
    state = {"t": float(now if issued_at is None else issued_at)}
    first = {"v": True}

    def nxt() -> float:
        if first["v"]:
            first["v"] = False
            return state["t"]
        state["t"] = math.nextafter(state["t"], math.inf)
        return state["t"]
    return nxt


# ---------------------------------------------------------------------------------------------------
# SSO sign-in — verify the identity, then JIT-provision (SCIM off) or link to the directory (SCIM on).
# ---------------------------------------------------------------------------------------------------

def _provision_from_identity(org_registry, config: SsoConfig, *, external_id: str, groups, issued_at: float,
                             audit: Optional[AuditFn] = None) -> ProvisionResult:
    """JUST-IN-TIME tail (SCIM off): resolve the capped role from the owner-signed config (never the IdP claim),
    derive the stable per-org username, and mint the ceiling-gated owner-signed membership — only when it changes
    (an unchanged role mints nothing). A role the OWNER set by hand outside the ceiling (e.g. founder) is left
    as the owner set it: sign-in never re-grants it."""
    username = _scim.sso_username(config, external_id)
    if not username:
        raise SsoLoginError("the verified identity carries no usable subject")
    role = _scim.resolve_role(config, groups or ())
    if role is None:                                   # structurally impossible for a bind-time-valid config
        raise SsoLoginError("no provisionable role resolves for this identity (fail-closed)")
    current = org_registry.membership_role(username, config.org_id)
    if current is not None and current not in _scim.SCIM_PROVISIONABLE_ROLES:
        return ProvisionResult(org_id=config.org_id, username=username, role=current, external_id=str(external_id))
    if current == role:
        return ProvisionResult(org_id=config.org_id, username=username, role=role, external_id=str(external_id))
    if audit is not None:
        audit("sso_jit_grant", username, f"role={role}")
    try:
        seq = _scim.provision_membership(org_registry, config, username=username, role=role, issued_at=issued_at)
    except ScimError as e:                             # the ceiling gate / grant precondition refused
        raise SsoLoginError(str(e)) from e
    return ProvisionResult(org_id=config.org_id, username=username, role=role,
                           external_id=str(external_id), seq=seq)


def _directory_role(config: SsoConfig, directory: OrgDirectory, u: DirectoryUser) -> Optional[str]:
    """The role the owner-signed config resolves for directory user `u`: its role selectors + the names of the
    directory groups it is in, through `resolve_role` (the config's map / default, clamped to its cap and the
    ceiling; None ⇒ deny)."""
    return _scim.resolve_role(config, list(u.selectors) + [g.display_name for g in directory.groups_of(u.id)])


def _login_principal(org_registry, config: SsoConfig, *, subject: str, link_ids=(), groups, issued_at: float,
                     directory_registry=None, audit: Optional[AuditFn] = None) -> ProvisionResult:
    """Resolve a VERIFIED sign-in to the member it admits. SCIM off ⇒ JIT. SCIM on ⇒ directory-managed: link the
    subject to the org's directory user (userName by letter case only, or externalId exactly — also via the extra
    immutable `link_ids`), and admit only an ACTIVE user holding a live membership. A subject no directory user
    matches is REFUSED: a derived `sso_username(subject)` is never looked up instead, since a directory user's id is
    derived from the userName / externalId it had when it was CREATED — after a rename that id belongs to a
    DIFFERENT person than the one now carrying the old name. Mints nothing in that mode except the CLAMP and its
    GIVE-BACK (see the module docstring): a membership above the role the CURRENT owner-signed config resolves for
    the user is brought down to it first — never the org's last administrator's — and while that clamped grant is
    still the live one a later sign-in gives back what the config allows again, never more than the clamp took (a
    role the owner set outside the ceiling is left as the owner set it)."""
    for ident in (subject, *link_ids):
        # an identifier is used EXACTLY as the IdP signed it: one that begins or ends with whitespace (any Unicode
        # space) is a DIFFERENT identifier that merely renders like a member's — refused, never trimmed into it
        if not isinstance(ident, str) or not ident.strip() or ident != ident.strip():
            raise SsoLoginError("the verified identity is blank or begins or ends with whitespace (refused, never "
                                "trimmed into another identifier)")
    if not config.scim_enabled:
        return _provision_from_identity(org_registry, config, external_id=subject, groups=groups,
                                        issued_at=issued_at, audit=audit)
    d = _directory_registry(directory_registry, org_registry).directory(config.org_id)
    u = d.user_by_name(subject)
    if u is None:
        for key in (subject, *link_ids):
            u = d.user_by_external_id(key)
            if u is not None:
                break
    if u is None:
        raise SsoLoginError("this organization adds members through its directory (SCIM) and this person is not in "
                            "it; the organization's IT administrator must assign VIGIL to them")
    if not u.active:
        raise SsoLoginError("this person is deactivated in the organization's directory")
    role = org_registry.membership_role(u.id, config.org_id)
    if role is None:
        raise SsoLoginError("this organization adds members through its directory (SCIM) and this person has no "
                            "active membership; the organization's IT administrator must assign VIGIL to them")
    held = ProvisionResult(org_id=config.org_id, username=u.id, role=role, external_id=str(subject))
    if role not in _scim.SCIM_PROVISIONABLE_ROLES:         # an owner-set role outside the ceiling stays the owner's
        return held
    want = _directory_role(config, d, u)
    if want is None:
        raise SsoLoginError("no provisionable role resolves for this person (fail-closed)")
    rank = _scim._provision_rank
    # what an earlier clamp took — only while the grant it minted is still the live one (any later grant, by the
    # owner or the IdP, makes the note stale: a sign-in never undoes a change made after the clamp)
    took = u.clamp[0] if u.clamp and u.clamp[1] == _granted_at(org_registry, config.org_id, u.id) else None
    if rank(want) < rank(role):                                          # CLAMP down to the current config
        from .provision import _member_admins
        # (`want` is below `role` <= org_admin, so it never holds manage_members: a clamp of the org's ONLY
        # administrator would orphan the org — it waits until another administrator exists)
        if _member_admins(org_registry, config.org_id) == {u.id}:
            return held
        return _regrant(org_registry, config, d, u, subject=subject, role=want, took=took or role,
                        action="sso_role_clamp", detail=f"role={want} was={role}", issued_at=issued_at, audit=audit)
    if took in _scim.SCIM_PROVISIONABLE_ROLES and rank(want) > rank(role):    # GIVE BACK what the clamp took
        back = want if rank(want) <= rank(took) else took                     # never more than it took
        return _regrant(org_registry, config, d, u, subject=subject, role=back,
                        took=None if back == took else took, action="sso_role_restore",
                        detail=f"role={back} was={role}", issued_at=issued_at, audit=audit)
    return held


def _granted_at(org_registry, org_id: str, username: str) -> Optional[float]:
    """The issued_at of `username`'s live grant in `org_id` (None when it has none)."""
    return next((m.issued_at for m in org_registry.memberships(org_id) if m.username == username), None)


def _regrant(org_registry, config: SsoConfig, d: OrgDirectory, u: DirectoryUser, *, subject: str, role: str,
             took: Optional[str], action: str, detail: str, issued_at: float,
             audit: Optional[AuditFn]) -> ProvisionResult:
    """Re-grant directory user `u` to `role` at sign-in (a clamp down, or the give-back of what a clamp took): the
    critical audit row FIRST, then the ceiling-gated owner-signed grant, then the directory note of what the clamp
    took (`took`; None ⇒ no note) keyed to that grant's issued_at, so a later sign-in can give it back only while
    this grant is still the live one."""
    if audit is not None:
        audit(action, u.id, detail)
    try:
        seq = _scim.provision_membership(org_registry, config, username=u.id, role=role, issued_at=issued_at)
    except ScimError as e:                             # the ceiling gate / grant precondition refused
        raise SsoLoginError(str(e)) from e
    at = _granted_at(org_registry, config.org_id, u.id)
    try:
        d.put_user(u.id, user_name=u.user_name, external_id=u.external_id, display_name=u.display_name,
                   active=u.active, selectors=u.selectors, profile=u.profile,
                   clamp=(took, at) if took and at is not None else (), now=issued_at)
    except DirectoryError as e:
        raise SsoLoginError(f"the sign-in clamp's directory note could not be written: {e}") from e
    return ProvisionResult(org_id=config.org_id, username=u.id, role=role, external_id=str(subject), seq=seq)


def sso_login_saml(xml_bytes: bytes, *, org_id: str, config_registry, org_registry, replay_ledger,
                   now: float, sig_verifier=None, issued_at: Optional[float] = None,
                   expected_request_id: Optional[str] = None, directory_registry=None,
                   audit: Optional[AuditFn] = None) -> ProvisionResult:
    """Verify a SAML Response for `org_id` (`ui.saml.verify_saml_response` — structural/XSW/temporal/audience/
    replay sound, and bound to `expected_request_id`'s AuthnRequest when given; the crypto backend fail-closes
    without a vetted XML-DSig lib), then resolve the member (JIT or directory-linked). FAIL-CLOSED on no active
    SAML config, a protocol mismatch, or any verification failure. The role comes from the OWNER-SIGNED config,
    never the assertion's attributes."""
    from . import saml as _saml
    config = config_registry.config(org_id)
    if config is None or config.protocol != "saml":
        raise SsoLoginError(f"no active SAML SSO config for org {org_id!r}")
    try:
        identity = _saml.verify_saml_response(xml_bytes, config=config, now=now, replay_ledger=replay_ledger,
                                              sig_verifier=sig_verifier,
                                              expected_in_response_to=expected_request_id)
    except _saml.SamlError as e:
        raise SsoLoginError(f"SAML verification failed: {e}") from e
    return _login_principal(org_registry, config, subject=identity.name_id, groups=identity.groups,
                            issued_at=now if issued_at is None else issued_at,
                            directory_registry=directory_registry, audit=audit)


def sso_login_oidc(id_token: str, *, org_id: str, config_registry, org_registry, jwks_keys, expected_nonce: str,
                   now: float, issued_at: Optional[float] = None, directory_registry=None,
                   audit: Optional[AuditFn] = None) -> ProvisionResult:
    """Verify an enterprise-OIDC id_token for `org_id` (reusing the airtight `ui.oidc.verify_id_token` —
    signature-first, asymmetric-only, iss/aud/exp/nbf/nonce) against the org's OWNER-SIGNED OIDC config, then
    resolve the member (JIT or directory-linked). FAIL-CLOSED on no active OIDC config or any verification
    failure. The subject is the IMMUTABLE `sub`; groups come from the `groups` claim (role SELECTION only — the
    role itself is the owner-signed config's)."""
    from . import oidc as _oidc
    config = config_registry.config(org_id)
    if config is None or config.protocol != "oidc":
        raise SsoLoginError(f"no active OIDC SSO config for org {org_id!r}")
    try:
        claims = _oidc.verify_id_token(id_token, jwks_keys=jwks_keys, issuer=config.oidc_issuer,
                                       client_id=config.oidc_client_id, expected_nonce=expected_nonce,
                                       allowed_algs=config.oidc_signing_algs, now=now,
                                       skew=config.clock_skew_seconds)
    except _oidc.OidcError as e:
        raise SsoLoginError(f"OIDC id_token verification failed: {e}") from e
    sub = claims.get("sub")
    if not isinstance(sub, str) or not sub.strip():
        raise SsoLoginError("id_token has no usable sub claim")
    groups = claims.get(_OIDC_GROUPS_CLAIM)
    groups = tuple(g for g in groups if isinstance(g, str)) if isinstance(groups, list) else ()
    oid = claims.get(_OIDC_OBJECT_ID_CLAIM)
    link_ids = (oid,) if isinstance(oid, str) and oid.strip() else ()
    # `sub` / `oid` pass on EXACTLY as signed (never trimmed): `_login_principal` refuses a padded one
    return _login_principal(org_registry, config, subject=sub, link_ids=link_ids, groups=groups,
                            issued_at=now if issued_at is None else issued_at,
                            directory_registry=directory_registry, audit=audit)


# ---------------------------------------------------------------------------------------------------
# SCIM 2.0 — request plumbing.
# ---------------------------------------------------------------------------------------------------

def _error(status: int, detail: str, scim_type: str = "") -> dict:
    body = {"schemas": [_SCHEMA_ERROR], "status": str(int(status)), "detail": str(detail)[:300]}
    if scim_type:
        body["scimType"] = scim_type
    return body


def _parse_resource_path(path: str) -> "Optional[tuple[str, Optional[str]]]":
    """(`Users`|`Groups`|..., id-or-None) from a SCIM path (`/Users`, `/Users/<id>`, or the same under any prefix
    such as `/scim/v2/<org>`). None for an unknown endpoint or a deeper path (fail-closed)."""
    p = str(path or "").split("?", 1)[0]
    segs = [s for s in p.split("/") if s]
    for i, s in enumerate(segs):
        if s in _RESOURCES:
            rest = segs[i + 1:]
            if not rest:
                return s, None
            if len(rest) == 1:
                rid = urllib.parse.unquote(rest[0])
                return (s, rid) if rid and len(rid) <= 512 else None
            return None
    return None


def _query(query: object) -> "dict[str, str]":
    """The query parameters (first value each; a repeated parameter is refused as ambiguous)."""
    try:
        q = urllib.parse.parse_qs(str(query or ""), keep_blank_values=True, strict_parsing=False)
    except ValueError:
        raise _ScimFail(400, "malformed query string", "invalidSyntax")
    out: "dict[str, str]" = {}
    for k, v in q.items():
        if len(v) != 1:
            raise _ScimFail(400, f"query parameter {k!r} given more than once", "invalidSyntax")
        out[k] = v[0]
    return out


_FILTER_RE = re.compile(r'^\s*([A-Za-z][A-Za-z0-9:._-]*)\s+(eq)\s+("(?:[^"\\]|\\.)*")\s*$', re.IGNORECASE)


def _strip_schema(attr: str, schema: str) -> str:
    a = str(attr or "").strip()
    if a.lower().startswith(schema.lower() + ":"):
        a = a[len(schema) + 1:]
    return a


def _parse_filter(flt: Optional[str], allowed: "frozenset[str]", schema: str) -> "Optional[tuple[str, str]]":
    """The ONE filter form IdPs use for reconciliation — `<attr> eq "<value>"` — as (lower-case attr, value). Any
    other expression (and/or/not, co/sw/pr, an attribute we do not index) is a 400 invalidFilter, never a silently
    unfiltered list (an IdP reading "all users" for "does x exist?" would link the wrong person)."""
    if flt is None or not str(flt).strip():
        return None
    m = _FILTER_RE.match(str(flt))
    if not m:
        raise _ScimFail(400, "unsupported filter (only `<attribute> eq \"<value>\"` is supported)", "invalidFilter")
    attr = _strip_schema(m.group(1), schema).lower()
    if attr not in allowed:
        raise _ScimFail(400, f"filtering on {m.group(1)!r} is not supported", "invalidFilter")
    try:
        value = json.loads(m.group(3))
    except ValueError:
        raise _ScimFail(400, "malformed filter value", "invalidFilter")
    return attr, str(value)


def _page(items: list, q: "dict[str, str]") -> "tuple[list, int]":
    def _int(v: Optional[str], default: int) -> int:
        try:
            return int(str(v).strip()) if v is not None and str(v).strip() else default
        except ValueError:
            raise _ScimFail(400, "startIndex/count must be integers", "invalidValue")
    start = max(1, _int(q.get("startIndex"), 1))
    count = max(0, min(_int(q.get("count"), MAX_RESULTS), MAX_RESULTS))
    return items[start - 1:start - 1 + count], start


def _list_response(resources: list, *, total: int, start: int) -> dict:
    return {"schemas": [_SCHEMA_LIST], "totalResults": int(total), "startIndex": int(start),
            "itemsPerPage": len(resources), "Resources": resources}


def _as_bool(v: object) -> Optional[bool]:
    """SCIM `active` as sent by real IdPs: a JSON bool, or (Entra) the strings "True"/"False". Else None."""
    if isinstance(v, bool):
        return v
    if isinstance(v, str) and v.strip().lower() in ("true", "false"):
        return v.strip().lower() == "true"
    return None


def _expect_object(body: object) -> dict:
    if not isinstance(body, dict):
        raise _ScimFail(400, "the request body must be a JSON object", "invalidSyntax")
    return body


def _iso(epoch: float) -> Optional[str]:
    try:
        if epoch and math.isfinite(epoch) and epoch > 0:
            return datetime.fromtimestamp(float(epoch), tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    except (OverflowError, OSError, ValueError):
        return None
    return None


class _Req:
    """One authenticated SCIM request for one org: the owner-signed config, the per-request org view, the org's
    directory view, a strictly increasing issued_at clock, the critical-audit hook, and the revoked usernames."""

    def __init__(self, config: SsoConfig, orgs: _RequestOrgs, directory: OrgDirectory, *,
                 at: "Callable[[], float]", audit: Optional[AuditFn]) -> None:
        self.config = config
        self.orgs = orgs
        self.dir = directory
        self.at = at
        self._audit = audit
        self.deactivated: "list[str]" = []

    def audit(self, action: str, target: str, outcome: str) -> None:
        if self._audit is not None:
            self._audit(action, target, outcome)

    def role(self, uid: str) -> Optional[str]:
        return self.orgs.membership_role(uid, self.config.org_id)


# ---------------------------------------------------------------------------------------------------
# Membership reconciliation — the ONLY place SCIM changes authority (through the ceiling-gated mint).
# ---------------------------------------------------------------------------------------------------

def _revoke(req: _Req, uid: str) -> None:
    current = req.role(uid)
    if current is not None:
        req.audit("scim_deactivate", uid, f"was={current}")
        _scim.deactivate_membership(req.orgs, req.config, username=uid)
    if uid not in req.deactivated:
        req.deactivated.append(uid)


def _reconcile(req: _Req, uid: str, *, create: bool) -> None:
    """Make `uid`'s membership match the directory: inactive/deleted ⇒ revoke; active ⇒ the role the owner-signed
    config resolves for its selectors + group names (minted only when it changes). `create` is True for a
    user-level write (the user is being provisioned) and False for a group change (which re-roles existing members
    but never creates one). An owner-set role outside the ceiling is never re-granted here."""
    u = req.dir.user(uid)
    if u is None or not u.active:
        _revoke(req, uid)
        return
    current = req.role(uid)
    if current is not None and current not in _scim.SCIM_PROVISIONABLE_ROLES:
        return
    if current is None and not create:
        return
    role = _directory_role(req.config, req.dir, u)
    if role is None:
        raise _ScimFail(400, "no provisionable role resolves for this user (fail-closed)", "invalidValue")
    if role == current:
        return
    req.audit("scim_grant", uid, f"role={role}")
    _scim.provision_membership(req.orgs, req.config, username=uid, role=role, issued_at=req.at())


# ---------------------------------------------------------------------------------------------------
# Users
# ---------------------------------------------------------------------------------------------------

_USER_FILTERS = frozenset({"username", "externalid", "id", "displayname"})
_GROUP_FILTERS = frozenset({"displayname", "externalid", "id"})


def _selectors_from(resource: dict) -> list:
    """The role selectors carried on a User resource: `groups[].display|value` and `roles[].value|display` (the
    governor's bounded reader). They only SELECT among the owner-signed map — never a role by themselves."""
    return list(_scim._group_selectors(resource))


def _profile_from(resource: dict) -> dict:
    out: dict = {}
    if isinstance(resource.get("name"), dict):
        out["name"] = resource["name"]
    if isinstance(resource.get("emails"), list):
        out["emails"] = resource["emails"]
    return out


def _identifier(value: object, what: str) -> str:
    """A user's link identifier (`userName` / `externalId`) EXACTLY as the IdP sent it — never trimmed: one that
    begins or ends with whitespace (any Unicode space) is refused, so a padded look-alike of a member's identifier is
    never trimmed INTO it (and so neither linked to that member at sign-in nor collided with it here)."""
    s = str(value or "")
    if s != s.strip():
        raise _ScimFail(400, f"{what} must not begin or end with whitespace", "invalidValue")
    return s


def _user_state_from(resource: dict) -> dict:
    active = resource.get("active", True)
    b = _as_bool(active)
    if b is None:
        raise _ScimFail(400, "active must be a boolean", "invalidValue")
    return {"user_name": _identifier(resource.get("userName"), "userName"),
            "external_id": _identifier(resource.get("externalId"), "externalId"),
            "display_name": str(resource.get("displayName") or "").strip(),
            "active": b, "selectors": _selectors_from(resource), "profile": _profile_from(resource)}


def _user_resource(req: _Req, u: DirectoryUser) -> dict:
    out: dict = {"schemas": [_SCHEMA_USER], "id": u.id, "userName": u.user_name, "active": bool(u.active)}
    if u.external_id:
        out["externalId"] = u.external_id
    if u.display_name:
        out["displayName"] = u.display_name
    for k in ("name", "emails"):
        if u.profile.get(k):
            out[k] = u.profile[k]
    out["groups"] = [{"value": g.id, "display": g.display_name, "type": "direct"} for g in req.dir.groups_of(u.id)]
    role = req.role(u.id) if u.active else None
    out["roles"] = [{"value": role}] if role else []
    meta: dict = {"resourceType": "User"}
    lm = _iso(u.issued_at)
    if lm:
        meta["lastModified"] = lm
    out["meta"] = meta
    return out


def _put_user(req: _Req, uid: str, st: dict) -> None:
    if not st["user_name"]:
        raise _ScimFail(400, "userName is required", "invalidValue")
    other = req.dir.user_by_name(st["user_name"])
    if other is not None and other.id != uid:
        raise _ScimFail(409, "a user with this userName already exists", "uniqueness")
    cur = req.dir.user(uid)
    try:
        req.dir.put_user(uid, user_name=st["user_name"], external_id=st["external_id"],
                         display_name=st["display_name"], active=st["active"], selectors=st["selectors"],
                         profile=st["profile"], clamp=cur.clamp if cur is not None else (),   # sign-in bookkeeping
                         now=req.at())
    except DirectoryError as e:
        raise _ScimFail(400, str(e), "invalidValue") from e


def _user_create(req: _Req, body: object) -> ScimResult:
    st = _user_state_from(_expect_object(body))
    if not st["user_name"] and st["external_id"]:
        st["user_name"] = st["external_id"]               # lenient: an externalId-only push still names the user
    if not st["user_name"]:
        raise _ScimFail(400, "userName is required", "invalidValue")
    if req.dir.user_by_name(st["user_name"]) is not None:
        raise _ScimFail(409, "a user with this userName already exists", "uniqueness")
    uid = _scim.sso_username(req.config, st["external_id"] or st["user_name"])
    if not uid:
        raise _ScimFail(400, "the user has no usable identifier", "invalidValue")
    if req.dir.user(uid) is not None:
        raise _ScimFail(409, "a user with this externalId already exists", "uniqueness")
    _put_user(req, uid, st)
    _reconcile(req, uid, create=True)
    return ScimResult(201, _user_resource(req, req.dir.user(uid)))  # type: ignore[arg-type]


def _user_replace(req: _Req, uid: str, body: object) -> ScimResult:
    if req.dir.user(uid) is None:
        raise _ScimFail(404, "no such user in this organization")
    st = _user_state_from(_expect_object(body))
    _put_user(req, uid, st)
    _reconcile(req, uid, create=True)
    return ScimResult(200, _user_resource(req, req.dir.user(uid)))  # type: ignore[arg-type]


_PATH_FILTER_RE = re.compile(r'^([A-Za-z][A-Za-z0-9._-]*)\[\s*([A-Za-z][A-Za-z0-9._-]*)\s+eq\s+'
                             r'("(?:[^"\\]|\\.)*")\s*\](?:\.([A-Za-z][A-Za-z0-9._-]*))?$', re.IGNORECASE)


def _patch_ops(body: object) -> list:
    b = _expect_object(body)
    ops = b.get("Operations")
    if not isinstance(ops, list) or not ops:
        raise _ScimFail(400, "a PATCH needs a non-empty Operations list", "invalidSyntax")
    if len(ops) > MAX_PATCH_OPS:
        raise _ScimFail(400, f"at most {MAX_PATCH_OPS} PATCH operations per request", "tooMany")
    out = []
    for op in ops:
        if not isinstance(op, dict):
            raise _ScimFail(400, "each PATCH operation must be an object", "invalidSyntax")
        kind = str(op.get("op") or "").strip().lower()
        if kind not in ("add", "replace", "remove"):
            raise _ScimFail(400, f"unknown PATCH op {op.get('op')!r}", "invalidSyntax")
        path = op.get("path")
        if path is not None and not isinstance(path, str):
            raise _ScimFail(400, "a PATCH path must be a string", "invalidPath")
        out.append((kind, (path or "").strip(), op.get("value")))
    return out


def _set_email(st: dict, kind: str, typ: str, value: object) -> None:
    emails = [dict(e) for e in (st["profile"].get("emails") or []) if isinstance(e, dict)]
    emails = [e for e in emails if str(e.get("type", "")).lower() != typ.lower()]
    if kind != "remove" and isinstance(value, str) and value.strip():
        emails.append({"value": value.strip(), "type": typ})
    st["profile"] = {**st["profile"], "emails": emails}


def _user_apply(st: dict, kind: str, path: str, value: object) -> None:
    """Apply ONE PATCH operation to a user's state. Attribute names are case-insensitive (RFC 7643 §2.1). The
    attributes this service keeps are applied; any other attribute (enterprise extension, title, ...) is accepted
    and not stored — rejecting it would stall a real IdP's whole sync over a field VIGIL never uses."""
    raw = _strip_schema(path, _SCHEMA_USER)
    m = _PATH_FILTER_RE.match(raw)
    if m:                                                   # e.g. emails[type eq "work"].value
        if m.group(1).lower() == "emails" and m.group(2).lower() == "type":
            try:
                typ = str(json.loads(m.group(3)))
            except ValueError:
                raise _ScimFail(400, "malformed PATCH path filter", "invalidPath")
            _set_email(st, kind, typ, value)
        return
    a = raw.lower()
    if a == "active":
        if kind == "remove":
            return
        b = _as_bool(value)
        if b is None:
            raise _ScimFail(400, "active must be a boolean", "invalidValue")
        st["active"] = b
    elif a == "username":
        if kind == "remove" or not isinstance(value, str) or not value.strip():
            raise _ScimFail(400, "userName is required and cannot be removed", "invalidValue")
        st["user_name"] = _identifier(value, "userName")
    elif a == "externalid":
        st["external_id"] = "" if kind == "remove" else _identifier(value if isinstance(value, str) else "",
                                                                    "externalId")
    elif a == "displayname":
        st["display_name"] = "" if kind == "remove" else str(value if isinstance(value, str) else "").strip()
    elif a in ("roles", "groups"):
        vals = list(_scim._group_selectors({"roles": value if isinstance(value, list) else [value]}))
        if kind == "replace":
            st["selectors"] = vals
        elif kind == "add":
            st["selectors"] = list(dict.fromkeys([*st["selectors"], *vals]))
        else:
            st["selectors"] = [s for s in st["selectors"] if s not in vals] if value is not None else []
    elif a == "name":
        st["profile"] = {**st["profile"], "name": value if (kind != "remove" and isinstance(value, dict)) else {}}
    elif a.startswith("name."):
        name = dict(st["profile"].get("name") or {})
        sub = raw.split(".", 1)[1]
        if kind == "remove":
            name.pop(sub, None)
        elif isinstance(value, str):
            name[sub] = value
        st["profile"] = {**st["profile"], "name": name}
    elif a == "emails":
        st["profile"] = {**st["profile"], "emails": value if (kind != "remove" and isinstance(value, list)) else []}


def _user_patch(req: _Req, uid: str, body: object) -> ScimResult:
    cur = req.dir.user(uid)
    if cur is None:
        raise _ScimFail(404, "no such user in this organization")
    st = {"user_name": cur.user_name, "external_id": cur.external_id, "display_name": cur.display_name,
          "active": cur.active, "selectors": list(cur.selectors), "profile": dict(cur.profile)}
    for kind, path, value in _patch_ops(body):
        if not path:
            if kind == "remove":
                raise _ScimFail(400, "a remove operation needs a path", "noTarget")
            if not isinstance(value, dict):
                raise _ScimFail(400, "a PATCH without a path needs an object value", "invalidValue")
            for k, v in value.items():
                _user_apply(st, kind, str(k), v)
        else:
            _user_apply(st, kind, path, value)
    _put_user(req, uid, st)
    _reconcile(req, uid, create=True)
    return ScimResult(200, _user_resource(req, req.dir.user(uid)))  # type: ignore[arg-type]


def _user_delete(req: _Req, uid: str) -> ScimResult:
    if req.dir.user(uid) is None:
        raise _ScimFail(404, "no such user in this organization")
    req.dir.delete_user(uid, now=req.at())
    _revoke(req, uid)
    return ScimResult(204, None)


def _user_match(u: DirectoryUser, attr: str, value: str) -> bool:
    if attr == "username":
        return username_key(u.user_name) == username_key(value)       # letter case only, never a look-alike
    if attr == "externalid":
        return u.external_id == value
    if attr == "id":
        return u.id == value
    return u.display_name.casefold() == value.casefold()


def _users(req: _Req, method: str, rid: Optional[str], body: object, q: "dict[str, str]") -> ScimResult:
    if rid is None:
        if method == "GET":
            flt = _parse_filter(q.get("filter"), _USER_FILTERS, _SCHEMA_USER)
            users = [u for u in req.dir.users() if flt is None or _user_match(u, *flt)]
            page, start = _page(users, q)
            return ScimResult(200, _list_response([_user_resource(req, u) for u in page], total=len(users),
                                                  start=start))
        if method == "POST":
            return _user_create(req, body)
        raise _ScimFail(405, f"{method} is not allowed on /Users")
    if method == "GET":
        u = req.dir.user(rid)
        if u is None:
            raise _ScimFail(404, "no such user in this organization")
        return ScimResult(200, _user_resource(req, u))
    if method == "PUT":
        return _user_replace(req, rid, body)
    if method == "PATCH":
        return _user_patch(req, rid, body)
    if method == "DELETE":
        return _user_delete(req, rid)
    raise _ScimFail(405, f"{method} is not allowed on a User")


# ---------------------------------------------------------------------------------------------------
# Groups
# ---------------------------------------------------------------------------------------------------

def _member_ref(req: _Req, uid: str) -> dict:
    u = req.dir.user(uid)
    return {"value": uid, "display": u.user_name if u is not None else uid, "type": "User"}


def _group_resource(req: _Req, gid: str, *, members: bool = True) -> dict:
    g = req.dir.group(gid)
    if g is None:
        raise _ScimFail(404, "no such group in this organization")
    out: dict = {"schemas": [_SCHEMA_GROUP], "id": g.id, "displayName": g.display_name}
    if g.external_id:
        out["externalId"] = g.external_id
    if members:
        out["members"] = [_member_ref(req, uid) for uid in req.dir.members(gid)]
    meta: dict = {"resourceType": "Group"}
    lm = _iso(g.issued_at)
    if lm:
        meta["lastModified"] = lm
    out["meta"] = meta
    return out


def _member_ids(value: object) -> "list[str]":
    """The user ids named by a SCIM `members` value (a list of {value: id} or one such object)."""
    items = value if isinstance(value, list) else ([value] if isinstance(value, dict) else [])
    if len(items) > MAX_MEMBER_VALUES:
        raise _ScimFail(400, f"at most {MAX_MEMBER_VALUES} member references per request", "tooMany")
    out: "list[str]" = []
    for it in items:
        v = it.get("value") if isinstance(it, dict) else None
        if not isinstance(v, str) or not v.strip():
            raise _ScimFail(400, "each member needs a string value (the user id)", "invalidValue")
        if v.strip() not in out:
            out.append(v.strip())
    return out


def _excluded(q: "dict[str, str]") -> "set[str]":
    return {a.strip().lower() for a in str(q.get("excludedAttributes") or "").split(",") if a.strip()}


def _rename_group(req: _Req, gid: str, name: object) -> None:
    if not isinstance(name, str) or not name.strip():
        raise _ScimFail(400, "displayName is required", "invalidValue")
    other = req.dir.group_by_name(name)
    if other is not None and other.id != gid:
        raise _ScimFail(409, "a group with this displayName already exists", "uniqueness")
    g = req.dir.group(gid)
    try:
        req.dir.put_group(gid, display_name=name.strip(), external_id=g.external_id if g else "", now=req.at())
    except DirectoryError as e:
        raise _ScimFail(400, str(e), "invalidValue") from e


def _set_group_external_id(req: _Req, gid: str, ext: str) -> None:
    g = req.dir.group(gid)
    if g is None:
        return
    try:
        req.dir.put_group(gid, display_name=g.display_name, external_id=ext, now=req.at())
    except DirectoryError as e:
        raise _ScimFail(400, str(e), "invalidValue") from e


def _add_members(req: _Req, gid: str, uids, touched: set) -> None:
    for uid in uids:
        if req.dir.add_member(gid, uid, now=req.at()):        # an id not in THIS org's directory adds nothing
            touched.add(uid)


def _remove_members(req: _Req, gid: str, uids, touched: set) -> None:
    for uid in uids:
        if req.dir.remove_member(gid, uid, now=req.at()):
            touched.add(uid)


def _replace_members(req: _Req, gid: str, uids, touched: set) -> None:
    want = set(uids)
    _remove_members(req, gid, [u for u in req.dir.members(gid) if u not in want], touched)
    _add_members(req, gid, [u for u in uids if u not in set(req.dir.members(gid))], touched)


def _group_create(req: _Req, body: object) -> ScimResult:
    b = _expect_object(body)
    name = b.get("displayName")
    if not isinstance(name, str) or not name.strip():
        raise _ScimFail(400, "displayName is required", "invalidValue")
    if req.dir.group_by_name(name) is not None:
        raise _ScimFail(409, "a group with this displayName already exists", "uniqueness")
    gid = "grp_" + secrets.token_hex(12)
    try:
        req.dir.put_group(gid, display_name=name.strip(), external_id=str(b.get("externalId") or ""), now=req.at())
    except DirectoryError as e:
        raise _ScimFail(400, str(e), "invalidValue") from e
    touched: set = set()
    _add_members(req, gid, _member_ids(b.get("members") or []), touched)
    for uid in sorted(touched):
        _reconcile(req, uid, create=False)
    return ScimResult(201, _group_resource(req, gid))


def _group_replace(req: _Req, gid: str, body: object) -> ScimResult:
    if req.dir.group(gid) is None:
        raise _ScimFail(404, "no such group in this organization")
    b = _expect_object(body)
    before = set(req.dir.members(gid))
    _rename_group(req, gid, b.get("displayName"))
    _set_group_external_id(req, gid, str(b.get("externalId") or ""))
    touched: set = set()
    _replace_members(req, gid, _member_ids(b.get("members") or []), touched)
    for uid in sorted(before | touched):                      # a rename re-roles every member
        _reconcile(req, uid, create=False)
    return ScimResult(200, _group_resource(req, gid))


def _group_patch(req: _Req, gid: str, body: object, q: "dict[str, str]") -> ScimResult:
    if req.dir.group(gid) is None:
        raise _ScimFail(404, "no such group in this organization")
    before = set(req.dir.members(gid))
    touched: set = set()
    renamed = False
    for kind, path, value in _patch_ops(body):
        raw = _strip_schema(path, _SCHEMA_GROUP)
        a = raw.lower()
        m = _PATH_FILTER_RE.match(raw)
        if m and m.group(1).lower() == "members" and m.group(2).lower() == "value" and not m.group(4):
            if kind != "remove":
                raise _ScimFail(400, "only remove is supported on a filtered members path", "invalidPath")
            try:
                _remove_members(req, gid, [str(json.loads(m.group(3)))], touched)
            except ValueError:
                raise _ScimFail(400, "malformed members path filter", "invalidPath")
        elif a == "members":
            if kind == "add":
                _add_members(req, gid, _member_ids(value), touched)
            elif kind == "replace":
                _replace_members(req, gid, _member_ids(value), touched)
            else:
                ids = _member_ids(value) if value is not None else req.dir.members(gid)
                _remove_members(req, gid, ids, touched)
        elif a == "displayname":
            if kind == "remove":
                raise _ScimFail(400, "displayName is required and cannot be removed", "invalidValue")
            _rename_group(req, gid, value)
            renamed = True
        elif a == "externalid":
            _set_group_external_id(req, gid, "" if kind == "remove" else str(value or ""))
        elif not a:
            if kind == "remove":
                raise _ScimFail(400, "a remove operation needs a path", "noTarget")
            if not isinstance(value, dict):
                raise _ScimFail(400, "a PATCH without a path needs an object value", "invalidValue")
            for k, v in value.items():
                kk = _strip_schema(str(k), _SCHEMA_GROUP).lower()
                if kk == "displayname":
                    _rename_group(req, gid, v)
                    renamed = True
                elif kk == "externalid":
                    _set_group_external_id(req, gid, str(v or ""))
                elif kk == "members":
                    (_replace_members if kind == "replace" else _add_members)(req, gid, _member_ids(v), touched)
        # any other attribute is accepted and not stored (see _user_apply)
    for uid in sorted((before | touched) if renamed else touched):
        _reconcile(req, uid, create=False)
    members = "members" not in _excluded(q)
    return ScimResult(200, _group_resource(req, gid, members=members))


def _group_delete(req: _Req, gid: str) -> ScimResult:
    if req.dir.group(gid) is None:
        raise _ScimFail(404, "no such group in this organization")
    was = req.dir.delete_group(gid, now=req.at())
    for uid in was:
        _reconcile(req, uid, create=False)
    return ScimResult(204, None)


def _group_match(req: _Req, gid: str, attr: str, value: str) -> bool:
    g = req.dir.group(gid)
    if g is None:
        return False
    if attr == "displayname":
        return g.display_name.casefold() == value.casefold()
    if attr == "externalid":
        return g.external_id == value
    return g.id == value


def _groups(req: _Req, method: str, rid: Optional[str], body: object, q: "dict[str, str]") -> ScimResult:
    if rid is None:
        if method == "GET":
            flt = _parse_filter(q.get("filter"), _GROUP_FILTERS, _SCHEMA_GROUP)
            gids = [g.id for g in req.dir.groups() if flt is None or _group_match(req, g.id, *flt)]
            page, start = _page(gids, q)
            members = "members" not in _excluded(q)
            return ScimResult(200, _list_response([_group_resource(req, g, members=members) for g in page],
                                                  total=len(gids), start=start))
        if method == "POST":
            return _group_create(req, body)
        raise _ScimFail(405, f"{method} is not allowed on /Groups")
    if method == "GET":
        return ScimResult(200, _group_resource(req, rid, members="members" not in _excluded(q)))
    if method == "PUT":
        return _group_replace(req, rid, body)
    if method == "PATCH":
        return _group_patch(req, rid, body, q)
    if method == "DELETE":
        return _group_delete(req, rid)
    raise _ScimFail(405, f"{method} is not allowed on a Group")


# ---------------------------------------------------------------------------------------------------
# Discovery (RFC 7644 §4) — static descriptions of exactly what this service supports.
# ---------------------------------------------------------------------------------------------------

def service_provider_config() -> dict:
    return {"schemas": [_SCHEMA_SPC],
            "patch": {"supported": True},
            "bulk": {"supported": False, "maxOperations": 0, "maxPayloadSize": 0},
            "filter": {"supported": True, "maxResults": MAX_RESULTS},
            "changePassword": {"supported": False},
            "sort": {"supported": False},
            "etag": {"supported": False},
            "authenticationSchemes": [{"type": "oauthbearertoken", "name": "OAuth Bearer Token", "primary": True,
                                       "description": "A per-organization bearer token issued by the VIGIL "
                                                      "owner (rotatable; only its fingerprint is stored)"}],
            "meta": {"resourceType": "ServiceProviderConfig"}}


def _resource_types() -> "list[dict]":
    return [{"schemas": [_SCHEMA_RESOURCE_TYPE], "id": "User", "name": "User", "endpoint": "/Users",
             "schema": _SCHEMA_USER, "meta": {"resourceType": "ResourceType"}},
            {"schemas": [_SCHEMA_RESOURCE_TYPE], "id": "Group", "name": "Group", "endpoint": "/Groups",
             "schema": _SCHEMA_GROUP, "meta": {"resourceType": "ResourceType"}}]


def _attr(name: str, typ: str = "string", **kw) -> dict:
    a = {"name": name, "type": typ, "multiValued": False, "required": False, "caseExact": False,
         "mutability": "readWrite", "returned": "default", "uniqueness": "none"}
    a.update(kw)
    return a


def _schemas() -> "list[dict]":
    user = {"schemas": [_SCHEMA_SCHEMA], "id": _SCHEMA_USER, "name": "User", "description": "User Account",
            "attributes": [_attr("userName", required=True, uniqueness="server"),
                           _attr("externalId", caseExact=True), _attr("displayName"),
                           _attr("active", "boolean"),
                           _attr("name", "complex"), _attr("emails", "complex", multiValued=True),
                           _attr("roles", "complex", multiValued=True),
                           _attr("groups", "complex", multiValued=True, mutability="readOnly")],
            "meta": {"resourceType": "Schema"}}
    group = {"schemas": [_SCHEMA_SCHEMA], "id": _SCHEMA_GROUP, "name": "Group", "description": "Group",
             "attributes": [_attr("displayName", required=True, uniqueness="server"),
                            _attr("externalId", caseExact=True),
                            _attr("members", "complex", multiValued=True)],
             "meta": {"resourceType": "Schema"}}
    return [user, group]


def _discovery(resource: str, rid: Optional[str], method: str) -> ScimResult:
    if method != "GET":
        raise _ScimFail(405, f"{method} is not allowed on /{resource}")
    if resource == "ServiceProviderConfig":
        if rid is not None:
            raise _ScimFail(404, "unknown SCIM endpoint")
        return ScimResult(200, service_provider_config())
    items = _resource_types() if resource == "ResourceTypes" else _schemas()
    if rid is None:
        return ScimResult(200, _list_response(items, total=len(items), start=1))
    hit = next((i for i in items if i["id"] == rid), None)
    if hit is None:
        raise _ScimFail(404, f"no such {resource[:-1]}")
    return ScimResult(200, hit)


# ---------------------------------------------------------------------------------------------------
# The entry points.
# ---------------------------------------------------------------------------------------------------

def scim_dispatch(method: str, path: str, body: object, authorization: object, *, org_id: str,
                  config_registry, org_registry, now: float, query: str = "", directory_registry=None,
                  issued_at: Optional[float] = None, issued_at_fn: "Optional[Callable[[], float]]" = None,
                  audit: Optional[AuditFn] = None) -> ScimResult:
    """Handle one SCIM 2.0 request for `org_id`. FAIL-CLOSED order: resolve the org's OWNER-SIGNED config;
    authenticate the bearer (constant-time fingerprint compare, org-scoped) — uniformly BEFORE revealing anything
    about routing; then route Users / Groups / discovery. The caller (the provisioner) holds the spine lock for
    the whole request, so a multi-record change is one serialized step. `issued_at_fn` (default: a strictly
    increasing clock from `issued_at`/`now`) stamps each owner-signed record; `audit(action, username, detail)`
    is called BEFORE each membership grant / revoke (the provisioner makes it a critical, fail-closed audit)."""
    config = config_registry.config(org_id)
    presented: Optional[BearerToken] = bearer_from_authorization_header(authorization)
    if not _scim.authenticate_scim(config, presented):
        return ScimResult(401, _error(401, "SCIM authentication failed"))
    assert config is not None  # authenticate_scim returned True ⇒ config is present + scim_enabled
    m = str(method or "").upper()
    req: Optional[_Req] = None

    def revoked() -> tuple:            # a revoke that already landed in this request must still reach the edge
        return tuple(req.deactivated) if req is not None else ()

    try:
        parsed = _parse_resource_path(path)
        if parsed is None:
            raise _ScimFail(404, "unknown SCIM endpoint")
        resource, rid = parsed
        q = _query(query)
        if resource in ("ServiceProviderConfig", "ResourceTypes", "Schemas"):
            return _discovery(resource, rid, m)
        orgs = _RequestOrgs(org_registry, config.org_id)
        if orgs.org(config.org_id) is None and m in _MUTATING:
            raise _ScimFail(404, "this organization is not active")
        directory = _directory_registry(directory_registry, org_registry).directory(config.org_id)
        req = _Req(config, orgs, directory, at=issued_at_fn or _clock(issued_at, now), audit=audit)
        res = (_users if resource == "Users" else _groups)(req, m, rid, body, q)
        return ScimResult(res.status, res.body, revoked())
    except _ScimFail as e:
        return ScimResult(e.status, _error(e.status, e.detail, e.scim_type), revoked())
    except (ScimError, DirectoryError, SsoLoginError) as e:
        return ScimResult(400, _error(400, str(e), "invalidValue"), revoked())


def handle_scim_request(method: str, path: str, body: object, authorization: object, *, org_id: str,
                        config_registry, org_registry, now: float, issued_at: Optional[float] = None,
                        query: str = "", directory_registry=None) -> "tuple[int, dict]":
    """`scim_dispatch` returning `(http_status, response_dict)` (an empty dict for a 204)."""
    r = scim_dispatch(method, path, body, authorization, org_id=org_id, config_registry=config_registry,
                      org_registry=org_registry, now=now, query=query, directory_registry=directory_registry,
                      issued_at=issued_at)
    return r.status, (r.body if r.body is not None else {})
