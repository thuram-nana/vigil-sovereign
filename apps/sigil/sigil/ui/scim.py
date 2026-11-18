"""Consumer PR-H (Area 7) — the SCIM 2.0 protocol handler + the SSO-login JIT composition.

This is the END-TO-END glue: it turns a VERIFIED external identity (SAML via `ui.saml`, enterprise-OIDC via the
airtight `ui.oidc`, or a bearer-authenticated SCIM push) into an OWNER-SIGNED, CEILING-CAPPED membership, by:

  1. resolving the org's OWNER-SIGNED `governor.sso_config.SsoConfig` (the delegation),
  2. authenticating / verifying the inbound identity against THAT config (org-scoped),
  3. reading the role FROM the config (capped) via `governor.scim.resolve_role` — NEVER from the IdP claim,
  4. minting the membership through `governor.scim.provision_membership` (the ceiling-gated mint site).

Every function is a PURE request→result mapping (no sockets, no globals), so the whole surface is unit-testable
without a live server; the HTTP edge/provisioner only serialises the result. The owner key lives in the injected
`OrgRegistry` (the single unchanged key custody) — so these functions must run PROVISIONER-side.

ORG-SCOPED EVERYWHERE: the org is resolved from the SCIM bearer's config / the SSO ACS binding, and provisioning
always targets `config.org_id`. A caller never supplies a target org as a free field, so one org's SSO/SCIM can
never provision into another.

NO MONEY / NO FACT / NO MODEL-ID: this module provisions IDENTITY→ROLE memberships only. It mints no FACT (only
the oracle does), moves no money, and surfaces no model identifier.

INTEGRATION SEAM (the HTTP transport — owner-deploy topology, intentionally NOT wired in this slice). These
composition functions are the complete, tested provisioner-callable API: they take the owner-key `OrgRegistry`
and the `SsoConfigRegistry` as parameters, exactly as a `Provisioner` method would construct them
(`SsoConfigRegistry(self.store, owner_key=self.orgs.owner_key, ...)`, `org_registry=self.orgs`), all gated on
`config.customer_sso_enabled()`. What remains is pure transport + deployment: (a) a provisioner method + a
flag-gated `sso_*/scim_*` dispatch (mirroring `_redpen_dispatch`); (b) the KEYLESS EDGE exposing the public,
IdP-callable endpoints — a SAML ACS `POST`, an enterprise-OIDC callback (both like the existing
`/api/customer/oidc/*` edge routes), and a bearer-authenticated SCIM endpoint keyed by `org_id` in the path —
relaying to the provisioner over the hop key; and (c) the OWNER steps before go-live: register the IdP, publish
the public URLs, and provision the vetted XML-DSig backend (`ui.saml`) for SAML. These are deliberately left as
an honest, specified seam rather than wired to an endpoint that does not yet exist — the security-bearing logic
(verification, the role ceiling, org-scoping, capped owner-signed minting) is complete and tested here.

FATAL-2: SOVEREIGN-side, imports NO `framework` / `strix` (`assert_no_offense()` at import).
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from ..reuse import assert_no_offense

assert_no_offense()

from ..governor import scim as _scim  # noqa: E402
from ..governor.scim import BearerToken, ScimError, bearer_from_authorization_header  # noqa: E402
from ..governor.sso_config import SsoConfig  # noqa: E402

# The SCIM error / list / user schema urns (RFC 7643 / 7644).
_SCHEMA_ERROR = "urn:ietf:params:scim:api:messages:2.0:Error"
_SCHEMA_LIST = "urn:ietf:params:scim:api:messages:2.0:ListResponse"
_SCHEMA_USER = "urn:ietf:params:scim:schemas:core:2.0:User"

# The OIDC id_token claim an enterprise config reads group membership from (for role SELECTION only — the role
# still comes from the owner-signed config map). The common convention is a `groups` claim.
_OIDC_GROUPS_CLAIM = "groups"


@dataclass(frozen=True)
class ProvisionResult:
    """The outcome of a successful SSO/SCIM provisioning — identity + the CAPPED role actually granted + the
    spine seq of the owner-signed membership grant. Carries NO secret, NO money figure, NO model id."""
    org_id: str
    username: str
    role: str
    external_id: str
    seq: int


class SsoLoginError(Exception):
    """A fail-closed SSO-login refusal (no active config, verification failed, role denied). The route maps it to
    a 401; it never leaks assertion / token internals."""


# ---------------------------------------------------------------------------------------------------
# SSO login (JIT provisioning) — verify the identity, then mint a capped owner-signed membership.
# ---------------------------------------------------------------------------------------------------

def _provision_from_identity(org_registry, config: SsoConfig, *, external_id: str, groups, issued_at: float) -> ProvisionResult:
    """Shared tail for both SSO protocols: resolve the capped role from the owner-signed config (never the IdP
    claim), derive the stable per-org username, and mint the ceiling-gated owner-signed membership."""
    username = _scim.sso_username(config, external_id)
    if not username:
        raise SsoLoginError("the verified identity carries no usable subject")
    role = _scim.resolve_role(config, groups or ())
    if role is None:                                   # structurally impossible for a bind-time-valid config
        raise SsoLoginError("no provisionable role resolves for this identity (fail-closed)")
    try:
        seq = _scim.provision_membership(org_registry, config, username=username, role=role, issued_at=issued_at)
    except ScimError as e:                             # the ceiling gate / grant precondition refused
        raise SsoLoginError(str(e)) from e
    return ProvisionResult(org_id=config.org_id, username=username, role=role,
                           external_id=str(external_id), seq=seq)


def sso_login_saml(xml_bytes: bytes, *, org_id: str, config_registry, org_registry, replay_ledger,
                   now: float, sig_verifier=None, issued_at: Optional[float] = None) -> ProvisionResult:
    """Verify a SAML Response for `org_id` (`ui.saml.verify_saml_response` — structural/XSW/temporal/audience/
    replay sound; the crypto backend fail-closes without a vetted XML-DSig lib) and JIT-provision the capped
    owner-signed membership. FAIL-CLOSED on no active SAML config, a protocol mismatch, or any verification
    failure. The role comes from the OWNER-SIGNED config, never the assertion's attributes."""
    from . import saml as _saml
    config = config_registry.config(org_id)
    if config is None or config.protocol != "saml":
        raise SsoLoginError(f"no active SAML SSO config for org {org_id!r}")
    try:
        identity = _saml.verify_saml_response(xml_bytes, config=config, now=now, replay_ledger=replay_ledger,
                                              sig_verifier=sig_verifier)
    except _saml.SamlError as e:
        raise SsoLoginError(f"SAML verification failed: {e}") from e
    return _provision_from_identity(org_registry, config, external_id=identity.name_id,
                                    groups=identity.groups, issued_at=now if issued_at is None else issued_at)


def sso_login_oidc(id_token: str, *, org_id: str, config_registry, org_registry, jwks_keys, expected_nonce: str,
                   now: float, issued_at: Optional[float] = None) -> ProvisionResult:
    """Verify an enterprise-OIDC id_token for `org_id` (reusing the airtight `ui.oidc.verify_id_token` —
    signature-first, asymmetric-only, iss/aud/exp/nbf/nonce) against the org's OWNER-SIGNED OIDC config, then
    JIT-provision the capped owner-signed membership. FAIL-CLOSED on no active OIDC config or any verification
    failure. The username binds to the IMMUTABLE `sub`; groups come from the `groups` claim (role SELECTION
    only — the role itself is the owner-signed config's)."""
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
    return _provision_from_identity(org_registry, config, external_id=sub.strip(), groups=groups,
                                    issued_at=now if issued_at is None else issued_at)


# ---------------------------------------------------------------------------------------------------
# SCIM 2.0 request handler — pure (method, path, body, authorization) → (status, response dict).
# ---------------------------------------------------------------------------------------------------

def _error(status: int, detail: str) -> "tuple[int, dict]":
    return status, {"schemas": [_SCHEMA_ERROR], "status": str(status), "detail": detail}


def _user_resource(username: str, external_id: str, role: str, active: bool) -> dict:
    """Project a provisioned membership into a SCIM User resource (the response shape an IdP reconciles against).
    The `id` is the stable per-org `sso_username`. Carries the capped role as an inert attribute only."""
    return {"schemas": [_SCHEMA_USER], "id": username, "userName": username, "externalId": external_id,
            "active": bool(active), "roles": [{"value": role}] if role else []}


def _path_user_id(path: str) -> Optional[str]:
    """The `<id>` from a `.../Users/<id>` path, or None for the collection path. Fail-closed on a path that is
    not under `/Users`."""
    p = str(path or "").split("?", 1)[0].rstrip("/")
    marker = "/Users"
    idx = p.rfind(marker)
    if idx < 0:
        return None
    rest = p[idx + len(marker):]
    if not rest:
        return ""                          # the collection endpoint (.../Users)
    return rest.lstrip("/") or ""


def handle_scim_request(method: str, path: str, body: object, authorization: object, *, org_id: str,
                        config_registry, org_registry, now: float,
                        issued_at: Optional[float] = None) -> "tuple[int, dict]":
    """Handle one SCIM 2.0 request for `org_id`, returning `(http_status, response_dict)`. FAIL-CLOSED order:
    resolve the org's OWNER-SIGNED config; authenticate the bearer (constant-time fingerprint compare,
    org-scoped); then route POST/PUT/PATCH/DELETE/GET `Users` to the ceiling-gated owner-signed provisioning.
    An unauthenticated or unconfigured request gets 401/403; it NEVER leaks whether a token simply had the wrong
    value vs the org being unconfigured beyond the status. The role provisioned is always the owner-signed
    config's (capped) — a SCIM payload's groups only SELECT among it."""
    config = config_registry.config(org_id)
    presented: Optional[BearerToken] = bearer_from_authorization_header(authorization)
    # Authenticate FIRST (uniformly), before revealing anything about routing — fail-closed to 401.
    if not _scim.authenticate_scim(config, presented):
        return _error(401, "SCIM authentication failed")
    assert config is not None  # authenticate_scim returned True ⇒ config is present + scim_enabled
    at = now if issued_at is None else issued_at

    user_id = _path_user_id(path)
    if user_id is None:
        return _error(404, "unknown SCIM endpoint")
    m = str(method or "").upper()

    try:
        if m == "POST" and user_id == "":
            return _scim_create(config, org_registry, body, at)
        if m in ("PUT",) and user_id:
            return _scim_replace(config, org_registry, user_id, body, at)
        if m == "PATCH" and user_id:
            return _scim_patch(config, org_registry, user_id, body, at)
        if m == "DELETE" and user_id:
            return _scim_delete(config, org_registry, user_id)
        if m == "GET":
            return _scim_get(config, org_registry, user_id, now=now)
    except ScimError as e:
        return _error(400, str(e))
    except SsoLoginError as e:
        return _error(400, str(e))
    return _error(405, f"method {m} not allowed on this SCIM resource")


def _scim_create(config: SsoConfig, org_registry, body: object, issued_at: float) -> "tuple[int, dict]":
    user = _scim.parse_scim_user(body)
    if user is None:
        return _error(400, "invalid SCIM User resource (no userName/externalId)")
    if not user.active:
        # An inactive create is a no-op provision — acknowledge without minting a membership.
        username = _scim.sso_username(config, user.external_id) or ""
        return 201, _user_resource(username, user.external_id, "", active=False)
    res = _provision_from_identity(org_registry, config, external_id=user.external_id, groups=user.groups,
                                   issued_at=issued_at)
    return 201, _user_resource(res.username, res.external_id, res.role, active=True)


def _scim_replace(config: SsoConfig, org_registry, user_id: str, body: object,
                  issued_at: float) -> "tuple[int, dict]":
    user = _scim.parse_scim_user(body)
    if user is None:
        return _error(400, "invalid SCIM User resource")
    username = _scim.sso_username(config, user.external_id) or user_id
    if not user.active:
        _scim.deactivate_membership(org_registry, config, username=username)
        return 200, _user_resource(username, user.external_id, "", active=False)
    res = _provision_from_identity(org_registry, config, external_id=user.external_id, groups=user.groups,
                                   issued_at=issued_at)
    return 200, _user_resource(res.username, res.external_id, res.role, active=True)


def _patch_sets_inactive(body: object) -> bool:
    """True iff a SCIM PATCH body deactivates the user (`active:false`) — the common Okta/Azure deprovision op,
    expressed either as `{"op":"replace","value":{"active":false}}` or `{"op":"replace","path":"active",
    "value":false}`. Any other patch is treated as a no-op-with-ack (we provision roles from the config, not from
    arbitrary attribute writes)."""
    if not isinstance(body, dict):
        return False
    for op in body.get("Operations") or ():
        if not isinstance(op, dict) or str(op.get("op", "")).lower() != "replace":
            continue
        val = op.get("value")
        path = str(op.get("path", "")).strip().lower()
        if path == "active" and _is_false(val):
            return True
        if isinstance(val, dict) and "active" in val and _is_false(val.get("active")):
            return True
    return False


def _is_false(v: object) -> bool:
    if isinstance(v, bool):
        return v is False
    if isinstance(v, str):
        return v.strip().lower() in ("false", "0", "no")
    return False


def _scim_patch(config: SsoConfig, org_registry, user_id: str, body: object,
                issued_at: float) -> "tuple[int, dict]":
    if _patch_sets_inactive(body):
        _scim.deactivate_membership(org_registry, config, username=user_id)
        return 200, _user_resource(user_id, user_id, "", active=False)
    # A non-deactivating patch: acknowledge current state (roles stay the owner-signed config's; we do not take
    # a role from an arbitrary attribute write).
    return 200, _user_resource(user_id, user_id, "", active=True)


def _scim_delete(config: SsoConfig, org_registry, user_id: str) -> "tuple[int, dict]":
    _scim.deactivate_membership(org_registry, config, username=user_id)
    return 204, {}


def _scim_get(config: SsoConfig, org_registry, user_id: str, *, now: float) -> "tuple[int, dict]":
    """Reconcile reads. GET `/Users/<id>` returns the user's current membership (404 if not an active SSO member
    of this org); GET `/Users` returns a ListResponse of the org's active SSO-provisioned members. Only this
    org's memberships are ever visible (org-scoped)."""
    members = org_registry.memberships(config.org_id)
    sso_members = {m.username: m.role for m in members if str(m.username).startswith("sso_")}
    if user_id == "":
        resources = [_user_resource(u, u, r, active=True) for u, r in sorted(sso_members.items())]
        return 200, {"schemas": [_SCHEMA_LIST], "totalResults": len(resources),
                     "startIndex": 1, "itemsPerPage": len(resources), "Resources": resources}
    role = sso_members.get(user_id)
    if role is None:
        return _error(404, "no such provisioned user in this org")
    return 200, _user_resource(user_id, user_id, role, active=True)
