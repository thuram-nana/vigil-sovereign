"""Consumer PR-H (Area 7) — the OWNER-SIGNED per-org SSO / SCIM CONFIGURATION (the delegation record).

This is the greenfield SSO/SCIM substrate `governor/orgs.py` explicitly DEFERRED, built to the resolution that
module's DEFERRED note prescribes:

    "A later slice must resolve it by having the owner (or an owner-signed delegation) SIGN each provisioned
     membership, never by trusting an IdP assertion as authority."

So SSO/SCIM here is NOT "take a role from an IdP claim". It is:

  1. the OWNER signs, per org, an `SsoConfig` — the DELEGATION: "org X trusts IdP Y (its SAML cert / OIDC
     issuer), SCIM pushes bearing token-fingerprint F may provision members, and an authenticated identity maps
     to role R via this group→role map, CAPPED at `role_cap`." This record IS the owner-signed delegation.
  2. an SSO login / SCIM push only proves WHO the user is (identity, never authority — the `ui.oidc` doctrine).
  3. the provisioner (`governor.scim`) then mints an OWNER-SIGNED membership (`governor.orgs.grant_membership`)
     whose ROLE is read FROM THIS owner-signed config (capped), never from the IdP claim.

THE ROLE CEILING IS ABSOLUTE (the security invariant of this PR). An SSO/SCIM-provisionable role is drawn ONLY
from `_SSO_PROVISIONABLE = {viewer, analyst, org_admin}`. It can NEVER be `operator`, `founder`, `owner`, nor
carry `manage_code` / `run_engagement` / `offense_authority` / any money-or-offense permission — those stay the
separately owner-signed authority (orgs.grant_membership for founder, the owner key itself for owner-tier). The
ceiling is enforced HERE at config BINDING time (`_check_provisionable_role`) — the FIRST of three independent
refusals; `governor.scim` re-enforces it at MINT time (second), and it mints only through a capped helper that
never passes a non-ceiling role to `grant_membership` (third). "Prefer two independent refusals."

ORG-SCOPED BY CONSTRUCTION: a config is keyed by `org_id`, and the SAML audience / OIDC issuer / SCIM token
fingerprint it carries are THIS org's. So one org's SSO can never authenticate into another: an assertion whose
audience is org A's SP entity-id fails org B's audience check; a SCIM token's fingerprint is in exactly one
org's config; and provisioning always targets `config.org_id`, never a client-supplied org.

TRUST CONSTRUCTION (mirrors `governor.orgs` / `accounts` EXACTLY — this is NOT a new key custody):
  * `set_config` = the DANGEROUS direction — honored only if OWNER-SIGNED (`verify_signed`) AND its `issued_at`
    STRICTLY exceeds the per-org high-water (anti-replay / anti-rollback of a rotated cert/token/map).
  * `revoke_config` = the SAFE direction — honored even UNSIGNED, fixed `issued_at` 0.0 (a replayed revoke merely
    re-revokes); gating the fail-safe direction would make it fail OPEN.
  * owner-key-succession-aware verify (`key_history.key_resolver(...).at(seq)`), identical to `orgs._fold_*`.

FATAL-2: SOVEREIGN-side, imports NO `framework` / `strix` (`assert_no_offense()` at import). It reuses only the
shared role vocabulary (`vigil_core.rbac`), the sovereign crypto primitives, and `cryptography` for X.509 cert
validation of a SAML IdP signing cert — exactly the dependency set `ui.oidc` already draws on.

HARD-PRUNE RESIDUAL (honest boundary — see `honest_todo`): unlike `orgs._fold_*`, this fold does a full genesis
scan with NO snapshot seed (adding one would require schema changes to `spine.snapshot` + `spine.prune`, outside
this slice's four files). The per-org LWW high-water therefore holds across the LIVE window but would RESET if a
hard prune removed a config's grant below its high-water, re-opening replay of a captured OLD config. That
residual can at worst reinstate a ROTATED-OUT IdP cert/token/group-map — it can NEVER exceed the role ceiling
(the ceiling is re-enforced structurally at mint time in `governor.scim`, independent of any config), so the
money/offense authority is never at risk from it. The SSO/SCIM flag is OFF by default regardless.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional

from ..reuse import assert_no_offense, sha256_hex

assert_no_offense()

# The ceiling roles below are a SUBSET of the ONE shared role vocabulary (`vigil_core.rbac`) — reused, never
# redefined. A lockstep test (`test_sso_config`) asserts every provisionable role is a real rbac role carrying
# none of the forbidden money/offense permissions, so this module needs no runtime import of the table.
from . import key_history as _kh  # noqa: E402  (owner-key-succession-aware resolver, mirrors orgs._fold_*)
from .authn import NO_HIGHWATER, as_issued_at, signed_payload, verify_signed  # noqa: E402
from .identity import owner_keypair, owner_pubkey  # noqa: E402

# Dedicated payload signal under the enforced generic `kind="event"` governor record (mirrors orgs' signals) so
# no new write-path kind must be registered; the signal disambiguates the fold.
SSO_CONFIG_SIGNAL = "governor.sso_config"

# ===================================================================================================
# THE ROLE CEILING (security invariant #1). SSO/SCIM may provision ONLY these per-org roles. This set is
# declared INDEPENDENTLY here and again in `governor.scim` (a second, independent refusal at mint time); a
# lockstep test asserts the two literals are equal, so a drift is caught WITHOUT either gate depending on the
# other. Every entry MUST be a real `vigil_core.rbac` role AND must carry NONE of the forbidden permissions
# below — a lockstep test proves that too, so adding a money/offense permission to one of these roles upstream
# would fail the build rather than silently widen what SSO can grant.
# ===================================================================================================
SSO_PROVISIONABLE_ROLES = frozenset({"viewer", "analyst", "org_admin"})

# Permissions SSO/SCIM must NEVER be able to confer, however the role vocabulary evolves. `manage_code`,
# `run_engagement`, `offense_authority` and `view_assessments` are the testing/offense ceiling; `manage_org`/
# `manage_users`/`promote`/`secrets`/`kill_release`/`approve_a2`/`approve_a3`/`toggle_*`/`config_nonsecret` are
# the owner-governance ceiling. A provisionable role that ever carried any of these would breach the money/offense
# single-owner ceiling — a lockstep test forbids it. NOTE this is DISJOINT from the per-org billing/membership
# permissions (`manage_billing`/`manage_members`/`manage_monitoring`/`view_*`): those are `org_admin`'s intended
# TENANT-SCOPED authority (the owner-approved tenant admin manages THEIR org's billing/members), which is exactly
# why `org_admin` is provisionable. The forbidden set is the OWNER/offense authority, never a tenant's own
# billing. `queue_proposal` is `analyst`'s benign propose-only capability and is NOT forbidden.
SSO_FORBIDDEN_PERMISSIONS = frozenset({
    "run_engagement", "manage_code", "offense_authority", "view_assessments", "approve_a2", "approve_a3",
    "toggle_guard", "toggle_protected_guard", "config_nonsecret", "promote", "secrets", "kill_release",
    "manage_users", "manage_org",
})

# The two protocols this slice supports. "oidc" reuses the airtight `ui.oidc` JWT verification core; "saml"
# uses `ui.saml` (structural/temporal/audience/replay + XSW-binding sound; the crypto backend fail-closes).
PROTOCOLS = ("saml", "oidc")

# Reuse the engine-contract tenant charset (an org_id == tenant_id; mirrors orgs._TENANT_RE, kept in lockstep by
# a test) — a config can only ever be keyed by a safe single-path-component tenant id.
_TENANT_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}")

# A SAML/entity identifier or endpoint URL: bounded, non-control, non-empty. Not a path component, so permissive.
_MAX_STR = 2048
# A SCIM/IdP group name used as a key in the group→role map: bounded + non-control (it is matched, never a path).
_MAX_GROUP = 256
_MAX_GROUP_MAP = 256          # at most this many group→role entries (bound the signed record)
_MAX_CERTS = 8                # at most this many IdP signing certs (rotation overlap); bounds the signed record

# The asymmetric-only OIDC signing algs an enterprise config may pin (mirrors ui.oidc.KNOWN_ASYMMETRIC_ALGS —
# a lockstep test keeps them equal). A symmetric / `none` alg is refused at bind time so it can never reach
# verification.
_KNOWN_OIDC_ALGS = frozenset({"RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512"})

# The authenticated CORE of a config grant — EVERY security-bearing field is inside it, so an owner-signed
# config can never be re-aimed (org_id), re-protocoled, re-pointed at another IdP (idp_entity_id / certs /
# issuer / jwks_uri), re-audienced (sp_entity_id / acs_url), re-mapped (default_role / group_role_map /
# role_cap) or have its SCIM token swapped (scim_token_fp) without breaking the signature. `issued_at` is inside
# it (else a captured grant's freshness could be re-stamped past the high-water without breaking the sig).
_CONFIG_CORE = ("signal", "org_id", "protocol", "state", "issued_at", "idp_entity_id", "idp_certs_pem",
                "sp_entity_id", "acs_url", "oidc_issuer", "oidc_client_id", "oidc_jwks_uri",
                "oidc_authorize_endpoint", "oidc_token_endpoint", "oidc_redirect_uri", "oidc_signing_algs",
                "oidc_egress_hosts", "default_role", "group_role_map", "role_cap", "scim_enabled",
                "scim_token_fp", "clock_skew_seconds")


class SsoConfigError(ValueError):
    """A fail-closed SSO/SCIM config binding refusal (bad role, bad protocol, malformed cert/endpoint). Raised at
    BINDING time so a bad config is a clean error now, never a silent bad grant on the spine later."""


# ---------------------------------------------------------------------------------------------------
# Validation — fail-closed at binding time.
# ---------------------------------------------------------------------------------------------------

def _check_org_id(org_id: str) -> str:
    oid = str(org_id or "").strip()
    if not _TENANT_RE.fullmatch(oid):
        raise SsoConfigError("org_id must be a valid tenant id (org_id == CRUCIBLE_TENANT): an alphanumeric "
                             "start then [A-Za-z0-9._-], max 64 chars, no separators / traversal")
    return oid


def _check_protocol(protocol: str) -> str:
    p = str(protocol or "").strip().lower()
    if p not in PROTOCOLS:
        raise SsoConfigError(f"protocol must be one of {PROTOCOLS}, got {protocol!r}")
    return p


def check_provisionable_role(role: str) -> str:
    """THE CEILING GATE (invariant #1), applied to default_role, role_cap and EVERY value in group_role_map.
    Refuses any role outside `SSO_PROVISIONABLE_ROLES` — so a config can NEVER be signed that would let SSO/SCIM
    grant `operator`/`founder`/`owner` or any money/offense role. Public so `governor.scim` can re-use the exact
    same gate at mint time (a second independent refusal over the same predicate)."""
    r = str(role or "").strip()
    if r not in SSO_PROVISIONABLE_ROLES:
        raise SsoConfigError(
            f"SSO/SCIM may provision ONLY {sorted(SSO_PROVISIONABLE_ROLES)} (the absolute role ceiling); "
            f"{role!r} is refused — operator/founder/owner and any money/offense role stay owner-signed")
    return r


def _check_str(value: object, what: str, *, required: bool) -> str:
    v = str(value or "").strip()
    if not v:
        if required:
            raise SsoConfigError(f"{what} is required")
        return ""
    if len(v) > _MAX_STR:
        raise SsoConfigError(f"{what} too long (> {_MAX_STR})")
    if any(ord(c) < 0x20 or ord(c) == 0x7f for c in v):
        raise SsoConfigError(f"{what} must not contain control characters")
    return v


def _check_https_or_http_url(value: object, what: str, *, required: bool, allow_http: bool = False) -> str:
    v = _check_str(value, what, required=required)
    if not v:
        return ""
    from urllib.parse import urlparse
    parts = urlparse(v)
    allowed = ("https",) if not allow_http else ("https", "http")
    if parts.scheme.lower() not in allowed or not parts.hostname:
        raise SsoConfigError(f"{what} must be an absolute {'/'.join(allowed)} URL with a host")
    return v


def _check_cert_pem(pem: object, idx: int) -> str:
    """A SAML IdP signing cert MUST parse as a real X.509 certificate (via `cryptography`) — fail-closed on
    malformed material, so a config can never carry a garbage 'cert' that a verifier would later choke on."""
    s = str(pem or "").strip()
    if not s or len(s) > _MAX_STR * 8:
        raise SsoConfigError(f"idp_certs_pem[{idx}] is empty or too large")
    try:
        from cryptography.x509 import load_pem_x509_certificate
        load_pem_x509_certificate(s.encode("ascii"))
    except Exception as e:  # noqa: BLE001 — any parse failure → fail-closed refusal
        raise SsoConfigError(f"idp_certs_pem[{idx}] is not a valid PEM X.509 certificate") from e
    return s


def _check_group_role_map(group_role_map: object, role_cap: str) -> dict[str, str]:
    """Validate the group→role map: bounded size, non-empty string keys, and EVERY value both provisionable
    (the ceiling) AND no higher than `role_cap` (by the provisioning rank). So the map can never encode an
    above-ceiling or above-cap grant at the source."""
    if group_role_map is None:
        return {}
    if not isinstance(group_role_map, dict):
        raise SsoConfigError("group_role_map must be an object of {group_name: role}")
    if len(group_role_map) > _MAX_GROUP_MAP:
        raise SsoConfigError(f"group_role_map too large (> {_MAX_GROUP_MAP} entries)")
    out: dict[str, str] = {}
    cap_rank = _provision_rank(role_cap)
    for g, r in group_role_map.items():
        gs = str(g or "").strip()
        if not gs or len(gs) > _MAX_GROUP:
            raise SsoConfigError("group_role_map key must be a non-empty group name (<= 256 chars)")
        if any(ord(c) < 0x20 or ord(c) == 0x7f for c in gs):
            raise SsoConfigError("group_role_map key must not contain control characters")
        role = check_provisionable_role(r)                          # ceiling gate on every mapped role
        if _provision_rank(role) > cap_rank:                        # never above the configured cap
            raise SsoConfigError(f"group_role_map[{gs!r}] -> {role!r} exceeds role_cap {role_cap!r}")
        out[gs] = role
    return out


# The deterministic provisioning rank over the ceiling roles ONLY (viewer < analyst < org_admin). Used to clamp a
# resolved role to `role_cap` and to pick the highest among a user's mapped groups. It is a LOCAL ordering for
# clamping — NOT a claim that org_admin ⊇ analyst in permissions (they are disjoint capability sets); it is only
# "how much to trust an SSO-provisioned member", and clamping is always the fail-SAFE direction (never exceeds
# the cap). A role outside the ceiling has rank +inf, so it can never be chosen or pass a cap comparison.
_PROVISION_RANK = {"viewer": 0, "analyst": 1, "org_admin": 2}


def _provision_rank(role: str) -> float:
    return _PROVISION_RANK.get(str(role or ""), float("inf"))


def token_fingerprint(token: str) -> str:
    """The stored SCIM bearer-token fingerprint: `sha256_hex(token)`. We store ONLY this one-way digest in the
    (owner-signed, but spine-visible) config, never the token — a spine read reveals no usable token, and a
    256-bit random token makes the digest infeasible to invert. The plaintext is shown to the owner ONCE at
    provisioning. Authentication (`governor.scim`) re-derives this from the presented token and constant-time
    compares."""
    return sha256_hex(str(token or "").encode("utf-8"))


# ---------------------------------------------------------------------------------------------------
# Entity
# ---------------------------------------------------------------------------------------------------

@dataclass(frozen=True)
class SsoConfig:
    org_id: str
    protocol: str                     # "saml" | "oidc"
    issued_at: float                  # owner-set anti-replay high-water for this org's config
    state: str                        # "active" | "revoked"
    # --- SAML ---
    idp_entity_id: str = ""           # the expected <Issuer> of an assertion
    idp_certs_pem: tuple = ()         # the IdP's X.509 signing cert(s) (PEM), rotation overlap allowed
    sp_entity_id: str = ""            # our SP entity-id == the required <Audience> (org-scoping)
    acs_url: str = ""                 # our ACS URL == the required Recipient / Destination
    # --- OIDC (enterprise; PKCE public client — no client secret in the signed config) ---
    oidc_issuer: str = ""
    oidc_client_id: str = ""
    oidc_jwks_uri: str = ""
    oidc_authorize_endpoint: str = ""
    oidc_token_endpoint: str = ""
    oidc_redirect_uri: str = ""
    oidc_signing_algs: tuple = ()
    oidc_egress_hosts: tuple = ()     # the allowlist bounding the provisioner's JWKS/token egress
    # --- provisioning policy (ALL capped at the ceiling by construction) ---
    default_role: str = "viewer"      # the role for an authenticated identity with no mapped group
    group_role_map: dict = field(default_factory=dict)
    role_cap: str = "org_admin"       # the resolved role is clamped to this (never above it, never above ceiling)
    clock_skew_seconds: int = 60
    # --- SCIM ---
    scim_enabled: bool = False
    scim_token_fp: str = ""           # sha256(token) fingerprint; "" ⇒ SCIM auth fail-closed


# ---------------------------------------------------------------------------------------------------
# The fold — ONE step per record (owner-key-succession-aware + fail-closed, mirrors orgs._apply_org_record).
# ---------------------------------------------------------------------------------------------------

_SKIP = object()


def _apply_config_record(r, resolver, state: dict, issued: dict, configs: dict):
    """Fold ONE record into (state, issued, configs). Returns the org_id it touched, or `_SKIP`."""
    p = r.payload
    if not isinstance(p, dict) or p.get("signal") != SSO_CONFIG_SIGNAL:
        return _SKIP
    org_id = p.get("org_id")
    if not isinstance(org_id, str) or not org_id:
        return _SKIP
    rec_state = p.get("state")
    if rec_state == "revoked":
        state[org_id] = "revoked"                        # honor ANY revoke (even unsigned) — safe direction
        return org_id
    if rec_state == "active":
        if not verify_signed(p, _CONFIG_CORE, resolver.at(r.seq)):
            return _SKIP                                 # fail-closed: unsigned / forged / wrong-epoch-key grant
        at = as_issued_at(p.get("issued_at"))
        if at <= issued.get(org_id, NO_HIGHWATER):
            return _SKIP                                 # REPLAY / stale re-append of an already-honored grant
        cfg = _config_from_payload(p, at)
        if cfg is None:
            return _SKIP                                 # a folded grant whose fields no longer validate → inert
        issued[org_id] = at                              # consume it so its own replay is refused hereafter
        state[org_id] = "active"
        configs[org_id] = cfg
        return org_id
    return _SKIP


def _config_from_payload(p: dict, issued_at: float) -> Optional[SsoConfig]:
    """Rebuild a validated `SsoConfig` from a verified `active` payload, or None if any field fails
    re-validation (defence in depth — a grant may be hand-appended; the binding API already validated, so this
    only ever rejects a directly-crafted owner-signed record with bad fields, which is then inert in the fold)."""
    try:
        protocol = _check_protocol(str(p.get("protocol") or ""))
        certs = tuple(_check_cert_pem(c, i) for i, c in enumerate(_as_tuple(p.get("idp_certs_pem"))[:_MAX_CERTS]))
        role_cap = check_provisionable_role(p.get("role_cap") or "org_admin")
        default_role = check_provisionable_role(p.get("default_role") or "viewer")
        if _provision_rank(default_role) > _provision_rank(role_cap):
            return None
        group_map = _check_group_role_map(p.get("group_role_map"), role_cap)
        algs = tuple(a for a in (str(x).strip().upper() for x in _as_tuple(p.get("oidc_signing_algs")))
                     if a in _KNOWN_OIDC_ALGS)
        return SsoConfig(
            org_id=str(p["org_id"]), protocol=protocol, issued_at=issued_at, state="active",
            idp_entity_id=str(p.get("idp_entity_id") or ""), idp_certs_pem=certs,
            sp_entity_id=str(p.get("sp_entity_id") or ""), acs_url=str(p.get("acs_url") or ""),
            oidc_issuer=str(p.get("oidc_issuer") or ""), oidc_client_id=str(p.get("oidc_client_id") or ""),
            oidc_jwks_uri=str(p.get("oidc_jwks_uri") or ""),
            oidc_authorize_endpoint=str(p.get("oidc_authorize_endpoint") or ""),
            oidc_token_endpoint=str(p.get("oidc_token_endpoint") or ""),
            oidc_redirect_uri=str(p.get("oidc_redirect_uri") or ""),
            oidc_signing_algs=algs, oidc_egress_hosts=tuple(str(h).strip().lower()
                                                            for h in _as_tuple(p.get("oidc_egress_hosts")) if str(h).strip()),
            default_role=default_role, group_role_map=group_map, role_cap=role_cap,
            clock_skew_seconds=max(0, _as_int(p.get("clock_skew_seconds"), 60)),
            scim_enabled=bool(p.get("scim_enabled")), scim_token_fp=str(p.get("scim_token_fp") or ""),
        )
    except (SsoConfigError, KeyError, TypeError, ValueError):
        return None


def _as_tuple(v) -> tuple:
    if v is None:
        return ()
    if isinstance(v, (list, tuple)):
        return tuple(v)
    return (v,)


def _as_int(v, default: int) -> int:
    try:
        return int(v)
    except (TypeError, ValueError):
        return default


# ---------------------------------------------------------------------------------------------------
# The registry — owner-signed config grants on the spine (construction mirrors OrgRegistry / AccountsRegistry).
# ---------------------------------------------------------------------------------------------------

class SsoConfigRegistry:
    def __init__(self, store, *, owner_key=None, trusted_pubkey: Optional[str] = None):
        self.store = store
        self.owner_key = owner_key if owner_key is not None else owner_keypair()
        self.trusted_pubkey = trusted_pubkey if trusted_pubkey is not None else owner_pubkey()

    # -- owner mutations --------------------------------------------------------------------------------
    def set_saml_config(self, org_id: str, *, idp_entity_id: str, idp_certs_pem, sp_entity_id: str, acs_url: str,
                        default_role: str = "viewer", group_role_map: Optional[dict] = None,
                        role_cap: str = "org_admin", clock_skew_seconds: int = 60, scim_enabled: bool = False,
                        scim_token: str = "", issued_at: float) -> int:
        """Owner-sign an active SAML SSO config for `org_id` — the DANGEROUS direction (verifies + fresh). Every
        role (default_role, role_cap, each group_role_map value) passes the CEILING gate; each cert must parse as
        X.509. If `scim_token` is given its FINGERPRINT (never the token) is stored. Returns the record seq."""
        if self.owner_key is None:
            raise SsoConfigError("SSO config requires the owner signing key")
        oid = _check_org_id(org_id)
        role_cap = check_provisionable_role(role_cap)
        default_role = check_provisionable_role(default_role)
        if _provision_rank(default_role) > _provision_rank(role_cap):
            raise SsoConfigError(f"default_role {default_role!r} exceeds role_cap {role_cap!r}")
        certs = tuple(_check_cert_pem(c, i) for i, c in enumerate(_as_tuple(idp_certs_pem)))
        if not certs:
            raise SsoConfigError("a SAML config requires at least one IdP signing certificate (idp_certs_pem)")
        if len(certs) > _MAX_CERTS:
            raise SsoConfigError(f"at most {_MAX_CERTS} IdP certs")
        core = {
            "signal": SSO_CONFIG_SIGNAL, "org_id": oid, "protocol": "saml", "state": "active",
            "issued_at": float(issued_at),
            "idp_entity_id": _check_str(idp_entity_id, "idp_entity_id", required=True),
            "idp_certs_pem": list(certs),
            "sp_entity_id": _check_str(sp_entity_id, "sp_entity_id", required=True),
            "acs_url": _check_https_or_http_url(acs_url, "acs_url", required=True, allow_http=True),
            "oidc_issuer": "", "oidc_client_id": "", "oidc_jwks_uri": "", "oidc_authorize_endpoint": "",
            "oidc_token_endpoint": "", "oidc_redirect_uri": "", "oidc_signing_algs": [], "oidc_egress_hosts": [],
            "default_role": default_role, "group_role_map": _check_group_role_map(group_role_map, role_cap),
            "role_cap": role_cap, "clock_skew_seconds": max(0, int(clock_skew_seconds)),
            "scim_enabled": bool(scim_enabled),
            "scim_token_fp": token_fingerprint(scim_token) if scim_token else "",
        }
        return self._append_active(core)

    def set_oidc_config(self, org_id: str, *, issuer: str, client_id: str, jwks_uri: str,
                        authorize_endpoint: str, token_endpoint: str, redirect_uri: str,
                        signing_algs=("RS256",), egress_hosts=(), default_role: str = "viewer",
                        group_role_map: Optional[dict] = None, role_cap: str = "org_admin",
                        clock_skew_seconds: int = 60, scim_enabled: bool = False, scim_token: str = "",
                        issued_at: float) -> int:
        """Owner-sign an active enterprise-OIDC SSO config for `org_id` (PKCE public client — no client secret in
        the signed record). The signing-alg allowlist is ASYMMETRIC-ONLY (a `none`/HS* alg is refused here, so it
        can never reach `ui.oidc.verify_id_token`). The egress-host allowlist bounds the provisioner's JWKS/token
        calls. Same ceiling gate on every role."""
        if self.owner_key is None:
            raise SsoConfigError("SSO config requires the owner signing key")
        oid = _check_org_id(org_id)
        role_cap = check_provisionable_role(role_cap)
        default_role = check_provisionable_role(default_role)
        if _provision_rank(default_role) > _provision_rank(role_cap):
            raise SsoConfigError(f"default_role {default_role!r} exceeds role_cap {role_cap!r}")
        algs = tuple(a.strip().upper() for a in _as_tuple(signing_algs) if str(a).strip())
        if not algs:
            raise SsoConfigError("oidc signing_algs is empty (need >= 1 asymmetric alg, e.g. RS256)")
        bad = [a for a in algs if a not in _KNOWN_OIDC_ALGS]
        if bad:
            raise SsoConfigError(f"refusing non-asymmetric / unknown OIDC signing alg(s): {bad}")
        hosts = tuple(str(h).strip().lower() for h in _as_tuple(egress_hosts) if str(h).strip())
        core = {
            "signal": SSO_CONFIG_SIGNAL, "org_id": oid, "protocol": "oidc", "state": "active",
            "issued_at": float(issued_at),
            "idp_entity_id": "", "idp_certs_pem": [], "sp_entity_id": "", "acs_url": "",
            "oidc_issuer": _check_str(issuer, "oidc issuer", required=True),
            "oidc_client_id": _check_str(client_id, "oidc client_id", required=True),
            "oidc_jwks_uri": _check_https_or_http_url(jwks_uri, "oidc jwks_uri", required=True),
            "oidc_authorize_endpoint": _check_https_or_http_url(authorize_endpoint, "oidc authorize_endpoint",
                                                               required=True),
            "oidc_token_endpoint": _check_https_or_http_url(token_endpoint, "oidc token_endpoint", required=True),
            "oidc_redirect_uri": _check_https_or_http_url(redirect_uri, "oidc redirect_uri", required=True,
                                                         allow_http=True),
            "oidc_signing_algs": list(algs), "oidc_egress_hosts": list(hosts),
            "default_role": default_role, "group_role_map": _check_group_role_map(group_role_map, role_cap),
            "role_cap": role_cap, "clock_skew_seconds": max(0, int(clock_skew_seconds)),
            "scim_enabled": bool(scim_enabled),
            "scim_token_fp": token_fingerprint(scim_token) if scim_token else "",
        }
        return self._append_active(core)

    def revoke_config(self, org_id: str) -> int:
        """Revoke an org's SSO/SCIM config — the SAFE direction (honored even unsigned, fixed `issued_at` 0.0).
        After a revoke, every SSO login and SCIM push for the org fails closed (no active config). Idempotent /
        replay-safe (a replayed revoke merely re-revokes)."""
        oid = _check_org_id(org_id)
        core = {"signal": SSO_CONFIG_SIGNAL, "org_id": oid, "protocol": "", "state": "revoked",
                "issued_at": 0.0}
        # Fill the remaining core fields blank so a verify over _CONFIG_CORE of a hand-signed revoke is well-formed
        # (a revoke is honored regardless of signature, but keep the record shape consistent).
        for k in _CONFIG_CORE:
            core.setdefault(k, "" if k not in ("scim_enabled",) else False)
        payload = {**signed_payload(core, self.owner_key), "by": "owner", "requested_by": "owner",
                   "tier": "A0", "decision": "auto", "reason": f"SSO config for org {oid} REVOKED (governed latch)"}
        return self.store.append(kind="event", source="governor", actor="WARDEN", payload=payload)

    def _append_active(self, core: dict) -> int:
        payload = {**signed_payload(core, self.owner_key), "by": "owner", "requested_by": "owner",
                   "tier": "A0", "decision": "auto",
                   "reason": f"SSO config for org {core['org_id']} set ({core['protocol']}, owner-signed grant)"}
        return self.store.append(kind="event", source="governor", actor="WARDEN", payload=payload)

    # -- reads (owner-key-succession-aware full genesis fold; see HARD-PRUNE RESIDUAL note) -------------
    def _fold(self) -> dict[str, SsoConfig]:
        resolver = _kh.key_resolver(self.store, current=self.trusted_pubkey)
        state: dict[str, str] = {}
        issued: dict[str, float] = {}
        configs: dict[str, SsoConfig] = {}
        for r in self.store.iter_records():
            _apply_config_record(r, resolver, state, issued, configs)
        return {o: c for o, c in configs.items() if state.get(o) == "active"}

    def config(self, org_id: str) -> Optional[SsoConfig]:
        """The current active `SsoConfig` for `org_id`, or None (fail-closed — unknown/revoked treated as
        absent). The role fields it carries are owner-signed (a Tier-1 cryptographic predicate), never
        self-asserted by a caller."""
        if not isinstance(org_id, str) or not org_id:
            return None
        return self._fold().get(org_id)

    def configs(self) -> list[SsoConfig]:
        """The current active SSO/SCIM configs, in org_id order (owner's SSO admin list)."""
        fold = self._fold()
        return [fold[o] for o in sorted(fold)]
