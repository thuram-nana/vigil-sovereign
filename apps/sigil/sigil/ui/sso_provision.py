"""Consumer PR-H (Area 7) — the PROVISIONER side of the SSO / SCIM HTTP edge.

The keyless customer edge (`ui.sso_edge`, mixed into `ui.custui`) holds no key and never reads the spine. Every
SSO / SCIM request it accepts is relayed over the hop key to the sovereign provisioner, whose `Provisioner`
methods (`sso_login_start`, `sso_saml_acs`, `sso_oidc_finish`, `scim_request`) delegate here. This module runs
in the ONE process that holds the owner key, so it is where the owner-signed config is read, the identity is
verified and the capped membership is minted (through `ui.scim` → `governor.scim.provision_membership`).

Where the ORG comes from (IDOR-safety for these session-less bootstrap actions): there is no customer session
yet, so the org is never trusted on its own — it only selects WHICH owner-signed config the proof is checked
against. Sign-in start takes the org a person asks to sign in to (public: it reveals only the IdP sign-in URL the
browser is about to visit anyway); the SAML ACS and the OIDC finish take the org from the edge's SERVER-SIDE,
single-use login state (minted at start, bound to the browser), and the assertion / id_token must then verify
under THAT org's owner-signed IdP (audience, issuer, signature, InResponseTo / nonce); SCIM takes the org from
the path and must present THAT org's bearer. A proof for org A can therefore never provision into org B.

Each action is fail-closed and rate-limited:
  * sign-in: the per-IP login limiter guards start / ACS / finish; a refused verification counts as a failure;
  * SCIM: failed bearer authentications are counted per (org, client IP) and lock out that pair's further
    INVALID attempts (a valid bearer is never refused by it — see `scim_request`); both limiters are on disk (the
    provisioner is rebuilt per request).
  * SCIM writes are bounded per REQUEST and charged per RECORD, so even a valid token cannot flood the spine or
    hold the shared critical section for long:
      - a body over a per-request bound (more than `ui.scim.MAX_PATCH_OPS` = 1000 PATCH operations, or more than
        `ui.scim.MAX_MEMBER_VALUES` = 1000 member references SUMMED over every operation of a group write) is
        refused 400 `tooMany` before the write budget and before the critical section is entered;
      - a group write that would author more than `ui.scim.MAX_DIRECTORY_WRITES` (= 1016) directory records is
        refused whole, before any record is written. Only removing state already on the spine is exempt (a group
        DELETE or a removal of every member, of a group of any size, still deprovisions) — that state was itself
        written, and charged, by earlier requests;
      - the per-org write budget (`VIGIL_SCIM_OPS_PER_MIN`) admits a write only while the org is not over budget
        (guard-and-count, one unit), then charges every further spine record the request appended (directory
        records, membership grants / revokes, their critical audit rows). A request that overdraws the budget
        holds the org's next write off until the budget has repaid it (a minute per `VIGIL_SCIM_OPS_PER_MIN`
        records), so over time one org's token appends at most about `VIGIL_SCIM_OPS_PER_MIN` records a minute,
        plus what one request may write. The cost of an overdraft lands on that org alone.

Every membership grant / revoke writes a CRITICAL `provision.audit` row FIRST (a failed audit write aborts the
change — committed implies audited), and the whole read-modify-write of a request runs inside the SAME critical
section as every other membership change (`_membership_section`: the process-wide spine lock, then the
cross-process membership flock the Team-screen verbs and the owner's `sigil org` verbs hold), so a sign-in or a
SCIM change never interleaves with an owner act in another process. The enterprise-OIDC token exchange + JWKS fetch
go out ONLY to the hosts in the owner-signed config's `oidc_egress_hosts` allowlist (https only), never to an
arbitrary URL — and both happen BEFORE the critical section is entered (no network wait while it is held).

FATAL-2: SOVEREIGN-side, imports NO `framework` / `strix` (`assert_no_offense()` at import).
"""
from __future__ import annotations

import base64
import binascii
import math
import re
from contextlib import contextmanager
from typing import Iterator, Optional

from ..reuse import assert_no_offense

assert_no_offense()

_TENANT_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}")      # org_id == tenant_id (mirrors orgs._TENANT_RE)
# The scopes an SP-initiated enterprise-OIDC sign-in asks for (identity only; groups ride the id_token claim).
OIDC_SCOPES = "openid email profile"
# A SAML Response is a few KiB; the base64 form relayed by the edge is capped (the XML parser caps again).
MAX_SAML_RESPONSE_B64 = 512 * 1024
_SCIM_METHODS = frozenset({"GET", "POST", "PUT", "PATCH", "DELETE"})
_SCIM_WRITES = frozenset({"POST", "PUT", "PATCH", "DELETE"})


def _registries(p):
    """The owner-signed SSO config registry + the SCIM directory, over the provisioner's spine and owner key."""
    from ..governor.scim_directory import ScimDirectoryRegistry
    from ..governor.sso_config import SsoConfigRegistry
    cfg = SsoConfigRegistry(p.store, owner_key=p.orgs.owner_key, trusted_pubkey=p.orgs.trusted_pubkey)
    directory = ScimDirectoryRegistry(p.store, owner_key=p.orgs.owner_key, trusted_pubkey=p.orgs.trusted_pubkey)
    return cfg, directory


def _org(org_id) -> str:
    """The org id EXACTLY as relayed when it is a well-formed tenant id, else "" (selects no config, so every leg
    refuses): never trimmed into a well-formed one."""
    oid = str(org_id or "")
    return oid if _TENANT_RE.fullmatch(oid) else ""


@contextmanager
def _membership_section(p) -> Iterator[None]:
    """The critical section of every membership change (`ui.provision`'s order): the process-wide spine lock, then
    the cross-process membership flock (`_members_lock`; a bounded wait, then `LockBusy` with nothing written)."""
    from .provision import _members_lock
    with p._lock, _members_lock(p.store):
        yield


def _critical_audit(p, org_id: str):
    """The audit hook `ui.scim` calls BEFORE each membership grant / revoke: a critical row (fail-closed)."""
    def audit(action: str, target: str, outcome: str) -> None:
        p._audit(action, requester="idp", org_id=org_id, target=target, outcome=outcome, critical=True)
    return audit


def sso_login_start(p, org_id: str, *, ip: str = "", now: Optional[float] = None) -> dict:
    """What the edge needs to send the browser to the org's IdP: the protocol and the IdP sign-in endpoint from the
    org's OWNER-SIGNED config (never a secret). Refused unless the org is active and has an active config."""
    from .provision import ProvisionDenied
    t = p._now() if now is None else float(now)
    p._rate_guard(f"sso:ip:{ip}", now=t)
    oid = _org(org_id)
    cfgreg, _ = _registries(p)
    cfg = cfgreg.config(oid) if oid else None
    if cfg is None or p.orgs.org(oid) is None:
        raise ProvisionDenied("single sign-on is not set up for this organization")
    if cfg.protocol == "saml":
        if not cfg.idp_sso_url:
            raise ProvisionDenied("this organization's SAML sign-in has no IdP sign-in URL (owner setup)")
        return {"protocol": "saml", "org_id": oid, "idp_sso_url": cfg.idp_sso_url,
                "sp_entity_id": cfg.sp_entity_id, "acs_url": cfg.acs_url}
    return {"protocol": "oidc", "org_id": oid, "client_id": cfg.oidc_client_id,
            "authorize_endpoint": cfg.oidc_authorize_endpoint, "redirect_uri": cfg.oidc_redirect_uri,
            "scopes": OIDC_SCOPES}


def _decode_saml_response(saml_response: object) -> bytes:
    s = re.sub(r"\s+", "", str(saml_response or ""))       # IdPs may fold the base64 across lines
    if not s or len(s) > MAX_SAML_RESPONSE_B64:
        raise ValueError("missing or oversize SAMLResponse")
    try:
        return base64.b64decode(s, validate=True)
    except (binascii.Error, ValueError) as e:
        raise ValueError("SAMLResponse is not base64") from e


def sso_saml_acs(p, org_id: str, saml_response: str, *, request_id: str, ip: str = "",
                 now: Optional[float] = None) -> dict:
    """The SAML ACS tail: verify the IdP's Response for the org the edge's single-use login state names, BOUND to
    that login's AuthnRequest (`request_id` ⇒ the signed InResponseTo), then resolve the member (JIT, or linked
    to the SCIM directory). The signature backend is `ui.saml`'s default — it FAILS CLOSED without a vetted
    XML-DSig library, so with none installed every SAML sign-in is refused here (never bypassed)."""
    from . import scim as uiscim
    from .provision import ProvisionDenied, ProvisionError
    t = p._now() if now is None else float(now)
    p._rate_guard(f"sso:ip:{ip}", now=t)
    oid = _org(org_id)
    if p.saml_replay is None:
        raise ProvisionError("SAML sign-in is not available on this deployment (no replay ledger)")
    cfgreg, directory = _registries(p)
    try:
        if not oid or not str(request_id or ""):
            raise ValueError("no org / AuthnRequest to bind the response to")
        xml = _decode_saml_response(saml_response)
        with _membership_section(p):
            res = uiscim.sso_login_saml(xml, org_id=oid, config_registry=cfgreg, org_registry=p.orgs,
                                        replay_ledger=p.saml_replay, now=t, issued_at=p._next_issued(),
                                        expected_request_id=str(request_id), directory_registry=directory,
                                        audit=_critical_audit(p, oid))
    except (uiscim.SsoLoginError, ValueError):
        p.rate_limiter.record_failure(f"sso:ip:{ip}", now=t)
        p._audit("sso_login", org_id=oid, outcome="denied", reason="saml")
        raise ProvisionDenied("single sign-on could not be verified")
    p.rate_limiter.record_success(f"sso:ip:{ip}")
    p._audit("sso_login", requester=res.username, org_id=oid, target=res.username, outcome="ok", reason="saml")
    return {"username": res.username, "org_id": res.org_id}


def _oidc_transport(p, cfg):
    """The token-exchange + JWKS transport, leg by leg: a test-injected hook where one is set, else that leg of the
    HOST-ALLOWLISTED https transport over the owner-signed `oidc_egress_hosts` (an empty allowlist refuses every
    egress — fail-closed). A leg without a hook is never left to the unpinned stdlib default."""
    from .oidc import host_allowlisted_transport
    post, fetch = host_allowlisted_transport(cfg.oidc_egress_hosts)
    return (p.sso_oidc_http_post or post), (p.sso_oidc_jwks_fetcher or fetch)


def sso_oidc_finish(p, org_id: str, *, code: str, code_verifier: str, nonce: str, ip: str = "",
                    now: Optional[float] = None) -> dict:
    """The enterprise-OIDC callback tail (the edge already proved the single-use state + the browser binding): the
    PKCE code exchange at the org's owner-signed token endpoint, the id_token verified against its JWKS (both only
    through the owner-signed egress allowlist), then the member resolved (JIT, or linked to the SCIM directory)."""
    from . import oidc as _oidc
    from . import scim as uiscim
    from .provision import ProvisionDenied
    t = p._now() if now is None else float(now)
    p._rate_guard(f"sso:ip:{ip}", now=t)
    oid = _org(org_id)
    cfgreg, directory = _registries(p)
    try:
        cfg = cfgreg.config(oid) if oid else None
        if cfg is None or cfg.protocol != "oidc":
            raise uiscim.SsoLoginError("no active enterprise-OIDC config for this organization")
        poster, fetcher = _oidc_transport(p, cfg)
        oc = _oidc.OidcConfig(issuer=cfg.oidc_issuer, client_id=cfg.oidc_client_id, client_secret="",
                              redirect_uri=cfg.oidc_redirect_uri, authorize_endpoint=cfg.oidc_authorize_endpoint,
                              token_endpoint=cfg.oidc_token_endpoint, jwks_uri=cfg.oidc_jwks_uri,
                              scopes=OIDC_SCOPES, username_claim="sub", signing_algs=cfg.oidc_signing_algs,
                              clock_skew_seconds=cfg.clock_skew_seconds)
        tokens = _oidc.exchange_code(oc, code, code_verifier=code_verifier, http_post=poster)
        keys = _oidc.JwksProvider(oc.jwks_uri, fetcher=fetcher).keys(now=t)
        with _membership_section(p):
            res = uiscim.sso_login_oidc(tokens["id_token"], org_id=oid, config_registry=cfgreg,
                                        org_registry=p.orgs, jwks_keys=keys, expected_nonce=str(nonce or ""),
                                        now=t, issued_at=p._next_issued(), directory_registry=directory,
                                        audit=_critical_audit(p, oid))
    except Exception:  # noqa: BLE001 — a refused token, an IdP/network fault or a non-member: one fail-closed denial
        p.rate_limiter.record_failure(f"sso:ip:{ip}", now=t)
        p._audit("sso_login", org_id=oid, outcome="denied", reason="oidc")
        raise ProvisionDenied("single sign-on could not be verified")
    p.rate_limiter.record_success(f"sso:ip:{ip}")
    p._audit("sso_login", requester=res.username, org_id=oid, target=res.username, outcome="ok", reason="oidc")
    return {"username": res.username, "org_id": res.org_id}


def _scim_refusal(status: int, detail: str, *, retry_after: float = 0.0) -> dict:
    from .scim import _error
    out: dict = {"status": status, "body": _error(status, detail), "deactivated": []}
    if retry_after:
        out["retry_after"] = int(max(1, math.ceil(retry_after)))
    return out


def scim_request(p, org_id: str, *, method: str, path: str, query: str = "", body=None, authorization: str = "",
                 ip: str = "", now: Optional[float] = None) -> dict:
    """One SCIM 2.0 request for the org in the edge's path, answered as {status, body, deactivated[,
    retry_after]} — the edge returns `status`/`body` to the IdP verbatim and severs the sessions of every username
    in `deactivated`. Authentication is the org's owner-signed bearer fingerprint (constant-time); an authenticated
    write counts against the org's write budget — one unit to be admitted, then one per further spine record it
    appended (see the module docstring for the per-request bounds, refused before the critical section).

    FAILED authentications count against (org, client IP) and, past the limit, that pair's further INVALID
    attempts are refused 429 without another audit row. A VALID bearer is never refused by that lock: an IdP's
    SCIM egress addresses are shared by every tenant of that IdP, so a lock that also stopped the valid token
    would let anyone with an account at the same IdP stall this org's DEPROVISIONING (an offboarded employee
    keeping access) by spraying wrong tokens from the shared address. A success therefore does not clear the
    count either (legitimate traffic never re-opens an attacker's quota). Guessing is bounded by the token
    (>= 256 random bits from `sigil sso`)."""
    from . import scim as uiscim
    from ..governor.scim import authenticate_scim, bearer_from_authorization_header
    t = p._now() if now is None else float(now)
    m = str(method or "").upper()
    if m not in _SCIM_METHODS:
        return _scim_refusal(405, f"{m or 'the method'} is not a SCIM method")
    if p.scim_auth_limiter is None or p.scim_write_limiter is None:
        return _scim_refusal(503, "SCIM is not available on this deployment")
    oid = _org(org_id)
    key = f"scim:auth:{oid}:{ip}"
    cfgreg, directory = _registries(p)
    cfg = cfgreg.config(oid) if oid else None
    if not authenticate_scim(cfg, bearer_from_authorization_header(authorization)):
        locked = p.scim_auth_limiter.locked(key, now=t)
        if locked is not None:
            return _scim_refusal(429, "too many failed SCIM authentications; wait and retry", retry_after=locked)
        p.scim_auth_limiter.record_failure(key, now=t)
        p._audit("scim_auth", org_id=oid, outcome="denied")
        return _scim_refusal(401, "SCIM authentication failed")
    over = uiscim.request_bound_refusal(m, path, body)
    if over is not None:                   # refused on its body alone: no budget spent, the critical section untouched
        return {"status": over.status, "body": over.body, "deactivated": []}
    budget = f"scim:writes:{oid}"
    if m in _SCIM_WRITES:
        wait = p.scim_write_limiter.admit(budget, now=t)
        if wait is not None:
            return _scim_refusal(429, "this organization's SCIM write rate is exceeded; retry shortly",
                                 retry_after=wait)
    with _membership_section(p):
        r = uiscim.scim_dispatch(m, path, body, authorization, org_id=oid, config_registry=cfgreg,
                                 org_registry=p.orgs, now=t, query=str(query or ""), directory_registry=directory,
                                 issued_at_fn=p._next_issued, audit=_critical_audit(p, oid))
    if r.records > 1:                      # `admit` counted one unit; every further record it appended is charged
        p.scim_write_limiter.charge(budget, r.records - 1, now=t)
    return {"status": r.status, "body": r.body, "deactivated": list(r.deactivated)}
