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

ONE ORG CANNOT STALL ANOTHER. Every membership change commits inside the SAME critical section — the process-wide
spine lock (`p._lock`), then the cross-process membership flock the Team-screen verbs and the owner's `sigil org`
verbs hold (`_membership_section`) — so a sign-in or a SCIM change never interleaves with an owner act in another
process. That section is shared by every org, so what one org's token may make it do is bounded:
  * PER-ORG SERIALIZATION: an org's SCIM writes take that org's own lock first (`_org_lock`, a cross-process flock
    per org; a bounded wait, then 429 + Retry-After), and its SCIM reads a separate per-org read lock, so an org
    has at most one write and one read in flight — and the write budget below is checked AND charged inside that
    lock, so concurrent writes can never all be admitted before any is charged. Another org never waits on it.
  * READS NEVER ENTER THE SHARED SECTION: a SCIM GET folds the spine lock-free (it appends nothing), under the
    per-org read lock and a per-org read budget (`VIGIL_SCIM_READS_PER_MIN`, guard-and-count; 429 when spent).
  * WRITES FOLD OUTSIDE IT: a write's folds (config, memberships, directory) run before the section is taken; on
    entry the records appended since the fold began are checked, and if any changed this org's state (a membership,
    org, SSO-config or directory record of this org, or an owner-key rotation) the fold is redone.
  * BOUNDED HOLDS: inside, a request appends at most `ui.scim.MAX_RECORDS_PER_HOLD` (= 128) spine records per hold
    of the section; past that it releases the section between two members' changes (or two directory records),
    lets other requests run, and re-takes it — re-checking that nothing of this org changed meanwhile (else it
    stops with a retryable 503, every record so far landed in the safe order). A group change too large for one hold
    (a rename re-roling thousands of members, the delete of a large mapped group) first opens a durable pending job
    on the spine (`governor.scim_directory`): it lowers every role first, then commits the directory, then raises,
    so at no point — between holds or after a crash — is a member above the role the directory then implies, and
    an open job is finished by the org's next SCIM write or sign-in.
  * PER-REQUEST BOUNDS: a body over a per-request bound (more than `ui.scim.MAX_PATCH_OPS` = 1000 PATCH operations,
    or more than `ui.scim.MAX_MEMBER_VALUES` = 1000 member references SUMMED over every operation of a group write)
    is refused 400 `tooMany` before the org lock, the write budget and the critical section; a group write that
    would author more than `ui.scim.MAX_DIRECTORY_WRITES` (= 1016) directory records is refused whole, before any
    record is written. Removing state already on the spine is exempt (a group DELETE, or a removal of every member,
    of a group of any size still deprovisions — that state was written, and charged, by earlier requests).
  * WRITE BUDGET: the per-org budget (`VIGIL_SCIM_OPS_PER_MIN`) admits a write only while the org is not over budget
    (guard-and-count, one unit), then charges — in a `finally`, so also when the request fails part-way — every
    further spine record the request appended. An overdraft holds the org's next write off until the budget has
    repaid it (a minute per `VIGIL_SCIM_OPS_PER_MIN` records). A request that can only take privilege away
    (`ui.scim.lowers_only`: a user / group DELETE, a deactivation, a removal of group members) is admitted even
    while the org is over budget — an offboarding never waits out an earlier sync's debt — and is still serialized,
    paced and charged.

Every membership grant / revoke writes a CRITICAL `provision.audit` row FIRST (a failed audit write aborts the
change — committed implies audited). The enterprise-OIDC token exchange + JWKS fetch go out ONLY to the hosts in
the owner-signed config's `oidc_egress_hosts` allowlist (https only), never to an arbitrary URL — and both happen
BEFORE the critical section is entered (no network wait while it is held).

FATAL-2: SOVEREIGN-side, imports NO `framework` / `strix` (`assert_no_offense()` at import).
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import math
import re
import time
from contextlib import contextmanager
from pathlib import Path
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
#: How long a SCIM request waits for its org's own lock (another request of the SAME org in flight) before a 429.
_ORG_LOCK_WAIT_S = 10.0
#: The pause between two holds of the shared section, so a request waiting for it is handed the lock.
_HANDOFF_S = 0.005
#: How many times a write re-folds outside the shared section when its org's state changed meanwhile, before it
#: folds under the section instead.
_FOLD_ATTEMPTS = 3


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


def _org_lock(p, org_id: str, kind: str, *, wait_s: float = _ORG_LOCK_WAIT_S):
    """ONE org's own cross-process lock (`kind` "write" or "read"): an flock on
    ``<spine dir>/<stem>.scim-orgs/<kind>-<sha256(org)>.lock`` (`*.lock` transients the backups skip), taken BEFORE
    the shared section and never while holding it (lock order: this -> `spine_lock` -> the membership flock). A
    bounded wait, then `LockBusy`. Another org's lock is a different file, so it never waits on this one."""
    from vigil_integration.live.seam_lock import locked_file
    raw = getattr(p.store, "path", None)
    if not raw:
        raise ValueError("the per-org SCIM lock needs a spine store with a path")
    sp = Path(raw)
    d = sp.parent / f"{sp.stem or sp.name}.scim-orgs"
    d.mkdir(mode=0o700, exist_ok=True)
    digest = hashlib.sha256(f"{kind}\x00{org_id}".encode("utf-8")).hexdigest()[:32]
    return locked_file(d / f"{kind}-{digest}.lock", wait_s=wait_s, create=False, chown_like=d)


def _handoff() -> None:
    """The pause between two holds of the shared section: a request waiting for it is handed the lock."""
    time.sleep(_HANDOFF_S)


def _org_state_changed(store, org_id: str, since_seq: int) -> bool:
    """True iff a record after `since_seq` can change what a request of `org_id` folded: a membership, org, SSO-config
    or SCIM-directory record of that org, or an owner-key-history record (it moves every signature window)."""
    from ..governor.key_history import KEY_HISTORY_KIND
    from ..governor.orgs import MEMBERSHIP_SIGNAL, ORG_SIGNAL
    from ..governor.scim_directory import SCIM_DIRECTORY_SIGNAL
    from ..governor.sso_config import SSO_CONFIG_SIGNAL
    signals = (MEMBERSHIP_SIGNAL, ORG_SIGNAL, SSO_CONFIG_SIGNAL, SCIM_DIRECTORY_SIGNAL)
    for r in store.iter_records(since_seq=since_seq):
        if r.kind == KEY_HISTORY_KIND:
            return True
        pl = r.payload
        if isinstance(pl, dict) and pl.get("signal") in signals and pl.get("org_id") == org_id:
            return True
    return False


class _SharedSection:
    """The shared membership critical section (`_membership_section`: `p._lock`, then the membership flock) as a
    SCIM request of one org uses it — entered in BOUNDED HOLDS (`ui.scim` paces the request: at most
    `ui.scim.MAX_RECORDS_PER_HOLD` records per hold), with the request's folds run outside it:

      * `fold(fn)`: note the spine tip, run `fn` (the folds) WITHOUT the section, take it, and keep the result only
        if no record of this org's state was appended since the tip (`_org_state_changed`) — else re-fold (bounded),
        finally under the section;
      * `slice()`: between two holds — release, hand the lock over (`_HANDOFF_S`), re-take, and raise
        `ui.scim.SectionLost` when it cannot be re-taken (the flock's bounded wait) or this org's state changed while
        it was released (the request then stops in the safe order; see `ui.scim._group_change`).

    The caller holds its org's own lock (`_org_lock`) throughout, so no other SCIM write of the org runs between two
    holds; `holds` counts the holds taken (tests read it)."""

    def __init__(self, p, org_id: str) -> None:
        self.p = p
        self.org_id = org_id
        self.records = 0                       # what the request appended (ui.scim sets it)
        self.holds = 0
        self._flock = None

    @property
    def held(self) -> bool:
        return self._flock is not None

    def _enter(self) -> None:
        from vigil_integration.live.seam_lock import LockBusy

        from .provision import _members_lock
        from .scim import SectionLost
        self.p._lock.acquire()
        try:
            cm = _members_lock(self.p.store)
            cm.__enter__()
        except LockBusy as e:
            self.p._lock.release()
            raise SectionLost("the membership critical section is busy") from e
        except BaseException:
            self.p._lock.release()
            raise
        self._flock = cm
        self.holds += 1

    def _exit(self) -> None:
        cm, self._flock = self._flock, None
        if cm is None:
            return
        try:
            cm.__exit__(None, None, None)
        finally:
            self.p._lock.release()

    def fold(self, fn):
        store = self.p.store
        for _attempt in range(_FOLD_ATTEMPTS):
            t0 = store.disk_tip()
            if t0 is None:
                break
            for _r in store.iter_records(since_seq=t0):    # builds the store's seq index OUTSIDE the section
                pass
            value = fn()
            self._enter()
            if not _org_state_changed(store, self.org_id, t0):
                return value
            self._exit()
        self._enter()
        return fn()

    def slice(self) -> None:
        from .scim import SectionLost
        tip = self.p.store.disk_tip()
        self._exit()
        _handoff()
        self._enter()
        if tip is None or _org_state_changed(self.p.store, self.org_id, tip):
            raise SectionLost("this organization's membership state changed while the request was paused")

    def close(self) -> None:
        self._exit()


def _critical_audit(p, org_id: str):
    """The audit hook `ui.scim` calls BEFORE each membership grant / revoke: a critical row (fail-closed)."""
    def audit(action: str, target: str, outcome: str) -> None:
        p._audit(action, requester="idp", org_id=org_id, target=target, outcome=outcome, critical=True)
    return audit


def _resume_pending_jobs(p, org_id: str, cfgreg, directory, *, now: float) -> None:
    """At a sign-in of a directory-managed org: finish the org's pending group jobs (`ui.scim.resume_directory_jobs`)
    — in bounded holds, under the org's own lock, charged to its write budget — so a group change a crash cut short
    does not wait for the IdP's next write. Only when that lock is FREE (a SCIM write of the org in flight finishes
    the job itself), and best effort: whatever it cannot do, the sign-in's own clamp still keeps the person at or
    below the role the directory implies."""
    from . import scim as uiscim
    try:
        with _org_lock(p, org_id, "write", wait_s=0.0):
            section = _SharedSection(p, org_id)
            try:
                uiscim.resume_directory_jobs(org_id=org_id, config_registry=cfgreg, org_registry=p.orgs, now=now,
                                             directory_registry=directory, issued_at_fn=p._next_issued,
                                             audit=_critical_audit(p, org_id), section=section)
            finally:
                section.close()
                if section.records > 0 and p.scim_write_limiter is not None:
                    p.scim_write_limiter.charge(f"scim:writes:{org_id}", section.records, now=now)
    except Exception:  # noqa: BLE001 — best effort (busy lock, audit store down, ...): the sign-in decides alone
        return


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
        _resume_pending_jobs(p, oid, cfgreg, directory, now=t)
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
        _resume_pending_jobs(p, oid, cfgreg, directory, now=t)
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
    in `deactivated`. Authentication is the org's owner-signed bearer fingerprint (constant-time). Then (see the
    module docstring for every bound):
      * a body over a per-request bound is refused 400 before anything is taken;
      * a READ takes the org's read lock (bounded wait, else 429), spends one unit of the org's read budget
        (`VIGIL_SCIM_READS_PER_MIN`; 429 + Retry-After when spent) and folds lock-free — it never enters the shared
        membership critical section;
      * a WRITE takes the org's write lock (bounded wait, else 429), and INSIDE it is admitted by the org's write
        budget (one unit; skipped for a request that can only take privilege away, `ui.scim.lowers_only`), runs in
        bounded holds of the shared section (`_SharedSection`, `ui.scim.MAX_RECORDS_PER_HOLD` records per hold),
        and is charged in a `finally` for every further record it appended, also when it fails part-way.

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
    reads = getattr(p, "scim_read_limiter", None)
    if p.scim_auth_limiter is None or p.scim_write_limiter is None or reads is None:
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
    if over is not None:                   # refused on its body alone: no lock taken, no budget spent
        return {"status": over.status, "body": over.body, "deactivated": []}

    def dispatch(section) -> "uiscim.ScimResult":
        return uiscim.scim_dispatch(m, path, body, authorization, org_id=oid, config_registry=cfgreg,
                                    org_registry=p.orgs, now=t, query=str(query or ""),
                                    directory_registry=directory, issued_at_fn=p._next_issued,
                                    audit=_critical_audit(p, oid), section=section)
    busy = _scim_refusal(429, "another SCIM request of this organization is in progress; retry shortly",
                         retry_after=_ORG_LOCK_WAIT_S)
    if m not in _SCIM_WRITES:
        lock = _held(_org_lock(p, oid, "read"))
        if lock is None:
            return busy
        with lock:
            wait = reads.admit(f"scim:reads:{oid}", now=t)
            if wait is not None:
                return _scim_refusal(429, "this organization's SCIM read rate is exceeded; retry shortly",
                                     retry_after=wait)
            r = dispatch(None)               # lock-free: a read appends nothing and never enters the shared section
        return {"status": r.status, "body": r.body, "deactivated": list(r.deactivated)}
    budget = f"scim:writes:{oid}"
    lock = _held(_org_lock(p, oid, "write"))
    if lock is None:
        return busy
    with lock:
        lowers = uiscim.lowers_only(m, path, body)
        if not lowers:                       # checked AND (below) charged inside the org's lock
            wait = p.scim_write_limiter.admit(budget, now=t)
            if wait is not None:
                return _scim_refusal(429, "this organization's SCIM write rate is exceeded; retry shortly",
                                     retry_after=wait)
        section = _SharedSection(p, oid)
        try:
            r = dispatch(section)
        finally:
            section.close()
            owed = section.records - (0 if lowers else 1)        # `admit` counted one unit
            if owed > 0:
                p.scim_write_limiter.charge(budget, owed, now=t)
    return {"status": r.status, "body": r.body, "deactivated": list(r.deactivated)}


@contextmanager
def _entered(cm) -> Iterator[None]:
    try:
        yield
    finally:
        cm.__exit__(None, None, None)


def _held(cm):
    """`cm` (an `_org_lock`) entered, as a context manager that releases it — or None when it stayed busy."""
    from vigil_integration.live.seam_lock import LockBusy
    try:
        cm.__enter__()
    except LockBusy:
        return None
    return _entered(cm)
