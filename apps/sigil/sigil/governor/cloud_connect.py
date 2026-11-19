"""Customer READ-ONLY CLOUD-GRANT connect — the self-serve, infrastructure-bound record that a customer has
connected a cloud account they control (consumer PR-C; the unified connect surface's cloud leg).

WHAT THIS IS: a per-org, owner-signed record that a customer has PROVEN CONTROL of a specific cloud account by
creating, in THAT account's own IAM, a read-only role that trusts VIGIL's connector principal under a VIGIL-issued,
unguessable ``external_id`` — the classic cross-account, confused-deputy-safe grant. Trusted sovereign code
(``ui.cloud_fetch``) then ASSUMES that role with our external_id and reads back the caller identity; the account the
role lands in IS the proof of control (only that account's IAM controller can create a role there and trust VIGIL).

THE SAME-SHAPE NEGATIVE CONTROL (why the verdict also needs a DENIAL): a successful assume with our external id
proves nothing about whether the role's trust policy REQUIRES that id. A role that trusts VIGIL's principal with no
``sts:ExternalId`` condition would also succeed — and then ANY VIGIL tenant could name that role and connect another
customer's account through VIGIL (the confused-deputy hole the external id exists to close). So the fetcher also
assumes the SAME role with a FRESH RANDOM external id, and the verdict holds only if that control was explicitly
DENIED. A role that admits an arbitrary external id is refused, for every tenant, with a message naming the fix.

WHY IT MATTERS (the doctrine, stated once, enforced): own-a-repo != own-a-host != CONNECT-A-CLOUD-ACCOUNT !=
offense-test. Connecting a cloud account RECORDS an owner-verified asset; it is a DISTINCT, read-only capability.
It NEVER, by itself, authorizes a live offense run — not against the cloud account, not against anything. The
``VIGIL_CUSTOMER_PROD_EXECUTION`` owner gate (``vigil_core.posture``) and the host-ownership + EngagementAuthority
chain are UNCHANGED by anything here. ``assume_target`` is the one read a later READ-ONLY posture run consumes, and
that run is a separate engagement that must itself pass ``build_offense_gate -> conjunctive_decide``.

TRUST BOUNDARY (critical, mirrors ``asset_ownership``): the observation (what the two AssumeRole calls and the
GetCallerIdentity call returned) is produced by TRUSTED SOVEREIGN CODE — NEVER supplied by the customer.
``verify_and_connect`` runs the deterministic verdict ITSELF over that observation and records an owner-signed grant
ONLY when the verdict passes; a grant is never recorded without the verdict firing. This module stays NETWORK-FREE
and independently testable (the I/O is injected).

CLAIM BOUNDARY (claim-discipline): the verdict proves ACCOUNT CONTROL and that the role ENFORCES our external id. It
does NOT prove the granted role is minimally scoped / genuinely read-only — that is a property of the customer's
attached permissions policy (the connect screen asks for AWS's managed ``SecurityAudit``). The grant RECORDS the
connection as read-only INTENT; it does not claim to have verified the policy's scope.

ASYMMETRIC AUTHENTICATION (mirrors ``asset_ownership`` / ``connected_repos``):
  * issue_challenge / record a verified grant = the DANGEROUS direction -> honored only if OWNER-SIGNED
    (``verify_signed``) AND its ``issued_at`` STRICTLY exceeds the per-(org_id, provider, account_id) high-water.
  * disconnect a grant = the SAFE direction -> ``state="revoked"`` honored even UNSIGNED, fixed ``issued_at`` 0.0
    (a replayed revoke merely re-revokes; gating the fail-safe direction would make it fail OPEN).

ANTI-REPLAY: per-(org_id, provider, account_id) last-writer-wins high-water (the SAME resurrection guard
accounts/orgs/asset_ownership carry). A captured owner-signed active grant cannot resurrect a revoked grant (its
``issued_at`` <= high-water -> ignored). Every grant also carries an OWNER-SIGNED ``expires_at`` so a lapsed grant
cannot be silently extended — re-connecting requires a fresh challenge + a fresh observation. OWNER-KEY SUCCESSION
is honored exactly as ``asset_ownership._fold``. HARD-PRUNE DURABILITY: the fold is a signature-verifying genesis
scan of the live window (no snapshot seed), so — exactly as ``connected_repos`` — a fail-closed TRIPWIRE
(``spine.prune.stranded_active_cloud_grants``) refuses a hard prune that would strand an active grant's only record
(which would silently disconnect it, or reset its high-water and re-open replay-resurrection).

FATAL-2: SOVEREIGN-side, ``assert_no_offense()`` at import; imports only the shared ``vigil_core`` (via
``reuse``) + the sovereign governor siblings (``authn`` / ``identity`` / ``key_history``). No ``framework`` /
``strix`` import.
"""
from __future__ import annotations

import hmac
import json
import re
import secrets
from dataclasses import dataclass, field
from typing import Optional

from ..reuse import assert_no_offense

assert_no_offense()

from . import key_history as _kh  # noqa: E402  (owner-key succession resolver, mirrors asset_ownership)
from .asset_ownership import _check_org_id  # noqa: E402  (the ONE tenant-id validator, shared)
from .authn import NO_HIGHWATER, as_issued_at, signed_payload, verify_signed  # noqa: E402
from .identity import owner_keypair, owner_pubkey  # noqa: E402

# Dedicated payload signals under the generic enforced ``kind="event"`` record (mirrors asset_ownership), so a
# NEW kind need not be registered with the write-path guard — the signal disambiguates the fold.
CHALLENGE_SIGNAL = "governor.cloud_connect_challenge"
GRANT_SIGNAL = "governor.cloud_connect_grant"

# The cloud provider vocabulary. The proof is CONCRETE for AWS (external-id assume-role + caller-identity account
# match + the same-shape negative control). GCP (service-account impersonation) and Azure (a multi-tenant app
# registration) need a different observation; their verdict is not wired (VIGIL-LIMIT:LIMIT-cloud-connect-gcp-azure-verdict),
# so BOTH a challenge and a verify refuse them — a customer is never walked into a flow that cannot finish.
PROVIDER_AWS = "aws"
PROVIDER_GCP = "gcp"
PROVIDER_AZURE = "azure"
_PROVIDERS = frozenset({PROVIDER_AWS, PROVIDER_GCP, PROVIDER_AZURE})
# The providers whose deterministic proof-of-control verdict exists. Anything else fails closed at the first step.
_VERIFIABLE_PROVIDERS = frozenset({PROVIDER_AWS})

# A cloud ACCOUNT id: a provider-agnostic single safe token (alnum start, then [A-Za-z0-9._-], max 128) — one safe
# spine key component that can never widen scope. AWS additionally requires the exact 12-digit account id.
_ACCOUNT_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}")
_AWS_ACCOUNT_RE = re.compile(r"[0-9]{12}")
# A role / grant REFERENCE the customer created — a public identifier, never a secret. Bounded + control-char-free;
# for AWS it must be the full IAM role ARN in the aws partition, IN the account being connected.
_ROLE_REF_MAX = 512
_AWS_ROLE_ARN_RE = re.compile(r"arn:aws:iam::([0-9]{12}):role/[A-Za-z0-9+=,.@_/-]{1,512}")

# The AWS managed policy the connect screen asks the customer to attach: read-only access to security configuration
# metadata (list/describe/get), the standard for cloud-posture tooling. Shown, never enforced by this module.
AWS_READ_ONLY_POLICY_ARN = "arn:aws:iam::aws:policy/SecurityAudit"

# A conservative default grant validity window. Cloud access changes hands (a role is deleted, an account is
# closed), so a grant EXPIRES and must be re-connected. 90 days mirrors the ownership-proof cadence; the owner
# signs the concrete ``expires_at``, so lengthening it is a deliberate owner act, never a config.
_DEFAULT_GRANT_TTL_S: float = 90.0 * 24.0 * 3600.0

# The owner-signed authenticated CORE of each record. ``issued_at`` MUST be inside it (else a captured grant could be
# re-stamped fresh past the high-water without breaking the signature). For a challenge the external_id is inside it
# so an owner-signed challenge cannot be re-tokened. For a grant org_id/provider/account_id/role_ref/external_id/
# verified_at/expires_at are inside it so a grant for (orgA, aws, 1111) can never be re-aimed at another org/account,
# nor have its role, its external id or its window rewritten. The grant carries the external id ITSELF (not a hash)
# so it stays CONSUMABLE after a later challenge supersedes the one it was proven against (``assume_target``).
_CHALLENGE_CORE = ("signal", "org_id", "provider", "account_id", "external_id", "state", "issued_at")
_GRANT_CORE = ("signal", "org_id", "provider", "account_id", "role_ref", "external_id",
               "verified_at", "expires_at", "state", "issued_at")

_SKIP = object()          # the shared fold step: the record touched no (org_id, provider, account_id)
_LOAD_FROM_VAULT = object()


# ---------------------------------------------------------------------------------------------------
# Validation (fail-closed at binding time — a clean ValueError now, never a silent bad record later).
# ---------------------------------------------------------------------------------------------------

def _check_provider(provider: str) -> str:
    p = str(provider or "").strip().lower()
    if p not in _PROVIDERS:
        raise ValueError(f"provider must be one of {sorted(_PROVIDERS)}")
    return p


def _check_verifiable(provider: str) -> str:
    """A provider whose proof-of-control VIGIL can actually check — anything else refuses at the first step."""
    p = _check_provider(provider)
    if p not in _VERIFIABLE_PROVIDERS:
        raise ValueError(f"connecting a {p!r} account is not available — only AWS accounts can be connected today")
    return p


def _check_account(account_id: str, provider: str = "") -> str:
    a = str(account_id or "").strip()
    if not _ACCOUNT_RE.fullmatch(a):
        raise ValueError("account_id must be an alphanumeric start then [A-Za-z0-9._-], max 128 chars, "
                         "no separators / traversal / spaces (an AWS account id / GCP project / Azure subscription)")
    if provider == PROVIDER_AWS and not _AWS_ACCOUNT_RE.fullmatch(a):
        raise ValueError("an AWS account id is exactly 12 digits")
    return a


def _check_role_ref(role_ref: str, provider: str = "", account_id: str = "") -> str:
    r = str(role_ref or "").strip()
    if not r:
        raise ValueError("a role reference is required (the read-only role you created for VIGIL)")
    if len(r) > _ROLE_REF_MAX or any(ord(c) < 0x20 or ord(c) == 0x7f for c in r):
        raise ValueError("role reference must be a non-empty, control-char-free string under 512 chars")
    if provider == PROVIDER_AWS:
        m = _AWS_ROLE_ARN_RE.fullmatch(r)
        if not m:
            raise ValueError("give the role's full ARN, e.g. arn:aws:iam::123456789012:role/VigilSecurityAudit")
        if account_id and m.group(1) != account_id:
            raise ValueError("the role ARN names a different AWS account than the one you are connecting")
    return r


# ---------------------------------------------------------------------------------------------------
# The deterministic verdict (PURE — no network, no state). Exposed for independent testing; the registry calls
# it inside ``verify_and_connect`` so a grant is never recorded without it firing.
# ---------------------------------------------------------------------------------------------------

def _ct_eq(a: str, b: str) -> bool:
    """Constant-time equality over UTF-8 bytes (never raises on non-ASCII, unlike compare_digest on a str)."""
    return hmac.compare_digest(str(a or "").encode("utf-8"), str(b or "").encode("utf-8"))


_NOT_MADE = "the connection check was not completed — start it again"


def cloud_grant_refusal(provider: str, external_id: str, account_id: str, observed, *,
                        control_external_id: str) -> Optional[str]:
    """``None`` iff ``observed`` proves CONTROL of ``account_id`` under ``provider`` via the VIGIL ``external_id``
    AND that the role ENFORCES that id; otherwise the customer-facing reason it does not. TOTAL and FAIL-CLOSED: an
    unknown/unverifiable provider, an empty id, a control id equal to the real one, or a malformed observation all
    refuse (never raises).

    ``observed`` is what the TRUSTED SOVEREIGN FETCHER saw (never customer-supplied). For AWS:

        {"assumed_with_external_id": <the id VIGIL assumed with>, "account": <GetCallerIdentity account>,
         "control_external_id": <the random id of the control assume>, "control_denied": <True iff AccessDenied>}

    The verdict holds iff ALL of:
      * ``assumed_with_external_id`` equals this challenge's ``external_id`` (constant-time) — the observation
        belongs to THIS challenge, so a replayed observation from a prior challenge is refused;
      * ``account`` equals the claimed ``account_id`` — the role LANDS IN the claimed account. THE control proof;
      * ``control_external_id`` equals the control id the provisioner generated for this check and differs from the
        real id, and ``control_denied`` is exactly ``True`` — the same role REFUSED an arbitrary external id, so its
        trust policy enforces ours (the confused-deputy guard; see the module docstring)."""
    try:
        ext, ctl = str(external_id or ""), str(control_external_id or "")
        if provider not in _VERIFIABLE_PROVIDERS:
            return "connecting this kind of cloud account is not available"
        if not ext or not ctl or _ct_eq(ext, ctl) or not isinstance(observed, dict):
            return _NOT_MADE
        got_ext, got_acct = observed.get("assumed_with_external_id"), observed.get("account")
        got_ctl, denied = observed.get("control_external_id"), observed.get("control_denied")
        if not isinstance(got_ext, str) or not _ct_eq(ext, got_ext):
            return _NOT_MADE
        if not isinstance(got_ctl, str) or not _ct_eq(ctl, got_ctl):
            return _NOT_MADE
        if not isinstance(got_acct, str) or not _ct_eq(str(account_id or ""), got_acct):
            return (f"control of {account_id} was not proven — the role VIGIL assumed is not in that account "
                    f"(check the account id and the role ARN)")
        if denied is not True:
            return ("the role does not require VIGIL's external id: its trust policy must carry the "
                    "sts:ExternalId condition shown on the connect screen (without it any VIGIL customer could name "
                    "this role), so the account was not connected")
        return None
    except Exception:  # noqa: BLE001 — a verdict is total: anything unexpected refuses
        return _NOT_MADE


def cloud_grant_proves(provider: str, external_id: str, account_id: str, observed, *,
                       control_external_id: str) -> bool:
    """``True`` iff :func:`cloud_grant_refusal` finds nothing to refuse (the boolean form of the same verdict)."""
    return cloud_grant_refusal(provider, external_id, account_id, observed,
                               control_external_id=control_external_id) is None


# ---------------------------------------------------------------------------------------------------
# Placement — a deterministic function of (VIGIL's connector principal, external_id). The edge hands this to the
# customer verbatim ("create a read-only role whose trust policy is exactly this").
# ---------------------------------------------------------------------------------------------------

def aws_trust_policy(principal_arn: str, external_id: str) -> str:
    """The exact IAM trust policy (JSON text) the customer's read-only role needs: it trusts ONLY VIGIL's connector
    principal and ONLY under this challenge's ``sts:ExternalId``. Deterministic (stable key order) so the screen and a
    test agree byte-for-byte."""
    doc = {"Version": "2012-10-17",
           "Statement": [{"Effect": "Allow", "Principal": {"AWS": str(principal_arn)}, "Action": "sts:AssumeRole",
                          "Condition": {"StringEquals": {"sts:ExternalId": str(external_id)}}}]}
    return json.dumps(doc, indent=2)


@dataclass(frozen=True)
class CloudConnectChallenge:
    org_id: str
    provider: str
    account_id: str
    external_id: str     # the unguessable VIGIL external-id the customer must require in the role's trust policy
    issued_at: float     # owner-set anti-replay high-water for this (org_id, provider, account_id) challenge


@dataclass(frozen=True)
class CloudGrant:
    org_id: str
    provider: str
    account_id: str
    role_ref: str                # the read-only role the customer created (a public id, never a secret)
    external_id: str = field(repr=False)   # the id the role's trust policy requires (never rendered in a repr)
    verified_at: float = 0.0
    expires_at: float = 0.0      # owner-signed expiry — re-connecting required after this
    issued_at: float = 0.0       # owner-set anti-replay high-water for this grant
    state: str = "active"        # "active" | "revoked"
    access: str = "read-only"    # the RECORDED connection intent (see the module CLAIM BOUNDARY note)

    @property
    def external_id_sha256(self) -> str:
        """A log-safe identifier of the external id this grant was proven under."""
        from ..reuse import sha256_hex
        return sha256_hex(self.external_id.encode("utf-8"))


@dataclass(frozen=True)
class CloudAssumeTarget:
    """What a later, separately-gated READ-ONLY posture run needs to reach a connected account: the role to assume
    and the external id its trust policy requires. Holding one authorizes NOTHING — the run is an engagement that
    must itself pass ``build_offense_gate -> conjunctive_decide``."""
    org_id: str
    provider: str
    account_id: str
    role_ref: str
    external_id: str = field(repr=False)
    expires_at: float = 0.0


# ---------------------------------------------------------------------------------------------------
# The fold body — shared by every read so they can never diverge (mirrors asset_ownership._apply_ownership_record).
# ---------------------------------------------------------------------------------------------------

def _grant_row(p: dict, at: float) -> dict:
    return {"provider": p.get("provider"), "account_id": p.get("account_id"), "role_ref": p.get("role_ref"),
            "external_id": p.get("external_id"), "verified_at": p.get("verified_at"),
            "expires_at": p.get("expires_at"), "issued_at": at}


def _payload_row(p: dict, at: float) -> dict:
    return dict(p)


def _apply_cloud_record(r, resolver, signal: str, core_fields, row_of, state: dict, issued: dict, rows: dict):
    """Fold ONE spine record of ``signal`` into (state, issued, rows). Returns the (org_id, provider, account_id)
    it touched, or ``_SKIP``. The DANGEROUS ``active`` direction verifies the owner signature under the pubkey
    valid at the record's seq and refuses a stale/replayed re-append; the SAFE ``revoked`` direction is honored
    regardless of signature (so it can never fail open)."""
    p = getattr(r, "payload", None)
    if not isinstance(p, dict) or p.get("signal") != signal:
        return _SKIP
    org_id = p.get("org_id")
    provider = p.get("provider")
    account_id = p.get("account_id")
    if (not isinstance(org_id, str) or not org_id or not isinstance(provider, str) or not provider
            or not isinstance(account_id, str) or not account_id):
        return _SKIP
    key = (org_id, provider, account_id)
    rec_state = p.get("state")
    if rec_state == "revoked":
        state[key] = "revoked"                     # honor ANY revoke (even unsigned) — safe direction
        return key
    if rec_state == "active":
        if not verify_signed(p, core_fields, resolver.at(r.seq)):
            return _SKIP                           # fail-closed: unsigned/forged/wrong-epoch-key grant
        at = as_issued_at(p.get("issued_at"))
        if at <= issued.get(key, NO_HIGHWATER):
            return _SKIP                           # REPLAY / stale re-append of an already-honored grant
        issued[key] = at
        state[key] = "active"
        rows[key] = row_of(p, at)
        return key
    return _SKIP


class CloudConnectRegistry:
    def __init__(self, store, *, owner_key=_LOAD_FROM_VAULT, trusted_pubkey: Optional[str] = None):
        self.store = store
        # Signing paths leave owner_key unset → load it from the vault. A pure-READ caller passes owner_key=None
        # explicitly → the owner PRIVATE key is never touched on that path (least-privilege, mirrors asset_ownership).
        self.owner_key = owner_keypair() if owner_key is _LOAD_FROM_VAULT else owner_key
        self.trusted_pubkey = trusted_pubkey if trusted_pubkey is not None else owner_pubkey()

    # -- owner mutations ----------------------------------------------------------------------------
    def issue_challenge(self, org_id: str, provider: str, account_id: str, *, issued_at: float,
                        external_id: Optional[str] = None) -> CloudConnectChallenge:
        """Owner-sign a fresh connect CHALLENGE for (org_id, provider, account_id) — the DANGEROUS direction,
        honored only if it verifies AND is FRESH (``issued_at`` strictly exceeds the per-key challenge high-water).
        Refuses a provider VIGIL cannot verify (no dead-end flow). A new challenge supersedes the prior one (LWW).
        ``external_id`` is injectable for tests; in production a fresh 256-bit URL-safe secret.

        A challenge grants NOTHING on its own — it is only the external-id the later verdict checks VIGIL assumed
        the role with."""
        if self.owner_key is None:
            raise ValueError("issuing a cloud-connect challenge requires the owner signing key")
        oid, prov = _check_org_id(org_id), _check_verifiable(provider)
        acct = _check_account(account_id, prov)
        ext = str(external_id) if external_id is not None else secrets.token_urlsafe(32)
        if not ext or any(ord(c) < 0x20 or ord(c) == 0x7f for c in ext):
            raise ValueError("external_id must be a non-empty control-char-free string")
        core = {"signal": CHALLENGE_SIGNAL, "org_id": oid, "provider": prov, "account_id": acct,
                "external_id": ext, "state": "active", "issued_at": float(issued_at)}
        payload = {**signed_payload(core, self.owner_key), "by": "owner", "requested_by": "owner",
                   "tier": "A0", "decision": "auto",
                   "reason": f"cloud-connect challenge issued for {prov}:{acct} (org {oid})"}
        self.store.append(kind="event", source="governor", actor="WARDEN", payload=payload)
        return CloudConnectChallenge(org_id=oid, provider=prov, account_id=acct, external_id=ext,
                                     issued_at=float(issued_at))

    def verify_and_connect(self, org_id: str, provider: str, account_id: str, *, role_ref: str,
                           observed, control_external_id: str, now: float,
                           ttl_seconds: float = _DEFAULT_GRANT_TTL_S) -> CloudGrant:
        """Run the deterministic verdict over a TRUSTED observation and, ONLY on success, owner-sign a READ-ONLY
        cloud GRANT for (org_id, provider, account_id). Fail-closed — raises ``ValueError`` (its text is the
        customer-facing reason) on an invalid org/provider/account/role, an unverifiable provider, a missing/stale
        challenge, a non-positive ttl, or a verdict that does not fire; a grant is NEVER recorded otherwise.

        ``observed`` is what the TRUSTED SOVEREIGN FETCHER saw (never customer-supplied); ``control_external_id`` is
        the random id the provisioner generated for this check's negative control. The verdict is checked against
        the CURRENT active challenge's external_id for the key; a verify with no outstanding challenge, or against a
        superseded external_id, refuses. On success the grant carries an owner-signed ``expires_at`` =
        ``now + ttl_seconds`` and the verified external id (so a later gated run can assume the role).

        RECORDING A GRANT AUTHORIZES NO OFFENSE: it is a read-only CONNECTION record (see the module docstring)."""
        if self.owner_key is None:
            raise ValueError("recording a cloud grant requires the owner signing key")
        oid, prov = _check_org_id(org_id), _check_verifiable(provider)
        acct = _check_account(account_id, prov)
        ref = _check_role_ref(role_ref, prov, acct)
        ttl = float(ttl_seconds)
        if not (ttl > 0.0):
            raise ValueError("ttl_seconds must be positive")
        ch = self.challenge(oid, prov, acct)
        if ch is None:
            raise ValueError(f"no outstanding cloud-connect challenge for {prov}:{acct} (org {oid}) — issue one first")
        refusal = cloud_grant_refusal(prov, ch.external_id, acct, observed, control_external_id=control_external_id)
        if refusal is not None:
            raise ValueError(refusal)
        verified_at = float(now)
        core = {"signal": GRANT_SIGNAL, "org_id": oid, "provider": prov, "account_id": acct, "role_ref": ref,
                "external_id": ch.external_id, "verified_at": verified_at, "expires_at": verified_at + ttl,
                "state": "active", "issued_at": verified_at}
        payload = {**signed_payload(core, self.owner_key), "by": "owner", "requested_by": "owner",
                   "tier": "A0", "decision": "auto",
                   "reason": f"read-only cloud grant RECORDED for {prov}:{acct} by org {oid} (owner-signed)"}
        self.store.append(kind="event", source="governor", actor="WARDEN", payload=payload)
        return CloudGrant(org_id=oid, provider=prov, account_id=acct, role_ref=ref, external_id=ch.external_id,
                          verified_at=verified_at, expires_at=verified_at + ttl, issued_at=verified_at,
                          state="active")

    def disconnect(self, org_id: str, provider: str, account_id: str) -> int:
        """Disconnect a cloud grant — the SAFE direction (honored even unsigned, fixed ``issued_at`` 0.0).
        Idempotent + replay-safe: a replayed revoke merely re-revokes. Used on offboarding / tenant decommission
        or when the customer removes the role. A grant with no active record authorizes nothing anywhere."""
        oid, prov, acct = _check_org_id(org_id), _check_provider(provider), _check_account(account_id)
        core = {"signal": GRANT_SIGNAL, "org_id": oid, "provider": prov, "account_id": acct, "role_ref": "",
                "external_id": "", "verified_at": 0.0, "expires_at": 0.0, "state": "revoked", "issued_at": 0.0}
        payload = {**signed_payload(core, self.owner_key), "by": "owner", "requested_by": "owner",
                   "tier": "A0", "decision": "auto",
                   "reason": f"cloud grant for {prov}:{acct} (org {oid}) DISCONNECTED (governed latch)"}
        return self.store.append(kind="event", source="governor", actor="WARDEN", payload=payload)

    # -- reads (owner-key-succession-aware folds) ---------------------------------------------------
    def _fold(self, signal: str, core_fields, row_of) -> dict:
        """Fold the spine into {(org_id, provider, account_id): record_dict} whose latest state is active,
        authenticating each ``active`` grant under the owner pubkey valid AT ITS SEQ and refusing any stale/
        replayed re-append via the per-key high-water. Revokes (safe direction) are honored regardless of
        signature. A genesis scan of the live window (no snapshot seed — the prune tripwire is the invariant)."""
        resolver = _kh.key_resolver(self.store, current=self.trusted_pubkey)
        state: dict[tuple, str] = {}
        issued: dict[tuple, float] = {}
        rows: dict[tuple, dict] = {}
        for r in self.store.iter_records():
            _apply_cloud_record(r, resolver, signal, core_fields, row_of, state, issued, rows)
        return {k: row for k, row in rows.items() if state.get(k) == "active"}

    def challenge(self, org_id: str, provider: str, account_id: str) -> Optional[CloudConnectChallenge]:
        """The current active challenge for the key, or None (fail-closed). The latest owner-signed,
        non-superseded external-id."""
        try:
            oid, prov, acct = _check_org_id(org_id), _check_provider(provider), _check_account(account_id)
        except ValueError:
            return None
        row = self._fold(CHALLENGE_SIGNAL, _CHALLENGE_CORE, _payload_row).get((oid, prov, acct))
        if row is None:
            return None
        return CloudConnectChallenge(org_id=oid, provider=prov, account_id=acct,
                                     external_id=str(row.get("external_id") or ""),
                                     issued_at=as_issued_at(row.get("issued_at")))

    def grant(self, org_id: str, provider: str, account_id: str) -> Optional[CloudGrant]:
        """The current active grant record for the key, or None (fail-closed). Does NOT apply the expiry filter —
        use ``has_current_grant`` / ``assume_target`` for a time-aware gate."""
        try:
            oid, prov, acct = _check_org_id(org_id), _check_provider(provider), _check_account(account_id)
        except ValueError:
            return None
        row = self._fold(GRANT_SIGNAL, _GRANT_CORE, _grant_row).get((oid, prov, acct))
        if row is None:
            return None
        return self._grant_of_row(oid, prov, acct, row)

    @staticmethod
    def _grant_of_row(oid: str, prov: str, acct: str, row: dict) -> CloudGrant:
        return CloudGrant(
            org_id=oid, provider=prov, account_id=acct, role_ref=str(row.get("role_ref") or ""),
            external_id=str(row.get("external_id") or ""),
            verified_at=float(as_issued_at(row.get("verified_at"))),
            expires_at=float(as_issued_at(row.get("expires_at"))),
            issued_at=as_issued_at(row.get("issued_at")), state="active")

    def has_current_grant(self, org_id: str, provider: str, account_id: str, *, now: float) -> bool:
        """True iff the key has an ACTIVE, UNEXPIRED read-only grant at ``now``. DEFAULT-DENY — no grant, a
        revoked grant, a grant for a DIFFERENT org, or an expired grant all refuse. This answers ONLY the
        connection question; it is NEVER a testing/offense authorization."""
        g = self.grant(org_id, provider, account_id)
        if g is None:
            return False
        return float(now) < g.expires_at

    def assume_target(self, org_id: str, provider: str, account_id: str, *, now: float) -> Optional[CloudAssumeTarget]:
        """The ONE read a later READ-ONLY posture run consumes: the role + external id of an ACTIVE, UNEXPIRED,
        owner-signed grant of a VERIFIABLE provider for exactly (org_id, provider, account_id), else None.
        DEFAULT-DENY on everything else (no grant, revoked, expired, another org's account, an empty role/id).
        Returning a target authorizes NOTHING: the run is an engagement that must itself pass
        ``build_offense_gate -> conjunctive_decide``; the engine-side consumer of this read is not built
        (VIGIL-LIMIT:LIMIT-customer-cloud-posture-run)."""
        g = self.grant(org_id, provider, account_id)
        if g is None or g.provider not in _VERIFIABLE_PROVIDERS or not (float(now) < g.expires_at):
            return None
        if not g.role_ref or not g.external_id:
            return None
        return CloudAssumeTarget(org_id=g.org_id, provider=g.provider, account_id=g.account_id,
                                 role_ref=g.role_ref, external_id=g.external_id, expires_at=g.expires_at)

    def grants_of_org(self, org_id: str, *, now: Optional[float] = None) -> "list[CloudGrant]":
        """Every cloud account ``org_id`` currently has connected, in (provider, account) order. CROSS-TENANT
        ISOLATED — only this org's rows (the fold is keyed per (org, provider, account) and the comprehension
        keeps only ``o == oid``), so one tenant can never read another's cloud grants. When ``now`` is given,
        EXPIRED grants are dropped (the time-aware view the connect screen shows)."""
        if not isinstance(org_id, str) or not org_id:
            return []
        try:
            oid = _check_org_id(org_id)
        except ValueError:
            return []
        out: list[CloudGrant] = []
        for (o, prov, acct), row in sorted(self._fold(GRANT_SIGNAL, _GRANT_CORE, _grant_row).items()):
            if o != oid:
                continue
            g = self._grant_of_row(o, prov, acct, row)
            if now is not None and not (float(now) < g.expires_at):
                continue
            out.append(g)
        return out

    def cloud_overview(self, org_id: str, *, now: float) -> "list[dict]":
        """Per-account connection status for ALL of ``org_id``'s cloud grants, in (provider, account) order — the
        tenant-scoped read behind the connect screen's cloud leg. DEFAULT-DENY to this org (the fold is keyed per
        (org, provider, account); another tenant's accounts are STRUCTURALLY absent, never a client-chosen filter).
        Each account is ``connected`` (active + unexpired) or ``expired`` (active grant past its owner-signed
        expiry → re-connect). Read-only: no lock, no mint, no owner key. A fixed allowlist of fields — the external
        id is NEVER projected; ``access`` is the recorded read-only intent."""
        if not isinstance(org_id, str) or not org_id:
            return []
        try:
            oid = _check_org_id(org_id)
        except ValueError:
            return []
        n = float(now)
        out: list[dict] = []
        for (o, prov, acct), row in sorted(self._fold(GRANT_SIGNAL, _GRANT_CORE, _grant_row).items()):
            if o != oid:
                continue
            exp = float(as_issued_at(row.get("expires_at")))
            out.append({"provider": prov, "account_id": acct, "role_ref": str(row.get("role_ref") or ""),
                        "verified_at": float(as_issued_at(row.get("verified_at"))), "expires_at": exp,
                        "access": "read-only", "status": "connected" if n < exp else "expired"})
        return out


def cloud_overview(store, org_id: str, *, now: float) -> dict:
    """Projector for the customer-plane connect read: the tenant-scoped per-account cloud-connection status for
    ``org_id``. A thin wrapper over :meth:`CloudConnectRegistry.cloud_overview` so the provisioner's
    ``_customer_read`` gate can call it exactly like ``assets_overview`` (``admit_customer`` has ALREADY
    authorized ``org_id`` as the session's own tenant before this runs)."""
    return {"cloud": CloudConnectRegistry(store, owner_key=None).cloud_overview(org_id, now=float(now))}
