"""Customer READ-ONLY CLOUD-GRANT connect — the self-serve, infrastructure-bound record that a customer has
connected a cloud account they control (consumer PR-C; the unified connect surface's cloud leg).

WHAT THIS IS: a per-org, owner-signed record that a customer has PROVEN CONTROL of a specific cloud account by
creating, in THAT account's own IAM, a read-only role that trusts VIGIL's connector principal under a VIGIL-issued,
unguessable ``external_id`` — the classic cross-account, confused-deputy-safe grant. Trusted sovereign code
(``ui.cloud_fetch``) then ASSUMES that role with our external_id and reads back the caller identity; the account the
role lands in IS the proof of control (only that account's IAM controller can create a role there and trust VIGIL).

CLOUDFLARE (a second verifiable provider, a DIFFERENT trust model): a Cloudflare API token IS a bearer secret the
customer hands over, so there is no delegated role to assume. The customer creates a READ-ONLY, SINGLE-ACCOUNT token
named ``vigil-verify-{external_id}`` (the name carries the challenge binding); trusted sovereign code
(``ui.cloudflare_fetch``) reads the token's OWN definition ONCE to bind the challenge and confirm it is read-only +
single-account, and VIGIL records only the token's PUBLIC id and a sha256 — NEVER the token. A token that can write,
or is account-global, is REFUSED (VIGIL will not hold a powerful customer secret even briefly).

THE SAME-SHAPE NEGATIVE CONTROL (why the verdict also needs a DENIAL): a successful assume with our external id
proves nothing about whether the role's trust policy REQUIRES that id. A role that trusts VIGIL's principal with no
``sts:ExternalId`` condition would also succeed — and then ANY VIGIL tenant could name that role and connect another
customer's account through VIGIL (the confused-deputy hole the external id exists to close). So the fetcher also
assumes the SAME role with a FRESH RANDOM external id, and the verdict holds only if that control was explicitly
DENIED. A role that admits an arbitrary external id is refused, for every tenant, with a message naming the fix.

PROVIDERS: the proof is wired for AWS (above), for GCP and for Azure; the observation shape differs per provider, the
verdict (``cloud_grant_refusal``) has a branch per wired provider, and the registry below is provider-agnostic.
Cloudflare remains unwired and fails closed at the first step (``_VERIFIABLE_PROVIDERS``).

GCP (service-account IMPERSONATION, NAME-bound): the customer creates a service account whose ID encodes the
unguessable external id, and VIGIL's connector SA mints a token AS exactly that SA under a project-admin-only
``roles/iam.serviceAccountTokenCreator`` grant; one 200 proves control for THIS challenge, and the unguessable
per-challenge NAME is the confused-deputy closure (no description read, no negative control).

AZURE (a multi-tenant app-registration consent) proves control of a TENANT to the same bar. VIGIL ships one
multi-tenant Azure AD app. A customer's Global Admin admin-consents it INTO their tenant (a tenant-admin-only act)
and, to bind THIS challenge, sets the issued ``external_id`` as a tag on VIGIL's enterprise application in their
directory (editable only by a tenant admin / the app's owner). Trusted sovereign code then takes a client-credentials
token against the customer's tenant (success proves the consent), decodes the token's ``tid`` claim (which must equal
the tenant id), reads VIGIL's OWN service principal back over Microsoft Graph and confirms the tag equals
``external_id`` (constant-time). The SAME-SHAPE NEGATIVE CONTROL asks for a token in a FRESH RANDOM control tenant
(derived from the control id), which must be explicitly DENIED — so a positive result is specific to the customer's
tenant and VIGIL's app is never treated as consented everywhere. Only a tenant admin can BOTH consent the app AND tag
its enterprise application, so the read-back proves control for THIS challenge (confused-deputy-safe: another tenant's
admin can set neither in the customer's directory, and could not know the unguessable external id).

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
    (``verify_signed``) AND its ``issued_at`` STRICTLY exceeds the per-(org_id, provider, account_id) high-water. A
    write that the fold would NOT honor (a stamp at or below the high-water, e.g. after a clock step back) is refused
    with an error BEFORE it is appended, so a caller is never told "connected" about a record the fold ignores.
  * disconnect a grant = the SAFE direction -> ``state="revoked"`` honored even UNSIGNED, fixed ``issued_at`` 0.0
    (a replayed revoke merely re-revokes; gating the fail-safe direction would make it fail OPEN).

RESUME + DISCONNECT SEMANTICS: the external id is STABLE per (org, provider, account) while its challenge is
outstanding — ``open_challenge`` hands back the outstanding challenge instead of minting a new id, so a customer who
reloads (or comes back after creating the role) is shown the SAME trust policy and the role they already created keeps
working. A connected grant does not consume its challenge (re-verifying an expired grant needs no trust-policy edit).
``disconnect`` retires BOTH the grant and the challenge: a disconnected account starts clean, a later reconnect gets a
fresh external id, and VIGIL can never reconnect through the old trust policy without the customer editing it.

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

import hashlib
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
# match + the same-shape negative control), for GCP (impersonating a service account whose NAME encodes the
# unguessable external id, under VIGIL's connector SA — the name-binding is the confused-deputy closure, no negative
# control), for AZURE (a multi-tenant app-registration consent token + an admin-set external-id binding read back
# over Microsoft Graph + the same-shape negative control), and for CLOUDFLARE (a customer-supplied READ-ONLY,
# single-account API token, read ONCE to bind this challenge via the token's own name and to confirm it is read-only
# + single-account, then never stored — the token IS a bearer secret, unlike AWS/GCP/Azure delegated access, so VIGIL
# holds it only for the two verify reads and records only its public id + a sha256). The observation shape differs per
# provider; the verdict (``cloud_grant_refusal``) has a branch per wired provider, and a provider with no wired verdict
# fails closed at ``_check_verifiable``.
PROVIDER_AWS = "aws"
PROVIDER_GCP = "gcp"
PROVIDER_AZURE = "azure"
PROVIDER_CLOUDFLARE = "cloudflare"
_PROVIDERS = frozenset({PROVIDER_AWS, PROVIDER_GCP, PROVIDER_AZURE, PROVIDER_CLOUDFLARE})
# The providers whose deterministic proof-of-control verdict exists (AWS cross-account assume-role; GCP SA
# impersonation; Azure multi-tenant app-registration consent; Cloudflare read-only API token). Anything else fails
# closed at the first step.
_VERIFIABLE_PROVIDERS = frozenset({PROVIDER_AWS, PROVIDER_GCP, PROVIDER_AZURE, PROVIDER_CLOUDFLARE})

# A cloud ACCOUNT id: a provider-agnostic single safe token (alnum start, then [A-Za-z0-9._-], max 128) — one safe
# spine key component that can never widen scope. AWS additionally requires the exact 12-digit account id; Cloudflare
# the exact 32-lowercase-hex account id.
_ACCOUNT_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}")
_AWS_ACCOUNT_RE = re.compile(r"[0-9]{12}")
# A GCP project id: a lowercase letter start, then [a-z0-9-], 6-30 chars total, no trailing hyphen. (The generic
# _ACCOUNT_RE admits it as the outer bound; this narrows the account for the gcp provider.)
_GCP_PROJECT_RE = re.compile(r"[a-z][a-z0-9-]{4,28}[a-z0-9]")
# A role / grant REFERENCE the customer created — a public identifier, never a secret. Bounded + control-char-free;
# for AWS it must be the full IAM role ARN in the aws partition, IN the account being connected; for GCP it is the
# target SERVICE-ACCOUNT email ([name]@[project].iam.gserviceaccount.com) whose project is the account being connected.
_ROLE_REF_MAX = 512
_AWS_ROLE_ARN_RE = re.compile(r"arn:aws:iam::([0-9]{12}):role/[A-Za-z0-9+=,.@_/-]{1,512}")
_GCP_SA_EMAIL_RE = re.compile(
    r"([a-z][a-z0-9-]{4,28}[a-z0-9])@([a-z][a-z0-9-]{4,28}[a-z0-9])\.iam\.gserviceaccount\.com")

# The challenge-bound GCP SA id derivation (DUPLICATED byte-for-byte in ui.cloud_fetch, pinned equal by a test — the
# same pattern the AWS role-ARN regex follows). The customer creates an SA whose NAME encodes THIS challenge's
# unguessable external id; VIGIL recomputes the same email to impersonate and, in the verdict, to bind the
# observation. "vgl-" + 20 lowercase hex = 24 chars, always inside GCP's SA-id rule (^[a-z][a-z0-9-]{4,28}[a-z0-9]$).
_GCP_SA_ID_DOMAIN = "vigil-cloud-connect-gcp-sa-id:v1:"


def _gcp_expected_sa_id(external_id: str) -> str:
    return "vgl-" + hashlib.sha256((_GCP_SA_ID_DOMAIN + str(external_id)).encode("utf-8")).hexdigest()[:20]


def _gcp_expected_sa_email(project: str, external_id: str) -> str:
    """The EXACT service-account email the customer must create for (project, external_id) — the GCP analog of
    ``aws_trust_policy``'s external-id condition. Deterministic; computed from the trusted project + the unguessable
    external id, so a tenant can never steer VIGIL at another project's SA (confused-deputy closure)."""
    return f"{_gcp_expected_sa_id(external_id)}@{project}.iam.gserviceaccount.com"


# An Azure account id is the customer's TENANT id — a lowercase GUID (AAD renders tenant ids lowercase, and the
# token's ``tid`` claim is compared against it constant-time, so the canonical lowercase form is required here).
_AZURE_TENANT_RE = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
# The Azure role_ref is the Object ID (a GUID) of VIGIL's enterprise application in the customer's tenant (what the
# admin copies from the portal) — a public reference recorded with the grant. The Azure proof reads VIGIL's OWN
# service principal by VIGIL's constant client id, so the role_ref never steers the read.
_AZURE_OBJECT_ID_RE = re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")
# A Cloudflare account id is 32 lowercase hex; the Cloudflare role_ref is the token's PUBLIC id (32 lowercase hex) —
# the secret token is NEVER a role_ref the grant stores (the secret travels only to the fetcher; see
# verify_and_connect / cloudflare_placement).
_CLOUDFLARE_ACCOUNT_RE = re.compile(r"[0-9a-f]{32}")
_CLOUDFLARE_TOKEN_ID_RE = re.compile(r"[0-9a-f]{32}")

# The Cloudflare connect token's NAME prefix: the customer names their read-only token ``vigil-verify-{external_id}``
# so its name carries the challenge binding (the fetcher reads the name back and the verdict ct-compares it).
_CLOUDFLARE_TOKEN_NAME_PREFIX = "vigil-verify-"
# The minimal READ-ONLY Cloudflare permission groups the connect screen asks the customer to add. All are Read-only:
# Account Settings Read + Zone Read give read posture visibility; "User API Tokens Read" lets VIGIL read the token's
# OWN definition (name + policies + account scope) to bind the challenge and prove read-only + single-account — the
# exact minimal set is confirmed against the live API (VIGIL-LIMIT:LIMIT-cloud-connect-cloudflare-livefire).
_CLOUDFLARE_MINIMAL_READ_GROUPS = ("Account Settings Read", "Zone Read", "User API Tokens Read")

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
# ``token_sha256`` is inside the signed core (mirrors asset_ownership._PROOF_CORE): for a Cloudflare grant it is the
# sha256 of the customer's bearer token — the grant RECOGNISES a re-presented token WITHOUT storing it. "" for AWS
# (delegated access, no bearer secret). Signed so it is tamper-bound, defaulted so AWS grants are signed identically
# every time; the fold, the overview projection and the prune tripwire all carry it transparently.
_GRANT_CORE = ("signal", "org_id", "provider", "account_id", "role_ref", "external_id", "token_sha256",
               "verified_at", "expires_at", "state", "issued_at")
# ``token_sha256`` JOINED the grant core after grants were already persisted under the narrower core, so a grant
# written before it carries NO ``token_sha256`` key. ``verify_signed`` rebuilds the core with ``payload.get(k)``, so
# such a grant re-canonicalises to ``{...,"token_sha256":null,...}`` — bytes the owner never signed — and would be
# dropped as forged: a genesis re-verify would silently disconnect every pre-existing AWS account, and the prune
# high-water (which re-verifies the same core on ANY hard prune, cloud-connect flag or not) would not see it, so its
# only durable copy could be pruned away. A legacy grant is recognised by the ABSENCE of the key and verified under
# the core it was ACTUALLY signed with. The owner Ed25519 signature still binds every other field, so this neither
# accepts a forgery nor permits a downgrade: adding ``token_sha256`` to a legacy payload, or stripping it from a
# current one, fails verification under BOTH cores.
_GRANT_CORE_LEGACY = tuple(f for f in _GRANT_CORE if f != "token_sha256")


def _verify_cloud_active(payload: dict, core_fields, pubkey) -> bool:
    """Verify the owner signature of an ACTIVE cloud record, tolerating a pre-``token_sha256`` grant. Shared by the
    registry fold (``_apply_cloud_record``) and the spine prune tripwire (``spine.prune``) so the two can never
    disagree on which grants are authentic. The challenge core carries no ``token_sha256`` → the single check."""
    if verify_signed(payload, core_fields, pubkey):
        return True
    if "token_sha256" in core_fields and "token_sha256" not in payload:
        legacy = _GRANT_CORE_LEGACY if core_fields is _GRANT_CORE else tuple(
            f for f in core_fields if f != "token_sha256")
        return verify_signed(payload, legacy, pubkey)
    return False


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
        raise ValueError(f"connecting a {p!r} account is not available — "
                         "only AWS, GCP, Azure and Cloudflare accounts can be connected today")
    return p


def _check_account(account_id: str, provider: str = "") -> str:
    a = str(account_id or "").strip()
    if not _ACCOUNT_RE.fullmatch(a):
        raise ValueError("account_id must be an alphanumeric start then [A-Za-z0-9._-], max 128 chars, "
                         "no separators / traversal / spaces (an AWS account id / GCP project / Azure tenant id)")
    if provider == PROVIDER_AWS and not _AWS_ACCOUNT_RE.fullmatch(a):
        raise ValueError("an AWS account id is exactly 12 digits")
    if provider == PROVIDER_GCP and not _GCP_PROJECT_RE.fullmatch(a):
        raise ValueError("a GCP project id is a lowercase letter then [a-z0-9-], 6-30 chars, no trailing hyphen")
    if provider == PROVIDER_AZURE and not _AZURE_TENANT_RE.fullmatch(a):
        raise ValueError("an Azure tenant id is a lowercase GUID, e.g. 00000000-0000-0000-0000-000000000000")
    if provider == PROVIDER_CLOUDFLARE and not _CLOUDFLARE_ACCOUNT_RE.fullmatch(a):
        raise ValueError("a Cloudflare account id is exactly 32 lowercase hex characters")
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
    if provider == PROVIDER_GCP:
        m = _GCP_SA_EMAIL_RE.fullmatch(r)
        if not m:
            raise ValueError("give the service account's full email, e.g. "
                             "vigil-connect@my-company-prod.iam.gserviceaccount.com")
        if account_id and m.group(2) != account_id:
            raise ValueError("the service-account email names a different GCP project than the one you are connecting")
    if provider == PROVIDER_AZURE and not _AZURE_OBJECT_ID_RE.fullmatch(r):
        raise ValueError("give the Object ID (a GUID) of VIGIL's enterprise application in your tenant, "
                         "e.g. 00000000-0000-0000-0000-000000000000")
    if provider == PROVIDER_CLOUDFLARE and not _CLOUDFLARE_TOKEN_ID_RE.fullmatch(r):
        # For Cloudflare the recorded reference is the token's PUBLIC id (32 hex), produced by the trusted fetcher's
        # observation — never the token itself (the grant must never carry the bearer secret). A bad id here means a
        # malformed observation, which the verdict already refuses; validate it so a bad record is never bound.
        raise ValueError("the Cloudflare API token id was not recognised")
    return r


# ---------------------------------------------------------------------------------------------------
# The deterministic verdict (PURE — no network, no state). Exposed for independent testing; the registry calls
# it inside ``verify_and_connect`` so a grant is never recorded without it firing.
# ---------------------------------------------------------------------------------------------------

def _ct_eq(a: str, b: str) -> bool:
    """Constant-time equality over UTF-8 bytes (never raises on non-ASCII, unlike compare_digest on a str)."""
    return hmac.compare_digest(str(a or "").encode("utf-8"), str(b or "").encode("utf-8"))


_NOT_MADE = "the connection check was not completed — start it again"


def _gcp_grant_refusal(external_id: str, account_id: str, observed: dict) -> Optional[str]:
    """The GCP branch of the verdict (see :func:`cloud_grant_refusal`). ``observed`` is what the TRUSTED SOVEREIGN
    FETCHER saw (never customer-supplied):

        {"impersonated": <True iff generateAccessToken on the challenge-named SA returned 200>,
         "expected_email": <the SA email VIGIL computed from (account_id, external_id) and impersonated>,
         "project": <the project VIGIL built the email from>, "external_id": <the id VIGIL was asked to bind>}

    Holds (returns ``None``) iff ALL of:
      * ``impersonated`` is exactly ``True`` — VIGIL minted a token AS the challenge-named SA;
      * ``expected_email`` equals the email VIGIL RE-COMPUTES from (``account_id``, this challenge's ``external_id``),
        constant-time — so a replayed or forged observation (whose SA name does not encode THIS challenge) is refused;
      * ``project`` equals the claimed ``account_id`` (constant-time).

    The CONFUSED-DEPUTY CLOSURE is the unguessable per-challenge SA NAME (mirrors how Azure binds via a tenant-set
    tag): a malicious VIGIL tenant cannot guess another customer's external id, so cannot make VIGIL impersonate a
    matching-named SA in a project it does not control. There is deliberately no negative control — a never-created
    "control SA" is ALWAYS denied in real GCP and so proves nothing about grant breadth."""
    acct = str(account_id or "")
    got_email, got_proj = observed.get("expected_email"), observed.get("project")
    if observed.get("impersonated") is not True:
        return _NOT_MADE                                   # no 200 from generateAccessToken (nothing was proven)
    expected = _gcp_expected_sa_email(acct, external_id)
    if not isinstance(got_email, str) or not _ct_eq(expected, got_email):
        return _NOT_MADE                                   # the observation's SA name is not THIS challenge's (replay)
    if not isinstance(got_proj, str) or not _ct_eq(acct, got_proj):
        return (f"control of {account_id} was not proven — the service account VIGIL impersonated is not in that "
                f"project (check the project id)")
    return None


def cloud_grant_refusal(provider: str, external_id: str, account_id: str, observed, *,
                        control_external_id: str) -> Optional[str]:
    """``None`` iff ``observed`` proves CONTROL of ``account_id`` under ``provider`` via the VIGIL ``external_id``
    (AWS: the role ENFORCES the id; GCP: the SA NAME encodes it); otherwise the customer-facing reason it does not.
    TOTAL and FAIL-CLOSED: an unknown/unverifiable provider, an empty id, or a malformed observation all refuse
    (never raises). The AWS branch additionally refuses an empty / equal-to-real control id.

    ``observed`` is what the TRUSTED SOVEREIGN FETCHER saw (never customer-supplied); its shape and checks are
    per-provider (the GCP branch is :func:`_gcp_grant_refusal`). For AWS:

        {"assumed_with_external_id": <the id VIGIL assumed with>, "account": <GetCallerIdentity account>,
         "control_external_id": <the random id of the control assume>, "control_denied": <True iff AccessDenied>}

    The verdict holds iff ALL of:
      * ``assumed_with_external_id`` equals this challenge's ``external_id`` (constant-time) — the observation
        belongs to THIS challenge, so a replayed observation from a prior challenge is refused;
      * ``account`` equals the claimed ``account_id`` — the role LANDS IN the claimed account. THE control proof;
      * ``control_external_id`` equals the control id the provisioner generated for this check and differs from the
        real id, and ``control_denied`` is exactly ``True`` — the same role REFUSED an arbitrary external id, so its
        trust policy enforces ours (the confused-deputy guard; see the module docstring).

    For AZURE the observation is instead

        {"tenant": <the token's tid claim>, "external_id_matched": <True iff the admin-set tag equals external_id>,
         "external_id": <the id the binding was checked against>, "control_tenant": <the derived control tenant>,
         "control_denied": <True iff the control tenant's token was explicitly AADSTS-denied>}

    and the verdict holds iff ``tenant`` equals the claimed ``account_id`` (the tenant VIGIL got a token for),
    ``external_id_matched`` is ``True`` AND ``external_id`` equals this challenge's id (constant-time; a replayed
    observation from a prior challenge is refused), ``control_tenant`` equals the tenant derived from this check's
    control id (the observation belongs to THIS check), and ``control_denied`` is exactly ``True``."""
    try:
        ext = str(external_id or "")
        if provider not in _VERIFIABLE_PROVIDERS:
            return "connecting this kind of cloud account is not available"
        if not ext or not isinstance(observed, dict):
            return _NOT_MADE
        if provider == PROVIDER_GCP:
            # GCP binds the challenge by the SA NAME (no negative control); the control id is unused here.
            return _gcp_grant_refusal(ext, account_id, observed)
        if provider == PROVIDER_CLOUDFLARE:
            # Cloudflare binds the challenge by the token's NAME + its read-only/single-account scope (no negative
            # control); the control id is unused here.
            return _cloudflare_grant_refusal(ext, account_id, observed)
        # AWS (cross-account assume-role) — the observation and its checks need the same-shape negative control:
        ctl = str(control_external_id or "")
        if not ctl or _ct_eq(ext, ctl):
            return _NOT_MADE
        if provider == PROVIDER_AZURE:
            return _azure_grant_refusal(ext, ctl, str(account_id or ""), observed)
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


def _cloudflare_grant_refusal(external_id: str, account_id: str, observed: dict) -> Optional[str]:
    """``None`` iff the TRUSTED Cloudflare fetcher's observation proves control of ``account_id`` under THIS
    challenge, with a token that is READ-ONLY and SINGLE-ACCOUNT; otherwise the customer-facing reason. TOTAL and
    FAIL-CLOSED (``cloud_grant_refusal`` wraps it in the try/except — never raises).

    ``observed`` is what the trusted fetcher saw (never customer-supplied):

        {"token_id": <the token's public id>, "account": <the single account the token is scoped to>,
         "name_matched": <True iff the token's own name ct-equals vigil-verify-{external_id}>,
         "external_id": <the challenge external_id the fetcher bound against>,
         "read_only": <True iff every permission group is a read-only group>,
         "single_account": <True iff the token's resources name exactly the one account, never all-accounts>}

    The verdict holds iff ALL of:
      * ``name_matched`` is exactly ``True`` AND ``external_id`` ct-equals this challenge's ``external_id`` — the
        token the customer created carries THIS challenge's binding in its own name, so a replayed observation from
        another challenge (or an unnamed token) is refused;
      * ``account`` ct-equals the claimed ``account_id`` — the token is scoped to the account being connected;
      * ``read_only`` is exactly ``True`` — the token carries no write/edit/admin permission (the adapted negative
        control: VIGIL will not hold a customer secret that can CHANGE their account, even briefly);
      * ``single_account`` is exactly ``True`` — the token reaches exactly this one account, never ``*``/all-accounts
        (a global token is refused for the same reason)."""
    got_acct = observed.get("account")
    got_ext = observed.get("external_id")
    name_matched = observed.get("name_matched")
    read_only = observed.get("read_only")
    single_account = observed.get("single_account")
    if name_matched is not True or not isinstance(got_ext, str) or not _ct_eq(str(external_id or ""), got_ext):
        return ("the API token's name does not match this request — name the token EXACTLY as the connect screen "
                "shows (vigil-verify-…) and try again")
    if not isinstance(got_acct, str) or not _ct_eq(str(account_id or ""), got_acct):
        return (f"control of {account_id} was not proven — the API token is not scoped to that account "
                f"(scope it to exactly that account and try again)")
    if read_only is not True:
        return ("the API token is not read-only — create it with only Read permissions (no Edit/Write): VIGIL "
                "accepts a read-only token only and will not hold a token that can change your account")
    if single_account is not True:
        return ("the API token is not scoped to a single account — scope it to exactly the account you are "
                "connecting (not 'All accounts'); a global token is refused")
    return None


def cloud_grant_proves(provider: str, external_id: str, account_id: str, observed, *,
                       control_external_id: str) -> bool:
    """``True`` iff :func:`cloud_grant_refusal` finds nothing to refuse (the boolean form of the same verdict)."""
    return cloud_grant_refusal(provider, external_id, account_id, observed,
                               control_external_id=control_external_id) is None


def azure_control_tenant(control_external_id: str) -> str:
    """A deterministic, random-LOOKING Azure tenant GUID derived from the provisioner's unguessable control id — the
    tenant the Azure negative control asks for a token against. It is NOT a real tenant (it is a domain-separated
    hash of a secret), so a well-behaved AAD answers with an explicit no-consent / tenant-not-found error; a control
    that answers anything but that explicit denial is inconclusive and fails closed. The SAME function runs in the
    fetcher (which tests this tenant) and in the verdict (which re-binds ``observed['control_tenant']`` to it), so a
    replayed or mismatched control observation is refused — the Azure analog of AWS's control-external-id re-bind."""
    from ..reuse import sha256_hex
    h = sha256_hex(("vigil-azure-connect-control:" + str(control_external_id or "")).encode("utf-8"))
    return f"{h[0:8]}-{h[8:12]}-{h[12:16]}-{h[16:20]}-{h[20:32]}"


def _azure_grant_refusal(ext: str, ctl: str, account_id: str, observed: dict) -> Optional[str]:
    """The AZURE leg of :func:`cloud_grant_refusal` (``ext``/``ctl`` already validated non-empty and distinct, and
    ``observed`` already known to be a dict). TOTAL and FAIL-CLOSED. Holds iff the token's ``tid`` is the claimed
    tenant, the admin-set external-id binding matched (constant-time) and is THIS challenge's id, the control tenant
    is the one derived from this check's control id, and the negative control was explicitly denied."""
    got_tid = observed.get("tenant")
    got_match = observed.get("external_id_matched")
    got_ext = observed.get("external_id")
    got_ctl = observed.get("control_tenant")
    denied = observed.get("control_denied")
    if not isinstance(got_tid, str) or not _ct_eq(account_id, got_tid):
        return (f"control of {account_id} was not proven — the token VIGIL obtained is for a different Azure tenant "
                f"(admin-consent VIGIL's app into tenant {account_id} and try again)")
    if got_match is not True or not isinstance(got_ext, str) or not _ct_eq(ext, got_ext):
        return ("the connect binding was not found in your tenant — set the external id shown on the connect screen "
                "as the tag on VIGIL's enterprise application, then verify again")
    if not isinstance(got_ctl, str) or not _ct_eq(azure_control_tenant(ctl), got_ctl):
        return _NOT_MADE
    if denied is not True:
        return ("the admin-consent proof is not specific to your tenant (the negative control was not denied), so "
                "the account was not connected")
    return None


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


# The GCP role a customer grants VIGIL's connector SA ON the target service account — the one capability the
# impersonation proof needs (and no more). Shown on the connect screen, never enforced by this module.
GCP_TOKEN_CREATOR_ROLE = "roles/iam.serviceAccountTokenCreator"


def gcp_placement(connector_sa: str, project: str, external_id: str) -> dict:
    """The exact steps the customer follows to prove control of ``project`` (the GCP analog of
    :func:`aws_trust_policy`): in THAT project, create a service account whose ID is EXACTLY ``sa_id`` — its name
    encodes THIS challenge's unguessable external id — and grant VIGIL's connector SA the
    ``roles/iam.serviceAccountTokenCreator`` role ON that service account (resource-scoped; a project-wide grant also
    works but is broader than needed). No description and no self-read grant are required: VIGIL proves control by
    impersonating exactly that SA. Deterministic (stable text + key order) so the screen and a test agree
    byte-for-byte. Returns the structured placement the screen renders, including the exact gcloud commands to paste."""
    sa_id = _gcp_expected_sa_id(external_id)
    sa_email = _gcp_expected_sa_email(project, external_id)
    return {
        "connector_sa": str(connector_sa),
        "token_creator_role": GCP_TOKEN_CREATOR_ROLE,
        "sa_id": sa_id,
        "sa_email": sa_email,
        "steps": [
            (f"In GCP project {project}, create a service account with EXACTLY this id (its name encodes your "
             f"connection — do not change it): {sa_id}"),
            ("Grant VIGIL's connector service account the Service Account Token Creator role ON that service "
             "account (resource-scoped; a project-wide grant also works but is broader than needed)."),
        ],
        "gcloud": [
            (f'gcloud iam service-accounts create {sa_id} --project={project} --display-name="VIGIL connect"'),
            (f'gcloud iam service-accounts add-iam-policy-binding {sa_email} --project={project} '
             f'--member="serviceAccount:{connector_sa}" --role="{GCP_TOKEN_CREATOR_ROLE}"'),
        ],
    }


def azure_placement(client_id: str, tenant_id: str, external_id: str) -> dict:
    """The exact admin-consent placement VIGIL hands the customer's Global Admin to prove control of Azure tenant
    ``tenant_id`` — the Azure analog of :func:`aws_trust_policy`, deterministic (stable) so the screen and a test
    agree byte-for-byte:
      * ``admin_consent_url`` — admin-consent VIGIL's multi-tenant app (``client_id``) INTO this tenant (a
        tenant-admin-only act; success is what the client-credentials token later proves);
      * ``binding_tag`` — after consent, set THIS value (the challenge ``external_id``) as a tag on VIGIL's
        enterprise application in the tenant (editable only by a tenant admin / the app's owner), which binds this
        specific challenge and closes the confused-deputy hole (another tenant's admin cannot set it, and could not
        guess the unguessable id);
      * ``graph_read`` — the exact Microsoft Graph read VIGIL performs with its OWN app token (keyed on VIGIL's
        constant ``client_id``, so it is never customer-steerable) to confirm the tag.
    Recording the resulting grant authorizes NO offense (see the module docstring)."""
    cid, tid = str(client_id), str(tenant_id)
    return {
        "client_id": cid,
        "admin_consent_url": f"https://login.microsoftonline.com/{tid}/adminconsent?client_id={cid}",
        "binding_tag": str(external_id),
        "graph_read": (f"GET https://graph.microsoft.com/v1.0/servicePrincipals(appId='{cid}')"
                       f"?$select=appId,id,tags"),
        "steps": [
            (f"As a Global Administrator of tenant {tid}, open the admin-consent URL and grant VIGIL's app admin "
             f"consent (read-only application permissions)."),
            ("In Microsoft Entra ID -> Enterprise applications -> VIGIL -> Properties, add the binding tag shown "
             "(the external id) as a tag, then Save."),
            ("Return here and verify: VIGIL reads its own service principal back over Microsoft Graph and confirms "
             "the tag equals the external id."),
        ],
    }


def cloudflare_token_name(external_id: str) -> str:
    """The exact name the customer's read-only Cloudflare token must carry: ``vigil-verify-{external_id}``. The name
    carries the challenge binding — the trusted fetcher reads the token's own name back and the verdict ct-compares
    it, so a token created for a different (or no) challenge is refused."""
    return f"{_CLOUDFLARE_TOKEN_NAME_PREFIX}{str(external_id)}"


def cloudflare_placement(external_id: str, account_id: str) -> dict:
    """The exact self-serve steps the customer follows to prove control of Cloudflare account ``account_id``: create
    a CUSTOM API TOKEN scoped READ-ONLY to EXACTLY that account, NAME it ``vigil-verify-{external_id}`` (the name
    carries this challenge's binding), and paste it into the connect screen ONCE.

    Unlike AWS/GCP/Azure (delegated access, VIGIL stores no customer secret), a Cloudflare API token IS a bearer
    secret the customer hands over. VIGIL reads the token's OWN definition exactly twice (status, then name +
    policies + account scope) to bind this challenge and confirm the token is read-only + single-account, then
    NEVER stores, logs or returns it — only the token's public id and a sha256 are recorded. Deterministic text, so
    the screen and a test agree byte-for-byte. The placement NEVER includes the external id's secret beyond the
    token name the customer must set (which they already see)."""
    name = cloudflare_token_name(external_id)
    acct = str(account_id)
    groups = list(_CLOUDFLARE_MINIMAL_READ_GROUPS)
    return {
        "token_name": name,
        "permission_groups": groups,
        "account_scope": acct,
        "read_only": True,
        "steps": [
            "In the Cloudflare dashboard open My Profile → API Tokens → Create Token → Create Custom Token.",
            f"Name the token EXACTLY {name} — the name proves this request is yours; a different name is rejected.",
            "Under Permissions add ONLY Read permissions (set each to Read, never Edit/Write): "
            + ", ".join(groups) + ". A token carrying any write/edit permission is refused.",
            (f"Under Account Resources choose Include → a specific account → {acct} (NOT 'All accounts'); keep any "
             "Zone Resources scoped within that same account only. A token that can reach more than this one "
             "account is refused."),
            "Leave Client IP Address Filtering and TTL at their defaults, create the token, and copy it.",
            ("Paste the token into the connect screen once. VIGIL verifies it and does NOT store it — only the "
             "token's public id and a sha256 are kept."),
        ],
    }


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
    role_ref: str                # the public reference the customer created: an AWS role ARN, or a Cloudflare token id
    external_id: str = field(repr=False)   # the id the role's trust policy requires (never rendered in a repr)
    verified_at: float = 0.0
    expires_at: float = 0.0      # owner-signed expiry — re-connecting required after this
    issued_at: float = 0.0       # owner-set anti-replay high-water for this grant
    state: str = "active"        # "active" | "revoked"
    access: str = "read-only"    # the RECORDED connection intent (see the module CLAIM BOUNDARY note)
    token_sha256: str = ""       # Cloudflare: sha256 of the bearer token (log-safe; the token itself is NEVER stored)

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
            "external_id": p.get("external_id"), "token_sha256": p.get("token_sha256"),
            "verified_at": p.get("verified_at"), "expires_at": p.get("expires_at"), "issued_at": at}


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
        if not _verify_cloud_active(p, core_fields, resolver.at(r.seq)):
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
        if not (float(issued_at) > self._highwater(CHALLENGE_SIGNAL, _CHALLENGE_CORE, (oid, prov, acct))):
            raise ValueError("a newer connection request already exists for this account — start again")
        core = {"signal": CHALLENGE_SIGNAL, "org_id": oid, "provider": prov, "account_id": acct,
                "external_id": ext, "state": "active", "issued_at": float(issued_at)}
        payload = {**signed_payload(core, self.owner_key), "by": "owner", "requested_by": "owner",
                   "tier": "A0", "decision": "auto",
                   "reason": f"cloud-connect challenge issued for {prov}:{acct} (org {oid})"}
        self.store.append(kind="event", source="governor", actor="WARDEN", payload=payload)
        return CloudConnectChallenge(org_id=oid, provider=prov, account_id=acct, external_id=ext,
                                     issued_at=float(issued_at))

    def open_challenge(self, org_id: str, provider: str, account_id: str, *,
                       issued_at: float) -> "tuple[CloudConnectChallenge, bool]":
        """The challenge the customer configures for (org_id, provider, account_id): the OUTSTANDING one when there is
        one (``resumed`` True — no record written, the external id and so the trust policy are unchanged), else a
        freshly owner-signed one (:meth:`issue_challenge`). Returns ``(challenge, resumed)``. Refuses an unverifiable
        provider / malformed account before any read or write. A challenge grants NOTHING either way."""
        oid, prov = _check_org_id(org_id), _check_verifiable(provider)
        acct = _check_account(account_id, prov)
        ch = self.challenge(oid, prov, acct)
        if ch is not None and ch.external_id:
            return ch, True
        return self.issue_challenge(oid, prov, acct, issued_at=issued_at), False

    def verify_and_connect(self, org_id: str, provider: str, account_id: str, *, role_ref: str,
                           observed, control_external_id: str, now: float,
                           ttl_seconds: float = _DEFAULT_GRANT_TTL_S, token_sha256: str = "") -> CloudGrant:
        """Run the deterministic verdict over a TRUSTED observation and, ONLY on success, owner-sign a READ-ONLY
        cloud GRANT for (org_id, provider, account_id). Fail-closed — raises ``ValueError`` (its text is the
        customer-facing reason) on an invalid org/provider/account/role, an unverifiable provider, a missing/stale
        challenge, a non-positive ttl, or a verdict that does not fire; a grant is NEVER recorded otherwise.

        ``observed`` is what the TRUSTED SOVEREIGN FETCHER saw (never customer-supplied); ``control_external_id`` is
        the random id the provisioner generated for this check's negative control. The verdict is checked against
        the CURRENT active challenge's external_id for the key; a verify with no outstanding challenge, or against a
        superseded external_id, refuses. On success the grant carries an owner-signed ``expires_at`` =
        ``now + ttl_seconds`` and the verified external id (so a later gated run can assume the role).

        ``token_sha256`` is recorded in the signed grant for a Cloudflare connection (the sha256 of the customer's
        bearer token, supplied by the provisioner — the registry NEVER sees the token). ``role_ref`` for Cloudflare
        is the token's PUBLIC id; the grant therefore RECOGNISES a re-presented token without ever storing it. ""
        for AWS (delegated access, no bearer secret). The token itself never reaches this method, the record, or
        the return — only its public id and its sha256.

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
        if not (verified_at > self._highwater(GRANT_SIGNAL, _GRANT_CORE, (oid, prov, acct))):
            # the fold would ignore a grant stamped at/below the key's high-water: refuse rather than report success
            raise ValueError("the connection could not be recorded just now — try again in a moment")
        tok_sha = str(token_sha256 or "")
        if tok_sha and any(ord(c) < 0x20 or ord(c) == 0x7f for c in tok_sha):
            raise ValueError("token_sha256 must be a control-char-free string")
        core = {"signal": GRANT_SIGNAL, "org_id": oid, "provider": prov, "account_id": acct, "role_ref": ref,
                "external_id": ch.external_id, "token_sha256": tok_sha, "verified_at": verified_at,
                "expires_at": verified_at + ttl, "state": "active", "issued_at": verified_at}
        payload = {**signed_payload(core, self.owner_key), "by": "owner", "requested_by": "owner",
                   "tier": "A0", "decision": "auto",
                   "reason": f"read-only cloud grant RECORDED for {prov}:{acct} by org {oid} (owner-signed)"}
        self.store.append(kind="event", source="governor", actor="WARDEN", payload=payload)
        return CloudGrant(org_id=oid, provider=prov, account_id=acct, role_ref=ref, external_id=ch.external_id,
                          verified_at=verified_at, expires_at=verified_at + ttl, issued_at=verified_at,
                          state="active", token_sha256=tok_sha)

    def disconnect(self, org_id: str, provider: str, account_id: str) -> int:
        """Disconnect a cloud account — the SAFE direction (honored even unsigned, fixed ``issued_at`` 0.0). Retires
        BOTH the grant and the outstanding challenge (see RESUME + DISCONNECT SEMANTICS): a disconnected account
        starts clean, and a reconnect gets a fresh external id. Idempotent + replay-safe: a replayed revoke merely
        re-revokes. Used when the customer disconnects or cancels a half-finished connection, or on offboarding /
        tenant decommission. A grant with no active record authorizes nothing anywhere. Returns the grant revoke's
        seq."""
        oid, prov, acct = _check_org_id(org_id), _check_provider(provider), _check_account(account_id)
        core = {"signal": GRANT_SIGNAL, "org_id": oid, "provider": prov, "account_id": acct, "role_ref": "",
                "external_id": "", "token_sha256": "", "verified_at": 0.0, "expires_at": 0.0,
                "state": "revoked", "issued_at": 0.0}
        payload = {**signed_payload(core, self.owner_key), "by": "owner", "requested_by": "owner",
                   "tier": "A0", "decision": "auto",
                   "reason": f"cloud grant for {prov}:{acct} (org {oid}) DISCONNECTED (governed latch)"}
        seq = self.store.append(kind="event", source="governor", actor="WARDEN", payload=payload)
        ch_core = {"signal": CHALLENGE_SIGNAL, "org_id": oid, "provider": prov, "account_id": acct,
                   "external_id": "", "state": "revoked", "issued_at": 0.0}
        ch_payload = {**signed_payload(ch_core, self.owner_key), "by": "owner", "requested_by": "owner",
                      "tier": "A0", "decision": "auto",
                      "reason": f"cloud-connect challenge for {prov}:{acct} (org {oid}) RETIRED with the disconnect"}
        self.store.append(kind="event", source="governor", actor="WARDEN", payload=ch_payload)
        return seq

    # -- reads (owner-key-succession-aware folds) ---------------------------------------------------
    def _fold_state(self, signal: str, core_fields, row_of) -> "tuple[dict, dict]":
        """Fold the spine into ``({(org_id, provider, account_id): record_dict} whose latest state is active,
        {key: anti-replay high-water})``, authenticating each ``active`` record under the owner pubkey valid AT ITS
        SEQ and refusing any stale/replayed re-append via the per-key high-water. Revokes (safe direction) are honored
        regardless of signature. A genesis scan of the live window (no snapshot seed — the prune tripwire is the
        invariant)."""
        resolver = _kh.key_resolver(self.store, current=self.trusted_pubkey)
        state: dict[tuple, str] = {}
        issued: dict[tuple, float] = {}
        rows: dict[tuple, dict] = {}
        for r in self.store.iter_records():
            _apply_cloud_record(r, resolver, signal, core_fields, row_of, state, issued, rows)
        return {k: row for k, row in rows.items() if state.get(k) == "active"}, issued

    def _fold(self, signal: str, core_fields, row_of) -> dict:
        return self._fold_state(signal, core_fields, row_of)[0]

    def _highwater(self, signal: str, core_fields, key: tuple) -> float:
        """The anti-replay high-water the fold holds for ``key`` under ``signal`` (``NO_HIGHWATER`` when none): a new
        active record is honored only when its ``issued_at`` strictly exceeds this."""
        return self._fold_state(signal, core_fields, _payload_row)[1].get(key, NO_HIGHWATER)

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
            issued_at=as_issued_at(row.get("issued_at")), state="active",
            token_sha256=str(row.get("token_sha256") or ""))

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
        Each account is ``connected`` (active + unexpired), ``expired`` (active grant past its owner-signed expiry →
        re-connect), or ``pending`` (a connection the customer STARTED — an outstanding challenge of a verifiable
        provider — with no grant yet, so the screen can offer to finish it; it carries only provider + account).
        Read-only: no lock, no mint, no owner key. A fixed allowlist of fields — the external id is NEVER projected;
        ``access`` is the recorded read-only intent."""
        if not isinstance(org_id, str) or not org_id:
            return []
        try:
            oid = _check_org_id(org_id)
        except ValueError:
            return []
        n = float(now)
        grants = {k: row for k, row in self._fold(GRANT_SIGNAL, _GRANT_CORE, _grant_row).items() if k[0] == oid}
        started = {k for k in self._fold(CHALLENGE_SIGNAL, _CHALLENGE_CORE, _payload_row)
                   if k[0] == oid and k[1] in _VERIFIABLE_PROVIDERS}
        out: list[dict] = []
        for key in sorted(set(grants) | started):
            _o, prov, acct = key
            row = grants.get(key)
            if row is None:
                out.append({"provider": prov, "account_id": acct, "access": "read-only", "status": "pending"})
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
