"""
sensors.cloud_live — LIVE, read-only AWS posture collection as a gated SENSOR (Phase C2).

This is the FIRST *live* cloud collector: where ``sensors.cloud.CloudPostureImportSensor`` ingests an
operator-exported file offline, ``CloudLiveSensor`` calls the AWS control-plane APIs **read-only** at
runtime and emits the SAME normalized native inventory those importers produce — so the entire proven
promotion path downstream (``cloud_observations`` leads, and the ``engage_fusion._reverify_cloud``
policy-path + achieved-state oracles) works UNCHANGED. The collector's whole job is to turn the
operator's real cloud into the exact ``{"export": <native-inventory-json>, "format": "native"}``
``ToolResult.output`` shape the file importers already emit; it invents no new schema and no new oracle.

Doctrine, by construction:
  * PROVE-DON'T-GUESS / ORACLE AUTHORITY. The collector mints only LEADS (a native inventory). A LEAD
    becomes a FACT only when the EXISTING deterministic oracles re-fire over the RETAINED export
    (``confirm_cloud_posture_facts`` re-derives each grant PATH over the retained policy graph;
    ``cloud_posture_oracle`` re-derives the encryption-at-rest achieved state) — NEVER because a live
    API said so. Stated precisely (not overclaimed): the collector's OWN judgment of whether a resource
    is public/over-broadly-trusted IS part of the grounding — but it is made CONSERVATIVELY and only over
    CONFIRMED state (a public ACL/policy that Block-Public-Access does not neutralise; a wildcard trust
    with NO narrowing Condition and no Deny), and the RAW ground-truth signals (``acl_public`` /
    ``policy_public`` / ``bpa`` / ``trust_conditioned`` …) are RETAINED alongside so the verdict is
    auditable and a future/active oracle can judge them independently. The oracle then re-derives the
    reachability PATH over that retained, conservative evidence. The near-zero-FP burden is met by erring
    to a false-NEGATIVE (an un-confirmable public signal stays an un-promoted lead), never a false-FACT.
  * AMBIENT CREDENTIALS, NEVER HANDED OVER. Credentials come from boto3's DEFAULT chain — environment,
    shared config/SSO cache, an EC2 instance profile, an ECS/EKS task role, a pod's IRSA identity. The
    operator configures the HOST's own read-only identity once; VIGIL discovers and uses it. No secret
    is passed through args, argv, or the spine. No ambient identity ⇒ a clean fail-closed no-op.
  * GATED, FAIL-CLOSED, DECLARED == ACTUAL EGRESS. Tier-2 / ``ACTIVE_RECON``: the engagement must be
    entitled, and every control-plane host the collector will reach is declared in ``egress_hosts`` so
    the egress gate (``build_engagement_allowlist``) REFUSES the run unless the operator provisioned it
    (C1's ``targets/<slug>/collector-hosts.txt``; ``localhost`` for a LocalStack/self-hosted endpoint is
    always permitted). Endpoint + region are resolved from the environment/constructor ONLY (never from
    run-time args) so the hosts the gate authorises are exactly the hosts boto3 will call — a run-time
    arg can never widen egress past what the gate already checked. HONEST SCOPE: boto3 uses botocore/
    urllib3, NOT the httpx client ``SovereignHttpxTransport`` wraps, so this gate is a PRE-FLIGHT
    AUTHORISATION (the sensor never runs unless its declared hosts are allowlisted) — not a byte-level
    socket firewall over boto3. Endpoint+region pinning keeps the calls on the declared hosts; the one
    residual is a cross-region S3 301-redirect to a sibling ``s3.<other-region>.amazonaws.com`` (provision
    ``*.amazonaws.com`` for a multi-region account). Stated plainly, never overclaimed.
  * READ-ONLY, NON-MUTATING. Every AWS call is a ``list_*`` / ``get_*`` / ``describe_*`` / STS
    ``get_caller_identity`` — the collector never writes to the operator's cloud. A per-resource
    AccessDenied degrades that datum away (best-effort) rather than sinking the collection.
  * DETERMINISM OF THE CORE. The live ``run`` is non-deterministic (it reflects the operator's cloud),
    but the boto3-response → native-inventory translation (``aws_inventory_from_responses`` and its
    helpers) is a PURE, total function of the retained responses — unit-tested with recorded fixtures,
    no SDK and no network. That pure core is what feeds the oracles.

TESTING. The deterministic core is CI-tested against recorded AWS/LocalStack response shapes (zero SDK,
zero network), including the adversarial NEGATIVE controls a near-zero-FP claim demands (a Condition-
narrowed wildcard trust, a Deny-subtracted wildcard, a public ACL neutralised by Block-Public-Access, a
public signal with BPA UNKNOWN). The live path is driven END-TO-END against a purpose-built AWS test
system — **moto** (in-process AWS mock) in CI, and **LocalStack** (emulated AWS in Docker, via an
``endpoint_url`` override) where that rig is up — each seeding a real account and running the collector's
actual boto3 ``run`` path; both skip cleanly when their dependency is absent, so CI stays green.

HONEST LIMITATIONS (stated, not papered over):
  * S3 objects carry no intrinsic "sensitive" bit, so the encryption-at-rest achieved-state FACT (which
    requires ``sensitive AND not encrypted``) fires only when the operator has TAGGED the bucket's data
    classification (``sensitive`` / ``classification`` / ``data-classification``) — operator-declared
    sensitivity, never fabricated. Public-exposure and over-broad-trust facts need no such tag.
  * Block-Public-Access neutralises at BOTH the bucket AND the account scope, so a public ACL/policy is
    confirmed anonymously reachable only when its neutraliser is observed False at BOTH scopes. If EITHER
    scope's BPA cannot be read — e.g. a scoped read role without ``s3:GetAccountPublicAccessBlock`` (the
    account-level S3-Control read) — the public signal stays an un-promoted LEAD (conservative — no false
    fact; a possible false negative). Grant that read for account-wide confirmation; the C3 active-
    reachability oracle definitively CONFIRMS anonymous reach regardless, where it matters.
  * A Condition-narrowed wildcard trust (the secure org/ExternalId pattern) is NOT promoted; the deep
    evaluation of trust Conditions is deferred to a future oracle that judges the retained raw condition.
"""

from __future__ import annotations

import json
import os
from typing import Any
from urllib.parse import urlsplit

from ..agents.tools import ToolContext, ToolResult
from ..entitlement.models import Capability
from ..intel.models import Observation
from .cloud import _load_export, cloud_observations

# S3 ACL grantee group URIs that denote "anyone" (public) / "any AWS account" (effectively public).
_S3_PUBLIC_ACL_URIS = frozenset({
    "http://acs.amazonaws.com/groups/global/allusers",
    "http://acs.amazonaws.com/groups/global/authenticatedusers",
})
# Bucket-tag keys the operator uses to DECLARE data sensitivity, and the values that mean "sensitive".
_SENSITIVITY_TAG_KEYS = frozenset({"sensitive", "classification", "data-classification", "dataclassification"})
_SENSITIVE_TAG_VALUES = frozenset({
    "true", "yes", "1", "sensitive", "confidential", "restricted", "secret", "pii", "high", "critical",
})
# STS AssumeRole principal tokens that denote "anyone" — a wildcard trust makes a role publicly assumable
# ONLY when it carries no narrowing Condition (see _trust_analysis).
_WILDCARD_TRUST = frozenset({"*", "arn:aws:iam::*:root"})

# S3 Block-Public-Access booleans. IgnorePublicAcls NEUTRALISES an existing public ACL; RestrictPublicBuckets
# NEUTRALISES anonymous access from a public bucket policy. BlockPublicAcls / BlockPublicPolicy are
# PREVENTIVE (they reject new public ACLs/policies) and do not retroactively neutralise, so they are
# retained as evidence but not used to compute effective anonymous reachability.
_BPA_KEYS = ("BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets")


# ---------------------------------------------------------------------------
# pure translation: recorded boto3 read-only responses -> the native inventory
# (no boto3, no network — the deterministic, CI-tested core the oracles consume)
# ---------------------------------------------------------------------------


def _bpa_fields(pab: Any) -> dict | None:
    """Extract the four Block-Public-Access booleans from a ``get_public_access_block`` OUTCOME, tri-state:
      * a response dict -> its four fields (a KNOWN BPA config);
      * the ``"absent"`` sentinel (the call raised ``NoSuchPublicAccessBlockConfiguration`` — no BPA is
        configured AT THIS LEVEL) -> all-False (a KNOWN 'off');
      * ``None`` (denied / not attempted) -> ``None`` (UNKNOWN — never assumed off).
    Total: any odd shape -> None."""
    if pab == "absent":
        return {k: False for k in _BPA_KEYS}
    if not isinstance(pab, dict):
        return None
    cfg = pab.get("PublicAccessBlockConfiguration")
    if not isinstance(cfg, dict):
        return None
    # defence-in-depth: a real AWS/S3 response ALWAYS carries all four booleans (even when only one was
    # set); a PARTIAL config is possible only from a non-AWS/S3-compatible ``endpoint_url``. Treat it as
    # UNKNOWN (None) rather than defaulting the absent keys to False — which would read a possibly-blocking
    # scope as 'not blocking', the less-conservative direction. An unknown scope stays un-promoted.
    if not all(k in cfg for k in _BPA_KEYS):
        return None
    return {k: bool(cfg.get(k)) for k in _BPA_KEYS}


def _merge_bpa(bucket_bpa: Any, account_bpa: Any) -> tuple[dict, int]:
    """Merge the bucket- and account-level BPA field dicts, OR-semantics (a ``True`` at EITHER scope
    blocks — AWS applies the most-restrictive combination). Returns (merged_fields, observed_scopes)
    where ``observed_scopes`` ∈ {0,1,2} is how many of the TWO scopes (bucket, account) were actually
    read. A neutraliser (``IgnorePublicAcls`` / ``RestrictPublicBuckets``) is 'confirmed not blocking'
    ONLY when it is observed False at BOTH scopes (``observed_scopes == 2`` AND the merged field is
    False): each scope can independently neutralise, so an UNREAD scope (e.g. a scoped read role without
    ``s3:GetAccountPublicAccessBlock``) leaves the effective state UNKNOWN — never assumed off."""
    levels = [b for b in (bucket_bpa, account_bpa) if isinstance(b, dict)]
    merged = {k: any(bool(b.get(k)) for b in levels) for k in _BPA_KEYS}
    return (merged, len(levels))


def _acl_is_public(acl: Any) -> bool:
    """True iff an S3 ``get_bucket_acl`` response grants a public group (AllUsers / AuthenticatedUsers).
    Total: a missing/oddly-typed response is not public."""
    if not isinstance(acl, dict):
        return False
    for g in acl.get("Grants") or []:
        if not isinstance(g, dict):
            continue
        grantee = g.get("Grantee") if isinstance(g.get("Grantee"), dict) else {}
        uri = str(grantee.get("URI") or "").strip().lower()
        if uri in _S3_PUBLIC_ACL_URIS:
            return True
    return False


def _policy_status_is_public(policy_status: Any) -> bool:
    """True iff an S3 ``get_bucket_policy_status`` response reports ``PolicyStatus.IsPublic``. Total."""
    if not isinstance(policy_status, dict):
        return False
    ps = policy_status.get("PolicyStatus") if isinstance(policy_status.get("PolicyStatus"), dict) else {}
    return bool(ps.get("IsPublic"))


def _encryption_state(encryption: Any) -> bool | None:
    """Tri-state encryption-at-rest from an S3 ``get_bucket_encryption`` outcome:
      * a response carrying at least one SSE rule -> ``True`` (encrypted);
      * the sentinel ``"absent"`` (the call raised ``ServerSideEncryptionConfigurationNotFoundError``,
        i.e. no default encryption) -> ``False``;
      * ``None`` (the call was denied / not attempted) -> UNKNOWN (never mistaken for insecure).
    """
    if encryption == "absent":
        return False
    if not isinstance(encryption, dict):
        return None
    cfg = encryption.get("ServerSideEncryptionConfiguration")
    if isinstance(cfg, dict) and isinstance(cfg.get("Rules"), list) and cfg["Rules"]:
        return True
    return None


def _sensitive_from_tagging(tagging: Any) -> bool | None:
    """True iff the operator TAGGED the bucket as sensitive (an ``get_bucket_tagging`` response with a
    recognised classification tag/value); ``None`` when no such tag is present (unknown — never
    fabricated). Total."""
    if not isinstance(tagging, dict):
        return None
    for t in tagging.get("TagSet") or []:
        if not isinstance(t, dict):
            continue
        key = str(t.get("Key") or "").strip().lower().replace("_", "-")
        val = str(t.get("Value") or "").strip().lower()
        if key in _SENSITIVITY_TAG_KEYS and val in _SENSITIVE_TAG_VALUES:
            return True
    return None


def bucket_resource(entry: Any, *, account_bpa: Any = None) -> dict | None:
    """Map ONE collected S3 bucket record onto a native-inventory resource. ``entry`` is what the live
    collector gathered for a bucket::

        {"name": "acme-secrets", "acl": <get_bucket_acl resp>|None,
         "policy_status": <get_bucket_policy_status resp>|None,
         "public_access_block": <get_public_access_block resp>|"absent"|None,
         "encryption": <get_bucket_encryption resp>|"absent"|None, "tagging": <get_bucket_tagging resp>|None}

    ``account_bpa`` is the account-level BPA FIELD DICT (from :func:`_bpa_fields`) or ``None`` (unknown).

    Returns a resource dict or ``None`` for a nameless entry. Pure + total. CONSERVATIVE, evidence-
    retaining, near-zero-FP by construction:

      * The RAW ground-truth signals (``acl_public`` / ``policy_public`` / the merged ``bpa`` / ``bpa_known``)
        are retained as resource attrs — the oracle ignores these keys, but they make the public verdict
        AUDITABLE and let a future oracle (or the C3 active-reachability oracle) judge them independently.
      * ``public`` (the promotable FACT flag + a synthesised anonymous grant) is set ONLY when anonymous
        reachability is AFFIRMATIVELY CONFIRMED: a public ACL/policy AND a KNOWN Block-Public-Access state
        that does not neutralise it (``IgnorePublicAcls`` neutralises a public ACL; ``RestrictPublicBuckets``
        neutralises a public policy). BPA UNKNOWN, or BPA neutralising -> ``public`` is NOT set, so the
        policy-path oracle finds no anonymous grant and promotes nothing (the raw signals remain an
        auditable lead). This deliberately errs to a false-NEGATIVE (a genuinely-public bucket whose BPA we
        cannot read stays an un-promoted lead) rather than a false-POSITIVE (the cardinal sin under oracle
        authority) — the C3 active oracle definitively confirms reachability where it matters.
      * ``encrypted`` / ``sensitive`` stay tri-state (set only when explicitly known / operator-tagged)."""
    if not isinstance(entry, dict):
        return None
    name = str(entry.get("name") or "").strip()
    if not name:
        return None
    res: dict[str, Any] = {"id": name, "kind": "datastore"}
    acl_public = _acl_is_public(entry.get("acl"))
    policy_public = _policy_status_is_public(entry.get("policy_status"))
    merged, observed_scopes = _merge_bpa(_bpa_fields(entry.get("public_access_block")),
                                         account_bpa if isinstance(account_bpa, dict) else None)
    both_scopes_known = observed_scopes == 2
    # retain the RAW ground truth as evidence (oracle-inert keys)
    if acl_public:
        res["acl_public"] = True
    if policy_public:
        res["policy_public"] = True
    res["bpa_known"] = both_scopes_known          # True only when BOTH bucket + account BPA were read
    if observed_scopes:
        res["bpa"] = merged
    # EFFECTIVE anonymous reachability — a public vector is CONFIRMED only when its neutraliser is observed
    # False at BOTH scopes (bucket AND account). A True at either scope neutralises; an UNREAD scope leaves
    # it UNCONFIRMED. Either way it is not promoted (conservative — no false public FACT; C3 confirms live).
    acl_open = both_scopes_known and not merged["IgnorePublicAcls"]
    policy_open = both_scopes_known and not merged["RestrictPublicBuckets"]
    if (acl_public and acl_open) or (policy_public and policy_open):
        res["public"] = True
        res["grants"] = [{"principal": "*", "access": "read"}]
    enc = _encryption_state(entry.get("encryption"))
    if enc is not None:
        res["encrypted"] = enc
    sens = _sensitive_from_tagging(entry.get("tagging"))
    if sens is not None:
        res["sensitive"] = sens
    return res


def _trust_analysis(assume_role_policy_document: Any) -> dict:
    """Analyse an IAM role trust policy (``AssumeRolePolicyDocument``, a dict from
    ``get_account_authorization_details``) into::

        {"concrete": [...],             # concrete principals allowed to assume (topology edges)
         "public_unconditioned": bool,  # an Allow with a '*'/'*:root' principal AND NO Condition (truly anyone)
         "public_conditioned":  bool,   # an Allow '*' NARROWED by a Condition (org/ExternalId/SourceAccount) — SECURE
         "has_deny_wildcard": bool}     # a Deny whose OWN principal is a wildcard (subtracts the public grant)

    A ``*`` principal carrying ANY ``Condition`` is the standard SECURE cross-account/organisation pattern
    (``aws:PrincipalOrgID`` / ``sts:ExternalId`` / ``aws:SourceAccount``) — it is emphatically NOT publicly
    assumable, so it must never be minted as a public FACT (BLOCK-1). ``Service`` trusts are ignored (a
    service trust is not a user-reachable assume). Total: any odd shape contributes nothing."""
    out: dict[str, Any] = {"concrete": [], "public_unconditioned": False,
                           "public_conditioned": False, "has_deny_wildcard": False}
    if not isinstance(assume_role_policy_document, dict):
        return out
    stmts = assume_role_policy_document.get("Statement")
    if isinstance(stmts, dict):
        stmts = [stmts]
    if not isinstance(stmts, list):
        return out
    for st in stmts:
        if not isinstance(st, dict):
            continue
        effect = str(st.get("Effect") or "").strip().lower()
        if effect not in ("allow", "deny"):
            continue
        wildcard, concrete = _statement_principals(st.get("Principal"))
        if effect == "deny":
            # only a Deny that ITSELF matches the wildcard actually subtracts a public grant; a Deny on a
            # DIFFERENT concrete principal does not (L1 — avoids suppressing a genuinely-public role).
            if wildcard:
                out["has_deny_wildcard"] = True
            continue
        out["concrete"].extend(concrete)   # a concrete trust is a real assume edge (condition or not)
        if wildcard:
            if _has_condition(st):         # case-insensitive (L2): a narrowing Condition is the secure pattern
                out["public_conditioned"] = True
            else:
                out["public_unconditioned"] = True
    return out


def _has_condition(statement: dict) -> bool:
    """True iff an IAM statement carries a non-empty ``Condition`` block — matched CASE-INSENSITIVELY so a
    non-canonical ``condition`` key still counts (defence-in-depth: AWS canonicalises to PascalCase, but a
    hand-fed export must not be able to hide a narrowing condition behind odd casing, L2)."""
    for k, v in statement.items():
        if str(k).strip().lower() == "condition" and v:
            return True
    return False


def _statement_principals(principal: Any) -> tuple[bool, list[str]]:
    """Parse an IAM statement ``Principal`` into (has_wildcard, concrete_principals). A ``"*"`` or an
    ``{"AWS": "*"|"…:*:root"|[…]}`` wildcard sets the flag; concrete ARNs/accounts are collected;
    ``Service``/``Federated`` trusts are ignored (not a user-reachable assume). Total."""
    concrete: list[str] = []
    if principal == "*":
        return True, concrete
    wildcard = False
    if isinstance(principal, dict):
        aws = principal.get("AWS")
        vals = [aws] if isinstance(aws, str) else (aws if isinstance(aws, list) else [])
        for v in vals:
            v = str(v or "").strip()
            if not v:
                continue
            if v in _WILDCARD_TRUST:
                wildcard = True
            else:
                concrete.append(v)
    return wildcard, concrete


def _roles_to_inventory(role_detail_list: Any) -> tuple[list[dict], list[dict]]:
    """From IAM ``get_account_authorization_details`` ``RoleDetailList`` build (principals, resources):
    each role is a ``role`` principal; each concrete trust principal gains a ``can_assume`` edge to it.

    A role becomes a public ``cloud_resource`` (over-broad trust — the policy-path oracle re-derives the
    anonymous assume path) ONLY when its trust is a wildcard that is UNCONDITIONED and not subtracted by a
    WILDCARD Deny (``public_unconditioned and not has_deny_wildcard``). A CONDITION-narrowed wildcard (the
    secure org/ExternalId pattern) or a wildcard-Deny'd wildcard is NOT promoted — instead the raw trust
    analysis is retained on the role PRINCIPAL (``trust_wildcard``/``trust_conditioned``/
    ``trust_deny_wildcard``, oracle-inert attrs) so the config is auditable without a false public FACT.
    Total: odd entries are skipped."""
    principals: list[dict] = []
    resources: list[dict] = []
    can_assume: dict[str, list[str]] = {}
    if not isinstance(role_detail_list, list):
        return principals, resources
    for role in role_detail_list:
        if not isinstance(role, dict):
            continue
        rid = str(role.get("Arn") or role.get("RoleName") or "").strip()
        if not rid:
            continue
        ta = _trust_analysis(role.get("AssumeRolePolicyDocument"))
        principal: dict[str, Any] = {"id": rid, "kind": "role"}
        if ta["public_unconditioned"] or ta["public_conditioned"]:
            principal["trust_wildcard"] = True
            principal["trust_conditioned"] = bool(ta["public_conditioned"])
            principal["trust_deny_wildcard"] = bool(ta["has_deny_wildcard"])
        principals.append(principal)
        if ta["public_unconditioned"] and not ta["has_deny_wildcard"]:
            resources.append({"id": rid, "kind": "cloud_resource", "public": True,
                              "grants": [{"principal": "*", "access": "assume"}]})
        for p in ta["concrete"]:
            can_assume.setdefault(p, [])
            if rid not in can_assume[p]:
                can_assume[p].append(rid)
    for pid, targets in can_assume.items():
        principals.append({"id": pid, "can_assume": list(targets)})
    return principals, resources


def _users_to_principals(user_detail_list: Any) -> list[dict]:
    """From IAM ``get_account_authorization_details`` ``UserDetailList`` build ``user`` principals. Total."""
    out: list[dict] = []
    if not isinstance(user_detail_list, list):
        return out
    for u in user_detail_list:
        if not isinstance(u, dict):
            continue
        uid = str(u.get("Arn") or u.get("UserName") or "").strip()
        if uid:
            out.append({"id": uid, "kind": "user"})
    return out


def aws_inventory_from_responses(
    *,
    buckets: Any = (),
    account_auth: Any = None,
    account_bpa: Any = None,
    provider: str = "aws",
) -> dict:
    """Assemble the native inventory (``{"provider","principals","resources"}``) from the collector's
    retained read-only responses. PURE + total — the deterministic core every cloud_live test exercises
    and every oracle consumes. ``buckets`` is the list of per-bucket records (see :func:`bucket_resource`);
    ``account_auth`` is the ``get_account_authorization_details`` response (or None); ``account_bpa`` is the
    ACCOUNT-level ``get_public_access_block`` outcome (dict / ``"absent"`` / None), applied to every bucket."""
    resources: list[dict] = []
    acct_bpa = _bpa_fields(account_bpa)          # dict|None — the account-wide BPA field view
    if not isinstance(buckets, (list, tuple)):   # totality: a non-iterable never raises
        buckets = ()
    for b in buckets:
        r = bucket_resource(b, account_bpa=acct_bpa)
        if r is not None:
            resources.append(r)
    principals: list[dict] = []
    if isinstance(account_auth, dict):
        role_pr, role_res = _roles_to_inventory(account_auth.get("RoleDetailList"))
        principals.extend(_users_to_principals(account_auth.get("UserDetailList")))
        principals.extend(role_pr)
        resources.extend(role_res)
    return {"provider": provider, "principals": principals, "resources": resources}


# ---------------------------------------------------------------------------
# the live sensor
# ---------------------------------------------------------------------------


def _aws_service_hosts(region: str) -> tuple[str, ...]:
    """The concrete AWS control-plane hosts the collector reaches for ``region`` — STS, S3, S3-Control and
    IAM — partition-aware (commercial / GovCloud / China). Declared as ``egress_hosts`` so the egress gate
    authorises exactly what boto3 will call. The one residual is a cross-REGION S3 access, where botocore
    may 301-redirect to a sibling ``s3.<other-region>...`` host; for a multi-region account the operator
    provisions ``*.amazonaws.com`` (C1 permits a ≥2-private-label wildcard) or scopes the region."""
    r = (region or "us-east-1").strip().lower() or "us-east-1"
    china = r.startswith("cn-")
    gov = r.startswith("us-gov-")
    sfx = "amazonaws.com.cn" if china else "amazonaws.com"
    hosts: set[str] = {f"sts.{r}.{sfx}", f"s3.{r}.{sfx}", f"s3-control.{r}.{sfx}"}
    if not china and not gov:           # only the COMMERCIAL partition exposes the global STS / S3 aliases
        hosts.add("sts.amazonaws.com")
        hosts.add("s3.amazonaws.com")
    # IAM is a single global endpoint per partition
    hosts.add(f"iam.{r}.{sfx}" if china else ("iam.us-gov.amazonaws.com" if gov else "iam.amazonaws.com"))
    return tuple(sorted(hosts))


class CloudLiveSensor:
    """Live, read-only AWS posture collector (Tier-2, ``ACTIVE_RECON``). Discovers the host's AMBIENT AWS
    identity (boto3 default chain), makes only ``list_*``/``get_*`` calls, and emits the native inventory
    as ``{"export": <json>, "format": "native"}`` — the SAME shape the offline importer emits, so the
    existing normalize + fusion re-verify promote its leads with no downstream change.

    Endpoint + region are read from the ENVIRONMENT/constructor ONLY (never run-time args) so the declared
    ``egress_hosts`` match the hosts boto3 will actually call. Set ``CRUCIBLE_AWS_ENDPOINT_URL`` (or
    ``AWS_ENDPOINT_URL``) to target LocalStack / a self-hosted / GovCloud endpoint; unset ⇒ real AWS for
    ``AWS_REGION`` (default ``us-east-1``). Fail-closed no-op when boto3 is absent, no ambient credentials
    are discoverable, or STS rejects the identity."""

    name = "cloud_live"
    tier = "T2"
    capability = Capability.ACTIVE_RECON
    destructive = False

    # a bounded number of buckets to inspect per run (each bucket costs a handful of read-only calls);
    # a very large account degrades to the first N rather than making an unbounded number of calls.
    _MAX_BUCKETS = 500

    def __init__(self, *, endpoint_url: str | None = None, region: str | None = None) -> None:
        self._endpoint_url = (
            endpoint_url if endpoint_url is not None
            else (os.environ.get("CRUCIBLE_AWS_ENDPOINT_URL")
                  or os.environ.get("AWS_ENDPOINT_URL") or ""))
        self._region = (region or os.environ.get("AWS_REGION")
                        or os.environ.get("AWS_DEFAULT_REGION") or "us-east-1")
        if self._endpoint_url:
            host = urlsplit(self._endpoint_url).hostname or ""
            self.egress_hosts: tuple[str, ...] = (host,) if host else ("<malformed-endpoint>",)
        else:
            self.egress_hosts = _aws_service_hosts(self._region)

    # -- live read-only collection (non-deterministic; degrades cleanly) --

    def _client_kwargs(self) -> dict:
        kw: dict[str, Any] = {"region_name": self._region}
        if self._endpoint_url:
            kw["endpoint_url"] = self._endpoint_url
        return kw

    def _collect_s3(self, s3: Any) -> list[dict]:
        """Per-bucket read-only posture: ACL, policy-status, Block-Public-Access, default-encryption,
        classification tags. A per-bucket denial/absence degrades that field (best-effort), never raising.
        Each closure binds ``name`` as a default arg so the loop variable is captured correctly."""
        out: list[dict] = []
        try:
            listing = s3.list_buckets()
        except Exception:
            return out
        for b in (listing.get("Buckets") or [])[: self._MAX_BUCKETS]:
            name = str(b.get("Name") or "").strip() if isinstance(b, dict) else ""
            if not name:
                continue
            rec: dict[str, Any] = {"name": name}
            rec["acl"] = self._safe_call(lambda n=name: s3.get_bucket_acl(Bucket=n))
            rec["policy_status"] = self._safe_call(lambda n=name: s3.get_bucket_policy_status(Bucket=n))
            rec["public_access_block"] = self._safe_notfound(
                lambda n=name: s3.get_public_access_block(Bucket=n), "NoSuchPublicAccessBlock")
            rec["encryption"] = self._safe_notfound(
                lambda n=name: s3.get_bucket_encryption(Bucket=n), "ServerSideEncryptionConfigurationNotFound")
            rec["tagging"] = self._safe_call(lambda n=name: s3.get_bucket_tagging(Bucket=n))
            out.append(rec)
        return out

    def _collect_account_bpa(self, session: Any, account: str, kw: dict) -> Any:
        """Account-level Block-Public-Access via S3-Control (read-only). ``"absent"`` when none is
        configured (a KNOWN 'off'); None when denied / S3-Control unavailable (UNKNOWN)."""
        if not account:
            return None
        try:
            s3c = session.client("s3control", **kw)
        except Exception:
            return None
        return self._safe_notfound(
            lambda: s3c.get_public_access_block(AccountId=account), "NoSuchPublicAccessBlock")

    def _collect_iam(self, iam: Any) -> dict | None:
        """IAM authorization details (users/roles/trust policies), read-only. Returns None when the call is
        denied (a scoped read-only role may lack ``iam:GetAccountAuthorizationDetails``) — IAM topology is
        then simply absent, S3 posture still returns."""
        try:
            paginator = iam.get_paginator("get_account_authorization_details")
            merged: dict[str, list] = {"UserDetailList": [], "RoleDetailList": [], "GroupDetailList": []}
            for page in paginator.paginate():
                for key in merged:
                    merged[key].extend(page.get(key) or [])
            return merged
        except Exception:
            try:
                return iam.get_account_authorization_details()
            except Exception:
                return None

    @staticmethod
    def _safe_call(fn: Any) -> Any:
        try:
            return fn()
        except Exception:
            return None

    @staticmethod
    def _safe_notfound(fn: Any, marker: str) -> Any:
        """Run a read-only call, distinguishing a genuine NOT-CONFIGURED result from a denial/other error:
          * success -> the response;
          * an exception whose botocore error CODE or exception CLASS name contains ``marker`` (e.g.
            ``ServerSideEncryptionConfigurationNotFound`` / ``NoSuchPublicAccessBlock``) -> the ``"absent"``
            sentinel (a KNOWN 'not configured', an explicit fact);
          * any other error (AccessDenied, network, throttle, …) -> ``None`` (UNKNOWN — never mistaken for
            an insecure fact). The error CODE is authoritative (real boto3 raises a ``ClientError`` whose
            type name is NOT the code) with the modeled-exception CLASS name as a fallback. The free-text
            MESSAGE is deliberately NOT matched — a denial whose message happened to quote the marker must
            not be misread as 'absent' (L3)."""
        try:
            return fn()
        except Exception as e:
            code = ""
            try:
                resp = getattr(e, "response", None)
                if isinstance(resp, dict):
                    code = str((resp.get("Error") or {}).get("Code") or "")
            except Exception:
                code = ""
            if marker in code or marker in type(e).__name__:
                return "absent"
            return None

    def run(self, args: dict, ctx: ToolContext) -> ToolResult:
        try:
            import boto3  # noqa: F401
        except Exception:
            return ToolResult(ok=False, note=(
                "cloud_live: boto3 not installed — live AWS collection unavailable (fail-closed no-op). "
                "Install it (`pip install boto3`) to enable live cloud posture."))
        try:
            session = boto3.Session(region_name=self._region)
            creds = session.get_credentials()
        except Exception as e:
            return ToolResult(ok=False, note=f"cloud_live: could not initialise an AWS session (fail-closed): {e}")
        if creds is None:
            return ToolResult(ok=False, note=(
                "cloud_live: no ambient AWS credentials discoverable (environment / shared config / SSO "
                "cache / instance-profile / task-role / IRSA) — fail-closed no-op. Configure the HOST's "
                "read-only AWS identity; VIGIL discovers and uses it — you need not hand credentials over."))
        kw = self._client_kwargs()
        try:
            ident = session.client("sts", **kw).get_caller_identity()
            account = str(ident.get("Account") or "")
        except Exception as e:
            return ToolResult(ok=False, note=(
                f"cloud_live: STS get-caller-identity failed — the ambient credentials are invalid/expired "
                f"or the endpoint is unreachable (fail-closed): {e}"))
        try:
            buckets = self._collect_s3(session.client("s3", **kw))
        except Exception:
            buckets = []
        try:
            account_bpa = self._collect_account_bpa(session, account, kw)
        except Exception:
            account_bpa = None
        try:
            account_auth = self._collect_iam(session.client("iam", **kw))
        except Exception:
            account_auth = None
        inventory = aws_inventory_from_responses(
            buckets=buckets, account_auth=account_auth, account_bpa=account_bpa, provider="aws")
        n_res, n_pri = len(inventory.get("resources", [])), len(inventory.get("principals", []))
        return ToolResult(
            ok=True,
            summary=(f"cloud_live: AWS account {account or '?'} — {n_res} resources, {n_pri} principals "
                     f"(read-only{', endpoint=' + self._endpoint_url if self._endpoint_url else ''})"),
            output={"export": json.dumps(inventory), "format": "native",
                    "provider": "aws", "account": account, "endpoint": self._endpoint_url or ""})

    def normalize(self, result: ToolResult, ctx: ToolContext, *, seq: int) -> list[Observation]:
        """Identical to the offline importer's normalize — the export is the native inventory, minted as
        IAM topology + posture LEADS via the SHARED ``cloud_observations`` minter (one way to produce the
        schema). The LEAD -> FACT promotion is the fusion re-verify's job, not the sensor's."""
        out = result.output or {}
        text, fmt = out.get("export"), out.get("format", "native")
        if not isinstance(text, str) or not text.strip():
            return []
        return cloud_observations(_load_export(text, fmt if isinstance(fmt, str) else "native"), seq=seq)
