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
    API said so. The live API response is evidence, re-verified offline; it is never laundered into a
    fact by the collector itself.
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
zero network). The live path is exercised against **LocalStack** (real emulated AWS in Docker) via an
``endpoint_url`` override + boto3's env-credential provider — an integration test that skips when boto3
or LocalStack is absent, so CI stays green while the live path is genuinely verified where the rig runs.

HONEST LIMITATION. S3 objects carry no intrinsic "sensitive" bit, so the encryption-at-rest achieved-
state FACT (which requires ``sensitive AND not encrypted``) fires only when the operator has TAGGED the
bucket's data classification (``sensitive`` / ``classification`` / ``data-classification``) — operator-
declared sensitivity, never fabricated. Public-exposure and over-broad-trust facts need no such tag.
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
# STS AssumeRole principal tokens that denote "anyone" — a wildcard trust makes a role publicly assumable.
_WILDCARD_TRUST = frozenset({"*", "arn:aws:iam::*:root"})


# ---------------------------------------------------------------------------
# pure translation: recorded boto3 read-only responses -> the native inventory
# (no boto3, no network — the deterministic, CI-tested core the oracles consume)
# ---------------------------------------------------------------------------


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


def bucket_resource(entry: Any) -> dict | None:
    """Map ONE collected S3 bucket record onto a native-inventory resource. ``entry`` is what the live
    collector gathered for a bucket::

        {"name": "acme-secrets", "acl": <get_bucket_acl resp>|None,
         "policy_status": <get_bucket_policy_status resp>|None,
         "encryption": <get_bucket_encryption resp>|"absent"|None, "tagging": <get_bucket_tagging resp>|None}

    Returns a resource dict (``id``/``kind``/``public``?/``encrypted``?/``sensitive``?/``grants``) or
    ``None`` for a nameless entry. Pure + total (odd/absent fields are simply not asserted). ``public`` is
    set only when EXPLICITLY observed (policy-status public OR a public ACL grant); ``encrypted`` only
    when explicitly known; ``sensitive`` only when the operator tagged it — so an unknown flag never
    becomes an insecure fact (near-zero-FP, matching the oracle's own tri-state discipline)."""
    if not isinstance(entry, dict):
        return None
    name = str(entry.get("name") or "").strip()
    if not name:
        return None
    res: dict[str, Any] = {"id": name, "kind": "datastore"}
    public = _policy_status_is_public(entry.get("policy_status")) or _acl_is_public(entry.get("acl"))
    if public:
        res["public"] = True
        # a concrete anonymous grant so the policy-path oracle can re-derive the public-access path
        # (normalize_cloud_export would synthesise this too; making it explicit keeps the record honest).
        res["grants"] = [{"principal": "*", "access": "read"}]
    enc = _encryption_state(entry.get("encryption"))
    if enc is not None:
        res["encrypted"] = enc
    sens = _sensitive_from_tagging(entry.get("tagging"))
    if sens is not None:
        res["sensitive"] = sens
    return res


def _trust_principals(assume_role_policy_document: Any) -> tuple[list[str], bool]:
    """Parse an IAM role's trust policy (``AssumeRolePolicyDocument``, already a dict from
    ``get_account_authorization_details``) into (concrete-principals-allowed-to-assume, has-wildcard-trust).
    Reads only ``Allow`` statements. ``Principal`` may be ``"*"``, ``{"AWS": "..."|[...]}``,
    ``{"Service": ...}`` (ignored — a service trust is not a user-reachable assume), etc. Total: any odd
    shape contributes nothing / no wildcard."""
    concrete: list[str] = []
    wildcard = False
    if not isinstance(assume_role_policy_document, dict):
        return concrete, wildcard
    stmts = assume_role_policy_document.get("Statement")
    if isinstance(stmts, dict):
        stmts = [stmts]
    if not isinstance(stmts, list):
        return concrete, wildcard
    for st in stmts:
        if not isinstance(st, dict) or str(st.get("Effect") or "").strip().lower() != "allow":
            continue
        principal = st.get("Principal")
        if principal == "*":
            wildcard = True
            continue
        if not isinstance(principal, dict):
            continue
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
    return concrete, wildcard


def _roles_to_inventory(role_detail_list: Any) -> tuple[list[dict], list[dict]]:
    """From IAM ``get_account_authorization_details`` ``RoleDetailList`` build (principals, resources):
    each role is a ``role`` principal; a role with WILDCARD trust becomes a public ``cloud_resource``
    (over-broad trust — the policy-path oracle re-derives the anonymous assume path); each concrete
    trust principal gains a ``can_assume`` edge to the role. Total: odd entries are skipped."""
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
        principals.append({"id": rid, "kind": "role"})
        concrete, wildcard = _trust_principals(role.get("AssumeRolePolicyDocument"))
        if wildcard:
            resources.append({"id": rid, "kind": "cloud_resource", "public": True,
                              "grants": [{"principal": "*", "access": "assume"}]})
        for p in concrete:
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
    provider: str = "aws",
) -> dict:
    """Assemble the native inventory (``{"provider","principals","resources"}``) from the collector's
    retained read-only responses. PURE + total — the deterministic core every cloud_live test exercises
    and every oracle consumes. ``buckets`` is the list of per-bucket records (see :func:`bucket_resource`);
    ``account_auth`` is the ``get_account_authorization_details`` response (or None when IAM was denied)."""
    resources: list[dict] = []
    for b in buckets or []:
        r = bucket_resource(b)
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
    """The concrete AWS control-plane hosts the collector reaches for ``region`` (global + regional STS/S3
    + global IAM). Declared as ``egress_hosts`` so the egress gate authorises exactly what boto3 will call.
    For multi-region S3 the operator provisions ``*.amazonaws.com`` (C1 permits a ≥2-private-label
    wildcard) or sets the bucket's region."""
    r = (region or "us-east-1").strip() or "us-east-1"
    return (
        "sts.amazonaws.com", f"sts.{r}.amazonaws.com",
        "iam.amazonaws.com",
        "s3.amazonaws.com", f"s3.{r}.amazonaws.com",
    )


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
        """Per-bucket read-only posture: ACL, policy-status, default-encryption, classification tags. A
        per-bucket denial/absence degrades that field (best-effort), never raising."""
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
            rec["acl"] = self._safe_call(lambda: s3.get_bucket_acl(Bucket=name))
            rec["policy_status"] = self._safe_call(lambda: s3.get_bucket_policy_status(Bucket=name))
            rec["encryption"] = self._safe_encryption(s3, name)
            rec["tagging"] = self._safe_call(lambda: s3.get_bucket_tagging(Bucket=name))
            out.append(rec)
        return out

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
    def _safe_encryption(s3: Any, name: str) -> Any:
        """Default-encryption with the NotFound case distinguished from a denial: a
        ``ServerSideEncryptionConfigurationNotFoundError`` (no default encryption) -> the ``"absent"``
        sentinel (an EXPLICIT not-encrypted fact); any other error -> None (unknown)."""
        try:
            return s3.get_bucket_encryption(Bucket=name)
        except Exception as e:
            if type(e).__name__ == "ServerSideEncryptionConfigurationNotFoundError" or \
                    "ServerSideEncryptionConfigurationNotFound" in str(e):
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
            account_auth = self._collect_iam(session.client("iam", **kw))
        except Exception:
            account_auth = None
        inventory = aws_inventory_from_responses(buckets=buckets, account_auth=account_auth, provider="aws")
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
