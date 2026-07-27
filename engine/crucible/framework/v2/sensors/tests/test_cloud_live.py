"""
Phase C2 — LIVE read-only AWS posture collector (sensors.cloud_live).

Three layers, each provable independently:

  1. DETERMINISTIC CORE (no SDK, no network): recorded AWS/LocalStack read-only response shapes ->
     ``aws_inventory_from_responses`` -> the native inventory -> the EXISTING cloud oracles FIRE
     (``confirm_cloud_posture_facts`` public-exposure/over-broad-trust; ``confirm_cloud_posture``
     encryption-at-rest). Includes the ADVERSARIAL negative controls a near-zero-FP claim demands:
     a Condition-narrowed wildcard trust, a Deny-subtracted wildcard, a public ACL neutralised by
     Block-Public-Access, and a public signal whose BPA is UNKNOWN — none of which may become a FACT.
  2. FAIL-CLOSED ``run``: no boto3 / no ambient credentials -> an honest no-op ToolResult; declared
     ``egress_hosts`` == the hosts boto3 will actually call (partition-aware).
  3. REAL END-TO-END against a purpose-built AWS test system: ``moto`` (in-process AWS mock) drives the
     collector's ACTUAL boto3 ``run`` path against a seeded account whose posture INCLUDES the traps
     (an ignored-ACL bucket, a Condition-narrowed role); the fusion re-verify promotes only the true
     positives. A LocalStack integration test (endpoint override) runs where that rig is up. Both skip
     cleanly when their dependency is absent, so CI stays green.
"""

from __future__ import annotations

import json
import socket
import sys
from types import SimpleNamespace

import pytest

from framework.v2.sensors.cloud import (
    cloud_observations,
    confirm_cloud_posture_facts,
    normalize_cloud_export,
)
from framework.v2.sensors.cloud_live import (
    CloudLiveSensor,
    aws_inventory_from_responses,
    bucket_resource,
)

# ---------------------------------------------------------------------------
# recorded read-only response shapes (exactly what boto3/LocalStack return)
# ---------------------------------------------------------------------------

_ACL_PUBLIC = {"Owner": {"ID": "o"}, "Grants": [
    {"Grantee": {"Type": "Group", "URI": "http://acs.amazonaws.com/groups/global/AllUsers"},
     "Permission": "READ"}]}
_ACL_PRIVATE = {"Owner": {"ID": "o"}, "Grants": [
    {"Grantee": {"Type": "CanonicalUser", "ID": "o"}, "Permission": "FULL_CONTROL"}]}
_ENC_ON = {"ServerSideEncryptionConfiguration": {"Rules": [
    {"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]}}
_TAG_SENSITIVE = {"TagSet": [{"Key": "data-classification", "Value": "confidential"}]}

_BPA_OFF = "absent"                             # KNOWN: no BPA configured -> not neutralising
_BPA_IGNORE_ACLS = {"PublicAccessBlockConfiguration": {
    "BlockPublicAcls": False, "IgnorePublicAcls": True, "BlockPublicPolicy": False, "RestrictPublicBuckets": False}}
_BPA_RESTRICT = {"PublicAccessBlockConfiguration": {
    "BlockPublicAcls": False, "IgnorePublicAcls": False, "BlockPublicPolicy": False, "RestrictPublicBuckets": True}}

# true positives
_PUBLIC_BUCKET = {"name": "acme-public", "acl": _ACL_PUBLIC, "policy_status": None,
                  "public_access_block": _BPA_OFF, "encryption": _ENC_ON, "tagging": None}
_SECRET_BUCKET = {"name": "acme-secrets", "acl": _ACL_PRIVATE,
                  "policy_status": {"PolicyStatus": {"IsPublic": False}},
                  "public_access_block": _BPA_OFF, "encryption": "absent", "tagging": _TAG_SENSITIVE}
_SAFE_BUCKET = {"name": "acme-safe", "acl": _ACL_PRIVATE,
                "policy_status": {"PolicyStatus": {"IsPublic": False}},
                "public_access_block": _BPA_OFF, "encryption": _ENC_ON, "tagging": None}
# adversarial negative controls (public SIGNAL present, but NOT anonymously reachable)
_ACL_IGNORED = {"name": "acme-acl-ignored", "acl": _ACL_PUBLIC, "policy_status": None,
                "public_access_block": _BPA_IGNORE_ACLS, "encryption": _ENC_ON, "tagging": None}
_POLICY_RESTRICTED = {"name": "acme-policy-restricted", "acl": _ACL_PRIVATE,
                      "policy_status": {"PolicyStatus": {"IsPublic": True}},
                      "public_access_block": _BPA_RESTRICT, "encryption": _ENC_ON, "tagging": None}
_BPA_UNKNOWN_BUCKET = {"name": "acme-bpa-unknown", "acl": _ACL_PUBLIC, "policy_status": None,
                       "public_access_block": None, "encryption": _ENC_ON, "tagging": None}   # BPA denied


def _role(name, statement):
    return {"RoleName": name, "Arn": f"arn:aws:iam::111122223333:role/{name}",
            "AssumeRolePolicyDocument": {"Version": "2012-10-17", "Statement": statement}}


_ROLE_WIDE_OPEN = _role("wide-open", [{"Effect": "Allow", "Principal": "*", "Action": "sts:AssumeRole"}])
_ROLE_ORG_SCOPED = _role("org-scoped", [{"Effect": "Allow", "Principal": "*", "Action": "sts:AssumeRole",
    "Condition": {"StringEquals": {"aws:PrincipalOrgID": "o-abc123"}}}])       # SECURE org pattern
_ROLE_EXTID = _role("extid", [{"Effect": "Allow", "Principal": {"AWS": "*"}, "Action": "sts:AssumeRole",
    "Condition": {"StringEquals": {"sts:ExternalId": "shared-secret"}}}])      # SECURE confused-deputy mitigation
_ROLE_DENY_WILD = _role("deny-wild", [
    {"Effect": "Allow", "Principal": "*", "Action": "sts:AssumeRole"},
    {"Effect": "Deny", "Principal": "*", "Action": "sts:AssumeRole"}])
_ROLE_SCOPED = _role("scoped", [{"Effect": "Allow", "Action": "sts:AssumeRole",
    "Principal": {"AWS": "arn:aws:iam::999988887777:root"}}])

_ACCOUNT_AUTH = {
    "UserDetailList": [{"UserName": "alice", "Arn": "arn:aws:iam::111122223333:user/alice"}],
    "RoleDetailList": [_ROLE_WIDE_OPEN, _ROLE_ORG_SCOPED, _ROLE_EXTID, _ROLE_DENY_WILD, _ROLE_SCOPED],
    "GroupDetailList": [],
}


# ---------------------------------------------------------------------------
# 1a. deterministic core — bucket public/encryption/sensitivity + BPA neutralisation
# ---------------------------------------------------------------------------


def test_bucket_resource_public_via_acl_when_bpa_off():
    r = bucket_resource(_PUBLIC_BUCKET)
    assert r["public"] is True and any(g["principal"] == "*" for g in r["grants"])
    assert r["acl_public"] is True and r["bpa_known"] is True          # raw evidence retained


def test_bucket_resource_encryption_and_sensitivity_tri_state():
    secret = bucket_resource(_SECRET_BUCKET)
    assert secret["encrypted"] is False and secret["sensitive"] is True
    assert "public" not in secret
    safe = bucket_resource(_SAFE_BUCKET)
    assert safe["encrypted"] is True and "sensitive" not in safe and "public" not in safe


def test_bpa_ignore_acls_neutralises_a_public_acl():
    r = bucket_resource(_ACL_IGNORED)
    assert "public" not in r                       # IgnorePublicAcls -> ACL does not grant anonymous access
    assert r["acl_public"] is True                 # but the raw signal is retained (auditable)
    assert r["bpa"]["IgnorePublicAcls"] is True


def test_bpa_restrict_neutralises_a_public_policy():
    r = bucket_resource(_POLICY_RESTRICTED)
    assert "public" not in r                       # RestrictPublicBuckets -> policy grants no anonymous access
    assert r["policy_public"] is True              # raw signal retained


def test_public_signal_with_unknown_bpa_is_not_confirmed_public():
    r = bucket_resource(_BPA_UNKNOWN_BUCKET)       # BPA denied -> cannot confirm reachability
    assert "public" not in r                       # conservative: no false public FACT
    assert r["acl_public"] is True and r["bpa_known"] is False          # retained as an un-promoted lead


def test_account_level_bpa_overrides_bucket_absence():
    # bucket has no BPA, but the ACCOUNT enforces IgnorePublicAcls -> a public ACL is still neutralised
    r = bucket_resource({"name": "b", "acl": _ACL_PUBLIC, "public_access_block": _BPA_OFF},
                        account_bpa={"BlockPublicAcls": False, "IgnorePublicAcls": True,
                                     "BlockPublicPolicy": False, "RestrictPublicBuckets": False})
    assert "public" not in r and r["acl_public"] is True


def test_bucket_resource_totality_on_garbage():
    assert bucket_resource({"name": ""}) is None and bucket_resource("nonsense") is None
    r = bucket_resource({"name": "b", "acl": 123, "policy_status": [], "public_access_block": 7,
                         "encryption": {}, "tagging": None})
    assert r["id"] == "b" and "public" not in r and r["bpa_known"] is False


def test_inventory_from_responses_is_total_on_non_iterable_buckets():
    # LOW-2: a truthy non-iterable must not raise (documented "PURE + total")
    assert aws_inventory_from_responses(buckets=1) == {"provider": "aws", "principals": [], "resources": []}
    assert aws_inventory_from_responses(buckets=None, account_auth="x")["resources"] == []


# ---------------------------------------------------------------------------
# 1b. deterministic core — IAM trust (BLOCK-1: Condition/Deny-aware)
# ---------------------------------------------------------------------------


def test_unconditioned_wildcard_trust_is_public():
    _pr, res = _roles_from({"RoleDetailList": [_ROLE_WIDE_OPEN]})
    pub = [r for r in res if r.get("public")]
    assert len(pub) == 1 and pub[0]["id"].endswith("role/wide-open")


def test_condition_narrowed_wildcard_trust_is_NOT_public():
    # BLOCK-1 regression: org-scoped and ExternalId-scoped '*' are SECURE — must NOT mint a public resource
    principals, resources = _roles_from({"RoleDetailList": [_ROLE_ORG_SCOPED, _ROLE_EXTID]})
    assert not any(r.get("public") for r in resources)                 # zero public FACT candidates
    # the raw analysis is retained on the role principal for audit
    org = next(p for p in principals if p["id"].endswith("role/org-scoped"))
    assert org["trust_wildcard"] is True and org["trust_conditioned"] is True


def test_deny_subtracted_wildcard_trust_is_NOT_public():
    _pr, resources = _roles_from({"RoleDetailList": [_ROLE_DENY_WILD]})
    assert not any(r.get("public") for r in resources)


def test_concrete_trust_builds_a_can_assume_edge_not_a_fact():
    principals, resources = _roles_from({"RoleDetailList": [_ROLE_SCOPED]})
    assert not any(r.get("public") for r in resources)
    assert any("role/scoped" in (p.get("can_assume") or [""])[0] for p in principals if p.get("can_assume"))


def _roles_from(account_auth: dict):
    inv = aws_inventory_from_responses(buckets=(), account_auth=account_auth)
    return inv["principals"], inv["resources"]


# ---------------------------------------------------------------------------
# 1c. the whole point — the EXISTING oracles fire over the translated inventory,
#     and fire on NOTHING that is actually safe
# ---------------------------------------------------------------------------


def test_oracles_fire_on_true_positives_and_nothing_safe():
    inv = aws_inventory_from_responses(
        buckets=[_PUBLIC_BUCKET, _SECRET_BUCKET, _SAFE_BUCKET, _ACL_IGNORED, _POLICY_RESTRICTED,
                 _BPA_UNKNOWN_BUCKET],
        account_auth=_ACCOUNT_AUTH)
    facts = confirm_cloud_posture_facts(inv)
    reached = {f["resource"] for f in facts if f["lead_class"] == "public_exposure"}
    # TRUE POSITIVES promoted:
    assert "acme-public" in reached
    assert any("wide-open" in r for r in reached)
    # NEGATIVE CONTROLS never promoted (the near-zero-FP surface BLOCK-1/MEDIUM-1 were about):
    for safe in ("acme-safe", "acme-acl-ignored", "acme-policy-restricted", "acme-bpa-unknown"):
        assert safe not in reached, f"false public FACT on {safe}"
    for safe_role in ("org-scoped", "extid", "deny-wild", "scoped"):
        assert not any(safe_role in r for r in reached), f"false trust FACT on {safe_role}"
    # achieved-state encryption oracle: only the sensitive+unencrypted bucket
    from framework.v2.verify.cloud_posture import confirm_cloud_posture
    assert _enc_fact_fires(confirm_cloud_posture, bucket_resource(_SECRET_BUCKET))
    assert not confirm_cloud_posture(bucket_resource(_SAFE_BUCKET)).confirmed


def _enc_fact_fires(confirm, resource) -> bool:
    res = confirm(resource)
    return bool(res.confirmed and any(
        (getattr(s, "observed", None) or {}).get("rule") == "encryption_at_rest_disabled"
        for s in (res.signals or []) if getattr(s, "fired", False)))


def test_normalize_mints_public_exposure_lead():
    inv = aws_inventory_from_responses(buckets=[_PUBLIC_BUCKET], account_auth=None)
    obs = cloud_observations(normalize_cloud_export(inv), seq=1)
    assert any(getattr(o, "attrs", {}).get("lead_class") == "public_exposure" for o in obs)


# ---------------------------------------------------------------------------
# 2. egress_hosts (declared == what boto3 will call) + fail-closed run
# ---------------------------------------------------------------------------


def test_egress_hosts_real_aws_include_all_service_hosts(monkeypatch):
    monkeypatch.delenv("CRUCIBLE_AWS_ENDPOINT_URL", raising=False)
    monkeypatch.delenv("AWS_ENDPOINT_URL", raising=False)
    h = CloudLiveSensor(region="eu-west-1").egress_hosts
    assert {"sts.eu-west-1.amazonaws.com", "s3.eu-west-1.amazonaws.com",
            "s3-control.eu-west-1.amazonaws.com", "iam.amazonaws.com"} <= set(h)


def test_egress_hosts_partition_aware():
    gov = set(CloudLiveSensor(region="us-gov-west-1").egress_hosts)
    assert "iam.us-gov.amazonaws.com" in gov and "s3.us-gov-west-1.amazonaws.com" in gov
    china = set(CloudLiveSensor(region="cn-north-1").egress_hosts)
    assert all(h.endswith("amazonaws.com.cn") for h in china)           # china partition suffix, no leak


def test_egress_hosts_endpoint_override_is_exact():
    assert CloudLiveSensor(endpoint_url="http://localhost:4566").egress_hosts == ("localhost",)


def test_run_fail_closed_without_boto3(monkeypatch):
    monkeypatch.setitem(sys.modules, "boto3", None)
    r = CloudLiveSensor().run({}, SimpleNamespace())
    assert r.ok is False and "boto3" in r.note and "fail-closed" in r.note.lower()


def test_run_fail_closed_without_ambient_credentials(monkeypatch):
    fake = SimpleNamespace(Session=lambda **_: SimpleNamespace(get_credentials=lambda: None))
    monkeypatch.setitem(sys.modules, "boto3", fake)
    r = CloudLiveSensor().run({}, SimpleNamespace())
    assert r.ok is False and "no ambient aws credentials" in r.note.lower()


# ---------------------------------------------------------------------------
# 3. REAL end-to-end against a purpose-built AWS test system (moto, in-process)
# ---------------------------------------------------------------------------


def _seed_fake_aws(boto3):
    """Seed the account with true positives AND traps. The COLLECTOR only reads; the TEST seeds."""
    s3 = boto3.client("s3", region_name="us-east-1")
    s3.create_bucket(Bucket="acme-public")
    s3.put_bucket_acl(Bucket="acme-public", ACL="public-read")               # TRUE public (no BPA)
    s3.create_bucket(Bucket="acme-secrets")
    s3.put_bucket_tagging(Bucket="acme-secrets",
                          Tagging={"TagSet": [{"Key": "data-classification", "Value": "confidential"}]})
    s3.create_bucket(Bucket="acme-safe")
    s3.put_bucket_encryption(Bucket="acme-safe", ServerSideEncryptionConfiguration={"Rules": [
        {"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]})
    s3.create_bucket(Bucket="acme-acl-ignored")                              # TRAP: public ACL neutralised by BPA
    s3.put_bucket_acl(Bucket="acme-acl-ignored", ACL="public-read")
    s3.put_public_access_block(Bucket="acme-acl-ignored", PublicAccessBlockConfiguration={
        "BlockPublicAcls": False, "IgnorePublicAcls": True, "BlockPublicPolicy": False, "RestrictPublicBuckets": False})
    iam = boto3.client("iam", region_name="us-east-1")
    iam.create_role(RoleName="wide-open", AssumeRolePolicyDocument=json.dumps(
        {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": "*", "Action": "sts:AssumeRole"}]}))
    iam.create_role(RoleName="org-scoped", AssumeRolePolicyDocument=json.dumps(   # TRAP: secure org pattern
        {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": "*", "Action": "sts:AssumeRole",
         "Condition": {"StringEquals": {"aws:PrincipalOrgID": "o-abc123"}}}]}))


def _assert_live_findings(export_json: str):
    inv = json.loads(export_json)
    facts = confirm_cloud_posture_facts(normalize_cloud_export(inv))
    reached = {f["resource"] for f in facts if f["lead_class"] == "public_exposure"}
    assert "acme-public" in reached and any("wide-open" in r for r in reached)   # true positives
    assert "acme-acl-ignored" not in reached                                     # trap held (BPA)
    assert not any("org-scoped" in r for r in reached)                           # trap held (Condition)
    from framework.v2.verify.cloud_posture import confirm_cloud_posture
    secret = next((r for r in inv["resources"] if r["id"] == "acme-secrets"), None)
    assert secret and secret.get("encrypted") is False and secret.get("sensitive") is True
    assert confirm_cloud_posture(secret).confirmed


def test_end_to_end_against_moto(monkeypatch):
    """Drive the collector's ACTUAL boto3 run() path against moto's in-process AWS — real client
    construction, the env-credential provider (ambient discovery), every read-only call, INCLUDING the
    Block-Public-Access + trust-Condition traps that must NOT promote."""
    pytest.importorskip("boto3")
    mock_aws = getattr(pytest.importorskip("moto"), "mock_aws", None)
    if mock_aws is None:
        pytest.skip("moto too old (no mock_aws)")
    import boto3
    for k, v in {"AWS_ACCESS_KEY_ID": "testing", "AWS_SECRET_ACCESS_KEY": "testing",
                 "AWS_SESSION_TOKEN": "testing", "AWS_DEFAULT_REGION": "us-east-1",
                 "AWS_REGION": "us-east-1"}.items():
        monkeypatch.setenv(k, v)
    monkeypatch.delenv("CRUCIBLE_AWS_ENDPOINT_URL", raising=False)
    monkeypatch.delenv("AWS_ENDPOINT_URL", raising=False)
    with mock_aws():
        _seed_fake_aws(boto3)
        result = CloudLiveSensor().run({}, SimpleNamespace())
    assert result.ok, result.note
    assert result.output["format"] == "native"
    _assert_live_findings(result.output["export"])


def _localstack_up(host: str = "127.0.0.1", port: int = 4566) -> bool:
    try:
        with socket.create_connection((host, port), timeout=0.5):
            return True
    except OSError:
        return False


@pytest.mark.skipif(not _localstack_up(), reason="LocalStack not running on 127.0.0.1:4566")
def test_end_to_end_against_localstack(monkeypatch):
    """Same assertions against LocalStack (real emulated AWS in Docker) via the endpoint_url override."""
    boto3 = pytest.importorskip("boto3")
    endpoint = "http://127.0.0.1:4566"
    for k, v in {"AWS_ACCESS_KEY_ID": "test", "AWS_SECRET_ACCESS_KEY": "test",
                 "AWS_DEFAULT_REGION": "us-east-1", "AWS_REGION": "us-east-1"}.items():
        monkeypatch.setenv(k, v)
    monkeypatch.setenv("CRUCIBLE_AWS_ENDPOINT_URL", endpoint)
    orig_client = boto3.client
    monkeypatch.setattr(boto3, "client",
                        lambda svc, **kw: orig_client(svc, endpoint_url=endpoint, **kw))
    _seed_fake_aws(boto3)
    sensor = CloudLiveSensor()
    assert sensor.egress_hosts == ("127.0.0.1",)
    result = sensor.run({}, SimpleNamespace())
    assert result.ok, result.note
    _assert_live_findings(result.output["export"])
