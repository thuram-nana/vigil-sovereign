"""
Phase C2 — LIVE read-only AWS posture collector (sensors.cloud_live).

Three layers, each provable independently:

  1. DETERMINISTIC CORE (no SDK, no network): recorded AWS/LocalStack read-only response shapes ->
     ``aws_inventory_from_responses`` -> the native inventory -> the EXISTING cloud oracles FIRE
     (``confirm_cloud_posture_facts`` public-exposure/over-broad-trust; ``confirm_cloud_posture``
     encryption-at-rest). This is the correctness that turns cloud data into FACTs, CI-guaranteed.
  2. FAIL-CLOSED ``run``: no boto3 / no ambient credentials -> an honest no-op ToolResult (never a crash,
     never a fabricated fact); declared ``egress_hosts`` == the hosts boto3 will actually call.
  3. REAL END-TO-END against a purpose-built AWS test system: ``moto`` (in-process AWS mock) drives the
     collector's ACTUAL boto3 ``run`` path against a seeded fake account (a public bucket, a sensitive
     unencrypted bucket, a wildcard-trust role) and the fusion re-verify promotes the oracle FACTs. A
     LocalStack integration test (same assertions, ``endpoint_url`` override) runs where that rig is up.
     Both skip cleanly when their dependency is absent, so CI stays green.
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

_PUBLIC_BUCKET = {"name": "acme-public", "acl": _ACL_PUBLIC, "policy_status": None,
                  "encryption": _ENC_ON, "tagging": None}
_SECRET_BUCKET = {"name": "acme-secrets", "acl": _ACL_PRIVATE,
                  "policy_status": {"PolicyStatus": {"IsPublic": False}},
                  "encryption": "absent", "tagging": _TAG_SENSITIVE}   # sensitive + unencrypted
_SAFE_BUCKET = {"name": "acme-safe", "acl": _ACL_PRIVATE,
                "policy_status": {"PolicyStatus": {"IsPublic": False}},
                "encryption": _ENC_ON, "tagging": None}

_ACCOUNT_AUTH = {
    "UserDetailList": [{"UserName": "alice", "Arn": "arn:aws:iam::111122223333:user/alice"}],
    "RoleDetailList": [
        {"RoleName": "wide-open", "Arn": "arn:aws:iam::111122223333:role/wide-open",
         "AssumeRolePolicyDocument": {"Version": "2012-10-17", "Statement": [
             {"Effect": "Allow", "Principal": "*", "Action": "sts:AssumeRole"}]}},
        {"RoleName": "scoped", "Arn": "arn:aws:iam::111122223333:role/scoped",
         "AssumeRolePolicyDocument": {"Version": "2012-10-17", "Statement": [
             {"Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::999988887777:root"},
              "Action": "sts:AssumeRole"}]}},
    ],
    "GroupDetailList": [],
}


# ---------------------------------------------------------------------------
# 1. deterministic core — pure translation + the existing oracles fire
# ---------------------------------------------------------------------------


def test_bucket_resource_public_via_acl():
    r = bucket_resource(_PUBLIC_BUCKET)
    assert r["id"] == "acme-public" and r["public"] is True
    assert any(g["principal"] == "*" for g in r["grants"])       # anonymous grant synthesised


def test_bucket_resource_encryption_and_sensitivity_tri_state():
    secret = bucket_resource(_SECRET_BUCKET)
    assert secret["encrypted"] is False and secret["sensitive"] is True   # explicit insecure state
    safe = bucket_resource(_SAFE_BUCKET)
    assert safe["encrypted"] is True and "sensitive" not in safe          # unknown sensitivity is NOT fabricated
    assert "public" not in safe                                           # not public


def test_bucket_resource_totality_on_garbage():
    assert bucket_resource({"name": ""}) is None
    assert bucket_resource("nonsense") is None
    r = bucket_resource({"name": "b", "acl": 123, "policy_status": [], "encryption": {}, "tagging": None})
    assert r == {"id": "b", "kind": "datastore"}                          # nothing asserted from garbage


def test_inventory_from_responses_shape():
    inv = aws_inventory_from_responses(
        buckets=[_PUBLIC_BUCKET, _SECRET_BUCKET, _SAFE_BUCKET], account_auth=_ACCOUNT_AUTH)
    rids = {r["id"] for r in inv["resources"]}
    assert {"acme-public", "acme-secrets", "acme-safe"} <= rids
    assert "arn:aws:iam::111122223333:role/wide-open" in rids            # wildcard-trust role -> resource
    pids = {p["id"] for p in inv["principals"]}
    assert "arn:aws:iam::111122223333:user/alice" in pids
    # the concrete-trust principal gained a can_assume edge to the scoped role
    assume = [p for p in inv["principals"] if p.get("can_assume")]
    assert any("arn:aws:iam::111122223333:role/scoped" in p["can_assume"] for p in assume)


def test_core_oracles_fire_over_the_translated_inventory():
    """The whole point: the translated LIVE inventory promotes to the SAME FACTs the offline importer
    would, via the existing deterministic oracles — no new promotion path."""
    inv = aws_inventory_from_responses(
        buckets=[_PUBLIC_BUCKET, _SECRET_BUCKET, _SAFE_BUCKET], account_auth=_ACCOUNT_AUTH)
    # policy-path oracle: public bucket + wildcard-trust role both re-derive an anonymous reach path
    facts = confirm_cloud_posture_facts(inv)
    reached = {f["resource"] for f in facts if f["lead_class"] == "public_exposure"}
    assert "acme-public" in reached
    assert "arn:aws:iam::111122223333:role/wide-open" in reached
    assert "acme-safe" not in reached                                    # benign bucket never promoted
    # achieved-state oracle: the sensitive unencrypted bucket fires encryption_at_rest_disabled
    from framework.v2.verify.cloud_posture import confirm_cloud_posture
    secret = bucket_resource(_SECRET_BUCKET)
    res = confirm_cloud_posture(secret)
    assert res.confirmed and any(
        (getattr(s, "observed", None) or {}).get("rule") == "encryption_at_rest_disabled"
        for s in (res.signals or []) if getattr(s, "fired", False))


def test_normalize_mints_public_exposure_lead():
    inv = aws_inventory_from_responses(buckets=[_PUBLIC_BUCKET], account_auth=None)
    obs = cloud_observations(normalize_cloud_export(inv), seq=1)
    assert any(getattr(o, "attrs", {}).get("lead_class") == "public_exposure" for o in obs)


# ---------------------------------------------------------------------------
# 2. egress_hosts (declared == what boto3 will call) + fail-closed run
# ---------------------------------------------------------------------------


def test_egress_hosts_real_aws_are_the_service_hosts(monkeypatch):
    monkeypatch.delenv("CRUCIBLE_AWS_ENDPOINT_URL", raising=False)
    monkeypatch.delenv("AWS_ENDPOINT_URL", raising=False)
    s = CloudLiveSensor(region="eu-west-1")
    assert "sts.eu-west-1.amazonaws.com" in s.egress_hosts
    assert "s3.eu-west-1.amazonaws.com" in s.egress_hosts
    assert "iam.amazonaws.com" in s.egress_hosts


def test_egress_hosts_endpoint_override_is_exact():
    s = CloudLiveSensor(endpoint_url="http://localhost:4566", region="us-east-1")
    assert s.egress_hosts == ("localhost",)          # LocalStack: exactly the endpoint host (localhost is always permitted)


def test_run_fail_closed_without_boto3(monkeypatch):
    monkeypatch.setitem(sys.modules, "boto3", None)   # `import boto3` -> ImportError
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
    """Seed the moto/LocalStack account: a public bucket, a sensitive unencrypted bucket, a benign
    encrypted bucket, and a wildcard-trust role. Uses only real boto3 write calls (the TEST seeds; the
    COLLECTOR only reads)."""
    s3 = boto3.client("s3", region_name="us-east-1")
    s3.create_bucket(Bucket="acme-public")
    s3.put_bucket_acl(Bucket="acme-public", ACL="public-read")
    s3.create_bucket(Bucket="acme-secrets")
    s3.put_bucket_tagging(Bucket="acme-secrets",
                          Tagging={"TagSet": [{"Key": "data-classification", "Value": "confidential"}]})
    s3.create_bucket(Bucket="acme-safe")
    s3.put_bucket_encryption(
        Bucket="acme-safe",
        ServerSideEncryptionConfiguration={"Rules": [
            {"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]})
    iam = boto3.client("iam", region_name="us-east-1")
    iam.create_role(RoleName="wide-open", AssumeRolePolicyDocument=json.dumps(
        {"Version": "2012-10-17", "Statement": [
            {"Effect": "Allow", "Principal": "*", "Action": "sts:AssumeRole"}]}))


def _assert_live_findings(export_json: str):
    inv = json.loads(export_json)
    facts = confirm_cloud_posture_facts(normalize_cloud_export(inv))
    reached = {f["resource"] for f in facts if f["lead_class"] == "public_exposure"}
    assert "acme-public" in reached                       # public bucket confirmed
    assert any("wide-open" in r for r in reached)         # wildcard-trust role confirmed
    # sensitive unencrypted bucket -> achieved-state encryption fact
    from framework.v2.verify.cloud_posture import confirm_cloud_posture
    secret = next((r for r in inv["resources"] if r["id"] == "acme-secrets"), None)
    assert secret is not None and secret.get("encrypted") is False and secret.get("sensitive") is True
    assert confirm_cloud_posture(secret).confirmed


def test_end_to_end_against_moto(monkeypatch):
    """Drive the collector's ACTUAL boto3 run() path against moto's in-process AWS. This exercises real
    boto3 client construction, the env-credential provider (ambient discovery), and every read-only call."""
    pytest.importorskip("boto3")
    mock_aws = getattr(pytest.importorskip("moto"), "mock_aws", None)
    if mock_aws is None:
        pytest.skip("moto too old (no mock_aws)")
    import boto3
    # ambient credential discovery via the ENV provider (moto accepts any); NO endpoint override ->
    # the real-AWS host branch, which moto intercepts at the botocore layer.
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
    """Same assertions against LocalStack (real emulated AWS in Docker) via the endpoint_url override —
    verifies the endpoint-override egress branch and the live path on a host with the rig up."""
    boto3 = pytest.importorskip("boto3")
    endpoint = "http://127.0.0.1:4566"
    for k, v in {"AWS_ACCESS_KEY_ID": "test", "AWS_SECRET_ACCESS_KEY": "test",
                 "AWS_DEFAULT_REGION": "us-east-1", "AWS_REGION": "us-east-1"}.items():
        monkeypatch.setenv(k, v)
    monkeypatch.setenv("CRUCIBLE_AWS_ENDPOINT_URL", endpoint)
    # seed against the same endpoint the collector will read
    orig_client = boto3.client
    monkeypatch.setattr(boto3, "client",
                        lambda svc, **kw: orig_client(svc, endpoint_url=endpoint, **kw))
    _seed_fake_aws(boto3)
    sensor = CloudLiveSensor()                       # reads CRUCIBLE_AWS_ENDPOINT_URL
    assert sensor.egress_hosts == ("127.0.0.1",)
    result = sensor.run({}, SimpleNamespace())
    assert result.ok, result.note
    _assert_live_findings(result.output["export"])
