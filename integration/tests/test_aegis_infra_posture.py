"""AS-26 (OPS-1) — OFFLINE posture test over the AEGIS staging CloudFormation templates.

Two halves, both offline:
  * the REAL templates are posture-clean (lint_paths over infra/aws/aegis-staging/*.cfn.yaml -> []); and
  * each posture rule is provably NOT a no-op — a deliberately-weakened in-memory template fires exactly
    the expected violation. The negatives call the per-rule functions with crafted dicts, so they need no
    YAML and run everywhere; the real-template half skips if PyYAML is unavailable (the constrained
    pytest-only job), while the aegis-infra advisory job installs it and runs the whole file + the analyzer
    CLI + cfn-lint."""
from __future__ import annotations

from pathlib import Path

import pytest

from vigil_integration.aegis_infra_lint import (
    check_cloudfront_edge,
    check_disjoint_eips,
    check_imdsv2,
    check_keyless_relay,
    check_mfa_roots,
    check_no_public_ingress,
    check_paging_and_drift,
    lint_paths,
)

REPO = Path(__file__).resolve().parents[2]
TEMPLATE_DIR = REPO / "infra" / "aws" / "aegis-staging"


def _templates() -> list[str]:
    return sorted(str(p) for p in TEMPLATE_DIR.glob("*.cfn.yaml"))


# ==================================================================================================
# the real templates are posture-clean
# ==================================================================================================
def test_real_templates_are_posture_clean() -> None:
    pytest.importorskip("yaml")
    paths = _templates()
    assert paths, "no AEGIS staging templates found"
    violations = lint_paths(paths)
    assert not violations, "AS-26 posture violations:\n  - " + "\n  - ".join(str(v) for v in violations)


def test_there_are_four_templates() -> None:
    assert len(_templates()) == 4


# ==================================================================================================
# negative controls — each rule bites on a weakened template
# ==================================================================================================
def test_imdsv2_negative() -> None:
    bad = {"Resources": {"LT": {"Type": "AWS::EC2::LaunchTemplate", "Properties": {
        "LaunchTemplateData": {"MetadataOptions": {"HttpTokens": "optional"}}}}}}
    v = check_imdsv2("t", bad)
    assert any(x.rule == "imdsv2" for x in v)
    good = {"Resources": {"LT": {"Type": "AWS::EC2::LaunchTemplate", "Properties": {
        "LaunchTemplateData": {"MetadataOptions": {"HttpTokens": "required"}}}}}}
    assert check_imdsv2("t", good) == []


def test_disjoint_eips_negative_overlap_and_missing() -> None:
    overlap = {"Resources": {
        "E1": {"Type": "AWS::EC2::EIP", "Properties": {"Tags": [
            {"Key": "vigil:eip-set", "Value": "defense"}, {"Key": "vigil:eip-set", "Value": "z4-offense"}]}},
    }}
    # E1 is tagged twice (last wins -> z4-offense); the defense set is then empty -> eip-sets violation.
    assert any(x.rule == "eip-sets" for x in check_disjoint_eips("t", overlap))
    good = {"Resources": {
        "D1": {"Type": "AWS::EC2::EIP", "Properties": {"Tags": [{"Key": "vigil:eip-set", "Value": "defense"}]}},
        "Z1": {"Type": "AWS::EC2::EIP", "Properties": {"Tags": [{"Key": "vigil:eip-set", "Value": "z4-offense"}]}},
    }}
    assert check_disjoint_eips("t", good) == []


_MFA4 = ["kms:PutKeyPolicy", "kms:ScheduleKeyDeletion", "kms:DisableKey", "kms:CreateGrant"]


def _mfa_key(root: str, *, actions: "list[str] | str | None" = None, mfa_value: str = "false",
             op: str = "BoolIfExists") -> dict:
    return {"Type": "AWS::KMS::Key", "Properties": {
        "Tags": [{"Key": "vigil:root", "Value": root}],
        "KeyPolicy": {"Statement": [{"Effect": "Deny", "Action": _MFA4 if actions is None else actions,
                                     "Condition": {op: {"aws:MultiFactorAuthPresent": mfa_value}}}]}}}


def test_mfa_roots_negative() -> None:
    no_mfa = {"Resources": {"K": {"Type": "AWS::KMS::Key", "Properties": {
        "Tags": [{"Key": "vigil:root", "Value": "test-owner"}],
        "KeyPolicy": {"Statement": [{"Effect": "Allow", "Action": "kms:*"}]}}}}}
    assert any(x.rule in ("mfa-root", "mfa-root-missing") for x in check_mfa_roots("t", no_mfa))
    good = {"Resources": {"KO": _mfa_key("test-owner"), "KR": _mfa_key("test-release")}}
    assert check_mfa_roots("t", good) == []


def test_mfa_gate_inverted_is_rejected() -> None:
    """A Deny conditioned on MultiFactorAuthPresent == 'true' denies the MFA'd admin and LETS THROUGH the
    un-MFA'd one — an inverted gate. It must fail the analyzer (finding 2)."""
    inverted = {"Resources": {"KO": _mfa_key("test-owner", mfa_value="true"),
                              "KR": _mfa_key("test-release", mfa_value="true")}}
    assert any(x.rule == "mfa-root" for x in check_mfa_roots("t", inverted))


def test_mfa_gate_action_narrow_is_rejected() -> None:
    """A Deny that names only kms:PutKeyPolicy leaves ScheduleKeyDeletion/DisableKey/CreateGrant reachable
    without MFA — a rubber stamp. It must fail the analyzer (finding 2)."""
    narrow = {"Resources": {"KO": _mfa_key("test-owner", actions=["kms:PutKeyPolicy"]),
                            "KR": _mfa_key("test-release", actions=["kms:PutKeyPolicy"])}}
    assert any(x.rule == "mfa-root" for x in check_mfa_roots("t", narrow))


def test_mfa_gate_wrong_operator_is_rejected() -> None:
    """A condition that is not Bool/BoolIfExists (e.g. StringEquals) is not an MFA-presence gate."""
    wrong = {"Resources": {"KO": _mfa_key("test-owner", op="StringEquals"),
                          "KR": _mfa_key("test-release", op="StringEquals")}}
    assert any(x.rule == "mfa-root" for x in check_mfa_roots("t", wrong))


def test_keyless_relay_negative() -> None:
    leaky = {"Resources": {"R": {"Type": "AWS::IAM::Role", "Properties": {
        "Tags": [{"Key": "vigil:zone", "Value": "z3r-relay"}],
        "Policies": [{"PolicyDocument": {"Statement": [{"Effect": "Allow", "Action": "cloudwatch:PutMetricData"}]}}]}}}}
    assert any(x.rule == "keyless-relay" for x in check_keyless_relay("t", leaky))
    keyless = {"Resources": {"R": {"Type": "AWS::IAM::Role", "Properties": {
        "Tags": [{"Key": "vigil:zone", "Value": "z3r-relay"}],
        "Policies": [{"PolicyDocument": {"Statement": [
            {"Effect": "Deny", "Action": ["kms:Decrypt", "secretsmanager:GetSecretValue"]}]}}]}}}}
    assert check_keyless_relay("t", keyless) == []


def test_public_ingress_negative() -> None:
    public = {"Resources": {"SG": {"Type": "AWS::EC2::SecurityGroup", "Properties": {
        "SecurityGroupIngress": [{"CidrIp": "0.0.0.0/0", "FromPort": 443}]}}}}
    assert any(x.rule == "public-ingress" for x in check_no_public_ingress("t", public))
    internal = {"Resources": {"SG": {"Type": "AWS::EC2::SecurityGroup", "Properties": {
        "SecurityGroupIngress": [{"CidrIp": "10.80.0.0/16", "FromPort": 80}]}}}}
    assert check_no_public_ingress("t", internal) == []


def test_public_ingress_coverage_not_string_equality() -> None:
    """Coverage, not string-equality (finding 4): 0.0.0.0/1 (and /8) are over-broad even though they are not
    the literal string '0.0.0.0/0'; a standalone AWS::EC2::SecurityGroupIngress is read too; a prefix-list /
    SG-source rule carries no CIDR and is not flagged."""
    wide = {"Resources": {"SG": {"Type": "AWS::EC2::SecurityGroup", "Properties": {
        "SecurityGroupIngress": [{"CidrIp": "0.0.0.0/1", "FromPort": 443}]}}}}
    assert any(x.rule == "public-ingress" for x in check_no_public_ingress("t", wide))
    standalone = {"Resources": {"I": {"Type": "AWS::EC2::SecurityGroupIngress",
                                      "Properties": {"CidrIp": "10.0.0.0/8", "FromPort": 80}}}}
    assert any(x.rule == "public-ingress" for x in check_no_public_ingress("t", standalone))
    prefix_list = {"Resources": {"SG": {"Type": "AWS::EC2::SecurityGroup", "Properties": {
        "SecurityGroupIngress": [{"SourcePrefixListId": "pl-123", "FromPort": 80},
                                 {"SourceSecurityGroupId": "sg-abc", "FromPort": 80}]}}}}
    assert check_no_public_ingress("t", prefix_list) == []
    intrinsic = {"Resources": {"SG": {"Type": "AWS::EC2::SecurityGroup", "Properties": {
        "SecurityGroupIngress": [{"CidrIp": {"Ref": "VpcCidr"}, "FromPort": 80}]}}}}
    assert check_no_public_ingress("t", intrinsic) == []


def _cf_dist(origins: list, target: str = "o") -> dict:
    return {"Resources": {"D": {"Type": "AWS::CloudFront::Distribution", "Properties": {
        "DistributionConfig": {"DefaultCacheBehavior": {"TargetOriginId": target}, "Origins": origins}}}}}


def _vpc_origin(oid: str = "o") -> dict:
    return {"Id": oid, "VpcOriginConfig": {"VpcOriginId": "v"},
            "OriginCustomHeaders": [{"HeaderName": "X-Vigil-Edge-Secret",
                                     "HeaderValue": {"Fn::Sub": "{{resolve:secretsmanager:S:SecretString:k}}"}}]}


def test_cloudfront_edge_negative() -> None:
    bare = _cf_dist([{"Id": "o", "DomainName": "x"}])
    rules = {x.rule for x in check_cloudfront_edge("t", bare)}
    assert {"cf-vpc-origin", "cf-edge-secret"} <= rules
    assert check_cloudfront_edge("t", _cf_dist([_vpc_origin()])) == []


def test_cloudfront_secret_on_non_served_origin_is_rejected() -> None:
    """A secret injected on a DIFFERENT origin than the one DefaultCacheBehavior serves does not protect the
    request that reaches the ALB (finding 5). The served origin 'o' has no secret -> cf-edge-secret."""
    served_plain = {"Id": "o", "VpcOriginConfig": {"VpcOriginId": "v"}}
    other_with_secret = _vpc_origin("other")
    v = check_cloudfront_edge("t", _cf_dist([served_plain, other_with_secret], target="o"))
    assert any(x.rule == "cf-edge-secret" for x in v)


def test_cloudfront_plain_string_secret_is_rejected() -> None:
    """A plain-literal HeaderValue (a secret hard-coded in the template) is not a secretsmanager dynamic
    reference and must be rejected (finding 5)."""
    plain = {"Id": "o", "VpcOriginConfig": {"VpcOriginId": "v"},
             "OriginCustomHeaders": [{"HeaderName": "X-Vigil-Edge-Secret", "HeaderValue": "literal-secret"}]}
    v = check_cloudfront_edge("t", _cf_dist([plain]))
    assert any(x.rule == "cf-edge-secret-plain" for x in v)


def test_cloudfront_target_matches_no_origin_is_rejected() -> None:
    v = check_cloudfront_edge("t", _cf_dist([_vpc_origin("real")], target="ghost"))
    assert any(x.rule == "cf-served-origin" for x in v)


def test_paging_and_drift_negative() -> None:
    empty: dict = {"Resources": {}}
    rules = {x.rule for x in check_paging_and_drift("t", empty)}
    assert {"paging", "drift"} <= rules
    good = {"Resources": {
        "T": {"Type": "AWS::SNS::Topic", "Properties": {}},
        "C": {"Type": "AWS::Config::ConfigRule", "Properties": {
            "Source": {"SourceIdentifier": "CLOUDFORMATION_STACK_DRIFT_DETECTION_CHECK"}}},
    }}
    assert check_paging_and_drift("t", good) == []


def test_unparseable_template_is_a_violation(tmp_path: Path) -> None:
    pytest.importorskip("yaml")
    from vigil_integration.aegis_infra_lint import lint_template
    bad = tmp_path / "broken.cfn.yaml"
    bad.write_text("Resources: [this is not a mapping\n", encoding="utf-8")
    v = lint_template(bad)
    assert v and v[0].rule in ("unparseable", "no-resources")
