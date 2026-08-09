"""WAVE #4 A3 — the IaC posture VIGIL-direct FACT capability (CLOUD_POSTURE + POLICY_PATH oracle families).

VIGIL parses the target's OWN Infrastructure-as-Code artifact — a Terraform plan-JSON / tfstate, or a
processed CloudFormation template — for the CONCRETE, RESOLVED achieved state it declares, and the
deterministic cloud_posture + policy_path oracles re-derive the insecure state / anon grant path. A FACT is a
bounded claim about the REPRESENTED artifact, never live infra and never a scanner's say-so.

The hard half (BLOCKER-3, near-zero-FP): an attribute is the oracle's achieved-state ONLY when unambiguous.
block_public_access=false -> public UNKNOWN (never True); a missing SSE block -> encrypted UNKNOWN (never
False); a CloudFormation intrinsic principal -> the grant is dropped; sensitivity comes ONLY from an explicit
tag, never a name.

The pure-parser tests run in the SOVEREIGN venv (no framework). The mint/reverify tests importorskip
framework and run in the framework-inclusive venv.
"""
from __future__ import annotations

import json

import pytest

from vigil_integration.live.iac_posture import (
    IacParseError,
    _is_literal_wildcard_principal,
    parse_cloudformation,
    parse_terraform,
)

# ==================================================================================================
# fixtures
# ==================================================================================================
_WILDCARD_POLICY = json.dumps({
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject",
                   "Resource": "arn:aws:s3:::acme-public-bucket/*"}],
})
_SCOPED_POLICY = json.dumps({
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::123456789012:role/app"},
                   "Action": "s3:GetObject"}],
})

# A tfstate with (1) an unencrypted + sensitive datastore AND (2) an S3 bucket policy Principal:"*".
TFSTATE_INSECURE = json.dumps({
    "version": 4, "terraform_version": "1.6.0",
    "resources": [
        {"mode": "managed", "type": "aws_db_instance", "name": "secrets",
         "instances": [{"attributes": {"id": "acme-secrets-db", "storage_encrypted": False,
                                       "tags": {"Name": "acme-secrets", "sensitive": "true"}}}]},
        {"mode": "managed", "type": "aws_s3_bucket_policy", "name": "public",
         "instances": [{"attributes": {"id": "acme-public-bucket", "bucket": "acme-public-bucket",
                                       "policy": _WILDCARD_POLICY}}]},
    ],
})

# A hardened tfstate: encryption on, a scoped (non-wildcard) principal, not public.
TFSTATE_HARDENED = json.dumps({
    "version": 4, "terraform_version": "1.6.0",
    "resources": [
        {"mode": "managed", "type": "aws_db_instance", "name": "safe",
         "instances": [{"attributes": {"id": "safe-db", "storage_encrypted": True,
                                       "tags": {"sensitive": "true"}}}]},
        {"mode": "managed", "type": "aws_s3_bucket_policy", "name": "priv",
         "instances": [{"attributes": {"id": "priv-bucket", "policy": _SCOPED_POLICY}}]},
    ],
})

# BLOCKER-3: a public-access-block toggle set false is NOT an achieved public grant -> public UNKNOWN.
TFSTATE_BPA_FALSE = json.dumps({
    "version": 4, "terraform_version": "1.6.0",
    "resources": [
        {"mode": "managed", "type": "aws_s3_bucket_public_access_block", "name": "bpa",
         "instances": [{"attributes": {"id": "data-bucket-bpa", "bucket": "data-bucket",
                                       "block_public_acls": False, "block_public_policy": False,
                                       "ignore_public_acls": False, "restrict_public_buckets": False}}]},
    ],
})

# Deceptive naming: a resource NAMED "public" / "secrets" but with a benign achieved state. Sensitivity and
# public-ness are NEVER inferred from a name, so nothing fires (near-zero-FP against name-based scanner FPs).
TFSTATE_DECEPTIVE_NAME = json.dumps({
    "version": 4, "terraform_version": "1.6.0",
    "resources": [
        {"mode": "managed", "type": "aws_db_instance", "name": "public_secrets_store",
         "instances": [{"attributes": {"id": "public-secrets-store", "storage_encrypted": True}}]},
    ],
})

TFSTATE_EMPTY = json.dumps({"version": 4, "terraform_version": "1.6.0", "resources": []})

# CloudFormation YAML with a LITERAL public resource (proves CFN feeds the SAME oracle).
CFN_YAML_PUBLIC = """
Resources:
  PublicBucketPolicy:
    Type: AWS::S3::BucketPolicy
    Properties:
      Bucket: acme-assets
      PolicyDocument:
        Version: "2012-10-17"
        Statement:
          - Effect: Allow
            Principal: "*"
            Action: s3:GetObject
            Resource: arn:aws:s3:::acme-assets/*
"""

# CloudFormation with an UNRESOLVED intrinsic principal (long-form Ref) -> UNKNOWN, not a wildcard.
CFN_YAML_INTRINSIC = """
Parameters:
  TrustedPrincipal:
    Type: String
Resources:
  MaybePolicy:
    Type: AWS::S3::BucketPolicy
    Properties:
      Bucket: gated
      PolicyDocument:
        Statement:
          - Effect: Allow
            Principal:
              Ref: TrustedPrincipal
            Action: s3:GetObject
"""

CFN_EMPTY = json.dumps({"AWSTemplateFormatVersion": "2010-09-09", "Resources": {}})


# ==================================================================================================
# PURE PARSER tests — sovereign-safe (no framework import)
# ==================================================================================================
def test_is_literal_wildcard_principal_literal_vs_intrinsic():
    assert _is_literal_wildcard_principal("*") is True
    assert _is_literal_wildcard_principal({"AWS": "*"}) is True
    assert _is_literal_wildcard_principal({"AWS": ["*", "arn:aws:iam::1:role/x"]}) is True
    # a specific principal is NOT a wildcard
    assert _is_literal_wildcard_principal("arn:aws:iam::1:role/x") is False
    assert _is_literal_wildcard_principal({"AWS": "arn:aws:iam::1:role/x"}) is False
    # an intrinsic / unresolved reference is NEVER a literal wildcard (BLOCKER-3)
    assert _is_literal_wildcard_principal({"Ref": "P"}) is False
    assert _is_literal_wildcard_principal({"AWS": {"Ref": "P"}}) is False
    assert _is_literal_wildcard_principal({"Fn::GetAtt": ["R", "Arn"]}) is False
    assert _is_literal_wildcard_principal({"Fn::If": ["c", "*", "y"]}) is False


def test_parse_terraform_tfstate_extracts_unambiguous_flags():
    inv = parse_terraform(TFSTATE_INSECURE)
    by_id = {r["id"]: r for r in inv["resources"]}
    db = by_id["aws_db_instance.secrets"]
    assert db.get("encrypted") is False and db.get("sensitive") is True   # explicit disable + explicit tag
    bucket = by_id["aws_s3_bucket_policy.public"]
    assert bucket.get("grants") == [{"principal": "*", "access": "s3:GetObject"}]   # literal wildcard grant


def test_parse_terraform_block_public_access_false_is_unknown_not_public():
    """THE KEY BLOCKER-3 CASE. A block_public_access=false toggle is not an achieved public grant."""
    inv = parse_terraform(TFSTATE_BPA_FALSE)
    r = inv["resources"][0]
    assert "public" not in r, f"block_public_access=false must NOT set public=True: {r}"
    assert "encrypted" not in r and "sensitive" not in r and "grants" not in r


def test_parse_terraform_hardened_has_no_insecure_flags():
    inv = parse_terraform(TFSTATE_HARDENED)
    by_id = {r["id"]: r for r in inv["resources"]}
    assert by_id["aws_db_instance.safe"].get("encrypted") is True
    assert "grants" not in by_id["aws_s3_bucket_policy.priv"]     # scoped principal -> no wildcard grant


def test_parse_terraform_never_infers_sensitivity_from_name():
    inv = parse_terraform(TFSTATE_DECEPTIVE_NAME)
    r = inv["resources"][0]
    assert "sensitive" not in r and "public" not in r    # name says 'public_secrets' — ignored


def test_parse_terraform_plan_json_prefers_state_values():
    plan = json.dumps({
        "format_version": "1.0", "terraform_version": "1.6.0",
        "values": {"root_module": {"resources": [
            {"address": "aws_db_instance.d", "type": "aws_db_instance", "name": "d",
             "values": {"storage_encrypted": False, "tags": {"sensitive": "true"}}}]}},
    })
    inv = parse_terraform(plan)
    assert inv["resources"][0]["id"] == "aws_db_instance.d"
    assert inv["resources"][0]["encrypted"] is False


def test_parse_cloudformation_literal_wildcard_grant():
    inv = parse_cloudformation(CFN_YAML_PUBLIC)
    r = inv["resources"][0]
    assert r["id"] == "PublicBucketPolicy"
    assert {"principal": "*", "access": "s3:GetObject"} in r.get("grants", [])


def test_parse_cloudformation_intrinsic_principal_is_not_a_wildcard():
    """BLOCKER-3 for CFN: an unresolved Ref principal contributes NO grant."""
    inv = parse_cloudformation(CFN_YAML_INTRINSIC)
    r = inv["resources"][0]
    assert "grants" not in r, f"an intrinsic principal must not become a wildcard grant: {r}"


def test_parse_terraform_malformed_raises_typed_error():
    with pytest.raises(IacParseError) as ei:
        parse_terraform('{"version":4, "resources": [')   # truncated JSON
    assert ei.value.reason == "malformed"


def test_parse_terraform_raw_hcl_is_a_typed_error_not_a_guess():
    # raw HCL is not JSON; safe_json refuses it (no achieved state to read) — never a silent parse.
    with pytest.raises(IacParseError):
        parse_terraform('resource "aws_s3_bucket" "b" { bucket = "x" }')


def test_parse_cloudformation_yaml_merge_bomb_is_refused():
    """safe_parse refuses a YAML '<<' merge key — a nested-merge bomb is a typed error, never a hang."""
    bomb = "Resources: &a\n  <<: *a\n"
    with pytest.raises(IacParseError):
        parse_cloudformation(bomb)


def test_parse_cloudformation_oversize_is_a_typed_error():
    from vigil_integration.live.iac_posture import _ARTIFACT_BUDGET
    huge = "{" + " " * (_ARTIFACT_BUDGET.max_bytes + 10) + "}"
    with pytest.raises(IacParseError) as ei:
        parse_cloudformation(huge)
    assert ei.value.reason == "oversize"


# ==================================================================================================
# MINT + OFFLINE RE-VERIFY tests — framework-inclusive
# ==================================================================================================
def _signers_and_trust():
    """One keypair -> the governance signer + a matching single-authorizer trust root (verify offline)."""
    from vigil_core import AuthorizerKey, TrustRoot, generate_keypair
    kp = generate_keypair()
    signers = [("gov0", kp.private_key_b64)]
    tr = TrustRoot(threshold=1, authorizers=[
        AuthorizerKey(key_id="gov0", name="gov0", public_key_b64=kp.public_key_b64)])
    return signers, tr


def test_tfstate_mints_cloud_posture_and_policy_path_facts_that_reverify():
    pytest.importorskip("framework.v2.verify", reason="CRUCIBLE not importable here")
    from framework.v2.evidence.certify import verify_certificate

    from vigil_integration.live.iac_posture import iac_verify

    signers, tr = _signers_and_trust()
    res = iac_verify(TFSTATE_INSECURE, fmt="terraform", engagement_slug="acme", signers=signers)

    branches = {a[0] for a in res.admissions}
    assert "iac.cloud_posture.achieved_state" in branches
    assert "iac.policy_path.iam_grant_path" in branches
    # a CLOUD_POSTURE fact (the unencrypted+sensitive db) AND a POLICY_PATH fact (the anon grant path)
    cloud_facts = [f for f in res.facts if f.bug_class == "cloud_misconfiguration"]
    policy_facts = [f for f in res.facts if f.bug_class == "privilege_path"]
    assert cloud_facts, f"expected a CLOUD_POSTURE fact; leads={res.leads}"
    assert policy_facts, f"expected a POLICY_PATH fact; admissions={res.admissions}"

    # every fact re-verifies offline end-to-end (authentic + bound + reproduced) from its retained context
    for f in res.facts:
        ctx = res.contexts[f.finding_ref]
        assert verify_certificate(f.signed, oracle_context=ctx, trust_root=tr).ok is True
        # the artifact identity is bound into the signed certificate (D2)
        d2 = f.signed.certificate.bound_identity
        assert d2.get("capture_method") == "artifact:terraform"
        assert d2.get("completeness") == "partial"
    assert res.family_verdict() == "FACT"


def test_cloudformation_yaml_public_resource_mints_a_fact():
    """Proves a processed CloudFormation template feeds the SAME oracle as Terraform."""
    pytest.importorskip("framework.v2.verify", reason="CRUCIBLE not importable here")
    pytest.importorskip("yaml")
    from framework.v2.evidence.certify import verify_certificate

    from vigil_integration.live.iac_posture import iac_verify

    signers, tr = _signers_and_trust()
    res = iac_verify(CFN_YAML_PUBLIC, fmt="cloudformation", engagement_slug="acme", signers=signers)
    assert res.n_facts >= 1, f"expected a FACT from the public CFN resource; admissions={res.admissions}"
    for f in res.facts:
        ctx = res.contexts[f.finding_ref]
        assert verify_certificate(f.signed, oracle_context=ctx, trust_root=tr).ok is True
        d2 = f.signed.certificate.bound_identity
        assert d2.get("capture_method") == "artifact:cloudformation"


def test_hardened_tfstate_does_not_fire():
    pytest.importorskip("framework.v2.verify", reason="CRUCIBLE not importable here")
    from vigil_integration.live.iac_posture import iac_verify

    signers, _ = _signers_and_trust()
    res = iac_verify(TFSTATE_HARDENED, fmt="terraform", engagement_slug="acme", signers=signers)
    assert res.n_facts == 0, f"a hardened artifact must mint no FACT: {[f.finding_ref for f in res.facts]}"
    assert all(r.outcome != "clean" for r in (res.facts + res.leads + res.inconclusive))
    assert res.family_verdict() != "CLEAN"     # not clean_capable -> INCONCLUSIVE, never CLEAN


def test_block_public_access_false_mints_no_fact_the_key_blocker3_test():
    pytest.importorskip("framework.v2.verify", reason="CRUCIBLE not importable here")
    from vigil_integration.live.iac_posture import iac_verify

    signers, _ = _signers_and_trust()
    res = iac_verify(TFSTATE_BPA_FALSE, fmt="terraform", engagement_slug="acme", signers=signers)
    assert res.n_facts == 0, "block_public_access=false is not an achieved public grant — must not fire"
    assert all(r.outcome != "clean" for r in (res.facts + res.leads + res.inconclusive))


def test_cloudformation_intrinsic_principal_mints_no_fact():
    pytest.importorskip("framework.v2.verify", reason="CRUCIBLE not importable here")
    pytest.importorskip("yaml")
    from vigil_integration.live.iac_posture import iac_verify

    signers, _ = _signers_and_trust()
    res = iac_verify(CFN_YAML_INTRINSIC, fmt="cloudformation", engagement_slug="acme", signers=signers)
    assert res.n_facts == 0, "an unresolved intrinsic principal must not mint a wildcard FACT"


def test_deceptive_scanner_naming_yields_no_fact():
    """A resource a naive scanner would flag on its NAME ('public_secrets_store') but whose parsed achieved
    state is benign yields NO FACT — VIGIL's own artifact re-derivation is the sole authority, so a
    name/tool-driven claim the parse does not support stays a non-fire (LEAD/INCONCLUSIVE), never a FACT."""
    pytest.importorskip("framework.v2.verify", reason="CRUCIBLE not importable here")
    from vigil_integration.live.iac_posture import iac_verify

    signers, _ = _signers_and_trust()
    res = iac_verify(TFSTATE_DECEPTIVE_NAME, fmt="terraform", engagement_slug="acme", signers=signers)
    assert res.n_facts == 0
    assert all(r.outcome != "clean" for r in (res.facts + res.leads + res.inconclusive))


def test_no_config_is_inconclusive_never_clean():
    pytest.importorskip("framework.v2.verify", reason="CRUCIBLE not importable here")
    from vigil_integration.live.iac_posture import iac_verify

    signers, _ = _signers_and_trust()
    for text, fmt in ((TFSTATE_EMPTY, "terraform"), (CFN_EMPTY, "cloudformation")):
        res = iac_verify(text, fmt=fmt, engagement_slug="acme", signers=signers)
        assert res.n_facts == 0 and res.admissions == []
        assert res.family_verdict() == "INCONCLUSIVE"   # nothing examined != CLEAN
        assert not any(getattr(r, "outcome", "") == "clean" for r in
                       (res.facts + res.leads + res.inconclusive))


def test_iac_uses_the_admission_path(monkeypatch):
    """The admission path IS used: iac_verify reaches a certificate ONLY through
    ``oracle_adapter.certify_admitted`` with an :class:`AdmittedVerdict` from ``verdict.admit`` — never by
    calling ``confirm_and_certify`` directly."""
    pytest.importorskip("framework.v2.verify", reason="CRUCIBLE not importable here")
    import vigil_integration.oracle_adapter as oa
    from vigil_integration.live.iac_posture import iac_verify
    from vigil_integration.live.verdict import AdmittedVerdict

    real = oa.certify_admitted
    branches: list = []

    def _spy(finding, admitted, **kw):
        assert isinstance(admitted, AdmittedVerdict), "iac reached minting WITHOUT an admitted verdict"
        assert admitted.branch in ("iac.cloud_posture.achieved_state", "iac.policy_path.iam_grant_path")
        assert kw.get("provenance") == "reproduced"
        assert (kw.get("binding") or {}).get("artifact_sha256")
        branches.append(admitted.branch)
        return real(finding, admitted, **kw)

    monkeypatch.setattr(oa, "certify_admitted", _spy)
    signers, _ = _signers_and_trust()
    iac_verify(TFSTATE_INSECURE, fmt="terraform", engagement_slug="acme", signers=signers)
    assert "iac.cloud_posture.achieved_state" in branches
    assert "iac.policy_path.iam_grant_path" in branches


def test_iac_malformed_artifact_raises_before_any_mint():
    pytest.importorskip("framework.v2.verify", reason="CRUCIBLE not importable here")
    from vigil_integration.live.iac_posture import iac_verify

    signers, _ = _signers_and_trust()
    with pytest.raises(IacParseError):
        iac_verify('{"resources": [', fmt="terraform", engagement_slug="acme", signers=signers)


def test_terraform_plan_desired_state_never_mints_an_achieved_fact():
    """RED-PEN A3-HIGH: `terraform show -json <planfile>` carries `planned_values` (DESIRED state) and no
    `values`. A plan's desired state is not the deployed reality (BLOCKER-3), so it must NOT mint an
    achieved-state CLOUD_POSTURE FACT. Only APPLIED state (`values` / a plan file's `prior_state.values`) is
    read."""
    import json
    from vigil_integration.live.iac_posture import iac_verify
    signers, tr = _signers_and_trust()
    pub_res = {"address": "aws_s3_bucket.b", "type": "aws_s3_bucket", "name": "b",
               "values": {"acl": "public-read"}}
    plan_only = json.dumps({"terraform_version": "1.5",
                            "planned_values": {"root_module": {"resources": [pub_res]}}})
    assert iac_verify(plan_only, fmt="terraform", engagement_slug="acme", signers=signers).n_facts == 0, \
        "a plan's planned_values (desired) minted an achieved-state FACT"
    applied = json.dumps({"terraform_version": "1.5", "values": {"root_module": {"resources": [pub_res]}}})
    assert iac_verify(applied, fmt="terraform", engagement_slug="acme", signers=signers).n_facts >= 1, \
        "applied `values` state must still FACT"
    prior = json.dumps({"terraform_version": "1.5",
                        "prior_state": {"values": {"root_module": {"resources": [pub_res]}}},
                        "planned_values": {"root_module": {"resources": []}}})
    assert iac_verify(prior, fmt="terraform", engagement_slug="acme", signers=signers).n_facts >= 1, \
        "a plan file's prior_state (applied) must FACT"
