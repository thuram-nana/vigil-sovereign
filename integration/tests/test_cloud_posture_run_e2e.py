"""Wave B.2 — the FIRST real AWS end-to-end, proven against a moto-backed AWS.

The whole offense-leg chain, over a REAL (moto in-process) AWS account, as pure glue:

    mint a read-only customer session as DATA (the duck shape a vigil_core MintedSession satisfies)
      -> COLLECT the real inventory with the EXISTING ``CloudLiveSensor`` as THAT identity (never VIGIL's
         ambient boto3 chain — ``require_injected_credentials=True``), under ``moto.mock_aws``
      -> ``run_cloud_posture_live`` D5-scope-gates the capture and re-fires the EXISTING deterministic
         ``cloud_posture`` + ``policy_path`` oracles over the RETAINED export, minting a signed FACT per
         confirmed insecure subject
      -> each FACT's certificate re-verifies OFFLINE with the retained capture bytes (and fails closed on a
         1-byte swap / missing bytes)
      -> the report adapter renders each FACT as a PROVEN FACT with its re-runnable certificate reference.

The seeded account carries the TRUE POSITIVES (a public-ACL bucket with account BPA all-off, a wide-open
role) AND the near-zero-FP negative-control TRAPS that must NOT promote (an ``IgnorePublicAcls`` bucket, a
Condition-narrowed org-scoped role). The oracle, not the collector's say-so, decides (criterion 6).

boto3 / moto / framework are import-guarded at module scope; every framework + evidence import is
FUNCTION-LOCAL after the guards (offense-leg). If boto3/moto are absent the whole module skips, so CI stays
green; where they are present the E2E MUST run and pass.
"""
from __future__ import annotations

import json
import os
from types import SimpleNamespace

import pytest

pytest.importorskip("boto3")
_moto = pytest.importorskip("moto")
mock_aws = getattr(_moto, "mock_aws", None)
if mock_aws is None:  # pragma: no cover - old moto without mock_aws
    pytest.skip("moto too old (no mock_aws)", allow_module_level=True)
pytest.importorskip("framework.v2.verify")

# Sovereign (no framework at module scope) — safe to import eagerly.
from vigil_integration.live.cloud_posture_run import (  # noqa: E402
    render_cloud_posture_report,
    run_cloud_posture_live,
)
from vigil_integration.live.cloud_scope import (  # noqa: E402
    CloudScopeEntry,
    CloudScopeGate,
    StaticCloudScopeSource,
)

# The minted session's claimed account — moto's DEFAULT account id, so STS get-caller-identity resolves to
# exactly this and the collector's account-drift guard (cloud_live.py ~:643-653) is satisfied.
ACCOUNT = "123456789012"
REGION = "us-east-1"

# The INJECTED read-only STS credential parts (the shape a vigil_core MintedSession exposes). Deliberately
# DISTINCT from the dummy AMBIENT AWS_* env seeded below, so a dropped-injection regression (a silent
# fall-back to VIGIL's ambient identity) is caught by the spy assertion.
INJECTED_AKID = "ASIATEMPKEY"
AMBIENT_AKID = "AKIAAMBIENTMUSTNOTBEUSED"


class _Creds:
    """A plain, duck-typed minted read-only session (``provider`` / ``access_key_id`` /
    ``secret_access_key`` / ``session_token`` / ``region`` / ``account_id``) — the exact shape a
    ``vigil_core.cloud_session.MintedSession`` satisfies. We model the sovereign-subprocess + spool crossing
    in-process with this fake; the real crossing is deferred to a later wave. Fields are overridable so a
    test can forge a PARTIAL (missing session_token) or non-AWS session."""

    def __init__(
        self,
        *,
        provider: str = "aws",
        account_id: str = ACCOUNT,
        region: str = REGION,
        access_key_id: str = INJECTED_AKID,
        secret_access_key: str = "temp-secret-value",
        session_token: str = "temp-session-token",
    ) -> None:
        self.provider = provider
        self.account_id = account_id
        self.region = region
        self.access_key_id = access_key_id
        self.secret_access_key = secret_access_key
        self.session_token = session_token


def _signers_and_trust():
    """Governance m-of-n signers + the matching TrustRoot (vigil_core — the sovereign crypto surface)."""
    from vigil_core import AuthorizerKey, TrustRoot, generate_keypair

    kp = generate_keypair()
    signers = [("gov0", kp.private_key_b64)]
    tr = TrustRoot(
        threshold=1,
        authorizers=[AuthorizerKey(key_id="gov0", name="gov0", public_key_b64=kp.public_key_b64)],
    )
    return signers, tr


def _gate():
    """An account-only in-scope gate: the charter authorises (aws, 123456789012), any region/resource — so
    every captured subject in the seeded account is authorised and the capture mints over the real export."""
    return CloudScopeGate(
        scope=StaticCloudScopeSource([CloudScopeEntry(provider="aws", account=ACCOUNT)]),
        engagement_slug="acme",
    )


def _set_dummy_ambient_env(monkeypatch):
    """Dummy AMBIENT AWS_* env (DISTINCT from the injected key) + unset any endpoint override, mirroring the
    collector's own moto E2E. The injected run must NEVER reach moto as this ambient identity."""
    for k, v in {
        "AWS_ACCESS_KEY_ID": AMBIENT_AKID,
        "AWS_SECRET_ACCESS_KEY": "ambient-secret-must-not-be-used",
        "AWS_SESSION_TOKEN": "ambient-token-must-not-be-used",
        "AWS_DEFAULT_REGION": REGION,
        "AWS_REGION": REGION,
    }.items():
        monkeypatch.setenv(k, v)
    monkeypatch.delenv("CRUCIBLE_AWS_ENDPOINT_URL", raising=False)
    monkeypatch.delenv("AWS_ENDPOINT_URL", raising=False)


def _seed_fake_aws(boto3):
    """Seed moto's account with the TRUE POSITIVES + the negative-control TRAPS. The COLLECTOR only reads;
    the TEST seeds. Mirrors the collector's own moto seeding (the reuse target)."""
    s3 = boto3.client("s3", region_name=REGION)
    # TRUE POSITIVE: a public-ACL bucket with NO neutralising BPA (account BPA set all-off below).
    s3.create_bucket(Bucket="acme-public")
    s3.put_bucket_acl(Bucket="acme-public", ACL="public-read")
    # TRAP: a public ACL NEUTRALISED by a bucket-level IgnorePublicAcls — must NOT promote.
    s3.create_bucket(Bucket="acme-acl-ignored")
    s3.put_bucket_acl(Bucket="acme-acl-ignored", ACL="public-read")
    s3.put_public_access_block(
        Bucket="acme-acl-ignored",
        PublicAccessBlockConfiguration={
            "BlockPublicAcls": False, "IgnorePublicAcls": True,
            "BlockPublicPolicy": False, "RestrictPublicBuckets": False,
        },
    )
    # Account-level BPA explicitly all-off (the common false-NEGATIVE trap, both neutraliser scopes OFF), so
    # acme-public's public vector is confirmed with BOTH bucket + account scopes read.
    try:
        boto3.client("s3control", region_name=REGION).put_public_access_block(
            AccountId=ACCOUNT,
            PublicAccessBlockConfiguration={
                "BlockPublicAcls": False, "IgnorePublicAcls": False,
                "BlockPublicPolicy": False, "RestrictPublicBuckets": False,
            },
        )
    except Exception:
        pass  # moto reports "absent" (a KNOWN off) even without this
    iam = boto3.client("iam", region_name=REGION)
    # TRUE POSITIVE: a wide-open role — Allow Principal '*' sts:AssumeRole with NO narrowing Condition.
    iam.create_role(
        RoleName="wide-open",
        AssumeRolePolicyDocument=json.dumps(
            {"Version": "2012-10-17",
             "Statement": [{"Effect": "Allow", "Principal": "*", "Action": "sts:AssumeRole"}]}),
    )
    # TRAP: an org-scoped role — the same wildcard trust NARROWED by aws:PrincipalOrgID (the secure org
    # pattern) — must NOT promote.
    iam.create_role(
        RoleName="org-scoped",
        AssumeRolePolicyDocument=json.dumps(
            {"Version": "2012-10-17",
             "Statement": [{"Effect": "Allow", "Principal": "*", "Action": "sts:AssumeRole",
                            "Condition": {"StringEquals": {"aws:PrincipalOrgID": "o-abc123"}}}]}),
    )


def _fact_subjects(result) -> set:
    """The ACTUAL subject id bound into each minted FACT's certificate (never the shared request glob)."""
    out = set()
    for f in result.facts:
        out.add(f.signed.certificate.bound_identity["resource_scope"]["resource"])
    return out


def test_cloud_posture_run_e2e(monkeypatch):
    """Mint -> collect (real sensor, moto) -> oracle re-fire -> signed FACT -> offline verify -> report."""
    import boto3

    from framework.v2.evidence.certify import verify_certificate
    from framework.v2.sensors.cloud import confirm_cloud_posture_facts, normalize_cloud_export
    from framework.v2.sensors.cloud_live import CloudLiveSensor
    from framework.v2.verify.policy_path import build_policy_graph, policy_path_context
    from framework.v2.verify.verifier import OracleVerifier

    _set_dummy_ambient_env(monkeypatch)
    signers, tr = _signers_and_trust()
    creds = _Creds()  # the minted DATA session (claimed account == moto default)

    with mock_aws():
        _seed_fake_aws(boto3)

        # -- STEP 3: COLLECT via the REAL sensor under moto (not a mock), as the injected identity. --
        collect = CloudLiveSensor(credentials=creds, require_injected_credentials=True).run(
            {}, SimpleNamespace())
        assert collect.ok, collect.note
        assert collect.output["format"] == "native"
        # the collector landed in EXACTLY the claimed account (the drift guard was satisfied, not skipped).
        assert collect.output.get("account") == ACCOUNT

        # -- STEP 4: the oracle FIRES over the COLLECTED data (run_cloud_posture_live internally calls
        #    confirm_cloud_posture_facts(normalize_cloud_export(...)) + the per-resource cloud_posture loop). --
        result = run_cloud_posture_live(
            creds, scope_gate=_gate(), engagement_slug="acme", signers=signers,
            capture_time_epoch=1_700_000_000)
        assert result.refused is False and result.n_facts >= 2, result.admissions

        subjects = _fact_subjects(result)
        # TRUE POSITIVES minted:
        assert "acme-public" in subjects, subjects
        assert any("wide-open" in s for s in subjects), subjects
        # NEGATIVE-CONTROL TRAPS held (never promoted):
        assert "acme-acl-ignored" not in subjects, subjects
        assert not any("org-scoped" in s for s in subjects), subjects

        # Prove the oracle ACTUALLY FIRED over the real export — not a mock return. (a) the public-exposure
        # facts the oracle itself re-derived over the collected inventory:
        inv = normalize_cloud_export(json.loads(collect.output["export"]), "native")
        pub_facts = [pf for pf in confirm_cloud_posture_facts(inv)
                     if pf.get("lead_class") == "public_exposure"]
        reached = {pf["resource"] for pf in pub_facts}
        assert "acme-public" in reached and any("wide-open" in r for r in reached), reached
        assert "acme-acl-ignored" not in reached and not any("org-scoped" in r for r in reached), reached
        # (b) inspect a live oracle SIGNAL's .fired over acme-public's grant path (never a stubbed verdict):
        acme = next(pf for pf in pub_facts if pf["resource"] == "acme-public")
        vr = OracleVerifier().confirm(
            policy_path_context(build_policy_graph(inv), acme["principal"], acme["resource"], acme["access"]))
        assert vr.confirmed and any(getattr(s, "fired", False) for s in (vr.signals or []))

    # -- STEP 5: each FACT's certificate RE-VERIFIES OFFLINE (+ negative controls). Pure, no moto. --
    for f in result.facts:
        ctx = result.contexts[f.finding_ref]
        cert = f.signed.certificate
        assert cert.capture_method == "api:list"                # a VIGIL-owned live read, not an artifact
        assert cert.bound_identity["resource_scope"]["provider"] == "aws"
        assert cert.bound_identity["resource_scope"]["account"] == ACCOUNT
        assert cert.bound_identity.get("capture_time_epoch") == 1_700_000_000  # deterministic, operator-set
        # the FACT carries a REAL calibrated oracle confidence (never the banned hard-coded 1.0, never 0) and
        # a named confirming oracle kind — i.e. the oracle fired, the value was not fabricated.
        assert f.is_fact and f.confirmed_by and 0.0 < float(f.confidence) < 1.0
        # correct bytes -> ok
        assert verify_certificate(f.signed, oracle_context=ctx, trust_root=tr,
                                  artifact_bytes=result.artifact_bytes).ok is True
        # 1-byte swap of the retained capture -> fail closed
        mutated = bytearray(result.artifact_bytes)
        mutated[len(mutated) // 2] ^= 0x01
        assert verify_certificate(f.signed, oracle_context=ctx, trust_root=tr,
                                  artifact_bytes=bytes(mutated)).ok is False
        # missing bytes (an artifact-recheck cert never re-checked) -> fail closed
        assert verify_certificate(f.signed, oracle_context=ctx, trust_root=tr).ok is False

    assert result.family_verdict() == "FACT"

    # -- STEP 6: the REPORT shows it — each FACT rendered as a PROVEN FACT with its re-runnable cert ref. --
    md = render_cloud_posture_report(result, target=f"aws:{ACCOUNT}")
    assert "PROVEN FACT" in md
    assert "sha256:" in md
    assert "framework.v2 verify" in md
    assert "oracle-confirmed fact(s)" in md


def test_require_injected_credentials_fails_closed_and_binds_the_injected_identity(monkeypatch):
    """CREDENTIAL ISOLATION (the top invariant), two halves:

      (a) a PARTIAL minted session (a missing STS session_token) makes the REAL sensor fail CLOSED
          (``ToolResult.ok`` False) with a no-identity-substitution / ambient-refusal note — it NEVER falls
          back to VIGIL's ambient boto3 identity; and
      (b) a COMPLETE minted session reaches boto3 as the INJECTED access key — NOT the (distinct) dummy
          ambient one — so a dropped-injection regression is caught.
    """
    import boto3

    from framework.v2.sensors.cloud_live import CloudLiveSensor

    _set_dummy_ambient_env(monkeypatch)

    # (a) partial session: no session_token -> fail-closed, no ambient substitution.
    partial = _Creds(session_token="")
    refused = CloudLiveSensor(credentials=partial, require_injected_credentials=True).run(
        {}, SimpleNamespace())
    assert refused.ok is False
    note = refused.note.lower()
    assert "no identity substitution" in note and "ambient" in note
    assert refused.output.get("missing_prerequisite")  # a typed INCONCLUSIVE marker, never a clean negative

    # (b) complete session: the INJECTED akid (not the ambient one) is what reaches boto3.Session.
    captured: list[dict] = []
    real_session = boto3.Session

    def _spy_session(*a, **k):
        captured.append(dict(k))
        return real_session(*a, **k)

    monkeypatch.setattr(boto3, "Session", _spy_session)
    with mock_aws():
        _seed_fake_aws(boto3)
        ok = CloudLiveSensor(credentials=_Creds(), require_injected_credentials=True).run(
            {}, SimpleNamespace())
    assert ok.ok, ok.note
    built = [k.get("aws_access_key_id") for k in captured if k.get("aws_access_key_id")]
    assert built == [INJECTED_AKID], built                     # the scoped session used the injected key
    assert os.environ["AWS_ACCESS_KEY_ID"] == AMBIENT_AKID     # the ambient key was present...
    assert AMBIENT_AKID not in built                           # ...and was NEVER substituted in
