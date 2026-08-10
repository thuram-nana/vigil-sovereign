"""WAVE #4 Track B — VIGIL-owned LIVE cloud-capture posture FACT capability (cloud_live_posture).

VIGIL's own read-only collector captures the target's real inventory (the SAME native shape the offline
importers produce); the D5 cloud-native scope gate authorises the (provider, account[, region][, resource])
against the signed charter BEFORE any adjudication; and the deterministic cloud_posture + policy_path oracles
re-derive the insecure achieved state / anon grant path over the RETAINED, SCOPED capture — a FACT bounded to
the captured live state, never the whole cloud, never CLEAN (a partial capture cannot prove absence).

Acceptance: an in-scope capture mints signed FACTs that re-verify offline (with the capture bytes + a 1-byte
mutation / missing-bytes fail); an OUT-OF-SCOPE / wildcard / kill-switched request is REFUSED (nothing
adjudicated); a hardened capture -> INCONCLUSIVE never CLEAN. LIVE-FIRE (the real collector) needs
operator-provisioned read-only creds; these fixtures are the offline, credential-free half.

Mint/reverify tests importorskip framework and run in the offense leg; the FATAL-2 + scope-gate-refusal parts
are sovereign-safe.
"""
from __future__ import annotations

import json

import pytest

from vigil_integration.live.cloud_live_posture import CloudLivePostureResult, cloud_live_verify
from vigil_integration.live.cloud_scope import CloudScopeEntry, CloudScopeGate, StaticCloudScopeSource


def _signers_and_trust():
    from vigil_core import AuthorizerKey, TrustRoot, generate_keypair
    kp = generate_keypair()
    signers = [("gov0", kp.private_key_b64)]
    tr = TrustRoot(threshold=1, authorizers=[
        AuthorizerKey(key_id="gov0", name="gov0", public_key_b64=kp.public_key_b64)])
    return signers, tr


def _gate(entries):
    return CloudScopeGate(scope=StaticCloudScopeSource(entries), engagement_slug="acme")


_IN_SCOPE = [CloudScopeEntry(provider="aws", account="111122223333")]

# A VIGIL-owned NATIVE inventory capture (the shape sensors.cloud_live emits): a public bucket-policy grant
# AND an unencrypted sensitive datastore. (grants/encrypted/sensitive are ALREADY extracted by the collector.)
_INSECURE_CAPTURE = {"format": "native", "export": {"resources": [
    {"id": "aws_s3_bucket_policy.public", "kind": "datastore",
     "grants": [{"principal": "*", "access": "s3:GetObject"}]},
    {"id": "aws_db_instance.sec", "kind": "datastore", "encrypted": False, "sensitive": True}]}}

# A hardened capture: nothing unambiguously insecure.
_HARDENED_CAPTURE = {"format": "native", "export": {"resources": [
    {"id": "aws_s3_bucket.priv", "kind": "datastore"}]}}

# A capture that OVER-RETURNS relative to a resource-constrained charter: one in-glob insecure bucket
# (arn:aws:s3:::acme-*) AND one OUT-OF-GLOB insecure bucket. A correct gate mints a FACT ONLY about the
# in-glob subject and REFUSES the out-of-glob one (the red-pen BLOCK-1 reproduction, now defended).
_OVERRETURN_CAPTURE = {"format": "native", "export": {"resources": [
    {"id": "arn:aws:s3:::acme-public", "kind": "datastore",
     "grants": [{"principal": "*", "access": "s3:GetObject"}]},
    {"id": "arn:aws:s3:::victim-prod-secrets", "kind": "datastore",
     "grants": [{"principal": "*", "access": "s3:GetObject"}]}]}}

# A capture whose ONLY resource differs from an in-scope glob by CASE alone (uppercase 'ACME'). The D5 gate
# matches resource ids CASE-SENSITIVELY, so this resource is OUT of scope. A correct gate must skip it in BOTH
# the cloud_posture AND policy_path branches — the policy_path branch must NOT launder the lowercased id
# 'arn:aws:s3:::acme-evil' into an in-scope match (the red-pen fix-of-the-fix over-scope + false-subject leak).
_CASE_MISMATCH_CAPTURE = {"format": "native", "export": {"resources": [
    {"id": "arn:aws:s3:::ACME-evil", "kind": "datastore",
     "grants": [{"principal": "*", "access": "s3:GetObject"}]}]}}


# ---- scope-gate refusals (sovereign-safe: no framework, no mint) ----------------------------------

def test_out_of_scope_account_is_refused_no_adjudication():
    # The gate's kill-switch pre-flight imports CRUCIBLE function-locally and FAILS CLOSED when it is absent
    # (the sovereign leg), so this test — which asserts the SCOPE refusal reason specifically — needs framework.
    pytest.importorskip("framework.v2.authority", reason="scope-gate kill-switch check needs CRUCIBLE")
    signers, _ = _signers_and_trust()
    r = cloud_live_verify(_INSECURE_CAPTURE, provider="aws", account="999999999999",
                          scope_gate=_gate(_IN_SCOPE), engagement_slug="acme", signers=signers)
    assert r.refused is True and r.n_facts == 0 and not r.contexts
    assert "not in the signed" in r.refusal_reason or "scope" in r.refusal_reason.lower()


def test_wildcard_request_is_refused():
    pytest.importorskip("framework.v2.authority", reason="scope-gate kill-switch check needs CRUCIBLE")
    signers, _ = _signers_and_trust()
    for prov, acct in (("*", "111122223333"), ("aws", "*"), ("", "111122223333"), ("aws", "")):
        r = cloud_live_verify(_INSECURE_CAPTURE, provider=prov, account=acct,
                              scope_gate=_gate(_IN_SCOPE), engagement_slug="acme", signers=signers)
        assert r.refused is True and r.n_facts == 0


def test_empty_charter_scope_fails_closed():
    pytest.importorskip("framework.v2.authority", reason="scope-gate kill-switch check needs CRUCIBLE")
    signers, _ = _signers_and_trust()
    r = cloud_live_verify(_INSECURE_CAPTURE, provider="aws", account="111122223333",
                          scope_gate=_gate([]), engagement_slug="acme", signers=signers)
    assert r.refused is True and r.n_facts == 0


def test_region_and_resource_globs_are_enforced():
    # asserts the gate's ALLOW path (in-region) — needs the kill-switch pre-flight to succeed (CRUCIBLE present).
    pytest.importorskip("framework.v2.authority", reason="scope-gate kill-switch check needs CRUCIBLE")
    signers, _ = _signers_and_trust()
    g = _gate([CloudScopeEntry(provider="aws", account="111122223333", region="us-east-1",
                               resource="arn:aws:s3:::acme-*")])
    # in-region + matching REQUEST resource -> the capture action is authorised (facts may mint)
    ok = cloud_live_verify(_INSECURE_CAPTURE, provider="aws", account="111122223333", region="us-east-1",
                           resource="arn:aws:s3:::acme-public", scope_gate=g, engagement_slug="acme",
                           signers=signers)
    assert ok.refused is False
    # wrong region -> refused
    bad = cloud_live_verify(_INSECURE_CAPTURE, provider="aws", account="111122223333", region="eu-west-1",
                            resource="arn:aws:s3:::acme-public", scope_gate=g, engagement_slug="acme",
                            signers=signers)
    assert bad.refused is True


def test_out_of_glob_captured_resources_are_not_minted():
    """BLOCK-1 negative control: an authorised capture whose returned resources fall OUTSIDE the charter's
    resource glob must mint NOTHING about them. On the pre-fix code this minted 3 FACTs about the out-of-glob
    resources (each falsely bound to the request glob); this asserts the leak is closed."""
    pytest.importorskip("framework.v2.verify", reason="CRUCIBLE not importable here")
    signers, _ = _signers_and_trust()
    g = _gate([CloudScopeEntry(provider="aws", account="111122223333", resource="arn:aws:s3:::acme-*")])
    # _INSECURE_CAPTURE's subjects (aws_s3_bucket_policy.public / aws_db_instance.sec) do NOT match acme-*.
    r = cloud_live_verify(_INSECURE_CAPTURE, provider="aws", account="111122223333",
                          resource="arn:aws:s3:::acme-public", scope_gate=g, engagement_slug="acme",
                          signers=signers)
    assert r.refused is False                          # the capture request itself was in scope
    assert r.n_facts == 0                              # ...but NOTHING out-of-glob was minted
    assert r.skipped_out_of_scope >= 1                 # the over-returned subjects were refused, not minted


def test_over_returning_capture_mints_only_in_glob_subject_with_true_binding():
    """BLOCK-1 positive+negative control: a capture that returns BOTH an in-glob and an out-of-glob insecure
    bucket mints a FACT ONLY about the in-glob subject, and every FACT's resource_scope names its ACTUAL
    subject (never the shared request glob, never the out-of-glob resource)."""
    pytest.importorskip("framework.v2.verify", reason="CRUCIBLE not importable here")
    signers, _ = _signers_and_trust()
    g = _gate([CloudScopeEntry(provider="aws", account="111122223333", resource="arn:aws:s3:::acme-*")])
    r = cloud_live_verify(_OVERRETURN_CAPTURE, provider="aws", account="111122223333",
                          resource="arn:aws:s3:::acme-public", scope_gate=g, engagement_slug="acme",
                          signers=signers)
    assert r.refused is False
    assert r.n_facts >= 1                              # the in-glob public bucket DID mint
    assert r.skipped_out_of_scope >= 1                 # the out-of-glob bucket was refused
    for f in r.facts:
        subj = f.signed.certificate.bound_identity["resource_scope"]["resource"]
        assert subj == "arn:aws:s3:::acme-public"      # every FACT's bound subject is the in-glob resource
        assert subj != "arn:aws:s3:::victim-prod-secrets"


def test_case_only_out_of_glob_resource_is_skipped_in_both_branches():
    """Red-pen fix-of-the-fix: a captured id that differs from an in-scope glob by CASE alone must be refused
    in BOTH the cloud_posture and policy_path branches (the gate matches case-sensitively). Pre-fix, the
    policy_path branch lowercased 'ACME-evil' -> 'acme-evil' and minted an over-scoped FACT under the
    relabeled subject; this asserts neither branch mints it and no FACT names the laundered id."""
    pytest.importorskip("framework.v2.verify", reason="CRUCIBLE not importable here")
    signers, _ = _signers_and_trust()
    g = _gate([CloudScopeEntry(provider="aws", account="111122223333", resource="arn:aws:s3:::acme-*")])
    r = cloud_live_verify(_CASE_MISMATCH_CAPTURE, provider="aws", account="111122223333",
                          resource="arn:aws:s3:::acme-public", scope_gate=g, engagement_slug="acme",
                          signers=signers)
    assert r.refused is False                          # the capture request itself was in scope
    assert r.n_facts == 0                              # neither branch minted the case-mismatched subject
    assert r.skipped_out_of_scope >= 1
    for f in r.facts:                                  # belt-and-suspenders: no laundered/relabeled subject
        assert f.signed.certificate.bound_identity["resource_scope"]["resource"] != "arn:aws:s3:::acme-evil"


def test_mixed_case_in_scope_subject_mints_with_raw_case_exact_binding():
    """Locks the fix-of-the-fix (the load-bearing positive property): a MIXED-CASE in-scope subject DOES
    mint, and EVERY branch binds the RAW case-exact id — not the oracle's lowercased canonical. A revert to
    binding the canonical id would fail this in the policy_path branch (it would bind '…:acme-data')."""
    pytest.importorskip("framework.v2.verify", reason="CRUCIBLE not importable here")
    signers, _ = _signers_and_trust()
    g = _gate([CloudScopeEntry(provider="aws", account="111122223333", resource="arn:aws:s3:::Acme-*")])
    cap = {"format": "native", "export": {"resources": [
        {"id": "arn:aws:s3:::Acme-Data", "kind": "datastore",
         "grants": [{"principal": "*", "access": "s3:GetObject"}]}]}}
    r = cloud_live_verify(cap, provider="aws", account="111122223333", resource="arn:aws:s3:::Acme-Data",
                          scope_gate=g, engagement_slug="acme", signers=signers)
    assert r.refused is False and r.n_facts >= 1
    subs = {f.signed.certificate.bound_identity["resource_scope"]["resource"] for f in r.facts}
    assert subs == {"arn:aws:s3:::Acme-Data"}          # raw case-exact in BOTH branches, never lowercased
    assert {f.bug_class for f in r.facts} >= {"cloud_misconfiguration", "privilege_path"}


def test_case_collision_policy_path_subject_is_skipped_fail_closed():
    """The policy_path branch cannot attribute a canonical id that maps to MULTIPLE case-distinct raw captured
    ids to a single case-exact subject, so it SKIPS fail-closed (recall loss, never a wrong-subject mint).
    The cloud_posture branch — which scope-checks each raw id independently — still mints both distinct raw
    subjects."""
    pytest.importorskip("framework.v2.verify", reason="CRUCIBLE not importable here")
    signers, _ = _signers_and_trust()
    g = _gate([CloudScopeEntry(provider="aws", account="111122223333")])   # account-only: both raws in scope
    cap = {"format": "native", "export": {"resources": [
        {"id": "arn:aws:s3:::acme-x", "kind": "datastore",
         "grants": [{"principal": "*", "access": "s3:GetObject"}]},
        {"id": "arn:aws:s3:::ACME-x", "kind": "datastore",
         "grants": [{"principal": "*", "access": "s3:GetObject"}]}]}}
    r = cloud_live_verify(cap, provider="aws", account="111122223333", scope_gate=g, engagement_slug="acme",
                          signers=signers)
    assert r.refused is False
    assert [f for f in r.facts if f.bug_class == "privilege_path"] == []   # collision -> fail-closed skip
    assert r.skipped_out_of_scope >= 1
    cp = {f.signed.certificate.bound_identity["resource_scope"]["resource"]
          for f in r.facts if f.bug_class == "cloud_misconfiguration"}
    assert cp == {"arn:aws:s3:::acme-x", "arn:aws:s3:::ACME-x"}            # both distinct raw subjects mint


# ---- in-scope capture -> signed FACT that re-verifies offline (framework leg) ---------------------

def test_in_scope_capture_mints_reverifiable_live_facts():
    pytest.importorskip("framework.v2.verify", reason="CRUCIBLE not importable here")
    from framework.v2.evidence.certify import verify_certificate
    signers, tr = _signers_and_trust()
    r = cloud_live_verify(_INSECURE_CAPTURE, provider="aws", account="111122223333", region="us-east-1",
                          scope_gate=_gate(_IN_SCOPE), engagement_slug="acme", signers=signers,
                          capture_time_epoch=1_700_000_000)
    assert isinstance(r, CloudLivePostureResult) and r.refused is False
    assert r.n_facts >= 2, f"expected cloud_posture + policy_path FACTs; got {r.admissions}"
    families = {f.bug_class for f in r.facts}
    assert "cloud_misconfiguration" in families and "privilege_path" in families
    for f in r.facts:
        cert = f.signed.certificate
        # the FACT is bound to the SCOPED LIVE capture (not the whole cloud), via a live-read capture method
        assert cert.capture_method == "api:list"
        bid = cert.bound_identity
        rs = bid["resource_scope"]
        assert rs["provider"] == "aws" and rs["account"] == "111122223333" and rs["region"] == "us-east-1"
        # BLOCK-1 / BLOCK #3: the scope names the FACT's ACTUAL subject, not a shared request glob.
        assert rs.get("resource") in {"aws_s3_bucket_policy.public", "aws_db_instance.sec"}
        assert bid.get("capture_time_epoch") == 1_700_000_000
        assert cert.artifact_recheck_required is True
        # re-verifies offline ONLY with the retained capture bytes
        assert verify_certificate(f.signed, oracle_context=r.contexts[f.finding_ref], trust_root=tr,
                                  artifact_bytes=r.artifact_bytes).ok is True
    assert r.family_verdict() == "FACT"


def test_live_capture_artifact_recheck_fails_on_mutation_or_missing():
    pytest.importorskip("framework.v2.verify", reason="CRUCIBLE not importable here")
    from framework.v2.evidence.certify import verify_certificate
    signers, tr = _signers_and_trust()
    r = cloud_live_verify(_INSECURE_CAPTURE, provider="aws", account="111122223333",
                          scope_gate=_gate(_IN_SCOPE), engagement_slug="acme", signers=signers)
    f = r.facts[0]
    ctx = r.contexts[f.finding_ref]
    # correct bytes -> ok; 1-byte mutation -> not ok; no bytes -> fail closed
    assert verify_certificate(f.signed, oracle_context=ctx, trust_root=tr, artifact_bytes=r.artifact_bytes).ok
    mutated = bytearray(r.artifact_bytes)
    mutated[len(mutated) // 2] ^= 0x01
    assert verify_certificate(f.signed, oracle_context=ctx, trust_root=tr, artifact_bytes=bytes(mutated)).ok is False
    assert verify_certificate(f.signed, oracle_context=ctx, trust_root=tr).ok is False


def test_hardened_capture_is_inconclusive_never_clean():
    pytest.importorskip("framework.v2.verify", reason="CRUCIBLE not importable here")
    signers, _ = _signers_and_trust()
    r = cloud_live_verify(_HARDENED_CAPTURE, provider="aws", account="111122223333",
                          scope_gate=_gate(_IN_SCOPE), engagement_slug="acme", signers=signers)
    assert r.refused is False and r.n_facts == 0
    assert r.family_verdict() == "INCONCLUSIVE"           # a partial capture never mints CLEAN
    assert all(out.outcome != "clean" for out in r.facts + r.leads + r.inconclusive)


def test_malformed_capture_is_a_typed_no_fact_not_a_crash():
    pytest.importorskip("framework.v2.verify", reason="CRUCIBLE not importable here")
    signers, _ = _signers_and_trust()
    r = cloud_live_verify(b"{not valid json", provider="aws", account="111122223333",
                          scope_gate=_gate(_IN_SCOPE), engagement_slug="acme", signers=signers)
    assert r.refused is False and r.n_facts == 0          # gate passed, parse failed -> no facts, no crash
    # (FATAL-2 — that importing this module co-loads no framework/strix — is verified by the CI sovereign leg's
    # import probe against .venv-sovereign, not in-process here where the offense leg has already loaded them.)
