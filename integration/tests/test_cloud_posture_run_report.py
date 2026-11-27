"""Wave B.2 — dep-free CI coverage of the cloud-posture REPORT ADAPTER (render_cloud_posture_report).

The moto full-stack E2E (``test_cloud_posture_run_e2e``) proves the real-collector half but SKIPS where boto3
is absent — which is every CI job (boto3 is importorskip-guarded repo-wide). This test needs NO boto3/moto: it
drives a synthetic in-scope insecure NATIVE capture (the ``{format, export}`` shape ``sensors.cloud_live``
emits) through the EXISTING ``cloud_live_verify`` to mint signed FACTs, then asserts the Wave B.2 report
adapter renders each as a re-runnable "PROVEN FACT". So the NEW adapter + its ``oracle_context`` threading are
exercised IN the pipeline, not only on a developer box.

``cloud_live_verify`` / ``render_cloud_posture_report`` do their ``framework`` imports function-locally, so the
mint/render tests ``importorskip('framework.v2.verify')`` and run in the OFFENSE leg; they skip (never fail)
in the sovereign leg where framework is unimportable — exactly like the sibling ``test_cloud_live_posture``.
"""
from __future__ import annotations

from types import SimpleNamespace

import pytest

from vigil_integration.live.cloud_live_posture import cloud_live_verify
from vigil_integration.live.cloud_scope import CloudScopeEntry, CloudScopeGate, StaticCloudScopeSource

_ACCOUNT = "111122223333"
_IN_SCOPE = [CloudScopeEntry(provider="aws", account=_ACCOUNT)]

# A VIGIL-owned NATIVE capture (the shape the live collector emits): a public bucket-policy grant AND an
# unencrypted sensitive datastore — both fire the deterministic cloud_posture oracle, so FACTs mint.
_INSECURE_CAPTURE = {"format": "native", "export": {"resources": [
    {"id": "aws_s3_bucket_policy.public", "kind": "datastore",
     "grants": [{"principal": "*", "access": "s3:GetObject"}]},
    {"id": "aws_db_instance.sec", "kind": "datastore", "encrypted": False, "sensitive": True}]}}


def _signers_and_trust():
    from vigil_core import AuthorizerKey, TrustRoot, generate_keypair
    kp = generate_keypair()
    return [("gov0", kp.private_key_b64)], TrustRoot(
        threshold=1, authorizers=[AuthorizerKey(key_id="gov0", name="gov0", public_key_b64=kp.public_key_b64)])


def _verify(account_claimed: str, scope_account: str):
    signers, _ = _signers_and_trust()
    gate = CloudScopeGate(
        scope=StaticCloudScopeSource([CloudScopeEntry(provider="aws", account=scope_account)]),
        engagement_slug="acme")
    return cloud_live_verify(_INSECURE_CAPTURE, provider="aws", account=account_claimed, scope_gate=gate,
                             engagement_slug="acme", signers=signers, capture_time_epoch=1_700_000_000)


def test_report_adapter_renders_proven_facts_without_boto3():
    pytest.importorskip("framework.v2.verify")
    from vigil_integration.live.cloud_posture_run import render_cloud_posture_report

    result = _verify(_ACCOUNT, _ACCOUNT)
    assert result.refused is False and result.n_facts >= 1, getattr(result, "admissions", None)
    # the oracle actually fired: each FACT names its confirming oracle AND carries a real calibrated
    # confidence (never the banned hard-coded 1.0, never 0) — the value is the oracle's, not fabricated.
    for f in result.facts:
        assert f.is_fact and f.confirmed_by and 0.0 < float(f.confidence) < 1.0

    md = render_cloud_posture_report(result, target=f"aws:{_ACCOUNT}")
    for marker in ("PROVEN FACT", "sha256:", "framework.v2 verify", "oracle-confirmed fact(s)"):
        assert marker in md, marker
    # the executive variant also surfaces the confirmed fact(s)
    assert "oracle-confirmed fact(s)" in render_cloud_posture_report(result, executive=True)


def test_report_adapter_is_empty_safe_for_a_refused_capture():
    """A refused (out-of-scope) capture mints no FACT; the adapter must render WITHOUT error and WITHOUT a
    PROVEN FACT line — a refusal is never dressed up as a finding."""
    pytest.importorskip("framework.v2.verify")
    from vigil_integration.live.cloud_posture_run import render_cloud_posture_report

    refused = _verify(_ACCOUNT, "999999999999")   # claimed account is NOT in the charter scope -> refused
    assert refused.refused is True and refused.n_facts == 0
    md = render_cloud_posture_report(refused, target=f"aws:{_ACCOUNT}")
    assert "PROVEN FACT" not in md


def test_live_collection_is_gated_and_refuses_when_not_entitled(monkeypatch, tmp_path):
    """GATE ISOLATION (dep-free; RUNS IN CI): ``run_cloud_posture_live`` drives the live collector THROUGH
    the W1.4 fail-closed chain (``invoke_tool``), never ``sensor.run()`` directly. With the ACTIVE_RECON
    entitlement DENIED, the gate refuses BEFORE the collector touches boto3 — so the result is a no-FACT,
    never-CLEAN INCONCLUSIVE carrying the gate reason, and no live control-plane read happens. No boto3 is
    needed (the gate refuses before the sensor's boto3 code), so this proves the gating is wired and the
    live collection cannot run ungated — exactly the control the sensor's fail-closed contract requires."""
    pytest.importorskip("framework.v2.verify")
    from framework.v2 import entitlement
    from framework.v2.common import paths

    from vigil_integration.live.cloud_posture_run import run_cloud_posture_live

    monkeypatch.setattr(paths, "killswitch_path", lambda slug: tmp_path / f"{slug}.halt")  # kill-switch clear

    def _deny(cap):
        raise PermissionError("active_recon not entitled")

    monkeypatch.setattr(entitlement, "require_capability", _deny)                            # NOT entitled

    session = SimpleNamespace(provider="aws", account_id=_ACCOUNT, region="us-east-1",
                              access_key_id="ASIATEMP", secret_access_key="s", session_token="t")
    signers, _ = _signers_and_trust()
    gate = CloudScopeGate(scope=StaticCloudScopeSource(_IN_SCOPE), engagement_slug="acme")
    result = run_cloud_posture_live(session, scope_gate=gate, engagement_slug="acme", signers=signers)

    assert result.n_facts == 0 and result.family_verdict() != "CLEAN"
    note = " ".join(result.notes).lower()
    assert "gated" in note and ("entitl" in note or "gate=entitlement" in note), result.notes
