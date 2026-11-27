"""Phase C2 · Cloudflare — dep-free CI coverage of the cloud-posture REPORT ADAPTER over a Cloudflare capture.

The Cloudflare twin of ``test_cloud_posture_run_gcp_report`` (GCP) / ``test_cloud_posture_run_report`` (AWS).
The fake-transport full E2E (``test_cloud_posture_run_cloudflare_e2e``) proves the real-collector half; this
test needs NOTHING but the sovereign + framework offense surface: it drives a synthetic in-scope insecure
Cloudflare-NATIVE capture (the ``{format, export}`` shape ``sensors.cloudflare_live`` emits — a confirmed-public
R2 bucket whose managed ``*.r2.dev`` URL is enabled, carrying a synthesised anonymous ``*`` read grant) through
the EXISTING provider-generic ``cloud_live_verify`` to mint signed FACTs, then asserts the report adapter
renders each as a re-runnable "PROVEN FACT". So the Cloudflare path through the adapter + its ``oracle_context``
threading are exercised IN the pipeline, on any CI box.

Plus the GATE-REFUSAL legs: ``run_cloud_posture_live`` drives the Cloudflare collector THROUGH the gated
``invoke_tool`` chain — with ACTIVE_RECON denied (or the control-plane host un-allowlisted) the gate refuses
BEFORE the collector touches the Cloudflare API, so no network is needed and the dispatch's fail-closed not-ok
branch (gate=entitlement / gate=egress) is proven in CI.

``cloud_live_verify`` / ``render_cloud_posture_report`` / ``run_cloud_posture_live`` do their ``framework``
imports function-locally, so these tests ``importorskip('framework.v2.verify')`` and run in the OFFENSE leg;
they skip (never fail) in the sovereign leg where framework is unimportable — exactly like the AWS/GCP siblings.
"""
from __future__ import annotations

from types import SimpleNamespace

import pytest

from vigil_integration.live.cloud_live_posture import cloud_live_verify
from vigil_integration.live.cloud_scope import CloudScopeEntry, CloudScopeGate, StaticCloudScopeSource

# For Cloudflare the tenant identity bound into every FACT is the 32-hex account id (session.account_id),
# matched EXACTLY by the D5 scope gate.
_ACCOUNT = "0123456789abcdef0123456789abcdef"
_IN_SCOPE = [CloudScopeEntry(provider="cloudflare", account=_ACCOUNT)]

_PUBLIC_BUCKET = f"{_ACCOUNT}/public-assets"
_CUSTOM_ONLY_BUCKET = f"{_ACCOUNT}/cdn-only"

# A VIGIL-owned Cloudflare-NATIVE capture (the exact shape ``cloudflare_inventory_from_responses`` emits): a
# CONFIRMED-public R2 bucket — the managed ``*.r2.dev`` URL is enabled (``r2_managed_public: true``), so
# ``public``/``grants`` (a synthesised anonymous ``*`` read) are set and the deterministic cloud oracle fires.
# The custom-domain-only bucket (managed NOT enabled, a ``r2_custom_domains`` signal only, no ``public``/
# ``grants``) is the negative control that must NOT mint a FACT.
_INSECURE_CAPTURE = {"format": "native", "export": {"provider": "cloudflare", "account": _ACCOUNT,
    "principals": [], "resources": [
        {"id": _PUBLIC_BUCKET, "kind": "datastore", "r2_managed_public": True, "public": True,
         "grants": [{"principal": "*", "access": "read"}]},
        {"id": _CUSTOM_ONLY_BUCKET, "kind": "datastore", "r2_managed_public": False,
         "r2_custom_domains": ["cdn.acme.com"]},  # custom-only -> auditable signal, never promoted -> no FACT
    ]}}


def _signers_and_trust():
    from vigil_core import AuthorizerKey, TrustRoot, generate_keypair
    kp = generate_keypair()
    return [("gov0", kp.private_key_b64)], TrustRoot(
        threshold=1, authorizers=[AuthorizerKey(key_id="gov0", name="gov0", public_key_b64=kp.public_key_b64)])


def _verify(account_claimed: str, scope_account: str):
    signers, _ = _signers_and_trust()
    gate = CloudScopeGate(
        scope=StaticCloudScopeSource([CloudScopeEntry(provider="cloudflare", account=scope_account)]),
        engagement_slug="acme")
    return cloud_live_verify(_INSECURE_CAPTURE, provider="cloudflare", account=account_claimed, scope_gate=gate,
                             engagement_slug="acme", signers=signers, capture_time_epoch=1_700_000_000)


def test_cloudflare_report_adapter_renders_proven_facts_without_network():
    pytest.importorskip("framework.v2.verify")
    from vigil_integration.live.cloud_posture_run import render_cloud_posture_report

    result = _verify(_ACCOUNT, _ACCOUNT)
    assert result.refused is False and result.n_facts >= 1, getattr(result, "admissions", None)
    # the FACT names its ACTUAL subject — the confirmed-public bucket, never the custom-domain-only negative
    # control.
    subjects = {f.signed.certificate.bound_identity["resource_scope"]["resource"] for f in result.facts}
    assert _PUBLIC_BUCKET in subjects, subjects
    assert _CUSTOM_ONLY_BUCKET not in subjects, subjects
    # the oracle actually fired: each FACT names its confirming oracle AND carries a real calibrated confidence
    # (never the banned hard-coded 1.0, never 0) — the value is the oracle's, not fabricated.
    for f in result.facts:
        assert f.is_fact and f.confirmed_by and 0.0 < float(f.confidence) < 1.0
        # the Cloudflare tenant identity bound into the cert is the 32-hex account id.
        assert f.signed.certificate.bound_identity["resource_scope"]["provider"] == "cloudflare"
        assert f.signed.certificate.bound_identity["resource_scope"]["account"] == _ACCOUNT

    md = render_cloud_posture_report(result, target=f"cloudflare:{_ACCOUNT}")
    for marker in ("PROVEN FACT", "sha256:", "framework.v2 verify", "oracle-confirmed fact(s)"):
        assert marker in md, marker
    # the executive variant also surfaces the confirmed fact(s)
    assert "oracle-confirmed fact(s)" in render_cloud_posture_report(result, executive=True)


def test_cloudflare_report_adapter_is_empty_safe_for_a_refused_capture():
    """A refused (out-of-scope account) capture mints no FACT; the adapter must render WITHOUT error and WITHOUT
    a PROVEN FACT line — a refusal is never dressed up as a finding."""
    pytest.importorskip("framework.v2.verify")
    from vigil_integration.live.cloud_posture_run import render_cloud_posture_report

    refused = _verify(_ACCOUNT, "fedcba9876543210fedcba9876543210")   # claimed account NOT in the charter scope
    assert refused.refused is True and refused.n_facts == 0
    md = render_cloud_posture_report(refused, target=f"cloudflare:{_ACCOUNT}")
    assert "PROVEN FACT" not in md


def _cloudflare_session():
    """A duck-typed per-run Cloudflare session (provider / account_id[32-hex] / bearer_token) — the shape the
    Cloudflare grant hands the collector. No network is reached: the gate refuses before the collector ever
    reads it."""
    return SimpleNamespace(provider="cloudflare", account_id=_ACCOUNT, bearer_token="cf-scoped-read-only-token")


def test_cloudflare_live_collection_is_gated_and_refuses_when_not_entitled(monkeypatch, tmp_path):
    """GATE ISOLATION (dep-free; RUNS IN CI): ``run_cloud_posture_live`` drives the Cloudflare collector THROUGH
    the W1.4 fail-closed chain (``invoke_tool``), never ``sensor.run()`` directly. With the ACTIVE_RECON
    entitlement DENIED, the gate refuses BEFORE the collector touches the Cloudflare API — so the result is a
    no-FACT, never-CLEAN INCONCLUSIVE carrying the gate reason, and no live control-plane read happens. Proves
    the dispatch inherits the gating and the Cloudflare collection cannot run ungated."""
    pytest.importorskip("framework.v2.verify")
    from framework.v2 import entitlement
    from framework.v2.common import paths

    from vigil_integration.live.cloud_posture_run import run_cloud_posture_live

    monkeypatch.setattr(paths, "killswitch_path", lambda slug: tmp_path / f"{slug}.halt")  # kill-switch clear

    def _deny(cap):
        raise PermissionError("active_recon not entitled")

    monkeypatch.setattr(entitlement, "require_capability", _deny)                            # NOT entitled

    signers, _ = _signers_and_trust()
    gate = CloudScopeGate(scope=StaticCloudScopeSource(_IN_SCOPE), engagement_slug="acme")
    result = run_cloud_posture_live(_cloudflare_session(), scope_gate=gate, engagement_slug="acme", signers=signers)

    assert result.n_facts == 0 and result.family_verdict() != "CLEAN"
    assert result.provider == "cloudflare" and result.account == _ACCOUNT
    note = " ".join(result.notes).lower()
    assert "gated" in note and ("entitl" in note or "gate=entitlement" in note), result.notes


def test_cloudflare_live_collection_is_gated_and_refuses_an_unallowlisted_host(monkeypatch, tmp_path):
    """GATE ISOLATION, egress leg (dep-free; RUNS IN CI): with the kill-switch clear and ACTIVE_RECON granted,
    an un-allowlisted control-plane host makes invoke_tool's egress gate refuse BEFORE any Cloudflare read — so
    run_cloud_posture_live returns a no-FACT, never-CLEAN INCONCLUSIVE with gate=egress. Proves the egress
    control reaches THROUGH the Cloudflare dispatch, not only the entitlement gate."""
    pytest.importorskip("framework.v2.verify")
    from framework.v2 import entitlement
    from framework.v2.agents import egress_guard
    from framework.v2.common import paths

    from vigil_integration.live.cloud_posture_run import run_cloud_posture_live

    monkeypatch.setattr(paths, "killswitch_path", lambda slug: tmp_path / f"{slug}.halt")   # kill-switch clear
    monkeypatch.setattr(entitlement, "require_capability", lambda cap: None)                 # entitled
    monkeypatch.setattr(egress_guard, "build_engagement_allowlist",
                        lambda **k: SimpleNamespace(permits=lambda host: False))             # NOTHING allowlisted

    signers, _ = _signers_and_trust()
    gate = CloudScopeGate(scope=StaticCloudScopeSource(_IN_SCOPE), engagement_slug="acme")
    result = run_cloud_posture_live(_cloudflare_session(), scope_gate=gate, engagement_slug="acme", signers=signers)

    assert result.n_facts == 0 and result.family_verdict() != "CLEAN"
    note = " ".join(result.notes).lower()
    assert "gate=egress" in note, result.notes
