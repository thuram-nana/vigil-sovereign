"""Wave B.3 — dep-free CI coverage of the cloud-posture REPORT ADAPTER over an AZURE capture.

The Azure twin of ``test_cloud_posture_run_gcp_report`` (GCP) / ``test_cloud_posture_run_report`` (AWS). The
azure-fake full E2E (``test_cloud_posture_run_azure_e2e``) proves the real-collector half; this test needs NO
azure libs at all: it drives a synthetic in-scope insecure AZURE-NATIVE capture (the ``{format, export}`` shape
``sensors.azure_live`` emits — a confirmed-public blob container whose ``publicAccess`` is ``Container`` in a
storage account that both allows public blob access and is internet-open) through the EXISTING provider-generic
``cloud_live_verify`` to mint signed FACTs, then asserts the Wave B.2 report adapter renders each as a
re-runnable "PROVEN FACT". So the Azure path through the adapter + its ``oracle_context`` threading are
exercised IN the pipeline, on any CI box.

Plus the GATE-REFUSAL legs: ``run_cloud_posture_live`` drives the Azure collector THROUGH the gated
``invoke_tool`` chain — with ACTIVE_RECON denied the gate refuses BEFORE the collector touches the azure SDK,
and an un-allowlisted control-plane host makes the egress gate refuse — so no azure libs are needed and the
dispatch's fail-closed not-ok branches are proven in CI.

``cloud_live_verify`` / ``render_cloud_posture_report`` / ``run_cloud_posture_live`` do their ``framework``
imports function-locally, so these tests ``importorskip('framework.v2.verify')`` and run in the OFFENSE leg;
they skip (never fail) in the sovereign leg where framework is unimportable — exactly like the GCP sibling.
"""
from __future__ import annotations

from types import SimpleNamespace

import pytest

from vigil_integration.live.cloud_live_posture import cloud_live_verify
from vigil_integration.live.cloud_scope import CloudScopeEntry, CloudScopeGate, StaticCloudScopeSource

# For Azure the tenant identity bound into every FACT is the SUBSCRIPTION id (session.account_id), matched
# EXACTLY by the D5 scope gate — there is no separate account.
_SUBSCRIPTION = "11111111-2222-3333-4444-555555555555"
_IN_SCOPE = [CloudScopeEntry(provider="azure", account=_SUBSCRIPTION)]

_PUBLIC_SUBJECT = "acmepublicacct/public-assets"
_LOCKED_SUBJECT = "acmelockedacct/would-be-public"

# A VIGIL-owned AZURE-NATIVE capture (the shape ``azure_live`` emits via ``azure_inventory_from_responses``): a
# CONFIRMED public blob container — ``publicAccess=Container`` in an account that the three-scope rule promoted
# (container public + account allowBlobPublicAccess + network internet-open) — so ``public``/``grants`` are set
# and the deterministic cloud oracle fires. The non-promoted container (``container_public`` raw signal only,
# the account FORBIDDING public blob access, no ``public``/``grants``) is the negative control that must NOT
# mint a FACT.
_INSECURE_CAPTURE = {"format": "native", "export": {"provider": "azure", "subscription": _SUBSCRIPTION,
    "principals": [], "resources": [
        {"id": _PUBLIC_SUBJECT, "kind": "datastore", "container_public": True, "account_allows_public": True,
         "account_internet_open": True, "public": True, "grants": [{"principal": "*", "access": "read"}]},
        {"id": _LOCKED_SUBJECT, "kind": "datastore", "container_public": True,
         "account_allows_public": False},  # account forbids public -> never promoted (no public/grants) -> no FACT
    ]}}


def _signers_and_trust():
    from vigil_core import AuthorizerKey, TrustRoot, generate_keypair
    kp = generate_keypair()
    return [("gov0", kp.private_key_b64)], TrustRoot(
        threshold=1, authorizers=[AuthorizerKey(key_id="gov0", name="gov0", public_key_b64=kp.public_key_b64)])


def _verify(subscription_claimed: str, scope_subscription: str):
    signers, _ = _signers_and_trust()
    gate = CloudScopeGate(
        scope=StaticCloudScopeSource([CloudScopeEntry(provider="azure", account=scope_subscription)]),
        engagement_slug="acme")
    return cloud_live_verify(_INSECURE_CAPTURE, provider="azure", account=subscription_claimed, scope_gate=gate,
                             engagement_slug="acme", signers=signers, capture_time_epoch=1_700_000_000)


def test_azure_report_adapter_renders_proven_facts_without_azure_libs():
    pytest.importorskip("framework.v2.verify")
    from vigil_integration.live.cloud_posture_run import render_cloud_posture_report

    result = _verify(_SUBSCRIPTION, _SUBSCRIPTION)
    assert result.refused is False and result.n_facts >= 1, getattr(result, "admissions", None)
    # the FACT names its ACTUAL subject — the public container, never the public-forbidding negative control.
    subjects = {f.signed.certificate.bound_identity["resource_scope"]["resource"] for f in result.facts}
    assert _PUBLIC_SUBJECT in subjects, subjects
    assert _LOCKED_SUBJECT not in subjects, subjects
    # the oracle actually fired: each FACT names its confirming oracle AND carries a real calibrated
    # confidence (never the banned hard-coded 1.0, never 0) — the value is the oracle's, not fabricated.
    for f in result.facts:
        assert f.is_fact and f.confirmed_by and 0.0 < float(f.confidence) < 1.0
        # the Azure tenant identity bound into the cert is the subscription id.
        assert f.signed.certificate.bound_identity["resource_scope"]["provider"] == "azure"
        assert f.signed.certificate.bound_identity["resource_scope"]["account"] == _SUBSCRIPTION

    md = render_cloud_posture_report(result, target=f"azure:{_SUBSCRIPTION}")
    for marker in ("PROVEN FACT", "sha256:", "framework.v2 verify", "oracle-confirmed fact(s)"):
        assert marker in md, marker
    # the executive variant also surfaces the confirmed fact(s)
    assert "oracle-confirmed fact(s)" in render_cloud_posture_report(result, executive=True)


def test_azure_report_adapter_is_empty_safe_for_a_refused_capture():
    """A refused (out-of-scope subscription) capture mints no FACT; the adapter must render WITHOUT error and
    WITHOUT a PROVEN FACT line — a refusal is never dressed up as a finding."""
    pytest.importorskip("framework.v2.verify")
    from vigil_integration.live.cloud_posture_run import render_cloud_posture_report

    refused = _verify(_SUBSCRIPTION, "99999999-0000-0000-0000-000000000000")  # claimed sub NOT in charter scope
    assert refused.refused is True and refused.n_facts == 0
    md = render_cloud_posture_report(refused, target=f"azure:{_SUBSCRIPTION}")
    assert "PROVEN FACT" not in md


def _azure_session():
    """A duck-typed minted Azure session (provider / account_id[subscription] / bearer_token) — the shape an
    Azure ``vigil_core.cloud_session.MintedSession`` exposes. No azure libs are constructed: the gate refuses
    before the collector ever reads it."""
    return SimpleNamespace(provider="azure", account_id=_SUBSCRIPTION, bearer_token="aad.scoped-read-only")


def test_azure_live_collection_is_gated_and_refuses_when_not_entitled(monkeypatch, tmp_path):
    """GATE ISOLATION (dep-free; RUNS IN CI): ``run_cloud_posture_live`` drives the Azure collector THROUGH the
    W1.4 fail-closed chain (``invoke_tool``), never ``sensor.run()`` directly. With the ACTIVE_RECON entitlement
    DENIED, the gate refuses BEFORE the collector touches the azure SDK — so the result is a no-FACT, never-CLEAN
    INCONCLUSIVE carrying the gate reason, and no live control-plane read happens. No azure libs are needed (the
    gate refuses before the sensor's azure code), proving the dispatch inherits the gating and the Azure
    collection cannot run ungated."""
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
    result = run_cloud_posture_live(_azure_session(), scope_gate=gate, engagement_slug="acme", signers=signers)

    assert result.n_facts == 0 and result.family_verdict() != "CLEAN"
    assert result.provider == "azure" and result.account == _SUBSCRIPTION
    note = " ".join(result.notes).lower()
    assert "gated" in note and ("entitl" in note or "gate=entitlement" in note), result.notes


def test_azure_live_collection_is_gated_and_refuses_an_unallowlisted_host(monkeypatch, tmp_path):
    """GATE ISOLATION, egress leg (dep-free; RUNS IN CI): with the kill-switch clear and ACTIVE_RECON granted,
    an un-allowlisted control-plane host makes invoke_tool's egress gate refuse BEFORE any azure read — so
    run_cloud_posture_live returns a no-FACT, never-CLEAN INCONCLUSIVE with gate=egress. Proves the egress
    control reaches THROUGH the Azure dispatch, not only the entitlement gate."""
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
    result = run_cloud_posture_live(_azure_session(), scope_gate=gate, engagement_slug="acme", signers=signers)

    assert result.n_facts == 0 and result.family_verdict() != "CLEAN"
    note = " ".join(result.notes).lower()
    assert "gate=egress" in note, result.notes
