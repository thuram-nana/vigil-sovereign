"""Wave B.3 — dep-free CI coverage of the cloud-posture REPORT ADAPTER over a GCP capture.

The GCP twin of ``test_cloud_posture_run_report`` (AWS). The google-fake full E2E
(``test_cloud_posture_run_gcp_e2e``) proves the real-collector half; this test needs NO google libs at all: it
drives a synthetic in-scope insecure GCP-NATIVE capture (the ``{format, export}`` shape ``sensors.gcp_live``
emits — a confirmed-public GCS bucket with an unconditioned ``allUsers`` grant) through the EXISTING
provider-generic ``cloud_live_verify`` to mint signed FACTs, then asserts the Wave B.2 report adapter renders
each as a re-runnable "PROVEN FACT". So the GCP path through the adapter + its ``oracle_context`` threading are
exercised IN the pipeline, on any CI box.

Plus the GATE-REFUSAL leg: ``run_cloud_posture_live`` drives the GCP collector THROUGH the gated
``invoke_tool`` chain — with ACTIVE_RECON denied the gate refuses BEFORE the collector touches the google SDK,
so no google libs are needed and the dispatch's fail-closed not-ok branch is proven in CI.

``cloud_live_verify`` / ``render_cloud_posture_report`` / ``run_cloud_posture_live`` do their ``framework``
imports function-locally, so these tests ``importorskip('framework.v2.verify')`` and run in the OFFENSE leg;
they skip (never fail) in the sovereign leg where framework is unimportable — exactly like the AWS sibling.
"""
from __future__ import annotations

from types import SimpleNamespace

import pytest

from vigil_integration.live.cloud_live_posture import cloud_live_verify
from vigil_integration.live.cloud_scope import CloudScopeEntry, CloudScopeGate, StaticCloudScopeSource

# For GCP the tenant identity bound into every FACT is the PROJECT id (session.account_id), matched EXACTLY by
# the D5 scope gate — there is no separate account.
_PROJECT = "acme-prod-847163"
_IN_SCOPE = [CloudScopeEntry(provider="gcp", account=_PROJECT)]

# A VIGIL-owned GCP-NATIVE capture (the shape ``gcp_live`` emits via ``gcp_inventory_from_responses``): a
# CONFIRMED public GCS bucket — an UNCONDITIONED ``allUsers`` grant that the two-scope PAP rule promoted
# (bucket ``inherited`` + org policy NOT enforcing) — so ``public``/``grants`` are set and the deterministic
# cloud oracle fires. The non-promoted bucket (``iam_public`` raw signal only, PAP ``enforced``, no
# ``public``/``grants``) is the negative control that must NOT mint a FACT.
_INSECURE_CAPTURE = {"format": "native", "export": {"provider": "gcp", "project": _PROJECT, "resources": [
    {"id": "acme-public-assets", "kind": "datastore", "iam_public": True, "public": True,
     "public_access_prevention": "inherited", "grants": [{"principal": "allUsers", "access": "read"}]},
    {"id": "acme-locked-down", "kind": "datastore", "iam_public": True,
     "public_access_prevention": "enforced"},  # PAP enforced -> never promoted (no public/grants) -> no FACT
]}}


def _signers_and_trust():
    from vigil_core import AuthorizerKey, TrustRoot, generate_keypair
    kp = generate_keypair()
    return [("gov0", kp.private_key_b64)], TrustRoot(
        threshold=1, authorizers=[AuthorizerKey(key_id="gov0", name="gov0", public_key_b64=kp.public_key_b64)])


def _verify(project_claimed: str, scope_project: str):
    signers, _ = _signers_and_trust()
    gate = CloudScopeGate(
        scope=StaticCloudScopeSource([CloudScopeEntry(provider="gcp", account=scope_project)]),
        engagement_slug="acme")
    return cloud_live_verify(_INSECURE_CAPTURE, provider="gcp", account=project_claimed, scope_gate=gate,
                             engagement_slug="acme", signers=signers, capture_time_epoch=1_700_000_000)


def test_gcp_report_adapter_renders_proven_facts_without_google_libs():
    pytest.importorskip("framework.v2.verify")
    from vigil_integration.live.cloud_posture_run import render_cloud_posture_report

    result = _verify(_PROJECT, _PROJECT)
    assert result.refused is False and result.n_facts >= 1, getattr(result, "admissions", None)
    # the FACT names its ACTUAL subject — the public bucket, never the enforced-PAP negative control.
    subjects = {f.signed.certificate.bound_identity["resource_scope"]["resource"] for f in result.facts}
    assert "acme-public-assets" in subjects, subjects
    assert "acme-locked-down" not in subjects, subjects
    # the oracle actually fired: each FACT names its confirming oracle AND carries a real calibrated
    # confidence (never the banned hard-coded 1.0, never 0) — the value is the oracle's, not fabricated.
    for f in result.facts:
        assert f.is_fact and f.confirmed_by and 0.0 < float(f.confidence) < 1.0
        # the GCP tenant identity bound into the cert is the project id.
        assert f.signed.certificate.bound_identity["resource_scope"]["provider"] == "gcp"
        assert f.signed.certificate.bound_identity["resource_scope"]["account"] == _PROJECT

    md = render_cloud_posture_report(result, target=f"gcp:{_PROJECT}")
    for marker in ("PROVEN FACT", "sha256:", "framework.v2 verify", "oracle-confirmed fact(s)"):
        assert marker in md, marker
    # the executive variant also surfaces the confirmed fact(s)
    assert "oracle-confirmed fact(s)" in render_cloud_posture_report(result, executive=True)


def test_gcp_report_adapter_is_empty_safe_for_a_refused_capture():
    """A refused (out-of-scope project) capture mints no FACT; the adapter must render WITHOUT error and WITHOUT
    a PROVEN FACT line — a refusal is never dressed up as a finding."""
    pytest.importorskip("framework.v2.verify")
    from vigil_integration.live.cloud_posture_run import render_cloud_posture_report

    refused = _verify(_PROJECT, "some-other-project")   # claimed project is NOT in the charter scope -> refused
    assert refused.refused is True and refused.n_facts == 0
    md = render_cloud_posture_report(refused, target=f"gcp:{_PROJECT}")
    assert "PROVEN FACT" not in md


def _gcp_session():
    """A duck-typed minted GCP session (provider / account_id[project] / bearer_token) — the shape a GCP
    ``vigil_core.cloud_session.MintedSession`` exposes. No google libs are constructed: the gate refuses before
    the collector ever reads it."""
    return SimpleNamespace(provider="gcp", account_id=_PROJECT, bearer_token="ya29.scoped-read-only")


def test_gcp_live_collection_is_gated_and_refuses_when_not_entitled(monkeypatch, tmp_path):
    """GATE ISOLATION (dep-free; RUNS IN CI): ``run_cloud_posture_live`` drives the GCP collector THROUGH the
    W1.4 fail-closed chain (``invoke_tool``), never ``sensor.run()`` directly. With the ACTIVE_RECON entitlement
    DENIED, the gate refuses BEFORE the collector touches the google SDK — so the result is a no-FACT,
    never-CLEAN INCONCLUSIVE carrying the gate reason, and no live control-plane read happens. No google libs
    are needed (the gate refuses before the sensor's google code), proving the dispatch inherits the gating and
    the GCP collection cannot run ungated."""
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
    result = run_cloud_posture_live(_gcp_session(), scope_gate=gate, engagement_slug="acme", signers=signers)

    assert result.n_facts == 0 and result.family_verdict() != "CLEAN"
    assert result.provider == "gcp" and result.account == _PROJECT
    note = " ".join(result.notes).lower()
    assert "gated" in note and ("entitl" in note or "gate=entitlement" in note), result.notes


def test_gcp_live_collection_is_gated_and_refuses_an_unallowlisted_host(monkeypatch, tmp_path):
    """GATE ISOLATION, egress leg (dep-free; RUNS IN CI): with the kill-switch clear and ACTIVE_RECON granted,
    an un-allowlisted control-plane host makes invoke_tool's egress gate refuse BEFORE any google read — so
    run_cloud_posture_live returns a no-FACT, never-CLEAN INCONCLUSIVE with gate=egress. Proves the egress
    control reaches THROUGH the GCP dispatch, not only the entitlement gate."""
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
    result = run_cloud_posture_live(_gcp_session(), scope_gate=gate, engagement_slug="acme", signers=signers)

    assert result.n_facts == 0 and result.family_verdict() != "CLEAN"
    note = " ".join(result.notes).lower()
    assert "gate=egress" in note, result.notes
