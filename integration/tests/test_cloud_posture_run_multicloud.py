"""Wave B.4 — the UNIFIED cross-provider cloud-posture run + report, proven end-to-end WITHOUT real cloud SDKs.

This is the dep-free CI coverage for the single entry point that assesses a customer across ALL FOUR providers
(``run_multicloud_posture``) and the one consolidated report (``render_multicloud_posture_report``). It proves
the AGGREGATION + REPORT glue over GENUINE signed FACTs, with no boto3 / google / azure / cloudflare install:

  * The FACTs are REAL. For each provider (aws + gcp + azure + cloudflare) a synthetic IN-SCOPE insecure NATIVE
    capture (the ``{format, export}`` shape each provider's live collector emits) is driven through the EXISTING
    provider-generic ``cloud_live_verify`` — the SAME dep-free mint the single-provider report tests use — so
    every per-provider ``CloudLivePostureResult`` carries oracle-confirmed, signed FACTs (never fabricated).

  * The ORCHESTRATION is exercised two ways. (1) ``run_multicloud_posture`` is driven with a monkeypatched
    ``run_cloud_posture_live`` that goes straight to the real ``cloud_live_verify`` (standing in for the real
    collector + gate chain, which would need the cloud SDKs) — so the real aggregation glue runs over GENUINE
    FACTs and the scope_gate / signers / capture_time flow through unchanged. (2) A separate test drives the
    REAL (un-patched) ``run_cloud_posture_live`` across all four providers through the W1.4 gate chain with
    ACTIVE_RECON denied, proving the unified run genuinely dispatches the real per-provider path for every
    provider and fails closed before any cloud SDK is touched.

  * Fail-closed is proven distinctly: a refused provider never suppresses the others' FACTs, a per-provider
    crash is isolated (never crashes the whole run, never a clean negative), an all-refused multi-run renders
    empty-safe with a never-CLEAN aggregate, and two sessions for the SAME provider both count (no masking).

``cloud_live_verify`` / ``run_multicloud_posture`` / ``render_multicloud_posture_report`` do their ``framework``
imports function-locally, so every test ``importorskip('framework.v2.verify')`` and runs in the OFFENSE leg;
they skip (never fail) in the sovereign leg where framework is unimportable — exactly like the single-provider
siblings (``test_cloud_posture_run_report`` / ``test_cloud_posture_run_gcp_report``).
"""
from __future__ import annotations

from types import SimpleNamespace

import pytest

# Sovereign modules (framework-clean at module scope) — safe to import eagerly, even in the sovereign leg.
from vigil_integration.live import cloud_posture_run as cpr
from vigil_integration.live.cloud_live_posture import CloudLivePostureResult, cloud_live_verify
from vigil_integration.live.cloud_scope import CloudScopeEntry, CloudScopeGate, StaticCloudScopeSource

_SLUG = "acme"
_CAPTURE_EPOCH = 1_700_000_000

# Per-provider tenant identities (what the session's account_id is and what the D5 scope gate matches: for GCP
# the "account" IS the project id, for Azure the subscription id, for Cloudflare the account id).
_AWS_ACCOUNT = "111122223333"
_GCP_PROJECT = "acme-prod-847163"
_AZURE_SUB = "sub-azure-abcd"
_CF_ACCOUNT = "cf-account-xyz"

# Synthetic IN-SCOPE insecure NATIVE captures — each is the shape its provider's live collector emits and each
# fires the deterministic cloud_posture / policy_path oracle on its TRUE-POSITIVE subject while a near-FP
# negative control is NOT promoted (so the FACT names its real subject, never the control).
_AWS_CAPTURE = {"format": "native", "export": {"resources": [
    {"id": "aws_s3_bucket_policy.public", "kind": "datastore",
     "grants": [{"principal": "*", "access": "s3:GetObject"}]},
    {"id": "aws_db_instance.sec", "kind": "datastore", "encrypted": False, "sensitive": True}]}}

_GCP_CAPTURE = {"format": "native", "export": {"provider": "gcp", "project": _GCP_PROJECT, "resources": [
    {"id": "acme-public-assets", "kind": "datastore", "iam_public": True, "public": True,
     "public_access_prevention": "inherited", "grants": [{"principal": "allUsers", "access": "read"}]},
    {"id": "acme-locked-down", "kind": "datastore", "iam_public": True,
     "public_access_prevention": "enforced"}]}}  # PAP enforced -> never promoted -> no FACT

_AZURE_CAPTURE = {"format": "native", "export": {"provider": "azure", "subscription": _AZURE_SUB,
    "resources": [
        {"id": "stacct/public-container", "kind": "datastore", "container_public": True,
         "account_allows_public": True, "account_internet_open": True, "public": True,
         "grants": [{"principal": "*", "access": "read"}]},
        {"id": "stacct/locked", "kind": "datastore", "container_public": True,
         "account_allows_public": False}]}}  # account denies public -> never promoted -> no FACT

_CF_CAPTURE = {"format": "native", "export": {"provider": "cloudflare", "account": _CF_ACCOUNT, "resources": [
    {"id": f"{_CF_ACCOUNT}/public-bucket", "kind": "datastore", "r2_managed_public": True, "public": True,
     "grants": [{"principal": "*", "access": "read"}]},
    {"id": f"{_CF_ACCOUNT}/private-bucket", "kind": "datastore",
     "r2_managed_public": False}]}}  # managed r2.dev URL not enabled -> no FACT

# provider -> (tenant id, native capture). Input order here is the deterministic report / aggregation order.
_PROVIDERS = (
    ("aws", _AWS_ACCOUNT, _AWS_CAPTURE),
    ("gcp", _GCP_PROJECT, _GCP_CAPTURE),
    ("azure", _AZURE_SUB, _AZURE_CAPTURE),
    ("cloudflare", _CF_ACCOUNT, _CF_CAPTURE),
)


def _signers():
    """Governance m-of-n signers (vigil_core — the sovereign crypto surface)."""
    from vigil_core import generate_keypair
    kp = generate_keypair()
    return [("gov0", kp.private_key_b64)]


def _combined_gate(providers=_PROVIDERS):
    """One signed charter cloud scope covering every provider's tenant — the real shape of a multi-cloud
    engagement (the operator signs one 2b table with a row per cloud)."""
    return CloudScopeGate(
        scope=StaticCloudScopeSource([CloudScopeEntry(provider=p, account=a) for p, a, _ in providers]),
        engagement_slug=_SLUG)


def _mint(provider, account, capture, gate, signers):
    """Mint a GENUINE per-provider result via the EXISTING provider-generic verify path (dep-free)."""
    return cloud_live_verify(capture, provider=provider, account=account, scope_gate=gate,
                             engagement_slug=_SLUG, signers=signers, capture_time_epoch=_CAPTURE_EPOCH)


def _session(provider, account):
    """A duck-typed minted read-only session — the DATA shape run_cloud_posture_live consumes."""
    return SimpleNamespace(provider=provider, account_id=account, region="",
                           access_key_id="ASIATEMP", secret_access_key="s", session_token="t",
                           bearer_token="ya29.scoped-read-only")


def _patch_run_to_real_mint(monkeypatch, signers):
    """Replace run_cloud_posture_live with one that goes straight to the real cloud_live_verify over the
    synthetic capture for the session's provider — standing in for the real collector + gate chain (which need
    the cloud SDKs) while keeping the mint GENUINE and letting scope_gate / signers / capture_time flow through
    run_multicloud_posture unchanged. An out-of-scope session still refuses naturally (the real gate refuses)."""
    by_provider = {p: cap for p, _a, cap in _PROVIDERS}

    def _run(session_data, *, scope_gate, engagement_slug, signers, capture_time_epoch=None,
             tool_context=None, sink=None):
        provider = str(getattr(session_data, "provider", "") or "")
        account = str(getattr(session_data, "account_id", "") or "")
        return cloud_live_verify(by_provider[provider], provider=provider, account=account,
                                 scope_gate=scope_gate, engagement_slug=engagement_slug, signers=signers,
                                 capture_time_epoch=capture_time_epoch)

    monkeypatch.setattr(cpr, "run_cloud_posture_live", _run)


# ---------------------------------------------------------------------------------------------------------
# 1. The unified run aggregates GENUINE signed FACTs across all four providers, and the one report renders
#    each provider's PROVEN FACT plus the correct aggregate summary.
# ---------------------------------------------------------------------------------------------------------
def test_run_multicloud_aggregates_genuine_facts_across_all_four_providers(monkeypatch):
    pytest.importorskip("framework.v2.verify")
    signers = _signers()
    gate = _combined_gate()

    # Baseline: mint each provider STANDALONE so we have an independent expected FACT count per provider.
    expected = {p: _mint(p, a, cap, gate, signers).n_facts for p, a, cap in _PROVIDERS}
    assert all(n >= 1 for n in expected.values()), expected   # every provider has a true positive

    _patch_run_to_real_mint(monkeypatch, signers)
    sessions = [_session(p, a) for p, a, _ in _PROVIDERS]
    multi = cpr.run_multicloud_posture(sessions, scope_gate=gate, engagement_slug=_SLUG, signers=signers,
                                       capture_time_epoch=_CAPTURE_EPOCH)

    # ALL FOUR providers represented, in input order (deterministic).
    assert multi.providers_assessed == ["aws", "gcp", "azure", "cloudflare"]
    assert set(multi.providers_with_facts) == {"aws", "gcp", "azure", "cloudflare"}
    assert multi.providers_refused == [] and multi.providers_inconclusive == []

    # Per-provider FACT count matches the standalone mint (nothing dropped or double-counted), and the
    # aggregate TOTAL == the SUM of the per-provider counts == the sum of the independent standalone counts.
    assert multi.facts_by_provider() == expected
    assert multi.total_facts == sum(expected.values())
    assert multi.total_facts == sum(r.n_facts for r in multi.results.values())
    assert multi.family_verdict() == "FACT"

    # The FACTs are genuine signed facts: a named confirming oracle and a REAL calibrated confidence (never the
    # banned hard-coded 1.0, never 0) — the oracle fired, the value was not fabricated.
    for res in multi.results.values():
        for f in res.facts:
            assert f.is_fact and f.confirmed_by and 0.0 < float(f.confidence) < 1.0

    # The ONE consolidated report renders each provider's PROVEN FACT (via the reused single-provider renderer)
    # AND the correct aggregate summary.
    md = cpr.render_multicloud_posture_report(multi, target="acme-tenant")
    assert "PROVEN FACT" in md                                   # from the per-provider sections' real FACTs
    assert "sha256:" in md and "framework.v2 verify" in md
    assert f"**Total confirmed FACTs:** {multi.total_facts}" in md
    for p in ("aws", "gcp", "azure", "cloudflare"):
        assert f"## {p} — " in md                                # one section per provider
        assert f"{p}={expected[p]}" in md                        # per-provider FACT count in the summary
    assert "**Combined verdict:** FACT" in md

    # The EXECUTIVE variant surfaces the AGGREGATE totals.
    exec_md = cpr.render_multicloud_posture_report(multi, target="acme-tenant", executive=True)
    assert "oracle-confirmed fact(s)" in exec_md
    assert f"**{multi.total_facts}** oracle-confirmed fact(s) across 4 of 4 provider(s)" in exec_md

    # Determinism: rendering the same aggregate twice is byte-identical (no clock / RNG).
    assert cpr.render_multicloud_posture_report(multi, target="acme-tenant") == md


# ---------------------------------------------------------------------------------------------------------
# 2. A refused provider does NOT suppress the others' FACTs; it is surfaced DISTINCTLY and never read as clean.
# ---------------------------------------------------------------------------------------------------------
def test_run_multicloud_a_refused_provider_does_not_suppress_the_others(monkeypatch):
    pytest.importorskip("framework.v2.verify")
    signers = _signers()
    gate = _combined_gate()

    _patch_run_to_real_mint(monkeypatch, signers)
    # azure's session claims a tenant that is NOT in the signed charter scope -> the D5 gate refuses it. The
    # other three remain in scope and must still mint their FACTs.
    sessions = [
        _session("aws", _AWS_ACCOUNT),
        _session("gcp", _GCP_PROJECT),
        _session("azure", "sub-OUT-OF-SCOPE"),
        _session("cloudflare", _CF_ACCOUNT),
    ]
    multi = cpr.run_multicloud_posture(sessions, scope_gate=gate, engagement_slug=_SLUG, signers=signers,
                                       capture_time_epoch=_CAPTURE_EPOCH)

    assert multi.providers_assessed == ["aws", "gcp", "azure", "cloudflare"]
    assert multi.providers_refused == ["azure"]                 # surfaced distinctly
    assert set(multi.providers_with_facts) == {"aws", "gcp", "cloudflare"}
    assert multi.results["azure"].refused is True and multi.results["azure"].n_facts == 0

    # The refusal did NOT zero the others: total == sum of the THREE in-scope providers, each unchanged.
    standalone = {p: _mint(p, a, cap, gate, signers).n_facts
                  for p, a, cap in _PROVIDERS if p != "azure"}
    assert {k: v for k, v in multi.facts_by_provider().items() if k != "azure"} == standalone
    assert multi.total_facts == sum(standalone.values()) and multi.total_facts >= 1
    # A multi-run with FACTs is FACT overall, but the refused provider is STILL surfaced (not laundered clean).
    assert multi.family_verdict() == "FACT"

    md = cpr.render_multicloud_posture_report(multi, target="acme-tenant")
    assert "PROVEN FACT" in md                                  # the in-scope providers' FACTs still render
    assert "Providers refused" in md and "azure" in md          # refusal surfaced in the report
    # The refused provider's own section renders WITHOUT a PROVEN FACT line (empty-safe, not dressed up).
    azure_section = md.split("## azure — ", 1)[1].split("## cloudflare — ", 1)[0]
    assert "PROVEN FACT" not in azure_section


# ---------------------------------------------------------------------------------------------------------
# 3. NEGATIVE CONTROL: an all-refused multi-run renders empty-safe with a never-CLEAN aggregate.
# ---------------------------------------------------------------------------------------------------------
def test_run_multicloud_all_refused_is_empty_safe_and_never_clean(monkeypatch):
    pytest.importorskip("framework.v2.verify")
    signers = _signers()
    # A charter scope that names a DIFFERENT tenant for every provider -> every session is out of scope.
    out_of_scope_gate = CloudScopeGate(
        scope=StaticCloudScopeSource([CloudScopeEntry(provider=p, account="some-other-tenant")
                                      for p, _a, _c in _PROVIDERS]),
        engagement_slug=_SLUG)

    _patch_run_to_real_mint(monkeypatch, signers)
    sessions = [_session(p, a) for p, a, _ in _PROVIDERS]
    multi = cpr.run_multicloud_posture(sessions, scope_gate=out_of_scope_gate, engagement_slug=_SLUG,
                                       signers=signers, capture_time_epoch=_CAPTURE_EPOCH)

    assert multi.providers_assessed == ["aws", "gcp", "azure", "cloudflare"]
    assert multi.providers_refused == ["aws", "gcp", "azure", "cloudflare"]
    assert multi.providers_with_facts == []
    assert multi.total_facts == 0
    # NEVER CLEAN — an all-refused run is INCONCLUSIVE, not a clean bill of health.
    assert multi.family_verdict() == "INCONCLUSIVE"

    md = cpr.render_multicloud_posture_report(multi, target="acme-tenant")
    assert "PROVEN FACT" not in md                              # empty-safe: no dressed-up finding anywhere
    assert "**Total confirmed FACTs:** 0" in md
    assert "**Combined verdict:** INCONCLUSIVE" in md
    # the executive variant is also empty-safe and never-CLEAN.
    exec_md = cpr.render_multicloud_posture_report(multi, target="acme-tenant", executive=True)
    assert "PROVEN FACT" not in exec_md
    assert "**0** oracle-confirmed fact(s) across 0 of 4 provider(s)" in exec_md


# ---------------------------------------------------------------------------------------------------------
# 4. A per-provider crash is ISOLATED: it never crashes the whole run, never masks the others, never clean.
# ---------------------------------------------------------------------------------------------------------
def test_run_multicloud_isolates_a_per_provider_crash(monkeypatch):
    pytest.importorskip("framework.v2.verify")
    signers = _signers()
    gate = _combined_gate()
    by_provider = {p: cap for p, _a, cap in _PROVIDERS}

    def _run_with_one_crash(session_data, *, scope_gate, engagement_slug, signers, capture_time_epoch=None,
                            tool_context=None, sink=None):
        provider = str(getattr(session_data, "provider", "") or "")
        account = str(getattr(session_data, "account_id", "") or "")
        if provider == "azure":
            raise RuntimeError("synthetic collector blew up for azure")   # one provider's run raises
        return cloud_live_verify(by_provider[provider], provider=provider, account=account,
                                 scope_gate=scope_gate, engagement_slug=engagement_slug, signers=signers,
                                 capture_time_epoch=capture_time_epoch)

    monkeypatch.setattr(cpr, "run_cloud_posture_live", _run_with_one_crash)
    sessions = [_session(p, a) for p, a, _ in _PROVIDERS]
    # The whole run must NOT crash.
    multi = cpr.run_multicloud_posture(sessions, scope_gate=gate, engagement_slug=_SLUG, signers=signers,
                                       capture_time_epoch=_CAPTURE_EPOCH)

    # Every provider is still represented; the crashed one is a no-FACT, never-CLEAN INCONCLUSIVE.
    assert multi.providers_assessed == ["aws", "gcp", "azure", "cloudflare"]
    assert multi.results["azure"].n_facts == 0
    assert multi.results["azure"].family_verdict() == "INCONCLUSIVE"
    assert "azure" in multi.providers_inconclusive and "azure" not in multi.providers_refused
    # The error is SURFACED, not swallowed silently: the exception type + message are in the provider's notes
    # AND the orchestration notes.
    azure_notes = " ".join(multi.results["azure"].notes)
    assert "RuntimeError" in azure_notes and "blew up for azure" in azure_notes
    assert any("azure" in n and "RuntimeError" in n for n in multi.notes), multi.notes

    # The other three were still assessed and kept their FACTs — the crash masked nothing.
    assert set(multi.providers_with_facts) == {"aws", "gcp", "cloudflare"}
    assert multi.total_facts >= 3 and multi.family_verdict() == "FACT"

    md = cpr.render_multicloud_posture_report(multi, target="acme-tenant")
    assert "Orchestration notes" in md and "RuntimeError" in md   # the isolated error is in the report


# ---------------------------------------------------------------------------------------------------------
# 5. The unified run drives the REAL per-provider dispatch for EVERY provider through the gate chain, and fails
#    closed (no cloud SDK touched) when ACTIVE_RECON is denied.
# ---------------------------------------------------------------------------------------------------------
def test_run_multicloud_drives_the_real_dispatch_gated_fail_closed(monkeypatch, tmp_path):
    pytest.importorskip("framework.v2.verify")
    from framework.v2 import entitlement
    from framework.v2.common import paths

    monkeypatch.setattr(paths, "killswitch_path", lambda slug: tmp_path / f"{slug}.halt")   # kill-switch clear

    def _deny(cap):
        raise PermissionError("active_recon not entitled")

    monkeypatch.setattr(entitlement, "require_capability", _deny)                            # NOT entitled

    signers = _signers()
    gate = _combined_gate()
    sessions = [_session(p, a) for p, a, _ in _PROVIDERS]
    # NOTE: run_cloud_posture_live is NOT patched here — this exercises the REAL dispatch for all four
    # providers. The entitlement gate refuses BEFORE any collector touches a cloud SDK, so no SDK is needed.
    multi = cpr.run_multicloud_posture(sessions, scope_gate=gate, engagement_slug=_SLUG, signers=signers)

    assert multi.providers_assessed == ["aws", "gcp", "azure", "cloudflare"]
    assert multi.total_facts == 0
    # Every provider's real dispatch ran and fell closed with the entitlement gate reason — no clean negative.
    for key, res in multi.results.items():
        assert res.n_facts == 0 and res.family_verdict() != "CLEAN"
        note = " ".join(res.notes).lower()
        assert "gated" in note and ("entitl" in note or "gate=entitlement" in note), (key, res.notes)
    # The combined verdict is INCONCLUSIVE — a gated multi-run is never reported as a clean tenant.
    assert multi.family_verdict() == "INCONCLUSIVE"
    md = cpr.render_multicloud_posture_report(multi, target="acme-tenant")
    assert "PROVEN FACT" not in md and "**Combined verdict:** INCONCLUSIVE" in md


# ---------------------------------------------------------------------------------------------------------
# 6. Two sessions for the SAME provider both count — a provider-key collision never masks a tenant's FACTs.
# ---------------------------------------------------------------------------------------------------------
def test_provider_key_fallback_never_aliases_on_index_account_collision():
    """Regression (red-pen): the ``_provider_key`` fallback must NEVER return a key already in ``existing`` —
    even when an earlier session's account string equals a later same-provider session's positional index
    (account "2" at index 2). A collision there would overwrite/DROP the earlier result and mask its FACTs."""
    class _R:
        def __init__(self, provider, account):
            self.provider = provider
            self.account = account
    existing: dict = {}
    # s0=(aws,'') -> 'aws'; s1=(aws,'2') -> 'aws#2'; s2=(aws,'') at index 2 would alias 'aws#2' under the old code.
    k0 = cpr._provider_key(_R("aws", ""), 0, existing); existing[k0] = 0
    k1 = cpr._provider_key(_R("aws", "2"), 1, existing); existing[k1] = 1
    k2 = cpr._provider_key(_R("aws", ""), 2, existing); existing[k2] = 2
    assert k1 == "aws#2"                      # the account branch keyed s1
    assert k2 not in (k0, k1)                 # s2 did NOT alias/overwrite s0 or s1
    assert len({k0, k1, k2}) == 3             # all three addressable -> no result dropped
    # determinism: the same sequence of (provider, account, index) yields the same keys on a fresh dict
    e3: dict = {}
    r0 = cpr._provider_key(_R("aws", ""), 0, e3); e3[r0] = 0
    r1 = cpr._provider_key(_R("aws", "2"), 1, e3); e3[r1] = 1
    r2 = cpr._provider_key(_R("aws", ""), 2, e3); e3[r2] = 2
    assert (r0, r1, r2) == (k0, k1, k2)       # byte-identical across runs


def test_run_multicloud_same_provider_twice_is_not_masked(monkeypatch):
    pytest.importorskip("framework.v2.verify")
    signers = _signers()
    # Two distinct AWS accounts, both in scope, both with a public bucket.
    acct_a, acct_b = _AWS_ACCOUNT, "444455556666"
    gate = CloudScopeGate(
        scope=StaticCloudScopeSource([CloudScopeEntry(provider="aws", account=acct_a),
                                      CloudScopeEntry(provider="aws", account=acct_b)]),
        engagement_slug=_SLUG)

    def _run(session_data, *, scope_gate, engagement_slug, signers, capture_time_epoch=None,
             tool_context=None, sink=None):
        account = str(getattr(session_data, "account_id", "") or "")
        return cloud_live_verify(_AWS_CAPTURE, provider="aws", account=account, scope_gate=scope_gate,
                                 engagement_slug=engagement_slug, signers=signers,
                                 capture_time_epoch=capture_time_epoch)

    monkeypatch.setattr(cpr, "run_cloud_posture_live", _run)
    sessions = [_session("aws", acct_a), _session("aws", acct_b)]
    multi = cpr.run_multicloud_posture(sessions, scope_gate=gate, engagement_slug=_SLUG, signers=signers,
                                       capture_time_epoch=_CAPTURE_EPOCH)

    # BOTH results are kept under DISTINCT keys (the collision is disambiguated, not dropped), and BOTH tenants'
    # FACTs are counted — a key collision can never mask one account's FACTs.
    assert len(multi.results) == 2
    keys = multi.providers_assessed
    assert keys[0] == "aws" and keys[1].startswith("aws#")      # second keyed deterministically
    per = list(multi.facts_by_provider().values())
    assert all(n >= 1 for n in per)
    assert multi.total_facts == sum(per) == sum(r.n_facts for r in multi.results.values())
    # Both accounts' subjects are bound into their own FACTs (distinct tenants, not conflated).
    accounts_bound = {f.signed.certificate.bound_identity["resource_scope"]["account"]
                      for r in multi.results.values() for f in r.facts}
    assert accounts_bound == {acct_a, acct_b}


# ---------------------------------------------------------------------------------------------------------
# 7. The dataclass shape itself: the three provider-state sets partition the assessed providers, and an empty
#    run is INCONCLUSIVE (never CLEAN) — a pure-DATA check needing no framework (but guarded for parity).
# ---------------------------------------------------------------------------------------------------------
def test_multicloud_result_shape_partitions_and_empty_is_never_clean():
    pytest.importorskip("framework.v2.verify")
    # Hand-built results (no mint) exercising each state: with-facts, refused, inconclusive.
    with_fact = CloudLivePostureResult(provider="aws", account=_AWS_ACCOUNT)
    with_fact.facts.append(object())                            # a stand-in FACT (n_facts == 1)
    refused = CloudLivePostureResult(provider="gcp", account=_GCP_PROJECT, refused=True,
                                     refusal_reason="out of scope")
    inconclusive = CloudLivePostureResult(provider="azure", account=_AZURE_SUB)   # assessed, 0 facts, not refused
    multi = cpr.MultiCloudPostureResult(
        results={"aws": with_fact, "gcp": refused, "azure": inconclusive})

    assert multi.providers_with_facts == ["aws"]
    assert multi.providers_refused == ["gcp"]
    assert multi.providers_inconclusive == ["azure"]
    # The three state sets PARTITION the assessed providers (disjoint, covering) — no provider is both counted
    # as clean and unassessed, and none is dropped.
    assert set(multi.providers_with_facts) | set(multi.providers_refused) \
        | set(multi.providers_inconclusive) == set(multi.providers_assessed)
    assert not (set(multi.providers_refused) & set(multi.providers_inconclusive))
    assert multi.total_facts == 1 and multi.family_verdict() == "FACT"

    # An empty unified run (no providers) is INCONCLUSIVE, never CLEAN.
    empty = cpr.MultiCloudPostureResult()
    assert empty.providers_assessed == [] and empty.total_facts == 0
    assert empty.family_verdict() == "INCONCLUSIVE"
