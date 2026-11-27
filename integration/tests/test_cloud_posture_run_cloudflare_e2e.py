"""Phase C2 · Cloudflare — the FIRST real Cloudflare end-to-end, proven against a fake-transport-backed R2.

The Cloudflare twin of ``test_cloud_posture_run_gcp_e2e`` (GCP/google-fake) and ``test_cloud_posture_run_e2e``
(AWS/moto). The whole offense-leg chain, over a FAKE (in-process, recording) Cloudflare R2 control plane, as
pure glue:

    hand the collector a FRESH per-run read-only Cloudflare session as DATA (the duck shape a Cloudflare grant
      yields — ``provider="cloudflare"``, ``account_id=<32-hex account>``, ``bearer_token=<API token>``; there
      is deliberately NO MintedSession for Cloudflare, see ``sensors.cloudflare_live`` docstring)
      -> COLLECT the real inventory with the EXISTING ``CloudflareLiveSensor`` as THAT identity (never any
         ambient identity — Cloudflare HAS none — ``require_injected_credentials=True``), under a RECORDING
         fake Cloudflare API transport
      -> ``run_cloud_posture_live`` DISPATCHES on provider=cloudflare, D5-scope-gates the capture and re-fires
         the EXISTING deterministic ``cloud_posture`` + ``policy_path`` oracles over the RETAINED export,
         minting a signed FACT per confirmed-public bucket
      -> each FACT's certificate re-verifies OFFLINE with the retained capture bytes (and fails closed on a
         1-byte swap / missing bytes)
      -> the report adapter renders each FACT as a PROVEN FACT with its re-runnable certificate reference.

The fake account carries the TRUE POSITIVE (an R2 bucket whose MANAGED public dev URL ``*.r2.dev`` is
``enabled: true`` — the single confirming scope R2 has, so a confirmed anonymous ``*`` read grant the
policy-path oracle promotes) AND the discriminating near-zero-FP negative control that must NOT promote (a
bucket with the managed URL NOT enabled but a custom domain bound — retained as an auditable
``r2_custom_domains`` SIGNAL only, never a public FACT, since a custom domain can sit behind Cloudflare Access /
a firewall). The oracle, not the collector's say-so, decides (criterion 6).

HOW THE REAL COLLECTOR + REAL ORACLE RUN WITHOUT NETWORK. There is NO vendor Cloudflare SDK to fake in
``sys.modules`` (unlike GCP's google / AWS's boto3): the collector's ONLY egress is the module-level
``cloudflare_live._http_get`` (stdlib ``urllib``, host-pinned to ``api.cloudflare.com``), behind an injectable
``transport`` seam of the SAME ``(url, headers, timeout) -> (status, bytes)`` shape. So the two legs the GCP
E2E split (direct COLLECT vs orchestrator DISPATCH) are driven here through that one seam, two ways:

  * the direct COLLECT asserts credential isolation through the ``transport=`` constructor seam (the real
    sensor, the real host ``_guard`` — ``_get`` guards the URL before calling the injected transport);
  * the orchestrator DISPATCH (``run_cloud_posture_live``, which builds the sensor itself with NO transport)
    runs the REAL collector end-to-end by monkeypatching ``cloudflare_live._http_get`` with the SAME recording
    fake — so the gated ``invoke_tool`` chain, the provider dispatch, the oracle re-fire, the signed FACT, the
    offline re-verify and the report are ALL exercised, with the injected bearer flowing through the live
    ``_http_get`` seam and never a byte of real network.

``framework`` is imported function-locally behind ``importorskip('framework.v2.verify')``, so this runs in the
OFFENSE leg and skips (never fails) in the sovereign leg where framework is unimportable — exactly like the
AWS/GCP siblings.
"""
from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

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

# The injected session's claimed Cloudflare account — exactly 32 lowercase hex (the collector refuses any other
# shape before it builds a URL, so a malformed id can never be path-injected into the R2 endpoint).
ACCOUNT = "0123456789abcdef0123456789abcdef"

# The INJECTED per-run read-only Cloudflare API token (a fresh bearer secret the customer hands over — VIGIL
# never stores it; there is no re-mintable MintedSession for Cloudflare). SYNTHETIC — no real secret in the
# tree. ``OTHER_TOKEN`` is a DISTINCT dummy, asserted NEVER used, so a dropped-injection regression (a silent
# fall-back to some other identity) would be caught — though Cloudflare has no ambient identity to fall back TO.
INJECTED_TOKEN = "cf-injected-scoped-read-only-token_ABC123"
OTHER_TOKEN = "cf-OTHER-IDENTITY-must-not-be-used"

# The TRUE POSITIVE and the discriminating negative control, seeded into the fake R2 account (the collector
# only READS these). ``open`` — managed ``*.r2.dev`` ENABLED -> confirmed public -> a FACT. ``cdn`` — managed
# NOT enabled but a custom domain bound -> an auditable signal, NEVER promoted (discriminates on exactly the
# managed-enabled variable vs. the true positive).
_SEED_BUCKETS = {"open": {"managed": True},
                 "cdn": {"managed": False, "customs": [("cdn.acme.com", True)]}}
_TRUE_POSITIVE = f"{ACCOUNT}/open"
_NEGATIVE_CONTROL = f"{ACCOUNT}/cdn"


class _Creds:
    """A plain, duck-typed per-run read-only Cloudflare session (``provider`` / ``account_id`` [the 32-hex
    Cloudflare account] / ``bearer_token`` [the fresh per-run API token]) — the exact shape the Cloudflare grant
    hands the collector. We model the sovereign crossing in-process with this fake; the real crossing is
    deferred to a later wave. Fields are overridable so a test can forge a PARTIAL (missing token) or
    non-Cloudflare session."""

    def __init__(self, *, provider: str = "cloudflare", account_id: str = ACCOUNT,
                 bearer_token: str = INJECTED_TOKEN) -> None:
        self.provider = provider
        self.account_id = account_id
        self.bearer_token = bearer_token


def _fake_cloudflare(*, buckets):
    """A RECORDING fake Cloudflare API ``(url, headers, timeout) -> (status, bytes)`` — the SAME shape the
    collector's ``transport`` seam AND its module-level ``_http_get`` take, so one fake drives both legs. It
    records the ``Authorization`` header of EVERY call (the injected-token spy) and serves recorded R2
    read-only JSON for the seeded ``buckets`` (a map ``name -> {"managed": bool, "customs": [(domain, en), …]}``).
    No network, no vendor SDK — exactly the pattern ``test_cloudflare_live_injected_credentials`` uses."""
    rec = {"auth": [], "urls": []}

    def transport(url, headers, timeout):
        rec["auth"].append(headers.get("Authorization"))
        rec["urls"].append(url)

        def body(doc):
            return 200, json.dumps(doc).encode("utf-8")

        if url.endswith(f"/accounts/{ACCOUNT}/r2/buckets"):
            return body({"success": True, "result": {"buckets": [{"name": n} for n in buckets]}})
        for name, spec in buckets.items():
            if url.endswith(f"/r2/buckets/{name}/domains/managed"):
                return body({"success": True, "result": {"enabled": bool(spec.get("managed"))}})
            if url.endswith(f"/r2/buckets/{name}/domains/custom"):
                domains = [{"domain": d, "enabled": en} for d, en in spec.get("customs", [])]
                return body({"success": True, "result": {"domains": domains}})
        return body({"success": False, "errors": [{"code": 7003}]})

    return transport, rec


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
    """An account-only in-scope gate: the charter authorises (cloudflare, ACCOUNT), any resource — so every
    captured R2 bucket in the seeded account is authorised and the capture mints over the real export."""
    return CloudScopeGate(
        scope=StaticCloudScopeSource([CloudScopeEntry(provider="cloudflare", account=ACCOUNT)]),
        engagement_slug="acme",
    )


def _grant_gates(monkeypatch, tmp_path):
    """Provision a PASSING engagement posture so invoke_tool's W1.4 gate chain lets the live collection run:
    the kill-switch is clear, the ACTIVE_RECON entitlement is granted, and the customer's control-plane host is
    on the egress allowlist. Mirrors the GCP E2E (the gate-REFUSAL path is proven dep-free in
    test_cloud_posture_run_cloudflare_report)."""
    from framework.v2 import entitlement
    from framework.v2.agents import egress_guard
    from framework.v2.common import paths

    monkeypatch.setattr(paths, "killswitch_path", lambda slug: tmp_path / f"{slug}.halt")   # kill-switch clear
    monkeypatch.setattr(entitlement, "require_capability", lambda cap: None)                 # ACTIVE_RECON granted
    monkeypatch.setattr(egress_guard, "build_engagement_allowlist",
                        lambda **k: SimpleNamespace(permits=lambda host: True))              # control-plane allowed


def _fact_subjects(result) -> set:
    """The ACTUAL subject id bound into each minted FACT's certificate (never the shared request glob)."""
    return {f.signed.certificate.bound_identity["resource_scope"]["resource"] for f in result.facts}


def test_cloud_posture_run_cloudflare_e2e(monkeypatch, tmp_path):
    """Inject -> collect (real CloudflareLiveSensor, fake transport) -> oracle re-fire -> signed FACT -> offline
    verify -> report, dispatched on provider=cloudflare."""
    import framework.v2.sensors.cloudflare_live as cf_live
    from framework.v2.evidence.certify import verify_certificate
    from framework.v2.sensors.cloud import confirm_cloud_posture_facts, normalize_cloud_export
    from framework.v2.sensors.cloudflare_live import CloudflareLiveSensor
    from framework.v2.verify.policy_path import build_policy_graph, policy_path_context
    from framework.v2.verify.verifier import OracleVerifier

    signers, tr = _signers_and_trust()
    creds = _Creds()  # the injected DATA session (provider=cloudflare, account_id=ACCOUNT, bearer_token=injected)

    # -- STEP 3: COLLECT via the REAL sensor under the fake transport, as the injected identity. --
    transport_direct, rec_direct = _fake_cloudflare(buckets=_SEED_BUCKETS)
    collect = CloudflareLiveSensor(
        credentials=creds, require_injected_credentials=True, transport=transport_direct).run({}, SimpleNamespace())
    assert collect.ok, collect.note
    assert collect.output["format"] == "native"
    assert collect.output.get("provider") == "cloudflare"
    assert collect.output.get("account") == ACCOUNT
    # CREDENTIAL ISOLATION: the INJECTED bearer reached EVERY transport call (the list + each bucket's managed
    # + custom read), and NO other identity was ever used. Cloudflare has no ambient identity to substitute, so
    # a single foreign Bearer would be an unambiguous leak.
    assert rec_direct["urls"] and set(rec_direct["auth"]) == {f"Bearer {INJECTED_TOKEN}"}, rec_direct["auth"]
    assert OTHER_TOKEN not in " ".join(a or "" for a in rec_direct["auth"])
    # NO TOKEN LEAK: the injected token rides ONLY in the Authorization header — never in the ToolResult.
    blob = f"{collect.summary}\n{getattr(collect, 'note', '')}\n{collect.output}"
    assert INJECTED_TOKEN not in blob

    # -- STEP 4: the oracle FIRES over the COLLECTED data (the real export the sensor just produced). --
    export = collect.output["export"]
    inv = normalize_cloud_export(json.loads(export), "native")
    pub_facts = [pf for pf in confirm_cloud_posture_facts(inv) if pf.get("lead_class") == "public_exposure"]
    reached = {pf["resource"] for pf in pub_facts}
    assert _TRUE_POSITIVE in reached, reached
    # NEGATIVE CONTROL held (never promoted by the oracle over the collected inventory): it DISCRIMINATES on
    # exactly one variable vs. the true positive — same R2 bucket shape, but the managed ``*.r2.dev`` URL is
    # NOT enabled (only a custom domain is bound), so its anonymous reach is not confirmed by this read.
    assert _NEGATIVE_CONTROL not in reached, reached
    # the negative control IS retained as an auditable custom-domain SIGNAL (not silently dropped).
    cdn = next(r for r in inv["resources"] if r["id"] == _NEGATIVE_CONTROL)
    assert "public" not in cdn and cdn.get("r2_custom_domains") == ["cdn.acme.com"]
    # inspect a LIVE oracle SIGNAL's .fired over the public bucket's grant path (never a stubbed verdict):
    tp = next(pf for pf in pub_facts if pf["resource"] == _TRUE_POSITIVE)
    vr = OracleVerifier().confirm(
        policy_path_context(build_policy_graph(inv), tp["principal"], tp["resource"], tp["access"]))
    assert vr.confirmed and any(getattr(s, "fired", False) for s in (vr.signals or []))

    # -- STEP 4b: run_cloud_posture_live DISPATCHES on cloudflare, runs the collector THROUGH the gated
    #    invoke_tool chain, and mints signed FACTs over the retained export. The orchestrator builds the sensor
    #    with NO transport, so the REAL collector runs end-to-end through the module-level ``_http_get`` seam —
    #    monkeypatched with the SAME recording fake, so no byte of real network is touched. --
    transport_orch, rec_orch = _fake_cloudflare(buckets=_SEED_BUCKETS)
    monkeypatch.setattr(cf_live, "_http_get", transport_orch)   # the live egress seam -> the recording fake
    _grant_gates(monkeypatch, tmp_path)                         # a properly-provisioned posture: the gate lets it run
    result = run_cloud_posture_live(
        creds, scope_gate=_gate(), engagement_slug="acme", signers=signers,
        capture_time_epoch=1_700_000_000)
    assert result.refused is False and result.n_facts >= 1, result.admissions
    assert result.provider == "cloudflare" and result.account == ACCOUNT
    # the injected bearer flowed through the LIVE ``_http_get`` seam of the orchestrator-built (transport-less)
    # collector — no other identity, ever.
    assert rec_orch["urls"] and set(rec_orch["auth"]) == {f"Bearer {INJECTED_TOKEN}"}, rec_orch["auth"]

    subjects = _fact_subjects(result)
    assert _TRUE_POSITIVE in subjects, subjects
    # NEGATIVE CONTROL held (never minted — the managed-not-enabled, custom-domain-only bucket):
    assert _NEGATIVE_CONTROL not in subjects, subjects

    # -- STEP 5: each FACT's certificate RE-VERIFIES OFFLINE (+ negative controls). Pure, no fake transport. --
    for f in result.facts:
        ctx = result.contexts[f.finding_ref]
        cert = f.signed.certificate
        assert cert.capture_method == "api:list"                # a VIGIL-owned live read, not an artifact
        assert cert.bound_identity["resource_scope"]["provider"] == "cloudflare"
        assert cert.bound_identity["resource_scope"]["account"] == ACCOUNT
        assert cert.bound_identity.get("capture_time_epoch") == 1_700_000_000   # deterministic, operator-set
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
    md = render_cloud_posture_report(result, target=f"cloudflare:{ACCOUNT}")
    assert "PROVEN FACT" in md
    assert "sha256:" in md
    assert "framework.v2 verify" in md
    assert "oracle-confirmed fact(s)" in md
    # NO TOKEN LEAK, end to end: the injected token appears in neither the result nor the rendered report.
    assert INJECTED_TOKEN not in f"{result.notes}\n{result.admissions}\n{md}"


def test_partial_cloudflare_session_fails_closed_through_run_cloud_posture_live(monkeypatch, tmp_path):
    """CREDENTIAL ISOLATION through the orchestrator: a PARTIAL injected Cloudflare session (a missing API
    token) makes the dispatched CloudflareLiveSensor fail CLOSED inside the gated chain —
    ``run_cloud_posture_live`` returns a no-FACT, never-CLEAN result carrying the no-identity-substitution
    reason. Cloudflare has NO ambient identity to fall back to, so the refusal precedes any HTTP: the live
    ``_http_get`` seam (monkeypatched to EXPLODE) is never reached. The gates are GRANTED so the refusal is the
    collector's own fail-closed, not merely a gate refusal."""
    import framework.v2.sensors.cloudflare_live as cf_live

    def _explode(*a, **k):   # the live egress seam must never be reached on a partial session
        raise AssertionError("no Cloudflare HTTP call may be made for a partial session (no identity substitution)")

    monkeypatch.setattr(cf_live, "_http_get", _explode)
    _grant_gates(monkeypatch, tmp_path)
    signers, _ = _signers_and_trust()

    partial = _Creds(bearer_token="")   # no token -> the collector must fail closed, never substitute an identity
    result = run_cloud_posture_live(
        partial, scope_gate=_gate(), engagement_slug="acme", signers=signers, capture_time_epoch=1_700_000_000)

    assert result.n_facts == 0 and result.family_verdict() != "CLEAN"
    assert result.provider == "cloudflare" and result.account == ACCOUNT
    note = " ".join(result.notes).lower()
    assert "no identity substitution" in note, result.notes
