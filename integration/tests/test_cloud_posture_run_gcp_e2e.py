"""Wave B.3 — the FIRST real GCP end-to-end, proven against a fake-google-backed Cloud Storage / project IAM.

The GCP twin of ``test_cloud_posture_run_e2e`` (AWS/moto). The whole offense-leg chain, over a FAKE (in-process
``sys.modules`` google) GCP project, as pure glue:

    mint a read-only customer session as DATA (the duck shape a GCP vigil_core MintedSession satisfies:
      provider="gcp", account_id=<project>, bearer_token=<OAuth2 token>)
      -> COLLECT the real inventory with the EXISTING ``GcpLiveSensor`` as THAT identity (never VIGIL's ambient
         ADC — ``require_injected_credentials=True``), under an in-process google fake
      -> ``run_cloud_posture_live`` DISPATCHES on provider=gcp, D5-scope-gates the capture and re-fires the
         EXISTING deterministic ``cloud_posture`` + ``policy_path`` oracles over the RETAINED export, minting a
         signed FACT per confirmed insecure subject
      -> each FACT's certificate re-verifies OFFLINE with the retained capture bytes (and fails closed on a
         1-byte swap / missing bytes)
      -> the report adapter renders each FACT as a PROVEN FACT with its re-runnable certificate reference.

The fake project carries the TRUE POSITIVE (a GCS bucket with an UNCONDITIONED ``allUsers`` grant, the bucket
not enforcing PAP and the effective org policy NOT enforcing — the two-scope rule promotes it) AND the
near-zero-FP negative-control TRAPS that must NOT promote (a Condition-narrowed anon binding; a bucket that
enforces PAP). The oracle, not the collector's say-so, decides (criterion 6). (The fake ALSO exercises the
project-IAM collection path, but project-level public-grant SIGNAL surfacing is the collector's own concern —
covered by ``test_gcp_live`` — so this GLUE E2E asserts only the bucket promotion/non-promotion it drives, and
makes no project-level claim it does not actually exercise.)

Unlike the AWS E2E (which needs real boto3/moto and SKIPS where they are absent), this E2E fakes the google
SDK surface in-process — exactly the pattern ``test_gcp_live_injected_credentials`` uses — so it RUNS IN CI
with no google libs installed. The injected bearer must reach the google client (spy) and the ambient ADC must
never be consulted. ``framework`` is imported function-locally behind ``importorskip('framework.v2.verify')``,
so this runs in the OFFENSE leg and skips (never fails) in the sovereign leg.
"""
from __future__ import annotations

import json
import sys
import types
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

# The minted session's claimed project (GCP's tenant identity — ``account_id`` IS the project id).
PROJECT = "acme-prod-847163"

# The INJECTED read-only OAuth2 bearer (the shape a GCP MintedSession exposes). Deliberately DISTINCT from the
# dummy AMBIENT token the fake ADC would mint, so a dropped-injection regression (a silent fall-back to VIGIL's
# ambient ADC) is caught by the spy assertion.
INJECTED_BEARER = "ya29.injected-scoped-read-only-token"
AMBIENT_BEARER = "ya29.AMBIENT-ADC-MUST-NOT-BE-USED"


class _Creds:
    """A plain, duck-typed minted read-only GCP session (``provider`` / ``account_id`` [the project] /
    ``bearer_token``) — the exact shape a ``vigil_core.cloud_session.MintedSession`` for a GCP provider
    satisfies. We model the sovereign crossing in-process with this fake; the real crossing is deferred to a
    later wave. Fields are overridable so a test can forge a PARTIAL (missing bearer) or non-GCP session."""

    def __init__(self, *, provider: str = "gcp", account_id: str = PROJECT,
                 bearer_token: str = INJECTED_BEARER) -> None:
        self.provider = provider
        self.account_id = account_id
        self.bearer_token = bearer_token


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
    """A project-only in-scope gate: the charter authorises (gcp, PROJECT), any region/resource — so every
    captured subject in the seeded project is authorised and the capture mints over the real export."""
    return CloudScopeGate(
        scope=StaticCloudScopeSource([CloudScopeEntry(provider="gcp", account=PROJECT)]),
        engagement_slug="acme",
    )


def _grant_gates(monkeypatch, tmp_path):
    """Provision a PASSING engagement posture so invoke_tool's W1.4 gate chain lets the live collection run:
    the kill-switch is clear, the ACTIVE_RECON entitlement is granted, and the customer's control-plane hosts
    are on the egress allowlist. Mirrors the AWS E2E (the gate-REFUSAL path is proven dep-free in
    test_cloud_posture_run_gcp_report)."""
    from framework.v2 import entitlement
    from framework.v2.agents import egress_guard
    from framework.v2.common import paths

    monkeypatch.setattr(paths, "killswitch_path", lambda slug: tmp_path / f"{slug}.halt")   # kill-switch clear
    monkeypatch.setattr(entitlement, "require_capability", lambda cap: None)                 # ACTIVE_RECON granted
    monkeypatch.setattr(egress_guard, "build_engagement_allowlist",
                        lambda **k: SimpleNamespace(permits=lambda host: True))              # control-plane allowed


def _install_fake_google(monkeypatch, *, forbid_ambient: bool = True) -> dict:
    """Fake the google SDK surface the REAL ``GcpLiveSensor`` reads at collection time, via ``sys.modules``
    (the pattern ``test_gcp_live_injected_credentials`` uses) — no google-auth / google-cloud install, no
    network. The fake SEEDS the project (the collector only READS):

      * ``google.oauth2.credentials.Credentials`` — records every token it is built from;
      * ``google.cloud.storage.Client`` — records the credentials it is handed and serves the seeded buckets;
      * ``google.cloud.orgpolicy_v2.OrgPolicyClient`` — serves an effective PAP policy that is NOT enforcing
        (so the inherited public bucket is confirmed by the two-scope rule);
      * ``google.cloud.resourcemanager_v3.ProjectsClient`` — serves a project IAM policy (a real principal +
        an anon binding) so ``_collect_project_iam`` is exercised without crashing (this glue E2E makes no
        project-level SIGNAL/FACT assertion — that is ``test_gcp_live``'s unit concern);
      * ``google.auth.default`` — RECORDS a call and, when ``forbid_ambient``, RAISES, so an injected run that
        touched the ambient chain fails loudly.

    Returns a recorder dict so a test can prove the injected bearer flowed to the clients and ADC was untouched.
    """
    rec: dict = {"cred_tokens": [], "adc_called": False, "client_creds": []}

    class _Credentials:
        def __init__(self, *, token=None, scopes=None, **kw):
            rec["cred_tokens"].append(token)
            self.token = token
            self.scopes = scopes

    class _IamConfig:
        def __init__(self, pap):
            self.public_access_prevention = pap

    class _Policy:
        def __init__(self, bindings):
            self.bindings = bindings

    class _Bucket:
        def __init__(self, name, *, bindings, pap, labels=None):
            self.name = name
            self._bindings = bindings
            self.iam_configuration = _IamConfig(pap)
            self.labels = labels or {}

        def get_iam_policy(self, **kw):
            return _Policy(self._bindings)

        def reload(self):
            return None

    # TRUE POSITIVE + the near-zero-FP traps (seeded; the collector only reads these).
    _BUCKETS = [
        # TRUE POSITIVE: an UNCONDITIONED allUsers grant, bucket PAP 'inherited' (+ org NOT enforcing below)
        # -> the two-scope rule CONFIRMS public -> a FACT.
        _Bucket("acme-public-assets", bindings=[{"members": ["allUsers"], "condition": None}], pap="inherited"),
        # TRAP: a Condition-narrowed anon binding -> retained as an audit signal only, NEVER promoted.
        _Bucket("acme-cond-share",
                bindings=[{"members": ["allAuthenticatedUsers"],
                           "condition": {"title": "t", "expression": "request.time < timestamp('2030-01-01T00:00:00Z')"}}],
                pap="inherited"),
        # TRAP: an unconditioned allUsers grant but the bucket ENFORCES PAP -> never public.
        _Bucket("acme-enforced", bindings=[{"members": ["allUsers"], "condition": None}], pap="enforced"),
    ]

    class _StorageClient:
        def __init__(self, *, project=None, credentials=None, **kw):
            rec["client_creds"].append(("storage", getattr(credentials, "token", None)))
            self.project = project

        def list_buckets(self):
            return list(_BUCKETS)

    class _OrgRule:
        enforce = False       # NOT enforcing (so the inherited public bucket is confirmed)
        condition = None

    class _OrgEff:
        spec = SimpleNamespace(rules=[_OrgRule()])

    class _OrgPolicyClient:
        def __init__(self, *, credentials=None, **kw):
            rec["client_creds"].append(("orgpolicy", getattr(credentials, "token", None)))

        def get_effective_policy(self, *, name=None, **kw):
            return _OrgEff()

    class _ProjectsClient:
        def __init__(self, *, credentials=None, **kw):
            rec["client_creds"].append(("resourcemanager", getattr(credentials, "token", None)))

        def get_iam_policy(self, *, resource=None, **kw):
            # a project-IAM allUsers grant (auditable public_roles signal, NOT a FACT) + a real principal.
            return _Policy([{"members": ["allUsers"], "condition": None},
                            {"members": ["user:admin@acme.com"], "condition": None}])

    def _adc_default(*a, **k):
        rec["adc_called"] = True
        if forbid_ambient:
            raise AssertionError("ambient google.auth.default() must not be consulted on an injected run")
        return _Credentials(token=AMBIENT_BEARER), "ambient-adc-project"

    google = types.ModuleType("google")
    g_auth = types.ModuleType("google.auth")
    g_auth.default = _adc_default  # type: ignore[attr-defined]
    g_oauth2 = types.ModuleType("google.oauth2")
    g_oauth2_creds = types.ModuleType("google.oauth2.credentials")
    g_oauth2_creds.Credentials = _Credentials  # type: ignore[attr-defined]
    g_cloud = types.ModuleType("google.cloud")
    g_cloud_storage = types.ModuleType("google.cloud.storage")
    g_cloud_storage.Client = _StorageClient  # type: ignore[attr-defined]
    g_cloud_orgpolicy = types.ModuleType("google.cloud.orgpolicy_v2")
    g_cloud_orgpolicy.OrgPolicyClient = _OrgPolicyClient  # type: ignore[attr-defined]
    g_cloud_rm = types.ModuleType("google.cloud.resourcemanager_v3")
    g_cloud_rm.ProjectsClient = _ProjectsClient  # type: ignore[attr-defined]
    google.auth = g_auth  # type: ignore[attr-defined]
    google.oauth2 = g_oauth2  # type: ignore[attr-defined]
    g_oauth2.credentials = g_oauth2_creds  # type: ignore[attr-defined]
    google.cloud = g_cloud  # type: ignore[attr-defined]
    g_cloud.storage = g_cloud_storage  # type: ignore[attr-defined]
    g_cloud.orgpolicy_v2 = g_cloud_orgpolicy  # type: ignore[attr-defined]
    g_cloud.resourcemanager_v3 = g_cloud_rm  # type: ignore[attr-defined]
    for name, mod in {
        "google": google, "google.auth": g_auth, "google.oauth2": g_oauth2,
        "google.oauth2.credentials": g_oauth2_creds, "google.cloud": g_cloud,
        "google.cloud.storage": g_cloud_storage, "google.cloud.orgpolicy_v2": g_cloud_orgpolicy,
        "google.cloud.resourcemanager_v3": g_cloud_rm,
    }.items():
        monkeypatch.setitem(sys.modules, name, mod)
    return rec


def _fact_subjects(result) -> set:
    """The ACTUAL subject id bound into each minted FACT's certificate (never the shared request glob)."""
    out = set()
    for f in result.facts:
        out.add(f.signed.certificate.bound_identity["resource_scope"]["resource"])
    return out


def test_cloud_posture_run_gcp_e2e(monkeypatch, tmp_path):
    """Mint -> collect (real GcpLiveSensor, google-fake) -> oracle re-fire -> signed FACT -> offline verify
    -> report, dispatched on provider=gcp."""
    from framework.v2.evidence.certify import verify_certificate
    from framework.v2.sensors.cloud import confirm_cloud_posture_facts, normalize_cloud_export
    from framework.v2.sensors.gcp_live import GcpLiveSensor
    from framework.v2.verify.policy_path import build_policy_graph, policy_path_context
    from framework.v2.verify.verifier import OracleVerifier

    rec = _install_fake_google(monkeypatch, forbid_ambient=True)
    _grant_gates(monkeypatch, tmp_path)    # a properly-provisioned posture: the gated collection runs
    signers, tr = _signers_and_trust()
    creds = _Creds()  # the minted DATA session (provider=gcp, account_id=project, bearer_token=injected)

    # -- STEP 3: COLLECT via the REAL sensor under the google fake, as the injected identity. --
    collect = GcpLiveSensor(credentials=creds, require_injected_credentials=True).run({}, SimpleNamespace())
    assert collect.ok, collect.note
    assert collect.output["format"] == "native"
    assert collect.output.get("provider") == "gcp"
    assert collect.output.get("project") == PROJECT
    # CREDENTIAL ISOLATION: the INJECTED bearer (not the ambient ADC) reached the google credentials AND the
    # google clients (storage / orgpolicy / resourcemanager); ambient ADC was NEVER consulted.
    assert INJECTED_BEARER in rec["cred_tokens"] and AMBIENT_BEARER not in rec["cred_tokens"]
    assert rec["client_creds"] and all(tok == INJECTED_BEARER for _svc, tok in rec["client_creds"]), rec["client_creds"]
    assert rec["adc_called"] is False

    # -- STEP 4: the oracle FIRES over the COLLECTED data (the real export the sensor just produced). --
    export = collect.output["export"]
    inv = normalize_cloud_export(json.loads(export), "native")
    pub_facts = [pf for pf in confirm_cloud_posture_facts(inv) if pf.get("lead_class") == "public_exposure"]
    reached = {pf["resource"] for pf in pub_facts}
    assert "acme-public-assets" in reached, reached
    # NEGATIVE-CONTROL TRAPS held (never promoted by the oracle over the collected inventory) — each
    # DISCRIMINATES on exactly one variable vs. the true positive: acme-cond-share (same shape but the anon
    # binding is Condition-narrowed) and acme-enforced (same unconditioned allUsers but the bucket ENFORCES PAP).
    assert "acme-cond-share" not in reached, reached
    assert "acme-enforced" not in reached, reached
    # inspect a LIVE oracle SIGNAL's .fired over the public bucket's grant path (never a stubbed verdict):
    acme = next(pf for pf in pub_facts if pf["resource"] == "acme-public-assets")
    vr = OracleVerifier().confirm(
        policy_path_context(build_policy_graph(inv), acme["principal"], acme["resource"], acme["access"]))
    assert vr.confirmed and any(getattr(s, "fired", False) for s in (vr.signals or []))

    # -- STEP 4b: run_cloud_posture_live DISPATCHES on gcp, runs the collector THROUGH the gated invoke_tool
    #    chain, and mints signed FACTs over the retained export. --
    result = run_cloud_posture_live(
        creds, scope_gate=_gate(), engagement_slug="acme", signers=signers,
        capture_time_epoch=1_700_000_000)
    assert result.refused is False and result.n_facts >= 1, result.admissions
    assert result.provider == "gcp" and result.account == PROJECT

    subjects = _fact_subjects(result)
    assert "acme-public-assets" in subjects, subjects
    # NEGATIVE-CONTROL TRAPS held (never minted — the condition-narrowed and PAP-enforced buckets):
    assert "acme-cond-share" not in subjects, subjects
    assert "acme-enforced" not in subjects, subjects

    # -- STEP 5: each FACT's certificate RE-VERIFIES OFFLINE (+ negative controls). Pure, no google fake. --
    for f in result.facts:
        ctx = result.contexts[f.finding_ref]
        cert = f.signed.certificate
        assert cert.capture_method == "api:list"                # a VIGIL-owned live read, not an artifact
        assert cert.bound_identity["resource_scope"]["provider"] == "gcp"
        assert cert.bound_identity["resource_scope"]["account"] == PROJECT      # GCP: account IS the project id
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
    md = render_cloud_posture_report(result, target=f"gcp:{PROJECT}")
    assert "PROVEN FACT" in md
    assert "sha256:" in md
    assert "framework.v2 verify" in md
    assert "oracle-confirmed fact(s)" in md


def test_partial_gcp_session_fails_closed_through_run_cloud_posture_live(monkeypatch, tmp_path):
    """CREDENTIAL ISOLATION through the orchestrator: a PARTIAL minted GCP session (a missing OAuth2 bearer)
    makes the dispatched GcpLiveSensor fail CLOSED inside the gated chain — ``run_cloud_posture_live`` returns a
    no-FACT, never-CLEAN result carrying the no-identity-substitution reason. It NEVER falls back to VIGIL's
    ambient ADC. The gates are GRANTED so the refusal is the collector's own fail-closed (not merely a gate
    refusal), and no google libs are needed — the sensor rejects the partial session before any google import,
    so the ambient fake is installed with forbid_ambient to prove ADC is never reached."""
    rec = _install_fake_google(monkeypatch, forbid_ambient=True)
    _grant_gates(monkeypatch, tmp_path)
    signers, _ = _signers_and_trust()

    partial = _Creds(bearer_token="")   # no bearer -> the collector must fail closed, never ambient
    result = run_cloud_posture_live(
        partial, scope_gate=_gate(), engagement_slug="acme", signers=signers, capture_time_epoch=1_700_000_000)

    assert result.n_facts == 0 and result.family_verdict() != "CLEAN"
    assert result.provider == "gcp" and result.account == PROJECT
    note = " ".join(result.notes).lower()
    assert "no identity substitution" in note, result.notes
    assert rec["adc_called"] is False and rec["cred_tokens"] == []   # no google credential ever built
