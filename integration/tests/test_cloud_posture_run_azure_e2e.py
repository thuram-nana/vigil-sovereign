"""Wave B.3 — the FIRST real AZURE end-to-end, proven against a fake-azure-backed Storage / RBAC control plane.

The Azure twin of ``test_cloud_posture_run_gcp_e2e`` (GCP/google-fake) and ``test_cloud_posture_run_e2e``
(AWS/moto). The whole offense-leg chain, over a FAKE (in-process ``sys.modules`` azure) Azure subscription, as
pure glue:

    mint a read-only customer session as DATA (the duck shape an Azure vigil_core MintedSession satisfies:
      provider="azure", account_id=<subscription>, bearer_token=<injected AAD bearer>)
      -> COLLECT the real inventory with the EXISTING ``AzureLiveSensor`` as THAT identity (never VIGIL's
         ambient ``DefaultAzureCredential`` — ``require_injected_credentials=True``), under an in-process azure
         fake
      -> ``run_cloud_posture_live`` DISPATCHES on provider=azure, D5-scope-gates the capture and re-fires the
         EXISTING deterministic ``cloud_posture`` + ``policy_path`` oracles over the RETAINED export, minting a
         signed FACT per confirmed insecure subject
      -> each FACT's certificate re-verifies OFFLINE with the retained capture bytes (and fails closed on a
         1-byte swap / missing bytes)
      -> the report adapter renders each FACT as a PROVEN FACT with its re-runnable certificate reference.

The fake subscription carries the TRUE POSITIVE (a blob container whose ``publicAccess`` is ``Container``, in a
storage account that both ALLOWS public blob access AND is internet-open — Azure's THREE-SCOPE rule promotes it)
AND the near-zero-FP negative-control TRAPS that must NOT promote, each DISCRIMINATING on exactly one of the
three scopes: a private container in the same (public-allowed, internet-open) account; a public container in an
account that FORBIDS public blob access; and a public container in a FIREWALLED (``defaultAction=Deny``)
account. The oracle, not the collector's say-so, decides (criterion 6). (The fake ALSO exercises the RBAC
topology path — a real role assignment principal — but Azure RBAC has no anonymous principal, so this GLUE E2E
asserts only the blob-container promotion/non-promotion it drives and makes no RBAC-level FACT claim.)

Like the GCP E2E (and unlike the AWS E2E, which needs real boto3/moto and SKIPS where they are absent), this
E2E fakes the azure SDK surface in-process — exactly the pattern ``test_azure_live_injected_credentials`` uses —
so it RUNS IN CI with no azure libs installed. The injected bearer must reach every azure client (spy) and the
ambient ``DefaultAzureCredential`` must never be consulted. ``framework`` is imported function-locally behind
``importorskip('framework.v2.verify')``, so this runs in the OFFENSE leg and skips (never fails) in the
sovereign leg.
"""
from __future__ import annotations

import json
import sys
import types
from collections import namedtuple
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

# The minted session's claimed subscription (Azure's tenant identity — ``account_id`` IS the subscription id).
SUBSCRIPTION = "11111111-2222-3333-4444-555555555555"

# The INJECTED read-only AAD bearer (the shape an Azure MintedSession exposes). Deliberately DISTINCT from the
# dummy AMBIENT token the fake DefaultAzureCredential would mint, so a dropped-injection regression (a silent
# fall-back to VIGIL's ambient Azure identity) is caught by the spy assertion.
INJECTED_BEARER = "aad.injected-scoped-read-only-token"
AMBIENT_BEARER = "aad.AMBIENT-IDENTITY-MUST-NOT-BE-USED"

# The seeded storage accounts / blob containers. Account names are lowercase (as real Azure storage account
# names are), so each resource id ``<account>/<container>`` is already canonical (raw == graph key) — no
# case-folding step can launder an id.
TP_ACCOUNT = "acmepublicacct"           # ALLOWS public blob access AND internet-open
TP_CONTAINER = "public-assets"          # publicAccess=Container -> TRUE POSITIVE (all three scopes permit)
TRAP_CONTAINER_PRIVATE = "private-logs"  # publicAccess=None in the SAME account -> container scope denies
LOCKED_ACCOUNT = "acmelockedacct"       # allowBlobPublicAccess=False -> account scope denies
FIREWALLED_ACCOUNT = "acmefirewalledacct"  # networkAcls.defaultAction=Deny -> network scope denies
WOULD_BE_PUBLIC = "would-be-public"     # a publicAccess=Container container in each denying account

TP_SUBJECT = f"{TP_ACCOUNT}/{TP_CONTAINER}"
TRAP_SUBJECTS = {
    f"{TP_ACCOUNT}/{TRAP_CONTAINER_PRIVATE}",
    f"{LOCKED_ACCOUNT}/{WOULD_BE_PUBLIC}",
    f"{FIREWALLED_ACCOUNT}/{WOULD_BE_PUBLIC}",
}


class _Creds:
    """A plain, duck-typed minted read-only Azure session (``provider`` / ``account_id`` [the subscription] /
    ``bearer_token``) — the exact shape a ``vigil_core.cloud_session.MintedSession`` for an Azure provider
    satisfies. We model the sovereign crossing in-process with this fake; the real crossing is deferred to a
    later wave. Fields are overridable so a test can forge a PARTIAL (missing bearer) or non-Azure session."""

    def __init__(self, *, provider: str = "azure", account_id: str = SUBSCRIPTION,
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
    """A subscription-only in-scope gate: the charter authorises (azure, SUBSCRIPTION), any region/resource — so
    every captured subject in the seeded subscription is authorised and the capture mints over the real
    export."""
    return CloudScopeGate(
        scope=StaticCloudScopeSource([CloudScopeEntry(provider="azure", account=SUBSCRIPTION)]),
        engagement_slug="acme",
    )


def _grant_gates(monkeypatch, tmp_path):
    """Provision a PASSING engagement posture so invoke_tool's W1.4 gate chain lets the live collection run:
    the kill-switch is clear, the ACTIVE_RECON entitlement is granted, and the customer's control-plane hosts
    are on the egress allowlist. Mirrors the GCP E2E (the gate-REFUSAL path is proven dep-free in
    test_cloud_posture_run_azure_report)."""
    from framework.v2 import entitlement
    from framework.v2.agents import egress_guard
    from framework.v2.common import paths

    monkeypatch.setattr(paths, "killswitch_path", lambda slug: tmp_path / f"{slug}.halt")   # kill-switch clear
    monkeypatch.setattr(entitlement, "require_capability", lambda cap: None)                 # ACTIVE_RECON granted
    monkeypatch.setattr(egress_guard, "build_engagement_allowlist",
                        lambda **k: SimpleNamespace(permits=lambda host: True))              # control-plane allowed


def _install_fake_azure(monkeypatch, *, forbid_ambient: bool = True) -> dict:
    """Fake the azure SDK surface the REAL ``AzureLiveSensor`` reads at collection time, via ``sys.modules``
    (the pattern ``test_azure_live_injected_credentials`` uses) — no azure-identity / azure-mgmt install, no
    network. The fake SEEDS the subscription (the collector only READS):

      * ``azure.identity.DefaultAzureCredential`` — RECORDS a call and, when ``forbid_ambient``, RAISES, so an
        injected run that touched the ambient chain fails loudly;
      * ``azure.mgmt.storage.StorageManagementClient`` — RECORDS the ``credential`` + ``subscription_id`` it is
        handed and serves the seeded storage accounts (allowBlobPublicAccess + network posture) and their blob
        containers (publicAccess);
      * ``azure.mgmt.authorization.AuthorizationManagementClient`` — ALSO records the credential + subscription
        it is handed and serves one real RBAC role assignment (an authenticated principal — never anonymous, so
        it mints no FACT, only exercising the RBAC topology path without crashing);
      * ``azure.core.credentials.AccessToken`` — the authentic 2-field shape the injected static credential
        replays (the no-op clients never call ``get_token``, but the faked surface stays faithful).

    Returns a recorder dict so a test can prove the injected bearer flowed to the clients and the ambient chain
    was untouched.
    """
    rec: dict = {"ambient_called": False, "client_creds": []}

    _AccessToken = namedtuple("AccessToken", ["token", "expires_on"])

    class _DefaultAzureCredential:
        def __init__(self, *a, **kw):
            rec["ambient_called"] = True
            if forbid_ambient:
                raise AssertionError("ambient DefaultAzureCredential() must not be consulted on an injected run")
            self.token = AMBIENT_BEARER

    def _arm_id(name: str) -> str:
        return (f"/subscriptions/{SUBSCRIPTION}/resourceGroups/rg-{name}"
                f"/providers/Microsoft.Storage/storageAccounts/{name}")

    def _acct(name: str, *, allow_public: bool, public_network_access: str = "Enabled",
              default_action: str = "Allow", tags: "dict | None" = None):
        return SimpleNamespace(
            id=_arm_id(name),
            allow_blob_public_access=allow_public,
            public_network_access=public_network_access,
            network_rule_set=SimpleNamespace(default_action=default_action),
            tags=tags or {})

    def _cont(name: str, public_access: str):
        return SimpleNamespace(name=name, public_access=public_access)

    # TRUE POSITIVE + the near-zero-FP traps (seeded; the collector only reads these). Each trap discriminates
    # on EXACTLY one of Azure's three scopes vs. the true positive.
    _ACCOUNTS = [
        _acct(TP_ACCOUNT, allow_public=True),                      # allows public AND internet-open
        _acct(LOCKED_ACCOUNT, allow_public=False),                 # account FORBIDS public blob access
        _acct(FIREWALLED_ACCOUNT, allow_public=True, default_action="Deny"),  # network LOCKED (not internet-open)
    ]
    _CONTAINERS = {
        TP_ACCOUNT: [
            _cont(TP_CONTAINER, "Container"),          # TRUE POSITIVE: public container, all three scopes permit
            _cont(TRAP_CONTAINER_PRIVATE, "None"),     # TRAP: container scope denies (publicAccess None)
        ],
        LOCKED_ACCOUNT: [_cont(WOULD_BE_PUBLIC, "Container")],      # TRAP: account scope denies
        FIREWALLED_ACCOUNT: [_cont(WOULD_BE_PUBLIC, "Blob")],       # TRAP: network scope denies
    }

    class _StorageManagementClient:
        def __init__(self, credential, subscription_id, *a, **kw):
            rec["client_creds"].append(("storage", getattr(credential, "token", None), subscription_id))
            self.storage_accounts = SimpleNamespace(list=lambda: list(_ACCOUNTS))
            self.blob_containers = SimpleNamespace(list=lambda rg, name: list(_CONTAINERS.get(name, [])))

    class _AuthorizationManagementClient:
        def __init__(self, credential, subscription_id, *a, **kw):
            rec["client_creds"].append(("rbac", getattr(credential, "token", None), subscription_id))
            self.role_assignments = SimpleNamespace(
                list_for_subscription=lambda: [
                    SimpleNamespace(principal_id="99999999-aaaa-bbbb-cccc-888888888888")])

    azure = types.ModuleType("azure")
    a_core = types.ModuleType("azure.core")
    a_core_creds = types.ModuleType("azure.core.credentials")
    a_core_creds.AccessToken = _AccessToken  # type: ignore[attr-defined]
    a_identity = types.ModuleType("azure.identity")
    a_identity.DefaultAzureCredential = _DefaultAzureCredential  # type: ignore[attr-defined]
    a_mgmt = types.ModuleType("azure.mgmt")
    a_mgmt_storage = types.ModuleType("azure.mgmt.storage")
    a_mgmt_storage.StorageManagementClient = _StorageManagementClient  # type: ignore[attr-defined]
    a_mgmt_auth = types.ModuleType("azure.mgmt.authorization")
    a_mgmt_auth.AuthorizationManagementClient = _AuthorizationManagementClient  # type: ignore[attr-defined]
    azure.core = a_core  # type: ignore[attr-defined]
    a_core.credentials = a_core_creds  # type: ignore[attr-defined]
    azure.identity = a_identity  # type: ignore[attr-defined]
    azure.mgmt = a_mgmt  # type: ignore[attr-defined]
    a_mgmt.storage = a_mgmt_storage  # type: ignore[attr-defined]
    a_mgmt.authorization = a_mgmt_auth  # type: ignore[attr-defined]
    for name, mod in {
        "azure": azure, "azure.core": a_core, "azure.core.credentials": a_core_creds,
        "azure.identity": a_identity, "azure.mgmt": a_mgmt, "azure.mgmt.storage": a_mgmt_storage,
        "azure.mgmt.authorization": a_mgmt_auth,
    }.items():
        monkeypatch.setitem(sys.modules, name, mod)
    return rec


def _fact_subjects(result) -> set:
    """The ACTUAL subject id bound into each minted FACT's certificate (never the shared request glob)."""
    out = set()
    for f in result.facts:
        out.add(f.signed.certificate.bound_identity["resource_scope"]["resource"])
    return out


def test_cloud_posture_run_azure_e2e(monkeypatch, tmp_path):
    """Mint -> collect (real AzureLiveSensor, azure-fake) -> oracle re-fire -> signed FACT -> offline verify
    -> report, dispatched on provider=azure."""
    from framework.v2.evidence.certify import verify_certificate
    from framework.v2.sensors.azure_live import AzureLiveSensor
    from framework.v2.sensors.cloud import confirm_cloud_posture_facts, normalize_cloud_export
    from framework.v2.verify.policy_path import build_policy_graph, policy_path_context
    from framework.v2.verify.verifier import OracleVerifier

    rec = _install_fake_azure(monkeypatch, forbid_ambient=True)
    _grant_gates(monkeypatch, tmp_path)    # a properly-provisioned posture: the gated collection runs
    signers, tr = _signers_and_trust()
    creds = _Creds()  # the minted DATA session (provider=azure, account_id=subscription, bearer_token=injected)

    # -- STEP 3: COLLECT via the REAL sensor under the azure fake, as the injected identity. --
    collect = AzureLiveSensor(credentials=creds, require_injected_credentials=True).run({}, SimpleNamespace())
    assert collect.ok, collect.note
    assert collect.output["format"] == "native"
    assert collect.output.get("provider") == "azure"
    assert collect.output.get("subscription") == SUBSCRIPTION
    # CREDENTIAL ISOLATION: the INJECTED bearer (not the ambient identity) reached EVERY azure client (storage +
    # RBAC), each SCOPED to exactly the injected subscription; the ambient DefaultAzureCredential was NEVER
    # consulted. A regression dropping the injected credential from either client (a silent fall-back to VIGIL's
    # ambient Azure identity for that surface) is caught here.
    assert rec["client_creds"], rec["client_creds"]
    assert all(tok == INJECTED_BEARER for _svc, tok, _sub in rec["client_creds"]), rec["client_creds"]
    assert all(sub == SUBSCRIPTION for _svc, _tok, sub in rec["client_creds"]), rec["client_creds"]
    assert {svc for svc, _tok, _sub in rec["client_creds"]} == {"storage", "rbac"}
    assert rec["ambient_called"] is False
    # the injected bearer never leaks into the native export either.
    assert INJECTED_BEARER not in collect.output["export"]

    # -- STEP 4: the oracle FIRES over the COLLECTED data (the real export the sensor just produced). --
    export = collect.output["export"]
    inv = normalize_cloud_export(json.loads(export), "native")
    pub_facts = [pf for pf in confirm_cloud_posture_facts(inv) if pf.get("lead_class") == "public_exposure"]
    reached = {pf["resource"] for pf in pub_facts}
    assert TP_SUBJECT in reached, reached
    # NEGATIVE-CONTROL TRAPS held (never promoted by the oracle over the collected inventory) — each
    # DISCRIMINATES on exactly one of Azure's three scopes vs. the true positive (container publicAccess, the
    # account's allowBlobPublicAccess, and the account's network firewall).
    for trap in TRAP_SUBJECTS:
        assert trap not in reached, (trap, reached)
    # inspect a LIVE oracle SIGNAL's .fired over the public container's anonymous grant path (never a stubbed
    # verdict): the anonymous ``*`` principal has a real grant path to the confirmed-public container.
    acme = next(pf for pf in pub_facts if pf["resource"] == TP_SUBJECT)
    vr = OracleVerifier().confirm(
        policy_path_context(build_policy_graph(inv), acme["principal"], acme["resource"], acme["access"]))
    assert vr.confirmed and any(getattr(s, "fired", False) for s in (vr.signals or []))

    # -- STEP 4b: run_cloud_posture_live DISPATCHES on azure, runs the collector THROUGH the gated invoke_tool
    #    chain, and mints signed FACTs over the retained export. --
    result = run_cloud_posture_live(
        creds, scope_gate=_gate(), engagement_slug="acme", signers=signers,
        capture_time_epoch=1_700_000_000)
    assert result.refused is False and result.n_facts >= 1, result.admissions
    assert result.provider == "azure" and result.account == SUBSCRIPTION

    subjects = _fact_subjects(result)
    assert TP_SUBJECT in subjects, subjects
    # NEGATIVE-CONTROL TRAPS held (never minted — the private container, the public-forbidding account, and the
    # firewalled account):
    for trap in TRAP_SUBJECTS:
        assert trap not in subjects, (trap, subjects)

    # -- STEP 5: each FACT's certificate RE-VERIFIES OFFLINE (+ negative controls). Pure, no azure fake. --
    for f in result.facts:
        ctx = result.contexts[f.finding_ref]
        cert = f.signed.certificate
        assert cert.capture_method == "api:list"                # a VIGIL-owned live read, not an artifact
        assert cert.bound_identity["resource_scope"]["provider"] == "azure"
        assert cert.bound_identity["resource_scope"]["account"] == SUBSCRIPTION   # Azure: account IS the sub id
        assert cert.bound_identity.get("capture_time_epoch") == 1_700_000_000     # deterministic, operator-set
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
    md = render_cloud_posture_report(result, target=f"azure:{SUBSCRIPTION}")
    assert "PROVEN FACT" in md
    assert "sha256:" in md
    assert "framework.v2 verify" in md
    assert "oracle-confirmed fact(s)" in md


def test_partial_azure_session_fails_closed_through_run_cloud_posture_live(monkeypatch, tmp_path):
    """CREDENTIAL ISOLATION through the orchestrator: a PARTIAL minted Azure session (a missing AAD bearer)
    makes the dispatched AzureLiveSensor fail CLOSED inside the gated chain — ``run_cloud_posture_live`` returns
    a no-FACT, never-CLEAN result carrying the no-identity-substitution reason. It NEVER falls back to VIGIL's
    ambient ``DefaultAzureCredential``. The gates are GRANTED so the refusal is the collector's own fail-closed
    (not merely a gate refusal), and no azure libs are needed — the sensor rejects the partial session before
    any azure import, so the ambient fake is installed with forbid_ambient to prove the ambient chain is never
    reached."""
    rec = _install_fake_azure(monkeypatch, forbid_ambient=True)
    _grant_gates(monkeypatch, tmp_path)
    signers, _ = _signers_and_trust()

    partial = _Creds(bearer_token="")   # no bearer -> the collector must fail closed, never ambient
    result = run_cloud_posture_live(
        partial, scope_gate=_gate(), engagement_slug="acme", signers=signers, capture_time_epoch=1_700_000_000)

    assert result.n_facts == 0 and result.family_verdict() != "CLEAN"
    assert result.provider == "azure" and result.account == SUBSCRIPTION
    note = " ".join(result.notes).lower()
    assert "no identity substitution" in note, result.notes
    assert rec["ambient_called"] is False and rec["client_creds"] == []   # no azure client ever built
