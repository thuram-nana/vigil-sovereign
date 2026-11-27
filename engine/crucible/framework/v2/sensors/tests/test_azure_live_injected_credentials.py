"""
Phase C2 · Azure — the AzureLiveSensor CUSTOMER-credential seam (the identity-substitution guard).

The Azure twin of Wave B.1's CloudLiveSensor seam (``test_cloud_live_injected_credentials``) and gcp_live's
Phase-C2 seam (``test_gcp_live_injected_credentials``). When a scoped read-only Azure session is INJECTED (a
``vigil_core.cloud_session.MintedSession`` for an Azure provider, duck-typed here so the engine imports no
governor object — the FATAL-2 boundary), the collector wraps the injected AAD BEARER token in a static
``azure.core.credentials`` TokenCredential and hands it to EVERY azure management client (storage + RBAC),
each scoped to the injected subscription, and NEVER consults the ambient ``DefaultAzureCredential``; a run that
REQUIRES an injected session fails CLOSED rather than fall back to VIGIL's own Azure identity; and a PARTIAL /
non-Azure session is REJECTED before any azure import — so the fail-closed cases run in CI with no azure libs
installed (the reject precedes every SDK call), exactly as the AWS/GCP seams' partial/non-provider cases do.

The azure SDK surface the sensor touches is FAKED in-process via ``sys.modules`` (mirroring the AWS boto3 fake
and the GCP google fake) — no azure-identity / azure-mgmt install, no network — so the INJECTED-token spy AND
the ambient-path regression ALSO run in CI (none skip). This is a strict superset of ``importorskip`` coverage:
the fake overrides any real lib for the test's duration (monkeypatch restores it after), keeping the result
identical whether or not the azure SDKs happen to be installed.
"""

from __future__ import annotations

import sys
import types
from collections import namedtuple
from types import SimpleNamespace

from framework.v2.sensors.azure_live import AzureLiveSensor

SUBSCRIPTION = "11111111-2222-3333-4444-555555555555"
BEARER = "aad.injected-scoped-read-only-token"
AMBIENT_TOKEN = "aad.AMBIENT-MUST-NOT-BE-USED"  # a DISTINCT dummy ambient identity, asserted never-used


class _Creds:
    """A duck-typed minted read-only Azure session — the shape a ``vigil_core.cloud_session.MintedSession`` for
    an Azure provider exposes (``provider`` / ``account_id`` [the subscription] / ``bearer_token`` [a short-
    lived AAD OAuth2 access token]). The aws_* fields are EMPTY on an Azure session (as the real MintedSession
    leaves them). Fields are overridable so a test can forge a PARTIAL (no bearer / no subscription) or
    non-Azure session."""

    def __init__(self, *, provider: str = "azure", account_id: str = SUBSCRIPTION,
                 bearer_token: str = BEARER) -> None:
        self.provider = provider
        self.account_id = account_id
        self.bearer_token = bearer_token
        self.access_key_id = ""
        self.secret_access_key = ""
        self.session_token = ""
        self.region = ""


def _install_fake_azure(monkeypatch, *, forbid_ambient: bool = True) -> dict:
    """Fake the azure SDK surface the sensor touches, via ``sys.modules`` (like the AWS boto3 / GCP google
    fakes):

      * ``azure.identity.DefaultAzureCredential`` — RECORDS a call and, when ``forbid_ambient``, RAISES, so an
        injected run that touched the ambient chain would fail loudly;
      * ``azure.mgmt.storage.StorageManagementClient`` — a no-op client (empty ``storage_accounts.list``) that
        RECORDS the ``credential`` + ``subscription_id`` it was handed (so the token is proven to FLOW to the
        client, not merely be constructed);
      * ``azure.mgmt.authorization.AuthorizationManagementClient`` — ALSO records the credential + subscription
        it is handed (empty ``role_assignments.list_for_subscription``), so the no-ambient-substitution
        invariant is proven for BOTH collection clients (storage + RBAC) — a regression dropping the injected
        credential from EITHER (which would silently fall back to the ambient chain for that surface) is caught;
      * ``azure.core.credentials.AccessToken`` — the authentic 2-field shape the static credential replays, so
        the faked surface is faithful even though the no-op clients never call ``get_token``.

    Returns a recorder dict."""
    rec: dict = {"ambient_called": False, "storage_credential": None, "storage_subscription": None,
                 "rbac_credential": None, "rbac_subscription": None}

    _AccessToken = namedtuple("AccessToken", ["token", "expires_on"])

    class _DefaultAzureCredential:
        def __init__(self, *a, **kw):
            rec["ambient_called"] = True
            if forbid_ambient:
                raise AssertionError(
                    "ambient DefaultAzureCredential() must not be consulted on an injected run")
            self.token = AMBIENT_TOKEN   # the ambient identity, asserted never-used on an injected run

    class _StorageManagementClient:
        def __init__(self, credential, subscription_id, *a, **kw):
            rec["storage_credential"] = credential
            rec["storage_subscription"] = subscription_id
            self.storage_accounts = SimpleNamespace(list=list)
            self.blob_containers = SimpleNamespace(list=lambda rg, name: [])

    class _AuthorizationManagementClient:
        def __init__(self, credential, subscription_id, *a, **kw):
            rec["rbac_credential"] = credential
            rec["rbac_subscription"] = subscription_id
            self.role_assignments = SimpleNamespace(list_for_subscription=list)

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
    # Wire the attribute graph so ``from azure.identity import DefaultAzureCredential`` / ``from azure.mgmt
    # .storage import StorageManagementClient`` / ``from azure.mgmt.authorization import
    # AuthorizationManagementClient`` / ``from azure.core.credentials import AccessToken`` all resolve.
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


# -- (a) the injected bearer reaches EVERY azure client; the ambient chain is never consulted ----------------


def test_injected_bearer_reaches_every_azure_client_not_ambient(monkeypatch):
    rec = _install_fake_azure(monkeypatch, forbid_ambient=True)
    r = AzureLiveSensor(credentials=_Creds(), require_injected_credentials=True).run({}, SimpleNamespace())
    assert r.ok is True, r.note
    # the injected bearer was handed to EVERY collection client (the token FLOWS to each: storage + RBAC — so
    # neither can regress to the ambient DefaultAzureCredential undetected)...
    assert getattr(rec["storage_credential"], "token", None) == BEARER
    assert getattr(rec["rbac_credential"], "token", None) == BEARER
    # ...each client SCOPED to exactly the injected subscription (``account_id``)...
    assert rec["storage_subscription"] == SUBSCRIPTION
    assert rec["rbac_subscription"] == SUBSCRIPTION
    # ...and the ambient chain (DefaultAzureCredential) was NEVER consulted (forbid_ambient would have raised).
    assert rec["ambient_called"] is False
    # the result is scoped to exactly the injected subscription/provider.
    assert (r.output or {}).get("subscription") == SUBSCRIPTION
    assert (r.output or {}).get("provider") == "azure"


def test_injected_bearer_never_leaks_into_the_result(monkeypatch):
    _install_fake_azure(monkeypatch, forbid_ambient=True)
    creds = _Creds()
    r = AzureLiveSensor(credentials=creds, require_injected_credentials=True).run({}, SimpleNamespace())
    blob = f"{r.summary}\n{getattr(r, 'note', '')}\n{r.output}"
    assert creds.bearer_token not in blob


# -- (b) a PARTIAL injected session fails closed BEFORE any azure call (runs with no azure libs) -------------


def test_partial_injected_session_fails_closed_before_any_azure_call():
    # No fake installed and no azure libs needed: the reject precedes every SDK import. A missing bearer OR a
    # missing subscription (account_id) is incomplete -> fail closed, no identity substitution, typed
    # INCONCLUSIVE.
    for bad in (_Creds(bearer_token=""), _Creds(account_id="")):
        r = AzureLiveSensor(credentials=bad, require_injected_credentials=True).run({}, SimpleNamespace())
        assert r.ok is False
        assert "no identity substitution" in r.note.lower()
        assert (r.output or {}).get("missing_prerequisite")  # typed INCONCLUSIVE marker, never a clean negative
        assert (r.output or {}).get("assessed") is False


# -- (c) a non-Azure injected session fails closed (runs with no azure libs) ---------------------------------


def test_non_azure_injected_session_fails_closed():
    # An Azure collector handed an AWS/GCP/Cloudflare MintedSession must refuse — never treat it as Azure creds,
    # never ambient.
    for other in ("aws", "gcp", "cloudflare"):
        r = AzureLiveSensor(credentials=_Creds(provider=other), require_injected_credentials=True).run(
            {}, SimpleNamespace())
        assert r.ok is False and "no identity substitution" in r.note.lower()
        assert (r.output or {}).get("missing_prerequisite")


# -- (d) require_injected + no session -> fail closed, ambient never reached, no credential built ------------


def test_required_injection_absent_fails_closed_never_ambient(monkeypatch):
    # Even with a perfectly good ambient credential available, a required-injection run REFUSES rather than use
    # it.
    rec = _install_fake_azure(monkeypatch, forbid_ambient=False)  # ambient WOULD succeed if consulted
    r = AzureLiveSensor(require_injected_credentials=True).run({}, SimpleNamespace())
    assert r.ok is False and "no identity substitution" in r.note.lower()
    assert rec["ambient_called"] is False        # the ambient chain was never even reached (the elif returns first)
    assert rec["storage_credential"] is None     # and no client was built, so no credential was handed anywhere
    assert rec["rbac_credential"] is None


# -- (e) the ambient path is unchanged when no session is injected -------------------------------------------


def test_ambient_path_unchanged_when_no_injection(monkeypatch):
    monkeypatch.delenv("AZURE_SUBSCRIPTION_ID", raising=False)
    rec = _install_fake_azure(monkeypatch, forbid_ambient=False)
    r = AzureLiveSensor(subscription=SUBSCRIPTION).run({}, SimpleNamespace())  # no injection, require_injected False
    assert r.ok is True, r.note
    assert rec["ambient_called"] is True          # the ambient DefaultAzureCredential WAS used, exactly as before
    assert getattr(rec["storage_credential"], "token", None) == AMBIENT_TOKEN  # built from the ambient identity
    assert rec["storage_subscription"] == SUBSCRIPTION
    assert (r.output or {}).get("subscription") == SUBSCRIPTION


# -- (f) the pre-existing ambient fail-closed no-op (no azure-identity) still holds for the bare sensor -------


def test_bare_sensor_still_fail_closed_without_azure_identity(monkeypatch):
    # Regression: the pre-existing ambient fail-closed no-op (no azure-identity) still holds for the bare sensor,
    # now that the azure.identity import lives in the else-branch rather than being reached unconditionally.
    monkeypatch.setitem(sys.modules, "azure.identity", None)
    monkeypatch.setitem(sys.modules, "azure", None)
    r = AzureLiveSensor(subscription=SUBSCRIPTION).run({}, SimpleNamespace())
    assert r.ok is False and "azure-identity" in r.note and "fail-closed" in r.note.lower()
