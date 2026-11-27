"""
Phase C2 · GCP — the GcpLiveSensor CUSTOMER-credential seam (the identity-substitution guard).

The GCP twin of Wave B.1's CloudLiveSensor seam (``test_cloud_live_injected_credentials``). When a scoped
read-only GCP session is INJECTED (a ``vigil_core.cloud_session.MintedSession`` for a GCP provider, duck-typed
here so the engine imports no governor object — the FATAL-2 boundary), the collector builds its google
credentials from the injected OAuth2 BEARER token and NEVER consults the ambient ADC chain
(``google.auth.default``); a run that REQUIRES an injected session fails CLOSED rather than fall back to
VIGIL's own Google identity; and a PARTIAL / non-GCP session is REJECTED before any google import — so the
fail-closed cases run in CI with no google libs installed (the reject precedes every SDK call), exactly as the
AWS seam's partial/non-AWS cases do.

The google SDK surface the sensor touches is FAKED in-process via ``sys.modules`` (mirroring the AWS seam's
boto3 fake) — no google-auth / google-cloud install, no network — so the INJECTED-token spy AND the ambient-
path regression ALSO run in CI (none skip). This is a strict superset of ``importorskip`` coverage: the fake
overrides any real lib for the test's duration (monkeypatch restores it after), keeping the result identical
whether or not the google SDKs happen to be installed.
"""

from __future__ import annotations

import sys
import types
from types import SimpleNamespace

from framework.v2.sensors.gcp_live import GcpLiveSensor

PROJECT = "acme-prod"
BEARER = "ya29.injected-scoped-read-only-token"
AMBIENT_TOKEN = "ya29.AMBIENT-MUST-NOT-BE-USED"  # a DISTINCT dummy ambient identity, asserted never-used


class _Creds:
    """A duck-typed minted read-only GCP session — the shape a ``vigil_core.cloud_session.MintedSession`` for a
    GCP provider exposes (``provider`` / ``account_id`` [the project] / ``bearer_token`` [a short-lived OAuth2
    access token]). The aws_* fields are EMPTY on a GCP session (as the real MintedSession leaves them). Fields
    are overridable so a test can forge a PARTIAL (no bearer / no project) or non-GCP session."""

    def __init__(self, *, provider: str = "gcp", account_id: str = PROJECT,
                 bearer_token: str = BEARER) -> None:
        self.provider = provider
        self.account_id = account_id
        self.bearer_token = bearer_token
        self.access_key_id = ""
        self.secret_access_key = ""
        self.session_token = ""
        self.region = ""


def _install_fake_google(monkeypatch, *, forbid_ambient: bool = True) -> dict:
    """Fake the google SDK surface the sensor touches, via ``sys.modules`` (like the AWS seam's boto3 fake):

      * ``google.oauth2.credentials.Credentials`` — records the token it was built from;
      * ``google.cloud.storage.Client`` — a no-op client (empty ``list_buckets``) that records the credentials
        it was handed (so the token is proven to FLOW to the client, not merely be constructed);
      * ``google.auth.default`` — RECORDS a call and, when ``forbid_ambient``, RAISES, so an injected run that
        touched the ambient chain would fail loudly.

    ``google.cloud`` is a plain module with NO ``__path__`` and no ``resourcemanager_v3`` / ``orgpolicy_v2``
    attribute, so those optional reads degrade to ``None`` exactly as in prod when the SDKs are absent (this
    suite tests CREDENTIAL HANDLING, not collection — the E2E covers collection). Returns a recorder dict."""
    rec: dict = {"token": None, "built": False, "adc_called": False, "storage_credentials": None}

    class _Credentials:
        def __init__(self, *, token=None, scopes=None, **kw):
            rec["built"] = True
            rec["token"] = token
            self.token = token
            self.scopes = scopes

    class _StorageClient:
        def __init__(self, *, project=None, credentials=None, **kw):
            rec["storage_credentials"] = credentials
            self.project = project

        def list_buckets(self):
            return []

    def _adc_default(*a, **k):
        rec["adc_called"] = True
        if forbid_ambient:
            raise AssertionError("ambient google.auth.default() must not be consulted on an injected run")
        return _Credentials(token=AMBIENT_TOKEN), "ambient-adc-project"

    google = types.ModuleType("google")
    g_auth = types.ModuleType("google.auth")
    g_auth.default = _adc_default  # type: ignore[attr-defined]
    g_oauth2 = types.ModuleType("google.oauth2")
    g_oauth2_creds = types.ModuleType("google.oauth2.credentials")
    g_oauth2_creds.Credentials = _Credentials  # type: ignore[attr-defined]
    g_cloud = types.ModuleType("google.cloud")
    g_cloud_storage = types.ModuleType("google.cloud.storage")
    g_cloud_storage.Client = _StorageClient  # type: ignore[attr-defined]
    # Wire the attribute graph so ``google.auth.default`` and ``from google.cloud import storage`` resolve.
    google.auth = g_auth  # type: ignore[attr-defined]
    google.oauth2 = g_oauth2  # type: ignore[attr-defined]
    g_oauth2.credentials = g_oauth2_creds  # type: ignore[attr-defined]
    google.cloud = g_cloud  # type: ignore[attr-defined]
    g_cloud.storage = g_cloud_storage  # type: ignore[attr-defined]
    for name, mod in {
        "google": google, "google.auth": g_auth, "google.oauth2": g_oauth2,
        "google.oauth2.credentials": g_oauth2_creds, "google.cloud": g_cloud,
        "google.cloud.storage": g_cloud_storage,
    }.items():
        monkeypatch.setitem(sys.modules, name, mod)
    return rec


# -- (a) the injected bearer reaches the google client; the ambient chain is never consulted -----------------


def test_injected_bearer_reaches_google_client_not_ambient(monkeypatch):
    rec = _install_fake_google(monkeypatch, forbid_ambient=True)
    r = GcpLiveSensor(credentials=_Creds(), require_injected_credentials=True).run({}, SimpleNamespace())
    assert r.ok is True, r.note
    # the google credentials were built from the INJECTED bearer token...
    assert rec["built"] is True and rec["token"] == BEARER
    # ...and those SAME injected credentials were handed to the storage client (the token FLOWS to the client)...
    assert getattr(rec["storage_credentials"], "token", None) == BEARER
    # ...and the ambient ADC chain (google.auth.default) was NEVER consulted (forbid_ambient would have raised).
    assert rec["adc_called"] is False
    # the result is scoped to exactly the injected project/provider.
    assert (r.output or {}).get("project") == PROJECT
    assert (r.output or {}).get("provider") == "gcp"


def test_injected_bearer_never_leaks_into_the_result(monkeypatch):
    _install_fake_google(monkeypatch, forbid_ambient=True)
    creds = _Creds()
    r = GcpLiveSensor(credentials=creds, require_injected_credentials=True).run({}, SimpleNamespace())
    blob = f"{r.summary}\n{getattr(r, 'note', '')}\n{r.output}"
    assert creds.bearer_token not in blob


# -- (b) a PARTIAL injected session fails closed BEFORE any google call (runs with no google libs) -----------


def test_partial_injected_session_fails_closed_before_any_google_call():
    # No fake installed and no google libs needed: the reject precedes every SDK import. A missing bearer OR a
    # missing project (account_id) is incomplete -> fail closed, no identity substitution, typed INCONCLUSIVE.
    for bad in (_Creds(bearer_token=""), _Creds(account_id="")):
        r = GcpLiveSensor(credentials=bad, require_injected_credentials=True).run({}, SimpleNamespace())
        assert r.ok is False
        assert "no identity substitution" in r.note.lower()
        assert (r.output or {}).get("missing_prerequisite")  # typed INCONCLUSIVE marker, never a clean negative
        assert (r.output or {}).get("assessed") is False


# -- (c) a non-GCP injected session fails closed (runs with no google libs) ----------------------------------


def test_non_gcp_injected_session_fails_closed():
    # A GCP collector handed an AWS/Azure MintedSession must refuse — never treat it as GCP creds, never ambient.
    for other in ("aws", "azure", "cloudflare"):
        r = GcpLiveSensor(credentials=_Creds(provider=other), require_injected_credentials=True).run(
            {}, SimpleNamespace())
        assert r.ok is False and "no identity substitution" in r.note.lower()
        assert (r.output or {}).get("missing_prerequisite")


# -- (d) require_injected + no session -> fail closed, ambient never reached (runs with no google libs) -------


def test_required_injection_absent_fails_closed_never_ambient(monkeypatch):
    # Even with a perfectly good ambient ADC available, a required-injection run REFUSES rather than use it.
    rec = _install_fake_google(monkeypatch, forbid_ambient=False)  # ambient WOULD succeed if consulted
    r = GcpLiveSensor(require_injected_credentials=True).run({}, SimpleNamespace())
    assert r.ok is False and "no identity substitution" in r.note.lower()
    assert rec["adc_called"] is False  # the ambient chain was never even reached (the elif returns first)
    assert rec["built"] is False


# -- (e) the ambient path is unchanged when no session is injected -------------------------------------------


def test_ambient_path_unchanged_when_no_injection(monkeypatch):
    monkeypatch.delenv("GOOGLE_CLOUD_PROJECT", raising=False)
    monkeypatch.delenv("CLOUDSDK_CORE_PROJECT", raising=False)
    rec = _install_fake_google(monkeypatch, forbid_ambient=False)
    r = GcpLiveSensor().run({}, SimpleNamespace())  # no injection, require_injected False
    assert r.ok is True, r.note
    assert rec["adc_called"] is True          # the ambient ADC chain WAS used, exactly as before
    assert rec["token"] == AMBIENT_TOKEN      # built from the ambient identity, not an injected one
    assert (r.output or {}).get("project") == "ambient-adc-project"


def test_bare_sensor_still_fail_closed_without_google_auth(monkeypatch):
    # Regression: the pre-existing ambient fail-closed no-op (no google-auth) still holds for the bare sensor,
    # now that the google.auth import lives in the else-branch rather than the top of run().
    monkeypatch.setitem(sys.modules, "google.auth", None)
    monkeypatch.setitem(sys.modules, "google", None)
    r = GcpLiveSensor().run({}, SimpleNamespace())
    assert r.ok is False and "google-auth" in r.note and "fail-closed" in r.note.lower()
