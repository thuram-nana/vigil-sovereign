"""Consumer PR-C — the live AZURE cloud-connect fetcher (``sigil.ui.cloud_fetch.AzureConsentConnectFetcher``), offline.

No network: a FAKE Microsoft Entra / Graph stands behind the fetcher's injectable transport (and, for the real
``_azure_http`` path, behind the shared ``_do_open`` seam). The fake answers the client-credentials token endpoint by
tenant (admin consent) and the Graph service-principal read by the admin-set tag, so the observation the verdict
judges is produced the way Azure would produce it.

Pinned here:
  * a good consent yields {tenant, external_id_matched: True, external_id, control_tenant, control_denied: True} in
    exactly three calls (token, the Graph binding read, the control-tenant token);
  * the tag absent reports external_id_matched False (the verdict then tells the customer to set it);
  * only an EXPLICIT AADSTS no-consent failure counts as a denied control — a 200, a throttle, a 5xx, VIGIL's own
    bad connector secret (another AADSTS code), or a transport fault are INCONCLUSIVE and raise (fail closed);
  * the token's ``tid`` is decoded (pure base64url) and must equal the tenant, from an expected AAD issuer host;
  * inputs are validated before any call; the egress is pinned to the allowlist before any socket; an oversized
    answer is refused; credentials never render in a repr or an error message;
  * ``config.azure_connect_fetcher`` builds the fetcher only when the cloud leg is on AND fully provisioned.
"""
from __future__ import annotations

import base64
import io
import json
import urllib.error
from urllib.parse import urlsplit

import pytest

from sigil.governor import cloud_connect as cc
from sigil.ui import cloud_fetch as cf
from sigil.ui.cloud_fetch import AzureConsentConnectFetcher, CloudFetchError

CLIENT_ID = "11111111-1111-1111-1111-111111111111"
SECRET = "not-a-real-azure-secret"  # gitleaks:allow - test placeholder, never a real credential
TENANT = "22222222-2222-2222-2222-222222222222"
OBJ = "33333333-3333-3333-3333-333333333333"   # VIGIL's enterprise-app Object ID in the customer tenant
EXT = "EXT-GOOD"
CTL = "CTL-RANDOM-1"


def _b64url(d: dict) -> str:
    return base64.urlsafe_b64encode(json.dumps(d).encode()).rstrip(b"=").decode()


def _jwt(tid: str, iss: "str | None" = None) -> str:
    """A well-formed (unsigned-trust) JWT whose payload carries ``tid`` + an AAD ``iss`` — the token AAD would hand
    back. The fetcher base64url-decodes the payload; it never trusts the signature beyond TLS provenance."""
    header = _b64url({"alg": "RS256", "typ": "JWT", "kid": "k"})
    issuer = iss if iss is not None else f"https://sts.windows.net/{tid}/"
    payload = _b64url({"tid": tid, "iss": issuer, "aud": "https://graph.microsoft.com", "appid": CLIENT_ID})
    return f"{header}.{payload}.{'s' * 16}"


def _token_ok(tid: str, iss: "str | None" = None) -> "tuple[int, bytes]":
    return 200, json.dumps({"access_token": _jwt(tid, iss), "token_type": "Bearer", "expires_in": 3600}).encode()


def _aadsts(code: int, status: int = 400, msg: str = "nope") -> "tuple[int, bytes]":
    return status, json.dumps({"error": "invalid_request", "error_description": f"AADSTS{code}: {msg}",
                               "error_codes": [code]}).encode()


class FakeEntra:
    """Microsoft Entra + Graph, faithfully enough: routes the token POST by the tenant in the URL path (the customer
    tenant gets a token; the derived control tenant is denied) and answers the Graph service-principal read with the
    admin-set tags. ``tags`` None = the external id is present; overrides stand in canned answers."""

    def __init__(self, *, tenant=TENANT, client_id=CLIENT_ID, tags=None, tid_override=None, iss_override=None,
                 token_answer=None, control_answer=None, graph_answer=None):
        self.tenant, self.client_id = tenant, client_id
        self.tags = [EXT, "WindowsAzureActiveDirectoryIntegratedApp"] if tags is None else tags
        self.tid_override, self.iss_override = tid_override, iss_override
        self.token_answer, self.control_answer, self.graph_answer = token_answer, control_answer, graph_answer
        self.control = cc.azure_control_tenant(CTL)
        self.calls: list = []

    def __call__(self, method, url, headers, body, timeout):
        parts = urlsplit(url)
        host = (parts.hostname or "").lower()
        if host == "login.microsoftonline.com":
            assert method == "POST"
            tenant = [p for p in parts.path.split("/") if p][0]
            self.calls.append(("token", tenant))
            if tenant == self.tenant:
                if self.token_answer is not None:
                    return self.token_answer
                tid = self.tid_override or tenant
                return _token_ok(tid, self.iss_override)
            if tenant == self.control:
                return self.control_answer if self.control_answer is not None else _aadsts(700016)
            return _aadsts(700016)                               # any unknown tenant: app-not-found
        if host == "graph.microsoft.com":
            assert method == "GET"
            self.calls.append(("graph", headers.get("Authorization", "")))
            if self.graph_answer is not None:
                return self.graph_answer
            return 200, json.dumps({"appId": self.client_id, "id": OBJ, "tags": self.tags}).encode()
        return 404, b"{}"


def _fetcher(transport) -> AzureConsentConnectFetcher:
    return AzureConsentConnectFetcher(client_id=CLIENT_ID, client_secret=SECRET, transport=transport)


def _assume(f, *, tenant=TENANT, obj=OBJ, ext=EXT, ctl=CTL):
    return f.assume(provider="azure", account_id=tenant, role_ref=obj, external_id=ext, control_external_id=ctl)


# ---- the observation ------------------------------------------------------------------------------------------
def test_a_good_consent_is_observed_in_three_calls_with_a_denied_control():
    fake = FakeEntra()
    obs = _assume(_fetcher(fake))
    assert obs == {"tenant": TENANT, "external_id_matched": True, "external_id": EXT,
                   "control_tenant": cc.azure_control_tenant(CTL), "control_denied": True}
    assert [c[0] for c in fake.calls] == ["token", "graph", "token"]
    assert fake.calls[1][1].startswith("Bearer ")               # the Graph read carried the app token
    assert fake.calls[2][1] == cc.azure_control_tenant(CTL)     # the third call is the derived control tenant


def test_the_tag_absent_reports_the_binding_not_matched():
    obs = _assume(_fetcher(FakeEntra(tags=["unrelated", "other"])))
    assert obs["external_id_matched"] is False and obs["control_denied"] is True


def test_the_observed_tenant_is_the_token_tid():
    # a token whose tid differs from the tenant being connected is inconclusive and fails closed
    with pytest.raises(CloudFetchError):
        _assume(_fetcher(FakeEntra(tid_override="99999999-9999-9999-9999-999999999999")))


def test_a_token_from_a_foreign_issuer_is_inconclusive():
    with pytest.raises(CloudFetchError):
        _assume(_fetcher(FakeEntra(iss_override=f"https://evil.example/{TENANT}/")))


def test_a_malformed_jwt_is_inconclusive():
    with pytest.raises(CloudFetchError):
        _assume(_fetcher(FakeEntra(token_answer=(200, json.dumps({"access_token": "not-a-jwt"}).encode()))))


def test_a_200_without_a_token_is_inconclusive():
    with pytest.raises(CloudFetchError):
        _assume(_fetcher(FakeEntra(token_answer=(200, b'{"token_type":"Bearer"}'))))


def test_the_customer_tenant_without_consent_names_the_fix():
    with pytest.raises(CloudFetchError, match="admin consent"):
        _assume(_fetcher(FakeEntra(token_answer=_aadsts(700016))))


def test_a_bad_connector_secret_is_inconclusive_never_denied():
    # VIGIL's OWN broken credential answers an AADSTS code too — it must NOT be read as the customer not consenting
    with pytest.raises(CloudFetchError):
        _assume(_fetcher(FakeEntra(token_answer=_aadsts(7000215, status=401, msg="Invalid client secret"))))


@pytest.mark.parametrize("answer", [(500, b"oops"), (429, b'{"error":"throttle"}'),
                                    _aadsts(7000215, status=401), _token_ok(cc.azure_control_tenant(CTL))])
def test_only_an_explicit_no_consent_counts_as_a_denied_control(answer):
    # the control answers something other than an explicit AADSTS no-consent: inconclusive => raise (never "denied"),
    # except a 200 token (VIGIL consented in the control tenant?!) which is observed as control_denied False
    fake = FakeEntra(control_answer=answer)
    if answer[0] == 200:
        assert _assume(_fetcher(fake))["control_denied"] is False
    else:
        with pytest.raises(CloudFetchError):
            _assume(_fetcher(fake))


def test_a_transport_fault_is_inconclusive_and_fails_closed():
    def boom(method, url, headers, body, timeout):
        raise ConnectionResetError("reset")
    with pytest.raises(CloudFetchError, match="could not be reached"):
        _assume(_fetcher(boom))


def test_a_graph_fault_or_wrong_appid_is_inconclusive():
    with pytest.raises(CloudFetchError):
        _assume(_fetcher(FakeEntra(graph_answer=(403, b'{"error":{"code":"Authorization_RequestDenied"}}'))))
    other = json.dumps({"appId": "deadbeef-dead-beef-dead-beefdeadbeef", "id": OBJ, "tags": [EXT]}).encode()
    with pytest.raises(CloudFetchError):
        _assume(_fetcher(FakeEntra(graph_answer=(200, other))))


def test_a_graph_appid_differing_only_in_case_still_binds():
    # red-pen wgeauhgdu (LOW): appId is a case-INSENSITIVE Azure AD GUID. The client-id config regex permits an
    # uppercase GUID, and Graph echoes Microsoft's own casing, so a case-only difference is the SAME app and must
    # still bind — else the connect bricks fail-closed (dead) for that deployment. A DIFFERENT appId still fails closed.
    cid = "ab111111-cd22-ef33-ab44-cd55ef66ab77"                 # a client id with hex LETTERS (CLIENT_ID is digits)

    def _graph(appid):
        def t(method, url, headers, body, timeout):
            return 200, json.dumps({"appId": appid, "id": OBJ, "tags": [EXT]}).encode()
        return t

    same = AzureConsentConnectFetcher(client_id=cid, client_secret=SECRET, transport=_graph(cid.upper()))
    assert same._binding_matched("bearer-token", EXT) is True   # same GUID, upper vs lower -> still bound
    diff = AzureConsentConnectFetcher(client_id=cid, client_secret=SECRET,
                                      transport=_graph("deadbeef-dead-beef-dead-beefdeadbeef"))
    with pytest.raises(CloudFetchError):
        diff._binding_matched("bearer-token", EXT)              # a genuinely different appId still fails closed


@pytest.mark.parametrize("kw, why", [
    ({"obj": "not-a-guid"}, "Object ID"),
    ({"tenant": "not-a-guid"}, "tenant id"),
    ({"ext": "SAME", "ctl": "SAME"}, "could not be made"),
    ({"ext": ""}, "could not be made"),
])
def test_inputs_are_validated_before_any_call(kw, why):
    fake = FakeEntra()
    with pytest.raises(CloudFetchError, match=why):
        _assume(_fetcher(fake), **kw)
    assert fake.calls == []
    with pytest.raises(CloudFetchError, match="only Azure"):
        _fetcher(fake).assume(provider="aws", account_id=TENANT, role_ref=OBJ, external_id=EXT, control_external_id=CTL)
    assert fake.calls == []


def test_the_egress_is_pinned_to_the_allowlist_before_any_socket(monkeypatch):
    from sigil import config
    fake = FakeEntra()
    monkeypatch.setattr(config, "AZURE_CLOUD_CONNECT_EGRESS_ALLOWLIST", frozenset())
    with pytest.raises(CloudFetchError) as e:
        _assume(_fetcher(fake))
    assert fake.calls == [] and "non-allowlisted" in e.value.detail
    for bad in ("http://login.microsoftonline.com/x", "https://u@graph.microsoft.com/",
                "https://graph.microsoft.com:8443/", "https://evil.example/"):
        with pytest.raises(CloudFetchError):
            cf._azure_guard(bad)


# ---- the real _azure_http path (behind the shared _do_open seam) ----------------------------------------------
class _Resp(io.BytesIO):
    status = 200

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def test_the_real_http_path_returns_error_documents_and_bounds_the_read(monkeypatch):
    def denied(req, timeout):
        raise urllib.error.HTTPError(req.full_url, 400, "Bad", {}, io.BytesIO(b'{"error_codes":[700016]}'))
    monkeypatch.setattr(cf, "_do_open", denied)
    status, raw = cf._azure_http("POST", "https://login.microsoftonline.com/t/oauth2/v2.0/token", {}, b"x", 1.0)
    assert status == 400 and b"700016" in raw
    monkeypatch.setattr(cf, "_do_open", lambda req, timeout: _Resp(b"a" * (cf._MAX_RESPONSE_BYTES + 10)))
    with pytest.raises(CloudFetchError, match="could not be made"):
        cf._azure_http("GET", "https://graph.microsoft.com/v1.0/x", {}, b"", 1.0)

    def fault(req, timeout):
        raise urllib.error.URLError("no route")
    monkeypatch.setattr(cf, "_do_open", fault)
    with pytest.raises(CloudFetchError, match="could not be reached"):
        cf._azure_http("POST", "https://login.microsoftonline.com/t/oauth2/v2.0/token", {}, b"x", 1.0)


def test_credentials_never_render():
    f = _fetcher(FakeEntra())
    assert SECRET not in repr(f)
    try:
        _assume(_fetcher(FakeEntra(token_answer=_aadsts(7000215, status=401))))
    except CloudFetchError as e:
        assert SECRET not in str(e) and SECRET not in e.detail
    with pytest.raises(ValueError):
        AzureConsentConnectFetcher(client_id="")
    with pytest.raises(ValueError):
        AzureConsentConnectFetcher(client_id=CLIENT_ID)        # neither a secret nor an assertion


# ---- config wiring --------------------------------------------------------------------------------------------
def test_config_builds_the_azure_fetcher_only_when_fully_provisioned(monkeypatch):
    from sigil import config
    env = {"VIGIL_CUSTOMER_CONNECT": "1", "VIGIL_CUSTOMER_CLOUD_CONNECT": "1",
           "VIGIL_CLOUD_CONNECT_AZURE_CLIENT_ID": CLIENT_ID,
           "VIGIL_CLOUD_CONNECT_AZURE_CLIENT_SECRET": "not-a-real-secret"}  # gitleaks:allow - test placeholder
    for k, v in env.items():
        monkeypatch.setenv(k, v)
    assert isinstance(config.azure_connect_fetcher(), AzureConsentConnectFetcher)
    assert config.cloud_connect_azure_client_id() == CLIENT_ID
    for missing in env:
        # VIGIL_CUSTOMER_CONNECT is now DEFAULT-ON, so FORCE it off (=0) to prove the master still gates the
        # fetcher; every other required piece is removed by unsetting it.
        if missing == "VIGIL_CUSTOMER_CONNECT":
            monkeypatch.setenv(missing, "0")
        else:
            monkeypatch.delenv(missing)
        assert config.azure_connect_fetcher() is None, missing
        monkeypatch.setenv(missing, env[missing])
    # a client assertion (cert path) in place of a secret also builds the fetcher
    monkeypatch.delenv("VIGIL_CLOUD_CONNECT_AZURE_CLIENT_SECRET")
    monkeypatch.setenv("VIGIL_CLOUD_CONNECT_AZURE_CLIENT_ASSERTION", "eyJ.assertion.jwt")
    assert isinstance(config.azure_connect_fetcher(), AzureConsentConnectFetcher)
    for bad in ("not-a-guid", "", "11111111-1111-1111-1111-11111111111g"):
        monkeypatch.setenv("VIGIL_CLOUD_CONNECT_AZURE_CLIENT_ID", bad)
        assert config.cloud_connect_azure_client_id() == "" and config.azure_connect_fetcher() is None, bad
