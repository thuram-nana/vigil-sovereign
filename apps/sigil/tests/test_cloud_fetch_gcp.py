"""Consumer PR-C — the live GCP cloud-connect fetcher (``sigil.ui.cloud_fetch.GcpImpersonationConnectFetcher``),
offline.

No network: a FAKE Google stands behind the fetcher's injectable transport (and, for the real ``_gcp_request`` path,
behind the ``_do_open`` seam). The GCP proof is NAME-BINDING: VIGIL computes the exact, challenge-bound SA email from
(project, external id) and impersonates EXACTLY that SA; a 200 is the whole positive proof. There is no metadata read
(a target SA cannot read itself) and no never-created "control SA" (which would always be denied, so is vacuous).

Pinned here:
  * the RS256 signer reproduces a FROZEN PKCS#1-v1.5/SHA256 vector over a known RSA test key, and the connector
    assertion the fetcher builds decodes to the standard SA-assertion claims and verifies against the public key
    (deterministic — a frozen clock);
  * a good grant yields {impersonated: True, expected_email, project, external_id} in exactly two calls (token,
    generateAccessToken on the challenge-named SA);
  * VIGIL impersonates the SA it COMPUTED (never the customer's free-text name); a submitted SA that is not the one
    shown is refused before any network call;
  * a 403 / 404 on the expected SA names the customer's fix (create the SA + grant tokenCreator); any other status /
    5xx / transport fault is INCONCLUSIVE and raises (fail closed);
  * inputs are validated before any call; the egress is pinned to the GCP allowlist before any socket; the connector
    key never renders in a repr or an error; a bad PEM fails closed;
  * the SA-id derivation is byte-identical across ui.cloud_fetch and governor.cloud_connect and fits GCP's SA-id rule;
  * ``config.cloud_connect_gcp_fetcher`` builds the fetcher only when the cloud leg is on AND fully provisioned.
"""
from __future__ import annotations

import io
import json
import re
import urllib.error
from urllib.parse import parse_qs, unquote

import pytest

from sigil.ui import cloud_fetch as cf
from sigil.ui.cloud_fetch import CloudFetchError, GcpImpersonationConnectFetcher

# A FIXED 2048-bit RSA test key (not a secret — generated for this vector) + its public half, and a frozen
# PKCS#1-v1.5/SHA256 signature over a known input. RSA-SHA256 is deterministic, so the vector pins the signer.
TEST_KEY_PEM = """-----BEGIN PRIVATE KEY-----
MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQCvNWm4iSlHAoLy
CvlTD8SmfC3B7ppJV1aIW/ugv1J7jIDNqQwhfWbqwuCmq8sVrecvIVigOXwUAode
4BRkdqDtvStJ+97tSkhNQY62HkuXIFyO90XoZ3VH/bo4gwtDliDo6NqmB3z321Hq
YkrZbBQCar5AZHcPtlTmsf+5hRI5az5Xgg1iYzfknldyaXJIi9Jv4nCWgjy0hth/
l1t2OHDu0QLlq8fUhHHtKLjM9RENYrUh/jttH3iCBUaTaL0fzB291ifPidROBk7Y
QgFzP9su+hLl3dgsW3P+1kD9hnbWTm/8prqYN7iQa3S4UxogoFj7889qLtTbBQgy
85JEWlM/AgMBAAECggEATYLCt4mugiShS3UBYfaq18A9+fqVtPZ3aLHQuweI9PFu
lg1AOZyhqB/4hKOhn4Ckstv8uj1UIAISYy2ct+knPqWefgd4Ut+25r6m5Pi4Fi6R
5AmOmscSQnwEIzYOCKNlAcTp3eOYLIqRTbCYTmGa5IrWieQoLAJMwxZh/G/bZRzJ
Chs3UN4NtTQpuTVFS5LMluIuQ8A7lzHcrnRaSLfxHK4FZWlZllVeBetCh7SSDYSo
dDjvLJW56t1g8MeoN6g3lRFy290CuYtx1OZ3hOs6Ruhaqw6Ej4ptDp4kiAIbISlR
ZqMdqdK+GHL4pMxWO1+RoHbDDz9/0ZGvicw0tF52gQKBgQDtPc5+UvyzN7dAN2sp
e7IZoBNHxiTjKqQIhJaUBFhf4PgbZHz1ewTamDmfTfYTxLp2uSgYpyuWAoVbECSi
KvhcLkmAmKHvGfhvwMTtvYbzlMs0R/m0u+liKyH8SQankLqT39cr9HW7v0gUluWb
DVbfXjJ2oa+AsnMZ9X+p90FUwQKBgQC9D/N9t8Vlt1TsmyqoeLhYGkf1HdUK2m06
aT3kUT9ZfxZU/UKk97fwcpTorUfRrE2ZIIkKQeMxMS1vOWi0Wi3+YtpmRObvv/xt
75Wese2AaH4g/rUWl2uKCMul7YHSVVWtDPBvt/KfU4Ik4FpV7C6UagS9SrIJh3Mh
sgQgqj2n/wKBgQDQ2LEYWbvllS231VF8Ek1l65otfAvrAxWl/fqE0RJvTR99Fcg/
Xg2W1Z0cVUhEfNHdRAA9O6TOCOgWky58qDE9DO5dy3/6ebVPw7ZYx5iug5UjMB1t
cmLwraHccvjtuCXXmZzVL/4YyjoNDg2QonyQZF8uOgXC2NUkzA6XtHeJwQKBgQCK
uOSJb0kYzD806NmRChsBEi+QTBZgw0p4HHZ8S5029sgVDktTLiw58mkOnO5gi5PY
coX7D8M6+gGDZdVM2Ap9aF0lwxLMAcufgrb+3UEOAh3h6eJHtE0E2FVM54tlIJYf
xqm433jXrPeGRVQjTYwT/AKEPgWKdmdk5vCeYyugUwKBgQDNlo31GoGKC0NZ/17M
oZkxPvdx057YWQRUYAYnNd6Y8yXUbqbgLvGRN8HcwESlcBiU1HOIEjke5s42jD94
fRIqSVmFVDVYFr8TMzMPks+/4R7q7aXP+8Zh+wnZxAt8BRaDbZiOJgiHwl+iQWHp
0sBZxn0D36VzPgUPeoum8m3BkQ==
-----END PRIVATE KEY-----
"""
TEST_PUB_PEM = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEArzVpuIkpRwKC8gr5Uw/E
pnwtwe6aSVdWiFv7oL9Se4yAzakMIX1m6sLgpqvLFa3nLyFYoDl8FAKHXuAUZHag
7b0rSfve7UpITUGOth5LlyBcjvdF6Gd1R/26OIMLQ5Yg6Ojapgd899tR6mJK2WwU
Amq+QGR3D7ZU5rH/uYUSOWs+V4INYmM35J5XcmlySIvSb+JwloI8tIbYf5dbdjhw
7tEC5avH1IRx7Si4zPURDWK1If47bR94ggVGk2i9H8wdvdYnz4nUTgZO2EIBcz/b
LvoS5d3YLFtz/tZA/YZ21k5v/Ka6mDe4kGt0uFMaIKBY+/PPai7U2wUIMvOSRFpT
PwIDAQAB
-----END PUBLIC KEY-----
"""
SIGNING_INPUT = b"eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.VIGIL-GCP-CONNECT-PIN-VECTOR"
PINNED_SIG_HEX = ("58e53f0a30ba4cc7fdc5ffacceeb5fefb4cdf3a6900745988f9a37befea55c5a0ce5b9029e09d13d0805d9c4819dfd9c"
                  "aede55ef83ab8f17aed8a230caa407e5749c55945de75ad36c011aa39c31bfc1dd1cb27392bd48fa51ac03e75035e713e"
                  "b0038c65b93df6531c7a49700c69d24a3e436212186a90890ecd282b12be5bde95a6c036821d6d225f9c4700e9287d551"
                  "17717624943b967871410a837026776d314f0af4e5481453388c22ac81479b93ab8a2dd0652772dec67885789b367516b"
                  "90deac67065b4c62fa294a47cac3e6171c2fc92ce03196d19720eb048a5258d3e42ab6b81d4e7593fff93406a1d4e9189"
                  "fc51257d838d5eb1c9ae4587516e")

PROJECT = "my-company-prod"
CONNECTOR_SA = "vigil-connector@vigil-sovereign-prod.iam.gserviceaccount.com"
EXT = "ext-ABC_123-xyz"
EXPECTED_EMAIL = cf._gcp_expected_sa_email(PROJECT, EXT)
FROZEN = 1795089600.0


def _json(d) -> bytes:
    return json.dumps(d).encode()


def _b64url_decode(s: str) -> bytes:
    import base64
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _sa_from_gen_url(url: str) -> str:
    return unquote(url.split("/serviceAccounts/", 1)[1].rsplit(":generateAccessToken", 1)[0])


class FakeGoogle:
    """oauth2 + iamcredentials, faithfully enough. ``grant_email`` is the ONE SA the connector may impersonate (the
    customer's project-admin grant; default = the challenge-named SA, so the good case succeeds). ``not_found`` makes a
    non-granted SA answer 404 instead of 403. ``override(method, url, body, call_n)`` can force a canned answer."""

    def __init__(self, *, grant_email=None, not_found=False, override=None):
        self.grant_email = grant_email if grant_email is not None else EXPECTED_EMAIL
        self.not_found, self.override = not_found, override
        self.connector_tok = "connector-access-token"
        self.imp_tok = "impersonated-access-token"
        self.calls: list = []

    def __call__(self, method, url, headers, body, timeout):
        self.calls.append((method, url, headers.get("Authorization", "")))
        if self.override is not None:
            hit = self.override(method, url, body, len(self.calls))
            if hit is not None:
                return hit
        if url == cf._OAUTH_TOKEN_URL:
            form = {k: v[0] for k, v in parse_qs(body.decode()).items()}
            assert form["grant_type"] == cf._JWT_BEARER_GRANT
            assert form["assertion"].count(".") == 2
            return 200, _json({"access_token": self.connector_tok, "token_type": "Bearer", "expires_in": 3600})
        if url.endswith(":generateAccessToken"):
            assert headers.get("Authorization") == "Bearer " + self.connector_tok
            sa = _sa_from_gen_url(url)
            if sa == self.grant_email:
                return 200, _json({"accessToken": self.imp_tok, "expireTime": "2026-11-19T13:00:00Z"})
            if self.not_found:
                return 404, _json({"error": {"code": 404, "status": "NOT_FOUND", "message": "missing"}})
            return 403, _json({"error": {"code": 403, "status": "PERMISSION_DENIED", "message": "denied"}})
        return 404, _json({"error": {"code": 404, "status": "NOT_FOUND"}})


def _fetcher(fake, *, key=TEST_KEY_PEM, email=CONNECTOR_SA) -> GcpImpersonationConnectFetcher:
    return GcpImpersonationConnectFetcher(connector_email=email, private_key_pem=key, transport=fake,
                                          clock=lambda: FROZEN)


def _assume(f, *, project=PROJECT, role=EXPECTED_EMAIL, ext=EXT):
    return f.assume(provider="gcp", account_id=project, role_ref=role, external_id=ext, control_external_id="ctl-x")


# ---- the signer ------------------------------------------------------------------------------------------------
def test_rs256_signer_matches_the_pinned_vector():
    assert cf._sign_rs256(SIGNING_INPUT, TEST_KEY_PEM).hex() == PINNED_SIG_HEX


def test_the_connector_assertion_is_a_valid_rs256_sa_jwt():
    captured: dict = {}

    class _Cap(FakeGoogle):
        def __call__(self, method, url, headers, body, timeout):
            if url == cf._OAUTH_TOKEN_URL:
                captured["assertion"] = parse_qs(body.decode())["assertion"][0]
            return super().__call__(method, url, headers, body, timeout)

    _assume(_fetcher(_Cap()))
    header_b64, claims_b64, sig_b64 = captured["assertion"].split(".")
    header = json.loads(_b64url_decode(header_b64))
    claims = json.loads(_b64url_decode(claims_b64))
    assert header == {"alg": "RS256", "typ": "JWT"}
    assert claims["iss"] == CONNECTOR_SA and claims["sub"] == CONNECTOR_SA
    assert claims["aud"] == cf._OAUTH_TOKEN_URL and claims["scope"] == cf._CLOUD_PLATFORM_SCOPE
    assert claims["iat"] == int(FROZEN) and claims["exp"] == int(FROZEN) + cf._GCP_JWT_LIFETIME_S
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding
    pub = serialization.load_pem_public_key(TEST_PUB_PEM.encode("utf-8"))
    pub.verify(_b64url_decode(sig_b64), f"{header_b64}.{claims_b64}".encode("ascii"),
               padding.PKCS1v15(), hashes.SHA256())


def test_a_bad_connector_pem_fails_closed():
    with pytest.raises(CloudFetchError):
        _assume(_fetcher(FakeGoogle(), key="-----BEGIN PRIVATE KEY-----\nnot-a-key\n-----END PRIVATE KEY-----\n"))


# ---- the name-binding derivation ------------------------------------------------------------------------------
def test_the_sa_id_derivation_is_pinned_across_modules_and_fits_gcps_rule():
    from sigil.governor import cloud_connect as cc
    for e in ("ext-ABC_123-xyz", "another-id", "x" * 60, "a+b=c,d.e@f:g/h-i_j"):
        assert cf._gcp_expected_sa_email(PROJECT, e) == cc._gcp_expected_sa_email(PROJECT, e)
        sid = cf._gcp_expected_sa_id(e)
        assert re.fullmatch(r"[a-z][a-z0-9-]{4,28}[a-z0-9]", sid) and 6 <= len(sid) <= 30, (e, sid)


# ---- the observation -------------------------------------------------------------------------------------------
def test_a_good_grant_is_observed_in_two_calls():
    fake = FakeGoogle()
    obs = _assume(_fetcher(fake))
    assert obs == {"impersonated": True, "expected_email": EXPECTED_EMAIL, "project": PROJECT, "external_id": EXT}
    assert [c[0] for c in fake.calls] == ["POST", "POST"]                 # token, generateAccessToken
    gen = next(u for (_m, u, _a) in fake.calls if u.endswith(":generateAccessToken"))
    assert _sa_from_gen_url(gen) == EXPECTED_EMAIL                        # VIGIL impersonated the COMPUTED name


def test_a_submitted_sa_that_is_not_the_one_shown_is_refused_before_any_call():
    fake = FakeGoogle()
    other = cf._gcp_expected_sa_email(PROJECT, "a-different-external-id")   # a valid SA email, but not THIS challenge's
    with pytest.raises(CloudFetchError, match="exact service account"):
        _assume(_fetcher(fake), role=other)
    assert fake.calls == []


def test_a_grant_vigil_cannot_use_yet_names_the_customers_fix():
    # the challenge-named SA answers 403 (not created / no tokenCreator): the customer's fix, stopped after the gen call
    fake = FakeGoogle(grant_email="vgl-0000000000000000000a@my-company-prod.iam.gserviceaccount.com")
    with pytest.raises(CloudFetchError, match="serviceAccountTokenCreator"):
        _assume(_fetcher(fake))
    assert [c[0] for c in fake.calls] == ["POST", "POST"]


def test_a_missing_sa_404_also_names_the_customers_fix():
    fake = FakeGoogle(grant_email="vgl-0000000000000000000a@my-company-prod.iam.gserviceaccount.com", not_found=True)
    with pytest.raises(CloudFetchError, match="serviceAccountTokenCreator"):
        _assume(_fetcher(fake))


@pytest.mark.parametrize("answer", [(500, b"oops"), (403, _json({"error": {"status": "RESOURCE_EXHAUSTED"}})),
                                    (429, _json({"error": {"status": "RESOURCE_EXHAUSTED"}})),
                                    (200, b"{not-json"), (401, _json({"error": {"status": "UNAUTHENTICATED"}}))])
def test_an_inconclusive_impersonation_status_fails_closed(answer):
    # the SECOND call (generateAccessToken) answers something other than 200 / explicit denied -> raise
    fake = FakeGoogle(override=lambda method, url, body, n: answer if n == 2 else None)
    with pytest.raises(CloudFetchError):
        _assume(_fetcher(fake))


def test_a_token_exchange_failure_fails_closed():
    fake = FakeGoogle(override=lambda method, url, body, n: (500, b"err") if n == 1 else None)
    with pytest.raises(CloudFetchError):
        _assume(_fetcher(fake))


def test_a_transport_fault_is_inconclusive_and_fails_closed():
    def boom(method, url, headers, body, timeout):
        raise ConnectionResetError("reset")
    with pytest.raises(CloudFetchError, match="could not be reached"):
        _assume(_fetcher(boom))


@pytest.mark.parametrize("kw, why", [
    ({"project": "BAD"}, "project id"),
    ({"ext": ""}, "could not be made"),
    ({"role": "not-the-shown-sa@my-company-prod.iam.gserviceaccount.com"}, "exact service account"),
])
def test_inputs_are_validated_before_any_call(kw, why):
    fake = FakeGoogle()
    with pytest.raises(CloudFetchError, match=why):
        _assume(_fetcher(fake), **kw)
    assert fake.calls == []
    with pytest.raises(CloudFetchError, match="only GCP"):
        _fetcher(fake).assume(provider="aws", account_id=PROJECT, role_ref=EXPECTED_EMAIL, external_id=EXT)
    assert fake.calls == []


def test_the_egress_is_pinned_to_the_allowlist_before_any_socket(monkeypatch):
    from sigil import config
    fake = FakeGoogle()
    monkeypatch.setattr(config, "GCP_EGRESS_ALLOWLIST", frozenset())
    with pytest.raises(CloudFetchError) as e:
        _assume(_fetcher(fake))
    assert fake.calls == [] and "non-allowlisted" in e.value.detail
    for bad in ("http://oauth2.googleapis.com/token", "https://u@iamcredentials.googleapis.com/v1",
                "https://iamcredentials.googleapis.com:8443/v1", "https://evil.example/"):
        with pytest.raises(CloudFetchError):
            cf._gcp_guard(bad)


# ---- the real _gcp_request path (behind the _do_open seam) -----------------------------------------------------
class _Resp(io.BytesIO):
    status = 200

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def test_the_real_request_path_returns_google_error_documents_and_bounds_the_read(monkeypatch):
    def denied(req, timeout):
        raise urllib.error.HTTPError(req.full_url, 403, "Forbidden", {},
                                     io.BytesIO(_json({"error": {"status": "PERMISSION_DENIED"}})))
    monkeypatch.setattr(cf, "_do_open", denied)
    status, raw = cf._gcp_request("POST", "https://iamcredentials.googleapis.com/x", {}, b"{}", 1.0)
    assert status == 403 and b"PERMISSION_DENIED" in raw
    monkeypatch.setattr(cf, "_do_open", lambda req, timeout: _Resp(b"a" * (cf._MAX_RESPONSE_BYTES + 10)))
    with pytest.raises(CloudFetchError, match="could not be made"):
        cf._gcp_request("POST", "https://iamcredentials.googleapis.com/x", {}, b"{}", 1.0)

    def fault(req, timeout):
        raise urllib.error.URLError("no route")
    monkeypatch.setattr(cf, "_do_open", fault)
    with pytest.raises(CloudFetchError, match="could not be reached"):
        cf._gcp_request("POST", "https://oauth2.googleapis.com/token", {}, b"", 1.0)


def test_credentials_never_render():
    f = _fetcher(FakeGoogle())
    assert TEST_KEY_PEM not in repr(f) and "PRIVATE KEY" not in repr(f)
    with pytest.raises(ValueError):
        GcpImpersonationConnectFetcher(connector_email="", private_key_pem=TEST_KEY_PEM)
    with pytest.raises(ValueError):
        GcpImpersonationConnectFetcher(connector_email=CONNECTOR_SA, private_key_pem="")


# ---- config wiring ------------------------------------------------------------------------------------------------
def test_config_builds_the_fetcher_only_when_the_gcp_leg_is_fully_provisioned(monkeypatch):
    from sigil import config
    env = {"VIGIL_CUSTOMER_CONNECT": "1", "VIGIL_CUSTOMER_CLOUD_CONNECT": "1",
           "VIGIL_CLOUD_CONNECT_GCP_CONNECTOR_SA": CONNECTOR_SA,
           "VIGIL_CLOUD_CONNECT_GCP_PRIVATE_KEY": TEST_KEY_PEM}
    for k, v in env.items():
        monkeypatch.setenv(k, v)
    assert isinstance(config.cloud_connect_gcp_fetcher(), GcpImpersonationConnectFetcher)
    assert config.cloud_connect_gcp_connector_sa() == CONNECTOR_SA
    for missing in env:
        # VIGIL_CUSTOMER_CONNECT is now DEFAULT-ON, so FORCE it off (=0) to prove the master still gates the
        # fetcher; every other required piece is removed by unsetting it.
        if missing == "VIGIL_CUSTOMER_CONNECT":
            monkeypatch.setenv(missing, "0")
        else:
            monkeypatch.delenv(missing)
        assert config.cloud_connect_gcp_fetcher() is None, missing
        monkeypatch.setenv(missing, env[missing])
    for bad in ("vigil-connector", "vigil-connector@proj.example.com", "vigil@x.iam.gserviceaccount.com y",
                "VIGIL@proj.iam.gserviceaccount.com"):
        monkeypatch.setenv("VIGIL_CLOUD_CONNECT_GCP_CONNECTOR_SA", bad)
        assert config.cloud_connect_gcp_connector_sa() == "" and config.cloud_connect_gcp_fetcher() is None, bad
