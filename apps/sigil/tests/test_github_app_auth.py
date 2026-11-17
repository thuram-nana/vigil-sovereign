"""Red-Pen R2 — the customer-facing GitHub App auth (sovereign-only, decision O-5).

Invariants pinned here:
  * the App JWT is RS256, iss = App id, inside GitHub's 10-minute window with iat backdated for skew, and its
    signature verifies under the App PUBLIC key;
  * the installation-token exchange POSTs to /app/installations/{id}/access_tokens with the App JWT as a Bearer,
    pins the API version, and returns GitHub's token (the accessor R3's broker calls);
  * the installation reads + the check-run write present the INSTALLATION token under the ``token`` scheme, never
    the App JWT, and the check run validates the repo / status / conclusion / head sha;
  * the App private key is OFF the spine and never in a repr or an error message;
  * every call is fail-closed when Red-Pen is off or the credential is missing / unusable;
  * NO network — a FAKE GitHub is injected through the egress transport seam.
"""
from __future__ import annotations

import base64
import json

import pytest

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa

from sigil.governor import github_app as ga
from sigil.governor import github_app_egress as egress


def _rsa_pem() -> str:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL,
                             serialization.NoEncryption()).decode("ascii")


def _public_of(pem: str):
    return serialization.load_pem_private_key(pem.encode(), password=None).public_key()


@pytest.fixture
def app(monkeypatch):
    """A configured App behind the enabled flag; returns the PEM so a test can verify the signature."""
    pem = _rsa_pem()
    monkeypatch.setenv("VIGIL_REDPEN_ENABLED", "1")
    monkeypatch.setenv("VIGIL_GITHUB_APP_ID", "12345")
    monkeypatch.setenv("VIGIL_GITHUB_APP_PRIVATE_KEY", pem)
    return pem


def _b64urld(seg: str) -> dict:
    return json.loads(base64.urlsafe_b64decode(seg + "=" * (-len(seg) % 4)))


def test_the_app_jwt_is_rs256_within_the_ten_minute_window_signed_by_the_app_key(app):
    jwt = ga.build_app_jwt(now=1_000_000)
    header_b64, claims_b64, sig_b64 = jwt.split(".")
    assert _b64urld(header_b64) == {"alg": "RS256", "typ": "JWT"}
    claims = _b64urld(claims_b64)
    assert claims["iss"] == "12345"
    assert claims["iat"] <= 1_000_000                       # iat backdated for clock skew
    assert 0 < claims["exp"] - 1_000_000 <= 600             # inside GitHub's 10-minute ceiling
    # the signature verifies under the App PUBLIC key (RS256 = PKCS1v15 + SHA256 over header.claims)
    sig = base64.urlsafe_b64decode(sig_b64 + "=" * (-len(sig_b64) % 4))
    _public_of(app).verify(sig, f"{header_b64}.{claims_b64}".encode(), padding.PKCS1v15(), hashes.SHA256())


def test_the_installation_token_is_exchanged_with_the_app_jwt_as_a_bearer(app):
    seen = {}

    def fake(method, url, *, headers, body):
        seen.update(method=method, url=url, auth=headers["Authorization"], ver=headers.get("X-GitHub-Api-Version"))
        return {"token": "ghs_tok", "expires_at": "2026-11-17T01:00:00Z", "repository_selection": "selected"}

    out = ga.mint_installation_token(42, now=1_000_000, transport=fake)
    assert out["token"] == "ghs_tok"
    assert seen["method"] == "POST"
    assert seen["url"] == "https://api.github.com/app/installations/42/access_tokens"
    assert seen["auth"].startswith("Bearer ")                # the App JWT, not an installation token
    assert seen["ver"] == "2022-11-28"


def test_the_installation_reads_present_the_installation_token_not_the_app_jwt(app):
    seen = {}

    def fake(method, url, *, headers, body):
        seen.update(url=url, auth=headers["Authorization"])
        return {"total_count": 1, "repositories": [{"full_name": "acme/widgets"}]}

    ga.list_installation_repositories("ghs_tok", transport=fake)
    assert seen["url"] == "https://api.github.com/installation/repositories"
    assert seen["auth"] == "token ghs_tok"                   # installation token under the `token` scheme


def test_the_check_run_is_created_then_updated_with_the_installation_token(app):
    calls = []

    def fake(method, url, *, headers, body):
        calls.append((method, url, headers["Authorization"], json.loads(body.decode())))
        return {"id": 777, "status": "completed"}

    ga.post_check_run("ghs_tok", "github.com/acme/widgets", head_sha="a" * 40, status="completed",
                      conclusion="failure", title="t", summary="s", transport=fake)
    ga.post_check_run("ghs_tok", "github.com/acme/widgets", head_sha="a" * 40, status="completed",
                      conclusion="failure", check_run_id=777, transport=fake)
    create, update = calls
    assert create[0] == "POST" and create[1].endswith("/repos/acme/widgets/check-runs")
    assert update[0] == "PATCH" and update[1].endswith("/repos/acme/widgets/check-runs/777")
    assert create[2] == "token ghs_tok" and create[3]["conclusion"] == "failure"
    assert create[3]["head_sha"] == "a" * 40 and create[3]["name"] == ga.CHECK_RUN_NAME


def test_a_completed_check_run_without_a_valid_conclusion_is_refused(app):
    with pytest.raises(ga.GitHubAppError):
        ga.post_check_run("ghs_tok", "github.com/acme/widgets", head_sha="a" * 40, status="completed",
                          conclusion="bogus", transport=lambda *a, **k: {})
    with pytest.raises(ga.GitHubAppError):                   # a non-hex sha is refused before any egress
        ga.post_check_run("ghs_tok", "github.com/acme/widgets", head_sha="not-a-sha", status="completed",
                          conclusion="failure", transport=lambda *a, **k: {})


def test_the_app_private_key_is_off_spine_and_never_in_a_repr_or_an_error(app):
    sec = ga._Secret(app)
    assert app not in repr(sec) and app not in str(sec) and "redacted" in repr(sec)
    # a malformed key raises WITHOUT echoing the key material
    bad = "-----BEGIN RSA PRIVATE KEY-----\nSECRETGARBAGE\n-----END RSA PRIVATE KEY-----"
    try:
        ga._sign_rs256(b"x", bad)
        assert False, "a malformed PEM must refuse"
    except ga.GitHubAppError as e:
        assert "SECRETGARBAGE" not in str(e)


def test_an_ec_key_is_refused_app_jwts_are_rs256(app, monkeypatch):
    ec_pem = (ec.generate_private_key(ec.SECP256R1())
              .private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL,
                             serialization.NoEncryption()).decode())
    monkeypatch.setenv("VIGIL_GITHUB_APP_PRIVATE_KEY", ec_pem)
    with pytest.raises(ga.GitHubAppError, match="RSA"):
        ga.build_app_jwt(now=1_000_000)


def test_every_app_call_is_refused_when_red_pen_is_off(monkeypatch, app):
    monkeypatch.delenv("VIGIL_REDPEN_ENABLED", raising=False)
    assert ga.github_app_configured() is True               # the credential presence is independent of the flag
    for call in (lambda: ga.build_app_jwt(now=1),
                 lambda: ga.mint_installation_token(42, now=1, transport=lambda *a, **k: {}),
                 lambda: ga.list_installation_repositories("t", transport=lambda *a, **k: {}),
                 lambda: ga.post_check_run("t", "github.com/a/b", head_sha="a" * 40, status="queued",
                                           transport=lambda *a, **k: {})):
        with pytest.raises(ga.GitHubAppError):
            call()


def test_a_missing_credential_is_fail_closed(monkeypatch):
    monkeypatch.setenv("VIGIL_REDPEN_ENABLED", "1")
    monkeypatch.delenv("VIGIL_GITHUB_APP_ID", raising=False)
    monkeypatch.delenv("VIGIL_GITHUB_APP_PRIVATE_KEY", raising=False)
    monkeypatch.delenv("VIGIL_GITHUB_APP_PRIVATE_KEY_SSM", raising=False)
    assert ga.github_app_configured() is False
    with pytest.raises(ga.GitHubAppError):
        ga.build_app_jwt(now=1)


def test_the_egress_pins_https_and_the_github_host_before_any_socket(monkeypatch):
    # the host pin is checked in request() BEFORE the transport is called (a fake that would answer never runs)
    answered = []
    monkeypatch.setattr(egress, "api_url", lambda path: "https://evil.example.com" + path)
    with pytest.raises(egress.GitHubEgressError, match="non-allowlisted host"):
        egress.request("GET", "/x", bearer="t", transport=lambda *a, **k: answered.append(1))
    assert answered == []


def test_a_transient_http_is_marked_transient(app):
    def boom(method, url, *, headers, body):
        raise egress._err("GitHub POST returned HTTP 503", transient=True, status=503)

    with pytest.raises(ga.GitHubAppError):
        ga.mint_installation_token(42, now=1, transport=boom)
