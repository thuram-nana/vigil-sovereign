"""Consumer PR-C — the live AWS cloud-connect fetcher (``sigil.ui.cloud_fetch``), offline.

No network: a FAKE STS stands behind the fetcher's injectable transport (and, for the real ``_post`` path, behind the
``_do_open`` seam). The fake re-verifies every request's SigV4 signature with the caller's secret and enforces a real
trust policy (which external ids the role accepts), so the observation the verdict judges is produced the way AWS
would produce it.

Pinned here:
  * the stdlib SigV4 signer reproduces AWS's published test-suite vector (get-vanilla) and the exact signatures
    botocore produces for the STS requests this module sends (generated offline, frozen clock, AWS's EXAMPLE keys);
  * a good grant yields {assumed_with_external_id, account, control_external_id, control_denied: True} in exactly
    three calls (assume, caller identity under the TEMPORARY credentials, the control assume);
  * a role that accepts any external id reports control_denied False (the verdict then refuses it);
  * only an explicit AccessDenied counts as a denied control — VIGIL's own bad credentials (another 403 code), a
    throttle, a 5xx or a transport fault are INCONCLUSIVE and raise (fail closed);
  * inputs are validated before any call; the egress is pinned to the allowlist before any socket; a DTD-bearing or
    oversized answer is refused; credentials never render in a repr or an error message;
  * ``config.cloud_connect_fetcher`` builds the fetcher only when the cloud leg is on AND fully provisioned.
"""
from __future__ import annotations

import io
import urllib.error
from urllib.parse import parse_qs

import pytest

from sigil.ui import cloud_fetch as cf
from sigil.ui.cloud_fetch import AwsStsConnectFetcher, CloudFetchError

# AWS's published documentation example credentials (sig-v4 test suite) — not a secret.
EXAMPLE_KEY_ID = "AKIDEXAMPLE"
EXAMPLE_SECRET = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"  # gitleaks:allow - AWS's published SigV4 test-suite example key
ACCT = "123456789012"
ROLE = "arn:aws:iam::123456789012:role/VigilSecurityAudit"
CT = "application/x-www-form-urlencoded; charset=utf-8"
NS = "https://sts.amazonaws.com/doc/2011-06-15/"


# ---- the signer ------------------------------------------------------------------------------------------------
def test_sigv4_matches_the_aws_test_suite_vector():
    auth = cf.sigv4_authorization(method="GET", host="example.amazonaws.com", path="/", query="",
                                  headers={"host": "example.amazonaws.com", "x-amz-date": "20150830T123600Z"},
                                  body=b"", region="us-east-1", service="service", access_key_id=EXAMPLE_KEY_ID,
                                  secret_access_key=EXAMPLE_SECRET, amz_date="20150830T123600Z")
    assert auth == ("AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, "
                    "SignedHeaders=host;x-amz-date, "
                    "Signature=5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31")


def test_sigv4_matches_botocore_for_the_exact_sts_requests():
    # Golden values produced by botocore 1.43 SigV4Auth (offline, frozen clock) for the two request shapes this module
    # sends — so the stdlib signer is pinned to the reference implementation, not just to itself.
    body = cf._form([("Action", "AssumeRole"), ("Version", "2011-06-15"), ("RoleArn", ROLE.replace("Audit", "Audit")),
                     ("RoleSessionName", "vigil-connect"), ("ExternalId", "ext-ABC_123-xyz"),
                     ("DurationSeconds", "900")])
    assert body.decode() == ("Action=AssumeRole&Version=2011-06-15&RoleArn=arn%3Aaws%3Aiam%3A%3A123456789012%3A"
                             "role%2FVigilSecurityAudit&RoleSessionName=vigil-connect&ExternalId=ext-ABC_123-xyz"
                             "&DurationSeconds=900")
    auth = cf.sigv4_authorization(method="POST", host="sts.amazonaws.com", path="/", query="",
                                  headers={"host": "sts.amazonaws.com", "x-amz-date": "20261119T120000Z",
                                           "content-type": CT}, body=body, region="us-east-1", service="sts",
                                  access_key_id=EXAMPLE_KEY_ID, secret_access_key=EXAMPLE_SECRET,
                                  amz_date="20261119T120000Z")
    assert auth.endswith("SignedHeaders=content-type;host;x-amz-date, "
                         "Signature=5ca2121c0dcf66a26d4670fe3bfe28f2bfc2898c1c934b4614fd54dfd0084106")
    auth = cf.sigv4_authorization(method="POST", host="sts.amazonaws.com", path="/", query="",
                                  headers={"host": "sts.amazonaws.com", "x-amz-date": "20261119T120000Z",
                                           "content-type": CT, "x-amz-security-token": "tokenEXAMPLE/+="},
                                  body=b"Action=GetCallerIdentity&Version=2011-06-15", region="us-east-1",
                                  service="sts", access_key_id="ASIAEXAMPLETEMP",
                                  secret_access_key="tempSecretEXAMPLE", amz_date="20261119T120000Z")
    assert auth.endswith("SignedHeaders=content-type;host;x-amz-date;x-amz-security-token, "
                         "Signature=e8a33324b83dd277ee8ff4759ec74e0629a08cbd071364aa78ebc7dfabb68f44")


def test_the_signer_refuses_to_sign_without_host_and_date():
    with pytest.raises(ValueError):
        cf.sigv4_authorization(method="GET", host="h", path="/", query="", headers={"host": "h"}, body=b"",
                               region="r", service="s", access_key_id="a", secret_access_key="b", amz_date="x")


# ---- a fake STS that verifies signatures and enforces a trust policy ---------------------------------------------
def _xml_ok_assume(n: int) -> bytes:
    return (f'<AssumeRoleResponse xmlns="{NS}"><AssumeRoleResult><Credentials><AccessKeyId>ASIATEMP{n:08d}'
            f'</AccessKeyId><SecretAccessKey>tempsecret{n}</SecretAccessKey><SessionToken>tok{n}</SessionToken>'
            f'<Expiration>2026-11-19T13:00:00Z</Expiration></Credentials><AssumedRoleUser><Arn>arn:aws:sts::{ACCT}:'
            f'assumed-role/VigilSecurityAudit/vigil-connect</Arn></AssumedRoleUser></AssumeRoleResult>'
            f'</AssumeRoleResponse>').encode()


def _xml_err(code: str, msg: str = "nope") -> bytes:
    return (f'<ErrorResponse xmlns="{NS}"><Error><Type>Sender</Type><Code>{code}</Code><Message>{msg}</Message>'
            f'</Error><RequestId>r</RequestId></ErrorResponse>').encode()


class FakeSts:
    """AWS STS, faithfully enough: verifies each SigV4 signature under the caller's secret, then answers AssumeRole by
    the role's trust policy (``accepts``: an external id -> allowed; None = the role trusts VIGIL with NO external-id
    condition) and GetCallerIdentity with the account the temporary credentials belong to."""

    def __init__(self, *, accepts=("EXT-GOOD",), lands_in=ACCT, override=None):
        self.accepts, self.lands_in, self.override = accepts, lands_in, override
        self.secrets = {EXAMPLE_KEY_ID: EXAMPLE_SECRET}
        self.temp: dict = {}
        self.calls: list = []

    def __call__(self, url, headers, body, timeout):
        assert url == "https://sts.amazonaws.com/"
        form = {k: v[0] for k, v in parse_qs(body.decode()).items()}
        auth = headers["Authorization"]
        key_id = auth.split("Credential=")[1].split("/")[0]
        token = headers.get("X-Amz-Security-Token", "")
        signed = {"host": "sts.amazonaws.com", "x-amz-date": headers["X-Amz-Date"], "content-type": CT}
        if token:
            signed["x-amz-security-token"] = token
        secret = self.secrets.get(key_id) or self.temp.get(key_id, {}).get("secret")
        expect = cf.sigv4_authorization(method="POST", host="sts.amazonaws.com", path="/", query="", headers=signed,
                                        body=body, region="us-east-1", service="sts", access_key_id=key_id,
                                        secret_access_key=secret or "?", amz_date=headers["X-Amz-Date"])
        self.calls.append((form.get("Action"), key_id, form.get("ExternalId")))
        if self.override is not None:
            hit = self.override(form, len(self.calls))
            if hit is not None:
                return hit
        if secret is None or auth != expect:
            return 403, _xml_err("SignatureDoesNotMatch")
        if form.get("Action") == "AssumeRole":
            assert form["RoleSessionName"] == "vigil-connect" and form["DurationSeconds"] == "900"
            if form.get("RoleArn") != ROLE:
                return 403, _xml_err("AccessDenied")
            if self.accepts is not None and form.get("ExternalId") not in self.accepts:
                return 403, _xml_err("AccessDenied", "not authorized to perform: sts:AssumeRole")
            n = len(self.temp) + 1
            self.temp[f"ASIATEMP{n:08d}"] = {"secret": f"tempsecret{n}", "token": f"tok{n}"}
            return 200, _xml_ok_assume(n)
        if form.get("Action") == "GetCallerIdentity":
            t = self.temp.get(key_id)
            if t is None or t["token"] != token:
                return 403, _xml_err("InvalidClientTokenId")
            return 200, (f'<GetCallerIdentityResponse xmlns="{NS}"><GetCallerIdentityResult><Arn>arn:aws:sts::'
                         f'{self.lands_in}:assumed-role/R/vigil-connect</Arn><UserId>AROA:vigil-connect</UserId>'
                         f'<Account>{self.lands_in}</Account></GetCallerIdentityResult></GetCallerIdentityResponse>'
                         ).encode()
        return 400, _xml_err("InvalidAction")


def _fetcher(sts) -> AwsStsConnectFetcher:
    return AwsStsConnectFetcher(access_key_id=EXAMPLE_KEY_ID, secret_access_key=EXAMPLE_SECRET, transport=sts,
                                clock=lambda: 1795089600.0)


def _assume(f, *, role=ROLE, account=ACCT, ext="EXT-GOOD", ctl="CTL-RANDOM-1"):
    return f.assume(provider="aws", account_id=account, role_ref=role, external_id=ext, control_external_id=ctl)


# ---- the observation -------------------------------------------------------------------------------------------
def test_a_good_grant_is_observed_in_three_signed_calls_with_a_denied_control():
    sts = FakeSts()
    obs = _assume(_fetcher(sts))
    assert obs == {"assumed_with_external_id": "EXT-GOOD", "account": ACCT, "control_external_id": "CTL-RANDOM-1",
                   "control_denied": True}
    assert [c[0] for c in sts.calls] == ["AssumeRole", "GetCallerIdentity", "AssumeRole"]
    assert sts.calls[1][1].startswith("ASIATEMP")          # the caller identity ran under the TEMPORARY credentials
    assert [c[2] for c in sts.calls] == ["EXT-GOOD", None, "CTL-RANDOM-1"]


def test_a_role_without_the_external_id_condition_reports_the_control_admitted():
    obs = _assume(_fetcher(FakeSts(accepts=None)))            # trusts VIGIL's principal with NO sts:ExternalId check
    assert obs["control_denied"] is False                     # the verdict refuses this role (confused deputy)


def test_the_observed_account_is_where_the_role_lands_not_what_was_claimed():
    assert _assume(_fetcher(FakeSts(lands_in="999999999999")))["account"] == "999999999999"


def test_a_role_that_refuses_our_external_id_names_the_customers_fix():
    sts = FakeSts(accepts=("SOMETHING-ELSE",))
    with pytest.raises(CloudFetchError, match="trust policy"):
        _assume(_fetcher(sts))
    assert len(sts.calls) == 1                                # stopped at the first refusal


@pytest.mark.parametrize("answer", [(403, _xml_err("InvalidClientTokenId")), (403, _xml_err("SignatureDoesNotMatch")),
                                    (400, _xml_err("Throttling")), (500, b"oops"), (200, b"<not-xml")])
def test_only_an_explicit_access_denied_counts_as_a_denied_control(answer):
    # the THIRD call (the control) answers something other than AccessDenied: inconclusive => raise, never "denied"
    sts = FakeSts(override=lambda form, n: answer if n == 3 else None)
    with pytest.raises(CloudFetchError):
        _assume(_fetcher(sts))


def test_a_transport_fault_is_inconclusive_and_fails_closed():
    def boom(url, headers, body, timeout):
        raise ConnectionResetError("reset")
    with pytest.raises(CloudFetchError, match="could not be reached"):
        _assume(_fetcher(boom))


@pytest.mark.parametrize("kw, why", [
    ({"role": "VigilSecurityAudit"}, "full ARN"),
    ({"role": "arn:aws:iam::999999999999:role/VigilSecurityAudit"}, "different AWS account"),
    ({"ext": "SAME", "ctl": "SAME"}, "could not be made"),
    ({"ext": ""}, "could not be made"),
])
def test_inputs_are_validated_before_any_call(kw, why):
    sts = FakeSts()
    with pytest.raises(CloudFetchError, match=why):
        _assume(_fetcher(sts), **kw)
    assert sts.calls == []
    with pytest.raises(CloudFetchError, match="only AWS"):
        _fetcher(sts).assume(provider="gcp", account_id="p", role_ref=ROLE, external_id="a1", control_external_id="b2")
    assert sts.calls == []


def test_the_egress_is_pinned_to_the_allowlist_before_any_socket(monkeypatch):
    from sigil import config
    sts = FakeSts()
    monkeypatch.setattr(config, "AWS_STS_EGRESS_ALLOWLIST", frozenset())
    with pytest.raises(CloudFetchError) as e:
        _assume(_fetcher(sts))
    assert sts.calls == [] and "non-allowlisted" in e.value.detail
    for bad in ("http://sts.amazonaws.com/", "https://u@sts.amazonaws.com/", "https://sts.amazonaws.com:8443/",
                "https://evil.example/"):
        with pytest.raises(CloudFetchError):
            cf._guard(bad)


# ---- the real _post path (behind the _do_open seam) ------------------------------------------------------------
class _Resp(io.BytesIO):
    status = 200

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def test_the_real_post_path_returns_aws_error_documents_and_bounds_the_read(monkeypatch):
    def denied(req, timeout):
        raise urllib.error.HTTPError(req.full_url, 403, "Forbidden", {}, io.BytesIO(_xml_err("AccessDenied")))
    monkeypatch.setattr(cf, "_do_open", denied)
    status, raw = cf._post("https://sts.amazonaws.com/", {}, b"x", 1.0)
    assert status == 403 and b"AccessDenied" in raw
    monkeypatch.setattr(cf, "_do_open", lambda req, timeout: _Resp(b"a" * (cf._MAX_RESPONSE_BYTES + 10)))
    with pytest.raises(CloudFetchError, match="could not be made"):
        cf._post("https://sts.amazonaws.com/", {}, b"x", 1.0)

    def fault(req, timeout):
        raise urllib.error.URLError("no route")
    monkeypatch.setattr(cf, "_do_open", fault)
    with pytest.raises(CloudFetchError, match="could not be reached"):
        cf._post("https://sts.amazonaws.com/", {}, b"x", 1.0)


def test_the_redirect_handler_never_follows():
    assert cf._NoRedirect().redirect_request(None, None, 302, "Found", {}, "https://evil.example/") is None


def test_an_answer_carrying_a_dtd_is_refused():
    evil = (b'<?xml version="1.0"?><!DOCTYPE x [<!ENTITY a "AAAA">]><AssumeRoleResponse><AccessKeyId>&a;'
            b'</AccessKeyId></AssumeRoleResponse>')
    assert cf._xml(evil) is None
    with pytest.raises(CloudFetchError):
        _assume(_fetcher(FakeSts(override=lambda form, n: (200, evil))))


def test_credentials_never_render():
    f = _fetcher(FakeSts())
    assert EXAMPLE_SECRET not in repr(f) and EXAMPLE_KEY_ID not in repr(f)
    try:
        _assume(_fetcher(FakeSts(accepts=("NOPE",))))
    except CloudFetchError as e:
        assert EXAMPLE_SECRET not in str(e) and EXAMPLE_SECRET not in e.detail
    with pytest.raises(ValueError):
        AwsStsConnectFetcher(access_key_id="", secret_access_key="x")


# ---- config wiring ------------------------------------------------------------------------------------------------
def test_config_builds_the_fetcher_only_when_the_cloud_leg_is_fully_provisioned(monkeypatch):
    from sigil import config
    env = {"VIGIL_CUSTOMER_CONNECT": "1", "VIGIL_CUSTOMER_CLOUD_CONNECT": "1",
           "VIGIL_CLOUD_CONNECT_AWS_PRINCIPAL_ARN": "arn:aws:iam::111122223333:role/vigil-connector",
           "VIGIL_CLOUD_CONNECT_AWS_ACCESS_KEY_ID": "AKIDEXAMPLE",
           "VIGIL_CLOUD_CONNECT_AWS_SECRET_ACCESS_KEY": "not-a-real-secret"}
    for k, v in env.items():
        monkeypatch.setenv(k, v)
    assert isinstance(config.cloud_connect_fetcher(), AwsStsConnectFetcher)
    assert config.cloud_connect_aws_principal_arn() == env["VIGIL_CLOUD_CONNECT_AWS_PRINCIPAL_ARN"]
    for missing in env:
        monkeypatch.delenv(missing)
        assert config.cloud_connect_fetcher() is None, missing
        monkeypatch.setenv(missing, env[missing])
    for bad in ("arn:aws:iam::12:role/x", "arn:aws-cn:iam::111122223333:role/x", "role/x",
                "arn:aws:iam::111122223333:role/x y", 'arn:aws:iam::111122223333:role/x"}'):
        monkeypatch.setenv("VIGIL_CLOUD_CONNECT_AWS_PRINCIPAL_ARN", bad)
        assert config.cloud_connect_aws_principal_arn() == "" and config.cloud_connect_fetcher() is None, bad
