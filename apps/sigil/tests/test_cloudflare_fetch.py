"""Consumer PR-C — the live CLOUDFLARE cloud-connect fetcher (``sigil.ui.cloudflare_fetch``), offline.

No network: a FAKE Cloudflare API stands behind the fetcher's injectable transport (and, for the real ``_get`` path,
behind the ``_do_open`` seam). The fake enforces a real token (``Authorization: Bearer``), a real token-definition
(name + policies + account scope), and Cloudflare's ``{success, result, errors}`` envelope, so the observation the
verdict judges is produced the way Cloudflare would produce it.

Pinned here:
  * a good read-only, single-account token named ``vigil-verify-{external_id}`` yields
    {token_id, account, name_matched: True, external_id, read_only: True, single_account: True} in exactly two GETs
    (verify, then the token's own definition);
  * the tampered variants the verdict must catch: a wrong token name (name_matched False), a write/edit permission
    present (read_only False), a ``*``/all-accounts resource (single_account False), a different account scope
    (account != claimed), an inactive token, a token that cannot read its own definition — each surfaced honestly;
  * a rejected token (401 / success:false) is the customer's fix; a 5xx / transport fault is INCONCLUSIVE and raises
    (fail closed); inputs are validated before any call; the egress is pinned to the allowlist before any socket;
  * the token NEVER renders in a repr, an error message, or an error detail;
  * ``config.cloud_connect_cloudflare_fetcher`` builds the fetcher only when the cloud leg is on.
"""
from __future__ import annotations

import io
import json
import urllib.error

import pytest

from sigil.ui import cloudflare_fetch as cf
from sigil.ui.cloudflare_fetch import CloudflareTokenConnectFetcher
from sigil.ui.cloud_fetch import CloudFetchError
from sigil.reuse import sha256_hex

ACCT = "a1b2c3d4e5f6071829304a5b6c7d8e9f"           # 32 lowercase hex (a Cloudflare account id)
OTHER_ACCT = "ffeeddccbbaa00998877665544332211"
TOKEN_ID = "0f1e2d3c4b5a69788796a5b4c3d2e1f0"
USER_ID = "99887766554433221100aabbccddeeff"
TOKEN = "cfTESTtoken0123456789ABCDEFghijkl-_wxyz"   # ~40 chars of the token charset (never a real secret)
EXT = "EXT-abc_123-XYZ"
GOOD_NAME = f"vigil-verify-{EXT}"


# ---- a fake Cloudflare API ------------------------------------------------------------------------------------
def _ok(result) -> bytes:
    return json.dumps({"success": True, "errors": [], "messages": [], "result": result}).encode()


def _err(code: int, msg: str = "nope") -> bytes:
    return json.dumps({"success": False, "errors": [{"code": code, "message": msg}], "result": None}).encode()


def _ro_policies(acct=ACCT, *, groups=("Account Settings Read", "Zone Read"), user_self=True, extra=None):
    pols = [{"id": "p1", "effect": "allow", "resources": {f"com.cloudflare.api.account.{acct}": "*"},
             "permission_groups": [{"id": str(i), "name": g} for i, g in enumerate(groups)]}]
    if user_self:
        pols.append({"id": "p2", "effect": "allow", "resources": {f"com.cloudflare.api.user.{USER_ID}": "*"},
                     "permission_groups": [{"id": "u", "name": "User API Tokens Read"}]})
    if extra:
        pols.append(extra)
    return pols


class FakeCloudflare:
    """Cloudflare's token API, faithfully enough: checks each Bearer, answers ``/user/tokens/verify`` with the token's
    id + status and ``/user/tokens/{id}`` with its name + policies. ``reject`` = an invalid token (401 success:false);
    ``verify`` / ``detail`` override the raw (status, body) answer for the inconclusive-answer tests."""

    def __init__(self, *, name=GOOD_NAME, policies=None, status="active", token_id=TOKEN_ID,
                 reject=False, verify=None, detail=None):
        self.name, self.status, self.token_id = name, status, token_id
        self.policies = policies if policies is not None else _ro_policies()
        self.reject, self.verify, self.detail = reject, verify, detail
        self.calls: list = []

    def __call__(self, url, headers, body, timeout):
        assert url.startswith("https://api.cloudflare.com/client/v4/")
        assert headers["Authorization"].startswith("Bearer ") and body == b""
        token = headers["Authorization"].split("Bearer ", 1)[1]
        path = url.split("/client/v4/", 1)[1]
        self.calls.append((path, token))
        if path == "user/tokens/verify":
            if self.verify is not None:
                return self.verify
            if self.reject:
                return 401, _err(1000, "Invalid API Token")
            return 200, _ok({"id": self.token_id, "status": self.status})
        if path == f"user/tokens/{self.token_id}":
            if self.detail is not None:
                return self.detail
            return 200, _ok({"id": self.token_id, "name": self.name, "status": self.status, "policies": self.policies})
        return 404, _err(7003, "no route")


def _fetcher(api) -> CloudflareTokenConnectFetcher:
    return CloudflareTokenConnectFetcher(transport=api)


def _assume(f, *, account=ACCT, token=TOKEN, ext=EXT, ctl="CTL-RANDOM-1"):
    return f.assume(provider="cloudflare", account_id=account, role_ref=token, external_id=ext,
                    control_external_id=ctl)


# ---- the observation -------------------------------------------------------------------------------------------
def test_a_good_read_only_single_account_token_is_observed_in_two_calls():
    api = FakeCloudflare()
    obs = _assume(_fetcher(api))
    assert obs == {"token_id": TOKEN_ID, "account": ACCT, "name_matched": True, "external_id": EXT,
                   "read_only": True, "single_account": True,
                   "token_sha256": sha256_hex(TOKEN.encode("utf-8"))}
    assert [c[0] for c in api.calls] == ["user/tokens/verify", f"user/tokens/{TOKEN_ID}"]
    assert all(c[1] == TOKEN for c in api.calls)        # both reads carried the customer's bearer token


def test_the_recorded_token_sha256_is_of_the_stripped_token_not_the_raw_field():
    # red-pen wyi72aiax (LOW): the fetcher strips the pasted token (e.g. a trailing newline from copy-paste) BEFORE it
    # verifies it, so the sha256 it records — the hash the grant recognises a re-presented token by — must be of the
    # STRIPPED bytes, never the raw field. A pasted token with surrounding whitespace yields the canonical hash.
    clean = _assume(_fetcher(FakeCloudflare()))["token_sha256"]
    padded = _assume(_fetcher(FakeCloudflare()), token=f"  {TOKEN}\n")["token_sha256"]
    assert clean == padded == sha256_hex(TOKEN.encode("utf-8"))


def test_a_token_named_for_a_different_challenge_reports_name_not_matched():
    obs = _assume(_fetcher(FakeCloudflare(name="vigil-verify-SOMETHING-ELSE")))
    assert obs["name_matched"] is False                 # the verdict refuses this (replay / wrong binding)
    obs2 = _assume(_fetcher(FakeCloudflare(name="my-token")))
    assert obs2["name_matched"] is False


@pytest.mark.parametrize("groups", [
    ("Account Settings Read", "DNS Write"),
    ("Account Settings Read", "Zone WAF Edit"),
    ("Workers Scripts Write",),
    ("Account Rulesets Manage",),
    ("Account Settings",),                              # an unknown/no-read-indicator group -> NOT read-only (fail closed)
])
def test_a_token_carrying_any_non_read_only_group_reports_not_read_only(groups):
    obs = _assume(_fetcher(FakeCloudflare(policies=_ro_policies(groups=groups))))
    assert obs["read_only"] is False


@pytest.mark.parametrize("resources", [
    {"*": "*"},
    {"com.cloudflare.api.account.*": "*"},
])
def test_an_account_global_token_reports_not_single_account(resources):
    pol = {"id": "p1", "effect": "allow", "resources": resources,
           "permission_groups": [{"id": "0", "name": "Account Settings Read"}]}
    obs = _assume(_fetcher(FakeCloudflare(policies=[pol])))
    assert obs["single_account"] is False and obs["account"] == ""


def test_a_token_reaching_two_accounts_reports_not_single_account():
    extra = {"id": "p3", "effect": "allow", "resources": {f"com.cloudflare.api.account.{OTHER_ACCT}": "*"},
             "permission_groups": [{"id": "0", "name": "Account Settings Read"}]}
    obs = _assume(_fetcher(FakeCloudflare(policies=_ro_policies(extra=extra))))
    assert obs["single_account"] is False


def test_the_observed_account_is_the_tokens_scope_not_what_was_claimed():
    obs = _assume(_fetcher(FakeCloudflare(policies=_ro_policies(acct=OTHER_ACCT))))
    assert obs["account"] == OTHER_ACCT and obs["single_account"] is True   # the verdict then refuses the mismatch


def test_a_token_scoped_to_the_account_plus_a_wildcard_is_single_account_false():
    # reaches the right account AND an all-accounts wildcard: the account matches but single_account is False
    pol = {"id": "p1", "effect": "allow",
           "resources": {f"com.cloudflare.api.account.{ACCT}": "*", "com.cloudflare.api.account.*": "*"},
           "permission_groups": [{"id": "0", "name": "Account Settings Read"}]}
    obs = _assume(_fetcher(FakeCloudflare(policies=[pol])))
    assert obs["account"] == ACCT and obs["single_account"] is False


def test_an_inactive_token_fails_closed():
    with pytest.raises(CloudFetchError, match="not active"):
        _assume(_fetcher(FakeCloudflare(status="disabled")))


def test_a_rejected_token_names_the_customers_fix():
    api = FakeCloudflare(reject=True)
    with pytest.raises(CloudFetchError, match="rejected"):
        _assume(_fetcher(api))
    assert len(api.calls) == 1                           # stopped at verify


@pytest.mark.parametrize("answer", [(500, b"oops"), (502, _err(1000)), (200, b"<not-json"),
                                    (200, _ok({"id": "short", "status": "active"}))])
def test_an_inconclusive_verify_answer_fails_closed(answer):
    with pytest.raises(CloudFetchError):
        _assume(_fetcher(FakeCloudflare(verify=answer)))


def test_a_token_that_cannot_read_its_own_definition_fails_closed():
    # a minimal token lacking "User API Tokens Read" can't read /user/tokens/{id}: 403 success:false -> fail closed,
    # never over-accepted (the verify succeeded, but scope could not be read)
    with pytest.raises(CloudFetchError, match="read the token's own definition"):
        _assume(_fetcher(FakeCloudflare(detail=(403, _err(9109, "Unauthorized to access requested resource")))))


def test_a_transport_fault_is_inconclusive_and_fails_closed():
    def boom(url, headers, body, timeout):
        raise ConnectionResetError("reset")
    with pytest.raises(CloudFetchError, match="could not be reached"):
        _assume(_fetcher(boom))


@pytest.mark.parametrize("kw, why", [
    ({"account": "not-hex"}, "32 hex"),
    ({"account": "A1B2C3D4E5F6071829304A5B6C7D8E9F"}, "32 hex"),     # uppercase is not a Cloudflare account id
    ({"token": "short"}, "malformed"),
    ({"token": "bad token with spaces and : colons"}, "malformed"),
    ({"ext": "SAME", "ctl": "SAME"}, "could not be made"),
    ({"ext": ""}, "could not be made"),
])
def test_inputs_are_validated_before_any_call(kw, why):
    api = FakeCloudflare()
    with pytest.raises(CloudFetchError, match=why):
        _assume(_fetcher(api), **kw)
    assert api.calls == []
    with pytest.raises(CloudFetchError, match="only Cloudflare"):
        _fetcher(api).assume(provider="aws", account_id=ACCT, role_ref=TOKEN, external_id="a1",
                             control_external_id="b2")
    assert api.calls == []


def test_the_egress_is_pinned_to_the_allowlist_before_any_socket(monkeypatch):
    from sigil import config
    api = FakeCloudflare()
    monkeypatch.setattr(config, "CLOUDFLARE_API_EGRESS_ALLOWLIST", frozenset())
    with pytest.raises(CloudFetchError) as e:
        _assume(_fetcher(api))
    assert api.calls == [] and "non-allowlisted" in e.value.detail
    for bad in ("http://api.cloudflare.com/x", "https://u@api.cloudflare.com/x",
                "https://api.cloudflare.com:8443/x", "https://evil.example/x"):
        with pytest.raises(CloudFetchError):
            cf._guard(bad)


# ---- the pure policy/group helpers (fully offline) -------------------------------------------------------------
@pytest.mark.parametrize("name, ro", [
    ("Account Settings Read", True), ("Zone Read", True), ("User API Tokens Read", True),
    ("Account Analytics Read", True), ("Logs Read", True),
    ("DNS Write", False), ("Zone WAF Edit", False), ("Account Rulesets Manage", False),
    ("Workers Scripts Write", False), ("Account Settings", False), ("", False), ("Billing Admin", False),
])
def test_read_only_group_detection(name, ro):
    assert cf._is_read_only_group(name) is ro


def test_policy_evaluation_is_fail_closed_on_odd_shapes():
    # a zone-global / organization / unknown resource -> broad -> not single-account
    for res in ({"com.cloudflare.api.organization.x": "*"}, {"com.cloudflare.api.zone.z": "*"}, "not-a-dict"):
        pol = {"effect": "allow", "resources": res, "permission_groups": [{"name": "Zone Read"}]}
        ro, single, acct = cf._evaluate_policies([pol] if res != "not-a-dict" else ["not-a-dict"])
        assert single is False
    # a deny policy is ignored; only the allow grants
    ro, single, acct = cf._evaluate_policies([
        {"effect": "deny", "resources": {"com.cloudflare.api.account.x": "*"},
         "permission_groups": [{"name": "DNS Write"}]},
        {"effect": "allow", "resources": {f"com.cloudflare.api.account.{ACCT}": "*"},
         "permission_groups": [{"name": "Account Settings Read"}]}])
    assert (ro, single, acct) == (True, True, ACCT)


# ---- the real _get path (behind the _do_open seam) -------------------------------------------------------------
class _Resp(io.BytesIO):
    status = 200

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def test_the_real_get_path_returns_cloudflare_error_documents_and_bounds_the_read(monkeypatch):
    def denied(req, timeout):
        raise urllib.error.HTTPError(req.full_url, 403, "Forbidden", {}, io.BytesIO(_err(9109)))
    monkeypatch.setattr(cf, "_do_open", denied)
    status, raw = cf._get("https://api.cloudflare.com/client/v4/user/tokens/verify", {}, 1.0)
    assert status == 403 and b"9109" in raw
    monkeypatch.setattr(cf, "_do_open", lambda req, timeout: _Resp(b"a" * (cf._MAX_RESPONSE_BYTES + 10)))
    with pytest.raises(CloudFetchError, match="could not be made"):
        cf._get("https://api.cloudflare.com/client/v4/user/tokens/verify", {}, 1.0)

    def fault(req, timeout):
        raise urllib.error.URLError("no route")
    monkeypatch.setattr(cf, "_do_open", fault)
    with pytest.raises(CloudFetchError, match="could not be reached"):
        cf._get("https://api.cloudflare.com/client/v4/user/tokens/verify", {}, 1.0)


def test_the_redirect_handler_never_follows():
    assert cf._NoRedirect().redirect_request(None, None, 302, "Found", {}, "https://evil.example/") is None


# ---- the token never leaks -------------------------------------------------------------------------------------
def test_the_token_never_renders_in_a_repr_or_an_error():
    f = _fetcher(FakeCloudflare())
    assert TOKEN not in repr(f)
    for api in (FakeCloudflare(reject=True), FakeCloudflare(status="disabled"),
                FakeCloudflare(detail=(403, _err(9109))), FakeCloudflare(verify=(500, b"x"))):
        try:
            _assume(_fetcher(api))
        except CloudFetchError as e:
            assert TOKEN not in str(e) and TOKEN not in e.detail

    def boom(url, headers, body, timeout):
        raise ConnectionResetError(TOKEN)               # even an exception carrying the token must not leak it
    try:
        _assume(_fetcher(boom))
    except CloudFetchError as e:
        assert TOKEN not in str(e) and TOKEN not in e.detail


# ---- config wiring ---------------------------------------------------------------------------------------------
def test_config_builds_the_cloudflare_fetcher_only_when_the_cloud_leg_is_on(monkeypatch):
    from sigil import config
    monkeypatch.delenv("VIGIL_CUSTOMER_CONNECT", raising=False)
    monkeypatch.delenv("VIGIL_CUSTOMER_CLOUD_CONNECT", raising=False)
    assert config.cloud_connect_cloudflare_fetcher() is None
    monkeypatch.setenv("VIGIL_CUSTOMER_CONNECT", "1")
    assert config.cloud_connect_cloudflare_fetcher() is None        # the cloud leg's own flag is still off
    monkeypatch.setenv("VIGIL_CUSTOMER_CLOUD_CONNECT", "1")
    assert isinstance(config.cloud_connect_cloudflare_fetcher(), CloudflareTokenConnectFetcher)
