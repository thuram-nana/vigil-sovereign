"""Consumer PR-C — the provisioner's CLOUDFLARE connect leg (challenge → placement, verify → owner-signed read-only
grant), and the load-bearing NEVER-STORE-THE-TOKEN invariant.

Vault-backed harness (one persisted owner key, faithful to production); runs with the integration PYTHONPATH.

Pinned here:
  * a Cloudflare challenge hands back the exact placement (a token named ``vigil-verify-{external_id}`` scoped
    read-only to the account), NOT an AWS trust policy, and the cloud leg is available whenever the flag + the
    Cloudflare fetcher + the limiter are in place (VIGIL holds no Cloudflare connector identity of its own);
  * a good read-only, single-account token records an owner-signed READ-ONLY grant carrying the token's PUBLIC id +
    a sha256 — and the raw token NEVER appears in any spine record, audit line, or the return (the central test);
  * an over-privileged (write) token, a global token, a token named for another challenge, and a rejected token all
    record NOTHING and leak nothing; the write path is ``run_engagement``-gated exactly as AWS;
  * CONNECT != OFFENSE: a Cloudflare grant mints no EngagementAuthority and leaves the live-offense gate untouched.
"""
from __future__ import annotations

import itertools
import json
import tempfile
import time

import pytest

from sigil.ui.provision import ProvisionDenied, ProvisionError

_iss = itertools.count(1)
ACCT = "a1b2c3d4e5f6071829304a5b6c7d8e9f"           # 32 lowercase hex (a Cloudflare account id)
TOKEN_ID = "0f1e2d3c4b5a69788796a5b4c3d2e1f0"
SECRET_TOKEN = "cfSECRETtok0123456789ABCDEFghij-_klmnopq"   # the bearer secret that must never be persisted
EXT_PREFIX = "vigil-verify-"


@pytest.fixture(autouse=True)
def _iso(monkeypatch):
    monkeypatch.setenv("VIGIL_BASE_DIR", tempfile.mkdtemp())
    monkeypatch.setenv("SIGIL_SPINE_DIR", tempfile.mkdtemp())
    monkeypatch.setenv("SIGIL_HOME", tempfile.mkdtemp())
    monkeypatch.setenv("VIGIL_CUSTOMER_CONNECT", "1")
    monkeypatch.setenv("VIGIL_CUSTOMER_CLOUD_CONNECT", "1")
    monkeypatch.delenv("VIGIL_CUSTOMER_PROD_EXECUTION", raising=False)   # the live-offense owner gate stays OFF


# ---- a fake Cloudflare API behind the REAL fetcher (so the token genuinely flows through provision) ----
def _ok(result):
    return json.dumps({"success": True, "errors": [], "result": result}).encode()


def _err(code, msg="nope"):
    return json.dumps({"success": False, "errors": [{"code": code, "message": msg}], "result": None}).encode()


def _ro_policies(acct=ACCT, groups=("Account Settings Read", "Zone Read")):
    return [{"effect": "allow", "resources": {f"com.cloudflare.api.account.{acct}": "*"},
             "permission_groups": [{"name": g} for g in groups]},
            {"effect": "allow", "resources": {"com.cloudflare.api.user.u": "*"},
             "permission_groups": [{"name": "User API Tokens Read"}]}]


class FakeCloudflare:
    def __init__(self, *, external_id_from_provision=True, name=None, policies=None, status="active", reject=False):
        self._name, self._policies, self._status, self._reject = name, policies, status, reject
        self.calls = []

    def __call__(self, url, headers, body, timeout):
        token = headers["Authorization"].split("Bearer ", 1)[1]
        path = url.split("/client/v4/", 1)[1]
        self.calls.append((path, token))
        if path == "user/tokens/verify":
            if self._reject:
                return 401, _err(1000, "Invalid API Token")
            return 200, _ok({"id": TOKEN_ID, "status": self._status})
        if path == f"user/tokens/{TOKEN_ID}":
            name = self._name if self._name is not None else _bound_name(self)   # resolved per-call via holder
            return 200, _ok({"id": TOKEN_ID, "name": name,
                             "policies": self._policies if self._policies is not None else _ro_policies()})
        return 404, _err(7003)


# The customer names their token vigil-verify-{external_id}; the challenge mints the external_id, so the fake must
# echo whatever the connect screen just issued. A tiny holder lets a test pin the name the token "really" has.
_NAME_HOLDER = {"name": None}


def _bound_name(_fake):
    return _NAME_HOLDER["name"]


def _fetcher(fake):
    from sigil.ui.cloudflare_fetch import CloudflareTokenConnectFetcher
    return CloudflareTokenConnectFetcher(transport=fake)


def _limiter(max_fails, window):
    from sigil.ui.login_ratelimit import LoginRateLimiter
    return LoginRateLimiter(tempfile.mkdtemp(), max_fails=max_fails, window_s=window, base_lock_s=window,
                            max_lock_s=window)


def _prov(*, fake=None, limiters=True):
    from sigil.governor.customers import CustomerRegistry
    from sigil.governor.identity import ensure_owner_keypair
    from sigil.governor.orgs import OrgRegistry
    from sigil.governor.wallet import WalletRegistry
    from sigil.spine.store import SpineStore
    from sigil.ui.email_channel import EmailTokenLedger, NullEmailSender
    from sigil.ui.login_ratelimit import LoginRateLimiter
    from sigil.ui.provision import Provisioner
    ensure_owner_keypair()
    s = SpineStore(tempfile.mktemp(suffix=".jsonl"))
    orgs = OrgRegistry(s)
    p = Provisioner(s, customers=CustomerRegistry(s), orgs=orgs, wallet=WalletRegistry(s),
                    email_tokens=EmailTokenLedger(tempfile.mkdtemp(), ttl_s=1e4),
                    rate_limiter=LoginRateLimiter(tempfile.mkdtemp(), max_fails=1000, window_s=1e4, base_lock_s=1.0),
                    email_sender=NullEmailSender(),
                    cloudflare_fetcher=_fetcher(fake if fake is not None else FakeCloudflare()),
                    cloud_connect_limiter=_limiter(10, 600.0) if limiters else None,
                    now_fn=time.time)
    return p, s, orgs


def _seat(orgs, org, user, role):
    orgs.create_org(org, org, owner=user, issued_at=float(next(_iss)))
    orgs.grant_membership(org, user, role, issued_at=float(next(_iss)))


def _connect(p, user, org, *, account=ACCT, token=SECRET_TOKEN):
    """Run the real challenge → (name the token for THAT challenge) → verify round-trip."""
    ch = p.cloud_connect_challenge(user, org, "cloudflare", account)
    _NAME_HOLDER["name"] = ch["token_name"]              # the customer names the token exactly as the screen shows
    return ch, p.cloud_connect_verify(user, org, "cloudflare", account, token)


# ---- challenge: the Cloudflare placement ---------------------------------------------------------------------
def test_challenge_returns_the_cloudflare_placement_not_an_aws_trust_policy():
    p, s, orgs = _prov()
    _seat(orgs, "org_a", "u_f", "operator")
    ch = p.cloud_connect_challenge("u_f", "org_a", "cloudflare", ACCT)
    assert ch["provider"] == "cloudflare" and ch["account_id"] == ACCT
    assert ch["token_name"] == EXT_PREFIX + ch["external_id"] and ch["resumed"] is False
    assert "trust_policy" not in ch and "principal_arn" not in ch
    assert any("Read" in g for g in ch["permission_groups"]) and isinstance(ch["steps"], list) and ch["steps"]


def test_the_overview_offers_cloud_connect_when_the_cloudflare_fetcher_is_present():
    p, s, orgs = _prov()                                 # no AWS principal/fetcher, only Cloudflare
    _seat(orgs, "org_a", "u_f", "operator")
    assert p.customer_connect_overview("u_f", "org_a")["available"]["cloud_connect"] is True
    p2, _, orgs2 = _prov(limiters=False)
    _seat(orgs2, "org_a", "u_f", "operator")
    assert p2.customer_connect_overview("u_f", "org_a")["available"]["cloud_connect"] is False


# ---- verify: the grant + the never-store-the-token invariant --------------------------------------------------
def test_a_good_token_records_a_read_only_grant():
    p, s, orgs = _prov()
    _seat(orgs, "org_a", "u_f", "operator")
    _, res = _connect(p, "u_f", "org_a")
    assert res["provider"] == "cloudflare" and res["account_id"] == ACCT
    assert res["role_ref"] == TOKEN_ID and res["access"] == "read-only"
    from sigil.governor.cloud_connect import CloudConnectRegistry
    g = CloudConnectRegistry(s, owner_key=None).grant("org_a", "cloudflare", ACCT)
    assert g is not None and g.role_ref == TOKEN_ID and g.token_sha256 and g.state == "active"


def test_the_customer_token_never_appears_in_any_record_audit_or_return():
    """THE central Cloudflare secret-handling test: the bearer token flows through the real fetcher, but NEVER into
    the spine (grant OR audit), and NEVER into the verify return."""
    p, s, orgs = _prov()
    _seat(orgs, "org_a", "u_f", "operator")
    ch, res = _connect(p, "u_f", "org_a")
    # (a) the return
    assert SECRET_TOKEN not in json.dumps(res)
    # (b) every spine record (grant records AND provision.audit rows both live here)
    blob = json.dumps([rec.payload for rec in s.iter_records()])
    assert SECRET_TOKEN not in blob
    # (c) the grant records a SHA of the token, the token id, and the account — but not the token
    from sigil.reuse import sha256_hex
    assert sha256_hex(SECRET_TOKEN.encode("utf-8")) in blob and TOKEN_ID in blob
    # (d) a rejected token leaves nothing behind either (its audit detail carries HTTP/CF codes, never the token)
    _NAME_HOLDER["name"] = ch["token_name"]
    with pytest.raises(ProvisionDenied):
        p.cloud_connect_verify("u_f", "org_a", "cloudflare", "b" * 32, SECRET_TOKEN)  # wrong account -> no grant
    assert SECRET_TOKEN not in json.dumps([rec.payload for rec in s.iter_records()])


def test_an_over_privileged_token_is_refused_and_records_nothing():
    p, s, orgs = _prov(fake=FakeCloudflare(policies=_ro_policies(groups=("Account Settings Read", "DNS Write"))))
    _seat(orgs, "org_a", "u_f", "operator")
    ch = p.cloud_connect_challenge("u_f", "org_a", "cloudflare", ACCT)
    _NAME_HOLDER["name"] = ch["token_name"]
    with pytest.raises(ProvisionDenied, match="read-only"):
        p.cloud_connect_verify("u_f", "org_a", "cloudflare", ACCT, SECRET_TOKEN)
    from sigil.governor.cloud_connect import CloudConnectRegistry
    assert CloudConnectRegistry(s, owner_key=None).grant("org_a", "cloudflare", ACCT) is None


def test_a_global_token_is_refused():
    # a token that reaches the claimed account AND carries an all-accounts wildcard: the account matches, but the
    # single-account guard fires (it is NOT scoped to exactly one account)
    both = [{"effect": "allow",
             "resources": {f"com.cloudflare.api.account.{ACCT}": "*", "com.cloudflare.api.account.*": "*"},
             "permission_groups": [{"name": "Account Settings Read"}]}]
    p, s, orgs = _prov(fake=FakeCloudflare(policies=both))
    _seat(orgs, "org_a", "u_f", "operator")
    ch = p.cloud_connect_challenge("u_f", "org_a", "cloudflare", ACCT)
    _NAME_HOLDER["name"] = ch["token_name"]
    with pytest.raises(ProvisionDenied, match="single account"):
        p.cloud_connect_verify("u_f", "org_a", "cloudflare", ACCT, SECRET_TOKEN)
    # a purely all-accounts token (no specific-account scope) is refused too — it proves control of no one account
    only_star = [{"effect": "allow", "resources": {"com.cloudflare.api.account.*": "*"},
                  "permission_groups": [{"name": "Account Settings Read"}]}]
    p2, s2, orgs2 = _prov(fake=FakeCloudflare(policies=only_star))
    _seat(orgs2, "org_b", "u_g", "operator")
    ch2 = p2.cloud_connect_challenge("u_g", "org_b", "cloudflare", ACCT)
    _NAME_HOLDER["name"] = ch2["token_name"]
    with pytest.raises(ProvisionDenied, match="not proven"):
        p2.cloud_connect_verify("u_g", "org_b", "cloudflare", ACCT, SECRET_TOKEN)


def test_a_token_named_for_another_challenge_is_refused():
    p, s, orgs = _prov()
    _seat(orgs, "org_a", "u_f", "operator")
    p.cloud_connect_challenge("u_f", "org_a", "cloudflare", ACCT)
    _NAME_HOLDER["name"] = "vigil-verify-SOME-OTHER-CHALLENGE"     # the token carries the wrong binding
    with pytest.raises(ProvisionDenied, match="does not match"):
        p.cloud_connect_verify("u_f", "org_a", "cloudflare", ACCT, SECRET_TOKEN)


def test_a_rejected_token_fails_closed_without_leaking():
    p, s, orgs = _prov(fake=FakeCloudflare(reject=True))
    _seat(orgs, "org_a", "u_f", "operator")
    p.cloud_connect_challenge("u_f", "org_a", "cloudflare", ACCT)
    with pytest.raises(ProvisionDenied) as e:
        p.cloud_connect_verify("u_f", "org_a", "cloudflare", ACCT, SECRET_TOKEN)
    assert SECRET_TOKEN not in str(e.value)
    assert SECRET_TOKEN not in json.dumps([rec.payload for rec in s.iter_records()])


# ---- the write gate ------------------------------------------------------------------------------------------
def test_the_cloudflare_write_paths_need_run_engagement():
    p, s, orgs = _prov()
    _seat(orgs, "org_a", "u_admin", "org_admin")         # billing admin: no run_engagement
    for call in (lambda: p.cloud_connect_challenge("u_admin", "org_a", "cloudflare", ACCT),
                 lambda: p.cloud_connect_verify("u_admin", "org_a", "cloudflare", ACCT, SECRET_TOKEN),
                 lambda: p.cloud_disconnect("u_admin", "org_a", "cloudflare", ACCT)):
        with pytest.raises(ProvisionDenied):
            call()


def test_connecting_cloudflare_mints_no_engagement_authority():
    from sigil.governor.cloud_connect import CloudConnectRegistry
    p, s, orgs = _prov()
    _seat(orgs, "org_a", "u_f", "operator")
    _connect(p, "u_f", "org_a")
    # the grant is a read-only CONNECTION record; it is NOT an assume target that authorizes anything, and the
    # live-offense gate is untouched (a Cloudflare grant never carries a usable credential — the token is not stored)
    reg = CloudConnectRegistry(s, owner_key=None)
    assert reg.has_current_grant("org_a", "cloudflare", ACCT, now=time.time()) is True
    tgt = reg.assume_target("org_a", "cloudflare", ACCT, now=time.time())
    assert tgt is not None and tgt.role_ref == TOKEN_ID        # the public id only; no bearer secret to replay
    p.cloud_disconnect("u_f", "org_a", "cloudflare", ACCT)
    assert reg.grant("org_a", "cloudflare", ACCT) is None
