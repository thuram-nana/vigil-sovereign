"""Consumer PR-C — the Connect surface END TO END over the real edge -> hop -> sovereign provisioner.

The keyless customer edge (custui) and the sovereign cockpit run in-process, joined by the real hop key (the
test_custui ``_stack``). Nothing here reaches the network: the ownership fetcher's ``fetch`` is replaced by a reader
of what the test "published", and the cloud fetcher is the REAL ``AwsStsConnectFetcher`` whose single open point
(``cloud_fetch._do_open``) is a FAKE AWS STS that verifies every SigV4 signature and enforces a real trust policy.

Pinned:
  * with the flag on, GET api/customer/connect answers the SESSION org's connections (a body/route org is never
    trusted), and POST api/customer/connect/ownership resumes, re-checks on the server's cadence and flips the host to
    Verified with no other request; the authorization affirmation travels only as a real JSON true;
  * the cloud routes are absent (404) while only the master flag is on; with the cloud flag on and VIGIL's connector
    identity provisioned, connecting an AWS account works end to end through the real signer and fetcher — a role
    that admits any external id is refused over the wire (the confused deputy), a correct role is recorded READ-ONLY,
    and disconnect removes it.
"""
from __future__ import annotations

import io
import time
import urllib.error

from test_cloud_fetch import EXAMPLE_KEY_ID, EXAMPLE_SECRET, FakeSts
from test_custui import _scrub_shared_owner_state  # noqa: F401  (autouse: keep the shared SIGIL_HOME pristine)
from test_custui import _get, _opener, _post, _stack

ACCT = "123456789012"
ROLE = "arn:aws:iam::123456789012:role/VigilSecurityAudit"
PRINCIPAL = "arn:aws:iam::111122223333:role/vigil-connector"
HOST = "app.acme-e2e.com"


def _isolate(monkeypatch, tmp_path):
    from sigil import config
    for attr in ("CONNECT_CHECK_RATELIMIT_DIR", "CONNECT_ORG_RATELIMIT_DIR", "CLOUD_CONNECT_RATELIMIT_DIR"):
        monkeypatch.setattr(config, attr, tmp_path / attr.lower())
    monkeypatch.setenv("VIGIL_CUSTOMER_CONNECT", "1")


def _founding_operator(sov, op, ep, email):
    """Sign up through the edge, then the owner makes the member an operator (testing role) on the sovereign store."""
    from sigil.governor.orgs import OrgRegistry
    t = _post(op, ep, "/api/customer/signup/request", {"email": email})[1]["dev_token"]
    conf = _post(op, ep, "/api/customer/signup/confirm",
                 {"token": t, "password": "customer-pw-1", "org_name": "Acme"})[1]
    OrgRegistry(sov.store()).grant_membership(conf["org_id"], conf["username"], "operator",
                                              issued_at=time.time() + 1e6)
    return conf["username"], conf["org_id"]


def test_the_website_flow_resumes_rechecks_and_flips_to_verified_over_the_real_hop(tmp_path, monkeypatch):
    from sigil.governor import asset_ownership as ao
    from sigil.ui import ownership_fetch, provision
    _isolate(monkeypatch, tmp_path)
    monkeypatch.setenv("VIGIL_OWNERSHIP_VERIFY", "1")                    # the operator opted into ownership egress
    monkeypatch.setattr(provision.Provisioner, "_RECHECK_INTERVAL_S", 0.5)  # the cadence, scaled down for the test
    published = {"on": False}
    sov, edge, ep, _ = _stack(tmp_path, monkeypatch)
    calls = []

    def fake_fetch(self, method, host, *, now=None):                      # what the customer published, nothing more
        calls.append((method, host))
        if not published["on"]:
            raise ownership_fetch.OwnershipFetchError("homepage returned HTTP 404")
        tok = ao.AssetOwnershipRegistry(sov.store(), owner_key=None).challenge(oid, host).token
        return "<html><head>" + ao.meta_tag(tok) + "</head></html>"
    monkeypatch.setattr(ownership_fetch.WellKnownFetcher, "fetch", fake_fetch)
    try:
        op = _opener()
        _u, oid = _founding_operator(sov, op, ep, "connect@acme.com")
        c, ov = _get(op, ep, "/api/customer/connect")
        assert c == 200 and ov["org_id"] == oid and ov["sites"] == [] and "cloud" not in ov, (c, ov)
        assert ov["available"]["site_check"] is True and ov["available"]["site_auto_recheck"] is True
        assert _post(op, ep, "/api/customer/connect/cloud/challenge", {"provider": "aws"})[0] == 404   # cloud flag off
        assert _post(op, ep, "/api/customer/target/challenge", {"host": HOST})[0] == 200          # the EXISTING route
        c, st = _post(op, ep, "/api/customer/connect/ownership", {"host": HOST, "org_id": "org_EVIL"})
        assert c == 200 and st["org_id"] == oid and st["status"] == "pending"                     # the SESSION org
        assert st["selected_method"] == "meta-tag" and "meta-tag" in st["methods"] and calls == []
        # the affirmation travels only as a real JSON true: a string is NOT an affirmation
        c, r = _post(op, ep, "/api/customer/connect/ownership", {"host": HOST, "recheck": True, "authorized": "true"})
        assert c == 403 and "authorized" in r["error"] and calls == [], (c, r)
        c, r = _post(op, ep, "/api/customer/connect/ownership", {"host": HOST, "recheck": True, "authorized": True})
        assert c == 200 and r["status"] == "pending" and r["checked"]["ok"] is False and len(calls) == 1, (c, r)
        published["on"] = True
        time.sleep(0.6)                                                   # past the (scaled) cadence window
        c, r = _post(op, ep, "/api/customer/connect/ownership", {"host": HOST, "recheck": True, "authorized": True})
        assert c == 200 and r["status"] == "verified" and r["checked"]["ok"] is True, (c, r)
        c, ov = _get(op, ep, "/api/customer/connect")
        assert [(s["host"], s["status"]) for s in ov["sites"]] == [(HOST, "verified")]
    finally:
        sov.shutdown(); edge.shutdown()


def _sts_opener(sts):
    """Adapt the FakeSts to the fetcher's real ``_do_open(req, timeout)`` seam (urllib capitalizes header names)."""
    canon = {"x-amz-date": "X-Amz-Date", "x-amz-security-token": "X-Amz-Security-Token",
             "authorization": "Authorization", "content-type": "Content-Type"}

    class _R(io.BytesIO):
        status = 200

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    def _open(req, timeout):
        headers = {canon.get(k.lower(), k): v for k, v in req.header_items()}
        status, raw = sts(req.full_url, headers, req.data, timeout)
        if status != 200:
            raise urllib.error.HTTPError(req.full_url, status, "error", {}, io.BytesIO(raw))
        return _R(raw)
    return _open


def test_an_aws_account_connects_end_to_end_through_the_real_fetcher(tmp_path, monkeypatch):
    from sigil.governor.cloud_connect import CloudConnectRegistry
    from sigil.ui import cloud_fetch
    _isolate(monkeypatch, tmp_path)
    monkeypatch.setenv("VIGIL_CUSTOMER_CLOUD_CONNECT", "1")
    monkeypatch.setenv("VIGIL_CLOUD_CONNECT_AWS_PRINCIPAL_ARN", PRINCIPAL)
    monkeypatch.setenv("VIGIL_CLOUD_CONNECT_AWS_ACCESS_KEY_ID", EXAMPLE_KEY_ID)
    monkeypatch.setenv("VIGIL_CLOUD_CONNECT_AWS_SECRET_ACCESS_KEY", EXAMPLE_SECRET)
    sts = FakeSts(accepts=None)                         # first: a role that trusts VIGIL with NO external-id condition
    monkeypatch.setattr(cloud_fetch, "_do_open", _sts_opener(sts))
    sov, edge, ep, _ = _stack(tmp_path, monkeypatch)
    try:
        op = _opener()
        _u, oid = _founding_operator(sov, op, ep, "cloud@acme.com")
        c, ov = _get(op, ep, "/api/customer/connect")
        assert c == 200 and ov["cloud"] == [] and ov["available"]["cloud_connect"] is True, (c, ov)
        c, ch = _post(op, ep, "/api/customer/connect/cloud/challenge",
                      {"provider": "aws", "account_id": ACCT, "org_id": "org_EVIL"})
        assert c == 200 and ch["principal_arn"] == PRINCIPAL and ch["external_id"] in ch["trust_policy"], (c, ch)
        assert CloudConnectRegistry(sov.store(), owner_key=None).challenge(oid, "aws", ACCT) is not None
        assert CloudConnectRegistry(sov.store(), owner_key=None).challenge("org_EVIL", "aws", ACCT) is None
        # the confused deputy, over the wire: the role admitted the random control id too -> refused, nothing recorded
        c, r = _post(op, ep, "/api/customer/connect/cloud/verify",
                     {"provider": "aws", "account_id": ACCT, "role_ref": ROLE})
        assert c == 403 and "sts:ExternalId" in r["error"], (c, r)
        assert CloudConnectRegistry(sov.store(), owner_key=None).grant(oid, "aws", ACCT) is None
        # the customer adds the condition: only OUR external id is accepted -> connected, read-only
        sts.accepts = (ch["external_id"],)
        c, r = _post(op, ep, "/api/customer/connect/cloud/verify",
                     {"provider": "aws", "account_id": ACCT, "role_ref": ROLE})
        assert c == 200 and r["access"] == "read-only" and r["account_id"] == ACCT, (c, r)
        assert [k[0] for k in sts.calls[-3:]] == ["AssumeRole", "GetCallerIdentity", "AssumeRole"]
        c, ov = _get(op, ep, "/api/customer/connect")
        assert [(a["account_id"], a["status"]) for a in ov["cloud"]] == [(ACCT, "connected")]
        assert ch["external_id"] not in str(ov)                          # the id is never projected back
        c, r = _post(op, ep, "/api/customer/connect/cloud/disconnect", {"provider": "aws", "account_id": ACCT})
        assert c == 200 and r["disconnected"] is True
        assert _get(op, ep, "/api/customer/connect")[1]["cloud"] == []
    finally:
        sov.shutdown(); edge.shutdown()
