"""
Phase C2 · Cloudflare — the CloudflareLiveSensor CUSTOMER-credential seam (the identity-substitution guard).

The Cloudflare twin of the AWS/GCP/Azure injected-credential seams. When a scoped per-run read-only Cloudflare
session is INJECTED (duck-typed here so the engine imports no governor object / ``MintedSession`` — the FATAL-2
boundary), the collector reaches the customer's Cloudflare account under THAT token and under no other identity;
a run that REQUIRES an injected session fails CLOSED rather than proceed (Cloudflare has NO ambient identity to
fall back to); and a PARTIAL / non-Cloudflare session is REJECTED before any Cloudflare HTTP call — so the
fail-closed cases run in CI with no Cloudflare dependency at all (the reject precedes every request).

There is no vendor Cloudflare SDK to fake: the collector's only client is stdlib ``urllib`` behind an injectable
``transport`` seam. The seam is a RECORDING fake Cloudflare API — it captures the ``Authorization`` header of
EVERY call, so the injected-token spy (the token reaches every request, and no other identity is ever used) AND
the oracle-promotion path both run offline, with no network.
"""

from __future__ import annotations

import json
from types import SimpleNamespace

from framework.v2.sensors.cloud import confirm_cloud_posture_facts
from framework.v2.sensors.cloudflare_live import CloudflareLiveSensor

ACCT = "0123456789abcdef0123456789abcdef"              # a 32-lowercase-hex Cloudflare account id
TOKEN = "cf-injected-scoped-read-only-token_ABC123"    # the per-run injected read-only API token (synthetic)
OTHER_TOKEN = "cf-OTHER-IDENTITY-must-not-be-used"     # a DISTINCT dummy, asserted never used


class _Creds:
    """A duck-typed per-run read-only Cloudflare session: ``provider`` / ``account_id`` (the 32-hex Cloudflare
    account) / ``bearer_token`` (the fresh per-run API token — the same bearer slot a GCP/Azure session carries;
    there is deliberately no MintedSession for Cloudflare, see the collector module docstring). Fields are
    overridable so a test can forge a PARTIAL (no token / no account) or non-Cloudflare session."""

    def __init__(self, *, provider: str = "cloudflare", account_id: str = ACCT, bearer_token: str = TOKEN) -> None:
        self.provider = provider
        self.account_id = account_id
        self.bearer_token = bearer_token
        # aws/gcp/azure slots a cross-provider MintedSession might carry — EMPTY on a Cloudflare session.
        self.access_key_id = ""
        self.secret_access_key = ""
        self.session_token = ""
        self.region = ""


def _fake_cloudflare(*, buckets):
    """A RECORDING fake Cloudflare API transport ``(url, headers, timeout) -> (status, body)``. It records the
    Authorization header of EVERY call (the injected-token spy) and serves recorded R2 read-only JSON for the
    seeded ``buckets`` (a map ``name -> {"managed": bool, "customs": [(domain, enabled), ...]}``)."""
    rec = {"auth": [], "urls": []}

    def transport(url, headers, timeout):
        rec["auth"].append(headers.get("Authorization"))
        rec["urls"].append(url)

        def body(doc):
            return 200, json.dumps(doc).encode("utf-8")

        if url.endswith(f"/accounts/{ACCT}/r2/buckets"):
            return body({"success": True, "result": {"buckets": [{"name": n} for n in buckets]}})
        for name, spec in buckets.items():
            if url.endswith(f"/r2/buckets/{name}/domains/managed"):
                return body({"success": True, "result": {"enabled": bool(spec.get("managed"))}})
            if url.endswith(f"/r2/buckets/{name}/domains/custom"):
                domains = [{"domain": d, "enabled": en} for d, en in spec.get("customs", [])]
                return body({"success": True, "result": {"domains": domains}})
        return body({"success": False, "errors": [{"code": 7003}]})

    return transport, rec


# -- (a) the injected token reaches EVERY Cloudflare call; no other identity is ever used ---------------------


def test_injected_token_reaches_every_call_and_no_other_identity():
    transport, rec = _fake_cloudflare(buckets={
        "open": {"managed": True}, "cdn": {"managed": False, "customs": [("cdn.acme.com", True)]}})
    r = CloudflareLiveSensor(credentials=_Creds(), require_injected_credentials=True, transport=transport).run(
        {}, SimpleNamespace())
    assert r.ok is True, r.note
    # the list call + each bucket's managed + custom read all happened (1 + 2*2 = 5 calls)...
    assert len(rec["urls"]) == 5
    # ...and EVERY one carried EXACTLY the injected token's Bearer header — no ambient / other identity, ever.
    assert set(rec["auth"]) == {f"Bearer {TOKEN}"}
    assert OTHER_TOKEN not in " ".join(a or "" for a in rec["auth"])
    # the run is scoped to exactly the injected account/provider.
    assert (r.output or {}).get("account") == ACCT and (r.output or {}).get("provider") == "cloudflare"


def test_seeded_public_bucket_promotes_and_deferred_one_does_not():
    transport, _ = _fake_cloudflare(buckets={
        "open": {"managed": True},                                       # managed r2.dev enabled -> FACT
        "cdn": {"managed": False, "customs": [("cdn.acme.com", True)]}})  # custom-only -> SIGNAL, not a FACT
    r = CloudflareLiveSensor(credentials=_Creds(), require_injected_credentials=True, transport=transport).run(
        {}, SimpleNamespace())
    inv = json.loads((r.output or {})["export"])
    # the EXISTING deterministic oracle promotes exactly the confirmed-public bucket to a public_exposure FACT.
    reached = {f["resource"] for f in confirm_cloud_posture_facts(inv) if f["lead_class"] == "public_exposure"}
    assert reached == {f"{ACCT}/open"}
    # the deferred bucket is present as an auditable SIGNAL (custom domain retained), never promoted.
    cdn = [x for x in inv["resources"] if x["id"] == f"{ACCT}/cdn"][0]
    assert "public" not in cdn and cdn["r2_custom_domains"] == ["cdn.acme.com"]


def test_injected_token_never_leaks_into_the_result():
    transport, _ = _fake_cloudflare(buckets={"open": {"managed": True}})
    creds = _Creds()
    r = CloudflareLiveSensor(credentials=creds, require_injected_credentials=True, transport=transport).run(
        {}, SimpleNamespace())
    blob = f"{r.summary}\n{getattr(r, 'note', '')}\n{r.output}"
    assert creds.bearer_token not in blob


# -- (b) a PARTIAL injected session fails closed BEFORE any Cloudflare call (no transport call) ---------------


def test_partial_injected_session_fails_closed_before_any_call():
    # a missing token OR a missing account is incomplete -> fail closed, no identity substitution, typed
    # INCONCLUSIVE; the transport (fake API) is NEVER reached.
    for bad in (_Creds(bearer_token=""), _Creds(account_id="")):
        transport, rec = _fake_cloudflare(buckets={"open": {"managed": True}})
        r = CloudflareLiveSensor(credentials=bad, require_injected_credentials=True, transport=transport).run(
            {}, SimpleNamespace())
        assert r.ok is False and "no identity substitution" in r.note.lower()
        assert (r.output or {}).get("missing_prerequisite") and (r.output or {}).get("assessed") is False
        assert rec["urls"] == []                               # refused before any HTTP (no ambient fall-through)


def test_malformed_account_id_fails_closed_before_any_call():
    # a non-32-hex account id would be path-injected into the R2 URL -> refuse before building any request.
    transport, rec = _fake_cloudflare(buckets={"open": {"managed": True}})
    r = CloudflareLiveSensor(credentials=_Creds(account_id="not-hex"), require_injected_credentials=True,
                             transport=transport).run({}, SimpleNamespace())
    assert r.ok is False and rec["urls"] == []
    assert (r.output or {}).get("assessed") is False


# -- (c) a non-Cloudflare injected session fails closed (no transport call) -----------------------------------


def test_non_cloudflare_injected_session_fails_closed():
    # a Cloudflare collector handed an AWS/GCP/Azure session must refuse — never treat it as Cloudflare creds.
    for other in ("aws", "gcp", "azure"):
        transport, rec = _fake_cloudflare(buckets={"open": {"managed": True}})
        r = CloudflareLiveSensor(credentials=_Creds(provider=other), require_injected_credentials=True,
                                 transport=transport).run({}, SimpleNamespace())
        assert r.ok is False and "no identity substitution" in r.note.lower()
        assert rec["urls"] == []


# -- (d) require_injected + no session -> fail closed, no call attempted (Cloudflare has no ambient identity) --


def test_required_injection_absent_fails_closed_no_call():
    transport, rec = _fake_cloudflare(buckets={"open": {"managed": True}})
    r = CloudflareLiveSensor(require_injected_credentials=True, transport=transport).run({}, SimpleNamespace())
    assert r.ok is False and "no identity substitution" in r.note.lower()
    assert rec["urls"] == []


# -- (e) a collection FAILURE is a typed INCONCLUSIVE, never a clean empty negative ---------------------------


def test_token_rejected_is_inconclusive_not_a_clean_empty():
    def rejecting(url, headers, timeout):
        return 403, json.dumps({"success": False, "errors": [{"code": 9109}]}).encode("utf-8")

    r = CloudflareLiveSensor(credentials=_Creds(), require_injected_credentials=True, transport=rejecting).run(
        {}, SimpleNamespace())
    assert r.ok is False
    assert (r.output or {}).get("status") == "inconclusive" and (r.output or {}).get("assessed") is False
    # the rejection reason rides in the note, but the token never does.
    assert TOKEN not in f"{r.note}\n{r.output}"


def test_successful_empty_account_is_assessed_not_inconclusive():
    # a genuine, authorised, EMPTY listing is an assessed ok=True result (zero resources) — not INCONCLUSIVE.
    transport, _ = _fake_cloudflare(buckets={})
    r = CloudflareLiveSensor(credentials=_Creds(), require_injected_credentials=True, transport=transport).run(
        {}, SimpleNamespace())
    assert r.ok is True
    assert json.loads((r.output or {})["export"])["resources"] == []
