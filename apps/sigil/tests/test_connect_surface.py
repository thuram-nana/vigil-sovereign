"""Consumer PR-C — the unified connect read projection (``sigil.ui.connect``): the one-screen overview + the
single-host ownership POLL.

These exercise the REAL persisted-owner-identity path end-to-end (a tmp SIGIL_HOME + ``ensure_owner_keypair``),
so the read registries (constructed ``owner_key=None``) authenticate under exactly the owner key the writes
signed with — the production wiring, not an injected shortcut.

Invariants pinned here:
  * the POLL resumes a half-finished proof, auto-selects a method, and signals auto-re-check per status
    (none / pending / verified / expired / invalid);
  * the OVERVIEW composes sites + repos + cloud, each tenant-scoped (the SELF-RED-PEN "cross-tenant asset read":
    org B's overview and poll never surface org A's assets);
  * a FACT is minted nowhere here (these are pure reads); no model/engine name ever appears.
"""
from __future__ import annotations

import itertools
import json
import re
import tempfile

import pytest

from sigil.governor import asset_ownership as ao
from sigil.governor.asset_ownership import AssetOwnershipRegistry
from sigil.governor.cloud_connect import CloudConnectRegistry
from sigil.governor.connected_repos import ConnectedRepoRegistry
from sigil.governor.identity import ensure_owner_keypair
from sigil.spine.store import SpineStore
from sigil.ui import connect
from vigil_core import BlockThreshold

_iss = itertools.count(1)
ACCT = "123456789012"


def _issue() -> float:
    return float(next(_iss))


@pytest.fixture(autouse=True)
def _home(monkeypatch):
    monkeypatch.setenv("SIGIL_HOME", tempfile.mkdtemp())
    ensure_owner_keypair()           # the persisted owner identity the read registries authenticate under


def _store():
    return SpineStore(tempfile.mktemp(suffix=".jsonl"))


def _prove_host(store, org: str, host: str, *, now: float, method: str = ao.METHOD_META_TAG) -> None:
    """Issue a challenge for (org, host) and record a proof over the matching trusted observation."""
    reg = AssetOwnershipRegistry(store)
    ch = reg.issue_challenge(org, host, issued_at=_issue())
    if method == ao.METHOD_META_TAG:
        observed: object = ao.meta_tag(ch.token)
    elif method == ao.METHOD_DNS_TXT:
        observed = ["unrelated=x", ao.expected_marker(ch.token)]
    else:
        observed = ao.expected_marker(ch.token)
    reg.verify_and_record(org, host, method=method, observed=observed, now=now)


def _challenge_host(store, org: str, host: str) -> None:
    """Issue a challenge but do NOT prove it — a half-finished proof the poll must resume."""
    AssetOwnershipRegistry(store).issue_challenge(org, host, issued_at=_issue())


def _grant_cloud(store, org: str, account: str, *, now: float, ttl: float = 1000.0) -> None:
    reg = CloudConnectRegistry(store)
    reg.issue_challenge(org, "aws", account, issued_at=_issue(), external_id="EXT-" + account)
    reg.verify_and_connect(org, "aws", account, role_ref=f"arn:aws:iam::{account}:role/VigilSecurityAudit",
                           observed={"assumed_with_external_id": "EXT-" + account, "account": account,
                                     "control_external_id": "CTL", "control_denied": True},
                           control_external_id="CTL", now=now, ttl_seconds=ttl)


# ---- the single-host ownership POLL -------------------------------------------------------------------------
def test_poll_none_when_nothing_started_auto_selects_by_host_shape():
    s = _store()
    out = connect.customer_ownership_poll(s, "acme", "apme.cm", now=100.0)
    assert out["status"] == "none"
    assert out["selected_method"] == ao.METHOD_DNS_TXT          # a bare domain: its zone (its root often redirects)
    assert out["recheck"]["due"] is False
    assert "methods" not in out                                  # nothing to resume yet
    sub = connect.customer_ownership_poll(s, "acme", "app.apme.cm", now=100.0)
    assert sub["status"] == "none" and sub["selected_method"] == ao.METHOD_META_TAG   # a subdomain: its own page


def test_auto_method_is_a_pure_host_shape_pick():
    assert connect.auto_method("example.com") == ao.METHOD_DNS_TXT
    assert connect.auto_method("www.example.com") == ao.METHOD_META_TAG
    assert connect.auto_method("a.b.example.co.uk") == ao.METHOD_META_TAG
    assert connect.auto_method("") == ao.METHOD_META_TAG                  # never raises, never an unknown method


def test_poll_pending_resumes_the_half_finished_proof_and_flags_recheck():
    s = _store()
    _challenge_host(s, "acme", "apme.cm")
    out = connect.customer_ownership_poll(s, "acme", "apme.cm", now=100.0)
    assert out["status"] == "pending"
    assert out["recheck"]["due"] is True                        # auto-re-check: awaiting the token
    # RESUME: every method's placement is surfaced so the customer continues where they left off
    assert set(out["methods"]) == {ao.METHOD_META_TAG, ao.METHOD_DNS_TXT, ao.METHOD_WELL_KNOWN}
    assert out["marker"].startswith("vigil-site-verification=")
    assert out["methods"][ao.METHOD_DNS_TXT]["dns_name"] == "_vigil-challenge.apme.cm"
    assert out["selected_method"] == ao.METHOD_DNS_TXT


def test_poll_verified_has_no_recheck_and_names_the_proving_method():
    s = _store()
    _prove_host(s, "acme", "apme.cm", now=100.0, method=ao.METHOD_DNS_TXT)
    out = connect.customer_ownership_poll(s, "acme", "apme.cm", now=200.0)
    assert out["status"] == "verified"
    assert out["method"] == ao.METHOD_DNS_TXT
    assert out["selected_method"] == ao.METHOD_DNS_TXT          # auto-select stays on the proving method
    assert out["recheck"]["due"] is False
    assert out["expires_at"] > out["verified_at"] == 100.0


def test_poll_expired_flags_recheck():
    s = _store()
    # prove with a short ttl by recording then advancing past expiry; use the registry directly for ttl control
    reg = AssetOwnershipRegistry(s)
    ch = reg.issue_challenge("acme", "apme.cm", issued_at=_issue())
    reg.verify_and_record("acme", "apme.cm", method=ao.METHOD_META_TAG, observed=ao.meta_tag(ch.token),
                          now=100.0, ttl_seconds=50.0)
    out = connect.customer_ownership_poll(s, "acme", "apme.cm", now=1000.0)
    assert out["status"] == "expired"
    assert out["recheck"]["due"] is True
    assert out["selected_method"] == ao.METHOD_META_TAG


def test_poll_invalid_host_is_fail_closed_never_raises():
    s = _store()
    for bad in ("https://apme.cm", "apme.cm/path", "10.0.0.1", "not a host"):
        out = connect.customer_ownership_poll(s, "acme", bad, now=100.0)
        assert out["status"] == "invalid" and out["recheck"]["due"] is False


def test_poll_is_tenant_scoped_org_b_never_sees_org_a_proof():
    # the SELF-RED-PEN "cross-tenant asset read": acme proves apme.cm; evil polling the same host sees nothing
    s = _store()
    _prove_host(s, "acme", "apme.cm", now=100.0)
    out = connect.customer_ownership_poll(s, "evil", "apme.cm", now=200.0)
    assert out["status"] == "none"                              # structurally unreachable (one-way per-org fold)


# ---- the one-screen OVERVIEW --------------------------------------------------------------------------------
def test_overview_composes_sites_repos_and_cloud_for_the_org():
    s = _store()
    _prove_host(s, "acme", "apme.cm", now=100.0)
    _challenge_host(s, "acme", "pending.example.com")
    ConnectedRepoRegistry(s).connect("acme", 42, "github.com/acme/widgets",
                                     block_threshold=BlockThreshold.MEDIUM_UP, monthly_limit_credits=250,
                                     issued_at=_issue())
    _grant_cloud(s, "acme", ACCT, now=100.0)
    out = connect.connect_overview(s, "acme", now=200.0)
    assert out["org_id"] == "acme"
    site_hosts = {r["host"]: r["status"] for r in out["sites"]}
    assert site_hosts == {"apme.cm": "verified", "pending.example.com": "pending"}
    assert out["repos"] == [{"repo": "github.com/acme/widgets",
                             "slug": out["repos"][0]["slug"],          # one-way hash, asserted present below
                             "block_threshold": "medium_up", "monthly_limit_credits": 250}]
    assert out["repos"][0]["slug"].startswith("cust_")
    assert [(c["provider"], c["account_id"], c["status"]) for c in out["cloud"]] == [("aws", ACCT, "connected")]


def test_overview_is_tenant_scoped_org_b_sees_none_of_org_a():
    # the SELF-RED-PEN "cross-tenant asset read" across all three legs
    s = _store()
    _prove_host(s, "acme", "apme.cm", now=100.0)
    ConnectedRepoRegistry(s).connect("acme", 42, "github.com/acme/widgets", issued_at=_issue())
    _grant_cloud(s, "acme", ACCT, now=100.0)
    out = connect.connect_overview(s, "evil", now=200.0)
    assert out == {"org_id": "evil", "sites": [], "repos": [], "cloud": []}


def test_overview_legs_are_absent_not_empty_when_not_included():
    # the repo leg follows the Code screen's own gate and the cloud leg its flag: when the caller excludes one it is
    # ABSENT (no key), never an empty placeholder a screen could mistake for "nothing connected"
    s = _store()
    ConnectedRepoRegistry(s).connect("acme", 42, "github.com/acme/widgets", issued_at=_issue())
    _grant_cloud(s, "acme", ACCT, now=100.0)
    out = connect.connect_overview(s, "acme", now=200.0, include_repos=False, include_cloud=False)
    assert set(out) == {"org_id", "sites"}


def test_overview_cloud_leg_marks_expired_and_hides_the_secret():
    import json
    s = _store()
    _grant_cloud(s, "acme", ACCT, now=100.0, ttl=50.0)
    out = connect.connect_overview(s, "acme", now=5000.0)
    assert out["cloud"][0]["status"] == "expired"
    assert "EXT-" not in json.dumps(out)                        # no external-id secret in any leg


# Engine/model/currency NAMES count as a customer-facing leak only when they appear as WHOLE WORDS:
# the same letters buried inside a high-entropy identifier (a random site-verification nonce, an
# opaque cust_<hash> slug) are not a mention, and scanning for them as raw substrings makes this
# check flaky (a random token can contain "gpt"/"usd" by chance). The "$" cost sigil is matched
# literally — it never occurs inside an alphanumeric identifier.
_BANNED_NAMES = ("claude", "gpt", "opus", "sonnet", "anthropic", "openai", "usd", "estimate")
_BANNED_NAME_RE = re.compile(r"\b(?:" + "|".join(re.escape(t) for t in _BANNED_NAMES) + r")\b")


def _banned_mentions(overview: dict) -> list[str]:
    """Banned engine/model/cost tokens that leak as customer-facing text in ``overview`` — names as
    whole words, ``$`` literal. Sorted and de-duplicated; an empty list means clean."""
    blob = json.dumps(overview).lower()
    hits = set(_BANNED_NAME_RE.findall(blob))
    if "$" in blob:
        hits.add("$")
    return sorted(hits)


def test_overview_contains_no_engine_or_model_name_or_cost():
    s = _store()
    _prove_host(s, "acme", "apme.cm", now=100.0)
    ConnectedRepoRegistry(s).connect("acme", 42, "github.com/acme/widgets", monthly_limit_credits=250, issued_at=_issue())
    _grant_cloud(s, "acme", ACCT, now=100.0)
    assert _banned_mentions(connect.connect_overview(s, "acme", now=200.0)) == []


def test_banned_mention_scan_catches_real_leaks_but_not_nonce_substrings():
    # Real engine / model / currency mentions ARE leaks (whole word, or split by a separator):
    assert _banned_mentions({"model": "gpt-4o", "plan": "Opus tier"}) == ["gpt", "opus"]
    assert _banned_mentions({"price": "12 USD"}) == ["usd"]
    assert _banned_mentions({"cost": "$0.03 estimate"}) == ["$", "estimate"]
    # ...but the SAME letters buried inside a random nonce / opaque slug are NOT (the flake this guards):
    nonce = "vigil-site-verification=gki7gvbrvovl5tdpklbpugptihuf1lbidohzlr85taq"  # contains 'gpt'
    assert _banned_mentions({"sites": [{"marker": nonce}], "repos": [{"slug": "cust_ab0pusddeadbeef"}]}) == []
