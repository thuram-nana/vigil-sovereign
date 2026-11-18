"""PR-D issue_sync — open a tracker issue for an oracle-minted FACT finding, auto-close on a proven fix.

Load-bearing invariants proven here:
  * FACT-ONLY (self-red-pen "mint a fact from a notice"): `open_issue` RAISES on anything that is not an
    oracle-minted finding (a notice / LEAD / free-form dict) — a notification can never become a tracker issue.
  * AUTO-CLOSE ON CLEARED: a finding whose newest retest verdict is `fixed` (the oracle-backed signal) closes
    EXACTLY its own issue, keyed on the full finding identity (never a sibling sharing its finding_ref).
  * NO MODEL IDENTIFIER / ALLOWLIST: issue content reuses the notice renderer, so no internal field or model id
    reaches a customer's tracker.
  * FLAG-GATED + TENANT-ISOLATED (registry per org).
"""
from __future__ import annotations

import tempfile

import pytest

from sigil import config
from sigil.governor import issue_sync as isy


@pytest.fixture
def notify_on(monkeypatch):
    monkeypatch.setenv("VIGIL_CUSTOMER_NOTIFY", "1")
    yield


def _finding(ref="F-1", *, slug="cust_acme", digest="d1", cleared=False, **over):
    row = {"engagement_slug": slug, "finding_ref": ref, "oracle_context_digest": digest, "bug_class": "sqli",
           "surface": "https://acme.example/login", "severity": "critical", "title": "SQLi in login",
           "summary": "Auth bypass via union select"}
    if cleared:
        row["retest"] = {"status": "fixed", "ts": 1.0}
    row.update(over)
    return row


class _FakeTracker:
    """An in-memory tracker for the plan/apply tests (no egress). create returns an incrementing key."""

    tracker = isy.TRACKER_GITHUB

    def __init__(self):
        self.created: list = []
        self.closed: list = []
        self._n = 0

    def create(self, *, title, body, labels):
        self._n += 1
        self.created.append((title, body, list(labels)))
        return str(self._n)

    def close(self, issue_key):
        self.closed.append(issue_key)
        return True


# -- FACT-ONLY: a notice can never open an issue (self-red-pen) -----------------------------------------------
def test_open_issue_refuses_a_notice_SELF_RED_PEN(notify_on):
    tracker = _FakeTracker()
    for notice in [{"id": "billing:low", "title": "Low balance", "body": "top up"},   # an in-app notice
                   {"engagement_slug": "cust_acme"},                                    # no finding_ref
                   {"finding_ref": "F-1"},                                              # no engagement_slug
                   "not-a-dict", 42, None]:
        with pytest.raises(isy.NotAFactFinding):
            isy.open_issue(tracker, notice)
    assert tracker.created == []    # nothing was ever opened from a non-FACT


def test_build_content_also_gates_fact_and_strips_model_id(notify_on):
    with pytest.raises(isy.NotAFactFinding):
        isy.build_issue_content({"title": "a notice"})
    content = isy.build_issue_content(_finding(model="claude-opus-4-8"))
    blob = (content.title + content.body + repr(content.labels)).lower()
    assert "claude" not in blob and "opus" not in blob
    assert "severity:critical" in content.labels and "class:sqli" in content.labels


# -- plan: open live, auto-close cleared ---------------------------------------------------------------------
def test_plan_opens_new_live_findings():
    actions = isy.plan_issue_actions([_finding("F-1"), _finding("F-2")], existing={})
    assert [a.op for a in actions] == ["open", "open"]
    assert {a.identity[1] for a in actions} == {"F-1", "F-2"}


def test_plan_auto_closes_cleared_finding():
    f = _finding("F-1")
    ident = isy.finding_identity(f)
    existing = {ident: isy.IssueLink(identity=ident, tracker=isy.TRACKER_GITHUB, issue_key="7", state="open")}
    # not cleared yet -> no action (issue already open)
    assert isy.plan_issue_actions([f], existing=existing) == []
    # now cleared (proven fix) -> CLOSE exactly this issue
    actions = isy.plan_issue_actions([_finding("F-1", cleared=True)], existing=existing)
    assert len(actions) == 1 and actions[0].op == "close" and actions[0].link.issue_key == "7"


def test_plan_does_not_open_an_already_cleared_finding():
    # a finding that is already fixed and never had an issue needs none (nothing to close, nothing to open)
    assert isy.plan_issue_actions([_finding("F-1", cleared=True)], existing={}) == []


def test_plan_closes_only_the_identity_that_was_fixed_not_a_sibling_ref():
    # two findings SHARE a finding_ref but differ by oracle_context_digest -> distinct identities. A fixed verdict on
    # one must close only ITS issue, never the sibling's. MUTATION-VERIFY: keying on finding_ref alone REDS this.
    a = _finding("F-dup", digest="dA")
    b = _finding("F-dup", digest="dB")
    existing = {isy.finding_identity(a): isy.IssueLink(identity=isy.finding_identity(a), tracker="github",
                                                       issue_key="10", state="open"),
                isy.finding_identity(b): isy.IssueLink(identity=isy.finding_identity(b), tracker="github",
                                                       issue_key="11", state="open")}
    actions = isy.plan_issue_actions([_finding("F-dup", digest="dA", cleared=True), b], existing=existing)
    assert len(actions) == 1 and actions[0].op == "close" and actions[0].link.issue_key == "10"


# -- the write path over a fake tracker ----------------------------------------------------------------------
def test_open_then_close_over_fake_tracker(notify_on):
    tracker = _FakeTracker()
    link = isy.open_issue(tracker, _finding("F-1"))
    assert link.state == "open" and link.issue_key == "1" and tracker.created
    closed = isy.close_issue(tracker, link)
    assert closed.state == "closed" and tracker.closed == ["1"]
    # closing an already-closed link is idempotent (no second egress)
    again = isy.close_issue(tracker, closed)
    assert again.state == "closed" and tracker.closed == ["1"]


def test_open_close_refuse_when_flag_off(monkeypatch):
    monkeypatch.delenv("VIGIL_CUSTOMER_NOTIFY", raising=False)
    tracker = _FakeTracker()
    with pytest.raises(Exception):
        isy.open_issue(tracker, _finding("F-1"))
    link = isy.IssueLink(identity=("cust_acme", "F-1", "d1"), tracker="github", issue_key="1", state="open")
    with pytest.raises(Exception):
        isy.close_issue(tracker, link)
    assert tracker.created == [] and tracker.closed == []


# -- the REAL GitHub client over the hardened, allowlisted egress (no network) --------------------------------
def test_github_client_uses_allowlisted_egress(notify_on):
    calls = []

    def fake_transport(method, url, *, headers, body):
        calls.append((method, url))
        return {"number": 42} if method == "POST" else {}

    client = isy.GithubIssueClient("acme/webapp", "ghs_installation_token", transport=fake_transport)
    key = client.create(title="t", body="b", labels=["vigil-finding"])
    assert key == "42"
    assert client.close("42") is True
    # the egress pinned every call to api.github.com (the allowlist) and built the issue routes
    assert calls[0] == ("POST", "https://api.github.com/repos/acme/webapp/issues")
    assert calls[1] == ("PATCH", "https://api.github.com/repos/acme/webapp/issues/42")
    # a malformed repo / bearer is refused at construction
    with pytest.raises(ValueError):
        isy.GithubIssueClient("not-a-repo", "tok")
    with pytest.raises(ValueError):
        isy.GithubIssueClient("acme/webapp", "")


# -- the per-tenant issue-link registry ----------------------------------------------------------------------
def test_registry_tenant_isolation(notify_on):
    reg = isy.IssueLinkRegistry(tempfile.mkdtemp())
    la = isy.IssueLink(identity=("cust_acme", "F-1", "d1"), tracker="github", issue_key="1", state="open")
    lb = isy.IssueLink(identity=("cust_other", "G-1", "d9"), tracker="github", issue_key="9", state="open")
    reg.put("acme", la)
    reg.put("other", lb)
    assert set(reg.links_of("acme").keys()) == {("cust_acme", "F-1", "d1")}
    assert set(reg.links_of("other").keys()) == {("cust_other", "G-1", "d9")}
    assert reg.links_of("mallory") == {}      # a third org reads nothing
    # an upsert of the same identity replaces, not duplicates
    reg.put("acme", isy.IssueLink(identity=("cust_acme", "F-1", "d1"), tracker="github", issue_key="1",
                                  state="closed"))
    assert reg.links_of("acme")[("cust_acme", "F-1", "d1")].state == "closed"
