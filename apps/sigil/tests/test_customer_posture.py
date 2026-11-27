"""APEX consumer PR-B — the customer Fix-first screen: the posture, its trend and what to fix first.

Load-bearing invariants (a false-green leaks one tenant's findings to another, leaks a locked trial's fix, shows an
org nobody tested as a perfect 100, or draws a better trend than the record supports):

* FLAG. ``VIGIL_CUSTOMER_POSTURE`` is default OFF and effective ONLY with its master switch ``VIGIL_APEX_PRESENTATION``.
  Off: both edge routes and both cockpit actions are absent (404 exactly as an unknown route / action), the page writes
  ``data-posture="0"`` (page and build byte-identical to a build without the switch), there is no Fix first tab,
  ``#/fix-first`` is the home screen, the guide never offers "Go to Fix first", and the Overview has no Posture card and
  makes no posture read.
* TENANT ISOLATION. The score, the list and the trend read ONLY the org's own server-derived slugs: another tenant's
  finding, its signed presentation and its retest verdicts can neither be shown nor move this org's score.
* PR-A, NOT RE-DERIVED. Each entry is PR-A's ``_triage_row`` (plus host / status / identity) in PR-A's order, and the
  score is PR-A's ``posture_score`` over the OPEN findings — with no verdict it IS PR-A's own posture read.
* FIXED. Only a provisioner-written verdict for this org's own finding identity counts, only while the retest UI is
  on; the newest wins; and a verdict never covers a finding proven after it.
* TRIAL PREVIEW. A locked trial's Fix-first read carries the revealed finding in full and every other entry cut to an
  allowlist (no signed remediation / plain impact / identity / proof) — end to end over the real hop.
* TREND. The same arithmetic at every point; before the first measurement a point has NO score (never 100); a record
  whose time cannot be read is placed where it can only make the trend look worse; the last point is the headline.
* UI. Renders only what the server sent; fixed words for 401 / 403 / failure (never the server's own); nothing mounts
  after the customer left; signed parts only when sent; no Retest for a locked trial; no estimate, price or engine name.

app.js's own functions are extracted verbatim and run under node on the customer UI kit (ui.js) with a minimal DOM; the
edge and the cockpit are exercised directly and over the real hop (the test_custui stack).

Mutation-verify targets (each neuter reds a NAMED test here):
  * customer_posture_enabled drops its master switch     -> test_the_flag_is_off_by_default_and_needs_its_master_switch
  * the edge routes not gated                             -> test_the_edge_routes_are_absent_with_the_flag_off
  * the cockpit dispatch not gated                        -> test_the_cockpit_actions_exist_only_with_the_flag
  * the slug scope dropped from the scan                  -> test_tenant_isolation_no_cross_tenant_finding_or_verdict
  * the provisioner-source check on verdicts dropped      -> test_only_this_orgs_provisioner_verdicts_count
  * a verdict covers a finding proven after it            -> test_a_fix_never_outlives_a_newer_proof
  * a re-proven finding also listed as fixed              -> test_a_fix_never_outlives_a_newer_proof
  * verdicts counted with the retest UI off               -> test_retest_verdicts_count_only_while_the_retest_ui_is_on
  * an org nobody tested scored 100                       -> test_an_org_with_nothing_tested_is_not_measured_never_100
  * an unreadable fix placed late, or a finding early     -> test_an_unreadable_time_can_only_make_the_trend_look_worse
  * the trial lock not applied / its allowlist dropped    -> test_the_trial_preview_holds_on_the_fix_first_read,
                                                             test_no_locked_detail_leaves_the_posture_reads
  * the tab, the route or the guide link not gated        -> test_with_the_flag_off_the_app_is_unchanged
  * the Overview card not gated                           -> test_the_overview_posture_card_only_with_the_flag
  * a plain-language part shown without its on-file mark  -> test_signed_parts_appear_only_when_sent
  * the server's own words shown on a failure             -> test_the_screen_loads_honestly
  * Retest offered to a locked trial                      -> test_a_locked_trial_sees_the_unlock_note_and_no_retest
"""
from __future__ import annotations

import itertools
import json
import re
import secrets
import subprocess
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path

import pytest
from test_custui import _scrub_shared_owner_state  # noqa: F401  (autouse: keep the shared SIGIL_HOME pristine)
from test_custui import _get, _opener, _post, _stack
from test_customer_monitoring_screen import _DOM, _fn, _var
from test_customer_onboarding import _guide, _need_node, _page_and_build

from sigil.governor.asset_ownership import METHOD_DNS_TXT, AssetOwnershipRegistry
from sigil.governor.customers import CustomerRegistry
from sigil.governor.identity import ensure_owner_keypair
from sigil.governor.orgs import OrgRegistry
from sigil.governor.wallet import WalletRegistry
from sigil.spine.store import SpineStore
from sigil.ui import customer_posture as cp
from sigil.ui import finding_presentation as fpres
from sigil.ui.email_channel import EmailTokenLedger, NullEmailSender
from sigil.ui.login_ratelimit import LoginRateLimiter
from sigil.ui.provision import ProvisionDenied, Provisioner
from sigil.ui.target_authorization import _customer_slug

APP = Path(__file__).resolve().parents[1] / "sigil" / "ui" / "customer_app"
UI_JS, APP_JS, GUIDE_JS = APP / "ui.js", APP / "app.js", APP / "guide.js"
FLAG, MASTER, RETEST = "VIGIL_CUSTOMER_POSTURE", "VIGIL_APEX_PRESENTATION", "VIGIL_CUSTOMER_RETEST_UI"

NOW = 1_800_000_000.0
WEEK = 7 * 24 * 3600
_ISSUED = itertools.count(1)


@pytest.fixture
def flags_on(monkeypatch):
    monkeypatch.setenv(FLAG, "1")
    monkeypatch.setenv(MASTER, "1")


def _iso(t: float) -> str:
    return datetime.fromtimestamp(t, timezone.utc).isoformat()


def _store() -> SpineStore:
    ensure_owner_keypair()
    s = SpineStore(tempfile.mktemp(suffix=".jsonl"))
    s.append(kind="message", source="x", actor="user", payload={"text": "hi"})
    return s


def _prove(store, org: str, host: str) -> str:
    reg = AssetOwnershipRegistry(store)
    ch = reg.issue_challenge(org, host, issued_at=float(next(_ISSUED)))
    reg.verify_and_record(org, host, method=METHOD_DNS_TXT, observed=[ch.marker], now=10.0, ttl_seconds=1e12)
    return _customer_slug(org, host)


def _presentation(tag: str, *, on_file: bool = True) -> dict:
    """A signed presentation block in the shape ``evidence.certify._build_presentation`` mints."""
    return {"schema": 1,
            "plain_impact": {"what": f"WHAT-{tag}", "category_consequence": f"CAN-LEAD-TO-{tag}",
                             "established": f"that PROVED-{tag}", "description_on_file": on_file},
            "remediation": f"For `id` on `GET /x`: FIX-{tag}",
            "priority": {"effort": "L"},
            "standards": {"controls": {"owasp": "A03:2021", "cwe": ["CWE-89"], "pci_dss": ["6.2.4"]}}}


def _finding(store, slug: str, ref: str, *, bug_class: str = "xss", severity: "str | None" = "high",
             at: "float | str | None" = None, digest: "str | None" = None, presentation: "dict | None" = None,
             title: "str | None" = None) -> int:
    cert = {"engagement_slug": slug, "finding_ref": ref, "bug_class": bug_class, "surface": f"https://h.example/{ref}",
            "confidence": "high", "summary": f"SUMMARY-{ref}", "how_to_verify": f"VERIFY-{ref}",
            "oracle_context_digest": digest if digest is not None else f"dig-{ref}",
            "report_claims": [{"sentence": f"CLAIM-{ref}"}], "artifact_manifest": {"a": f"MANIFEST-{ref}"}}
    if severity is not None:
        cert["severity"] = severity
    if title is not None:
        cert["title"] = title
    if presentation is not None:
        cert["presentation"] = presentation
    ts = at if isinstance(at, str) else (_iso(at) if at is not None else None)
    return store.append(kind="finding", source="offense", actor="ORACLE", ts=ts,
                        payload={"certificate": cert, "finding_ref": ref,
                                 "signatures": [{"key_id": "gov", "signature_b64": "x"}]})


def _verdict(store, slug: str, ref: str, status: str, *, at: "float | str | None" = None,
             digest: "str | None" = None, source: str = "provision") -> int:
    ts = at if isinstance(at, str) else (_iso(at) if at is not None else None)
    return store.append(kind="finding_retest", source=source, actor="WARDEN", ts=ts,
                        payload={"engagement_slug": slug, "finding_ref": ref,
                                 "oracle_context_digest": digest if digest is not None else f"dig-{ref}",
                                 "status": status, "nonce": secrets.token_urlsafe(8), "ts": 0.0})


def _completed(store, slug: str, *, at: "float | None" = None) -> int:
    return store.append(kind="assessment_outcome", source="sigil", actor="settle-drain",
                        ts=_iso(at) if at is not None else None,
                        payload={"engagement_slug": slug, "org_id": "x", "outcome": "completed",
                                 "nonce": secrets.token_urlsafe(8), "ts": 0.0})


def _posture(store, org: str = "acme", *, verdicts: bool = True, **kw) -> dict:
    return cp.customer_posture(store, org, now=NOW, retest_verdicts=verdicts, **kw)


def _refs(entries) -> list:
    return [e["finding_ref"] for e in entries]


def ps(*rows) -> int:
    """PR-A's posture score over these (bug_class, severity) findings — the arithmetic every number here must equal."""
    return fpres.posture_score([{"bug_class": b, "severity": s} for b, s in rows])


# ==== the flag ===========================================================================================================
def test_the_flag_is_off_by_default_and_needs_its_master_switch(monkeypatch):
    from sigil import config
    monkeypatch.delenv(FLAG, raising=False)
    monkeypatch.delenv(MASTER, raising=False)
    assert config.customer_posture_enabled() is False
    monkeypatch.setenv(FLAG, "1")
    assert config.customer_posture_enabled() is False, "on without its master switch must be OFF"
    monkeypatch.setenv(MASTER, "1")
    assert config.customer_posture_enabled() is True
    for v in ("0", "", "no", "maybe", "off"):
        monkeypatch.setenv(FLAG, v)
        assert config.customer_posture_enabled() is False, v
    monkeypatch.setenv(FLAG, "yes")
    monkeypatch.setenv(MASTER, "0")
    assert config.customer_posture_enabled() is False


# ==== the projection: measured, ordered, PR-A's own ========================================================================
def test_an_org_with_nothing_tested_is_not_measured_never_100():
    s = _store()
    none = _posture(s, "nohost")                                   # no proven host at all
    assert none["measured"] is False and none["posture_score"] is None and none["hosts_total"] == 0
    slug = _prove(s, "acme", "acme.example")
    out = _posture(s)
    assert out["measured"] is False and out["posture_score"] is None and out["hosts_total"] == 1
    assert out["fix_first"] == [] and out["findings_total"] == 0
    assert [p["posture_score"] for p in out["trend"]["points"]] == [None] * cp.TREND_POINTS
    assert out["trend"]["current"] is None and out["trend"]["change"] is None
    # an assessment that COMPLETED with nothing found IS a measurement: a clean 100 from then on
    _completed(s, slug, at=NOW - 2 * WEEK)
    out = _posture(s)
    assert out["measured"] is True and out["posture_score"] == 100
    assert [p["posture_score"] for p in out["trend"]["points"]] == [None] * 9 + [100] * 3
    # a canceled / failed run measured nothing
    s2 = _store()
    slug2 = _prove(s2, "acme", "acme.example")
    s2.append(kind="assessment_outcome", source="sigil", actor="settle-drain",
              payload={"engagement_slug": slug2, "outcome": "failed", "nonce": "n", "ts": 0.0})
    assert _posture(s2)["measured"] is False


def test_the_list_is_worst_first_in_pr_a_order_with_host_and_identity(monkeypatch):
    monkeypatch.setenv(MASTER, "1")
    s = _store()
    slug = _prove(s, "acme", "acme.example")
    _finding(s, slug, "redir", bug_class="open_redirect", severity="low")
    _finding(s, slug, "sql", bug_class="sqli", severity="critical", presentation=_presentation("sql"))
    _finding(s, slug, "xss", bug_class="xss", severity="high")
    out = _posture(s)
    assert _refs(out["fix_first"]) == ["sql", "xss", "redir"]                  # critical, high, low
    assert out["posture_score"] == ps(("sqli", "critical"), ("xss", "high"), ("open_redirect", "low"))
    assert out["open_total"] == 3 and out["fixed_total"] == 0 and out["findings_total"] == 3
    assert out["severity_counts"]["critical"] == 1 and out["severity_counts"]["low"] == 1
    top = out["fix_first"][0]
    assert top["host"] == "acme.example" and top["status"] == "open" and top["oracle_context_digest"] == "dig-sql"
    assert top["engagement_slug"] == slug and top["remediation"].endswith("FIX-sql")
    # PR-A, not re-derived: with no verdict and no lock this IS PR-A's posture read — same score, same order, and
    # every field of each PR-A triage entry carried unchanged
    pra = fpres.assessment_posture(s, "acme", now=NOW)
    assert out["posture_score"] == pra["posture_score"]
    assert _refs(out["fix_first"]) == [t["finding_ref"] for t in pra["triage"]]
    for mine, theirs in zip(out["fix_first"], pra["triage"]):
        assert {k: mine[k] for k in theirs} == theirs
    # nothing the cert carries beyond the triage projection rides along (no proof, no summary)
    blob = json.dumps(out)
    for leak in ("SUMMARY-", "VERIFY-", "CLAIM-", "MANIFEST-"):
        assert leak not in blob, leak


def test_a_fixed_verdict_lifts_the_score_and_moves_the_finding_to_fixed():
    s = _store()
    slug = _prove(s, "acme", "acme.example")
    _finding(s, slug, "sql", bug_class="sqli", severity="critical", at=NOW - 3 * WEEK)
    _finding(s, slug, "redir", bug_class="open_redirect", severity="low", at=NOW - 3 * WEEK)
    before = _posture(s)["posture_score"]
    _verdict(s, slug, "sql", "fixed", at=NOW - WEEK)
    out = _posture(s)
    assert _refs(out["fix_first"]) == ["redir"] and _refs(out["fixed"]) == ["sql"]
    assert out["posture_score"] == ps(("open_redirect", "low")) > before
    assert (out["open_total"], out["fixed_total"], out["findings_total"]) == (1, 1, 2)
    assert out["fixed"][0]["status"] == "fixed" and out["fixed"][0]["status_at"] == NOW - WEEK
    assert out["severity_counts"]["critical"] == 0                              # counts are of what is OPEN
    assert out["basis"]["counts_fixes"] is True and out["basis"]["weights"] == fpres._PENALTY


def test_still_vulnerable_keeps_it_open_and_the_newest_verdict_wins():
    s = _store()
    slug = _prove(s, "acme", "acme.example")
    _finding(s, slug, "a", bug_class="sqli", severity="critical")
    _finding(s, slug, "b", bug_class="sqli", severity="critical")
    _verdict(s, slug, "a", "fixed")
    _verdict(s, slug, "a", "still_vulnerable")                  # a later retest re-proved it
    _verdict(s, slug, "b", "still_vulnerable")
    _verdict(s, slug, "b", "fixed")                             # and b's later retest cleared it
    out = _posture(s)
    assert _refs(out["fix_first"]) == ["a"] and out["fix_first"][0]["status"] == "still_vulnerable"
    assert _refs(out["fixed"]) == ["b"]


def test_a_fix_never_outlives_a_newer_proof():
    s = _store()
    slug = _prove(s, "acme", "acme.example")
    crit = ("sqli", "critical")
    _finding(s, slug, "sql", bug_class="sqli", severity="critical", at=NOW - 4 * WEEK)
    _verdict(s, slug, "sql", "fixed", at=NOW - 3 * WEEK)
    _finding(s, slug, "sql", bug_class="sqli", severity="critical", at=NOW - WEEK)   # proven AGAIN, same identity
    out = _posture(s)
    # open, once — never ALSO fixed: the earlier record the verdict covered is superseded by the newer proof
    assert (out["open_total"], out["fixed_total"], out["findings_total"]) == (1, 0, 1)
    assert out["fixed"] == [] and out["fix_first"][0]["status"] == "open"
    assert out["posture_score"] == ps(crit)
    # the history: open, then fixed while the fix stood, then open again from the new proof on — never both at once
    assert [(p["posture_score"], p["open"], p["fixed"]) for p in out["trend"]["points"]][7:] == [
        (ps(crit), 1, 0), (100, 0, 1), (100, 0, 1), (ps(crit), 1, 0), (ps(crit), 1, 0)]


def test_only_this_orgs_provisioner_verdicts_count():
    s = _store()
    slug = _prove(s, "acme", "acme.example")
    other = _prove(s, "globex", "globex.example")
    _finding(s, slug, "sql", bug_class="sqli", severity="critical")
    _verdict(s, slug, "sql", "fixed", source="drain")               # not the provisioner: never counts
    _verdict(s, other, "sql", "fixed")                              # another tenant's slug: never this org's
    _verdict(s, slug, "sql", "fixed", digest="dig-OTHER")           # another finding's identity
    _verdict(s, slug, "sql", "cleared")                             # not a verdict the retest action writes
    s.append(kind="finding_retest", source="provision", actor="WARDEN",
             payload={"engagement_slug": [slug], "finding_ref": "sql", "status": "fixed"})   # unhashable slug
    out = _posture(s)
    assert out["fixed_total"] == 0 and out["fix_first"][0]["status"] == "open"
    assert out["posture_score"] == ps(("sqli", "critical"))
    _verdict(s, slug, "sql", "fixed")                               # control: the real one counts
    assert _posture(s)["fixed_total"] == 1


def test_retest_verdicts_count_only_while_the_retest_ui_is_on():
    s = _store()
    slug = _prove(s, "acme", "acme.example")
    _finding(s, slug, "sql", bug_class="sqli", severity="critical", at=NOW - 3 * WEEK)
    _verdict(s, slug, "sql", "fixed", at=NOW - WEEK)
    on, off = _posture(s, verdicts=True), _posture(s, verdicts=False)
    assert on["fixed_total"] == 1 and on["posture_score"] == 100
    assert off["fixed_total"] == 0 and off["posture_score"] == ps(("sqli", "critical"))
    assert off["basis"]["counts_fixes"] is False
    assert [p["fixed"] for p in off["trend"]["points"]] == [0] * cp.TREND_POINTS


def test_tenant_isolation_no_cross_tenant_finding_or_verdict(monkeypatch):
    monkeypatch.setenv(MASTER, "1")
    s = _store()
    a = _prove(s, "acme", "acme.example")
    b = _prove(s, "globex", "globex.example")
    # org A: a presented critical, then fixed; org B: one low finding sharing A's ref and digest (a collision attempt)
    _finding(s, a, "shared", bug_class="sqli", severity="critical", digest="dig-same",
             presentation=_presentation("ACME-ONLY-SECRET"), title="ACME-ONLY-TITLE")
    _finding(s, b, "shared", bug_class="open_redirect", severity="low", digest="dig-same")
    _verdict(s, a, "shared", "fixed", digest="dig-same")
    bp = _posture(s, "globex")
    assert bp["findings_total"] == 1 and bp["open_total"] == 1 and bp["fixed_total"] == 0    # A's fix never fixes B's
    assert bp["posture_score"] == ps(("open_redirect", "low"))
    assert bp["fix_first"][0]["host"] == "globex.example"
    blob = json.dumps(bp) + json.dumps(cp.posture_trend(s, "globex", now=NOW, retest_verdicts=True))
    assert "ACME-ONLY" not in blob and "acme.example" not in blob, "org A's finding leaked into org B's posture"
    ap = _posture(s, "acme")                                        # control: A sees its own (the read is not vacuous)
    assert ap["fixed_total"] == 1 and "ACME-ONLY-TITLE" in json.dumps(ap)


def test_signed_parts_only_when_signed_never_fabricated(monkeypatch):
    monkeypatch.setenv(MASTER, "1")
    s = _store()
    slug = _prove(s, "acme", "acme.example")
    _finding(s, slug, "signed", bug_class="sqli", severity="critical", presentation=_presentation("s"))
    _finding(s, slug, "bare", bug_class="xss", severity="high")
    by = {e["finding_ref"]: e for e in _posture(s)["fix_first"]}
    assert by["signed"]["presentation_signed"] is True and by["signed"]["plain_impact"]["what"] == "WHAT-s"
    assert by["bare"]["presentation_signed"] is False
    assert "plain_impact" not in by["bare"] and "remediation" not in by["bare"]        # never fabricated
    assert any(c["framework"] == "owasp" for c in by["bare"]["standards_chips"])     # class chips still shown
    monkeypatch.delenv(MASTER)                       # the projection never surfaces the block without its master switch
    assert "remediation" not in {k for e in _posture(s)["fix_first"] for k in e}


def test_the_trial_preview_holds_on_the_fix_first_read(monkeypatch):
    monkeypatch.setenv(MASTER, "1")
    s = _store()
    slug = _prove(s, "acme", "acme.example")
    _finding(s, slug, "first", bug_class="xss", severity="high", presentation=_presentation("first"))   # the reveal
    _finding(s, slug, "crit", bug_class="sqli", severity=None, presentation=_presentation("crit"))
    _finding(s, slug, "low", bug_class="open_redirect", severity="low", presentation=_presentation("low"))
    full = _posture(s)
    out = _posture(s, locked=True, can_buy=True)
    assert out["preview"] == {"locked": True, "can_buy": True, "copy_key": "trial_preview"}
    assert out["posture_score"] == full["posture_score"] and out["trend"] == full["trend"]   # aggregates unchanged
    assert _refs(out["fix_first"]) == _refs(full["fix_first"])
    by = {e["finding_ref"]: e for e in out["fix_first"]}
    assert "locked" not in by["first"] and by["first"]["remediation"].endswith("FIX-first")
    assert by["first"]["oracle_context_digest"] == "dig-first"
    for ref in ("crit", "low"):
        e = by[ref]
        assert e["locked"] is True and set(e) <= set(cp._LOCKED_ENTRY_KEYS), sorted(set(e) - set(cp._LOCKED_ENTRY_KEYS))
        assert e["title"] and e["severity"] and e["host"] == "acme.example" and e["standards_chips"]
    assert by["crit"]["severity_basis"] == "estimated" and "unlocked report" in by["crit"]["class_guidance"]
    blob = json.dumps({k: v for k, v in by.items() if k != "first"})
    for leak in ("FIX-crit", "FIX-low", "WHAT-", "PROVED-", "CAN-LEAD-TO", "dig-crit", "dig-low", "SUMMARY-", "VERIFY-"):
        assert leak not in blob, leak
    assert "preview" not in full                                     # an unlocked org's read carries no preview block


def test_the_trend_replays_the_same_arithmetic_week_by_week():
    s = _store()
    slug = _prove(s, "acme", "acme.example")
    _finding(s, slug, "crit", bug_class="sqli", severity="critical", at=NOW - 5 * WEEK)
    _finding(s, slug, "high", bug_class="xss", severity="high", at=NOW - 3 * WEEK)
    _verdict(s, slug, "crit", "fixed", at=NOW - 2 * WEEK)
    _finding(s, slug, "low", bug_class="open_redirect", severity="low", at=NOW - WEEK)
    out = _posture(s)
    tr = out["trend"]
    pts = tr["points"]
    assert len(pts) == cp.TREND_POINTS and tr["step_seconds"] == WEEK
    assert [p["at"] for p in pts] == [int(NOW - (cp.TREND_POINTS - 1 - k) * WEEK) for k in range(cp.TREND_POINTS)]
    crit, high, low = ("sqli", "critical"), ("xss", "high"), ("open_redirect", "low")
    assert [p["posture_score"] for p in pts] == [None] * 6 + [ps(crit), ps(crit), ps(crit, high), ps(high),
                                                               ps(high, low), ps(high, low)]
    assert [(p["open"], p["fixed"]) for p in pts][6:] == [(1, 0), (1, 0), (2, 0), (1, 1), (2, 1), (2, 1)]
    assert tr["current"] == out["posture_score"] == pts[-1]["posture_score"]        # the last point IS the headline
    assert tr["since"] == pts[6]["at"] and tr["change"] == ps(high, low) - ps(crit)
    # the trend read is the very same series, and a read is reproducible
    alone = cp.posture_trend(s, "acme", now=NOW, retest_verdicts=True)
    assert {k: v for k, v in alone.items() if k != "org_id"} == tr and alone["org_id"] == "acme"
    assert _posture(s) == out


def test_an_unreadable_time_can_only_make_the_trend_look_worse():
    s = _store()
    slug = _prove(s, "acme", "acme.example")
    crit, high, low = ("sqli", "critical"), ("xss", "high"), ("open_redirect", "low")
    _finding(s, slug, "crit", bug_class="sqli", severity="critical", at=NOW - 5 * WEEK)
    _finding(s, slug, "high", bug_class="xss", severity="high", at="not a time")       # unreadable: placed at NOW
    _finding(s, slug, "low", bug_class="open_redirect", severity="low", at=NOW + 9 * WEEK)   # future: placed at NOW
    scores = [p["posture_score"] for p in _posture(s)["trend"]["points"]]
    assert scores[6:] == [ps(crit)] * 5 + [ps(crit, high, low)]       # bad news only ever at the latest point
    # a fix whose time cannot be read counts from the earliest point its finding is on record (good news early)...
    _verdict(s, slug, "crit", "fixed", at="garbled")
    scores = [p["posture_score"] for p in _posture(s)["trend"]["points"]]
    assert scores[6:] == [100] * 5 + [ps(high, low)]
    # ...and a re-opening verdict whose time cannot be read lands at the latest point (bad news late)
    _verdict(s, slug, "crit", "still_vulnerable", at="??")
    scores = [p["posture_score"] for p in _posture(s)["trend"]["points"]]
    assert scores[6:] == [100] * 5 + [ps(crit, high, low)]


def test_the_list_is_capped_but_the_totals_stay_true(monkeypatch):
    s = _store()
    slug = _prove(s, "acme", "acme.example")
    for i in range(3):
        _finding(s, slug, f"f{i}", bug_class="xss", severity="high")
    monkeypatch.setattr(cp, "LIST_CAP", 2)
    out = _posture(s)
    assert len(out["fix_first"]) == 2 and out["open_total"] == 3
    assert out["posture_score"] == ps(*[("xss", "high")] * 3)           # the score is never computed from the cap


def test_malformed_records_are_skipped_never_fatal():
    s = _store()
    slug = _prove(s, "acme", "acme.example")
    s.append(kind="finding", source="x", actor="y", payload={"finding_ref": "no-cert"})
    s.append(kind="finding", source="x", actor="y", payload={"certificate": "not-a-dict"})
    s.append(kind="finding", source="x", actor="y", payload={"certificate": {"engagement_slug": [slug]}})
    s.append(kind="assessment_outcome", source="x", actor="y", payload={"engagement_slug": {"x": 1}, "outcome": "completed"})
    _finding(s, slug, "ok", bug_class="xss", severity="high")
    out = _posture(s)
    assert _refs(out["fix_first"]) == ["ok"] and out["findings_total"] == 1


# ==== the provisioner, the cockpit and the edge ===============================================================================
def _prov(store, owner) -> Provisioner:
    return Provisioner(
        store, customers=CustomerRegistry(store, owner_key=owner), orgs=OrgRegistry(store, owner_key=owner),
        wallet=WalletRegistry(store, owner_key=owner), email_tokens=EmailTokenLedger(tempfile.mkdtemp(), ttl_s=1e4),
        rate_limiter=LoginRateLimiter(tempfile.mkdtemp(), max_fails=50, window_s=1e4, base_lock_s=50.0),
        email_sender=NullEmailSender(), trial_credits=100, now_fn=lambda: NOW)


def _org(p: Provisioner, org: str, members: "dict[str, str]") -> None:
    p.orgs.create_org(org, org.upper(), owner="owner", issued_at=float(next(_ISSUED)))
    for user, role in members.items():
        p.orgs.grant_membership(org, user, role, issued_at=float(next(_ISSUED)))


def test_the_provisioner_gates_on_view_assessments_and_the_flag(monkeypatch):
    s = _store()
    p = _prov(s, ensure_owner_keypair())
    _org(p, "acme", {"olive": "operator", "adam": "org_admin"})
    _prove(s, "acme", "acme.example")
    monkeypatch.delenv(FLAG, raising=False)
    monkeypatch.setenv(MASTER, "1")
    for call in (p.customer_posture, p.customer_posture_trend):
        with pytest.raises(ProvisionDenied, match="not enabled"):       # refuses even if reached with the flag off
            call("olive", "acme")
    monkeypatch.setenv(FLAG, "1")
    out = p.customer_posture("olive", "acme")
    assert out["org_id"] == "acme" and out["hosts_total"] == 1 and "preview" not in out
    assert p.customer_posture_trend("olive", "acme")["org_id"] == "acme"
    for who, org in (("adam", "acme"), ("olive", "globex"), ("nobody", "acme")):
        for call in (p.customer_posture, p.customer_posture_trend):
            with pytest.raises(ProvisionDenied, match="may not read"):  # billing role / another org / no member
                call(who, org)
    monkeypatch.setenv(RETEST, "1")
    assert p.customer_posture("olive", "acme")["basis"]["counts_fixes"] is True
    monkeypatch.delenv(RETEST)
    assert p.customer_posture("olive", "acme")["basis"]["counts_fixes"] is False


def test_the_provisioner_applies_the_trial_lock_and_who_may_buy(monkeypatch, flags_on):
    s = _store()
    p = _prov(s, ensure_owner_keypair())
    _org(p, "acme", {"olive": "operator", "fay": "founder"})
    slug = _prove(s, "acme", "acme.example")
    _finding(s, slug, "a", bug_class="xss", severity="high")
    _finding(s, slug, "b", bug_class="sqli", severity="critical")
    monkeypatch.setattr(p, "_preview_locked", lambda org: True)
    monkeypatch.setenv("VIGIL_SIGNUP_FOUNDER_TESTER_ENABLED", "1")     # else a founder is admitted as org_admin only
    op = p.customer_posture("olive", "acme")
    assert op["preview"] == {"locked": True, "can_buy": False, "copy_key": "trial_preview"}
    assert [e.get("locked") for e in op["fix_first"]] == [True, None]       # b (critical) locked; a, the reveal, full
    assert p.customer_posture("fay", "acme")["preview"]["can_buy"] is True   # the founder may buy the unlock


class _P:
    def __init__(self):
        self.calls: list = []

    def __getattr__(self, name):
        def f(*a, **k):
            self.calls.append((name, a, k))
            return {"ok": True}
        return f


def test_the_cockpit_actions_exist_only_with_the_flag(monkeypatch):
    from sigil.ui.server import Handler
    body = {"org_id": "org_a", "ip": "1.2.3.4", "requester": "cust_eve", "username": "cust_eve"}
    for flag, master in (("", ""), ("1", ""), ("", "1")):
        monkeypatch.setenv(FLAG, flag)
        monkeypatch.setenv(MASTER, master)
        for action in ("customer_posture", "posture_trend"):
            p = _P()
            assert Handler._provision_dispatch(None, p, action, "cust_ad", dict(body)) is None, (flag, master)
            assert p.calls == []
    monkeypatch.setenv(FLAG, "1")
    monkeypatch.setenv(MASTER, "1")
    p = _P()
    Handler._provision_dispatch(None, p, "customer_posture", "cust_ad", dict(body))
    Handler._provision_dispatch(None, p, "posture_trend", "cust_ad", dict(body))
    # the requester is the hop principal and the org the edge session's — a body field naming someone else is never used
    assert p.calls == [("customer_posture", ("cust_ad", "org_a"), {"ip": "1.2.3.4"}),
                       ("customer_posture_trend", ("cust_ad", "org_a"), {"ip": "1.2.3.4"})]


def _edge_stub(session):
    """A customer-edge handler with its session and its hop to the provisioner stubbed: what does it relay?"""
    from sigil.ui.custui import CustomerHandler
    h = object.__new__(CustomerHandler)
    sent: dict = {}
    h._session = lambda: session
    h._ip = lambda: "1.2.3.4"
    h._provision = lambda action, principal, body: (sent.update(action=action, principal=principal, body=body)
                                                    or (200, {"ok": True}))
    h._json = lambda obj, code=200: sent.update(code=code, out=obj)
    h._deny = lambda code=403, msg="forbidden": sent.update(code=code, out={"error": msg})
    return h, sent


_SESSION = {"username": "cust_ad", "org_id": "org_a", "mfa_at": 123.0}
_ROUTES = {"/api/customer/posture": "customer_posture", "/api/customer/posture/trend": "posture_trend"}


def test_the_edge_routes_are_absent_with_the_flag_off(monkeypatch):
    for flag, master in (("", ""), ("1", ""), ("", "1")):
        monkeypatch.setenv(FLAG, flag)
        monkeypatch.setenv(MASTER, master)
        for path in _ROUTES:
            h, sent = _edge_stub(dict(_SESSION))
            h.path = path
            h.do_GET()
            h2, unknown = _edge_stub(dict(_SESSION))
            h2.path = "/api/customer/nope"
            h2.do_GET()
            assert sent == unknown == {"code": 404, "out": {"error": "not found"}}, (path, flag, master)


def test_the_edge_relays_for_the_session_org_only(flags_on):
    for path, action in _ROUTES.items():
        h, sent = _edge_stub(dict(_SESSION))
        h.path = path + "?org_id=org_b&username=cust_bb"
        h.do_GET()
        assert sent == {"action": action, "principal": "cust_ad", "body": {"org_id": "org_a", "ip": "1.2.3.4"},
                        "code": 200, "out": {"ok": True}}, path
        for session in (None, {}, {"username": "cust_ad"}, {"username": "cust_ad", "org_id": ""}):
            h, sent = _edge_stub(session)
            h.path = path
            h.do_GET()
            assert sent["code"] == 401 and "action" not in sent, (path, session)


def test_the_edge_writes_the_posture_flag_into_the_page(tmp_path, monkeypatch):
    monkeypatch.delenv(FLAG, raising=False)
    monkeypatch.delenv(MASTER, raising=False)
    off, build_off = _page_and_build(tmp_path / "a")
    assert 'data-posture="0"' in off and "__VIGIL_POSTURE__" not in off
    for v in ("0", "", "no", "maybe", "1"):            # "1" too: without its master switch the screen is off
        monkeypatch.setenv(FLAG, v)
        assert _page_and_build(tmp_path / f"c{v or 'empty'}") == (off, build_off), v
    monkeypatch.setenv(FLAG, "1")
    monkeypatch.setenv(MASTER, "1")
    on, build_on = _page_and_build(tmp_path / "b")
    assert 'data-posture="1"' in on and build_on != build_off
    # the page's only difference: its own value and the build id (the master switch writes nothing into the page)
    assert on.replace('data-posture="1"', 'data-posture="0"').replace(build_on, build_off) == off


# ==== over the real hop =======================================================================================================
def _signup(op, ep, email: str) -> "tuple[str, str]":
    t = _post(op, ep, "/api/customer/signup/request", {"email": email})[1]["dev_token"]
    conf = _post(op, ep, "/api/customer/signup/confirm",
                 {"token": t, "password": "customer-pw-1", "org_name": email.split("@")[1]})[1]
    return conf["org_id"], conf["username"]


def _prove_live(store, org: str, host: str) -> str:
    reg = AssetOwnershipRegistry(store)
    ch = reg.issue_challenge(org, host, issued_at=time.time() + 1e6 + next(_ISSUED))
    reg.verify_and_record(org, host, method=METHOD_DNS_TXT, observed=[ch.marker], now=time.time(), ttl_seconds=1e9)
    return _customer_slug(org, host)


def test_the_posture_reads_over_the_real_hop_are_session_scoped(tmp_path, monkeypatch):
    sov, edge, ep, _ = _stack(tmp_path, monkeypatch)
    try:
        opA, opB = _opener(), _opener()
        orgA, userA = _signup(opA, ep, "a@acme.io")
        orgB, userB = _signup(opB, ep, "b@globex.io")
        for path in _ROUTES:                                        # flag off: absent, exactly as an unknown route
            assert _get(opA, ep, path) == _get(opA, ep, "/api/customer/nope"), path
        monkeypatch.setenv(FLAG, "1")
        monkeypatch.setenv(MASTER, "1")
        for path in _ROUTES:
            assert _get(opA, ep, path)[0] == 403, path              # the sign-up org_admin: billing is not testing
            assert _get(_opener(), ep, path)[0] == 401, path         # no session: refused before the hop
        for org, user in ((orgA, userA), (orgB, userB)):
            OrgRegistry(sov.store()).grant_membership(org, user, "operator", issued_at=time.time() + 1e6)
        slugA = _prove_live(sov.store(), orgA, "app.acme.io")
        slugB = _prove_live(sov.store(), orgB, "app.globex.io")
        _finding(sov.store(), slugA, "a-low", bug_class="open_redirect", severity="low")
        _finding(sov.store(), slugA, "a-crit", bug_class="sqli", severity="critical", title="ACME-CRIT")
        _finding(sov.store(), slugB, "b-high", bug_class="xss", severity="high", title="GLOBEX-HIGH")
        c, a = _get(opA, ep, f"/api/customer/posture?org_id={orgB}")       # an org selector is IGNORED
        assert c == 200 and a["org_id"] == orgA and a["measured"] is True
        assert _refs(a["fix_first"]) == ["a-crit", "a-low"] and "GLOBEX" not in json.dumps(a)
        assert a["posture_score"] == ps(("sqli", "critical"), ("open_redirect", "low"))
        c, t = _get(opA, ep, "/api/customer/posture/trend")
        assert c == 200 and t["org_id"] == orgA and t["current"] == a["posture_score"]
        c, b = _get(opB, ep, "/api/customer/posture")
        assert c == 200 and b["org_id"] == orgB and _refs(b["fix_first"]) == ["b-high"] and "ACME" not in json.dumps(b)
    finally:
        sov.shutdown(); edge.shutdown()


def test_no_locked_detail_leaves_the_posture_reads(tmp_path, monkeypatch):
    """The preview leak scan, over the real hop, for the routes outside `_READS`: a locked trial org's Fix-first and
    trend reads never carry a non-revealed finding's signed fix, plain-language impact, identity or proof."""
    monkeypatch.setenv("VIGIL_TRIAL_PREVIEW_ENABLED", "1")
    monkeypatch.setenv(FLAG, "1")
    monkeypatch.setenv(MASTER, "1")
    sov, edge, ep, _ = _stack(tmp_path, monkeypatch)
    try:
        op = _opener()
        org, user = _signup(op, ep, "trial@acme.io")
        OrgRegistry(sov.store()).grant_membership(org, user, "operator", issued_at=time.time() + 2e6)
        slug = _prove_live(sov.store(), org, "app.acme.io")
        refs = [f"f{i}" for i in range(4)]
        for ref in refs:
            _finding(sov.store(), slug, ref, bug_class="sqli", severity="critical", presentation=_presentation(ref))
        c, found = _get(op, ep, "/api/customer/assessments/findings")
        assert c == 200 and found["preview"]["locked"]
        revealed = [r["finding_ref"] for r in found["findings"] if not r["locked"]]
        assert revealed == ["f0"]                                    # the findings read pins the one reveal
        c, post = _get(op, ep, "/api/customer/posture")
        assert c == 200 and post["preview"]["locked"] is True and post["preview"]["can_buy"] is False
        full = [e["finding_ref"] for e in post["fix_first"] if not e.get("locked")]
        assert full == revealed                                      # the SAME reveal, never a second one
        c, trend = _get(op, ep, "/api/customer/posture/trend")
        assert c == 200
        blob = json.dumps(post) + json.dumps(trend)
        for ref in refs[1:]:
            for leak in (f"FIX-{ref}", f"WHAT-{ref}", f"PROVED-{ref}", f"CAN-LEAD-TO-{ref}", f"dig-{ref}",
                         f"SUMMARY-{ref}", f"VERIFY-{ref}", f"CLAIM-{ref}", f"MANIFEST-{ref}"):
                assert leak not in blob, leak
        assert "FIX-f0" in blob and "dig-f0" in blob                 # the reveal IS in full (the scan is not vacuous)
    finally:
        sov.shutdown(); edge.shutdown()


# ==== the screen, under node ====================================================================================================
def _src() -> str:
    return APP_JS.read_text(encoding="utf-8")


_WORLD = r"""
document.body.dataset.posture = %(posture)s;
document.body.dataset.retest = %(retest)s;
document.createElementNS = (ns, t) => { const e = new El(t); e.ns = ns; return e; };
var GUIDE = null, GUIDE_ON = false;
let who = { authenticated: true, username: "ana", org_id: "org_x" };
const state = { get: () => ({ who }) };
function authed() { return !!(who && who.authenticated); }
globalThis.location = { hash: "#/fix-first" };
const navs = []; function nav(r) { navs.push(r); location.hash = r; }
let whoRefreshes = 0; async function refreshWho() { whoRefreshes++; }
function shell(inner, current) { return h("div.shell", { dataset: { current: current } }, inner); }
var ntf = { open: false }; function toggleNtf() {}
const VUI = window.VUI;
const calls = [];
let server = {};            // "GET <path>" / "POST <path>" -> {data} | {status, data} | {wait: <promise of the data>}
async function answer(key) {
  const r = server[key];
  if (!r) { const e = new Error("404"); e.status = 404; e.data = { error: "not found" }; throw e; }
  if (r.wait) return await r.wait;
  if (r.status) { const e = new Error("x"); e.status = r.status; e.data = r.data; throw e; }
  return r.data;
}
VUI.getJSON = async p => { calls.push(["GET", p]); return answer("GET " + p); };
VUI.postJSON = async (p, b) => { calls.push(["POST", p, b]); return answer("POST " + p); };
VUI.toast = () => {}; VUI.errorBanner = () => {}; VUI.clearErrorBanner = () => {};
const tick = () => new Promise(r => setTimeout(r, 0));
const flush = async () => { for (let i = 0; i < 12; i++) await tick(); };
const fire = (el, type) => (el.listeners[type] || []).slice().forEach(f => f({ preventDefault() {} }));
const entries = () => document.querySelectorAll("div.cust-fix-entry");
const out = {};
"""

_APP_FUNCS = ("pageFlag", "loadingHolder", "kv", "fmtDate", "here", "overviewLink", "viewFixFirst", "fixFirstBody",
              "postureTile", "postureDelta", "postureTrend", "postureSvg", "posturePointText", "postureSpark",
              "postureCounts", "postureHow", "postureTable", "fixPreviewNote", "fixList", "fixEntry", "fixSection",
              "fixRich", "fixStandards", "fixChip", "fixFixed", "postureFill", "retestBadge", "retestControls",
              "retestFinding", "retestMessage")
_APP_VARS = ("API", "POSTURE_ON", "FIX_PAGE", "FIX_SEVERITY", "FIX_TIER", "FIX_EFFORT", "FIX_CHIPS", "POSTURE_SVG",
             "POSTURE_BOX", "RETEST_ON")


def _node(script: str, *, posture: str = "1", retest: str = "0") -> dict:
    src = _src()
    prog = "\n".join([_DOM, f"require({json.dumps(str(UI_JS))});", "const h = window.VUI.h;",
                      _WORLD % {"posture": json.dumps(posture), "retest": json.dumps(retest)}]
                     + [_fn(src, n) for n in _APP_FUNCS] + [_var(src, n) for n in _APP_VARS]
                     + ["(async () => {\n" + script + "\n})().then(() => process.stdout.write(JSON.stringify(out)),"
                        " e => { console.error(e && e.stack || e); process.exit(3); });"])
    r = subprocess.run([_need_node(), "-e", prog], capture_output=True, text=True, timeout=60)
    assert r.returncode == 0, r.stderr
    return json.loads(r.stdout)


def _served(payload: dict, trend: "dict | None" = None) -> str:
    srv = {"GET api/customer/posture": {"data": payload}}
    if trend is not None:
        srv["GET api/customer/posture/trend"] = {"data": trend}
    return f"server = {json.dumps(srv)};\n"


_SCREEN = r"""
const view = viewFixFirst(); document.body.appendChild(view); await flush();
"""


def _realistic(monkeypatch, *, locked: bool = False, can_buy: bool = False) -> dict:
    """A real Fix-first payload, computed by the server's own projection (so the screen renders what ships)."""
    monkeypatch.setenv(MASTER, "1")
    s = _store()
    slug = _prove(s, "acme", "acme.example")
    _finding(s, slug, "crit", bug_class="sqli", severity="critical", at=NOW - 5 * WEEK, title="SQL injection at /login",
             presentation=_presentation("crit"))
    _finding(s, slug, "high", bug_class="xss", severity="high", at=NOW - 3 * WEEK, title="Reflected XSS at /search")
    _verdict(s, slug, "crit", "fixed", at=NOW - 2 * WEEK)
    _finding(s, slug, "low", bug_class="open_redirect", severity="low", at=NOW - WEEK, title="Open redirect at /go",
             presentation=_presentation("low", on_file=False))
    _finding(s, slug, "med", bug_class="weak_tls", severity="medium", at=NOW - WEEK, title="Weak TLS")
    return json.loads(json.dumps(_posture(s, locked=locked, can_buy=can_buy)))


def test_with_the_flag_off_the_app_is_unchanged():
    """app.js's own top bar (shell + navLink), routeShown and route table, verbatim, over stub screens."""
    src = _src()
    i = src.index("  var ROUTES = {")
    table = src[i:src.index("\n  };", i) + 5]
    views = ("viewDashboard", "viewLogin", "viewSignup", "viewRecover", "viewGoogleCode", "viewBilling",
             "viewBillingReturn", "viewInvoices", "viewAssets", "viewAssessments", "viewGuideScreen", "viewMonitoring",
             "viewTeam", "viewCode", "viewSecurityScreen", "viewFixFirst", "viewAttackPath", "viewConnect")
    stubs = ("var SECURITY_ON = false, MONITORING_ON = false, CODE_ON = false, TEAM_ON = false, ATTACK_PATH_ON = false,"
             " CONNECT_ON = false, SETTINGS_ON = false, PRIVACY_CENTER_ON = false, SELLER_IDENTITY_ON = false,"
             " LIVE_ON = false;\n"
             "function ntfWidget() { return null; }\nasync function doLogout() {}\n"
             "function viewSoon(t) { return \"viewSoon:\" + t; }\n"
             + "\n".join(f"function {v}() {{ return {json.dumps(v)}; }}" for v in views))
    script = r"""
const links = shell(h("div"), "#/").querySelectorAll("button.cust-nav-link").map(b => text(b));
out.links = links;
out.route = ROUTES["#/fix-first"](); out.home = ROUTES["#/"]();
who = { authenticated: false }; out.signedOut = ROUTES["#/fix-first"](); who = { authenticated: true, username: "ana" };
out.shown = [routeShown("#/fix-first"), routeShown("#/billing")];
await tick();
out.calls = calls;
"""
    harness = stubs + "\n" + _fn(src, "navLink") + _fn(src, "shell") + _fn(src, "routeShown") + table + "\n" + script
    base = ["Overview", "Billing", "Invoices", "Assets", "Assessments", "Team"]
    for flag in ("0", "", "__VIGIL_POSTURE__"):
        off = _node(harness, posture=flag)
        assert off["links"] == base + ["Sign out (ana)"], flag
        assert off["route"] == off["home"] == "viewDashboard" and off["signedOut"] == "viewLogin", flag
        assert off["shown"] == [False, True] and off["calls"] == [], flag      # no "Go to Fix first", no read
    on = _node(harness, posture="1")
    assert on["links"] == base + ["Fix first", "Sign out (ana)"]
    assert on["route"] == "viewFixFirst" and on["signedOut"] == "viewLogin" and on["shown"] == [True, True]
    assert '.concat(pageFlag("posture") ? [navLink("Fix first", "#/fix-first")] : [])' in src


def test_the_screen_shows_the_posture_the_trend_and_the_list_worst_first(monkeypatch):
    payload = _realistic(monkeypatch)
    out = _node(_served(payload) + _SCREEN + r"""
out.calls = calls;
out.title = text(document.querySelector("h2"));
out.score = text(document.querySelector("span.cust-posture-score")) + text(document.querySelector("span.cust-posture-max"));
out.delta = text(document.querySelector("p.cust-posture-delta"));
out.deltaClass = document.querySelector("p.cust-posture-delta").className;
out.counts = document.querySelector("div.cust-posture").querySelectorAll("p.cust-muted").map(text)[0];
const svg = document.querySelector("svg");
out.svg = [svg.getAttribute("class"), svg.ns, svg.getAttribute("aria-label")];
out.polyline = document.querySelector("polyline").getAttribute("points").split(" ").length;
out.hits = document.querySelectorAll("rect").length;
out.focusable = document.querySelectorAll("rect").every(r => r.getAttribute("tabindex") === "0");
const rects = document.querySelectorAll("rect");
const readout = document.querySelector("p.cust-posture-readout");
fire(rects[11], "focus"); out.readNow = text(readout);
const cross = document.querySelectorAll("line")[1];
out.cross = [cross.getAttribute("visibility"), cross.getAttribute("x1")];
fire(rects[0], "pointerenter"); out.readOld = text(readout);
out.dotHidden = document.querySelectorAll("circle")[1].getAttribute("visibility");
fire(rects[0], "pointerleave"); out.readGone = text(readout); out.crossGone = cross.getAttribute("visibility");
out.labels = rects.map(r => r.getAttribute("aria-label"));
out.table = document.querySelector("details.cust-posture-table").querySelectorAll("tr").map(tr => tr.children.map(text));
out.how = document.querySelector("details.cust-posture-how").querySelectorAll("p").map(text);
out.order = entries().map(e => text(e.querySelector("strong.cust-fix-title")));
out.sev = entries().map(e => text(e.querySelector("span.sev")));
out.first = text(entries()[0]);
out.firstSecs = entries()[0].querySelectorAll("div.cust-fix-sec").map(d => text(d.querySelector("span.k")));
out.chips = entries()[0].querySelectorAll("span.cust-fix-chip").map(text);
out.code = entries()[0].querySelectorAll("code").map(text);
out.fixed = text(document.querySelector("details.cust-fix-fixed"));
out.h3 = document.querySelectorAll("h3").map(text);
""")
    assert out["calls"] == [["GET", "api/customer/posture"]]           # one read, the session's: no org id, no body
    assert out["title"] == "Fix first" and out["score"] == f"{payload['posture_score']}/100"
    tr = payload["trend"]
    assert out["delta"] == f"▲Up {tr['change']} since {datetime.fromtimestamp(tr['since'], timezone.utc):%Y-%m-%d}"
    assert out["deltaClass"] == "cust-posture-delta up"
    assert out["counts"] == "From 3 open findings on 1 verified host · 1 fixed by a retest."
    assert out["svg"] == ["cust-posture-spark", "http://www.w3.org/2000/svg", "Your posture over the last 12 weeks"]
    assert out["polyline"] == 6 and out["hits"] == 12 and out["focusable"] is True      # 6 scored weeks, 12 targets
    last = tr["points"][-1]
    assert out["readNow"] == f"Now: {last['posture_score']}/100 · {last['open']} open · {last['fixed']} fixed"
    assert out["cross"][0] == "visible" and out["readGone"] == "" and out["crossGone"] == "hidden"
    assert out["readOld"].endswith(": not measured yet") and out["dotHidden"] == "hidden"
    assert len(out["table"]) == 13 and out["table"][0] == ["Date", "Posture", "Open", "Fixed"]
    assert out["table"][1][1:] == ["Not measured yet", "—", "—"] and out["table"][-1][0] == "Now"
    assert out["table"][-1][1:] == [f"{last['posture_score']}/100", str(last["open"]), str(last["fixed"])]
    assert out["labels"][-1] == out["readNow"]                       # each week's accessible name is its readout
    assert "Critical 45, High 22" in out["how"][0] and "not a certified rating" in out["how"][2]
    assert out["how"][1] == "A finding stops counting once a retest shows its proof no longer works."
    # worst first, exactly the server's order; the fixed critical is under Fixed, not in the list
    assert out["order"] == [e["title"] for e in payload["fix_first"]] == ["Reflected XSS at /search", "Weak TLS",
                                                                          "Open redirect at /go"]
    assert out["sev"] == ["High", "Medium", "Low"]
    assert out["h3"] == ["Security posture", "What to fix first"]
    assert "SQL injection at /login" in out["fixed"] and "Fixed (1)" in out["fixed"]
    # the unsigned high finding: chips, but no plain-language part and no fix — said honestly
    assert out["firstSecs"] == ["Standards it touches"]
    assert "Its proof and how to verify it are on Assessments." in out["first"]
    assert "OWASP Top 10 A03:2021" in out["chips"] and any(c.startswith("CWE-") for c in out["chips"])
    assert out["code"] == []


def test_signed_parts_appear_only_when_sent(monkeypatch):
    payload = _realistic(monkeypatch)
    low = next(e for e in payload["fix_first"] if e["finding_ref"] == "low")       # signed, description NOT on file
    signed = dict(low, finding_ref="sig", title="Signed", plain_impact=dict(low["plain_impact"], description_on_file=True))
    payload = dict(payload, fix_first=[signed, low])
    out = _node(_served(payload) + _SCREEN + r"""
out.secs = entries().map(e => e.querySelectorAll("div.cust-fix-sec").map(d => [text(d.querySelector("span.k")),
                                                                               text(d.querySelector("p"))]));
out.code = entries()[0].querySelectorAll("code").map(text);
out.text = entries().map(text);
""")
    signed_secs, low_secs = out["secs"]
    assert [k for k, _ in signed_secs] == ["What it is", "What VIGIL's check proved", "What this kind of weakness can lead to",
                                           "Standards it touches", "How to fix it"]
    assert dict(signed_secs)["What it is"] == "WHAT-low" and dict(signed_secs)["What VIGIL's check proved"] == "that PROVED-low"
    assert dict(signed_secs)["How to fix it"] == "For id on GET /x: FIX-low" and out["code"] == ["id", "GET /x"]
    # description not on file: what the check proved and the fix, but no improvised "what it is" / "can lead to"
    assert [k for k, _ in low_secs] == ["What VIGIL's check proved", "Standards it touches", "How to fix it"]
    assert all("Its proof and how to verify it are on Assessments." not in t for t in out["text"])


def test_a_locked_trial_sees_the_unlock_note_and_no_retest(monkeypatch):
    payload = _realistic(monkeypatch, locked=True)
    script = _SCREEN + r"""
out.note = text(document.querySelector("div.cust-fix-preview"));
out.go = document.querySelector("div.cust-fix-preview").querySelectorAll("button").map(text);
out.retest = document.querySelectorAll("button").filter(b => text(b) === "Retest").length;
out.entries = entries().map(text);
"""
    out = _node(_served(payload) + script, retest="1")
    assert "During your trial you see every finding, and one of them in full." in out["note"]
    assert out["go"] == [] and "Someone who manages billing" in out["note"]
    assert out["retest"] == 0                                        # a locked trial cannot retest: none is offered
    locked = [t for t in out["entries"] if "Its proof and fix unlock with the full report." in t]
    assert len(locked) == len([e for e in payload["fix_first"] if e.get("locked")]) > 0
    buyer = _node(_served(_realistic(monkeypatch, locked=True, can_buy=True)) + script, retest="1")
    assert buyer["go"] == ["Go to Billing"]


def test_retest_controls_follow_the_retest_switch_and_name_the_finding(monkeypatch):
    payload = _realistic(monkeypatch)
    first = payload["fix_first"][0]
    script = _served(payload) + r"""
server["POST api/customer/retest"] = { data: { status: "fixed" } };
""" + _SCREEN + r"""
const b = document.querySelectorAll("button").filter(x => text(x) === "Retest");
out.buttons = b.length;
if (b.length) { b[0].click(); await flush(); }
out.posts = calls.filter(c => c[0] === "POST");
out.after = b.length ? text(entries()[0]) : "";
"""
    off = _node(script, retest="0")
    assert off["buttons"] == 0 and off["posts"] == []
    on = _node(script, retest="1")
    assert on["buttons"] == len(payload["fix_first"])
    # the finding's full identity exactly as the read gave it — never an org or a user
    assert on["posts"] == [["POST", "api/customer/retest", {"engagement_slug": first["engagement_slug"],
                                                            "finding_ref": first["finding_ref"],
                                                            "oracle_context_digest": first["oracle_context_digest"]}]]
    assert "✓ Fixed" in on["after"]


def test_the_list_pages_twenty_at_a_time_and_says_when_it_is_capped(monkeypatch):
    payload = _realistic(monkeypatch)
    one = payload["fix_first"][0]
    payload = dict(payload, fix_first=[dict(one, finding_ref=f"f{i}", title=f"F{i}") for i in range(25)], open_total=30)
    out = _node(_served(payload) + _SCREEN + r"""
out.first = entries().length;
const more = document.querySelectorAll("button").filter(b => text(b).indexOf("Show ") === 0);
out.more = more.map(text);
more[0].click();
out.after = entries().length;
out.left = document.querySelectorAll("button").filter(b => text(b).indexOf("Show ") === 0).length;
out.cap = document.querySelectorAll("p.cust-muted").map(text).filter(t => t.indexOf("most urgent") >= 0);
""")
    assert out["first"] == 20 and out["more"] == ["Show 5 more"] and out["after"] == 25 and out["left"] == 0
    assert out["cap"] == ["Showing the 25 most urgent of 30 open findings."]


def test_the_screen_loads_honestly():
    def run(serve: str, then: str = "") -> dict:
        return _node(serve + _SCREEN + then + r"""
out.body = text(document.querySelector("div.cust-fix")); out.navs = navs; out.whoRefreshes = whoRefreshes;
out.buttons = document.querySelector("div.cust-fix").querySelectorAll("button").map(text);
""")
    secret = "requester may not read this org (view_assessments) at 10.0.0.7"
    forbidden = run(f'server = {{ "GET api/customer/posture": {{ status: 403, data: {{ error: {json.dumps(secret)} }} }} }};')
    assert forbidden["body"] == ("Your role does not have access to findings. The founder can see them, and so can a "
                                 "teammate VIGIL has made an Operator.")
    for status in (404, 500, 502, 503):
        failed = run(f'server = {{ "GET api/customer/posture": {{ status: {status}, data: {{ error: {json.dumps(secret)} }} }} }};')
        assert failed["body"] == "Could not load your posture right now.", status
    ended = run('server = { "GET api/customer/posture": { status: 401, data: { error: "login required" } } };')
    assert ended["whoRefreshes"] == 1 and ended["navs"] == ["#/login"]
    # nothing tested yet: an honest card that says where to begin — never a score
    no_host = run(_served({"measured": False, "posture_score": None, "hosts_total": 0}))
    assert no_host["body"].startswith("No results yet. Prove you control a host in Assets")
    assert no_host["buttons"] == ["Go to Assets"]
    untested = run(_served({"measured": False, "posture_score": None, "hosts_total": 2}))
    assert untested["buttons"] == ["Go to Assessments"] and "/100" not in untested["body"]
    clean = run(_served({"measured": True, "posture_score": 100, "hosts_total": 1, "open_total": 0, "fix_first": [],
                         "fixed": [], "trend": {"points": []}, "basis": {}}))
    assert "Nothing to fix right now" in clean["body"] and "100/100" in clean["body"]
    # a read that comes back after the customer left changes nothing (and redirects nowhere)
    left = _node(r"""
let release; const gate = new Promise(r => { release = r; });
server = { "GET api/customer/posture": { wait: gate.then(() => { const e = new Error("x"); e.status = 401; throw e; }) } };
const view = viewFixFirst(); document.body.appendChild(view);
location.hash = "#/billing"; release(); await flush();
out.body = text(document.querySelector("div.cust-fix")); out.navs = navs; out.whoRefreshes = whoRefreshes;
""")
    assert left["body"] == "Loading…" and left["navs"] == [] and left["whoRefreshes"] == 0


_OVERVIEW = r"""
document.body.dataset.overview = "1";
var MONITORING_ON = false;
function seenSet() { return {}; }
"""


def _overview(script: str, *, posture: str = "1") -> dict:
    src = _src()
    extra = "\n".join([_OVERVIEW, _fn(src, "viewOverview"), _fn(src, "overviewCard"), _fn(src, "creditsFill"),
                       _fn(src, "hostsFill"), _fn(src, "assessFill"), _fn(src, "ntfFill")])
    return _node(extra + "\n" + script, posture=posture)


_OV_SERVER = r"""
server = { "GET api/customer/billing": { data: { credits: { available: 5 } } }, "GET api/customer/assets": { data: { assets: [] } },
           "GET api/customer/assessments": { data: { assessments: [] } }, "GET api/customer/notifications": { data: { notifications: [] } },
           "GET api/customer/posture/trend": { data: TREND } };
location.hash = "#/";
const view = viewOverview(); document.body.appendChild(view); await flush();
const card = t => document.querySelectorAll("div.card").filter(c => ((c.querySelectorAll("h3")[0] || {}).textContent) === t)[0];
out.titles = document.querySelectorAll("div.card").map(c => (c.querySelectorAll("h3")[0] || {}).textContent);
out.reads = calls.map(c => c[1]);
"""


def test_the_overview_posture_card_only_with_the_flag(monkeypatch):
    payload = _realistic(monkeypatch)
    trend = dict(payload["trend"], org_id="acme")
    script = _OV_SERVER.replace("TREND", json.dumps(trend)) + r"""
const c = card("Posture");
out.rows = c ? c.querySelectorAll("div.cust-kv").map(text) : null;
out.delta = c ? text(c.querySelector("p.cust-posture-delta")) : null;
if (c) { c.querySelectorAll("button")[0].click(); }
out.navs = navs;
"""
    on = _overview(script)
    assert on["titles"] == ["Account", "Credits", "Authorized hosts", "Assessments", "Posture", "Notifications"]
    last = trend["points"][-1]
    assert on["rows"] == [f"Posture{trend['current']}/100", f"Open findings{last['open']}"]
    assert on["delta"].startswith(f"▲Up {trend['change']} since ") and on["navs"] == ["#/fix-first"]
    assert "api/customer/posture/trend" in on["reads"] and "api/customer/posture" not in on["reads"]
    for flag in ("0", "", "__VIGIL_POSTURE__"):
        off = _overview(script, posture=flag)
        assert "Posture" not in off["titles"] and off["rows"] is None, flag
        assert not any("posture" in r for r in off["reads"]), flag
    unmeasured = _overview(_OV_SERVER.replace("TREND", json.dumps({"points": [], "current": None})) + r"""
out.text = text(card("Posture"));
""")
    assert unmeasured["text"] == "PostureNo results yet.Open Fix first"


_ENGINE = re.compile(r"\b(claude|anthropic|opus|sonnet|haiku|fable|strix|nyx|ultracode|gpt|openai|llm)\b", re.I)
_ESTIMATE = re.compile(r"estimat|quote|predict|forecast|\bcost", re.I)
_MONEY = re.compile(r"[$€£]\s?\d|\b(usd|eur|gbp)\b|\bcredits?\b", re.I)


def test_the_screen_shows_no_estimate_price_or_engine_name(monkeypatch):
    out = _node(_served(_realistic(monkeypatch)) + _SCREEN + "out.blob = view.textContent;")
    for rx in (_ENGINE, _ESTIMATE, _MONEY):
        hit = rx.search(out["blob"])
        assert not hit, hit and hit.group(0)
    # and none in any words the screen's own code can put on screen (its string literals; comments are not shown)
    src = _src()
    code = "\n".join(_fn(src, n) for n in _APP_FUNCS[5:26]) + _var(src, "FIX_TIER") + _var(src, "FIX_EFFORT")
    words = "\n".join(re.findall(r'"((?:[^"\\]|\\.)*)"', code))
    for rx in (_ENGINE, _ESTIMATE):
        hit = rx.search(words)
        assert not hit, hit and hit.group(0)
    hit = re.compile(r"[$€£]\s?\d|\b(usd|eur|gbp)\b", re.I).search(words)
    assert not hit, hit and hit.group(0)


def test_the_guide_walks_through_fix_first_with_the_screens_own_words():
    out = _guide()
    steps = {(ch["id"], st["id"]): st for ch in out["chapters"] for st in ch["steps"]}
    st = steps[("assess", "fixfirst")]
    assert (st["where"], st["route"]) == ("Fix first", "#/fix-first")
    # the step names the page switch the screen is served under — the very name the top bar reads (pageFlag)
    assert st["when"] == "posture"
    # it sits between reading the findings and confirming a fix: read them, fix the worst first, then confirm.
    # a later step (the attack-path story) may fall between fixing and the retest, so fixfirst need only land
    # immediately after findings and strictly before the confirm step.
    order = [s["id"] for ch in out["chapters"] if ch["id"] == "assess" for s in ch["steps"]]
    assert order.index("findings") + 1 == order.index("fixfirst")
    assert order.index("fixfirst") < order.index("retest")
    told = " ".join(st["clicks"])
    src = _src()
    # every control the step names is one the screen really shows
    for label in ("Fix first", "Retest", "How the score works", "Show the numbers"):
        assert label in told and f'"{label}"' in src, label
    assert 'navLink("Fix first", "#/fix-first")' in src and "not a certified rating" in st["why"]
    # the guide reaches the screen only through routeShown, which hides it while the flag is off (wiring test above)
    assert re.search(r'\(route !== "#/fix-first" \|\| POSTURE_ON\)', _fn(src, "routeShown"))


def test_the_sparkline_ink_is_chosen_per_theme():
    """The line's ink is a token chosen per theme (dark: --text-2, light: --text-1 — each validated to clear 3:1 on the
    card and to stay distinguishable from the accent end-dot), declared for BOTH light selectors tokens.css uses."""
    css = (APP / "app.css").read_text(encoding="utf-8")
    assert ".cust-posture-trend { --posture-spark: var(--text-2);" in css
    assert ':root[data-theme="light"] .cust-posture-trend { --posture-spark: var(--text-1); }' in css
    assert re.search(r'@media \(prefers-color-scheme: light\) \{\s*:root:not\(\[data-theme="dark"\]\) '
                     r'\.cust-posture-trend \{ --posture-spark: var\(--text-1\); \}', css)
    assert "stroke: var(--posture-spark)" in css and ".cust-posture-now { fill: var(--st-running)" in css
