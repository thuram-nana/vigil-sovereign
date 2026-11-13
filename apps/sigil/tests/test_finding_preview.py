"""S5a — the server-side partial-results projection for a trial-preview org.

Load-bearing invariants (each a mutation target):
  * LOCKED only when the preview flag is on AND the org holds `trial-preview:<org>` AND it is not unlocked;
    a legacy-trial, unlocked or flag-off org gets output deep-equal to today's;
  * completeness: every finding_ref is present, `count` is the true total, every row has title / severity /
    surface, a planted critical shows critical, an unknown class shows `unrated` and is never dropped;
  * the omitted keys are OMITTED (not null) on every locked row; no sentinel of a locked finding is returned;
  * exactly ONE reveal: the lowest spine seq over the EVER-proven slug set — a later, more severe finding, a
    severity-table edit, expiring and re-proving the host, or a failed first run never move or add one;
  * the FoldCache rows are never redacted in place; org A's unlock never unlocks org B.
"""
from __future__ import annotations

import itertools
import json
import tempfile

import pytest

from sigil.governor.asset_ownership import METHOD_DNS_TXT, AssetOwnershipRegistry
from sigil.governor.report_unlock import ReportUnlockRegistry
from sigil.governor.wallet import WalletRegistry
from sigil.spine.store import SpineStore
from sigil.ui import assessments as A
from sigil.ui import finding_preview as fp
from sigil.ui.target_authorization import _customer_slug

NOW = 1000.0
_FLAG = "VIGIL_TRIAL_PREVIEW_ENABLED"
_it = itertools.count(1)


@pytest.fixture(autouse=True)
def _owner(tmp_path, monkeypatch):
    from sigil import config
    monkeypatch.setenv("SIGIL_HOME", str(tmp_path))
    monkeypatch.setattr(config, "SPINE_PATH", tmp_path / "spine" / "spine.jsonl")
    from sigil.governor.identity import ensure_owner_keypair
    ensure_owner_keypair()


def _store():
    return SpineStore(tempfile.mktemp(suffix=".jsonl"))


def _prove(store, org, host, ttl=1e12):
    reg = AssetOwnershipRegistry(store)
    ch = reg.issue_challenge(org, host, issued_at=float(next(_it)))
    reg.verify_and_record(org, host, method=METHOD_DNS_TXT, observed=[ch.marker], now=10.0 + next(_it),
                          ttl_seconds=ttl)


def _finding(store, org, host, ref, **cert):
    c = {"engagement_slug": _customer_slug(org, host), "finding_ref": ref, "bug_class": "xss",
         "surface": "/q", "confidence": 0.9,
         "how_to_verify": f"SENTINEL-HTV-{ref}", "report_claims": [{"sentence": f"SENTINEL-RC-{ref}"}],
         "summary": f"SENTINEL-SUM-{ref}", "oracle_context_digest": f"SENTINEL-OCD-{ref}",
         "artifact_manifest": {"a": f"SENTINEL-AM-{ref}"}}
    c.update(cert)
    store.append(kind="finding", source="offense", actor="ORACLE",
                 payload={"certificate": c, "finding_ref": ref, "signatures": [{"key_id": "g", "signature_b64": "x"}]})


def _trial(store, org):
    WalletRegistry(store).grant(org, 100, "trial", entry_id=f"trial-preview:{org}", issued_at=float(next(_it)))


def _locked_read(store, org="org_a"):
    return A.assessment_findings(store, org, now=NOW, preview=fp.preview_locked(store, org), can_buy=True)


def _rig(n=3, *, trial=True):
    s = _store()
    _prove(s, "org_a", "a.example")
    for i in range(n):
        _finding(s, "org_a", "a.example", f"f{i}")
    if trial:
        _trial(s, "org_a")
    return s


# --- who is locked ----------------------------------------------------------------------------------------------

def test_flag_off_unlocked_and_legacy_orgs_are_byte_identical(monkeypatch):
    s = _rig()
    legacy = _store()
    _prove(legacy, "org_a", "a.example")
    _finding(legacy, "org_a", "a.example", "f0")
    WalletRegistry(legacy).grant("org_a", 100, "trial", entry_id="trial:org_a", issued_at=1.0)
    monkeypatch.delenv(_FLAG, raising=False)
    off = json.dumps(_locked_read(s), sort_keys=True)
    assert off == json.dumps(A.assessment_findings(s, "org_a", now=NOW), sort_keys=True)
    monkeypatch.setenv(_FLAG, "1")
    assert not fp.preview_locked(legacy, "org_a")
    assert fp.preview_locked(s, "org_a")
    ReportUnlockRegistry(s).unlock("org_a", "topup", source_ref="e1", issued_at=1.0)
    assert not fp.preview_locked(s, "org_a")
    assert json.dumps(_locked_read(s), sort_keys=True) == off


def test_an_owner_relock_relocks(monkeypatch):
    monkeypatch.setenv(_FLAG, "1")
    s = _rig()
    ReportUnlockRegistry(s).unlock("org_a", "topup", source_ref="e1", issued_at=1.0)
    ReportUnlockRegistry(s).owner_set("org_a", "relock", reason="chargeback", issued_at=2.0)
    assert fp.preview_locked(s, "org_a")


# --- completeness and redaction ---------------------------------------------------------------------------------

def test_locked_read_is_complete_and_omits_detail(monkeypatch):
    monkeypatch.setenv(_FLAG, "1")
    s = _rig(4)
    _finding(s, "org_a", "a.example", "crit", bug_class="rce")
    _finding(s, "org_a", "a.example", "odd", bug_class="never_heard_of_it")
    out = _locked_read(s)
    refs = {r["finding_ref"] for r in out["findings"]}
    assert refs == {"f0", "f1", "f2", "f3", "crit", "odd"} and out["count"] == 6
    assert out["preview"] == {"locked": True, "can_buy": True, "copy_key": "trial_preview"}
    locked = [r for r in out["findings"] if r["locked"]]
    assert len(locked) == 5 and sum(1 for r in out["findings"] if not r["locked"]) == 1
    for r in out["findings"]:
        assert r["title"] and r["severity"] and r["surface"] and r["host"] == "a.example"
    for r in locked:
        for k in fp.LOCKED_OMIT:
            assert k not in r, f"{k} must be omitted, not set"
        assert r["label"] == fp.LOCKED_LABEL
    by = {r["finding_ref"]: r for r in out["findings"]}
    assert by["crit"]["severity"] == "critical" and by["crit"]["severity_basis"] == "estimated"
    assert "class_guidance" in by["crit"]
    assert by["odd"]["severity"] == "unrated"
    blob = json.dumps(out)
    revealed = next(r["finding_ref"] for r in out["findings"] if not r["locked"])
    for ref in refs - {revealed}:
        assert f"SENTINEL-HTV-{ref}" not in blob and f"SENTINEL-SUM-{ref}" not in blob
        assert f"SENTINEL-RC-{ref}" not in blob and f"SENTINEL-OCD-{ref}" not in blob
        assert f"SENTINEL-AM-{ref}" not in blob
    assert f"SENTINEL-HTV-{revealed}" in blob


def test_pagination_happens_after_the_projection(monkeypatch):
    monkeypatch.setenv(_FLAG, "1")
    s = _rig(5)
    out = A.assessment_findings(s, "org_a", now=NOW, limit=2, preview=True)
    assert out["count"] == 5 and len(out["findings"]) == 2
    assert all("how_to_verify" not in r for r in out["findings"] if r["locked"])


def test_certificate_severity_is_used_when_present():
    sev, basis = fp.derived_severity({"severity": "Low", "bug_class": "rce"})
    assert (sev, basis) == ("low", "certificate")


def test_under_rating_control_every_table_class_at_least_medium_unless_benign():
    benign = {"open_redirect", "graphql_introspection", "weak_tls", "weak_crypto_artifact",
              "static_broken_crypto", "service_reachable", "probe"}
    for cls, sev in fp.CLASS_SEVERITY.items():
        if cls not in benign:
            assert sev in ("critical", "high"), cls


# --- the one pinned reveal --------------------------------------------------------------------------------------

def _revealed(out):
    return [r["finding_ref"] for r in out["findings"] if not r["locked"]]


def test_the_reveal_is_the_lowest_seq_and_a_later_critical_does_not_move_it(monkeypatch):
    monkeypatch.setenv(_FLAG, "1")
    s = _rig(2)
    assert _revealed(_locked_read(s)) == ["f0"]
    _finding(s, "org_a", "a.example", "boom", bug_class="rce")
    assert _revealed(_locked_read(s)) == ["f0"]


def test_editing_the_severity_table_does_not_move_the_reveal(monkeypatch):
    monkeypatch.setenv(_FLAG, "1")
    s = _rig(3)
    monkeypatch.setitem(fp.CLASS_SEVERITY, "xss", "info")
    assert _revealed(_locked_read(s)) == ["f0"]


def test_expiring_and_reproving_the_host_gives_no_second_reveal(monkeypatch):
    monkeypatch.setenv(_FLAG, "1")
    s = _store()
    _prove(s, "org_a", "a.example")
    _finding(s, "org_a", "a.example", "old")
    AssetOwnershipRegistry(s).revoke_proof("org_a", "a.example")
    _prove(s, "org_a", "a.example")
    _finding(s, "org_a", "a.example", "new")
    _trial(s, "org_a")
    assert _revealed(_locked_read(s)) == ["old"]


def test_an_outcome_first_and_no_findings_consume_nothing(monkeypatch):
    monkeypatch.setenv(_FLAG, "1")
    s = _store()
    _prove(s, "org_a", "a.example")
    s.append(kind="assessment_outcome", source="settle", actor="X",
             payload={"engagement_slug": _customer_slug("org_a", "a.example"), "outcome": "failed"})
    _trial(s, "org_a")
    assert _locked_read(s)["findings"] == []
    _finding(s, "org_a", "a.example", "first")
    _finding(s, "org_a", "a.example", "second")
    assert _revealed(_locked_read(s)) == ["first"]


# --- isolation and cache safety ---------------------------------------------------------------------------------

def test_tenant_isolation_and_cache_rows_untouched(monkeypatch):
    monkeypatch.setenv(_FLAG, "1")
    monkeypatch.setenv("VIGIL_FOLD_CACHE_ENABLED", "1")
    s = _rig(3)
    _prove(s, "org_b", "b.example")
    _finding(s, "org_b", "b.example", "b0")
    _trial(s, "org_b")
    ReportUnlockRegistry(s).unlock("org_a", "topup", source_ref="e1", issued_at=1.0)
    assert not fp.preview_locked(s, "org_a") and fp.preview_locked(s, "org_b")
    full_before = A.assessment_findings(s, "org_b", now=NOW)
    locked = _locked_read(s, "org_b")
    assert all(r["locked"] is False for r in locked["findings"])      # one finding: it is the reveal
    _finding(s, "org_b", "b.example", "b1")
    locked = _locked_read(s, "org_b")
    assert sum(r["locked"] for r in locked["findings"]) == 1
    full_after = A.assessment_findings(s, "org_b", now=NOW)
    assert all("how_to_verify" in r for r in full_after["findings"]), "the cached rows were redacted in place"
    assert full_before["findings"][0]["how_to_verify"] == "SENTINEL-HTV-b0"


def test_summary_teaser_counts_by_severity_only_when_locked(monkeypatch):
    monkeypatch.setenv(_FLAG, "1")
    s = _rig(2)
    _finding(s, "org_a", "a.example", "crit", bug_class="rce")
    plain = A.assessment_summary(s, "org_a", now=NOW)
    assert "preview" not in plain and "severity" not in plain["assessments"][0]
    teaser = A.assessment_summary(s, "org_a", now=NOW, preview=True)
    assert teaser["preview"] is True
    assert teaser["assessments"][0]["severity"]["critical"] == 1
    assert teaser["assessments"][0]["severity"]["high"] == 2


@pytest.mark.parametrize("cache", ["1", ""])
def test_ever_proven_hosts_ignores_an_unsigned_revoke_of_a_never_proven_pair(monkeypatch, cache):
    monkeypatch.setenv("VIGIL_FOLD_CACHE_ENABLED", cache)
    s = _store()
    _prove(s, "org_a", "a.example")
    s.append(kind="event", source="governor", actor="X",
             payload={"signal": "governor.asset_ownership_proof", "org_id": "org_a", "host": "ghost.example",
                      "state": "revoked"})
    assert AssetOwnershipRegistry(s).ever_proven_hosts("org_a") == ["a.example"]


def test_the_provisioner_read_applies_the_preview_server_side(monkeypatch):
    from sigil.governor.customers import CustomerRegistry
    from sigil.governor.orgs import OrgRegistry
    from sigil.ui.email_channel import EmailTokenLedger, NullEmailSender
    from sigil.ui.login_ratelimit import LoginRateLimiter
    from sigil.ui.provision import Provisioner
    monkeypatch.setenv(_FLAG, "1")
    s = _rig(3)
    orgs = OrgRegistry(s)
    orgs.create_org("org_a", "A", owner="owner", issued_at=float(next(_it)))
    orgs.grant_membership("org_a", "ana", "operator", issued_at=float(next(_it)))
    p = Provisioner(s, customers=CustomerRegistry(s), orgs=orgs, wallet=WalletRegistry(s),
                    email_tokens=EmailTokenLedger(tempfile.mkdtemp(), ttl_s=1e4),
                    rate_limiter=LoginRateLimiter(tempfile.mkdtemp(), max_fails=50, window_s=1e4, base_lock_s=50.0),
                    email_sender=NullEmailSender(), trial_credits=100, now_fn=lambda: NOW)
    out = p.customer_assessment_findings("ana", "org_a")
    assert out["preview"]["locked"] and out["preview"]["can_buy"] is False      # operator: no manage_billing
    assert sum(1 for r in out["findings"] if not r["locked"]) == 1
    assert p.customer_assessments("ana", "org_a")["preview"] is True
    ReportUnlockRegistry(s).unlock("org_a", "topup", source_ref="e1", issued_at=1.0)
    full = p.customer_assessment_findings("ana", "org_a")
    assert "preview" not in full and all("how_to_verify" in r for r in full["findings"])


def test_a_reveal_spent_on_a_lapsed_host_is_not_spent_again(monkeypatch):
    """The reveal is chosen over EVER-proven hosts: a finding on a host whose proof has since lapsed keeps the
    reveal, so the findings on the org's current hosts all stay locked."""
    monkeypatch.setenv(_FLAG, "1")
    s = _store()
    _prove(s, "org_a", "old.example")
    _finding(s, "org_a", "old.example", "spent")
    AssetOwnershipRegistry(s).revoke_proof("org_a", "old.example")
    _prove(s, "org_a", "new.example")
    _finding(s, "org_a", "new.example", "n0")
    _finding(s, "org_a", "new.example", "n1")
    _trial(s, "org_a")
    out = _locked_read(s)
    assert {r["finding_ref"] for r in out["findings"]} == {"n0", "n1"}
    assert _revealed(out) == []


def test_findings_sharing_a_finding_ref_get_exactly_one_reveal(monkeypatch):
    """finding_ref is not unique (a check id or class): the reveal is pinned to one record, so every other
    finding that shares its ref stays locked — within one host and across hosts."""
    monkeypatch.setenv(_FLAG, "1")
    s = _store()
    _prove(s, "org_a", "a.example")
    _prove(s, "org_a", "b.example")
    s_ref = "xss"
    for host, surface in (("a.example", "/q"), ("a.example", "/admin"), ("b.example", "/x")):
        c = {"engagement_slug": _customer_slug("org_a", host), "finding_ref": s_ref, "bug_class": "xss",
             "surface": surface, "confidence": 0.9, "how_to_verify": f"SECRET-{host}-{surface}",
             "summary": f"SUM-{host}-{surface}"}
        s.append(kind="finding", source="offense", actor="ORACLE",
                 payload={"certificate": c, "finding_ref": s_ref, "signatures": []})
    _trial(s, "org_a")
    out = _locked_read(s)
    assert out["count"] == 3
    unlocked = [r for r in out["findings"] if not r["locked"]]
    assert len(unlocked) == 1 and unlocked[0]["surface"] == "/q"
    blob = json.dumps(out)
    assert "SECRET-a.example-/admin" not in blob and "SECRET-b.example-/x" not in blob
