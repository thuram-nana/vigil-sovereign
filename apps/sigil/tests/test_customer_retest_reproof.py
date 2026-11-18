"""C1b completion — the SOVEREIGN half of the LIVE retest re-proof (behind VIGIL_CUSTOMER_RETEST_REPROOF).

What this pins (the sovereign plane only — the keyless offense worker is its own suite,
``integration/tests/test_retest_reproof.py``; here a ``drive`` seam simulates it by writing a valid outcome):

  * FLAG: with the re-proof flag OFF (UI on), ``retest`` without an injected reverify is BYTE-IDENTICAL to the
    merged stub — it refuses "not available", writes NO ticket, reserves NO credit, records nothing.
  * THE REAL PATH (flag ON): ``retest`` RESERVES an owner-signed lease, PUBLISHES an owner-signed ticket carrying
    the finding identity + the lease, BOUNDED-WAITS the offense worker's inert outcome, SETTLES the lease, and
    maps the verdict with its EXISTING mapping (cleared->fixed, still_present->still_vulnerable, else->refused).
  * METERING: the lease is settled to ZERO consumption — a full refund — whatever the verdict or a timeout, so the
    wallet net delta is 0 (a model-free re-fire never charges), but the re-proof always ran under a reserved lease.
  * SILENCE != FIXED: a bounded-wait timeout (no outcome) and an inconclusive outcome both refuse with the finding
    UNCHANGED; an outcome whose identity does not match the issued ticket is ignored (never drives the mapping).
  * The merged refusals (IDOR, lapsed proof, step-up, trial-lock, flag-UI-off) still hold BEFORE the re-proof.

Runs with the integration PYTHONPATH (the seam lives across it), mirroring test_customer_retest_ui.
"""
from __future__ import annotations

import itertools
import json
import tempfile
from pathlib import Path

import pytest
from test_custui import _scrub_shared_owner_state  # noqa: F401  (autouse: keep shared SIGIL_HOME owner state pristine)

_iss = itertools.count(1)
_NOW = 2500.0


@pytest.fixture(autouse=True)
def _iso(monkeypatch):
    monkeypatch.setenv("VIGIL_BASE_DIR", tempfile.mkdtemp())
    monkeypatch.setenv("SIGIL_SPINE_DIR", tempfile.mkdtemp())
    monkeypatch.setenv("SIGIL_HOME", tempfile.mkdtemp())
    monkeypatch.setenv("VIGIL_CUSTOMER_RETEST_UI", "1")
    monkeypatch.setenv("VIGIL_CUSTOMER_RETEST_REPROOF", "1")
    for v in ("VIGIL_CUSTOMER_STEPUP_REQUIRED", "VIGIL_METERED_BILLING", "VIGIL_TRIAL_PREVIEW_ENABLED"):
        monkeypatch.delenv(v, raising=False)


def _store():
    from sigil.spine.store import SpineStore
    return SpineStore(tempfile.mktemp(suffix=".jsonl"))


def _setup(store, org, host, *, role="operator", credits=1000, now=1000.0, ttl=1e12):
    from sigil.governor.asset_ownership import METHOD_DNS_TXT, AssetOwnershipRegistry
    from sigil.governor.identity import ensure_owner_keypair
    from sigil.governor.orgs import OrgRegistry
    from sigil.governor.wallet import WalletRegistry
    from sigil.ui.target_authorization import add_customer_target
    ensure_owner_keypair()
    orgs = OrgRegistry(store)
    if orgs.org(org) is None:
        orgs.create_org(org, org, owner="u", issued_at=float(next(_iss)))
    orgs.grant_membership(org, "u", role, issued_at=float(next(_iss)))
    WalletRegistry(store).grant(org, credits, "trial", entry_id=f"trial:{org}:{next(_iss)}", issued_at=float(next(_iss)))
    reg = AssetOwnershipRegistry(store)
    ch = reg.issue_challenge(org, host, issued_at=float(next(_iss)))
    reg.verify_and_record(org, host, method=METHOD_DNS_TXT, observed=[ch.marker], now=now, ttl_seconds=ttl)
    assert add_customer_target(host, org_id=org, store=store, now=now)["ok"]


def _finding(store, org, host, ref, **cert):
    from sigil.ui.target_authorization import _customer_slug
    slug = _customer_slug(org, host)
    c = {"engagement_slug": slug, "finding_ref": ref, "bug_class": cert.get("bug_class", "xss"),
         "surface": cert.get("surface", "https://x/" + ref), "confidence": "high", "severity": "high",
         "oracle_context_digest": cert.get("digest", "d-" + ref)}
    store.append(kind="finding", source="offense", actor="ORACLE",
                 payload={"certificate": c, "finding_ref": ref,
                          "signatures": [{"key_id": "gov", "signature_b64": "x"}]})
    return slug


def _prov(store):
    from sigil.ui.provision import build_provisioner
    return build_provisioner(store)


def _ident(org, host, ref):
    from sigil.ui.target_authorization import _customer_slug
    return {"engagement_slug": _customer_slug(org, host), "oracle_context_digest": "d-" + ref}


def _balance(store, org):
    from sigil.ui.launch_gate import LaunchGate
    return LaunchGate(store).meter.available(org, _NOW)


def _seam_base():
    from vigil_core.seam_base import resolve_seam_base
    return resolve_seam_base(None)


def _ticket_dir():
    from vigil_core import RETEST_REPROOF_SEAM_SUBDIR
    return Path(_seam_base()) / RETEST_REPROOF_SEAM_SUBDIR


def _tickets():
    d = _ticket_dir()
    return [json.loads(p.read_text()) for p in sorted(d.glob("*.json"))] if d.is_dir() else []


def _driver(verdict):
    """A test ``drive`` seam standing in for the keyless offense worker: read the ticket the sovereign just
    published and write a MATCHING outcome with ``verdict`` (the real offense trigger + outcome writer are
    exercised; only the framework-dependent worker body is replaced). ``verdict=None`` writes nothing (a
    timeout)."""
    def _drive(base):
        if verdict is None:
            return
        from vigil_integration.jobs.retest_reproof import _write_outcome, retest_reproof_jobs_from_seam
        from vigil_core import retest_reproof_outcome
        for job in retest_reproof_jobs_from_seam(base):
            ex = job.extra
            _write_outcome(base, retest_reproof_outcome(
                slug=job.slug, finding_ref=ex["finding_ref"], nonce=ex["nonce"], verdict=verdict,
                oracle_context_digest=ex.get("oracle_context_digest", ""), reason="test", consumed_mc=0))
    return _drive


def _mismatched_driver(base):
    """Write an outcome for a DIFFERENT finding/nonce than the issued ticket — the sovereign must ignore it."""
    from vigil_integration.jobs.retest_reproof import _write_outcome, retest_reproof_jobs_from_seam
    from vigil_core import retest_reproof_outcome
    for job in retest_reproof_jobs_from_seam(base):
        # correct nonce file name so the reader finds A file, but wrong finding_ref -> identity mismatch
        _write_outcome(base, retest_reproof_outcome(
            slug=job.slug, finding_ref="SOMEONE-ELSE", nonce=job.extra["nonce"], verdict="cleared"))


# a thin wrapper so the signature stays readable: provision.retest takes _drive_reproof / _reproof_wait
def _run(st, org, host, ref, *, verdict="cleared", wait=(2.0, 0.01), **kw):
    kw.setdefault("now", _NOW)
    return _prov(st).retest("u", org, ref, _drive_reproof=_driver(verdict), _reproof_wait=wait,
                            **{**_ident(org, host, ref), **kw})


# --------------------------------------------------------------------------- the real re-proof path ----
def test_a_cleared_outcome_marks_fixed_records_and_refunds_in_full():
    st = _store()
    _setup(st, "org_a", "apme.cm")
    _finding(st, "org_a", "apme.cm", "F1")
    before = _balance(st, "org_a")
    r = _run(st, "org_a", "apme.cm", "F1", verdict="cleared")
    assert r == {"finding_ref": "F1", "host": "apme.cm", "status": "fixed"}
    # a signed finding_retest record exists and the findings read overlays it
    assert [rec.kind for rec in st.iter_records() if getattr(rec, "kind", None) == "finding_retest"] == ["finding_retest"]
    out = _prov(st).customer_assessment_findings("u", "org_a")
    assert next(x for x in out["findings"] if x["finding_ref"] == "F1")["retest"]["status"] == "fixed"
    # METERED: a ticket carrying the owner-signed lease was published, and the lease settled to a FULL refund
    tks = _tickets()
    assert len(tks) == 1 and tks[0]["finding_ref"] == "F1" and tks[0]["host"] == "apme.cm"
    assert tks[0]["org_id"] == "org_a" and isinstance(tks[0]["lease"], dict) and tks[0]["lease"].get("document")
    assert _balance(st, "org_a") == before                      # reserve 200 then refund 200 -> net 0


def test_a_still_present_outcome_marks_still_vulnerable():
    st = _store()
    _setup(st, "org_a", "apme.cm")
    _finding(st, "org_a", "apme.cm", "F1")
    r = _run(st, "org_a", "apme.cm", "F1", verdict="still_present")
    assert r["status"] == "still_vulnerable"
    out = _prov(st).customer_assessment_findings("u", "org_a")
    assert next(x for x in out["findings"] if x["finding_ref"] == "F1")["retest"]["status"] == "still_vulnerable"


def test_an_inconclusive_outcome_refuses_unchanged_and_refunds():
    from sigil.ui.provision import ProvisionDenied
    st = _store()
    _setup(st, "org_a", "apme.cm")
    _finding(st, "org_a", "apme.cm", "F1")
    before = _balance(st, "org_a")
    with pytest.raises(ProvisionDenied) as e:
        _run(st, "org_a", "apme.cm", "F1", verdict="inconclusive")
    assert "could not confirm" in str(e.value)
    assert [r for r in st.iter_records() if getattr(r, "kind", None) == "finding_retest"] == []
    assert _balance(st, "org_a") == before                      # refunded in full even on a refusal


def test_a_timeout_with_no_outcome_refuses_unavailable_and_refunds():
    # silence is NEVER a fix: the offense worker never wrote an outcome -> bounded-wait times out -> "unavailable"
    from sigil.ui.provision import ProvisionDenied
    st = _store()
    _setup(st, "org_a", "apme.cm")
    _finding(st, "org_a", "apme.cm", "F1")
    before = _balance(st, "org_a")
    with pytest.raises(ProvisionDenied) as e:
        _run(st, "org_a", "apme.cm", "F1", verdict=None, wait=(0.15, 0.01))   # drive writes nothing
    assert "not available" in str(e.value) and "could not confirm" not in str(e.value)
    assert [r for r in st.iter_records() if getattr(r, "kind", None) == "finding_retest"] == []
    assert _balance(st, "org_a") == before                      # the held reservation is released, never stranded


def test_an_outcome_for_another_finding_is_ignored():
    # an outcome whose identity does not match the issued ticket never drives the mapping -> timeout -> unavailable
    from sigil.ui.provision import ProvisionDenied
    st = _store()
    _setup(st, "org_a", "apme.cm")
    _finding(st, "org_a", "apme.cm", "F1")
    with pytest.raises(ProvisionDenied) as e:
        _prov(st).retest("u", "org_a", "F1", now=_NOW, _drive_reproof=_mismatched_driver,
                         _reproof_wait=(0.15, 0.01), **_ident("org_a", "apme.cm", "F1"))
    assert "not available" in str(e.value)
    assert [r for r in st.iter_records() if getattr(r, "kind", None) == "finding_retest"] == []


def test_too_few_credits_refuses_the_reserve_and_writes_no_ticket():
    from sigil.ui.provision import ProvisionDenied
    st = _store()
    _setup(st, "org_a", "apme.cm", credits=10)                   # below the 200-credit retest reservation
    _finding(st, "org_a", "apme.cm", "F1")
    with pytest.raises(ProvisionDenied) as e:
        _run(st, "org_a", "apme.cm", "F1", verdict="cleared")
    assert "credit" in str(e.value).lower()
    assert _tickets() == []                                      # nothing published, nothing reserved
    assert [r for r in st.iter_records() if getattr(r, "kind", None) == "finding_retest"] == []


def test_the_published_ticket_names_the_exact_finding_and_carries_the_lease():
    st = _store()
    _setup(st, "org_a", "apme.cm")
    _finding(st, "org_a", "apme.cm", "xss", digest="d-two", surface="https://apme.cm/b", bug_class="sqli")
    captured = {}

    def _spy(base):
        captured["tickets"] = _tickets()
    with pytest.raises(Exception):      # noqa: B017 — no outcome -> times out -> refuses; we only want the ticket
        _prov(st).retest("u", "org_a", "xss", now=_NOW, _drive_reproof=_spy, _reproof_wait=(0.05, 0.01),
                         engagement_slug=_ident("org_a", "apme.cm", "xss")["engagement_slug"],
                         oracle_context_digest="d-two")
    t = captured["tickets"][0]
    assert t["finding_ref"] == "xss" and t["oracle_context_digest"] == "d-two" and t["bug_class"] == "sqli"
    assert t["host"] == "apme.cm" and t["nonce"] == t["lease"]["document"]["nonce"]   # ticket nonce == lease nonce


# --------------------------------------------------------------------------- flag off = byte-identical stub ----
def test_reproof_flag_off_refuses_unavailable_writes_no_ticket_reserves_nothing(monkeypatch):
    from sigil.ui.provision import ProvisionDenied, _retest_reverify
    monkeypatch.setenv("VIGIL_CUSTOMER_RETEST_REPROOF", "0")      # UI on, re-proof OFF: the merged stub
    assert _retest_reverify({"host": "x"}) == "unavailable"
    st = _store()
    _setup(st, "org_a", "apme.cm")
    _finding(st, "org_a", "apme.cm", "F1")
    before = _balance(st, "org_a")
    with pytest.raises(ProvisionDenied) as e:                     # no reverify injected -> stub -> "not available"
        _prov(st).retest("u", "org_a", "F1", now=_NOW, **_ident("org_a", "apme.cm", "F1"))
    assert "not available" in str(e.value) and "could not confirm" not in str(e.value)
    assert _tickets() == [] and _balance(st, "org_a") == before   # NO ticket, NO reserve (byte-identical)
    assert [r for r in st.iter_records() if getattr(r, "kind", None) == "finding_retest"] == []


def test_an_injected_reverify_bypasses_the_reproof_path_entirely():
    # a caller passing reverify= is used verbatim: no ticket, no reserve (the direct-seam / test path)
    st = _store()
    _setup(st, "org_a", "apme.cm", credits=10)                   # too few for a reserve -> proves no reserve happens
    _finding(st, "org_a", "apme.cm", "F1")
    before = _balance(st, "org_a")
    r = _prov(st).retest("u", "org_a", "F1", now=_NOW, reverify=lambda ctx: "cleared",
                         **_ident("org_a", "apme.cm", "F1"))
    assert r["status"] == "fixed" and _tickets() == [] and _balance(st, "org_a") == before


# --------------------------------------------------------------------------- merged refusals still hold ----
def test_idor_cross_tenant_is_refused_before_any_reserve_or_ticket():
    from sigil.ui.provision import ProvisionDenied
    st = _store()
    _setup(st, "org_a", "apme.cm")
    _setup(st, "org_b", "bbb.cm")
    _finding(st, "org_a", "apme.cm", "FA")
    _finding(st, "org_b", "bbb.cm", "FB")
    with pytest.raises(ProvisionDenied) as e:
        _prov(st).retest("u", "org_a", "FB", now=_NOW, _drive_reproof=_driver("cleared"), _reproof_wait=(0.1, 0.01),
                         **_ident("org_b", "bbb.cm", "FB"))
    assert "no such finding" in str(e.value)
    assert _tickets() == []                                      # refused before the re-proof ever reserved/published


def test_a_lapsed_ownership_proof_refuses_before_the_reproof():
    from sigil.ui.provision import ProvisionDenied
    st = _store()
    _setup(st, "org_a", "apme.cm", now=1000.0, ttl=100.0)        # proof lapsed by now=2500
    _finding(st, "org_a", "apme.cm", "F1")
    with pytest.raises(ProvisionDenied) as e:
        _run(st, "org_a", "apme.cm", "F1", verdict="cleared")
    assert "ownership proof" in str(e.value) and _tickets() == []


def test_step_up_is_enforced_before_the_reproof(monkeypatch):
    from sigil.ui.provision import ProvisionStepUpRequired
    monkeypatch.setenv("VIGIL_CUSTOMER_STEPUP_REQUIRED", "1")
    st = _store()
    _setup(st, "org_a", "apme.cm")
    _finding(st, "org_a", "apme.cm", "F1")
    with pytest.raises(ProvisionStepUpRequired):
        _run(st, "org_a", "apme.cm", "F1", verdict="cleared", mfa_at=0.0)
    assert _tickets() == []                                      # a stale step-up never reaches the re-proof
    r = _run(st, "org_a", "apme.cm", "F1", verdict="cleared", mfa_at=_NOW - 1.0)
    assert r["status"] == "fixed"
