"""Consumer Area 10 / PR-K — the one-click "Fix it for me" DISPATCH (``VIGIL_CUSTOMER_FIX_IT``).

The offense Fix worker (``vigil_integration.jobs.redpen_fix``), the gated fix-PR executor, the PCR ladder and the
sovereign dispatch (``sigil.ui.redpen_provision.redpen_fix_this``) are already built + tested. PR-K is the thin,
flag-gated wire that turns the customer "Fix this" button from an inert ``coming`` answer into a real dispatch:
reserve/meter the fix against the wallet and publish a validated marker to the dedicated ``redpen-actions`` seam,
behind the WHOLE guard chain that was already there (flag + ``manage_code`` admit + E3c step-up + an active
owner-signed connected-repo record). Nothing here mints a FACT or asserts a clearance — a clearance is the signed
NEGATIVE remediation cert the independent verification path earns, which is surfaced separately (APEX-3 / PR-I).

Default-OFF: with ``VIGIL_CUSTOMER_FIX_IT`` unset the action is byte-identical to the inert ``coming`` answer and
the overview advertises ``fix`` as unavailable — verified here and in ``test_customer_code_screen`` (the whole
file runs with the dispatch off, so every existing ``coming`` assertion is the flag-off golden).

Mutation-verify (each neuter reds a NAMED test here):
  * the dispatch gate always dispatches (ignores ``customer_fix_it_enabled``)
                                                 -> test_flag_off_fix_is_byte_identical_coming
  * the dispatch never fires when the flag is on -> test_flag_on_fix_dispatches_reserves_and_publishes
  * the overview advertises ``fix`` with the flag off / hides it with the flag on
                                                 -> test_overview_advertises_fix_only_when_the_flag_is_on
  * the dispatch skips the ``manage_code`` admit -> test_fix_dispatch_requires_manage_code
  * the dispatch skips the step-up               -> test_fix_dispatch_takes_the_step_up_before_reserving
  * the dispatch ignores the connected-repo record / the wallet floor
                                                 -> test_fix_dispatch_refused_when_not_connected,
                                                    test_fix_dispatch_refused_when_credits_are_short
  * the dispatch runs with the master flag off   -> test_fix_dispatch_fails_closed_when_the_master_flag_is_off
  * the customer-facing payload names a model / price / units
                                                 -> test_fix_dispatch_names_no_model_price_or_units
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from vigil_core import REDPEN_ACTION_SEAM_SUBDIR, redpen_action_marker

from sigil import config
from sigil.governor.connected_repos import ConnectedRepoRegistry
from sigil.ui.provision import ProvisionDenied, ProvisionError, ProvisionStepUpRequired

from test_customer_code_screen import _LEAK, _audits, _connect, _prov, _records, API_REPO

_FIX_IT = "VIGIL_CUSTOMER_FIX_IT"
_STEPUP = "VIGIL_CUSTOMER_STEPUP_REQUIRED"


@pytest.fixture
def prov(tmp_path, monkeypatch):
    """The real Code-screen Provisioner (``_prov`` sets ``VIGIL_REDPEN_ENABLED`` + the founder-tester flag), with
    the seam base + model-meter dir under tmp and org_a's wallet funded so a fix can reserve. ``VIGIL_CUSTOMER_FIX_IT``
    is left OFF — each dispatch test turns it on, so an untouched test is on the inert path by construction."""
    monkeypatch.setenv("VIGIL_BASE_DIR", str(tmp_path / "seam"))
    monkeypatch.setattr(config, "MODEL_METER_DIR", tmp_path / "meter")
    monkeypatch.delenv(_FIX_IT, raising=False)
    monkeypatch.delenv(_STEPUP, raising=False)
    p, s = _prov(tmp_path / "prov", monkeypatch)
    p.wallet.grant("org_a", 1_000, "trial", entry_id="trial:1", issued_at=p._next_issued())
    return p, s


def _markers(tmp_path) -> list:
    seam = Path(str(tmp_path)) / "seam" / REDPEN_ACTION_SEAM_SUBDIR
    return [json.loads(p.read_text()) for p in sorted(seam.glob("*.json"))] if seam.is_dir() else []


# ---- default OFF: byte-identical to the inert "coming" answer ---------------------------------------


def test_flag_off_fix_is_byte_identical_coming(prov, tmp_path):
    p, s = prov
    _connect(p, "org_a", API_REPO)
    before = p.wallet.available("org_a")
    n = _records(s)
    assert p.redpen_fix_this("cust_fo", "org_a", API_REPO, "f1") == {
        "org_id": "org_a", "repo": API_REPO, "finding_ref": "f1", "coming": True}
    assert p.wallet.available("org_a") == before          # nothing reserved
    assert _records(s) == n                               # nothing enqueued, charged or audited
    assert _markers(tmp_path) == []                       # nothing published; the seam dir is never created
    assert not (Path(str(tmp_path)) / "seam" / REDPEN_ACTION_SEAM_SUBDIR).exists()


def test_overview_advertises_fix_only_when_the_flag_is_on(prov, monkeypatch):
    p, _s = prov
    _connect(p, "org_a", API_REPO)
    off = p.redpen_code_overview("cust_fo", "org_a")["available"]
    assert off == {"connect": False, "review": False, "schedule": False, "fix": False, "retest": False}
    monkeypatch.setenv(_FIX_IT, "1")
    on = p.redpen_code_overview("cust_fo", "org_a")["available"]
    # fix becomes available; retest/review/schedule stay with their own (unbuilt-here) workers — honest
    assert on == {"connect": False, "review": False, "schedule": False, "fix": True, "retest": False}


# ---- flag ON: the real dispatch ---------------------------------------------------------------------


def test_flag_on_fix_dispatches_reserves_and_publishes(prov, tmp_path, monkeypatch):
    p, s = prov
    monkeypatch.setenv(_FIX_IT, "1")
    _connect(p, "org_a", API_REPO)
    before = p.wallet.available("org_a")
    out = p.redpen_fix_this("cust_fo", "org_a", API_REPO, "f1")
    assert out == {"org_id": "org_a", "repo": API_REPO, "finding_ref": "f1", "dispatched": True}
    assert "coming" not in out                            # the UI shows the "preparing a fix" done-copy, not "coming"
    assert p.wallet.available("org_a") < before           # credits are held for the fix (metered, no estimate)
    markers = _markers(tmp_path)
    assert len(markers) == 1 and markers[0]["redpen_action"] == "fix" and markers[0]["finding_ref"] == "f1"
    assert any(a["outcome"] == "dispatched" and a["action"] == "redpen_fix_this" for a in _audits(s, "redpen_fix_this"))


def test_the_published_marker_matches_the_shared_wire_contract(prov, tmp_path, monkeypatch):
    """The marker the sovereign publishes is byte-identical to the shared ``vigil_core.redpen_action`` contract
    the keyless offense trigger parses — so the two planes agree and a fix names EXACTLY one finding."""
    p, _s = prov
    monkeypatch.setenv(_FIX_IT, "1")
    _connect(p, "org_a", API_REPO)
    p.redpen_fix_this("cust_fo", "org_a", API_REPO, "finding-xyz")
    m = _markers(tmp_path)[0]
    expected = redpen_action_marker(action="fix", slug=m["slug"], repo=m["repo"], nonce=m["nonce"],
                                    finding_ref="finding-xyz")
    assert m == expected
    assert m["finding_ref"] == "finding-xyz" and "finding_refs" not in m   # exactly one finding


def test_fix_dispatch_names_no_model_price_or_units(prov, tmp_path, monkeypatch):
    """The customer-facing dispatch payload and the published marker carry no model name, price, estimate or credit
    count (the Code screen's own leak probe) — the reservation is metered sovereign-side, never surfaced."""
    p, _s = prov
    monkeypatch.setenv(_FIX_IT, "1")
    _connect(p, "org_a", API_REPO)
    out = p.redpen_fix_this("cust_fo", "org_a", API_REPO, "f1")
    blob = json.dumps(out) + "\n" + json.dumps(_markers(tmp_path))
    assert not _LEAK.search(blob), _LEAK.search(blob)


# ---- flag ON: every guard still holds (no bypass) ---------------------------------------------------


def test_fix_dispatch_requires_manage_code(prov, tmp_path, monkeypatch):
    p, s = prov
    monkeypatch.setenv(_FIX_IT, "1")
    _connect(p, "org_a", API_REPO)
    before = p.wallet.available("org_a")
    for who in ("cust_ad", "cust_an", "cust_vi", "cust_bb", "cust_nobody"):   # billing admin / analyst / viewer / other org / stranger
        with pytest.raises(ProvisionDenied):
            p.redpen_fix_this(who, "org_a", API_REPO, "f1")
    assert p.wallet.available("org_a") == before and _markers(tmp_path) == []


def test_fix_dispatch_takes_the_step_up_before_reserving(prov, tmp_path, monkeypatch):
    p, _s = prov
    monkeypatch.setenv(_FIX_IT, "1")
    monkeypatch.setenv(_STEPUP, "1")
    _connect(p, "org_a", API_REPO)
    before = p.wallet.available("org_a")
    with pytest.raises(ProvisionStepUpRequired):                     # no fresh factor
        p.redpen_fix_this("cust_fo", "org_a", API_REPO, "f1", mfa_at=0.0)
    with pytest.raises(ProvisionStepUpRequired):                     # a stale factor
        p.redpen_fix_this("cust_fo", "org_a", API_REPO, "f1", mfa_at=p._now() - 3600.0)
    with pytest.raises(ProvisionDenied) as e:                        # authority FIRST: a viewer is denied, never "step up"
        p.redpen_fix_this("cust_vi", "org_a", API_REPO, "f1", mfa_at=0.0)
    assert not isinstance(e.value, ProvisionStepUpRequired)
    assert p.wallet.available("org_a") == before and _markers(tmp_path) == []   # nothing held/published on any refusal
    out = p.redpen_fix_this("cust_fo", "org_a", API_REPO, "f1", mfa_at=p._now())   # a fresh factor dispatches
    assert out["dispatched"] is True and p.wallet.available("org_a") < before


def test_fix_dispatch_refused_when_not_connected(prov, tmp_path, monkeypatch):
    p, _s = prov
    monkeypatch.setenv(_FIX_IT, "1")
    _connect(p, "org_a", API_REPO)
    ConnectedRepoRegistry(p.store).disconnect("org_a", API_REPO)
    before = p.wallet.available("org_a")
    with pytest.raises(ProvisionDenied):
        p.redpen_fix_this("cust_fo", "org_a", API_REPO, "f1")
    assert p.wallet.available("org_a") == before and _markers(tmp_path) == []


def test_fix_dispatch_refused_when_credits_are_short(prov, tmp_path, monkeypatch):
    """org_b's founder has manage_code and a connected repository but NO funded wallet — the reservation is the
    wallet floor, so the fix is refused and nothing is published."""
    p, _s = prov
    monkeypatch.setenv(_FIX_IT, "1")
    _connect(p, "org_b", "github.com/beta/secret")
    with pytest.raises(ProvisionDenied):
        p.redpen_fix_this("cust_bb", "org_b", "github.com/beta/secret", "f1")
    assert _markers(tmp_path) == []


def test_fix_dispatch_fails_closed_when_the_master_flag_is_off(prov, tmp_path, monkeypatch):
    """``VIGIL_CUSTOMER_FIX_IT`` on but the master ``VIGIL_REDPEN_ENABLED`` off ⇒ the dispatch fails closed (the
    sovereign dispatch re-checks the master flag), nothing reserved or published. In production the route is a 404
    with the master flag off; this pins the provisioner-level fail-closed as defence in depth."""
    p, _s = prov
    _connect(p, "org_a", API_REPO)
    monkeypatch.setenv(_FIX_IT, "1")
    monkeypatch.delenv("VIGIL_REDPEN_ENABLED", raising=False)
    before = p.wallet.available("org_a")
    with pytest.raises(ProvisionDenied):
        p.redpen_fix_this("cust_fo", "org_a", API_REPO, "f1")
    assert p.wallet.available("org_a") == before and _markers(tmp_path) == []


def test_fix_dispatch_requires_a_finding_ref(prov, tmp_path, monkeypatch):
    p, _s = prov
    monkeypatch.setenv(_FIX_IT, "1")
    _connect(p, "org_a", API_REPO)
    for bad in ("", "a b", "x" * 201):                      # blank / whitespace / over-long: no single finding named
        with pytest.raises(ProvisionError):
            p.redpen_fix_this("cust_fo", "org_a", API_REPO, bad)
    assert _markers(tmp_path) == []
