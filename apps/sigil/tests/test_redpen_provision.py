"""R5 — the SOVEREIGN Fix-this / Retest provisioner actions + their admit gate.

Both actions are behind ``VIGIL_REDPEN_ENABLED`` and gated on the ``manage_code`` permission (decision O-4). Fix is
sensitive (opens a PR) — it also reserves/meters via ``reserve_redpen_review`` (which re-verifies the connected-repo
record + wallet floor + monthly limit) and takes an E3c step-up. Retest is read-only — flag + admit + connected-repo
verify, no reservation. Both publish a marker to the dedicated ``redpen-actions`` seam.

The first half drives the gate logic with fakes; the "real hop" half runs the SAME actions over the real sovereign
registries (spine store, ``OrgRegistry.admit_customer``, ``ConnectedRepoRegistry``, ``LaunchGate`` + wallet) — the
HTTP edge that will call them is C6's.
"""
from __future__ import annotations

import itertools
import json
import tempfile
from pathlib import Path
from types import SimpleNamespace

import pytest

from vigil_core import REDPEN_ACTION_SEAM_SUBDIR, REDPEN_FIX_ACTION, REDPEN_RETEST_ACTION

from sigil import config
from sigil.governor.connected_repos import ConnectedRepoRegistry
from sigil.governor.identity import ensure_owner_keypair
from sigil.governor.orgs import OrgRegistry
from sigil.governor.wallet import WalletRegistry
from sigil.spine.store import SpineStore
from sigil.ui.launch_gate import LaunchGate
from sigil.ui.provision import ProvisionDenied
from sigil.ui.redpen_provision import publish_redpen_action, redpen_fix_this, redpen_retest
from sigil.ui.target_authorization import _customer_slug

_ORG = "cust_org"
_REPO = "github.com/acme/widget"
_SLUG = "cust_deadbeef"


@pytest.fixture(autouse=True)
def _seam_and_flag(monkeypatch, tmp_path):
    monkeypatch.setenv("VIGIL_REDPEN_ENABLED", "1")
    monkeypatch.setenv("VIGIL_BASE_DIR", str(tmp_path))   # the seam base → under tmp
    return tmp_path


def _orgs(allow=True):
    """A fake org registry: ``admit_customer`` returns ``allow`` and records the permission it was asked for."""
    asked: list = []

    def admit(*, username, org_id, permission):
        asked.append(permission)
        return allow

    return SimpleNamespace(admit_customer=admit, _asked=asked)


def _launch_gate(ok=True, error="nope"):
    def reserve(*, org_id, repo, now, depth="quick", nonce=None):
        if ok:
            return {"ok": True, "slug": _SLUG, "repo": repo, "units_reserved": 3, "nonce": nonce}
        return {"ok": False, "error": error}
    return SimpleNamespace(reserve_redpen_review=reserve)


def _markers(tmp_path) -> list:
    seam = Path(tmp_path) / REDPEN_ACTION_SEAM_SUBDIR
    return [json.loads(p.read_text()) for p in sorted(seam.glob("*.json"))] if seam.is_dir() else []


# ---- publish ----------------------------------------------------------------------------------------


def test_publish_writes_a_valid_marker(_seam_and_flag):
    path = publish_redpen_action(action=REDPEN_FIX_ACTION, slug=_SLUG, repo=_REPO, nonce="n1", finding_ref="F-1")
    m = json.loads(Path(path).read_text())
    assert m == {"redpen_action": "fix", "slug": _SLUG, "repo": _REPO, "nonce": "n1", "finding_ref": "F-1"}


# ---- fix: the admit gate ----------------------------------------------------------------------------


def test_fix_publishes_only_when_admitted_manage_code(_seam_and_flag):
    orgs = _orgs(allow=True)
    out = redpen_fix_this(requester="u", org_id=_ORG, repo=_REPO, finding_ref="F-1", orgs=orgs,
                          launch_gate=_launch_gate(), now=0.0)
    assert out["ok"] and out["action"] == REDPEN_FIX_ACTION and out["slug"] == _SLUG
    assert orgs._asked == ["manage_code"]                      # the gate asked for manage_code
    assert _markers(_seam_and_flag) and _markers(_seam_and_flag)[0]["finding_ref"] == "F-1"


def test_fix_refused_without_manage_code(_seam_and_flag):
    with pytest.raises(ProvisionDenied):
        redpen_fix_this(requester="u", org_id=_ORG, repo=_REPO, finding_ref="F-1", orgs=_orgs(allow=False),
                        launch_gate=_launch_gate(), now=0.0)
    assert _markers(_seam_and_flag) == []                      # nothing published on a refusal


def test_fix_refused_when_flag_off(monkeypatch, _seam_and_flag):
    monkeypatch.delenv("VIGIL_REDPEN_ENABLED", raising=False)
    with pytest.raises(ProvisionDenied):
        redpen_fix_this(requester="u", org_id=_ORG, repo=_REPO, finding_ref="F-1", orgs=_orgs(),
                        launch_gate=_launch_gate(), now=0.0)
    assert _markers(_seam_and_flag) == []


def test_fix_refused_when_reservation_fails(_seam_and_flag):
    # reserve_redpen_review is where the connected-repo record / wallet floor / monthly limit are enforced
    with pytest.raises(ProvisionDenied):
        redpen_fix_this(requester="u", org_id=_ORG, repo=_REPO, finding_ref="F-1", orgs=_orgs(),
                        launch_gate=_launch_gate(ok=False, error="not connected"), now=0.0)
    assert _markers(_seam_and_flag) == []


def test_fix_requires_a_finding_ref(_seam_and_flag):
    with pytest.raises(ProvisionDenied):
        redpen_fix_this(requester="u", org_id=_ORG, repo=_REPO, finding_ref="", orgs=_orgs(),
                        launch_gate=_launch_gate(), now=0.0)


def test_fix_takes_the_stepup_before_reserving(_seam_and_flag):
    steps: list = []
    out = redpen_fix_this(requester="u", org_id=_ORG, repo=_REPO, finding_ref="F-1", orgs=_orgs(),
                          launch_gate=_launch_gate(), now=0.0, require_stepup=lambda mfa: steps.append(mfa),
                          mfa_at=123.0)
    assert out["ok"] and steps == [123.0]                     # the E3c step-up ran


def test_fix_failed_stepup_reserves_nothing(_seam_and_flag):
    # a stale step-up must refuse BEFORE any credits are held or any marker is published
    reserved: list = []

    def reserve(**kw):
        reserved.append(kw)
        return {"ok": True, "slug": _SLUG, "repo": _REPO, "units_reserved": 3}

    def stale(_mfa):
        raise ProvisionDenied("a fresh step-up is required")

    with pytest.raises(ProvisionDenied):
        redpen_fix_this(requester="u", org_id=_ORG, repo=_REPO, finding_ref="F-1", orgs=_orgs(),
                        launch_gate=SimpleNamespace(reserve_redpen_review=reserve), now=0.0,
                        require_stepup=stale, mfa_at=0.0)
    assert reserved == [] and _markers(_seam_and_flag) == []


# ---- retest: the admit gate + connected-repo verify -------------------------------------------------


def test_retest_publishes_when_admitted_and_connected(_seam_and_flag):
    orgs = _orgs(allow=True)
    out = redpen_retest(requester="u", org_id=_ORG, repo=_REPO, orgs=orgs, store=object(), now=0.0,
                        finding_refs=["F-1", "F-2"],
                        _connected=lambda oid, repo: SimpleNamespace(org_id=_ORG))
    assert out["ok"] and out["action"] == REDPEN_RETEST_ACTION and out["finding_refs"] == ["F-1", "F-2"]
    assert orgs._asked == ["manage_code"]
    assert _markers(_seam_and_flag)[0]["finding_refs"] == ["F-1", "F-2"]


def test_retest_refused_without_manage_code(_seam_and_flag):
    with pytest.raises(ProvisionDenied):
        redpen_retest(requester="u", org_id=_ORG, repo=_REPO, orgs=_orgs(allow=False), store=object(), now=0.0,
                      finding_ref="F-1", _connected=lambda oid, repo: SimpleNamespace(org_id=_ORG))
    assert _markers(_seam_and_flag) == []


def test_retest_refused_when_not_connected(_seam_and_flag):
    with pytest.raises(ProvisionDenied):
        redpen_retest(requester="u", org_id=_ORG, repo=_REPO, orgs=_orgs(), store=object(), now=0.0,
                      finding_ref="F-1", _connected=lambda oid, repo: None)   # no connected-repo record
    assert _markers(_seam_and_flag) == []


def test_retest_refused_when_flag_off(monkeypatch, _seam_and_flag):
    monkeypatch.delenv("VIGIL_REDPEN_ENABLED", raising=False)
    orgs = _orgs()
    with pytest.raises(ProvisionDenied):
        redpen_retest(requester="u", org_id=_ORG, repo=_REPO, orgs=orgs, store=object(), now=0.0,
                      finding_ref="F-1", _connected=lambda oid, repo: SimpleNamespace(org_id=_ORG))
    assert orgs._asked == [] and _markers(_seam_and_flag) == []   # refused before even the admit


# ---- the shared wire contract (vigil_core.redpen_action) --------------------------------------------


@pytest.mark.parametrize("kw", [
    {"action": "merge", "slug": _SLUG, "repo": _REPO, "nonce": "n", "finding_ref": "F-1"},   # no such action
    {"action": "fix", "slug": _SLUG, "repo": _REPO, "nonce": "n"},                          # a fix needs a ref
    {"action": "retest", "slug": _SLUG, "repo": _REPO, "nonce": "n"},                       # a retest needs one
    {"action": "fix", "slug": "", "repo": _REPO, "nonce": "n", "finding_ref": "F-1"},       # no slug
])
def test_marker_contract_refuses_malformed_actions(kw):
    from vigil_core import redpen_action_marker
    with pytest.raises(ValueError):
        redpen_action_marker(**kw)


def test_retest_requires_at_least_one_ref(_seam_and_flag):
    with pytest.raises(ProvisionDenied):
        redpen_retest(requester="u", org_id=_ORG, repo=_REPO, orgs=_orgs(), store=object(), now=0.0,
                      _connected=lambda oid, repo: SimpleNamespace(org_id=_ORG))


# ---- the REAL hop: real spine + OrgRegistry.admit_customer + ConnectedRepoRegistry + LaunchGate/wallet --------

_iss = itertools.count(1)
_RORG, _RREPO, _NOW = "org_a", "github.com/acme/widgets", 2000.0


@pytest.fixture
def real(monkeypatch, tmp_path):
    """A real sovereign stack: an org with an operator (has manage_code) and an org_admin (does not), a funded
    wallet and ONE connected repository. No money configuration is set (none is needed to reserve)."""
    monkeypatch.setenv("SIGIL_HOME", tempfile.mkdtemp())
    monkeypatch.setenv("SIGIL_SPINE_DIR", tempfile.mkdtemp())
    monkeypatch.setattr(config, "MODEL_METER_DIR", tmp_path / "model_meter")
    monkeypatch.delenv("VIGIL_METERED_BILLING", raising=False)
    store = SpineStore(tempfile.mktemp(suffix=".jsonl"))
    ensure_owner_keypair()
    orgs = OrgRegistry(store)
    orgs.create_org(_RORG, _RORG, owner="u", issued_at=float(next(_iss)))
    orgs.grant_membership(_RORG, "op", "operator", issued_at=float(next(_iss)))
    orgs.grant_membership(_RORG, "adm", "org_admin", issued_at=float(next(_iss)))
    WalletRegistry(store).grant(_RORG, 1_000, "trial", entry_id=f"trial:{next(_iss)}", issued_at=float(next(_iss)))
    ConnectedRepoRegistry(store).connect(_RORG, 42, _RREPO, issued_at=float(next(_iss)))
    return SimpleNamespace(store=store, orgs=orgs, gate=LaunchGate(store),
                           avail=lambda: WalletRegistry(store).available(_RORG))


def test_real_hop_fix_reserves_then_publishes_for_a_manage_code_member(real, _seam_and_flag):
    before = real.avail()
    out = redpen_fix_this(requester="op", org_id=_RORG, repo=_RREPO, finding_ref="F-1", orgs=real.orgs,
                          launch_gate=real.gate, now=_NOW)
    assert out["ok"] and out["slug"] == _customer_slug(_RORG, _RREPO)        # the W2 cust_ slug of (org, repo)
    assert before - real.avail() == out["units_reserved"] > 0                # credits are held for the fix
    assert _markers(_seam_and_flag) == [{"redpen_action": "fix", "slug": out["slug"], "repo": _RREPO,
                                         "nonce": out["nonce"], "finding_ref": "F-1"}]


def test_real_hop_retest_runs_under_the_same_slug_and_holds_no_credits(real, _seam_and_flag):
    before = real.avail()
    out = redpen_retest(requester="op", org_id=_RORG, repo=_RREPO, orgs=real.orgs, store=real.store, now=_NOW,
                        finding_ref="F-1")
    assert out["ok"] and out["slug"] == _customer_slug(_RORG, _RREPO)        # where the review's FACTs live
    assert real.avail() == before                                           # a retest charges nothing


def test_real_hop_org_admin_can_neither_fix_nor_retest(real, _seam_and_flag):
    before = real.avail()
    with pytest.raises(ProvisionDenied):
        redpen_fix_this(requester="adm", org_id=_RORG, repo=_RREPO, finding_ref="F-1", orgs=real.orgs,
                        launch_gate=real.gate, now=_NOW)
    with pytest.raises(ProvisionDenied):
        redpen_retest(requester="adm", org_id=_RORG, repo=_RREPO, orgs=real.orgs, store=real.store, now=_NOW,
                      finding_ref="F-1")
    assert real.avail() == before and _markers(_seam_and_flag) == []


def test_real_hop_a_disconnected_repo_can_neither_be_fixed_nor_retested(real, _seam_and_flag):
    ConnectedRepoRegistry(real.store).disconnect(_RORG, _RREPO)
    before = real.avail()
    with pytest.raises(ProvisionDenied):
        redpen_fix_this(requester="op", org_id=_RORG, repo=_RREPO, finding_ref="F-1", orgs=real.orgs,
                        launch_gate=real.gate, now=_NOW)
    with pytest.raises(ProvisionDenied):
        redpen_retest(requester="op", org_id=_RORG, repo=_RREPO, orgs=real.orgs, store=real.store, now=_NOW,
                      finding_ref="F-1")
    assert real.avail() == before and _markers(_seam_and_flag) == []


def test_real_hop_flag_off_golden(real, _seam_and_flag, monkeypatch):
    """With VIGIL_REDPEN_ENABLED off, both R5 actions refuse over the real stack: nothing is admitted-through,
    nothing is reserved, nothing is published — byte-identical to a build without R5."""
    monkeypatch.delenv("VIGIL_REDPEN_ENABLED", raising=False)
    before = real.avail()
    with pytest.raises(ProvisionDenied):
        redpen_fix_this(requester="op", org_id=_RORG, repo=_RREPO, finding_ref="F-1", orgs=real.orgs,
                        launch_gate=real.gate, now=_NOW)
    with pytest.raises(ProvisionDenied):
        redpen_retest(requester="op", org_id=_RORG, repo=_RREPO, orgs=real.orgs, store=real.store, now=_NOW,
                      finding_ref="F-1")
    assert real.avail() == before and _markers(_seam_and_flag) == []
    assert not (Path(_seam_and_flag) / REDPEN_ACTION_SEAM_SUBDIR).exists()   # the seam dir is never even created
