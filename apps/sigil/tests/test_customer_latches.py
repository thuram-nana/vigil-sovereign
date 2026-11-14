"""The owner's customer latches (``governor.customer_latch``) and the kill switch on the customer launch path.

Guarantees pinned here:
  * no record = every latch ON (an upgrade changes nothing); OFF is honoured on the very next read, by the same
    objects (no restart), signed or not; ON counts only as a fresh owner-signed record (a forged ON, a captured ON
    replayed, or an ON for another latch never reopens it); a read that fails answers OFF;
  * ``customer_launch`` and the kill switch refuse a NEW reservation with nothing debited and no lease minted; the
    kill switch also refuses a start, with nothing written to the seam; cancel, settle, pause and resume of an
    existing launch stay open under both, so held credits are never stranded;
  * ``customer_signup`` refuses a new sign-up request, a new confirmation and a new Google customer, while finishing a
    sign-up whose account already exists and logging in stay open; the verification token stays valid for later;
  * ``checkout`` refuses a new checkout before any processor work; the environment flag stays the ceiling;
  * ``trial`` withholds a new sign-up trial and refuses a new trial scan; a trial grant already made stands;
  * the latches carry across a hard prune, and ``sigil latch``, ``sigil status``, ``sigil doctor`` and the dashboard
    snapshot read them.

Run: SIGIL_HOME=$(mktemp -d) python -m pytest apps/sigil/tests/test_customer_latches.py -q
"""
from __future__ import annotations

import argparse
import itertools
import json
import os
import tempfile

import pytest

from sigil.governor import customer_latch as cl
from sigil.governor.authn import signed_payload
from sigil.governor.capability import CAPABILITIES, SIGNAL as CAP_SIGNAL, CapabilityGate
from sigil.reuse import generate_keypair
from sigil.spine.snapshot import SnapshotState, build
from sigil.spine.store import SpineStore

OWNER = generate_keypair()
OP = OWNER.public_key_b64
ATTACKER = generate_keypair()
_iss = itertools.count(1)


def _t() -> float:
    return float(next(_iss))


def _store(tmp_path, name="spine.jsonl"):
    return SpineStore(str(tmp_path / name))


@pytest.fixture(params=["", "1"], ids=["fold-cache-off", "fold-cache-on"])
def fold_cache(request, monkeypatch):
    monkeypatch.setenv("VIGIL_FOLD_CACHE_ENABLED", request.param)
    return request.param


# ---------------------------------------------------------------------------------------------------------------
# the latch itself
# ---------------------------------------------------------------------------------------------------------------
def test_the_five_latches_and_no_record_means_on(tmp_path, fold_cache):
    s = _store(tmp_path)
    assert cl.LATCHES == ("checkout", "customer_launch", "customer_signup", "founder_tester", "trial")
    assert cl.state_all(s, trusted_pubkey=OP) == {n: "on" for n in cl.LATCHES}
    assert all(cl.refusal(s, n, trusted_pubkey=OP) is None for n in cl.LATCHES)
    assert CapabilityGate(s, owner_key=OWNER, trusted_pubkey=OP).state_all() == {c: "enabled" for c in
                                                                                 sorted(CAPABILITIES)}


@pytest.mark.parametrize("name", cl.LATCHES)
def test_off_is_honoured_at_once_and_only_an_owner_signed_on_reopens(tmp_path, fold_cache, name):
    s = _store(tmp_path)
    assert cl.is_open(s, name, trusted_pubkey=OP)
    cl.turn_off(s, name, owner_key=None, by="phone")                 # unsigned: the safe direction
    assert cl.is_open(s, name, trusted_pubkey=OP) is False
    assert cl.refusal(s, name, trusted_pubkey=OP) == cl.PAUSED[name]
    others = [n for n in cl.LATCHES if n != name]
    assert all(cl.is_open(s, n, trusted_pubkey=OP) for n in others)  # one latch, one switch
    cl.turn_on(s, name, owner_key=ATTACKER, issued_at=_t())         # forged ON: never reopens
    assert cl.is_open(s, name, trusted_pubkey=OP) is False
    cl.turn_on(s, name, owner_key=OWNER, issued_at=_t())
    assert cl.is_open(s, name, trusted_pubkey=OP) is True


def test_a_captured_on_replayed_after_an_off_never_reopens(tmp_path, fold_cache):
    s = _store(tmp_path)
    cl.turn_off(s, "checkout", owner_key=OWNER)
    seq = cl.turn_on(s, "checkout", owner_key=OWNER, issued_at=_t())
    captured = s.get(seq).payload
    cl.turn_off(s, "checkout", owner_key=OWNER)
    s.append(kind="event", source="governor", actor="WARDEN", payload=dict(captured))   # verbatim replay
    assert cl.is_open(s, "checkout", trusted_pubkey=OP) is False


def test_an_on_for_one_latch_never_reopens_another(tmp_path, fold_cache):
    s = _store(tmp_path)
    cl.turn_off(s, "customer_launch", owner_key=OWNER)
    seq = cl.turn_on(s, "checkout", owner_key=OWNER, issued_at=_t())
    p = dict(s.get(seq).payload)
    p["capability"] = "customer_launch"                              # re-aimed: the signature no longer verifies
    s.append(kind="event", source="governor", actor="WARDEN", payload=p)
    assert cl.is_open(s, "customer_launch", trusted_pubkey=OP) is False


def test_a_latch_record_from_any_other_writer_is_ignored(tmp_path, fold_cache):
    s = _store(tmp_path)
    core = {"signal": CAP_SIGNAL, "capability": "checkout", "state": "disabled", "issued_at": 0.0}
    s.append(kind="event", source="provision", actor="WARDEN", payload=signed_payload(core, OWNER))
    assert cl.is_open(s, "checkout", trusted_pubkey=OP) is True


def test_an_unknown_latch_is_refused(tmp_path):
    s = _store(tmp_path)
    for fn in (lambda: cl.is_open(s, "launch"), lambda: cl.turn_off(s, "voice"), lambda: cl.ceiling_state("x")):
        with pytest.raises(ValueError):
            fn()
    with pytest.raises(ValueError):
        cl.turn_on(s, "checkout", owner_key=None, issued_at=_t())


def test_a_read_that_fails_answers_off(tmp_path, monkeypatch):
    s = _store(tmp_path)

    def boom(*a, **k):
        raise OSError("disk")
    monkeypatch.setattr(CapabilityGate, "reader", classmethod(boom))
    assert cl.is_open(s, "customer_launch") is False
    assert cl.state_all(s) == {n: "off" for n in cl.LATCHES}


def test_an_off_carries_across_a_hard_prune(tmp_path, monkeypatch):
    s = _store(tmp_path)
    cl.turn_off(s, "trial", owner_key=OWNER)
    recs = list(s.iter_records())
    snap = build(recs, trusted_pubkey=OP, base_seq=len(recs), snapshot_seq=len(recs) - 1)
    assert snap.capability_latch_map().get("trial") is False
    monkeypatch.setattr(SnapshotState, "load", classmethod(lambda cls, store: snap))
    assert CapabilityGate.reader(s, trusted_pubkey=OP)._scan_enabled("trial") is False


def test_the_ceiling_names_the_environment_setting():
    assert cl.ceiling_state("customer_launch") == "none" and cl.ceiling_state("customer_signup") == "none"
    assert cl.ceiling_state("checkout", {"VIGIL_CUSTOMER_CHECKOUT_ENABLED": "1"}) == \
        "VIGIL_CUSTOMER_CHECKOUT_ENABLED=1"
    assert cl.ceiling_state("checkout", {}) == "VIGIL_CUSTOMER_CHECKOUT_ENABLED=unset"
    assert cl.ceiling_state("trial", {"VIGIL_TRIAL_CREDITS": "100"}) == "VIGIL_TRIAL_CREDITS=100"
    assert cl.ceiling_state("founder_tester", {}) == "VIGIL_SIGNUP_FOUNDER_TESTER_ENABLED=unset"


# ---------------------------------------------------------------------------------------------------------------
# the launch path: customer_launch and the kill switch gate only NEW reservations (and the kill switch, a start)
# ---------------------------------------------------------------------------------------------------------------
@pytest.fixture
def launch_env(monkeypatch):
    monkeypatch.setenv("VIGIL_BASE_DIR", tempfile.mkdtemp())
    monkeypatch.setenv("SIGIL_SPINE_DIR", tempfile.mkdtemp())
    monkeypatch.setenv("SIGIL_HOME", tempfile.mkdtemp())
    from sigil.governor.identity import ensure_owner_keypair
    return ensure_owner_keypair()


def _seat(store, org="org_a", host="apme.cm", credits=100):
    from sigil.governor.asset_ownership import METHOD_DNS_TXT, AssetOwnershipRegistry
    from sigil.governor.orgs import OrgRegistry
    from sigil.governor.wallet import WalletRegistry
    from sigil.ui.target_authorization import add_customer_target
    orgs = OrgRegistry(store)
    orgs.create_org(org, org, owner="u", issued_at=_t())
    orgs.grant_membership(org, "u", "operator", issued_at=_t())
    WalletRegistry(store).grant(org, credits, "trial", entry_id=f"trial:{org}", issued_at=_t())
    reg = AssetOwnershipRegistry(store)
    ch = reg.issue_challenge(org, host, issued_at=_t())
    reg.verify_and_record(org, host, method=METHOD_DNS_TXT, observed=[ch.marker], now=1000.0, ttl_seconds=1e12)
    assert add_customer_target(host, org_id=org, store=store, now=1000.0)["ok"]


def _avail(store, org="org_a"):
    from sigil.governor.wallet import WalletRegistry
    return WalletRegistry(store).available(org)


def _reserve(gate, org="org_a", host="apme.cm"):
    return gate.reserve_launch(requester="u", org_id=org, host=host, units=10, now=2000.0)


def _on_seam(slug):
    from vigil_integration.live.credit_lease_broker import read_credit_lease
    return read_credit_lease(os.environ["VIGIL_BASE_DIR"], slug)


def test_customer_launch_off_refuses_a_new_reservation_and_debits_nothing(tmp_path, launch_env, fold_cache):
    from sigil.ui.launch_gate import LaunchGate
    s = _store(tmp_path)
    _seat(s)
    gate = LaunchGate(s)                                          # one gate object throughout: no restart
    cl.turn_off(s, "customer_launch", owner_key=None, by="phone")
    r = _reserve(gate)
    assert r == {"ok": False, "error": cl.PAUSED["customer_launch"]} and _avail(s) == 100
    cl.turn_on(s, "customer_launch", owner_key=launch_env, issued_at=_t())
    r = _reserve(gate)
    assert r["ok"] and _avail(s) == 90


def test_existing_launches_stay_cancellable_startable_pausable_under_the_latch(tmp_path, launch_env, monkeypatch):
    monkeypatch.setenv("VIGIL_CUSTOMER_PAUSE_RESUME_ENABLED", "1")
    from sigil.ui.launch_gate import LaunchGate
    s = _store(tmp_path)
    _seat(s)
    gate = LaunchGate(s)
    a, b = _reserve(gate), None
    _seat(s, org="org_b", host="beta.cm")
    b = _reserve(gate, org="org_b", host="beta.cm")
    assert a["ok"] and b["ok"]
    cl.turn_off(s, "customer_launch", owner_key=None)
    # start (publish) an existing reservation: open under the latch
    assert gate.publish_lease(signed_lease=a["lease"], expect_org_id="org_a")["ok"]
    assert gate.pause_launch(signed_lease=a["lease"], expect_org_id="org_a")["ok"]
    assert gate.resume_launch(signed_lease=a["lease"], expect_org_id="org_a", now=2500.0)["ok"]
    settled = gate.settle_launch(signed_lease=a["lease"], consumed_units=4, now=3000.0)
    assert settled["ok"] and _avail(s, "org_a") == 96
    cancelled = gate.settle_launch(signed_lease=b["lease"], consumed_units=0, now=3000.0)   # a customer cancel
    assert cancelled["ok"] and _avail(s, "org_b") == 100


def test_the_kill_switch_refuses_new_reservations_and_starts_but_not_cancel_or_pause(tmp_path, launch_env,
                                                                                     monkeypatch, fold_cache):
    monkeypatch.setenv("VIGIL_CUSTOMER_PAUSE_RESUME_ENABLED", "1")
    from sigil.governor.killswitch import KillSwitch
    from sigil.ui.launch_gate import LaunchGate, _HALTED
    s = _store(tmp_path)
    _seat(s)
    gate = LaunchGate(s)
    held = _reserve(gate)
    assert held["ok"] and _avail(s) == 90
    KillSwitch(s, owner_key=launch_env).engage(reason="incident")
    assert _reserve(gate) == {"ok": False, "error": _HALTED} and _avail(s) == 90
    out = gate.publish_lease(signed_lease=held["lease"], expect_org_id="org_a")
    assert out == {"ok": False, "error": _HALTED} and _on_seam(held["slug"]) is None
    assert gate.pause_launch(signed_lease=held["lease"], expect_org_id="org_a")["ok"]
    assert gate.resume_launch(signed_lease=held["lease"], expect_org_id="org_a", now=2500.0)["ok"]
    assert gate.settle_launch(signed_lease=held["lease"], consumed_units=0, now=3000.0)["ok"]
    assert _avail(s) == 100                                        # the held credits came back
    KillSwitch(s, owner_key=launch_env).release(issued_at=_t())
    assert _reserve(gate)["ok"]


def test_a_kill_switch_that_cannot_be_read_refuses_a_new_reservation(tmp_path, launch_env, monkeypatch):
    from sigil.governor.killswitch import KillSwitch
    from sigil.ui.launch_gate import LaunchGate
    s = _store(tmp_path)
    _seat(s)

    def boom(self):
        raise OSError("disk")
    monkeypatch.setattr(KillSwitch, "is_engaged", boom)
    r = _reserve(LaunchGate(s))
    assert not r["ok"] and "kill switch could not be read" in r["error"] and _avail(s) == 100


# ---------------------------------------------------------------------------------------------------------------
# the provisioner: sign-up, checkout, trial
# ---------------------------------------------------------------------------------------------------------------
from test_trial_signup import _FLAG, _google, _grants, _prov, _signup  # noqa: E402


def _off(p, name):
    cl.turn_off(p.store, name, owner_key=None, by="phone")


def _on(p, name):
    cl.turn_on(p.store, name, owner_key=OWNER_FOR_PROV, issued_at=_t())


from test_trial_signup import OWNER as OWNER_FOR_PROV  # noqa: E402


def test_customer_signup_off_refuses_a_new_sign_up_and_keeps_the_token(fold_cache):
    from sigil.ui.provision import ProvisionDenied
    p, s, wallet, _tc = _prov()
    tok = p.request_signup("first@acme.io", ip="1.1.1.1", now=100.0)["dev_token"]   # requested while on
    _off(p, "customer_signup")
    with pytest.raises(ProvisionDenied, match="sign-ups are paused"):
        p.request_signup("second@acme.io", ip="1.1.1.2", now=100.0)
    with pytest.raises(ProvisionDenied, match="sign-ups are paused"):
        p.confirm_signup(tok, password="customer-pw-1", org_name="Acme", now=100.0)
    assert p.customers.by_email("first@acme.io") is None and not _grants(s)
    _on(p, "customer_signup")
    out = p.confirm_signup(tok, password="customer-pw-1", org_name="Acme", now=100.0)   # the token is still valid
    assert out["org_id"] and wallet.available(out["org_id"]) == 100


def test_finishing_a_started_sign_up_and_logging_in_stay_open(fold_cache):
    from sigil.ui.provision import _signup_username
    p, s, wallet, _tc = _prov()
    done = _signup(p, "done@acme.io")
    tok = p.request_signup("half@acme.io", ip="1.1.1.1", now=100.0)["dev_token"]
    p.customers.create("half@acme.io", password="customer-pw-1", username=_signup_username(tok),
                       issued_at=p._next_issued())                  # a sign-up that stopped after its account
    _off(p, "customer_signup")
    out = p.confirm_signup(tok, password="customer-pw-1", org_name="Half", now=100.0)
    assert out["username"] == _signup_username(tok) and wallet.available(out["org_id"]) == 100
    assert p.login("done@acme.io", "customer-pw-1", now=100.0)["username"] == done["username"]


def test_customer_signup_off_refuses_a_new_google_customer_but_not_its_retry(fold_cache):
    from sigil.ui.provision import ProvisionDenied, _federated_username
    p, s, wallet, _tc = _prov()
    _off(p, "customer_signup")
    with pytest.raises(ProvisionDenied, match="sign-ups are paused"):
        _google(p, s, "new@gmail.com", "sub-new")
    assert p.customers.by_email("new@gmail.com") is None
    iss = "https://accounts.google.com"
    p.customers.create("half@gmail.com", password=None, username=_federated_username(iss, "sub-half"),
                       issued_at=p._next_issued())
    _google(p, s, "half@gmail.com", "sub-half")                       # finishing its own account: open
    assert p.customer_credentials.by_federated(iss, "sub-half") is not None


@pytest.mark.parametrize("preview", ["", "1"], ids=["legacy-trial", "preview-trial"])
def test_trial_off_withholds_a_new_trial_and_the_sign_up_still_commits(monkeypatch, fold_cache, preview):
    monkeypatch.setenv(_FLAG, preview)
    p, s, wallet, tc = _prov()
    _off(p, "trial")
    out = _signup(p, "t@acme.io")
    assert out["trial"] == "unavailable" and wallet.available(out["org_id"]) == 0 and not _grants(s)
    assert p.customers.by_email("t@acme.io") is not None
    if preview:
        assert tc.claims_of(out["org_id"]) == []                     # no mailbox claim burned while paused
    _on(p, "trial")
    assert "trial" not in _signup(p, "u@acme.io")


@pytest.mark.parametrize("preview", ["", "1"], ids=["legacy-trial", "preview-trial"])
def test_a_trial_already_granted_stands_when_the_latch_goes_off(monkeypatch, fold_cache, preview):
    monkeypatch.setenv(_FLAG, preview)
    p, s, wallet, tc = _prov()
    out = _signup(p, "g@acme.io")
    assert wallet.available(out["org_id"]) == 100
    _off(p, "trial")
    with p._lock:
        assert p._grant_signup_trial(out["org_id"], "g@acme.io", source_ref="signup") == "granted"
    # one trial entry (a re-applied legacy grant re-appends the same entry, which the wallet counts once)
    assert wallet.available(out["org_id"]) == 100 and len({g["entry_id"] for g in _grants(s)}) == 1


def test_trial_off_refuses_a_new_trial_scan(monkeypatch, fold_cache):
    from sigil.ui.provision import ProvisionDenied
    p, s, _w, _tc = _prov()
    _off(p, "trial")
    with p._lock, pytest.raises(ProvisionDenied, match="trial scans are paused"):
        p._trial_launch_check("u", "org_x", "acme.io", "vigil_launch_quick", now=100.0)
    audit = [r.payload for r in s.iter_records() if r.payload.get("reason") == "trial_paused"]
    assert audit and audit[-1].get("outcome") == "trial_refused"


def _checkout_prov():
    from test_customer_checkout import _provisioner
    return _provisioner()


def test_checkout_off_refuses_a_new_checkout_before_any_processor_work(monkeypatch, fold_cache):
    from sigil.ui.provision import ProvisionDenied
    monkeypatch.setenv("SIGIL_HOME", tempfile.mkdtemp())
    p, admin, _t2, org, _o, wallet = _checkout_prov()
    p._checkout_provider = lambda: pytest.fail("no processor work while checkout is paused")
    cl.turn_off(p.store, "checkout", owner_key=None)
    monkeypatch.delenv("VIGIL_CUSTOMER_CHECKOUT_ENABLED", raising=False)
    with pytest.raises(ProvisionDenied, match="not enabled"):        # the flag is the ceiling: it decides first
        p.billing_checkout(admin, org, "vigil_topup_1k")
    monkeypatch.setenv("VIGIL_CUSTOMER_CHECKOUT_ENABLED", "1")
    with pytest.raises(ProvisionDenied, match="purchases are paused"):
        p.billing_checkout(admin, org, "vigil_topup_1k")


def test_checkout_proceeds_once_the_owner_turns_it_back_on(monkeypatch):
    from test_customer_checkout import _LINK, _real_provider
    monkeypatch.setenv("SIGIL_HOME", tempfile.mkdtemp())
    monkeypatch.setenv("VIGIL_CUSTOMER_CHECKOUT_ENABLED", "1")
    p, admin, _t2, org, _o, wallet = _checkout_prov()
    owner = p.orgs.owner_key
    cl.turn_off(p.store, "checkout", owner_key=None)
    cl.turn_on(p.store, "checkout", owner_key=owner, issued_at=_t())
    posted: list = []
    p._checkout_provider = lambda: _real_provider(posted)
    assert p.billing_checkout(admin, org, "vigil_topup_1k")["checkout_url"] == _LINK


# ---------------------------------------------------------------------------------------------------------------
# reads: sigil latch / sigil status / sigil doctor / the dashboard snapshot
# ---------------------------------------------------------------------------------------------------------------
@pytest.fixture
def home(monkeypatch, tmp_path):
    """The CLI and the doctor open the default spine (`SpineStore()`): point it at this test's own file."""
    from sigil import cli
    from sigil.governor.identity import ensure_owner_keypair
    path = tmp_path / "spine.jsonl"
    monkeypatch.setattr(cli, "SpineStore", lambda *a, **k: SpineStore(path))
    return path, ensure_owner_keypair()


def _cli(action, name="all", reason="", as_json=False):
    from sigil.cli import cmd_latch
    cmd_latch(argparse.Namespace(action=action, name=name, reason=reason, json=as_json))


def test_sigil_latch_status_off_and_on(home, capsys):
    _cli("status", as_json=True)
    rep = json.loads(capsys.readouterr().out)
    assert rep["kill_switch"] == "released"
    assert {n: v["latch"] for n, v in rep["customer_latches"].items()} == {n: "on" for n in cl.LATCHES}
    path, _owner = home
    _cli("off", "checkout", reason="drill")
    _cli("status", as_json=True)
    rep = json.loads(capsys.readouterr().out.split("\n", 1)[1])      # after the "checkout OFF" line
    assert rep["customer_latches"]["checkout"]["latch"] == "off"
    assert cl.is_open(SpineStore(path), "checkout") is False
    _cli("on", "checkout", reason="drill over")
    assert cl.is_open(SpineStore(path), "checkout") is True
    _cli("off")                                                       # all
    assert cl.state_all(SpineStore(path)) == {n: "off" for n in cl.LATCHES}
    with pytest.raises(SystemExit):
        _cli("on")                                                    # never all at once
    with pytest.raises(SystemExit):
        _cli("off", "nope")


def test_status_doctor_and_dashboard_read_the_switches(home, capsys):
    from sigil.cli import _switches_read, sigil_doctor_report
    from sigil.dashboard import snapshot
    store = SpineStore(home[0])
    cl.turn_off(store, "trial", owner_key=None)
    sw = _switches_read(store)
    assert sw["customer_latches"]["trial"]["latch"] == "off"
    assert sw["customer_latches"]["checkout"]["ceiling"].startswith("VIGIL_CUSTOMER_CHECKOUT_ENABLED=")
    check = next(c for c in sigil_doctor_report()["checks"] if c["id"] == "switches")
    assert check["required"] is False and check["ok"] is False and "OFF: trial" in check["detail"]
    assert snapshot(store)["customer_latches"]["trial"] == "off"
