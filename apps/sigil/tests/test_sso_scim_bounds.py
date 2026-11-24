"""PR-H — what an UNAUTHENTICATED client, a hostile tenant's IdP, or a deprovisioning request can make the SSO / SCIM
provisioner do (rvH5):

  * N1 — a failed SCIM authentication never grows the spine for an org id with no SCIM config (same 401), and is
    locked out per client IP across every org id, so the audit rows it may append are bounded per address;
  * N3 — no code path waits on the membership flock while holding the process-wide spine lock; a nested entry is
    refused at once; a sign-in never folds under the shared section and finishes a pending job only outside it; a
    tenant's Team-screen act on another member does not stop an in-flight group job;
  * N2 — the SSO config / org / membership folds of these paths are served by the verified incremental fold cache;
    every unauthenticated SSO leg is counted per client IP (successes included); unauthenticated SSO work has a
    global concurrency bound (503); and floods of starts or of valid assertions from one org leave another org's
    write and sign-in within 5x of their calm times;
  * LOW — a deprovisioning request only ever lowers: a raise it would cause is deferred to a budgeted write, a pending
    job is resumed only for its lowering steps, and a PUT that rewrites more than `active` is not exempt;
  * the mutation gaps the review listed (S12, S13, S15, S17/D06, S23/P30, P04, P06, P15).
"""
from __future__ import annotations

import json
import shutil
import threading
import time
from pathlib import Path

import pytest

import test_sso_edge as edge
from test_custui import _scrub_shared_owner_state  # noqa: F401  (autouse: keep the shared SIGIL_HOME pristine)
from test_scim_isolation import (_assertion_b64, _cut_after, _HoldMeter, _in_thread, _jobs, _n, _never_above_the_directory,
                                 _roles, _scim, _seed, _sign_in, _watch_folds)
from test_sso_edge import ORG_A, ORG_B, TOKEN_A, TOKEN_B, _okta_user

from sigil import config
from sigil.governor.orgs import OrgRegistry
from sigil.governor.scim_directory import ScimDirectoryRegistry
from sigil.spine import store as spine_store
from sigil.spine.store import SpineStore, spine_lock
from sigil.ui import provision
from sigil.ui import saml as uisaml
from sigil.ui import scim as uiscim
from sigil.ui import sso_provision
from sigil.ui.provision import ProvisionBusy, ProvisionDenied, ProvisionRateLimited, build_provisioner


@pytest.fixture
def stack(tmp_path, monkeypatch):
    s = edge.Stack(tmp_path, monkeypatch)
    yield s
    s.close()


@pytest.fixture
def signed(monkeypatch):
    monkeypatch.setattr(uisaml, "signxml_sig_verifier", edge._toy_xmldsig_verifier)


@pytest.fixture
def meter(stack, monkeypatch):
    m = _HoldMeter()
    monkeypatch.setitem(spine_store._LOCKS, str(Path(stack.spine).resolve()), m)
    orig = SpineStore.append

    def append(store, *a, **kw):
        m.note_append()
        return orig(store, *a, **kw)
    monkeypatch.setattr(SpineStore, "append", append)
    return m


def _unauth_scim(stack, org: str, *, ip: str = "198.51.100.66", token: str = "x") -> dict:
    return sso_provision.scim_request(build_provisioner(stack.store()), org, method="GET", path=f"/scim/v2/{org}/Users",
                                      authorization=f"Bearer {token}", ip=ip)


def _founder_and_teammate(stack, org: str) -> None:
    p = build_provisioner(stack.store())
    for name in ("fo", "tm"):
        p.customers.create(f"{name}@{org[-4:]}.io", issued_at=time.time(), username=f"cust_{name}")
    OrgRegistry(stack.store()).grant_membership(org, "cust_fo", "founder", issued_at=time.time())
    OrgRegistry(stack.store()).grant_membership(org, "cust_tm", "viewer", issued_at=time.time())


# =====================================================================================================================
# N1 — unauthenticated SCIM traffic grows the spine by a bounded amount per address, and never for an org id
# without SCIM
# =====================================================================================================================
def test_failed_scim_auth_for_org_ids_without_scim_appends_nothing_and_locks_the_address_out(stack):
    """One address rotating the org id in the path (any well-formed id, the org need not exist): the spine never
    grows, and after the per-IP limit every further attempt is refused 429 — the rotation never escapes it."""
    stack.saml_org(ORG_A, scim_token=TOKEN_A)
    before = _n(stack)
    statuses = [_unauth_scim(stack, f"org_{k:024x}")["status"] for k in range(60)]
    assert statuses[:10] == [401] * 10 and set(statuses[10:]) == {429}, statuses
    assert _n(stack) == before
    assert _unauth_scim(stack, f"org_{999:024x}", ip="198.51.100.67")["status"] == 401   # another address: its own


def test_the_same_over_the_real_edge(stack):
    stack.saml_org(ORG_A, scim_token=TOKEN_A)
    before = _n(stack)
    st = [stack.scim("GET", f"/scim/v2/org_{k:024x}/Users", token="nope", ip="198.51.100.66").status
          for k in range(30)]
    assert st[:10] == [401] * 10 and set(st[10:]) == {429} and _n(stack) == before


def test_failed_scim_auth_against_a_real_org_is_audited_at_most_the_per_ip_limit(stack):
    """Against an org that HAS a SCIM bearer, failures are audited — but rotating between it and unknown org ids
    from one address appends at most the per-IP limit's worth of rows before the address is locked out."""
    stack.saml_org(ORG_A, scim_token=TOKEN_A)
    before = _n(stack)
    for k in range(40):
        _unauth_scim(stack, ORG_A if k % 2 else f"org_{k:024x}")
    assert len(stack.audits("scim_auth")) <= 10 and _n(stack) - before <= 10
    # a valid bearer behind the locked address is never refused
    assert _scim(stack, ORG_A, "GET", "/Users", ip="198.51.100.66")["status"] == 200


def test_an_unknown_org_and_a_known_org_answer_the_same_401(stack):
    stack.saml_org(ORG_A, scim_token=TOKEN_A)
    known = _unauth_scim(stack, ORG_A, ip="198.51.100.70")
    unknown = _unauth_scim(stack, "org_" + "e" * 24, ip="198.51.100.71")
    assert known == unknown and known["status"] == 401


# =====================================================================================================================
# N3 — the membership flock is never waited on while the spine lock is held
# =====================================================================================================================
@pytest.fixture
def flock_waits(monkeypatch):
    """Record every `_members_lock` acquisition: (did this thread hold the spine lock?, the wait it was allowed)."""
    seen: list = []
    orig = provision._members_lock

    def members_lock(store, *, wait_s=None):
        seen.append((bool(spine_lock(store.path)._is_owned()),
                     provision._MEMBERS_LOCK_WAIT_S if wait_s is None else float(wait_s)))
        return orig(store, wait_s=wait_s)
    monkeypatch.setattr(provision, "_members_lock", members_lock)
    return seen


def test_no_path_waits_on_the_membership_flock_while_holding_the_spine_lock(stack, signed, flock_waits):
    """A SCIM write, a clamping sign-in, a Team-screen act and an owner verb — run while another process holds the
    membership flock for a moment: each waits for it WITHOUT the spine lock (another thread's spine append is never
    stalled meanwhile), and no acquisition is ever allowed a wait while the spine lock is held."""
    stack.saml_org(ORG_A, scim_token=TOKEN_A)
    _gid, uids = _seed(stack, ORG_A, 2, role="org_admin")
    _founder_and_teammate(stack, ORG_A)
    acts = [lambda: _scim(stack, ORG_A, "POST", "/Users", _okta_user("w@acme.com", "00u-w")),
            lambda: _sign_in(stack, ORG_A, f"s0@{ORG_A}.example"),
            lambda: build_provisioner(stack.store()).grant_member("cust_fo", ORG_A, "cust_tm", "analyst"),
            lambda: provision.owner_set_member_role(stack.store(), ORG_A, "cust_tm", "viewer", reason="test",
                                                    issued_at=time.time())]
    for act in acts:
        with provision._members_lock(stack.store()):          # "another process" holds the flock (no spine lock)
            t, out = _in_thread("act", act)
            time.sleep(0.3)
            t0 = time.time()
            stack.store().append(kind="message", source="x", actor="user", payload={"text": "other org's append"})
            assert time.time() - t0 < 2.0, "a spine append waited on a thread waiting for the membership flock"
            assert t.is_alive()                               # it is still waiting for the flock — without the lock
        t.join(30)
        assert "e" not in out, out
    assert flock_waits and not [w for w in flock_waits if w[0] and w[1] > 0], flock_waits
    assert stack.role(uids[0], ORG_A) == "viewer"            # the sign-in clamped (its section was entered)


def test_a_nested_entry_of_the_section_is_refused_at_once(stack):
    from vigil_integration.live.seam_lock import LockBusy
    stack.saml_org(ORG_A, scim_token=TOKEN_A)
    p = build_provisioner(stack.store())
    ran: list = []
    monkey_cfg, monkey_dir = sso_provision._registries(p)
    with sso_provision._membership_section(p):
        t0 = time.time()
        with pytest.raises(LockBusy):
            with sso_provision._membership_section(p):
                ran.append(1)
        sso_provision._resume_pending_jobs(p, ORG_A, monkey_cfg, monkey_dir, now=time.time())   # returns at once
        assert time.time() - t0 < 1.0 and ran == []
        assert provision.members_section_held()
    assert not provision.members_section_held()


def test_a_sign_in_never_folds_under_the_section_and_resumes_jobs_outside_it(stack, signed, monkeypatch):
    """An org with an open pending group job, whose sign-in folds keep being invalidated (an in-flight write of the
    org appending): the sign-in gives up with a retryable refusal instead of folding under the section; another
    org's write is never held meanwhile; and the next sign-in finishes the job OUTSIDE any section."""
    stack.saml_org(ORG_A, scim_token=TOKEN_A)
    stack.saml_org(ORG_B, scim_token=TOKEN_B)
    gid, uids = _seed(stack, ORG_A, 50, group="Admins", role="org_admin")
    ScimDirectoryRegistry(stack.store()).directory(ORG_A).put_job(gid, {"delete": True}, now=time.time())
    calls = {"n": 0}
    orig = sso_provision._org_state_changed

    def changed(store, org_id, since, member_ok=None):
        if org_id == ORG_A and calls["n"] < sso_provision._FOLD_ATTEMPTS:
            calls["n"] += 1
            return True
        return orig(store, org_id, since, member_ok)
    monkeypatch.setattr(sso_provision, "_org_state_changed", changed)
    t0 = time.time()
    b = {}
    tb = threading.Thread(target=lambda: b.update(r=_scim(stack, ORG_B, "POST", "/Users",
                                                            _okta_user("b@beta.com", "00u-b"))))
    tb.start()
    with pytest.raises(ProvisionDenied, match="try again"):
        _sign_in(stack, ORG_A, f"s0@{ORG_A}.example")
    tb.join(30)
    assert time.time() - t0 < 5.0 and b["r"]["status"] == 201
    assert list(_jobs(stack, ORG_A)) == [gid]
    held: list = []
    orig_resume = sso_provision._resume_pending_jobs

    def resume(p, org_id, *a, **kw):
        held.append((provision.members_section_held(), bool(spine_lock(stack.spine)._is_owned())))
        return orig_resume(p, org_id, *a, **kw)
    monkeypatch.setattr(sso_provision, "_resume_pending_jobs", resume)
    assert _sign_in(stack, ORG_A, f"s1@{ORG_A}.example")["org_id"] == ORG_A
    assert held == [(False, False)] and _jobs(stack, ORG_A) == {}
    roles = _roles(stack, ORG_A)
    assert {roles[u] for u in uids} == {"viewer"}


def test_a_tenant_team_act_on_another_member_does_not_stop_an_in_flight_group_job(stack, monkeypatch):
    """The org's founder re-roles a password teammate from the Team screen while the IdP's long rename is between
    holds: the rename is not stopped (it can only ever act on SSO members) and lands whole."""
    monkeypatch.setattr(uiscim, "MAX_RECORDS_PER_HOLD", 16)
    stack.saml_org(ORG_A, scim_token=TOKEN_A)
    gid, uids = _seed(stack, ORG_A, 150, group="Plain")
    _founder_and_teammate(stack, ORG_A)
    acts = {"n": 0}
    orig = sso_provision._handoff

    def handoff():
        orig()
        if acts["n"] < 3:
            acts["n"] += 1
            build_provisioner(stack.store()).grant_member("cust_fo", ORG_A, "cust_tm",
                                                          "analyst" if acts["n"] % 2 else "viewer")
    monkeypatch.setattr(sso_provision, "_handoff", handoff)
    r = _scim(stack, ORG_A, "PATCH", f"/Groups/{gid}", {"Operations": [
        {"op": "replace", "path": "displayName", "value": "Admins"}]})
    assert acts["n"] == 3 and r["status"] == 200, r
    roles = _roles(stack, ORG_A)
    assert {roles[u] for u in uids} == {"org_admin"} and _jobs(stack, ORG_A) == {}


# =====================================================================================================================
# N2 — cached folds, counted unauthenticated legs, a global bound on unauthenticated SSO work
# =====================================================================================================================
@pytest.fixture
def full_scans(monkeypatch):
    """Count reads of the spine from its start (a fold of the whole spine)."""
    n = {"v": 0}
    orig = SpineStore.iter_records

    def iter_records(store, *, since_seq=-1, strict_order=False):
        if since_seq < 0:
            n["v"] += 1
        return orig(store, since_seq=since_seq, strict_order=strict_order)
    monkeypatch.setattr(SpineStore, "iter_records", iter_records)
    return n


def test_a_sign_in_start_reads_the_cached_folds_and_sees_changes_from_another_process(stack, full_scans):
    stack.saml_org(ORG_A)
    p = build_provisioner(stack.store())
    assert sso_provision.sso_login_start(p, ORG_A, ip="192.0.2.1")["protocol"] == "saml"
    full_scans["v"] = 0
    for i in range(5):
        r = sso_provision.sso_login_start(build_provisioner(stack.store()), ORG_A, ip=f"192.0.2.{i + 2}")
        assert r["idp_sso_url"] == edge.IDP_SSO_URL
    assert full_scans["v"] == 0                          # no fold of the whole spine: the cache answered
    # a config re-signed by another process (its own store object) is seen at once
    u = stack.urls(ORG_A)
    SsoConfigRegistry = type(stack.cfg())
    SsoConfigRegistry(SpineStore(stack.spine)).set_saml_config(
        ORG_A, idp_entity_id=edge.IDP_ENTITY, idp_certs_pem=[edge.IDP_CERT], idp_sso_url="https://idp2.acme.example/sso",
        sp_entity_id=u["saml_sp_entity_id"], acs_url=u["saml_acs_url"], default_role="viewer",
        group_role_map={"Admins": "org_admin"}, role_cap="org_admin", issued_at=time.time())
    r = sso_provision.sso_login_start(build_provisioner(stack.store()), ORG_A, ip="192.0.2.50")
    assert r["idp_sso_url"] == "https://idp2.acme.example/sso"
    OrgRegistry(SpineStore(stack.spine)).revoke_org(ORG_A)
    with pytest.raises(ProvisionDenied):
        sso_provision.sso_login_start(build_provisioner(stack.store()), ORG_A, ip="192.0.2.51")


def test_every_unauthenticated_sso_leg_is_counted_per_ip_successes_included(stack, signed, monkeypatch):
    monkeypatch.setattr(config, "SSO_REQUESTS_PER_IP_PER_MIN", 3)
    stack.saml_org(ORG_A)
    ip = "192.0.2.9"
    for _ in range(3):
        sso_provision.sso_login_start(build_provisioner(stack.store()), ORG_A, ip=ip)       # successes count
    with pytest.raises(ProvisionRateLimited):
        sso_provision.sso_login_start(build_provisioner(stack.store()), ORG_A, ip=ip)
    held = _assertion_b64(stack, ORG_A, "ann@acme.example")
    with pytest.raises(ProvisionRateLimited):                                              # the ACS leg too
        _sign_in(stack, ORG_A, b64=held, ip=ip)
    assert _roles(stack, ORG_A) == {}
    assert _sign_in(stack, ORG_A, b64=held, ip="192.0.2.10")["org_id"] == ORG_A           # unspent; another address


def test_unauthenticated_sso_work_has_a_global_concurrency_bound(stack, signed, monkeypatch):
    monkeypatch.setattr(config, "SSO_CONCURRENCY", 2)
    monkeypatch.setattr(sso_provision, "_SSO_GATE_WAIT_S", 0.2)
    stack.saml_org(ORG_A)
    gate = sso_provision._sso_gate_semaphore()
    assert gate.acquire(timeout=1) and gate.acquire(timeout=1)          # the bound is taken
    try:
        with pytest.raises(ProvisionBusy) as e:
            sso_provision.sso_login_start(build_provisioner(stack.store()), ORG_A, ip="192.0.2.20")
        assert e.value.retry_after > 0
        with pytest.raises(ProvisionBusy):
            _sign_in(stack, ORG_A, "ann@acme.example", ip="192.0.2.21")
        assert _roles(stack, ORG_A) == {}
    finally:
        gate.release()
        gate.release()
    assert sso_provision.sso_login_start(build_provisioner(stack.store()), ORG_A, ip="192.0.2.22")["org_id"] == ORG_A
    assert issubclass(ProvisionBusy, ProvisionRateLimited)


def _b_timers(stack):
    def write(tag):
        t0 = time.time()
        assert _scim(stack, ORG_B, "POST", "/Users", _okta_user(f"{tag}@beta.com", f"00u-{tag}"))["status"] == 201
        return time.time() - t0

    def sign_in():
        t0 = time.time()
        assert _sign_in(stack, ORG_B, f"b0@{ORG_B}.example", ip="192.0.2.200")["org_id"] == ORG_B
        return time.time() - t0
    return write, sign_in


def _flood(stack, fn, threads: int):
    stop = threading.Event()
    counter = iter(range(10 ** 7))
    lock = threading.Lock()
    done = [0, 0]

    def run():
        while not stop.is_set():
            with lock:
                k = next(counter)
            try:
                fn(k)
                done[0] += 1
            except Exception:  # noqa: BLE001 — refusals are part of the flood
                done[1] += 1
    ths = [threading.Thread(target=run, daemon=True) for _ in range(threads)]
    for t in ths:
        t.start()
    return stop, ths, done


@pytest.mark.parametrize("kind", ["start-flood-one-ip", "valid-assertion-flood"])
def test_floods_from_one_org_leave_another_orgs_write_and_sign_in_within_5x(stack, signed, kind):
    stack.saml_org(ORG_A, scim_token=TOKEN_A)
    stack.saml_org(ORG_B, scim_token=TOKEN_B)
    _seed(stack, ORG_A, 1500)
    _seed(stack, ORG_B, 1, prefix="b")
    write, sign_in = _b_timers(stack)
    calm_w, calm_s = write("calm"), sign_in()
    if kind == "start-flood-one-ip":
        def one(_k):
            sso_provision.sso_login_start(build_provisioner(stack.store()), ORG_A, ip="198.51.100.9")
    else:
        # the hostile tenant's IdP signs its assertions elsewhere: signed up front, so the flood measures the provisioner
        signed_up_front = [_assertion_b64(stack, ORG_A, f"s{k}@{ORG_A}.example") for k in range(1500)]

        def one(k):
            _sign_in(stack, ORG_A, b64=signed_up_front[k % 1500],
                     ip=f"10.{k // 65536 % 256}.{k // 256 % 256}.{k % 256}")
    stop, ths, done = _flood(stack, one, 32)
    time.sleep(2)
    busy_w, busy_s = write("busy"), sign_in()
    stop.set()
    for t in ths:
        t.join(120)
    print(f"\n{kind}: org A ok/refused {done}; org B write {calm_w:.2f}s -> {busy_w:.2f}s, "
          f"sign-in {calm_s:.2f}s -> {busy_s:.2f}s")
    assert sum(done) > 0
    assert busy_w < 5 * max(calm_w, 1.0), (calm_w, busy_w)
    assert busy_s < 5 * max(calm_s, 1.0), (calm_s, busy_s)


# =====================================================================================================================
# LOW — a deprovisioning request only ever lowers
# =====================================================================================================================
def _overdraw(stack, monkeypatch) -> None:
    shutil.rmtree(config.SCIM_WRITE_RATELIMIT_DIR, ignore_errors=True)
    monkeypatch.setattr(config, "SCIM_OPS_PER_MIN", 2)
    assert _scim(stack, ORG_A, "POST", "/Users", _okta_user("x@acme.com", "00u-x"))["status"] == 201
    assert _scim(stack, ORG_A, "POST", "/Users", _okta_user("y@acme.com", "00u-y"))["status"] == 429


def _repay(monkeypatch) -> None:
    shutil.rmtree(config.SCIM_WRITE_RATELIMIT_DIR, ignore_errors=True)
    monkeypatch.setattr(config, "SCIM_OPS_PER_MIN", 10 ** 6)


def test_a_member_removal_admitted_past_the_write_budget_never_raises(stack, monkeypatch):
    """A hand-lowered member (the owner set viewer; the directory still implies org_admin through another group)
    removed from one group by a deprovisioning request while the org is over budget: admitted, and the member stays
    viewer — the raise is deferred, recorded in an open job, and lands with the org's next budgeted write."""
    stack.saml_org(ORG_A, scim_token=TOKEN_A)
    gid_a, (uid,) = _seed(stack, ORG_A, 1, group="Admins", role="org_admin")
    d = ScimDirectoryRegistry(stack.store()).directory(ORG_A)
    gid_s = "grp_" + "5" * 24
    d.put_group(gid_s, display_name="Security", now=time.time())
    d.add_member(gid_s, uid, now=time.time())
    OrgRegistry(stack.store()).grant_membership(ORG_A, uid, "viewer", issued_at=time.time())
    _overdraw(stack, monkeypatch)
    r = _scim(stack, ORG_A, "PATCH", f"/Groups/{gid_s}", {"Operations": [
        {"op": "remove", "path": f'members[value eq "{uid}"]'}]})
    assert r["status"] == 200 and stack.role(uid, ORG_A) == "viewer"
    assert list(_jobs(stack, ORG_A)) == [gid_s]
    _repay(monkeypatch)
    assert _scim(stack, ORG_A, "POST", "/Users", _okta_user("z@acme.com", "00u-z"))["status"] == 201
    assert stack.role(uid, ORG_A) == "org_admin" and _jobs(stack, ORG_A) == {}


def test_a_deprovisioning_request_resumes_only_the_lowering_steps_of_a_pending_job(stack, monkeypatch):
    monkeypatch.setattr(uiscim, "MAX_RECORDS_PER_HOLD", 16)
    stack.saml_org(ORG_A, scim_token=TOKEN_A)
    gid, uids = _seed(stack, ORG_A, 60, group="Plain")
    shutil.rmtree(config.SCIM_WRITE_RATELIMIT_DIR, ignore_errors=True)
    monkeypatch.setattr(config, "SCIM_OPS_PER_MIN", 10)          # the rename is admitted, and overdraws the budget
    cut = _cut_after(monkeypatch, 3)
    r = _scim(stack, ORG_A, "PATCH", f"/Groups/{gid}", {"Operations": [
        {"op": "replace", "path": "displayName", "value": "Admins"}]})
    assert r["status"] == 503 and list(_jobs(stack, ORG_A)) == [gid]
    cut["on"] = False
    before = sum(1 for u in uids if _roles(stack, ORG_A)[u] == "org_admin")
    assert 0 < before < len(uids)
    assert _scim(stack, ORG_A, "POST", "/Users", _okta_user("y@acme.com", "00u-y"))["status"] == 429
    assert _scim(stack, ORG_A, "DELETE", "/Users/sso_" + "0" * 24)["status"] == 404
    roles = _roles(stack, ORG_A)
    assert sum(1 for u in uids if roles[u] == "org_admin") == before and list(_jobs(stack, ORG_A)) == [gid]
    _repay(monkeypatch)
    assert _scim(stack, ORG_A, "POST", "/Users", _okta_user("z@acme.com", "00u-z"))["status"] == 201
    roles = _roles(stack, ORG_A)
    assert {roles[u] for u in uids} == {"org_admin"} and _jobs(stack, ORG_A) == {}


def test_a_deprovisioning_request_never_lands_a_pending_jobs_directory_change(stack, monkeypatch):
    """A rename AWAY from a mapping cut short while still lowering (its rename record not yet committed); then, over
    budget, an unrelated deprovisioning request: it lowers the job's remaining members, but neither commits the
    rename nor closes the job — that is left to the org's next budgeted write."""
    monkeypatch.setattr(uiscim, "MAX_RECORDS_PER_HOLD", 16)
    stack.saml_org(ORG_A, scim_token=TOKEN_A)
    gid, uids = _seed(stack, ORG_A, 60, group="Admins", role="org_admin")
    shutil.rmtree(config.SCIM_WRITE_RATELIMIT_DIR, ignore_errors=True)
    monkeypatch.setattr(config, "SCIM_OPS_PER_MIN", 10)
    cut = _cut_after(monkeypatch, 2)
    assert _scim(stack, ORG_A, "PATCH", f"/Groups/{gid}", {"Operations": [
        {"op": "replace", "path": "displayName", "value": "Staff"}]})["status"] == 503
    cut["on"] = False
    assert _scim(stack, ORG_A, "POST", "/Users", _okta_user("y@acme.com", "00u-y"))["status"] == 429
    assert _scim(stack, ORG_A, "DELETE", "/Users/sso_" + "0" * 24)["status"] == 404
    roles = _roles(stack, ORG_A)
    assert {roles[u] for u in uids} == {"viewer"}                       # every lowering landed
    d = ScimDirectoryRegistry(stack.store()).directory(ORG_A)
    assert d.group(gid).display_name == "Admins" and list(d.jobs()) == [gid]   # the rename did not
    _repay(monkeypatch)
    assert _scim(stack, ORG_A, "POST", "/Users", _okta_user("z@acme.com", "00u-z"))["status"] == 201
    d = ScimDirectoryRegistry(stack.store()).directory(ORG_A)
    assert d.group(gid).display_name == "Staff" and d.jobs() == {}


def test_a_deprovisioning_change_never_overwrites_a_jobs_unlanded_directory_change(stack, monkeypatch):
    """A rename AWAY from a mapping cut short while it was still lowering (its rename not yet committed); then, over
    budget, a deprovisioning removal on that same group: it is not exempt (it would overwrite the job's end state),
    so the write budget refuses it — and the job, intact, still finishes the rename at the next budgeted write."""
    monkeypatch.setattr(uiscim, "MAX_RECORDS_PER_HOLD", 16)
    stack.saml_org(ORG_A, scim_token=TOKEN_A)
    gid, uids = _seed(stack, ORG_A, 60, group="Admins", role="org_admin")
    shutil.rmtree(config.SCIM_WRITE_RATELIMIT_DIR, ignore_errors=True)
    monkeypatch.setattr(config, "SCIM_OPS_PER_MIN", 10)
    cut = _cut_after(monkeypatch, 2)
    r = _scim(stack, ORG_A, "PATCH", f"/Groups/{gid}", {"Operations": [
        {"op": "replace", "path": "displayName", "value": "Staff"}]})
    assert r["status"] == 503 and list(_jobs(stack, ORG_A)) == [gid]
    cut["on"] = False
    spec = _jobs(stack, ORG_A)[gid]
    assert ScimDirectoryRegistry(stack.store()).directory(ORG_A).group(gid).display_name == "Admins"
    removal = _scim(stack, ORG_A, "PATCH", f"/Groups/{gid}", {"Operations": [
        {"op": "remove", "path": f'members[value eq "{uids[-1]}"]'}]})
    assert removal["status"] == 429 and _jobs(stack, ORG_A) == {gid: spec}
    _repay(monkeypatch)
    assert _scim(stack, ORG_A, "POST", "/Users", _okta_user("z@acme.com", "00u-z"))["status"] == 201
    d = ScimDirectoryRegistry(stack.store()).directory(ORG_A)
    assert d.group(gid).display_name == "Staff" and _jobs(stack, ORG_A) == {}
    roles = _roles(stack, ORG_A)
    assert {roles[u] for u in uids} == {"viewer"}


def test_a_put_with_active_false_that_rewrites_identity_is_not_exempt(stack, monkeypatch):
    stack.saml_org(ORG_A, scim_token=TOKEN_A)
    _gid, ids = _seed(stack, ORG_A, 3)
    _overdraw(stack, monkeypatch)
    body = _okta_user("renamed@acme.com", "00u-renamed", active=False)
    r = _scim(stack, ORG_A, "PUT", f"/Users/{ids[0]}", body)
    u = ScimDirectoryRegistry(stack.store()).directory(ORG_A).user(ids[0])
    assert r["status"] == 429 and u.user_name == f"s0@{ORG_A}.example" and u.active
    assert stack.role(ids[0], ORG_A) == "viewer"
    # control: a PUT that only deactivates (every other attribute as stored) is the exempt offboarding
    same = {"userName": u.user_name, "externalId": u.external_id, "active": False}
    off = _scim(stack, ORG_A, "PUT", f"/Users/{ids[0]}", same)
    assert off["status"] == 200 and stack.role(ids[0], ORG_A) is None


# =====================================================================================================================
# Mutation gaps
# =====================================================================================================================
def test_S12_resume_never_creates_the_group_of_a_create_cut_short(stack):
    """A pending job whose group record never landed (a create cut short): the next write closes it without
    creating the group (the IdP retries its own create)."""
    stack.saml_org(ORG_A, scim_token=TOKEN_A)
    _gid, uids = _seed(stack, ORG_A, 2)
    gid = "grp_" + "7" * 24
    ScimDirectoryRegistry(stack.store()).directory(ORG_A).put_job(
        gid, {"delete": False, "name": "Admins", "ext": "", "members": uids}, now=time.time())
    assert _scim(stack, ORG_A, "POST", "/Users", _okta_user("z@acme.com", "00u-z"))["status"] == 201
    d = ScimDirectoryRegistry(stack.store()).directory(ORG_A)
    assert d.group(gid) is None and d.jobs() == {}
    assert {_roles(stack, ORG_A)[u] for u in uids} == {"viewer"}


def test_S13_a_job_that_can_no_longer_be_applied_is_closed(stack):
    """A pending job whose recorded end state is refused now (its name taken by another group): closed, so it
    never blocks or re-runs on every later request."""
    stack.saml_org(ORG_A, scim_token=TOKEN_A)
    gid, _uids = _seed(stack, ORG_A, 2, group="Plain")
    _gid2, _ = _seed(stack, ORG_A, 1, group="Taken", prefix="t")
    ScimDirectoryRegistry(stack.store()).directory(ORG_A).put_job(
        gid, {"delete": False, "name": "Taken", "ext": "", "members": []}, now=time.time())
    assert _scim(stack, ORG_A, "POST", "/Users", _okta_user("z@acme.com", "00u-z"))["status"] == 201
    assert _jobs(stack, ORG_A) == {}
    assert ScimDirectoryRegistry(stack.store()).directory(ORG_A).group(gid).display_name == "Plain"


def test_S15_a_group_larger_than_a_job_can_list_is_still_renamed(stack, monkeypatch):
    """A group with more members than a job record may list (`MAX_JOB_MEMBERS`) is renamed — its job records the
    (empty) member delta, never the whole member list."""
    from sigil.governor import scim_directory
    monkeypatch.setattr(scim_directory, "MAX_JOB_MEMBERS", 1100)        # scaled down: 1200 members > the job's list
    monkeypatch.setattr(uiscim, "MAX_RECORDS_PER_HOLD", 512)
    stack.saml_org(ORG_A, scim_token=TOKEN_A)
    gid, uids = _seed(stack, ORG_A, 1200, group="Plain")
    r = _scim(stack, ORG_A, "PATCH", f"/Groups/{gid}", {"Operations": [
        {"op": "replace", "path": "displayName", "value": "Admins"}]}, )
    assert r["status"] == 200, r["body"]
    roles = _roles(stack, ORG_A)
    assert {roles[u] for u in uids} == {"org_admin"} and _jobs(stack, ORG_A) == {}


def test_S17_D06_a_user_delete_cascade_is_paced(stack, meter, monkeypatch):
    """A user in many groups: its DELETE cascades one edge record per group, paced in bounded holds."""
    monkeypatch.setattr(uiscim, "MAX_RECORDS_PER_HOLD", 8)
    stack.saml_org(ORG_A, scim_token=TOKEN_A)
    _gid, (uid,) = _seed(stack, ORG_A, 1)
    d = ScimDirectoryRegistry(stack.store()).directory(ORG_A)
    for k in range(30):
        g = f"grp_{k + 1:024x}"
        d.put_group(g, display_name=f"G{k}", now=time.time())
        d.add_member(g, uid, now=time.time())
    t, out = _in_thread("org-a-delete", lambda: _scim(stack, ORG_A, "DELETE", f"/Users/{uid}"))
    t.join(60)
    assert out["r"]["status"] == 204, out
    assert meter.max_hold("org-a-delete") <= 8 and meter.hold_count("org-a-delete") >= 4
    assert ScimDirectoryRegistry(stack.store()).directory(ORG_A).groups_of(uid) == []


def test_S23_P30_a_sign_ins_resumption_of_a_job_is_charged(stack, signed, monkeypatch):
    monkeypatch.setattr(uiscim, "MAX_RECORDS_PER_HOLD", 16)
    stack.saml_org(ORG_A, scim_token=TOKEN_A)
    gid, uids = _seed(stack, ORG_A, 40, group="Admins", role="org_admin")
    cut = _cut_after(monkeypatch, 1)
    assert _scim(stack, ORG_A, "DELETE", f"/Groups/{gid}")["status"] == 503
    cut["on"] = False
    shutil.rmtree(config.SCIM_WRITE_RATELIMIT_DIR, ignore_errors=True)
    before = _n(stack)
    assert _sign_in(stack, ORG_A, f"s0@{ORG_A}.example")["org_id"] == ORG_A
    assert _jobs(stack, ORG_A) == {}
    appended = _n(stack) - before
    marker = build_provisioner(stack.store()).scim_write_limiter._marker(f"scim:writes:{ORG_A}")
    assert marker.exists(), "the sign-in's resumption of the job was never charged"
    rec = json.loads(marker.read_text())
    charged = len(rec["fails"]) if rec["fails"] else None
    assert charged is not None and 0 < charged <= appended, (charged, appended)


def test_P04_a_directory_change_during_a_sign_ins_fold_is_re_checked(stack, signed, meter, monkeypatch):
    """The person is deactivated in the directory while their sign-in is folding: the sign-in re-folds and refuses,
    never admitting them on the state it read before."""
    stack.saml_org(ORG_A, scim_token=TOKEN_A)
    _gid, (uid,) = _seed(stack, ORG_A, 1)

    def deactivate():
        d = ScimDirectoryRegistry(stack.store()).directory(ORG_A)
        u = d.user(uid)
        d.put_user(uid, user_name=u.user_name, external_id=u.external_id, active=False, now=time.time())
    seen = _watch_folds(monkeypatch, meter, on_first=deactivate)
    with pytest.raises(ProvisionDenied):
        _sign_in(stack, ORG_A, f"s0@{ORG_A}.example")
    assert len(seen) == 2


def test_P06_a_config_re_signed_between_holds_stops_a_group_job(stack, monkeypatch):
    """The owner re-signs the org's SSO config (its role map) while a long rename is between holds: the rename stops
    (it resolved roles under the old map) and the job is left for the next write to finish under the new one."""
    monkeypatch.setattr(uiscim, "MAX_RECORDS_PER_HOLD", 16)
    stack.saml_org(ORG_A, scim_token=TOKEN_A)
    gid, uids = _seed(stack, ORG_A, 60, group="Plain")
    done = {"v": False}
    orig = sso_provision._handoff

    def handoff():
        orig()
        if not done["v"]:
            done["v"] = True
            u = stack.urls(ORG_A)
            stack.cfg().set_saml_config(ORG_A, idp_entity_id=edge.IDP_ENTITY, idp_certs_pem=[edge.IDP_CERT],
                                        idp_sso_url=edge.IDP_SSO_URL, sp_entity_id=u["saml_sp_entity_id"],
                                        acs_url=u["saml_acs_url"], default_role="viewer",
                                        group_role_map={"Admins": "analyst"}, role_cap="org_admin",
                                        scim_enabled=True, scim_token=TOKEN_A, issued_at=time.time())
    monkeypatch.setattr(sso_provision, "_handoff", handoff)
    r = _scim(stack, ORG_A, "PATCH", f"/Groups/{gid}", {"Operations": [
        {"op": "replace", "path": "displayName", "value": "Admins"}]})
    assert done["v"] and r["status"] == 503 and list(_jobs(stack, ORG_A)) == [gid]
    assert _scim(stack, ORG_A, "POST", "/Users", _okta_user("z@acme.com", "00u-z"))["status"] == 201
    roles = _roles(stack, ORG_A)
    assert {roles[u] for u in uids} == {"analyst"} and _jobs(stack, ORG_A) == {}   # finished under the NEW map
    _never_above_the_directory(stack, ORG_A)


def test_P15_the_deprovisioning_cap_is_charged_exactly(stack, monkeypatch):
    """A deprovisioning request costs exactly the records it appended, and one unit when it appended none."""
    stack.saml_org(ORG_A, scim_token=TOKEN_A)
    _gid, ids = _seed(stack, ORG_A, 1)
    p = build_provisioner(stack.store())
    marker = p.scim_deprov_limiter._marker(f"scim:deprov:{ORG_A}")

    def units():
        return len(json.loads(marker.read_text())["fails"]) if marker.exists() else 0
    before = _n(stack)
    assert _scim(stack, ORG_A, "DELETE", f"/Users/{ids[0]}")["status"] == 204
    wrote = _n(stack) - before
    assert wrote == 3 and units() == 3                               # audit + revoke + the user record
    assert _scim(stack, ORG_A, "DELETE", f"/Users/{ids[0]}")["status"] == 404
    assert units() == 4                                              # nothing appended: still one unit


def test_A01_conditions_not_on_or_after_equality_boundary():
    """Conditions NotOnOrAfter: refused from (NotOnOrAfter + skew) on — at the exact instant — accepted a second
    before (the subject confirmation window kept open)."""
    import test_saml as ts
    later = "2001-09-14T00:00:00Z"
    with pytest.raises(uisaml.SamlError, match="Conditions NotOnOrAfter has passed"):
        ts._verify(ts._response(cond_nooa=ts._iso(ts.NOW - 60), scd_nooa=later))
    assert ts._verify(ts._response(cond_nooa=ts._iso(ts.NOW - 59), scd_nooa=later)).name_id == "user@acme"


@pytest.mark.parametrize("ops", [
    [{"op": "remove", "path": "active"}],
    [{"op": "remove", "path": "active", "value": False}],
    [{"op": "remove", "value": {"active": False}}],
])
def test_L07_removing_active_is_not_a_deprovisioning(ops):
    assert uiscim.lowers_only("PATCH", "/Users/sso_" + "1" * 24, {"Operations": ops}) is False


def test_C01_W03_the_scim_read_budget_is_1800_reads_a_minute(stack):
    lim = build_provisioner(stack.store()).scim_read_limiter
    assert config.SCIM_READS_PER_MIN == 1800 and lim.max_fails == 1800
    assert (lim.window_s, lim.base_lock_s, lim.max_lock_s) == (60.0, 60.0, 60.0)


def test_the_unauthenticated_leg_and_gate_defaults_are_pinned():
    assert config.SSO_REQUESTS_PER_IP_PER_MIN == 300 and config.SSO_CONCURRENCY == 4
    assert sso_provision._SSO_GATE_WAIT_S == 5.0 and sso_provision._FOLD_ATTEMPTS == 3
