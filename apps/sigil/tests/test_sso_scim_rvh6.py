"""PR-H rvH6 — the SSO work bound one org can use, the replay ledger's cost, unauthenticated spine growth, the
deprovisioning deferral bound, and the guards the rvH6 mutation run found unpinned.

  * the SSO work bound: one org holds at most its share (`VIGIL_SSO_ORG_CONCURRENCY`) of the global slots — its
    further legs wait in its own queue, so another org's sign-in is never queued behind it;
  * the SAML replay ledger: a spend is O(1) (time-bucketed markers, per-bucket counts) and the reaping runs outside the
    work bound, bounded per call — a tenant filling its own partition cannot turn its sign-ins into long slot holds;
  * a refusal an unauthenticated client provokes (a spent org budget, a failed verification) grows the spine by at
    most one row per org per minute, whatever the number of requests or addresses, and counts against the address;
  * a deprovisioning request that would defer more raises than a job may list never fails: its lowers land and the
    job carries a "re-role every member" mark the next budgeted write honours;
  * the 22 guards (M02, M07, M13, M15, M16, M22, M29, M31, M34, M36, M39, M46-M50, M53, M55-M57, M60, M66).
Several tests below are the rvH6 reviewer's confirmation probes, promoted.
"""
from __future__ import annotations

import base64
import json
import shutil
import statistics
import threading
import time
from contextlib import contextmanager

import pytest

import test_sso_edge as edge
from test_custui import _scrub_shared_owner_state  # noqa: F401  (autouse: keep the shared SIGIL_HOME pristine)
from test_scim_isolation import _assertion_b64, _jobs, _n, _never_above_the_directory, _roles, _scim, _seed, _sign_in
from test_sso_edge import ORG_A, ORG_B, TOKEN_A, TOKEN_B, _authn_request, _okta_user

from sigil import config
from sigil.governor import scim_directory as gdir
from sigil.governor.orgs import OrgRegistry
from sigil.governor.scim_directory import ScimDirectoryRegistry
from sigil.governor.sso_config import SsoConfigRegistry
from sigil.spine import fold_cache as fc
from sigil.spine.store import SpineStore, spine_lock
from sigil.ui import provision
from sigil.ui import saml as uisaml
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


def _overdraw(stack, monkeypatch) -> None:
    shutil.rmtree(config.SCIM_WRITE_RATELIMIT_DIR, ignore_errors=True)
    monkeypatch.setattr(config, "SCIM_OPS_PER_MIN", 2)
    assert _scim(stack, ORG_A, "POST", "/Users", _okta_user("x@acme.com", "00u-x"))["status"] == 201
    assert _scim(stack, ORG_A, "POST", "/Users", _okta_user("y@acme.com", "00u-y"))["status"] == 429


def _repay(monkeypatch) -> None:
    shutil.rmtree(config.SCIM_WRITE_RATELIMIT_DIR, ignore_errors=True)
    monkeypatch.setattr(config, "SCIM_OPS_PER_MIN", 10 ** 6)


def _resign(stack, group_role_map: dict) -> None:
    u = stack.urls(ORG_A)
    SsoConfigRegistry(stack.store()).set_saml_config(
        ORG_A, idp_entity_id=edge.IDP_ENTITY, idp_certs_pem=[edge.IDP_CERT], idp_sso_url=edge.IDP_SSO_URL,
        sp_entity_id=u["saml_sp_entity_id"], acs_url=u["saml_acs_url"], default_role="viewer",
        group_role_map=group_role_map, role_cap="org_admin", scim_enabled=True, scim_token=TOKEN_A,
        issued_at=time.time())


def _acs(stack, org: str, b64: str, ip: str):
    return sso_provision.sso_saml_acs(build_provisioner(stack.store()), org, b64, request_id="_req1", ip=ip)


def _assert_rerole_job(stack, gid: str, *, since_after: float, touch=None) -> dict:
    """The org's only open job is group `gid`'s DELETE carrying the re-role mark, whose window starts with the
    deferring request (`since` >= `since_after`, never in the future) — plus the listed `touch` users, when given."""
    jobs = _jobs(stack, ORG_A)
    job = jobs.get(gid) or {}
    want = {"delete": True, "rerole": True, "since": job.get("since")}
    if touch is not None:
        want["touch"] = sorted(touch)
    assert jobs == {gid: want}, jobs
    assert isinstance(job["since"], float) and since_after <= job["since"] <= time.time(), (since_after, job)
    return job


# =====================================================================================================================
# 1. one org's share of the SSO work bound; the replay ledger's spend is O(1) and its reaping is outside the bound
# =====================================================================================================================
def test_one_org_never_holds_more_than_its_share_of_the_sso_work_bound(stack, signed, monkeypatch):
    """Org A's one slot is taken (one of its legs in progress) and 8 more of its sign-ins arrive: they wait in org A's
    OWN queue — the global slots stay free — and give up with a 503; org B's sign-in is answered at once."""
    monkeypatch.setattr(sso_provision, "_SSO_GATE_WAIT_S", 0.5)
    stack.saml_org(ORG_A)
    stack.saml_org(ORG_B)
    a_slot = sso_provision._sso_org_semaphore(ORG_A)
    glob = sso_provision._sso_gate_semaphore()
    assert a_slot.acquire(timeout=1)
    out: list = []
    try:
        a = [_assertion_b64(stack, ORG_A, f"a{k}@acme.example") for k in range(8)]

        def one(k):
            try:
                _acs(stack, ORG_A, a[k], f"192.0.2.{10 + k}")
                out.append("ok")
            except ProvisionBusy:
                out.append("503")
        ths = [threading.Thread(target=one, args=(k,)) for k in range(8)]
        for t in ths:
            t.start()
        time.sleep(0.2)
        free = glob._value
        t0 = time.time()
        assert _sign_in(stack, ORG_B, "b@beta.example", ip="192.0.2.99")["org_id"] == ORG_B
        b_took = time.time() - t0
        for t in ths:
            t.join(10)
    finally:
        a_slot.release()
    assert free == config.SSO_CONCURRENCY                   # org A's waiters took none of the global slots
    assert out == ["503"] * 8 and b_took < 2.0, (out, b_took)


def _fill(led, scope: str, bucket: int, n: int) -> None:
    part = led._partition(scope)
    d = led._bucket_dir(part, bucket)
    d.mkdir(parents=True, exist_ok=True)
    exp = json.dumps({"exp": bucket * led._BUCKET_S})
    for i in range(n):
        (d / f"{i:064x}").write_text(exp)


def test_a_replay_spend_is_constant_time_and_the_reaping_is_bounded_per_call(tmp_path, monkeypatch):
    """A partition holding 30,000 live markers and 20,000 expired ones: a spend does a BOUNDED amount of filesystem
    work — it reaps at most `_SPEND_REAP` expired markers itself plus its own temp file, so its unlinks per spend are
    O(1), never O(partition) — and `maintain` reaps at most its limit per call; replay protection is intact. The
    bounded-WORK assertion is the real O(1) guarantee and is robust on a loaded / ext4 host where wall time is not (a
    partially reaped directory's `scandir` cost is a filesystem artefact, not the algorithm); a loose absolute wall
    bound still catches a gross regression."""
    led = uisaml.SamlReplayLedger(tmp_path / "replay", max_outstanding=10 ** 6)
    now = 1_000_000_000.0
    live, dead = led._bucket_of(now + 24 * 3600), int(now // led._BUCKET_S) - 10
    _fill(led, "org", live, 30000)
    _fill(led, "org", dead, 20000)
    assert led.maintain("org", now=now, limit=1000) == 1000            # first call also builds the counts
    unlinks = [0]
    orig_unlink = uisaml.SamlReplayLedger._unlink

    @staticmethod
    def counting_unlink(path):
        unlinks[0] += 1
        return orig_unlink(path)
    monkeypatch.setattr(uisaml.SamlReplayLedger, "_unlink", counting_unlink)
    scans = [0]
    orig_scan = uisaml.SamlReplayLedger._scan

    def counting_scan(self, part, key):
        scans[0] += 1
        return orig_scan(self, part, key)
    monkeypatch.setattr(uisaml.SamlReplayLedger, "_scan", counting_scan)
    t0 = time.time()
    for k in range(50):
        unlinks[0] = 0
        assert led.try_spend(f"x{k}", now + 600, now=now, scope="org")
        assert unlinks[0] <= led._SPEND_REAP + 1, (k, unlinks[0])      # O(1): <= _SPEND_REAP reaped + its own temp
    per_spend = (time.time() - t0) / 50
    assert scans[0] == 0, scans                                        # ... and never a re-count of the partition
    part = led._partition("org")
    left_dead = sum(1 for _ in led._bucket_dir(part, dead).iterdir())
    assert left_dead == 20000 - 1000 - 50 * led._SPEND_REAP
    print(f"\nreplay spend: {per_spend * 1000:.2f} ms/spend beside 50,000 markers, "
          f"<= {led._SPEND_REAP + 1} unlinks each")
    assert per_spend < 1.0, per_spend                                  # a loose absolute bound: never seconds per spend
    assert led.try_spend("x0", now + 600, now=now + 1, scope="org") is False     # a replay is still refused
    while led.maintain("org", now=now, limit=5000):
        pass
    assert not led._bucket_dir(part, dead).exists()
    assert sum(1 for _ in led._bucket_dir(part, live).iterdir()) == 30000


def test_a_tenant_filling_its_replay_partition_cannot_turn_sign_ins_into_long_slot_holds(stack, signed, monkeypatch):
    """The rvH6 shape: org A's partition is FULL — 12,000 live markers (in-budget 24 h assertions) and 6,000 expired
    ones, over its cap — while 8 of its sign-ins run: every hold of the SSO work bound stays short, org B's sign-ins
    are never refused, and the expired markers are reaped outside the bound (org A's spends then find room again)."""
    stack.saml_org(ORG_A)
    stack.saml_org(ORG_B)
    led = uisaml.SamlReplayLedger(config.CUSTOMER_SAML_REPLAY_DIR)
    _fill(led, ORG_A, led._bucket_of(time.time() + 24 * 3600), 12000)
    dead = int(time.time() // led._BUCKET_S) - 10
    _fill(led, ORG_A, dead, 6000)                                          # expired: for the reaping to remove
    b_assert = [_assertion_b64(stack, ORG_B, f"b{k}@beta.example") for k in range(8)]
    a_assert = [_assertion_b64(stack, ORG_A, f"a{k}@acme.example") for k in range(300)]
    holds: list = []
    orig_gate = sso_provision._sso_gate

    @contextmanager
    def gate(org_id=""):
        with orig_gate(org_id):
            t1 = time.time()
            try:
                yield
            finally:
                holds.append(time.time() - t1)
    monkeypatch.setattr(sso_provision, "_sso_gate", gate)

    def b(k):
        t0 = time.time()
        try:
            _acs(stack, ORG_B, b_assert[k], f"192.0.2.{200 + k}")
            return time.time() - t0, "ok"
        except ProvisionBusy:
            return time.time() - t0, "503"
    calm = [b(k) for k in range(2)]
    stop, ctr, lock = threading.Event(), iter(range(300)), threading.Lock()

    def run():
        while not stop.is_set():
            with lock:
                i = next(ctr, None)
            if i is None:
                return
            try:
                _acs(stack, ORG_A, a_assert[i], f"2001:db8:3:{i:x}::1")
            except Exception:  # noqa: BLE001 — refusals are part of the flood
                pass
    ths = [threading.Thread(target=run, daemon=True) for _ in range(8)]
    for t in ths:
        t.start()
    time.sleep(1.5)
    busy = [b(k) for k in range(2, 8)]
    stop.set()
    for t in ths:
        t.join(120)
    p50 = sorted(holds)[len(holds) // 2]
    print(f"\nreplay-fill: gate holds p50 {p50:.3f}s max {max(holds):.3f}s (n={len(holds)}); org B calm "
          f"{[round(x, 3) for x, _ in calm]} -> busy {[(round(x, 3), o) for x, o in busy]}")
    assert all(o == "ok" for _x, o in busy) and p50 < 0.2, (p50, busy)
    assert not led._bucket_dir(led._partition(ORG_A), dead).exists()      # reaped by the sign-ins, outside the bound


def test_a_valid_assertion_flood_from_one_org_measured_against_calm(stack, signed):
    """rvH6 N2b, measured honestly: 32 threads of org A's valid sign-ins (an in-budget burst); org B's sign-in (its
    assertions signed up front, only `sso_saml_acs` timed) against its calm time, the ratio reported against calm
    itself (no floor). With the folds cached a calm sign-in is ~10 ms, so the ratio is large while the absolute delay
    stays small: the bound asserted is absolute — org B's sign-in stays well under half a second, never refused."""
    stack.saml_org(ORG_A, scim_token=TOKEN_A)
    stack.saml_org(ORG_B, scim_token=TOKEN_B)
    _seed(stack, ORG_A, 1500)
    _seed(stack, ORG_B, 6, prefix="b")
    b_assert = [_assertion_b64(stack, ORG_B, f"b{k}@{ORG_B}.example") for k in range(6)]
    a_assert = [_assertion_b64(stack, ORG_A, f"s{k}@{ORG_A}.example") for k in range(1500)]

    def b(k):
        t0 = time.time()
        _acs(stack, ORG_B, b_assert[k], f"192.0.2.{200 + k}")
        return time.time() - t0
    calm = statistics.median(b(k) for k in range(3))
    stop, lock, ctr = threading.Event(), threading.Lock(), iter(range(10 ** 8))
    done: dict = {}

    def run():
        while not stop.is_set():
            with lock:
                i = next(ctr)
            try:
                _acs(stack, ORG_A, a_assert[i % 1500], f"2001:db8:2:{i:x}::1")
                key = "ok"
            except Exception as e:  # noqa: BLE001
                key = type(e).__name__
            with lock:
                done[key] = done.get(key, 0) + 1
    ths = [threading.Thread(target=run, daemon=True) for _ in range(32)]
    for t in ths:
        t.start()
    time.sleep(3)
    busy = [b(k) for k in range(3, 6)]
    stop.set()
    for t in ths:
        t.join(120)
    ratio = statistics.median(busy) / calm
    print(f"\nN2b: org A {done}; org B sign-in calm {calm:.3f}s -> busy {[round(x, 3) for x in busy]} "
          f"(median x{ratio:.1f} of calm, +{statistics.median(busy) - calm:.3f}s)")
    assert max(busy) < 0.5, (calm, busy)


# =====================================================================================================================
# 2. unauthenticated refusals: at most one spine row per org per minute, counted against the address
# =====================================================================================================================
def test_refusals_before_verification_grow_the_spine_by_a_constant_per_org(stack, signed, monkeypatch):
    """Once org A's sign-in budget is spent: 400 garbage ACS posts from ONE address (locked out after 5 refusals) and
    then 300 from 300 different addresses add at most one spine row — independent of requests and addresses."""
    monkeypatch.setattr(config, "SSO_SIGNINS_PER_MIN", 3)
    stack.saml_org(ORG_A)
    for k in range(3):
        _sign_in(stack, ORG_A, f"u{k}@acme.example", ip=f"192.0.2.{k + 1}")
    before = _n(stack)
    garbage = base64.b64encode(b"<garbage/>").decode()
    one: dict = {}
    for _ in range(400):
        try:
            _acs(stack, ORG_A, garbage, "203.0.113.99")
        except Exception as e:  # noqa: BLE001
            one[type(e).__name__] = one.get(type(e).__name__, 0) + 1
    assert one == {"ProvisionDenied": 5, "ProvisionRateLimited": 395}, one
    for k in range(300):
        with pytest.raises(ProvisionDenied):
            _acs(stack, ORG_A, garbage, f"2001:db8:{k:x}::1")
    rows = _n(stack) - before
    print(f"\nORGRATE: one address {one}; 700 refusals -> {rows} spine row(s)")
    assert rows <= 1
    # a budget-spent org whose budget is repaid signs in again (the refusals never touched it)
    shutil.rmtree(config.SSO_SIGNIN_RATELIMIT_DIR, ignore_errors=True)
    assert _sign_in(stack, ORG_A, "u9@acme.example", ip="192.0.2.50")["org_id"] == ORG_A


def test_failed_verifications_grow_the_spine_by_a_constant_per_org(stack, signed):
    """Garbage ACS posts naming an org with budget left (each a failed verification) from 300 addresses: one row."""
    stack.saml_org(ORG_A)
    before = _n(stack)
    garbage = base64.b64encode(b"<garbage/>").decode()
    for k in range(300):
        with pytest.raises(ProvisionDenied):
            _acs(stack, ORG_A, garbage, f"2001:db8:{k:x}::1")
    assert _n(stack) - before <= 1


def test_refusals_over_the_real_edge_grow_the_spine_by_a_constant(stack, signed, monkeypatch):
    """The rvH6 edge shape: an unauthenticated browser starting a sign-in and posting garbage to the ACS, 200 times,
    once the org's budget is spent."""
    monkeypatch.setattr(config, "SSO_SIGNINS_PER_MIN", 2)
    stack.saml_org(ORG_A)
    for k in range(2):
        edge._saml_sign_in(stack, ORG_A, name_id=f"real{k}@acme.example")
    before = _n(stack)
    for _ in range(200):
        r, _sid = stack.start(ORG_A)
        if r.status == 302 and r.location.startswith(edge.IDP_SSO_URL):
            _req, relay = _authn_request(r.location)
            stack.post_acs(b"<not-even-saml/>", relay)
    assert _n(stack) - before <= 2


# =====================================================================================================================
# 3. the deferral bound never fails a deprovisioning request
# =====================================================================================================================
def test_a_group_delete_deferring_more_raises_than_a_job_may_list_lowers_everyone_and_re_roles_later(stack,
                                                                                                    monkeypatch):
    """Scaled (`MAX_JOB_MEMBERS` 4): a mapped group's DELETE that would defer 6 raises stores the re-role mark instead
    of failing; its contractor-only members are lowered at once; the next budgeted write re-resolves everyone."""
    monkeypatch.setattr(gdir, "MAX_JOB_MEMBERS", 4)
    stack.saml_org(ORG_A, scim_token=TOKEN_A, group_role_map={"Admins": "org_admin", "Contractors": "analyst"})
    xg, xonly = _seed(stack, ORG_A, 3, group="Contractors", role="analyst", prefix="c")
    _ag, both = _seed(stack, ORG_A, 6, group="Admins", role="viewer", prefix="b")   # below what Admins implies
    d = ScimDirectoryRegistry(stack.store()).directory(ORG_A)
    for u in both:
        d.add_member(xg, u, now=time.time())
    _overdraw(stack, monkeypatch)
    t0 = time.time()
    r = _scim(stack, ORG_A, "DELETE", f"/Groups/{xg}")
    assert r["status"] == 204, r
    roles = _roles(stack, ORG_A)
    assert {roles[u] for u in xonly} == {"viewer"} and {roles[u] for u in both} == {"viewer"}
    _assert_rerole_job(stack, xg, since_after=t0)
    _repay(monkeypatch)
    assert _scim(stack, ORG_A, "POST", "/Users", _okta_user("z@acme.com", "00u-z"))["status"] == 201
    roles = _roles(stack, ORG_A)
    assert {roles[u] for u in both} == {"org_admin"} and _jobs(stack, ORG_A) == {}
    _never_above_the_directory(stack, ORG_A)


def test_the_deferral_bound_at_its_real_value(stack, monkeypatch):
    """The rvH6 ordinary-admin scenario at the production bound (4096): 4,100 engineers also in Contractors, the owner
    promotes Engineering to org_admin, the IdP DELETEs Contractors. It succeeds (no 400, now or on a retry), lowers the
    contractor-only members, and the next budgeted write raises the engineers."""
    stack.saml_org(ORG_A, scim_token=TOKEN_A, group_role_map={"Contractors": "analyst", "Engineering": "viewer"})
    cg, conly = _seed(stack, ORG_A, 3, group="Contractors", role="analyst", prefix="c")
    _eg, eng = _seed(stack, ORG_A, 4100, group="Engineering", role="analyst", prefix="e")
    d = ScimDirectoryRegistry(stack.store()).directory(ORG_A)
    t = time.time()
    for i, u in enumerate(eng):
        d.add_member(cg, u, now=t + i * 1e-4)
    _resign(stack, {"Contractors": "analyst", "Engineering": "org_admin"})
    t0 = time.time()
    r = _scim(stack, ORG_A, "DELETE", f"/Groups/{cg}")
    assert r["status"] == 204, r
    roles = _roles(stack, ORG_A)
    assert {roles[x] for x in conly} == {"viewer"}
    _assert_rerole_job(stack, cg, since_after=t0)
    assert _scim(stack, ORG_A, "DELETE", f"/Groups/{cg}")["status"] == 404               # a retry: never a 400
    _repay(monkeypatch)                     # the ~4,100 records the DELETE appended are owed to the write budget
    assert _scim(stack, ORG_A, "POST", "/Users", _okta_user("z@acme.com", "00u-z"))["status"] == 201
    roles = _roles(stack, ORG_A)
    assert {roles[u] for u in eng} == {"org_admin"} and _jobs(stack, ORG_A) == {}
    _never_above_the_directory(stack, ORG_A)


# =====================================================================================================================
# 4. the guards the rvH6 mutation run found unpinned
# =====================================================================================================================
def test_M60_a_revoked_config_is_never_served_from_the_cache(stack):
    stack.saml_org(ORG_A)
    reg = SsoConfigRegistry(stack.store(), cached=True)
    assert reg.config(ORG_A) is not None                                   # the cache is warm
    SsoConfigRegistry(SpineStore(stack.spine)).revoke_config(ORG_A)       # another store object (another process)
    assert reg.config(ORG_A) is None
    assert SsoConfigRegistry(stack.store(), cached=True).configs() == []
    with pytest.raises(ProvisionDenied):
        sso_provision.sso_login_start(build_provisioner(stack.store()), ORG_A, ip="192.0.2.6")


@pytest.mark.parametrize("cold", [True, False])
def test_M56_M57_cold_readers_rebuild_a_fold_once(tmp_path, cold):
    store = SpineStore(str(tmp_path / "spine.jsonl"))
    for k in range(20):
        store.append(kind="message", source="x", actor="user", payload={"text": f"r{k}"})
    cache = fc.FoldCache(f"test.single-flight.{cold}", step=lambda st, r, _ctx: st.append(r.seq))
    builds: list = []

    def build():
        builds.append(1)
        time.sleep(0.3)
        return [], None, -1, 10 ** 9
    if not cold:
        cache.read(store, ("k",), build=build, reader=len)
        builds.clear()
        store.append(kind="message", source="x", actor="user", payload={"text": "new"})
    out: list = []
    ths = [threading.Thread(target=lambda: out.append(cache.read(store, ("k",), build=build, reader=len)))
           for _ in range(32)]
    for t in ths:
        t.start()
    for t in ths:
        t.join(30)
    assert out == [21 if not cold else 20] * 32
    assert len(builds) == (1 if cold else 0), len(builds)


def test_M15_the_leg_counter_keeps_a_bounded_number_of_keys():
    c = sso_provision._LegCounter(max_keys=100)
    for i in range(1000):
        c.admit(("s", f"10.0.{i // 256}.{i % 256}"), limit=300, now=1000.0)
    assert len(c._keys) == 100


def test_M16_the_leg_counter_window_resets_when_the_clock_steps_back():
    c = sso_provision._LegCounter()
    for _ in range(3):
        assert c.admit(("s", "ip"), limit=3, now=10_000.0) is None
    assert c.admit(("s", "ip"), limit=3, now=10_000.0) is not None
    assert c.admit(("s", "ip"), limit=3, now=6_400.0) is None             # the wall clock stepped back an hour


def test_M66_the_leg_counter_window_is_one_minute():
    c = sso_provision._LegCounter()
    for _ in range(3):
        assert c.admit(("s", "ip2"), limit=3, now=1000.0) is None
    assert c.admit(("s", "ip2"), limit=3, now=1059.0) is not None
    assert c.admit(("s", "ip2"), limit=3, now=1061.0) is None


def test_the_per_client_counts_key_ipv6_on_the_64():
    assert sso_provision._client_key("2001:db8:1:2:aaaa::1") == sso_provision._client_key("2001:db8:1:2::ffff")
    assert sso_provision._client_key("2001:db8:1:3::1") != sso_provision._client_key("2001:db8:1:2::1")
    assert sso_provision._client_key("198.51.100.7") == "198.51.100.7"
    assert sso_provision._client_key("::ffff:198.51.100.7") == "198.51.100.7"


def test_CSRFLOCK_the_lockout_key_is_per_full_address_and_maps_nat64_fronts():
    """CSRFLOCK, part 1 — the SSO failure lockout key narrows to a single client, never a shared front: a whole regular
    IPv6 /64 is NOT one client (so two hosts in it are separate lockouts), and a NAT64 well-known front (64:ff9b::/96)
    maps back to the embedded IPv4 — in BOTH the lockout key and the coarse volume key — so two IPv4 clients behind one
    NAT64 front are never locked together."""
    lk, ck = sso_provision._lockout_key, sso_provision._client_key
    # two distinct IPv4 clients behind one NAT64 front keep their own lockout key (not one collapsed /64)
    assert lk("64:ff9b::198.51.100.7") == "198.51.100.7" and lk("64:ff9b::198.51.100.8") == "198.51.100.8"
    assert lk("64:ff9b::198.51.100.7") != lk("64:ff9b::198.51.100.8")
    assert ck("64:ff9b::198.51.100.7") == "198.51.100.7"                 # the coarse volume key maps NAT64 too
    assert ck("64:ff9b::198.51.100.7") != ck("64:ff9b::198.51.100.8")
    # a regular IPv6 client's LOCKOUT is its full address, never the /64 (the coarse volume key still uses the /64)
    assert lk("2001:db8:1:2::1") == "2001:db8:1:2::1" and lk("2001:db8:1:2::1") != lk("2001:db8:1:2::2")
    assert ck("2001:db8:1:2::1") == ck("2001:db8:1:2::2")
    assert lk("::ffff:198.51.100.7") == "198.51.100.7" and lk("198.51.100.7") == "198.51.100.7"


def test_CSRFLOCK_one_orgs_idp_failures_never_lock_another_orgs_sign_ins(stack, signed):
    """CSRFLOCK, part 2 — a hostile org A's IdP cannot lock a victim's address out of org B's SSO. The failure lockout
    is per (spine, org, full address): garbage ACS posts to org A (whose IdP the attacker controls, via a lured
    browser) lock only (A, address); the victim's org-B sign-in from the SAME address is still admitted. (Round 7
    keyed the lockout per address across ALL orgs, so A's failures locked B's sign-ins too.)"""
    stack.saml_org(ORG_A)                                               # the hostile tenant (its IdP is the attacker)
    stack.saml_org(ORG_B)                                               # the victim's own org
    ip = "198.51.100.200"
    assert _sign_in(stack, ORG_B, "victim@beta.example", ip=ip)["org_id"] == ORG_B      # calm: the victim signs in
    garbage = base64.b64encode(b"<garbage/>").decode()
    for _ in range(5):                                                  # the attacker's five garbage ACS to org A
        with pytest.raises(ProvisionDenied):
            _acs(stack, ORG_A, garbage, ip)
    p = build_provisioner(stack.store())
    assert sso_provision._SSO_FAILS.locked(sso_provision._fail_key(p, ORG_A, ip), now=time.time()) is not None
    assert sso_provision._SSO_FAILS.locked(sso_provision._fail_key(p, ORG_B, ip), now=time.time()) is None
    # the victim's org-B sign-in from the same address is STILL admitted (refused under the old cross-org key)
    assert _sign_in(stack, ORG_B, "victim2@beta.example", ip=ip)["org_id"] == ORG_B


def test_CSRFLOCK_over_the_edge_a_hostile_idp_never_locks_a_victim_out_of_another_org(stack, signed):
    """CSRFLOCK over the REAL edge (the rvH7 reviewer's probe, promoted): a victim lured to a hostile tenant's page is
    walked through five rounds of (start org A, org A's IdP auto-posts a garbage SAMLResponse with the fresh
    RelayState). That locks the victim's address out of org A ONLY — its own start of org A is refused — while the
    victim's start of its own org B still goes to org B's IdP (round 7 answered it '/#sso=err', locked across every
    org)."""
    stack.saml_org(ORG_A)                       # the hostile tenant (its IdP is the attacker's page)
    stack.saml_org(ORG_B)                       # the victim's own org
    _cookie, user = edge._saml_sign_in(stack, ORG_B, name_id="victim@beta.example")     # calm: the victim signs in
    assert user
    for _ in range(5):                          # the attacker's page: start org A, then its IdP auto-posts garbage
        r, _sid = stack.start(ORG_A)
        assert r.status == 302 and r.location.startswith(edge.IDP_SSO_URL + "?"), (r.status, r.location)
        _req, relay = _authn_request(r.location)
        assert stack.post_acs(b"<garbage/>", relay).status == 303
    r, _sid = stack.start(ORG_B)                # the victim now signs in to ITS org: still sent to org B's IdP
    assert r.status == 302 and r.location.startswith(edge.IDP_SSO_URL + "?"), (r.status, r.location)
    r, _sid = stack.start(ORG_A)                # ... while org A's own lockout of that address holds
    assert r.status == 302 and not r.location.startswith(edge.IDP_SSO_URL), (r.status, r.location)


@pytest.mark.parametrize("locked_ip,neighbour_ip", [
    ("64:ff9b::198.51.100.7", "64:ff9b::198.51.100.8"),          # two IPv4 clients behind one NAT64 front
    ("2001:db8:7:7::1", "2001:db8:7:7::2"),                      # two hosts of one shared IPv6 /64 (a LAN prefix)
])
def test_CSRFLOCK_two_clients_behind_one_front_are_never_locked_together(stack, signed, locked_ip, neighbour_ip):
    """CSRFLOCK, the client key — five failures from one client behind a shared front lock THAT client (for that org)
    and nobody else: its neighbour behind the same NAT64 front, or in the same IPv6 /64, still signs in (round 7 keyed
    the lockout on the /64, so the whole front was locked as one)."""
    stack.saml_org(ORG_A)
    garbage = base64.b64encode(b"<garbage/>").decode()
    for _ in range(5):
        with pytest.raises(ProvisionDenied):
            _acs(stack, ORG_A, garbage, locked_ip)
    with pytest.raises(ProvisionRateLimited):                          # the failing client itself is locked out
        sso_provision.sso_login_start(build_provisioner(stack.store()), ORG_A, ip=locked_ip)
    assert sso_provision.sso_login_start(build_provisioner(stack.store()), ORG_A, ip=neighbour_ip)["org_id"] == ORG_A
    assert _sign_in(stack, ORG_A, "neighbour@acme.example", ip=neighbour_ip)["org_id"] == ORG_A


def test_M13_the_oidc_callback_leg_is_counted_per_ip(stack, monkeypatch):
    monkeypatch.setattr(config, "SSO_REQUESTS_PER_IP_PER_MIN", 2)
    stack.oidc_org(ORG_A, client_id="cid-a")
    calls = {"n": 0}

    def post(*_a, **_k):
        calls["n"] += 1
        raise RuntimeError("idp")
    out = []
    for _ in range(4):
        p = build_provisioner(stack.store())
        p.sso_oidc_http_post = post
        try:
            sso_provision.sso_oidc_finish(p, ORG_A, code="c", code_verifier="v" * 43, nonce="n", ip="192.0.2.33")
            out.append("ok")
        except ProvisionRateLimited:
            out.append("429")
        except Exception as e:  # noqa: BLE001
            out.append(type(e).__name__)
    assert out[2:] == ["429", "429"] and calls["n"] == 2, (out, calls)


def test_M31_a_busy_bound_on_the_oidc_callback_is_a_503_not_a_counted_failure(stack, monkeypatch):
    """The bound is free for the callback's first step and taken by the time its id_token is to be verified (another
    leg took the only slot while this one waited on the IdP): a retryable 503 — never a counted, audited failure."""
    from sigil.ui import oidc as uioidc
    monkeypatch.setattr(config, "SSO_CONCURRENCY", 1)
    monkeypatch.setattr(sso_provision, "_SSO_GATE_WAIT_S", 0.2)
    stack.oidc_org(ORG_A, client_id="cid-a")
    gate = sso_provision._sso_gate_semaphore()
    taken: list = []

    def exchange(*_a, **_k):                         # the IdP answers — meanwhile another leg takes the only slot
        assert gate.acquire(timeout=1)
        taken.append(1)
        return {"id_token": "x.y.z"}
    monkeypatch.setattr(uioidc, "exchange_code", exchange)
    monkeypatch.setattr(uioidc.JwksProvider, "keys", lambda self, now=None: [])
    p = build_provisioner(stack.store())
    try:
        with pytest.raises(ProvisionBusy):
            sso_provision.sso_oidc_finish(p, ORG_A, code="c", code_verifier="v" * 43, nonce="n", ip="192.0.2.44")
    finally:
        for _ in taken:
            gate.release()
    assert taken == [1]
    assert [a for a in stack.audits("sso_login") if a.get("outcome") == "denied"] == []
    assert (sso_provision._ident(p), ORG_A, "192.0.2.44") not in sso_provision._SSO_FAILS._keys


def test_M02_M07_an_outer_spine_lock_holder_never_waits_on_the_flock(stack):
    from vigil_integration.live.seam_lock import LockBusy
    stack.saml_org(ORG_A, scim_token=TOKEN_A)
    p = build_provisioner(stack.store())
    with provision._members_lock(stack.store()):
        with spine_lock(stack.store().path):
            t0 = time.time()
            with pytest.raises(LockBusy):
                with provision._members_section(p._lock, p.store):
                    pass
            assert time.time() - t0 < 0.5


def test_M36_a_sign_in_that_resumed_a_job_writes_its_clamp_inside_the_section(stack, signed, monkeypatch):
    from sigil.governor import scim as gscim
    stack.saml_org(ORG_A, scim_token=TOKEN_A)
    _g, uids = _seed(stack, ORG_A, 2, group="Admins", role="org_admin")
    pg, pmembers = _seed(stack, ORG_A, 3, group="Plain", prefix="p")
    ScimDirectoryRegistry(stack.store()).directory(ORG_A).put_job(
        pg, {"delete": False, "name": "Plain2", "members": sorted(pmembers)}, now=time.time())
    _resign(stack, {"Admins": "analyst"})
    seen: list = []
    orig = gscim.provision_membership

    def spy(*a, **kw):
        seen.append(provision.members_section_held())
        return orig(*a, **kw)
    monkeypatch.setattr(gscim, "provision_membership", spy)
    _sign_in(stack, ORG_A, f"s0@{ORG_A}.example", ip="192.0.2.7")
    assert seen and all(seen) and stack.role(uids[0], ORG_A) == "analyst" and _jobs(stack, ORG_A) == {}


@pytest.mark.parametrize("how", ["demote", "revoke"])
def test_M22_a_clamp_never_orphans_the_org_when_the_other_admin_loses_admin_during_the_fold(stack, signed, monkeypatch,
                                                                                          how):
    stack.saml_org(ORG_A, scim_token=TOKEN_A)
    _g, (s0,) = _seed(stack, ORG_A, 1, group="Admins", role="org_admin")
    build_provisioner(stack.store()).customers.create("alice@a.io", issued_at=time.time(), username="cust_alice")
    OrgRegistry(stack.store()).grant_membership(ORG_A, "cust_alice", "org_admin", issued_at=time.time())
    _resign(stack, {"Admins": "analyst"})                    # s0 must be clamped — unless s0 is the only admin
    orig = sso_provision._SharedSection._enter
    fired = {"n": 0}

    def enter(self):
        if fired["n"] == 0:
            fired["n"] = 1
            o = OrgRegistry(stack.store())
            if how == "demote":
                o.grant_membership(ORG_A, "cust_alice", "viewer", issued_at=time.time())
            else:
                o.revoke_membership(ORG_A, "cust_alice")
        return orig(self)
    monkeypatch.setattr(sso_provision._SharedSection, "_enter", enter)
    _sign_in(stack, ORG_A, f"s0@{ORG_A}.example", ip="192.0.2.13")
    admins = {m.username for m in stack.orgs().memberships(ORG_A) if m.role in ("org_admin", "founder")}
    assert admins == {s0}


def test_M39_a_second_deferral_on_the_same_group_keeps_the_first_ones_raises(stack, monkeypatch):
    stack.saml_org(ORG_A, scim_token=TOKEN_A)
    _ga, uids = _seed(stack, ORG_A, 2, group="Admins", role="org_admin")
    d = ScimDirectoryRegistry(stack.store()).directory(ORG_A)
    gs = "grp_" + "6" * 24
    d.put_group(gs, display_name="Security", now=time.time())
    for u in uids:
        d.add_member(gs, u, now=time.time())
        OrgRegistry(stack.store()).grant_membership(ORG_A, u, "viewer", issued_at=time.time())   # hand-lowered
    _overdraw(stack, monkeypatch)
    for u in uids:                                         # two deprovisioning removals, each deferring one raise
        assert _scim(stack, ORG_A, "PATCH", f"/Groups/{gs}", {"Operations": [
            {"op": "remove", "path": f'members[value eq "{u}"]'}]})["status"] == 200
    touch = _jobs(stack, ORG_A).get(gs, {}).get("touch")
    _repay(monkeypatch)
    assert _scim(stack, ORG_A, "POST", "/Users", _okta_user("z@acme.com", "00u-z"))["status"] == 201
    roles = _roles(stack, ORG_A)
    assert touch == sorted(uids) and {roles[u] for u in uids} == {"org_admin"}


def test_M34_a_deactivating_put_that_rewrites_identity_lands_when_the_budget_has_room(stack):
    stack.saml_org(ORG_A, scim_token=TOKEN_A)
    _gid, ids = _seed(stack, ORG_A, 2)
    r = _scim(stack, ORG_A, "PUT", f"/Users/{ids[0]}", _okta_user("renamed@acme.com", "00u-renamed", active=False))
    assert r["status"] == 200 and stack.role(ids[0], ORG_A) is None
    assert ScimDirectoryRegistry(stack.store()).directory(ORG_A).user(ids[0]).user_name == "renamed@acme.com"


@pytest.mark.parametrize("field", ["profile", "selectors", "externalId", "displayName", "userName"])
def test_M46_M50_a_deactivating_put_that_changes_any_one_attribute_is_budgeted(stack, monkeypatch, field):
    stack.saml_org(ORG_A, scim_token=TOKEN_A)
    _gid, ids = _seed(stack, ORG_A, 2)
    _overdraw(stack, monkeypatch)
    u = ScimDirectoryRegistry(stack.store()).directory(ORG_A).user(ids[0])
    body: dict = {"userName": u.user_name, "externalId": u.external_id, "active": False}
    if field == "profile":
        body["emails"] = [{"value": "drift@acme.com", "primary": True}]
    elif field == "selectors":
        body["groups"] = [{"display": "Admins"}]
    elif field == "externalId":
        body["externalId"] = "00u-drift"
    elif field == "displayName":
        body["displayName"] = "Drifted Name"
    else:
        body["userName"] = "drift@" + ORG_A + ".example"
    assert _scim(stack, ORG_A, "PUT", f"/Users/{ids[0]}", body)["status"] == 429
    after = ScimDirectoryRegistry(stack.store()).directory(ORG_A).user(ids[0])
    assert (after.user_name, after.external_id, after.display_name, after.selectors, after.profile, after.active) == \
        (u.user_name, u.external_id, u.display_name, u.selectors, u.profile, True)


@pytest.mark.parametrize("delete", [True, False])
def test_M53_M55_a_job_touch_list_is_bounded(delete):
    ids = [f"sso_{i:024x}" for i in range(gdir.MAX_JOB_MEMBERS + 1)]
    spec = ({"delete": True, "touch": ids} if delete else
            {"delete": False, "name": "G", "ext": "", "members": [], "touch": ids})
    assert gdir._job_from(spec) is None
    ok = gdir._job_from({**spec, "touch": ids[:3]})
    assert ok is not None and ok.get("touch") == sorted(ids[:3])
    assert gdir._job_from({**spec, "touch": None, "rerole": True}) is not None
    assert gdir._job_from({**spec, "touch": None, "rerole": "yes"}) is None


def test_M29_a_deprovisioning_request_charges_the_write_budget_every_record(stack, monkeypatch):
    from sigil.ui import login_ratelimit as lr
    stack.saml_org(ORG_A, scim_token=TOKEN_A)
    _gid, ids = _seed(stack, ORG_A, 2)
    charged: list = []
    orig = lr.LoginRateLimiter.charge

    def charge(self, key, units, **kw):
        charged.append((key.split(":")[1], units))
        return orig(self, key, units, **kw)
    monkeypatch.setattr(lr.LoginRateLimiter, "charge", charge)
    assert _scim(stack, ORG_A, "DELETE", f"/Users/{ids[0]}")["status"] == 204
    assert charged == [("writes", 3), ("deprov", 3)], charged


def test_a_replay_never_consumes_capacity(tmp_path):
    led = uisaml.SamlReplayLedger(tmp_path / "replay", max_outstanding=2)
    now = 1_000_000_000.0
    assert led.try_spend("a1", now + 60, now=now)
    for _ in range(5):
        assert led.try_spend("a1", now + 60, now=now) is False
    assert led.try_spend("a2", now + 60, now=now)
    with pytest.raises(uisaml.SamlError, match="capacity"):
        led.try_spend("a3", now + 60, now=now)


def test_the_sso_share_defaults_are_pinned():
    assert config.SSO_ORG_CONCURRENCY == 1 and config.SSO_CONCURRENCY == 4
    assert uisaml.SamlReplayLedger._DEFAULT_MAX == 16384 and uisaml.SamlReplayLedger._SPEND_REAP == 8
    assert uisaml.SamlReplayLedger._BUCKET_S == 300.0


def test_a_carried_re_role_mark_survives_a_second_deferral(stack, monkeypatch):
    """A first deprovisioning removal defers more raises than a job may list (the re-role mark); a second one on the
    same group defers one more: the mark is kept, and the next budgeted write re-roles all of them."""
    monkeypatch.setattr(gdir, "MAX_JOB_MEMBERS", 4)
    stack.saml_org(ORG_A, scim_token=TOKEN_A)
    _ga, uids = _seed(stack, ORG_A, 6, group="Admins", role="org_admin")
    d = ScimDirectoryRegistry(stack.store()).directory(ORG_A)
    gs = "grp_" + "6" * 24
    d.put_group(gs, display_name="Security", now=time.time())
    for u in uids:
        d.add_member(gs, u, now=time.time())
        OrgRegistry(stack.store()).grant_membership(ORG_A, u, "viewer", issued_at=time.time())   # hand-lowered
    _overdraw(stack, monkeypatch)
    assert _scim(stack, ORG_A, "PATCH", f"/Groups/{gs}", {"Operations": [
        {"op": "remove", "path": "members", "value": [{"value": u} for u in uids[:5]]}]})["status"] == 200
    assert _jobs(stack, ORG_A)[gs].get("rerole") is True
    assert _scim(stack, ORG_A, "PATCH", f"/Groups/{gs}", {"Operations": [
        {"op": "remove", "path": f'members[value eq "{uids[5]}"]'}]})["status"] == 200
    assert _jobs(stack, ORG_A)[gs].get("rerole") is True
    _repay(monkeypatch)
    assert _scim(stack, ORG_A, "POST", "/Users", _okta_user("z@acme.com", "00u-z"))["status"] == 201
    roles = _roles(stack, ORG_A)
    assert {roles[u] for u in uids} == {"org_admin"} and _jobs(stack, ORG_A) == {}


def test_scim_and_sign_in_reads_are_served_by_the_fold_caches(stack, signed, monkeypatch):
    """After a first request warms them, a SCIM read and a sign-in fold NOTHING of the spine from its start: the
    config, org, membership and directory folds are all incremental."""
    stack.saml_org(ORG_A, scim_token=TOKEN_A)
    _seed(stack, ORG_A, 20)
    assert _scim(stack, ORG_A, "GET", "/Users")["status"] == 200
    assert _sign_in(stack, ORG_A, f"s0@{ORG_A}.example", ip="192.0.2.61")["org_id"] == ORG_A
    n = {"v": 0}
    orig = SpineStore.iter_records

    def iter_records(store, *, since_seq=-1, strict_order=False):
        if since_seq < 0:
            n["v"] += 1
        return orig(store, since_seq=since_seq, strict_order=strict_order)
    monkeypatch.setattr(SpineStore, "iter_records", iter_records)
    assert _scim(stack, ORG_A, "GET", "/Users")["status"] == 200
    assert _sign_in(stack, ORG_A, f"s1@{ORG_A}.example", ip="192.0.2.62")["org_id"] == ORG_A
    assert n["v"] == 0, n
    # and the cached directory is the full fold's
    cached = ScimDirectoryRegistry(stack.store(), cached=True).directory(ORG_A)
    full = ScimDirectoryRegistry(stack.store()).directory(ORG_A)
    assert (cached._users, cached._groups, cached._edges, cached._hw, cached._jobs) == \
        (full._users, full._groups, full._edges, full._hw, full._jobs)


@pytest.mark.parametrize("offset", [0.0, 1.0, 150.0, 299.0])
def test_a_spent_marker_outlives_its_accept_until_at_every_bucket_alignment(tmp_path, offset):
    """Wherever `accept_until` falls inside a time bucket, the spent marker is still there — the replay refused — at
    every instant up to and including `accept_until`, however hard the partition is reaped meanwhile."""
    led = uisaml.SamlReplayLedger(tmp_path / "replay")
    x = 1_000_000_200.0 + offset                       # accept_until
    assert led.try_spend("a", x, now=x - 3000, scope="o")
    for now in (x - 600, x - 300, x - 1, x):
        led.maintain("o", now=now, limit=10 ** 6)
        assert led.try_spend("a", x, now=now, scope="o") is False, now


# =====================================================================================================================
# rvH7 round-8 regressions — BURST/DIRCPU, REROLE-HOLD, REROLE-SCOPE, and the three surviving round-7 mutation gaps
# =====================================================================================================================
def _count_user_parses(monkeypatch, org: str) -> list:
    """Count the per-record USER parses (`scim_directory._user_from`) made for `org` — the O(org) work a directory read
    used to redo on every read."""
    n = [0]
    orig = gdir._user_from

    def counted(oid, rid, data, at):
        if oid == org:
            n[0] += 1
        return orig(oid, rid, data, at)
    monkeypatch.setattr(gdir, "_user_from", counted)
    return n


def test_BURST_a_cached_directory_read_parses_only_what_changed(stack, monkeypatch):
    """BURST/DIRCPU, the root — the cached directory fold is kept PARSED, record by record: a repeated read of an
    unchanged directory parses nothing, another org's write parses nothing of this org, and after this org's write of
    ONE user record the next read parses exactly that record — never the org. (Round 7 re-parsed the org's WHOLE
    directory on every read, under the fold cache's entry lock that every org's directory read takes; a memo keyed
    by the org's version would still re-parse the whole org after each of its in-budget writes.)"""
    stack.saml_org(ORG_A, scim_token=TOKEN_A)
    stack.saml_org(ORG_B, scim_token=TOKEN_B)
    _seed(stack, ORG_A, 300, group="Admins", role="org_admin", prefix="a")
    reg = ScimDirectoryRegistry(stack.store(), cached=True)
    assert len(reg.directory(ORG_A).users()) == 300                          # warm
    parses = _count_user_parses(monkeypatch, ORG_A)
    for _ in range(3):
        assert len(reg.directory(ORG_A).users()) == 300
    assert parses[0] == 0, parses
    assert _scim(stack, ORG_B, "POST", "/Users", _okta_user("x@beta.com", "00u-x"))["status"] == 201
    assert len(ScimDirectoryRegistry(stack.store(), cached=True).directory(ORG_A).users()) == 300
    assert parses[0] == 0, parses                                             # B's write: nothing of A re-parsed
    assert _scim(stack, ORG_A, "POST", "/Users", _okta_user("y@acme.com", "00u-y"))["status"] == 201
    before = parses[0]
    assert len(ScimDirectoryRegistry(stack.store(), cached=True).directory(ORG_A).users()) == 301
    assert parses[0] - before == 1, (before, parses)                          # ONE user record folded, not 301


def _count_snapshot_work(monkeypatch) -> dict:
    """Count the work a cached directory read can do: a fresh read-only snapshot of an org's fold (one copy of its
    containers, `_DirSnapshot.__init__`), the snapshot's edge index (`_DirSnapshot.index` computing it) and a view's
    own edge index (`OrgDirectory._index`, O(the org's edges))."""
    n = {"snapshot": 0, "index_built": 0, "view_index": 0}
    orig_init, orig_index, orig_view_index = gdir._DirSnapshot.__init__, gdir._DirSnapshot.index, \
        gdir.OrgDirectory._index

    def init(self, *a, **kw):
        n["snapshot"] += 1
        return orig_init(self, *a, **kw)

    def index(self):
        if self._by is None:
            n["index_built"] += 1
        return orig_index(self)

    def view_index(self):
        n["view_index"] += 1
        return orig_view_index(self)
    monkeypatch.setattr(gdir._DirSnapshot, "__init__", init)
    monkeypatch.setattr(gdir._DirSnapshot, "index", index)
    monkeypatch.setattr(gdir.OrgDirectory, "_index", view_index)
    return n


def test_BURST_an_unchanged_directory_is_read_in_constant_time(stack, monkeypatch):
    """BURST/DIRCPU, the read itself — a cached read of an UNCHANGED directory copies nothing and indexes nothing: every
    reader is handed the same memoised read-only snapshot (O(1) under the fold cache's entry lock), and its edge index
    is derived once per snapshot, outside that lock. Another org's write leaves this org's snapshot as it is; this
    org's own write makes the next read take exactly ONE fresh snapshot (one copy of the containers, one index), which
    every later reader shares again. (Round 7 re-parsed the whole directory per read; a copy-per-read still costs
    O(org) per read under the entry lock, and an index rebuild O(the org's edges) per read.)"""
    stack.saml_org(ORG_A, scim_token=TOKEN_A)
    stack.saml_org(ORG_B, scim_token=TOKEN_B)
    _seed(stack, ORG_A, 200, group="Admins", role="org_admin", prefix="a")
    first = ScimDirectoryRegistry(stack.store(), cached=True).directory(ORG_A)               # warm
    n = _count_snapshot_work(monkeypatch)
    views = [ScimDirectoryRegistry(stack.store(), cached=True).directory(ORG_A) for _ in range(5)]
    assert n == {"snapshot": 0, "index_built": 0, "view_index": 0}, n
    assert all(v._users is first._users and v._by_user is first._by_user for v in views)     # one shared snapshot
    assert len(views[-1].users()) == 200 and len(views[-1].members(views[-1].groups()[0].id)) == 200
    assert _scim(stack, ORG_B, "POST", "/Users", _okta_user("x@beta.com", "00u-x"))["status"] == 201
    assert ScimDirectoryRegistry(stack.store(), cached=True).directory(ORG_A)._users is first._users
    assert n == {"snapshot": 0, "index_built": 0, "view_index": 0}, n                       # B's write: A untouched
    assert _scim(stack, ORG_A, "POST", "/Users", _okta_user("y@acme.com", "00u-y"))["status"] == 201
    n.update(snapshot=0, index_built=0, view_index=0)
    after = [ScimDirectoryRegistry(stack.store(), cached=True).directory(ORG_A) for _ in range(4)]
    assert n == {"snapshot": 1, "index_built": 1, "view_index": 0}, n                       # ONE fresh snapshot
    assert all(v._users is after[0]._users for v in after) and len(after[0].users()) == 201


def test_BURST_a_write_through_a_shared_snapshot_never_reaches_another_reader(stack):
    """The memoised snapshot is SHARED, so a view built on it takes its own copy on its first write (copy-on-write):
    the write lands on the spine and in that view only — another reader's view of the same snapshot is unchanged, and
    the next read sees the write. The snapshot is read-only: a write path that skipped the copy raises (TypeError /
    AttributeError) instead of corrupting what other readers hold."""
    stack.saml_org(ORG_A, scim_token=TOKEN_A)
    gid, uids = _seed(stack, ORG_A, 3, group="Admins", role="org_admin", prefix="a")
    reg = ScimDirectoryRegistry(stack.store(), cached=True)
    mine, other = reg.directory(ORG_A), reg.directory(ORG_A)
    assert mine._users is other._users
    snap_users, snap_edges = other._users, other._edges
    new = "sso_" + "e" * 24
    t = time.time()
    assert mine.put_user(new, user_name="new@acme.example", active=True, now=t)
    assert mine.add_member(gid, new, now=t)
    assert mine.remove_member(gid, uids[0], now=t)
    assert mine.delete_user(uids[1], now=t)
    mine.put_job(gid, {"delete": True, "touch": [uids[2]]}, now=t)
    assert mine._users is not snap_users and mine.user(new) is not None and mine.members(gid) == sorted([new, uids[2]])
    # the other reader (and the shared snapshot) never saw any of it
    assert other._users is snap_users and other._edges is snap_edges and other.user(new) is None
    assert other.members(gid) == sorted(uids) and other.jobs() == {} and len(other.users()) == 3
    fresh = reg.directory(ORG_A)                                                        # the next read sees it
    assert fresh.user(new) is not None and fresh.user(uids[1]) is None and fresh.members(gid) == sorted([new, uids[2]])
    assert fresh.jobs() == {gid: {"delete": True, "touch": [uids[2]]}}
    full = ScimDirectoryRegistry(stack.store()).directory(ORG_A)
    assert fresh.users() == full.users() and fresh._edges == full._edges and fresh._hw == full._hw
    # read-only: nothing can be written into the shared snapshot behind the copy
    with pytest.raises((TypeError, AttributeError)):
        fresh._users[new] = None                                                        # type: ignore[index]
    with pytest.raises((TypeError, AttributeError)):
        fresh._edges.add((gid, uids[0]))                                                # type: ignore[attr-defined]
    with pytest.raises((TypeError, AttributeError)):
        fresh._by_group[gid] = set()                                                    # type: ignore[index]
    with pytest.raises((TypeError, AttributeError)):
        fresh._by_user.setdefault(new, set())                                           # type: ignore[attr-defined]
    with pytest.raises((TypeError, AttributeError)):
        fresh._jobs[gid]["touch"] = []                                                  # type: ignore[index]
    jobs = fresh.jobs()
    jobs[gid]["touch"].append("x")                                                      # a caller's copy, never ours
    assert reg.directory(ORG_A).jobs() == {gid: {"delete": True, "touch": [uids[2]]}}
    # a staged group change COMMITTED onto a view still reading the shared snapshot (no write through it before):
    # the commit takes the view's own copy first, so the snapshot other readers hold is unchanged
    real, bystander = reg.directory(ORG_A), reg.directory(ORG_A)
    assert real._shared and real._users is bystander._users
    staged = real.staged()
    assert staged.add_member(gid, uids[0], now=time.time())
    real.commit(staged)
    assert real.members(gid) == sorted([new, uids[0], uids[2]])
    assert bystander.members(gid) == sorted([new, uids[2]]) and bystander._edges is fresh._edges
    assert reg.directory(ORG_A).members(gid) == sorted([new, uids[0], uids[2]])


def test_BURST_the_parsed_fold_matches_a_full_fold_after_random_activity(stack):
    """The incremental parsed fold is EXACTLY the full fold: after random directory activity (users, groups, edges,
    jobs — created, rewritten, deleted, re-created; a replayed stale record; a signed record whose data does not
    parse), read incrementally in between, the cached view equals a full fold of the spine, and the S0d
    rebuild-and-compare audit matches."""
    import random

    from sigil.governor import fold_read
    stack.saml_org(ORG_A, scim_token=TOKEN_A)
    rng = random.Random(8)
    d = ScimDirectoryRegistry(stack.store()).directory(ORG_A)
    users = [f"sso_{i:024x}" for i in range(10)]
    groups = [f"grp_{i:024x}" for i in range(4)]
    early = None
    for step in range(240):
        op = rng.choice(["put", "put", "del", "group", "delgroup", "add", "add", "rm", "job", "finish", "bad"])
        u, g, t = rng.choice(users), rng.choice(groups), time.time()
        if op == "put":
            d.put_user(u, user_name=f"{u}@acme.example", display_name=f"n{step}", active=rng.random() < 0.8,
                       selectors=[rng.choice(["Admins", "Staff"])], profile={"name": {"givenName": f"g{step}"}},
                       now=t)
        elif op == "del":
            d.delete_user(u, now=t)
        elif op == "group":
            d.put_group(g, display_name=f"G{groups.index(g)}-{step % 3}", now=t)
        elif op == "delgroup":
            d.delete_group(g, now=t)
        elif op == "add":
            d.add_member(g, u, now=t)
        elif op == "rm":
            d.remove_member(g, u, now=t)
        elif op == "job":
            d.put_job(g, {"delete": True, "touch": [u], **({"rerole": True, "since": t} if step % 2 else {})},
                      now=t)
        elif op == "finish":
            d.finish_job(g, now=t)
        else:                                           # an owner-signed record whose data does not parse: inert
            at = d._fresh("user", u, t)
            d._reg._append(ORG_A, "user", u, "active", {"userName": ""}, issued_at=at)
            d._hw[("user", u)] = at
            d._users.pop(u, None)
        if step == 20:
            early = next(r for r in reversed(list(stack.store().iter_records()))
                         if isinstance(r.payload, dict) and r.payload.get("signal") == gdir.SCIM_DIRECTORY_SIGNAL)
        if step % 7 == 0:
            ScimDirectoryRegistry(stack.store(), cached=True).directory(ORG_A)      # incremental catch-up in between
    stack.store().append(kind=early.kind, source=early.source, actor=early.actor, payload=dict(early.payload))
    cached = ScimDirectoryRegistry(stack.store(), cached=True).directory(ORG_A)
    full = ScimDirectoryRegistry(stack.store()).directory(ORG_A)
    assert cached.users() == full.users() and cached.groups() == full.groups()
    assert cached._edges == full._edges and cached.jobs() == full.jobs() and cached._hw == full._hw
    assert {g: cached.members(g) for g in groups} == {g: full.members(g) for g in groups}
    rep = fold_read.audit_with(lambda: ScimDirectoryRegistry(SpineStore(stack.spine), cached=True).directory(ORG_A))
    assert [r["status"] for r in rep if r["fold"] == "governor.scim_directory"] == ["match"], rep


def test_BURST_one_orgs_heavy_traffic_leaves_another_orgs_sign_in_burst_unrefused(stack, signed, monkeypatch):
    """BURST/DIRCPU, the behaviour — a large directory-managed org A runs in-budget SCIM reads AND writes back to back
    while another org B's burst of 16 sign-ins arrives at once: none of B's sign-ins is refused (round 7: every one of
    A's reads re-parsed its whole directory under the shared entry lock, and B's burst — one slot of the SSO work
    bound per org — turned that slowdown into 503s), and A's traffic parses only what it wrote (O(delta)), never its
    directory."""
    import os
    monkeypatch.setattr(config, "SCIM_READS_PER_MIN", 10 ** 6)
    monkeypatch.setattr(config, "SCIM_OPS_PER_MIN", 10 ** 6)
    monkeypatch.setattr(config, "SSO_SIGNINS_PER_MIN", 10 ** 6)
    stack.saml_org(ORG_A, scim_token=TOKEN_A)
    stack.saml_org(ORG_B)
    with monkeypatch.context() as mp:
        mp.setattr(os, "fsync", lambda fd: None)
        _ga, auids = _seed(stack, ORG_A, 2500, group="Admins", role="org_admin", prefix="a")
    ScimDirectoryRegistry(stack.store(), cached=True).directory(ORG_A)         # warm
    b = [_assertion_b64(stack, ORG_B, f"b{k}@beta.example") for k in range(16)]
    parses = _count_user_parses(monkeypatch, ORG_A)
    stop = threading.Event()
    wrote = [0, 0]                                      # PATCH attempts (each writes at most one user record), 200s
    a_status: dict = {}

    def a_reads():
        while not stop.is_set():
            r = _scim(stack, ORG_A, "GET", "/Users?count=1", ip="203.0.113.77")
            a_status[r["status"]] = a_status.get(r["status"], 0) + 1

    def a_writes():
        k = 0
        while not stop.is_set():
            wrote[0] += 1
            r = _scim(stack, ORG_A, "PATCH", f"/Users/{auids[k % len(auids)]}", {"Operations": [
                {"op": "replace", "path": "displayName", "value": f"renamed {k}"}]}, ip="203.0.113.78")
            wrote[1] += r["status"] == 200
            k += 1
    a_threads = [threading.Thread(target=a_reads, daemon=True), threading.Thread(target=a_writes, daemon=True)]
    for t in a_threads:
        t.start()
    time.sleep(0.5)
    out: dict = {}

    def one(k):
        try:
            _acs(stack, ORG_B, b[k], f"198.18.7.{k + 1}")
            out[k] = "ok"
        except ProvisionBusy:
            out[k] = "503"
        except Exception as e:  # noqa: BLE001
            out[k] = type(e).__name__
    burst = [threading.Thread(target=one, args=(k,)) for k in range(16)]
    for t in burst:
        t.start()
    for t in burst:
        t.join(120)
    stop.set()
    for t in a_threads:
        t.join(60)
    assert sorted(out.values()) == ["ok"] * 16, out                           # not one of B's sign-ins refused
    assert a_status.get(200, 0) > 0 and wrote[1] > 0, (a_status, wrote)       # A really was busy meanwhile
    # each of A's user writes is parsed twice (its own put_user, then once by the next read's catch-up)
    assert parses[0] <= 2 * wrote[0] + 2, (parses, wrote)


def _plan_work(monkeypatch) -> dict:
    """Count the PLAN work of a group change / a pending job (`OrgDirectory.staged`, a re-role window scan, a group
    member's `ui.scim._target`) — split by whether THIS thread held the shared membership section meanwhile."""
    from sigil.ui import scim as uiscim
    n = {"staged": 0, "window": 0, "target": 0, "staged_outside": 0, "window_outside": 0, "target_outside": [],
         "user_target": 0}
    orig_staged, orig_window, orig_target = gdir.OrgDirectory.staged, gdir.OrgDirectory.edge_users_since, \
        uiscim._target

    def staged(self):
        n["staged" if provision.members_section_held() else "staged_outside"] += 1
        return orig_staged(self)

    def window(self, gid, since):
        n["window" if provision.members_section_held() else "window_outside"] += 1
        return orig_window(self, gid, since)

    def target(req, uid, *, create):
        if create:
            n["user_target"] += 1                       # a user write's own reconcile (O(1)), not a group plan
        elif provision.members_section_held():
            n["target"] += 1
        else:
            n["target_outside"].append(uid)
        return orig_target(req, uid, create=create)
    monkeypatch.setattr(gdir.OrgDirectory, "staged", staged)
    monkeypatch.setattr(gdir.OrgDirectory, "edge_users_since", window)
    monkeypatch.setattr(uiscim, "_target", target)
    return n


def _rerole_org(stack, monkeypatch, *, others: int = 60) -> tuple:
    """Org A with Contractors (3 contractor-only analysts + 6 hand-lowered admins also in it) and `others` further
    admins; a budget-exempt DELETE of Contractors (scaled `MAX_JOB_MEMBERS` 4) then leaves a re-role job open."""
    monkeypatch.setattr(gdir, "MAX_JOB_MEMBERS", 4)
    stack.saml_org(ORG_A, scim_token=TOKEN_A, group_role_map={"Admins": "org_admin", "Contractors": "analyst"})
    xg, xonly = _seed(stack, ORG_A, 3, group="Contractors", role="analyst", prefix="c")
    ag, both = _seed(stack, ORG_A, 6, group="Admins", role="viewer", prefix="b")      # below what Admins implies
    _og, rest = _seed(stack, ORG_A, others, group="Staff", role="viewer", prefix="o")
    d = ScimDirectoryRegistry(stack.store()).directory(ORG_A)
    for u in both:
        d.add_member(xg, u, now=time.time())
    _overdraw(stack, monkeypatch)
    t0 = time.time()
    assert _scim(stack, ORG_A, "DELETE", f"/Groups/{xg}")["status"] == 204
    _assert_rerole_job(stack, xg, since_after=t0)
    return xg, xonly, ag, both, rest


def test_REROLE_HOLD_a_budget_exempt_request_does_no_plan_work_under_the_section(stack, monkeypatch):
    """REROLE-HOLD — while a re-role job is open, budget-exempt deprovisioning requests (a 404 DELETE of a nonexistent
    user; a group PATCH removing a non-member, the sibling shape) do NO plan work while holding the shared section:
    no staged copy of the directory, no re-role window scan, no member re-resolved under it (round 7 re-resolved
    EVERY member of the org inside the section on each such request). The job stays open for a budgeted write."""
    xg, _xonly, ag, _both, _rest = _rerole_org(stack, monkeypatch)
    job = _jobs(stack, ORG_A)[xg]
    n = _plan_work(monkeypatch)
    for _ in range(3):
        assert _scim(stack, ORG_A, "DELETE", f"/Users/sso_{'0' * 24}")["status"] == 404
    assert _scim(stack, ORG_A, "PATCH", f"/Groups/{ag}", {"Operations": [
        {"op": "remove", "path": f'members[value eq "sso_{"1" * 24}"]'}]})["status"] == 200
    assert (n["staged"], n["window"], n["target"]) == (0, 0, 0), n          # nothing O(org) under the section
    assert n["window_outside"] == 0 and n["target_outside"] == [], n        # nor a re-role resolve at all
    assert n["staged_outside"] == 1, n                  # only the PATCH's own plan: the gone group's job is skipped
    assert _jobs(stack, ORG_A) == {xg: job}                                  # still open (a budgeted write lands it)


def test_REROLE_HOLD_an_open_rerole_job_never_slows_an_unrelated_append(stack, monkeypatch):
    """REROLE-HOLD, cross-org — an unrelated append (another org's record through the same process-wide spine lock)
    runs while org A floods budget-exempt 404 DELETEs with a re-role job open: A's requests do no plan work under the
    section (the deterministic guard), and the unrelated appends are never held behind A for long (a loose absolute
    bound — the host may be loaded; round 7 held the lock O(org) per request: 0.58 s p50 at 40k users)."""
    _rerole_org(stack, monkeypatch, others=400)
    n = _plan_work(monkeypatch)
    stop = threading.Event()

    def flood():
        while not stop.is_set():
            _scim(stack, ORG_A, "DELETE", f"/Users/sso_{'0' * 24}")
    th = threading.Thread(target=flood, daemon=True)
    th.start()
    lat = []
    store = stack.store()
    try:
        time.sleep(0.2)
        for k in range(30):
            t0 = time.perf_counter()
            store.append(kind="message", source="x", actor="user", payload={"text": f"unrelated {k}"})
            lat.append(time.perf_counter() - t0)
            time.sleep(0.01)
    finally:
        stop.set()
        th.join(60)
    print(f"\nunrelated append during A's flood: p50 {statistics.median(lat) * 1000:.1f} ms, "
          f"max {max(lat) * 1000:.1f} ms")
    assert (n["staged"], n["window"], n["target"]) == (0, 0, 0), n
    assert max(lat) < 2.0, lat


def test_a_group_change_whose_org_changed_while_it_was_planned_is_refused_whole(stack, monkeypatch):
    """The plan of a group change runs with the section RELEASED (`_SharedSection.outside`), so it is re-checked when
    the section is re-taken: an owner act on one of the org's directory members landing meanwhile makes the request
    stop with a retryable 503, and nothing of the planned change is written (the group not renamed, no role moved)."""
    from sigil.ui import scim as uiscim
    stack.saml_org(ORG_A, scim_token=TOKEN_A, group_role_map={"Admins": "org_admin"})
    sg, uids = _seed(stack, ORG_A, 3, group="Staff", role="viewer", prefix="p")
    fired: list = []
    orig = uiscim._target

    def target(req, uid, *, create):
        if not create and not fired:                    # mid-plan: the owner changes a member by hand
            fired.append(provision.members_section_held())
            OrgRegistry(stack.store()).grant_membership(ORG_A, uids[0], "analyst", issued_at=time.time())
        return orig(req, uid, create=create)
    monkeypatch.setattr(uiscim, "_target", target)
    n0 = _n(stack)
    r = _scim(stack, ORG_A, "PATCH", f"/Groups/{sg}", {"Operations": [
        {"op": "replace", "path": "displayName", "value": "Admins"}]})
    assert r["status"] == 503 and fired == [False], (r, fired)      # planned outside the section, then refused
    assert ScimDirectoryRegistry(stack.store()).directory(ORG_A).group(sg).display_name == "Staff"
    assert _n(stack) == n0 + 1                                       # only the owner's own grant landed
    roles = _roles(stack, ORG_A)
    assert roles[uids[0]] == "analyst" and {roles[u] for u in uids[1:]} == {"viewer"}


def test_REROLE_HOLD_the_budgeted_close_of_a_rerole_job_resolves_only_its_window_outside_the_section(stack,
                                                                                                    monkeypatch):
    """The budgeted write that closes a re-role job resolves only the job's WINDOW (the deleted group's former
    members), all of it with the section released — never the org's other members, never under the section."""
    xg, xonly, _ag, both, rest = _rerole_org(stack, monkeypatch)
    n = _plan_work(monkeypatch)
    _repay(monkeypatch)
    assert _scim(stack, ORG_A, "POST", "/Users", _okta_user("q@acme.com", "00u-q"))["status"] == 201
    assert (n["staged"], n["window"], n["target"]) == (0, 0, 0), n
    assert n["window_outside"] >= 1 and set(n["target_outside"]) <= set(both) | set(xonly), n
    assert not set(n["target_outside"]) & set(rest), n                       # the rest of the org: never resolved
    roles = _roles(stack, ORG_A)
    assert {roles[u] for u in both} == {"org_admin"} and _jobs(stack, ORG_A) == {}
    _never_above_the_directory(stack, ORG_A)


def test_REROLE_HOLD_a_lower_only_resume_of_a_group_present_rerole_job_resolves_only_the_group(stack, monkeypatch):
    """A crash can leave a 'delete + re-role' job open while its group still EXISTS (the delete had not committed).
    A deprovisioning (lower_only) resume lands only the LOWERINGS the delete implies — its group's own members, with
    the section released — never the job's window of deferred raises, nor the rest of the org."""
    monkeypatch.setattr(gdir, "MAX_JOB_MEMBERS", 4)
    stack.saml_org(ORG_A, scim_token=TOKEN_A, group_role_map={"Admins": "org_admin", "Contractors": "analyst"})
    xg, xmembers = _seed(stack, ORG_A, 6, group="Contractors", role="analyst", prefix="c")
    _og, _others = _seed(stack, ORG_A, 60, group="Admins", role="org_admin", prefix="o")
    d = ScimDirectoryRegistry(stack.store()).directory(ORG_A)
    d.put_job(xg, {"delete": True, "rerole": True, "since": 0.0}, now=time.time())   # a group-present job (crash)
    assert _jobs(stack, ORG_A).get(xg) == {"delete": True, "rerole": True, "since": 0.0}
    n = _plan_work(monkeypatch)
    assert _scim(stack, ORG_A, "DELETE", f"/Users/sso_{'0' * 24}")["status"] == 404     # budget-exempt: resumes it
    assert (n["staged"], n["window"], n["target"]) == (0, 0, 0), n
    assert n["window_outside"] == 0 and set(n["target_outside"]) == set(xmembers), n
    assert {_roles(stack, ORG_A)[u] for u in xmembers} == {"viewer"}          # its lowerings landed
    assert ScimDirectoryRegistry(stack.store()).directory(ORG_A).group(xg) is not None     # the delete still waits


@pytest.mark.parametrize("bound", [4, 4096])
def test_REROLE_SCOPE_a_rerole_job_leaves_members_it_never_touched_alone(stack, monkeypatch, bound):
    """REROLE-SCOPE (the rvH7 reviewer's probe, promoted): an admin the owner lowered by hand on the Team screen BEFORE
    the deprovisioning request, and in no group it changed — or one who left the deleted group long before it — is
    NOT raised back when the re-role job is finished, exactly as with the touch list under the bound; the members the
    request deferred are raised (round 7's mark re-resolved every member of the org and reverted the demotions)."""
    monkeypatch.setattr(gdir, "MAX_JOB_MEMBERS", bound)
    stack.saml_org(ORG_A, scim_token=TOKEN_A, group_role_map={"Admins": "org_admin", "Contractors": "analyst"})
    xg, _x = _seed(stack, ORG_A, 3, group="Contractors", role="analyst", prefix="c")
    _ag, both = _seed(stack, ORG_A, 6, group="Admins", role="viewer", prefix="b")
    _g2, (bystander, old) = _seed(stack, ORG_A, 2, group="Admins", role="org_admin", prefix="z")
    d = ScimDirectoryRegistry(stack.store()).directory(ORG_A)
    for u in both:
        d.add_member(xg, u, now=time.time())
    d.add_member(xg, old, now=time.time())              # `old` left Contractors long BEFORE the request ...
    d.remove_member(xg, old, now=time.time())
    for u in (bystander, old):                          # ... and the owner lowered both admins by hand
        OrgRegistry(stack.store()).grant_membership(ORG_A, u, "viewer", issued_at=time.time())
    _overdraw(stack, monkeypatch)
    assert _scim(stack, ORG_A, "DELETE", f"/Groups/{xg}")["status"] == 204
    job = _jobs(stack, ORG_A)[xg]
    assert (job.get("rerole") is True) == (bound == 4) and (bound == 4 or len(job["touch"]) == 6), job
    _repay(monkeypatch)
    assert _scim(stack, ORG_A, "POST", "/Users", _okta_user("q@acme.com", "00u-q"))["status"] == 201
    roles = _roles(stack, ORG_A)
    assert roles[bystander] == "viewer" and roles[old] == "viewer", roles      # the owner's demotions stand
    assert {roles[u] for u in both} == {"org_admin"} and _jobs(stack, ORG_A) == {}
    _never_above_the_directory(stack, ORG_A)


def test_REROLE_SCOPE_an_owner_change_after_the_job_is_not_reverted_by_it(stack, monkeypatch):
    """REROLE-SCOPE — a deferred member the owner changes by hand AFTER the job opened keeps the owner's role when the
    job is finished (its live grant is newer than the job); the other deferred members are still raised."""
    _xg, _xonly, _ag, both, _rest = _rerole_org(stack, monkeypatch)
    OrgRegistry(stack.store()).grant_membership(ORG_A, both[0], "analyst", issued_at=time.time())   # AFTER the job
    _repay(monkeypatch)
    assert _scim(stack, ORG_A, "POST", "/Users", _okta_user("q@acme.com", "00u-q"))["status"] == 201
    roles = _roles(stack, ORG_A)
    assert roles[both[0]] == "analyst", roles[both[0]]                         # the owner's later change stands
    assert {roles[u] for u in both[1:]} == {"org_admin"} and _jobs(stack, ORG_A) == {}
    _never_above_the_directory(stack, ORG_A)


def test_REROLE_SCOPE_a_listed_job_that_overflows_into_a_window_keeps_its_listed_members(stack, monkeypatch):
    """Two deprovisioning removals from one group: the first defers 3 raises (a listed job), the second 3 more — 6,
    more than a job may list (scaled 4), so the job becomes a re-role WINDOW (from the second removal on) that still
    LISTS the first three. The next budgeted write raises all six; an admin no removal touched (the owner lowered
    them by hand) stays as the owner set them."""
    monkeypatch.setattr(gdir, "MAX_JOB_MEMBERS", 4)
    stack.saml_org(ORG_A, scim_token=TOKEN_A, group_role_map={"Admins": "org_admin", "Contractors": "analyst"})
    xg, _none = _seed(stack, ORG_A, 0, group="Contractors", role="analyst", prefix="c")
    _ag, both = _seed(stack, ORG_A, 6, group="Admins", role="viewer", prefix="b")
    _g2, (bystander,) = _seed(stack, ORG_A, 1, group="Admins", role="viewer", prefix="z")
    d = ScimDirectoryRegistry(stack.store()).directory(ORG_A)
    for u in both:
        d.add_member(xg, u, now=time.time())
    _overdraw(stack, monkeypatch)
    for half in (both[:3], both[3:]):
        assert _scim(stack, ORG_A, "PATCH", f"/Groups/{xg}", {"Operations": [
            {"op": "remove", "path": "members", "value": [{"value": u} for u in half]}]})["status"] == 200
    job = _jobs(stack, ORG_A)[xg]
    assert job.get("rerole") is True and job.get("touch") == sorted(both[:3]), job
    assert {_roles(stack, ORG_A)[u] for u in both} == {"viewer"}              # every raise deferred so far
    _repay(monkeypatch)
    assert _scim(stack, ORG_A, "POST", "/Users", _okta_user("q@acme.com", "00u-q"))["status"] == 201
    roles = _roles(stack, ORG_A)
    assert {roles[u] for u in both} == {"org_admin"} and roles[bystander] == "viewer" and _jobs(stack, ORG_A) == {}
    _never_above_the_directory(stack, ORG_A)


def test_a_rerole_jobs_window_start_is_validated():
    """A re-role job's window start `since` is a finite issued_at >= 0 (0.0 when absent): anything else makes the
    record malformed (inert)."""
    spec = {"delete": True, "rerole": True}
    assert gdir._job_from(spec) == {"delete": True, "rerole": True, "since": 0.0}
    assert gdir._job_from({**spec, "since": 12.5}) == {"delete": True, "rerole": True, "since": 12.5}
    for bad in (-1.0, float("nan"), float("inf"), True, "12", None):
        assert gdir._job_from({**spec, "since": bad}) is None, bad
    assert gdir._job_from({"delete": False, "name": "G", "ext": "", "members": [], "rerole": True, "since": 3.0}) == \
        {"delete": False, "name": "G", "ext": "", "members": [], "rerole": True, "since": 3.0}


def test_MUT_an_in_use_per_org_sso_share_survives_eviction():
    """Mutation gap — a per-org SSO share that is currently referenced is NEVER evicted, even when more than the cap of
    other org ids are named: a second leg of the held org still waits on the SAME semaphore."""
    sso_provision._SSO_ORG_GATES.clear()
    try:
        with sso_provision._sso_org_semaphore_ref("org_held") as held:
            for i in range(sso_provision._SSO_ORG_GATES_MAX + 50):
                with sso_provision._sso_org_semaphore_ref(f"org_evict_{i}"):
                    pass
            assert sso_provision._sso_org_semaphore("org_held") is held      # not evicted while referenced
    finally:
        sso_provision._SSO_ORG_GATES.clear()


def test_MUT_the_sso_failure_lockout_doubles_each_time():
    """Mutation gap — the SSO failure lockout DOUBLES on each successive lockout (60s, 120, 240, ... up to the cap), so
    a repeat offender is held longer each time."""
    fl = sso_provision._FailLock(max_fails=3, window_s=10_000.0, base_lock_s=60.0, max_lock_s=3600.0)
    t, locks = 0.0, []
    for _round in range(8):
        for _ in range(3):
            fl.record_failure(("s", "x"), now=t)
        w = fl.locked(("s", "x"), now=t)
        locks.append(round(w))
        t += w + 1
    assert locks == [60, 120, 240, 480, 960, 1920, 3600, 3600], locks


def test_MUT_a_partial_reap_decrements_the_bucket_count(tmp_path):
    """Mutation gap — when `_reap` stops at its limit PART-WAY through a bucket (the bucket is not removed), the
    in-memory per-bucket count is decremented for every marker it unlinked, so `total()` reflects what was removed."""
    led = uisaml.SamlReplayLedger(tmp_path / "replay", max_outstanding=10 ** 6)
    now = 1_000_000_000.0
    dead = int(now // led._BUCKET_S) - 10
    _fill(led, "org", dead, 100)
    part = led._partition("org")
    state = led._state(part)
    assert state.buckets.get(dead) == 100
    assert led._reap(part, state, now, 30) == 30                     # stop part-way: 30 of 100, bucket NOT removed
    assert state.buckets.get(dead) == 70, state.buckets.get(dead)    # 100 - 30 unlinked, decremented
    assert led._bucket_dir(part, dead).exists()                      # the bucket itself is still there
