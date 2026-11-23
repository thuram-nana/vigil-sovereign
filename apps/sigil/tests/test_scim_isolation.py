"""PR-H — one organization cannot make the SHARED membership critical section stall another organization.

Every membership change commits inside one section shared by every org (`ui.sso_provision._membership_section`: the
process-wide spine lock, then the cross-process membership flock). These tests pin what one org's valid SCIM token
can make that section do, through the real provisioner (`sso_provision.scim_request` over `build_provisioner`, as
the cockpit runs it per request):

  * BOUNDED HOLDS — a request appends at most `ui.scim.MAX_RECORDS_PER_HOLD` records per hold of the spine lock,
    measured per acquisition with an instrumented lock; a rename that re-roles a whole group, and the delete of a
    3,000-member mapped group, still land every member at the right role;
  * DURABLE, RESUMABLE — a group change cut short between two holds leaves no member above the role the directory
    then implies, and the org's next SCIM write (or sign-in) finishes it; a concurrent change of the org's
    membership state between two holds stops the request rather than overwrite it;
  * PER-ORG SERIALIZATION — concurrent writes of one org are admitted one at a time against the budget, which is
    charged in a `finally` (also when an audit write fails part-way); another org never waits on that lock;
  * READS — a SCIM GET never takes the spine lock or the membership flock, has its own per-org budget, and a storm of
    one org's reads does not stall another org's write;
  * DEPROVISIONING — a request that can only take privilege away is admitted while the org is over its write budget.
"""
from __future__ import annotations

import json
import threading
import time
from pathlib import Path

import pytest

import test_sso_edge as edge
from test_custui import _scrub_shared_owner_state  # noqa: F401  (autouse: keep the shared SIGIL_HOME pristine)
from test_sso_edge import ORG_A, ORG_B, TOKEN_A, TOKEN_B, _FailingAudit, _okta_user, _saml_sign_in

from sigil import config
from sigil.governor import scim as gscim
from sigil.governor.orgs import OrgRegistry
from sigil.governor.scim_directory import ScimDirectoryRegistry
from sigil.spine import store as spine_store
from sigil.spine.store import SpineStore
from sigil.ui import saml as uisaml
from sigil.ui import scim as uiscim
from sigil.ui import sso_provision
from sigil.ui.provision import _members_lock, build_provisioner

_TOKENS = {ORG_A: TOKEN_A, ORG_B: TOKEN_B}


@pytest.fixture
def stack(tmp_path, monkeypatch):
    """The cockpit + customer edge of `test_sso_edge` (owner key, isolated ledgers); most tests below call the
    provisioner directly (`_scim`), as the cockpit does per request."""
    s = edge.Stack(tmp_path, monkeypatch)
    yield s
    s.close()


@pytest.fixture
def signed(monkeypatch):
    monkeypatch.setattr(uisaml, "signxml_sig_verifier", edge._toy_xmldsig_verifier)


def _scim(stack, org: str, method: str, path: str, body=None, *, ip: str = "203.0.113.10") -> dict:
    """One SCIM request through a FRESH provisioner (as the cockpit builds one per request), in this thread."""
    return sso_provision.scim_request(build_provisioner(stack.store()), org, method=method,
                                      path=f"/scim/v2/{org}{path}", body=body,
                                      authorization=f"Bearer {_TOKENS[org]}", ip=ip)


def _seed(stack, org: str, n: int, *, group: str = "", role: str = "viewer", prefix: str = "s") -> "tuple[str, list]":
    """`n` directory users of `org` holding `role`, in a new group named `group` (none when ""): state earlier,
    separately budgeted writes would have paid for, written directly (fast)."""
    cfg = stack.cfg().config(org)
    d = ScimDirectoryRegistry(stack.store()).directory(org)
    orgs = stack.orgs()
    gid = ""
    t = time.time()
    if group:
        gid = "grp_" + format(abs(hash((org, group, prefix))) % (16 ** 24), "024x")
        d.put_group(gid, display_name=group, now=t)
    uids = []
    for i in range(n):
        uid = gscim.sso_username(cfg, f"{prefix}-ext{i}")
        at = t + (i + 1) * 1e-3
        d.put_user(uid, user_name=f"{prefix}{i}@{org}.example", external_id=f"{prefix}-ext{i}", active=True, now=at)
        orgs._append_active_membership(org, uid, role, issued_at=at)
        if gid:
            d.add_member(gid, uid, now=at)
        uids.append(uid)
    return gid, uids


def _roles(stack, org: str) -> dict:
    return {m.username: m.role for m in stack.orgs().memberships(org)}


def _implied(stack, org: str) -> dict:
    """The role the CURRENT directory + owner-signed config imply for every active directory user of `org`."""
    cfg = stack.cfg().config(org)
    d = ScimDirectoryRegistry(stack.store()).directory(org)
    return {u.id: uiscim._directory_role(cfg, d, u) for u in d.users() if u.active}


def _never_above_the_directory(stack, org: str) -> None:
    rank = gscim._provision_rank
    implied, roles = _implied(stack, org), _roles(stack, org)
    above = {u: (r, implied.get(u)) for u, r in roles.items() if u.startswith("sso_")
             and r in gscim.SCIM_PROVISIONABLE_ROLES and (implied.get(u) is None or rank(r) > rank(implied[u]))}
    assert above == {}, above


def _jobs(stack, org: str) -> dict:
    return ScimDirectoryRegistry(stack.store()).directory(org).jobs()


def _n(stack) -> int:
    return sum(1 for _ in stack.store().iter_records())


class _HoldMeter:
    """The process-wide spine lock of the stack's spine, instrumented: each OUTERMOST hold records how many spine
    records were appended while it was held, and by which thread. Installed in `spine_store._LOCKS`, so every
    provisioner built afterwards (`p._lock = spine_lock(path)`) and every `SpineStore.append` uses it."""

    def __init__(self) -> None:
        self._lk = threading.RLock()
        self._tls = threading.local()
        self._guard = threading.Lock()
        self.holds: "list[tuple[str, int]]" = []
        self.acquired_by: "set[str]" = set()

    def acquire(self, blocking: bool = True, timeout: float = -1) -> bool:
        ok = self._lk.acquire(blocking, timeout)
        if ok:
            d = getattr(self._tls, "depth", 0)
            if d == 0:
                self._tls.count = 0
                with self._guard:
                    self.acquired_by.add(threading.current_thread().name)
            self._tls.depth = d + 1
        return ok

    def release(self) -> None:
        self._tls.depth -= 1
        if self._tls.depth == 0:
            with self._guard:
                self.holds.append((threading.current_thread().name, self._tls.count))
        self._lk.release()

    def __enter__(self):
        self.acquire()
        return self

    def __exit__(self, *_exc) -> None:
        self.release()

    def _is_owned(self) -> bool:
        return getattr(self._tls, "depth", 0) > 0

    def note_append(self) -> None:
        if self._is_owned():
            self._tls.count += 1

    def max_hold(self, thread: str) -> int:
        return max((c for t, c in self.holds if t == thread), default=0)

    def hold_count(self, thread: str) -> int:
        return sum(1 for t, c in self.holds if t == thread and c > 0)


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


def _in_thread(name: str, fn) -> "tuple[threading.Thread, dict]":
    out: dict = {}

    def run():
        try:
            out["r"] = fn()
        except BaseException as e:  # noqa: BLE001 — surfaced by the test
            out["e"] = e
    t = threading.Thread(target=run, name=name)
    t.start()
    return t, out


# =====================================================================================================================
# F1 — BOUNDED HOLDS: a rename / a large deprovision is paced in holds of at most MAX_RECORDS_PER_HOLD records
# =====================================================================================================================
def test_the_hold_bound_is_pinned():
    assert uiscim.MAX_RECORDS_PER_HOLD == 128
    assert uiscim.MAX_DIRECTORY_WRITES == uiscim.MAX_MEMBER_VALUES + 16 == 1016


def test_a_rename_that_re_roles_a_whole_group_never_holds_the_spine_lock_past_the_bound(stack, meter, monkeypatch):
    """A one-operation rename onto a role mapping re-roles EVERY member (two records each). It never appends more than
    the bound while holding the spine lock; it lands in many holds; every member ends at the mapped role — and the
    rename back off the mapping lowers them all again, bounded the same way."""
    monkeypatch.setattr(uiscim, "MAX_RECORDS_PER_HOLD", 16)
    stack.saml_org(ORG_A, scim_token=TOKEN_A)
    gid, uids = _seed(stack, ORG_A, 120, group="Plain")
    t, out = _in_thread("org-a-rename", lambda: _scim(stack, ORG_A, "PATCH", f"/Groups/{gid}", {
        "Operations": [{"op": "replace", "path": "displayName", "value": "Admins"}]}))
    t.join(120)
    assert out["r"]["status"] == 200, out
    assert meter.max_hold("org-a-rename") <= 16
    assert meter.hold_count("org-a-rename") >= (2 * 120) // 16
    assert {u: r for u, r in _roles(stack, ORG_A).items() if u in uids} == {u: "org_admin" for u in uids}
    assert _jobs(stack, ORG_A) == {}                      # the durable job it opened is closed
    t, out = _in_thread("org-a-rename-off", lambda: _scim(stack, ORG_A, "PUT", f"/Groups/{gid}", {
        "displayName": "Staff", "members": [{"value": u} for u in uids]}))
    t.join(120)
    assert out["r"]["status"] == 200, out
    assert meter.max_hold("org-a-rename-off") <= 16 and meter.hold_count("org-a-rename-off") >= 15
    assert {u: r for u, r in _roles(stack, ORG_A).items() if u in uids} == {u: "viewer" for u in uids}
    _never_above_the_directory(stack, ORG_A)


def test_another_orgs_write_lands_between_the_holds_of_a_long_rename(stack, meter, monkeypatch):
    """While org A's long rename is in flight (released between holds), org B's write is answered — it does not wait
    for org A's request to finish."""
    monkeypatch.setattr(uiscim, "MAX_RECORDS_PER_HOLD", 16)
    stack.saml_org(ORG_A, scim_token=TOKEN_A)
    stack.saml_org(ORG_B, scim_token=TOKEN_B)
    gid, uids = _seed(stack, ORG_A, 400, group="Plain")
    a, out_a = _in_thread("org-a", lambda: _scim(stack, ORG_A, "PATCH", f"/Groups/{gid}", {
        "Operations": [{"op": "replace", "path": "displayName", "value": "Admins"}]}))
    deadline = time.time() + 60
    while meter.hold_count("org-a") < 2 and time.time() < deadline:
        time.sleep(0.01)
    b, out_b = _in_thread("org-b", lambda: _scim(stack, ORG_B, "POST", "/Users", _okta_user("b@beta.com", "00u-b")))
    b.join(60)
    a_still_running = a.is_alive()
    a.join(300)
    assert out_b["r"]["status"] == 201 and out_a["r"]["status"] == 200, (out_a, out_b)
    assert a_still_running, "org B's write waited for org A's whole request"
    roles = _roles(stack, ORG_A)
    assert {roles[u] for u in uids} == {"org_admin"}


def test_a_delete_of_a_3000_member_mapped_group_lowers_everyone_in_bounded_holds(stack, meter):
    """The real bound (not monkeypatched): the delete of a 3,000-member mapped group — legitimate deprovisioning,
    about 9,000 records — succeeds, lowers every member, and never holds the spine lock for more than the bound."""
    stack.saml_org(ORG_A, scim_token=TOKEN_A)
    gid, uids = _seed(stack, ORG_A, 3000, group="Admins", role="org_admin")
    t, out = _in_thread("org-a-delete", lambda: _scim(stack, ORG_A, "DELETE", f"/Groups/{gid}"))
    t.join(600)
    assert out["r"]["status"] == 204, out
    assert meter.max_hold("org-a-delete") <= uiscim.MAX_RECORDS_PER_HOLD
    assert meter.hold_count("org-a-delete") >= 9000 // uiscim.MAX_RECORDS_PER_HOLD
    roles = _roles(stack, ORG_A)
    assert {roles[u] for u in uids} == {"viewer"}
    assert _jobs(stack, ORG_A) == {} and ScimDirectoryRegistry(stack.store()).directory(ORG_A).group(gid) is None


# =====================================================================================================================
# F1 — DURABLE, RESUMABLE: a change cut short between two holds never leaves a role above the directory, and the
# org's next write or sign-in finishes it
# =====================================================================================================================
def _cut_after(monkeypatch, holds: int) -> dict:
    """Make the shared section refuse to be re-taken after `holds` slices (as a crash / a busy flock would stop the
    request between two holds). Returns a switch: set ["on"] = False to let requests run normally again."""
    state = {"on": True, "n": 0}
    orig = sso_provision._SharedSection.slice

    def slice_(self):
        state["n"] += 1
        if state["on"] and state["n"] > holds:
            self._exit()
            raise uiscim.SectionLost("cut short (test)")
        return orig(self)
    monkeypatch.setattr(sso_provision._SharedSection, "slice", slice_)
    return state


@pytest.mark.parametrize("direction", ["raise", "lower"])
def test_a_group_change_cut_short_is_finished_by_the_next_write(stack, monkeypatch, direction):
    """A rename cut short after a few holds: the request answers a retryable error, no member is above the role the
    directory then implies (a raise lands after the directory; a downgrade before it), the durable job is open — and
    the org's next, unrelated write finishes it: every member at the role the rename implies, the job closed."""
    monkeypatch.setattr(uiscim, "MAX_RECORDS_PER_HOLD", 16)
    stack.saml_org(ORG_A, scim_token=TOKEN_A)
    start, end, want = ("Plain", "Admins", "org_admin") if direction == "raise" else ("Admins", "Staff", "viewer")
    gid, uids = _seed(stack, ORG_A, 100, group=start, role="viewer" if direction == "raise" else "org_admin")
    cut = _cut_after(monkeypatch, 3)
    r = _scim(stack, ORG_A, "PATCH", f"/Groups/{gid}", {"Operations": [
        {"op": "replace", "path": "displayName", "value": end}]})
    assert r["status"] == 503, r
    roles = _roles(stack, ORG_A)
    moved = sum(1 for u in uids if roles[u] == want)
    assert 0 < moved < len(uids)                                    # it really stopped part-way
    assert list(_jobs(stack, ORG_A)) == [gid]
    _never_above_the_directory(stack, ORG_A)
    cut["on"] = False
    nxt = _scim(stack, ORG_A, "POST", "/Users", _okta_user("new@acme.com", "00u-new"))
    assert nxt["status"] == 201, nxt
    roles = _roles(stack, ORG_A)
    assert {roles[u] for u in uids} == {want} and _jobs(stack, ORG_A) == {}
    g = ScimDirectoryRegistry(stack.store()).directory(ORG_A).group(gid)
    assert g is not None and g.display_name == end
    _never_above_the_directory(stack, ORG_A)


def test_a_group_change_cut_short_is_finished_by_the_next_sign_in(stack, signed, monkeypatch):
    """As above, finished instead by a sign-in of the org (before the person is admitted)."""
    monkeypatch.setattr(uiscim, "MAX_RECORDS_PER_HOLD", 16)
    stack.saml_org(ORG_A, scim_token=TOKEN_A)
    gid, uids = _seed(stack, ORG_A, 60, group="Admins", role="org_admin")
    cut = _cut_after(monkeypatch, 2)
    r = _scim(stack, ORG_A, "DELETE", f"/Groups/{gid}")
    assert r["status"] == 503 and list(_jobs(stack, ORG_A)) == [gid], r
    _never_above_the_directory(stack, ORG_A)
    cut["on"] = False
    _cookie, who = _saml_sign_in(stack, ORG_A, name_id="s0@" + ORG_A + ".example")
    assert who == uids[0]
    roles = _roles(stack, ORG_A)
    assert {roles[u] for u in uids} == {"viewer"} and _jobs(stack, ORG_A) == {}
    assert ScimDirectoryRegistry(stack.store()).directory(ORG_A).group(gid) is None


def test_a_concurrent_change_of_the_orgs_state_between_holds_stops_the_request(stack, monkeypatch):
    """An owner act on the org lands while a long rename is released between two holds (here: the owner raises one
    member by hand to founder). The rename stops instead of acting on what it folded before — so it never overwrites
    the owner's role — and the next write finishes the job around it."""
    monkeypatch.setattr(uiscim, "MAX_RECORDS_PER_HOLD", 16)
    stack.saml_org(ORG_A, scim_token=TOKEN_A)
    gid, uids = _seed(stack, ORG_A, 80, group="Plain")
    target = uids[-1]                                   # re-roled last, so its planned raise has not landed yet
    done = {"v": False}
    orig = sso_provision._handoff

    def handoff():
        orig()
        if not done["v"]:
            done["v"] = True
            OrgRegistry(stack.store()).grant_membership(ORG_A, target, "founder", issued_at=time.time())
    monkeypatch.setattr(sso_provision, "_handoff", handoff)
    r = _scim(stack, ORG_A, "PATCH", f"/Groups/{gid}", {"Operations": [
        {"op": "replace", "path": "displayName", "value": "Admins"}]})
    assert done["v"] and r["status"] == 503, r
    assert stack.role(target, ORG_A) == "founder"
    assert _scim(stack, ORG_A, "POST", "/Users", _okta_user("n@acme.com", "00u-n"))["status"] == 201
    roles = _roles(stack, ORG_A)
    assert roles[target] == "founder"                   # an owner-set role outside the ceiling is never re-granted
    assert {roles[u] for u in uids if u != target} == {"org_admin"} and _jobs(stack, ORG_A) == {}


# =====================================================================================================================
# F2 — PER-ORG SERIALIZATION: concurrent writes of one org are admitted one at a time against the budget
# =====================================================================================================================
def _burst(stack, monkeypatch, *, concurrent: bool, budget: int, k: int, users: int) -> "tuple[list, int]":
    monkeypatch.setattr(config, "SCIM_OPS_PER_MIN", 10 ** 6)
    stack.saml_org(ORG_A, scim_token=TOKEN_A)
    _gid, ids = _seed(stack, ORG_A, users)
    gids = [_scim(stack, ORG_A, "POST", "/Groups", {"displayName": f"Plain{j}"})["body"]["id"] for j in range(k)]
    import shutil
    shutil.rmtree(config.SCIM_WRITE_RATELIMIT_DIR, ignore_errors=True)
    monkeypatch.setattr(config, "SCIM_OPS_PER_MIN", budget)
    before = _n(stack)
    body = {"Operations": [{"op": "add", "path": "members", "value": [{"value": u} for u in ids]}]}
    out: list = [None] * k

    def go(j):
        out[j] = _scim(stack, ORG_A, "PATCH", f"/Groups/{gids[j]}", body)["status"]
    if concurrent:
        ths = [threading.Thread(target=go, args=(j,)) for j in range(k)]
        for t in ths:
            t.start()
        for t in ths:
            t.join(300)
    else:
        for j in range(k):
            go(j)
    return out, _n(stack) - before


@pytest.mark.parametrize("concurrent", [False, True])
def test_concurrent_writes_of_one_org_are_refused_once_the_budget_is_spent(stack, monkeypatch, concurrent):
    """8 writes of 40 records each against a budget of 10 records a minute: sent one after another OR all at once,
    exactly one is admitted and the org appends one request's worth — never all eight admitted before any charge."""
    out, wrote = _burst(stack, monkeypatch, concurrent=concurrent, budget=10, k=8, users=40)
    assert out.count(200) == 1 and set(out) <= {200, 429}, out
    assert wrote <= 40, (out, wrote)


def test_concurrent_writes_at_the_default_budget_stay_within_it(stack, monkeypatch):
    """The reviewer's shape at the SHIPPED default: 12 concurrent 300-member group creates on mapped groups (~901
    records each) append at most one minute's budget plus one request."""
    default = config.SCIM_OPS_PER_MIN
    monkeypatch.setattr(config, "SCIM_OPS_PER_MIN", 10 ** 6)
    stack.saml_org(ORG_A, scim_token=TOKEN_A, group_role_map={f"Adm{j}": "org_admin" for j in range(12)})
    _gid, ids = _seed(stack, ORG_A, 300)
    import shutil
    shutil.rmtree(config.SCIM_WRITE_RATELIMIT_DIR, ignore_errors=True)
    monkeypatch.setattr(config, "SCIM_OPS_PER_MIN", default)
    before = _n(stack)
    out: list = [None] * 12

    def go(j):
        out[j] = _scim(stack, ORG_A, "POST", "/Groups", {"displayName": f"Adm{j}",
                                                         "members": [{"value": u} for u in ids]})["status"]
    ths = [threading.Thread(target=go, args=(j,)) for j in range(12)]
    for t in ths:
        t.start()
    for t in ths:
        t.join(600)
    wrote = _n(stack) - before
    assert set(out) <= {201, 429} and out.count(429) >= 1, out
    assert wrote <= default + 1000, (out, wrote)                # one minute's budget plus at most one request


def test_another_org_never_waits_on_an_orgs_own_lock(stack, monkeypatch):
    """While org A's own write lock is held (a long request of org A), org B's write and read are answered at once,
    and org A's next write is refused 429 after the bounded wait — nothing written."""
    monkeypatch.setattr(sso_provision, "_ORG_LOCK_WAIT_S", 0.3)
    stack.saml_org(ORG_A, scim_token=TOKEN_A)
    stack.saml_org(ORG_B, scim_token=TOKEN_B)
    p = build_provisioner(stack.store())
    with sso_provision._org_lock(p, ORG_A, "write"):
        t0 = time.time()
        assert _scim(stack, ORG_B, "POST", "/Users", _okta_user("b@beta.com", "00u-b"))["status"] == 201
        assert _scim(stack, ORG_B, "GET", "/Users")["status"] == 200
        assert time.time() - t0 < 5.0
        before = _n(stack)
        busy = _scim(stack, ORG_A, "POST", "/Users", _okta_user("a@acme.com", "00u-a"))
        assert busy["status"] == 429 and busy["retry_after"] >= 1 and _n(stack) == before
        assert _scim(stack, ORG_A, "GET", "/Users")["status"] == 200          # reads have their own lock
    assert _scim(stack, ORG_A, "POST", "/Users", _okta_user("a@acme.com", "00u-a"))["status"] == 201
    with sso_provision._org_lock(p, ORG_A, "read"):                 # one read of an org at a time
        assert _scim(stack, ORG_A, "GET", "/Users")["status"] == 429
        assert _scim(stack, ORG_B, "GET", "/Users")["status"] == 200
        assert _scim(stack, ORG_A, "POST", "/Users", _okta_user("c@acme.com", "00u-c"))["status"] == 201


def _watch_folds(monkeypatch, meter, on_first=None) -> list:
    """Record, for every fold of a request's memberships (`ui.scim._RequestOrgs`), whether the folding thread held
    the spine lock; run `on_first()` right after the first fold (a change landing while the request folds)."""
    seen: list = []
    orig = uiscim._RequestOrgs.__init__

    def init(self, base, org_id):
        orig(self, base, org_id)
        seen.append(meter._is_owned())
        if on_first is not None and len(seen) == 1:
            on_first()
    monkeypatch.setattr(uiscim._RequestOrgs, "__init__", init)
    return seen


def test_a_write_folds_outside_the_shared_section(stack, meter, monkeypatch):
    stack.saml_org(ORG_A, scim_token=TOKEN_A)
    seen = _watch_folds(monkeypatch, meter)
    assert _scim(stack, ORG_A, "POST", "/Users", _okta_user("a@acme.com", "00u-a"))["status"] == 201
    assert seen == [False]


def test_a_change_of_the_orgs_state_during_the_fold_is_re_folded(stack, meter, monkeypatch):
    """The owner raises a member by hand to founder while a group write is folding (outside the section): on entry
    the write sees the org's state moved, folds again, and so never re-grants over the owner's role."""
    stack.saml_org(ORG_A, scim_token=TOKEN_A)
    gid, (uid,) = _seed(stack, ORG_A, 1, group="Plain")
    seen = _watch_folds(monkeypatch, meter, on_first=lambda: OrgRegistry(stack.store()).grant_membership(
        ORG_A, uid, "founder", issued_at=time.time()))
    r = _scim(stack, ORG_A, "PATCH", f"/Groups/{gid}", {"Operations": [
        {"op": "replace", "path": "displayName", "value": "Admins"}]})
    assert r["status"] == 200 and len(seen) == 2, (r, seen)
    assert stack.role(uid, ORG_A) == "founder"


# =====================================================================================================================
# F3 — READS never enter the shared section, have their own per-org budget, and cannot starve another org's write
# =====================================================================================================================
def test_a_scim_read_never_takes_the_spine_lock_or_the_membership_flock(stack, meter):
    stack.saml_org(ORG_A, scim_token=TOKEN_A)
    gid, _uids = _seed(stack, ORG_A, 20, group="Plain")
    held = threading.Event()
    release = threading.Event()

    def hold():
        with meter, _members_lock(stack.store()):        # the whole shared section, held by another thread
            held.set()
            release.wait(30)
    h = threading.Thread(target=hold, name="holder")
    h.start()
    try:
        assert held.wait(10)
        for path, q in (("/Users", ""), (f"/Groups/{gid}", ""), ("/Groups", "")):
            t, out = _in_thread("org-a-read", lambda path=path: _scim(stack, ORG_A, "GET", path))
            t.join(10)
            assert not t.is_alive() and out["r"]["status"] == 200, (path, out)
    finally:
        release.set()
        h.join(30)
    assert "org-a-read" not in meter.acquired_by


def test_scim_reads_have_a_per_org_budget(stack, monkeypatch):
    monkeypatch.setattr(config, "SCIM_READS_PER_MIN", 3)
    stack.saml_org(ORG_A, scim_token=TOKEN_A)
    stack.saml_org(ORG_B, scim_token=TOKEN_B)
    assert [_scim(stack, ORG_A, "GET", "/Users")["status"] for _ in range(3)] == [200, 200, 200]
    over = _scim(stack, ORG_A, "GET", "/Users")
    assert over["status"] == 429 and over["retry_after"] >= 1
    assert over["body"]["schemas"] == ["urn:ietf:params:scim:api:messages:2.0:Error"]
    assert _scim(stack, ORG_B, "GET", "/Users")["status"] == 200             # another org's reads are its own
    assert _scim(stack, ORG_A, "POST", "/Users", _okta_user("a@acme.com", "00u-a"))["status"] == 201   # writes too


def test_a_storm_of_one_orgs_reads_does_not_stall_another_orgs_write(stack):
    """The reviewer's shape: 8 threads of org A GETs over a large directory while org B makes one write. Org A's
    reads run one at a time outside the shared section, so org B's write is not held hostage."""
    stack.saml_org(ORG_A, scim_token=TOKEN_A)
    stack.saml_org(ORG_B, scim_token=TOKEN_B)
    _seed(stack, ORG_A, 1500)
    t0 = time.time()
    assert _scim(stack, ORG_B, "POST", "/Users", _okta_user("calm@beta.com", "00u-calm"))["status"] == 201
    calm = time.time() - t0
    stop = threading.Event()
    gets = [0]

    def spam():
        while not stop.is_set():
            _scim(stack, ORG_A, "GET", "/Users", ip="198.51.100.7")
            gets[0] += 1
    ths = [threading.Thread(target=spam, daemon=True) for _ in range(8)]
    for t in ths:
        t.start()
    time.sleep(2)
    t1 = time.time()
    st = _scim(stack, ORG_B, "POST", "/Users", _okta_user("busy@beta.com", "00u-busy"))["status"]
    busy = time.time() - t1
    stop.set()
    for t in ths:
        t.join(120)
    assert st == 201 and gets[0] > 0
    assert busy < 5 * max(calm, 1.0), (calm, busy)


# =====================================================================================================================
# F4 — a request that can only take privilege away is never held off by write debt
# =====================================================================================================================
_DEACT_OKTA = {"Operations": [{"op": "replace", "value": {"active": False}}]}
_DEACT_ENTRA = {"Operations": [{"op": "Replace", "path": "active", "value": "False"}]}


@pytest.mark.parametrize("method,path,body,want", [
    ("DELETE", "/Users/sso_" + "1" * 24, None, True),
    ("DELETE", "/Groups/grp_" + "1" * 24, None, True),
    ("PATCH", "/Users/sso_" + "1" * 24, _DEACT_OKTA, True),
    ("PATCH", "/Users/sso_" + "1" * 24, _DEACT_ENTRA, True),
    ("PUT", "/Users/sso_" + "1" * 24, {"userName": "a", "active": False}, True),
    ("PATCH", "/Groups/grp_" + "1" * 24, {"Operations": [{"op": "remove", "path": "members"}]}, True),
    ("PATCH", "/Groups/grp_" + "1" * 24, {"Operations": [
        {"op": "remove", "path": 'members[value eq "sso_' + "1" * 24 + '"]'},
        {"op": "Remove", "path": "members", "value": [{"value": "sso_" + "2" * 24}]}]}, True),
    # anything that can grant, or that is not purely a removal, stays budgeted
    ("PATCH", "/Users/sso_" + "1" * 24, {"Operations": [{"op": "replace", "value": {"active": True}}]}, False),
    ("PATCH", "/Users/sso_" + "1" * 24, {"Operations": [
        {"op": "replace", "value": {"active": False, "roles": [{"value": "Admins"}]}}]}, False),
    ("PATCH", "/Users/sso_" + "1" * 24, {"Operations": [
        {"op": "replace", "path": "active", "value": False},
        {"op": "replace", "path": "active", "value": True}]}, False),
    ("PATCH", "/Users/sso_" + "1" * 24, {"Operations": [{"op": "remove", "path": "active"}]}, False),
    ("PUT", "/Users/sso_" + "1" * 24, {"userName": "a"}, False),
    ("PATCH", "/Groups/grp_" + "1" * 24, {"Operations": [
        {"op": "remove", "path": "members"}, {"op": "add", "path": "members", "value": [{"value": "x"}]}]}, False),
    ("PATCH", "/Groups/grp_" + "1" * 24, {"Operations": [{"op": "replace", "path": "displayName",
                                                          "value": "Staff"}]}, False),
    ("PUT", "/Groups/grp_" + "1" * 24, {"displayName": "Staff", "members": []}, False),
    ("POST", "/Users", {"userName": "a", "active": False}, False),
    ("PATCH", "/Users", _DEACT_OKTA, False),
    ("GET", "/Users/sso_" + "1" * 24, None, False),
])
def test_lowers_only_classifies_by_shape(method, path, body, want):
    assert uiscim.lowers_only(method, path, body) is want


def test_an_offboarding_is_never_held_off_by_the_orgs_write_debt(stack, monkeypatch):
    """At the shipped budget, a legitimate large group write overdraws the org; a write that could grant is then
    refused 429 — but deactivations, a user DELETE, a member removal and a group DELETE are admitted at once and take
    the roles away. They are still charged: the debt the next ordinary write waits out grows."""
    monkeypatch.setattr(config, "SCIM_OPS_PER_MIN", 10 ** 6)
    stack.saml_org(ORG_A, scim_token=TOKEN_A)
    _gid, ids = _seed(stack, ORG_A, 700)
    import shutil
    shutil.rmtree(config.SCIM_WRITE_RATELIMIT_DIR, ignore_errors=True)
    monkeypatch.setattr(config, "SCIM_OPS_PER_MIN", 1800)
    g = _scim(stack, ORG_A, "POST", "/Groups", {"displayName": "Admins",
                                               "members": [{"value": u} for u in ids[:600]]})
    assert g["status"] == 201                                       # ~1801 records: the org is now over budget
    held = _scim(stack, ORG_A, "PUT", f"/Users/{ids[650]}", _okta_user("s650@x.example", "s-ext650"))
    assert held["status"] == 429
    w0 = held["retry_after"]
    assert _scim(stack, ORG_A, "PATCH", f"/Users/{ids[0]}", _DEACT_OKTA)["status"] == 200
    assert _scim(stack, ORG_A, "PATCH", f"/Users/{ids[1]}", _DEACT_ENTRA)["status"] == 200
    assert _scim(stack, ORG_A, "DELETE", f"/Users/{ids[2]}")["status"] == 204
    gid = g["body"]["id"]
    assert _scim(stack, ORG_A, "PATCH", f"/Groups/{gid}", {"Operations": [
        {"op": "remove", "path": f'members[value eq "{ids[3]}"]'}]})["status"] == 200
    roles = _roles(stack, ORG_A)
    assert ids[0] not in roles and ids[1] not in roles and ids[2] not in roles and roles[ids[3]] == "viewer"
    assert _scim(stack, ORG_A, "DELETE", f"/Groups/{gid}")["status"] == 204
    roles = _roles(stack, ORG_A)
    assert {roles[u] for u in ids[4:600]} == {"viewer"}
    later = _scim(stack, ORG_A, "PUT", f"/Users/{ids[650]}", _okta_user("s650@x.example", "s-ext650"))
    assert later["status"] == 429 and later["retry_after"] > w0 + 30        # the deprovisioning was charged


# =====================================================================================================================
# F5 — what a request appended before an unexpected failure is still charged
# =====================================================================================================================
def test_records_appended_before_a_failing_audit_are_still_charged(stack, monkeypatch):
    """A mapped group create whose grant audit fails after the directory landed (group + 2 edges): the request fails,
    and the org's write budget holds every record it appended — the admitted unit plus the 2 further ones."""
    stack.saml_org(ORG_A, scim_token=TOKEN_A)
    _gid, ids = _seed(stack, ORG_A, 2)
    import shutil
    shutil.rmtree(config.SCIM_WRITE_RATELIMIT_DIR, ignore_errors=True)
    fail = _FailingAudit(monkeypatch, {"scim_grant"})
    before = _n(stack)
    with pytest.raises(OSError):
        _scim(stack, ORG_A, "POST", "/Groups", {"displayName": "Admins", "members": [{"value": u} for u in ids]})
    assert fail.attempts == ["scim_grant"] and _n(stack) - before == 3
    p = build_provisioner(stack.store())
    rec = json.loads(p.scim_write_limiter._marker(f"scim:writes:{ORG_A}").read_text())
    assert len(rec["fails"]) == 3


# =====================================================================================================================
# P04 — a body over a per-request bound is refused before the budget (and before any lock)
# =====================================================================================================================
def test_an_over_bound_body_spends_no_budget(stack, monkeypatch):
    monkeypatch.setattr(config, "SCIM_OPS_PER_MIN", 2)
    stack.saml_org(ORG_A, scim_token=TOKEN_A)
    big = {"displayName": "G", "members": [{"value": f"sso_{i:024x}"} for i in range(1001)]}
    p = build_provisioner(stack.store())
    with sso_provision._org_lock(p, ORG_A, "write"):              # refused without taking the org's lock either
        for _ in range(3):
            assert _scim(stack, ORG_A, "POST", "/Groups", big)["status"] == 400
    assert _scim(stack, ORG_A, "POST", "/Users", _okta_user("a@acme.com", "00u-a"))["status"] == 201


# =====================================================================================================================
# SIGN-INS — verified first, then a per-org budget, resolved one at a time per org, with the folds outside the
# shared section; one org's sign-in flood never stalls another org
# =====================================================================================================================
def _assertion_b64(stack, org: str, name_id: str, *, key=None) -> str:
    import base64
    u = stack.urls(org)
    xml = edge._sign(edge._saml_response(request_id="_req1", audience=u["saml_sp_entity_id"],
                                         recipient=u["saml_acs_url"], name_id=name_id), key or edge.IDP_KEY)
    return base64.b64encode(xml).decode()


def _sign_in(stack, org: str, name_id: str = "", *, b64: str = "", ip: str = "198.51.100.1", key=None) -> dict:
    """One SAML ACS tail through a FRESH provisioner (the edge's login state already named `org` and `_req1`)."""
    return sso_provision.sso_saml_acs(build_provisioner(stack.store()), org,
                                      b64 or _assertion_b64(stack, org, name_id, key=key), request_id="_req1", ip=ip)


def test_the_sign_in_budget_and_lock_defaults_are_pinned():
    assert config.SSO_SIGNINS_PER_MIN == 600 and config.SCIM_DEPROVISIONS_PER_MIN == 6000
    assert sso_provision._SIGNIN_LOCK_WAIT_S == 10.0


def test_a_sign_in_never_folds_while_holding_the_spine_lock(stack, signed, meter, monkeypatch):
    """A directory-managed sign-in that CLAMPS (the member holds org_admin, the directory implies viewer): every fold
    — memberships and directory — runs without the spine lock, and the hold that lands the clamp appends at most its
    3 records (audit row, grant, directory note)."""
    stack.saml_org(ORG_A, scim_token=TOKEN_A)
    _gid, uids = _seed(stack, ORG_A, 2, role="org_admin")
    seen = _watch_folds(monkeypatch, meter)
    dirs: list = []
    orig = ScimDirectoryRegistry.directory

    def directory(self, org_id):
        dirs.append(meter._is_owned())
        return orig(self, org_id)
    monkeypatch.setattr(ScimDirectoryRegistry, "directory", directory)
    t, out = _in_thread("sign-in", lambda: _sign_in(stack, ORG_A, f"s0@{ORG_A}.example"))
    t.join(60)
    assert out["r"]["username"] == uids[0], out
    assert stack.role(uids[0], ORG_A) == "viewer" and stack.audits("sso_role_clamp")
    assert seen and not any(seen) and dirs and not any(dirs), (seen, dirs)
    assert 1 <= meter.max_hold("sign-in") <= 3


def test_the_per_org_sign_in_budget_refuses_with_nothing_minted(stack, signed, monkeypatch):
    """Over `VIGIL_SSO_SIGNINS_PER_MIN` verified sign-ins a minute, the org's next sign-in is refused BEFORE its
    assertion is verified or spent: nothing minted, the client IP not counted as a failure, and once the budget is
    repaid the very same assertion still signs in (it was never consumed)."""
    from sigil.ui.provision import ProvisionDenied
    monkeypatch.setattr(config, "SSO_SIGNINS_PER_MIN", 2)
    stack.saml_org(ORG_A)                                       # just-in-time: a sign-in mints the membership
    stack.saml_org(ORG_B)
    assert _sign_in(stack, ORG_A, "ann@acme.example")["org_id"] == ORG_A
    assert _sign_in(stack, ORG_A, "bob@acme.example")["org_id"] == ORG_A
    before, n0 = _roles(stack, ORG_A), _n(stack)
    held = _assertion_b64(stack, ORG_A, "cat@acme.example")
    with pytest.raises(ProvisionDenied, match="too many sign-ins"):
        _sign_in(stack, ORG_A, b64=held, ip="198.51.100.77")
    assert _roles(stack, ORG_A) == before and len(before) == 2
    assert _n(stack) == n0 + 1 and stack.audits("sso_login")[-1]["reason"] == "saml:org_rate"   # one audit row
    p = build_provisioner(stack.store())
    assert p.rate_limiter.locked("sso:ip:198.51.100.77") is None and not p.rate_limiter._marker(
        "sso:ip:198.51.100.77").exists()
    assert _sign_in(stack, ORG_B, "dan@beta.example")["org_id"] == ORG_B           # another org's budget is its own
    import shutil
    shutil.rmtree(config.SSO_SIGNIN_RATELIMIT_DIR, ignore_errors=True)            # the budget repaid
    assert _sign_in(stack, ORG_A, b64=held, ip="198.51.100.77")["org_id"] == ORG_A
    assert len(_roles(stack, ORG_A)) == 3


def test_assertions_that_fail_verification_never_spend_the_orgs_sign_in_budget(stack, signed, monkeypatch):
    from sigil.ui.provision import ProvisionDenied
    monkeypatch.setattr(config, "SSO_SIGNINS_PER_MIN", 2)
    stack.saml_org(ORG_A)
    for i in range(5):                                          # forged by someone without the IdP's key
        with pytest.raises(ProvisionDenied, match="could not be verified"):
            _sign_in(stack, ORG_A, f"x{i}@acme.example", key=edge.ATTACKER_KEY, ip=f"203.0.113.{i + 1}")
    assert _roles(stack, ORG_A) == {}
    assert _sign_in(stack, ORG_A, "ann@acme.example")["org_id"] == ORG_A
    assert _sign_in(stack, ORG_A, "bob@acme.example")["org_id"] == ORG_A


def test_the_per_org_sign_in_budget_covers_enterprise_oidc(stack, monkeypatch):
    """Over the budget an enterprise-OIDC sign-in is refused before its code is even exchanged (no IdP egress)."""
    from sigil.ui import oidc as uioidc
    monkeypatch.setattr(config, "SSO_SIGNINS_PER_MIN", 1)
    exchanges: list = []
    orig = uioidc.exchange_code

    def exchange(*a, **kw):
        exchanges.append(1)
        return orig(*a, **kw)
    monkeypatch.setattr(uioidc, "exchange_code", exchange)
    stack.oidc_org(ORG_A, client_id="cid-acme")
    ok = edge._oidc_sign_in(stack, ORG_A, sub="00u-ann")
    assert ok.location == "/" and len(exchanges) == 1, (ok.status, ok.location)
    refused = edge._oidc_sign_in(stack, ORG_A, sub="00u-bob")
    assert refused.location == "/#sso=err" and len(_roles(stack, ORG_A)) == 1
    assert len(exchanges) == 1 and stack.audits("sso_login")[-1]["reason"] == "oidc:org_rate"


def test_one_orgs_sign_ins_are_resolved_one_at_a_time(stack, signed, monkeypatch):
    """While a sign-in of org A is being resolved (its sign-in lock held), the next one of org A waits the bounded
    time and is refused with nothing minted — and org B's sign-in is answered at once."""
    from sigil.ui.provision import ProvisionDenied
    monkeypatch.setattr(sso_provision, "_SIGNIN_LOCK_WAIT_S", 0.3)
    stack.saml_org(ORG_A)
    stack.saml_org(ORG_B)
    p = build_provisioner(stack.store())
    with sso_provision._org_lock(p, ORG_A, "signin"):
        with pytest.raises(ProvisionDenied, match="too many sign-ins"):
            _sign_in(stack, ORG_A, "ann@acme.example")
        assert _roles(stack, ORG_A) == {}
        t0 = time.time()
        assert _sign_in(stack, ORG_B, "dan@beta.example")["org_id"] == ORG_B
        assert time.time() - t0 < 5.0
    assert _sign_in(stack, ORG_A, "ann@acme.example")["org_id"] == ORG_A


def test_a_config_re_signed_between_verification_and_resolution_refuses_the_sign_in(stack, signed, monkeypatch):
    """The member is resolved only under the config the assertion verified under: a config the owner re-signed in
    between (e.g. a rotated IdP certificate) refuses the sign-in, nothing minted."""
    from sigil.ui.provision import ProvisionDenied
    stack.saml_org(ORG_A)
    orig = uiscim.verify_saml_sign_in

    def verify(*a, **kw):
        out = orig(*a, **kw)
        u = stack.urls(ORG_A)
        stack.cfg().set_saml_config(ORG_A, idp_entity_id=edge.IDP_ENTITY, idp_certs_pem=[edge.IDP_CERT],
                                    idp_sso_url=edge.IDP_SSO_URL, sp_entity_id=u["saml_sp_entity_id"],
                                    acs_url=u["saml_acs_url"], default_role="viewer",
                                    group_role_map={"Admins": "org_admin"}, role_cap="analyst",
                                    scim_enabled=False, scim_token="", issued_at=time.time())
        return out
    monkeypatch.setattr(uiscim, "verify_saml_sign_in", verify)
    with pytest.raises(ProvisionDenied, match="could not be verified"):
        _sign_in(stack, ORG_A, "ann@acme.example")
    assert _roles(stack, ORG_A) == {}


def test_a_sign_in_flood_from_one_org_does_not_stall_another_orgs_write_or_sign_in(stack, signed):
    """A hostile tenant's IdP signs its own users in, in a loop, from many addresses (8 threads, a fresh client IP
    each time) over a large directory. Org B's SCIM write and org B's sign-in stay within 5x their calm time."""
    stack.saml_org(ORG_A, scim_token=TOKEN_A)
    stack.saml_org(ORG_B, scim_token=TOKEN_B)
    _seed(stack, ORG_A, 1500)
    _seed(stack, ORG_B, 1, prefix="b")
    b_user = f"b0@{ORG_B}.example"

    def b_write(tag: str) -> float:
        t0 = time.time()
        assert _scim(stack, ORG_B, "POST", "/Users", _okta_user(f"{tag}@beta.com", f"00u-{tag}"))["status"] == 201
        return time.time() - t0

    def b_sign_in() -> float:
        t0 = time.time()
        assert _sign_in(stack, ORG_B, b_user, ip="192.0.2.200")["org_id"] == ORG_B
        return time.time() - t0
    calm_w, calm_s = b_write("calm"), b_sign_in()
    stop = threading.Event()
    done = [0]
    counter = iter(range(10 ** 6))

    def flood():
        while not stop.is_set():
            k = next(counter)
            try:
                _sign_in(stack, ORG_A, f"s{k % 1500}@{ORG_A}.example", ip=f"10.{k // 65536 % 256}.{k // 256 % 256}."
                                                                         f"{k % 256}")
                done[0] += 1
            except Exception:  # noqa: BLE001 — refusals (busy / budget) are part of the flood
                pass
    ths = [threading.Thread(target=flood, daemon=True) for _ in range(8)]
    for t in ths:
        t.start()
    time.sleep(2)
    busy_w, busy_s = b_write("busy"), b_sign_in()
    stop.set()
    for t in ths:
        t.join(120)
    print(f"\norg A sign-ins resolved during the flood: {done[0]}; org B write {calm_w:.2f}s -> {busy_w:.2f}s, "
          f"sign-in {calm_s:.2f}s -> {busy_s:.2f}s")
    assert done[0] > 0
    assert busy_w < 5 * max(calm_w, 1.0), (calm_w, busy_w)
    assert busy_s < 5 * max(calm_s, 1.0), (calm_s, busy_s)


# =====================================================================================================================
# DEPROVISIONING — its own high per-org cap, with a one-a-minute floor
# =====================================================================================================================
def test_deprovisioning_has_its_own_cap_and_always_makes_progress(stack, monkeypatch):
    """Under the cap a deprovisioning is never refused; each costs at least one unit (also one that appended nothing);
    over it, one more is still admitted in the minute, then 429 + Retry-After. The write budget is not involved."""
    monkeypatch.setattr(config, "SCIM_DEPROVISIONS_PER_MIN", 3)
    stack.saml_org(ORG_A, scim_token=TOKEN_A)
    stack.saml_org(ORG_B, scim_token=TOKEN_B)
    gone = [f"/Users/sso_{i:024x}" for i in range(6)]
    assert [_scim(stack, ORG_A, "DELETE", g)["status"] for g in gone[:3]] == [404, 404, 404]   # under the cap
    assert _scim(stack, ORG_A, "DELETE", gone[3])["status"] == 404                              # the floor
    over = _scim(stack, ORG_A, "DELETE", gone[4])
    assert over["status"] == 429 and 1 <= over["retry_after"] <= 60
    assert _scim(stack, ORG_A, "POST", "/Users", _okta_user("a@acme.com", "00u-a"))["status"] == 201
    assert _scim(stack, ORG_B, "DELETE", gone[5])["status"] == 404                              # B's cap is its own
