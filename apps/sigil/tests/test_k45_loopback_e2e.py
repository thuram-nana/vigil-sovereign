"""K4-5e — the customer-launch MONEY loop, composed end to end (mock-first, framework-free).

Proves the three K4-5 halves agree on ONE lease, which the per-slice unit suites cannot on their own:
  * K4-5d(A) provisions the per-slug owner OFFENSE_GOVERNANCE_ROLE delegation at launch
    (``ui.launch_governance.provision_launch_governance`` over the STABLE base gov key);
  * K4-5d(B) the keyless worker, at run end, loads that SAME base gov key and emits a governance-signed
    ``EngagementCompletion`` (here we drive that post-run step directly — it is framework-free: load the gov
    signers + ``emit_completion_signal`` — the only framework part of the real worker is ``run_engagement``,
    which K4-3/K4-5d already exercise with an injected engine, and the enqueue/gate are covered by
    test_launch_drain / test_engage_runner);
  * K4-5b the sovereign settle-drain verifies that completion AGAINST the launch delegation and settles.

So this composes reserve → publish → provision-delegation → [worker completion emit] → settle-drain →
settle_launch, and pins the money invariants on the composed path: net-spend == consumption (completed ⇒ the
full reserved units, no refund; failed/canceled ⇒ full refund); a cancel THEN a late completed for the same
(slug, nonce) cannot double-settle (the K4-1 tombstone — the settle-vs-arm TOCTOU); and strict tenant
isolation (orgA's launch delegation + drain settle ONLY orgA's lease, never orgB's).

Runs entirely on the SOVEREIGN leg (no framework in-process — FATAL-2): the whole money loop uses only sigil +
vigil_core + the framework-free integration seams (credit_lease_broker / completion_signal / governance_identity).
PYTHONPATH=apps/sigil:integration.
"""
from __future__ import annotations

import itertools
import os
import tempfile
from pathlib import Path

import pytest

from sigil.governor.asset_ownership import METHOD_DNS_TXT, AssetOwnershipRegistry
from sigil.governor.identity import ensure_owner_keypair
from sigil.governor.orgs import OrgRegistry
from sigil.governor.wallet import WalletRegistry
from sigil.inbound.completion_spool import CompletionSpoolWatcher
from sigil.spine.store import SpineStore
from sigil.ui.launch_gate import LaunchGate
from sigil.ui.launch_governance import provision_launch_governance
from sigil.ui.target_authorization import _customer_slug, add_customer_target
from vigil_core.delegation import DelegationCert
from vigil_integration.jobs.completion_signal import emit_completion_signal
from vigil_integration.live.credit_lease_broker import is_lease_settled, read_credit_lease
from vigil_integration.live.governance_identity import (
    DEFAULT_GOVERNANCE_KEY_FILE, GOVERNANCE_KEY_ID, load_or_create_governance_keypair,
)

_iss = itertools.count(1)
NOW, NOT_AFTER = 2000.0, 9_000_000_000


@pytest.fixture(autouse=True)
def _iso(monkeypatch):
    monkeypatch.setenv("VIGIL_BASE_DIR", tempfile.mkdtemp())
    monkeypatch.setenv("SIGIL_SPINE_DIR", tempfile.mkdtemp())
    monkeypatch.setenv("SIGIL_HOME", tempfile.mkdtemp())


def _store():
    return SpineStore(tempfile.mktemp(suffix=".jsonl"))


def _base():
    return os.environ["VIGIL_BASE_DIR"]


def _seat_member(store, *, org, host, credits=100):
    """Seat a member + wallet credits + ownership proof + a customer authority (no reserve/publish)."""
    orgs = OrgRegistry(store)
    orgs.create_org(org, org, owner="u", issued_at=float(next(_iss)))
    orgs.grant_membership(org, "u", "operator", issued_at=float(next(_iss)))
    WalletRegistry(store).grant(org, credits, "trial", entry_id=f"trial:{org}", issued_at=float(next(_iss)))
    reg = AssetOwnershipRegistry(store)
    ch = reg.issue_challenge(org, host, issued_at=float(next(_iss)))
    reg.verify_and_record(org, host, method=METHOD_DNS_TXT, observed=[ch.marker], now=NOW, ttl_seconds=1e12)
    assert add_customer_target(host, org_id=org, store=store, now=NOW)["ok"]


def test_launch_start_provisions_delegation_before_publishing_no_orphan_lease(monkeypatch):
    # K4-5 red-pen fold (MED): launch_start must provision the per-slug settle delegation BEFORE publishing the
    # runnable lease, so a provisioning failure leaves NO published-but-unsettleable lease (orphan lease).
    import sigil.ui.launch_governance as _lg
    from sigil.ui.provision import ProvisionDenied, build_provisioner
    s = _store()
    ensure_owner_keypair()
    _seat_member(s, org="org_a", host="apme.cm")
    r = LaunchGate(s).reserve_launch(requester="u", org_id="org_a", host="apme.cm", units=30, now=NOW)
    assert r["ok"], r

    def _boom(**kw):
        raise RuntimeError("deleg provisioning failed")

    monkeypatch.setattr(_lg, "provision_launch_governance", _boom)
    with pytest.raises(ProvisionDenied):
        build_provisioner(s).launch_start("u", "org_a", r["lease"])
    assert read_credit_lease(_base(), r["slug"]) is None            # provision failed FIRST → lease NOT published


def test_launch_start_happy_path_provisions_then_publishes(monkeypatch):
    from sigil.ui.provision import build_provisioner
    from vigil_core.delegation import DelegationCert
    s = _store()
    ensure_owner_keypair()
    _seat_member(s, org="org_a", host="apme.cm")
    r = LaunchGate(s).reserve_launch(requester="u", org_id="org_a", host="apme.cm", units=30, now=NOW)
    out = build_provisioner(s).launch_start("u", "org_a", r["lease"])
    assert out["slug"] == r["slug"] and out.get("governance_delegation")
    assert read_credit_lease(_base(), r["slug"]) is not None        # published
    # the provisioned delegation is real + verifies under the owner key for THIS slug
    from sigil.governor.identity import owner_pubkey
    from vigil_core.delegation import OFFENSE_GOVERNANCE_ROLE, verify_delegation
    cert = DelegationCert.model_validate_json(Path(out["governance_delegation"]).read_text(encoding="utf-8"))
    assert verify_delegation(cert, trusted_owner_pubkey=owner_pubkey(), now=int(NOW),
                             role=OFFENSE_GOVERNANCE_ROLE, scope=r["slug"]) is not None


def _seat_and_reserve(store, owner, *, org, host, units=30, credits=100):
    """Seat a member + wallet + ownership proof + customer authority, then reserve + PUBLISH a lease, then
    PROVISION the per-slug launch governance delegation (what provision.launch_start does). Returns the
    reserve result + the loaded delegation."""
    orgs = OrgRegistry(store)
    orgs.create_org(org, org, owner="u", issued_at=float(next(_iss)))
    orgs.grant_membership(org, "u", "operator", issued_at=float(next(_iss)))
    WalletRegistry(store).grant(org, credits, "trial", entry_id=f"trial:{org}", issued_at=float(next(_iss)))
    reg = AssetOwnershipRegistry(store)
    ch = reg.issue_challenge(org, host, issued_at=float(next(_iss)))
    reg.verify_and_record(org, host, method=METHOD_DNS_TXT, observed=[ch.marker], now=NOW, ttl_seconds=1e12)
    assert add_customer_target(host, org_id=org, store=store, now=NOW)["ok"]
    g = LaunchGate(store)
    r = g.reserve_launch(requester="u", org_id=org, host=host, units=units, now=NOW)
    assert r["ok"], r
    assert g.publish_lease(signed_lease=r["lease"], expect_org_id=org)["ok"]
    deleg_path = provision_launch_governance(slug=r["slug"], not_after=NOT_AFTER, base_dir=_base())
    deleg = DelegationCert.model_validate_json(Path(deleg_path).read_text(encoding="utf-8"))
    return r, deleg


def _worker_emits(slug, nonce, outcome, spool):
    """The framework-free half of what the keyless worker does post-run: load the STABLE base gov signers
    (the SAME key provision_launch_governance delegated to) and emit a governance-signed completion."""
    kp = load_or_create_governance_keypair(path=os.path.join(_base(), DEFAULT_GOVERNANCE_KEY_FILE))
    return emit_completion_signal(engagement_slug=slug, nonce=nonce, outcome=outcome,
                                  signers=[(GOVERNANCE_KEY_ID, kp.private_key_b64)], spool_dir=spool)


def _settle_drain(store, owner, deleg, slug, spool):
    return CompletionSpoolWatcher(store, spool_dir=spool, owner_pubkey=owner.public_key_b64, delegation=deleg,
                                  scope=slug, base_dir=_base(), now_fn=lambda: NOW).drain()


def _avail(store, org):
    return WalletRegistry(store).available(org)


def test_full_loop_completed_settles_net_spend_equals_consumption():
    s = _store()
    owner = ensure_owner_keypair()
    r, deleg = _seat_and_reserve(s, owner, org="org_a", host="apme.cm", units=30, credits=100)
    assert _avail(s, "org_a") == 70                                  # 30 reserved (held)
    spool = tempfile.mkdtemp()
    _worker_emits(r["slug"], r["nonce"], "completed", spool)         # the run completed
    out = _settle_drain(s, owner, deleg, r["slug"], spool)
    assert out == {"settled": 1, "noop": 0, "rejected": 0, "deduped": 0}, out
    assert _avail(s, "org_a") == 70                                  # net-spend == consumption (30), NO refund
    assert is_lease_settled(_base(), r["slug"], r["nonce"]) is True
    assert read_credit_lease(_base(), r["slug"]) is None             # lease tombstoned (K4-1)


def test_full_loop_failed_settles_full_refund():
    s = _store()
    owner = ensure_owner_keypair()
    r, deleg = _seat_and_reserve(s, owner, org="org_a", host="apme.cm", units=30, credits=100)
    spool = tempfile.mkdtemp()
    _worker_emits(r["slug"], r["nonce"], "failed", spool)            # the run crashed → refund
    assert _settle_drain(s, owner, deleg, r["slug"], spool)["settled"] == 1
    assert _avail(s, "org_a") == 100                                 # full refund (consumed 0)


def test_cancel_then_late_completed_cannot_double_settle():
    # the K4-1 settle-vs-arm TOCTOU on the composed loop: a CANCELED settle refunds + tombstones; a LATER
    # completed completion for the SAME (slug,nonce) — different bytes — finds no live lease → safe no-op,
    # never a second (consuming) settle of an already-refunded launch.
    s = _store()
    owner = ensure_owner_keypair()
    r, deleg = _seat_and_reserve(s, owner, org="org_a", host="apme.cm", units=30, credits=100)
    spool = tempfile.mkdtemp()
    _worker_emits(r["slug"], r["nonce"], "canceled", spool)
    assert _settle_drain(s, owner, deleg, r["slug"], spool)["settled"] == 1
    assert _avail(s, "org_a") == 100                                 # canceled → full refund
    _worker_emits(r["slug"], r["nonce"], "completed", spool)         # a LATE completed for the same launch
    out = _settle_drain(s, owner, deleg, r["slug"], spool)
    assert out["settled"] == 0 and out["noop"] == 1                  # lease tombstoned → no-op (no double settle)
    assert _avail(s, "org_a") == 100                                 # still fully refunded — not re-consumed


def test_completed_then_launch_cancel_cannot_double_refund():
    # K4-5 red-pen HIGH: a COMPLETED settle (refund=0) must make a LATER launch_cancel (a DIRECT
    # settle_launch(consumed=0) that bypasses the seam read) an idempotent NO-OP — else the charged, completed
    # run is FULLY REFUNDED (free run). Guarded by the is_lease_settled check inside settle_launch (the
    # settlement marker is written on EVERY settle, including a refund=0 COMPLETED).
    s = _store()
    owner = ensure_owner_keypair()
    r, deleg = _seat_and_reserve(s, owner, org="org_a", host="apme.cm", units=30, credits=100)
    assert _avail(s, "org_a") == 70
    spool = tempfile.mkdtemp()
    _worker_emits(r["slug"], r["nonce"], "completed", spool)
    assert _settle_drain(s, owner, deleg, r["slug"], spool)["settled"] == 1     # COMPLETED: charged, refund 0
    assert _avail(s, "org_a") == 70 and is_lease_settled(_base(), r["slug"], r["nonce"])
    # a DIRECT launch_cancel-style settle (consumed=0) for the SAME (slug,nonce) — must be an idempotent no-op
    out = LaunchGate(s).settle_launch(signed_lease=r["lease"], consumed_units=0, now=NOW, expect_org_id="org_a")
    assert out["ok"] and out["action"] == "launch_already_settled" and out["refunded"] == 0
    assert _avail(s, "org_a") == 70            # NOT refunded to 100 — the completed/charged run stays charged


def test_launch_cancel_refuses_a_started_launch_but_refunds_a_reservation(monkeypatch):
    # K4-5 red-pen fold (MED): a customer cancel (full refund) is valid ONLY for a reserved-but-NOT-started
    # launch. Once STARTED (published, may have armed+run), cancel is refused — it must settle through its
    # completion — so a run that ran can't be full-refunded. Reserve+cancel (pre-start) still refunds.
    from sigil.ui.provision import ProvisionDenied, build_provisioner
    s = _store()
    ensure_owner_keypair()
    _seat_member(s, org="org_a", host="apme.cm", credits=100)
    # pre-start: a reserved-but-not-started launch cancels for a full refund
    r1 = LaunchGate(s).reserve_launch(requester="u", org_id="org_a", host="apme.cm", units=30, now=NOW)
    assert _avail(s, "org_a") == 70
    out = build_provisioner(s).launch_cancel("u", "org_a", r1["lease"])
    assert out["refunded"] == 30 and _avail(s, "org_a") == 100         # not started → full refund
    # started: publish (start) a fresh reservation, then a cancel is REFUSED (must settle through completion)
    r2 = LaunchGate(s).reserve_launch(requester="u", org_id="org_a", host="apme.cm", units=40, now=NOW)
    assert _avail(s, "org_a") == 60
    p = build_provisioner(s)
    p.launch_start("u", "org_a", r2["lease"])                          # STARTED (published to the seam)
    with pytest.raises(ProvisionDenied, match="started"):
        p.launch_cancel("u", "org_a", r2["lease"])
    assert _avail(s, "org_a") == 60                                    # NOT refunded — a started run settles on completion


def _slug_spool(slug):
    return str(Path(_base()) / "completion-spool" / slug)   # the worker's per-slug default completion spool


def test_tenant_isolation_per_slug_spools_no_cross_tenant_destruction():
    # K4-5 red-pen fold (MED): the worker's DEFAULT per-slug completion spool (base/completion-spool/<slug>/)
    # means two tenants' completions land in SEPARATE spools, so a per-slug-scoped drain reads only its own and
    # can NEVER claim+quarantine (destroy) another tenant's valid completion. orgA's drain settles orgA; orgB's
    # completion stays intact in orgB's own spool and its own drain settles it — both charged, neither lost.
    s = _store()
    owner = ensure_owner_keypair()
    ra, dela = _seat_and_reserve(s, owner, org="org_a", host="a.example", units=30, credits=100)
    rb, delb = _seat_and_reserve(s, owner, org="org_b", host="b.example", units=40, credits=100)
    assert ra["slug"] != rb["slug"] == _customer_slug("org_b", "b.example")
    _worker_emits(ra["slug"], ra["nonce"], "completed", _slug_spool(ra["slug"]))   # per-slug spools
    _worker_emits(rb["slug"], rb["nonce"], "completed", _slug_spool(rb["slug"]))
    # orgA's drain reads ONLY orgA's spool → settles orgA; orgB's spool is untouched (no cross-tenant claim)
    outa = _settle_drain(s, owner, dela, ra["slug"], _slug_spool(ra["slug"]))
    assert outa == {"settled": 1, "noop": 0, "rejected": 0, "deduped": 0}, outa
    assert _avail(s, "org_a") == 70 and _avail(s, "org_b") == 60      # orgA charged; orgB intact + still held
    # orgB's completion was NOT destroyed by orgA's drain — orgB's own drain settles it
    outb = _settle_drain(s, owner, delb, rb["slug"], _slug_spool(rb["slug"]))
    assert outb["settled"] == 1 and _avail(s, "org_b") == 60          # orgB charged (40 consumed, no refund)


def test_worker_default_completion_spool_is_per_slug(monkeypatch):
    # the DEFAULT (no completion_spool_dir) routes to base/completion-spool/<slug> — the per-slug isolation.
    from vigil_integration.jobs.engage_worker import _completion_spool, _finding_spool
    base = tempfile.mkdtemp()
    assert _completion_spool(base, None, "cust_abc").endswith("/completion-spool/cust_abc")
    assert _finding_spool(base, None, "cust_abc").endswith("/finding-spool/cust_abc")
    assert _completion_spool(base, "/explicit/path", "cust_abc") == "/explicit/path"   # explicit used as-is
