"""`sigil seam migrate --apply` — an expired launch's archived completion reaches the settle drain again.

A completion the settle drain archived as a no-op because it read another directory than the one the cockpit
published the lease in (``processed/``) is handed back to the drain (``incoming/``) once the lease is on the seam: the
drain verifies it under its delegation and settles the launch on the seam at the completion's outcome — completed is
charged, canceled or failed is refunded. Only an EXPIRED, UNSETTLED legacy launch's completion is selected; a settled
launch's completion stays archived. An expired, unsettled launch with no completion anywhere in the spool is HELD for
the owner: both reservation sweeps report it ``legacy_hold`` and never settle it. The drain's scan checkpoint is
removed (the next pass reads the whole spine), and a checkpoint naming another seam is never continued.

Sovereign leg: PYTHONPATH=apps/sigil:integration:packages/core/vigil_core.

Mutation-verify targets (each neuter reds a NAMED test here):
  * requeue before the lease is on the seam                 -> test_a_completed_launch_is_charged_through_its_requeued_completion
  * a settled launch's completion requeued                  -> test_a_settled_launchs_completion_stays_archived
  * legacy_hold not honoured by the sweep                    -> test_a_held_launch_is_never_settled_by_the_sweep
  * the scan checkpoint kept                                 -> test_the_scan_checkpoint_is_removed
  * the checkpoint's seam identity dropped                   -> test_a_checkpoint_from_another_seam_is_not_continued
"""
from __future__ import annotations

import pytest

from sigil import ops_sweeps, seam_migrate
from sigil.governor.identity import delegate_offense_governance, ensure_owner_keypair
from sigil.inbound.completion_spool import CompletionSpoolWatcher
from sigil.ui.launch_gate import LaunchGate
from sigil.ui.target_authorization import _customer_slug
from vigil_core import AuthorizerKey, generate_keypair
from vigil_integration import seam_migration as sm
from vigil_integration.jobs.completion_signal import emit_completion_signal
from vigil_integration.live.credit_lease_broker import is_lease_settled, read_credit_lease

from tests.test_seam_migrate import (  # type: ignore
    HOST, LATE, NOW, ORG, _avail, _move, _reserve, _seat, _settle, _store, make_trees,
)


@pytest.fixture
def trees(monkeypatch, tmp_path):
    return make_trees(monkeypatch, tmp_path)


def _deleg():
    gov = generate_keypair()
    deleg = delegate_offense_governance(
        ensure_owner_keypair(), authorizers=[AuthorizerKey(key_id="gov", name="gov", public_key_b64=gov.public_key_b64)],
        threshold=1, scope=_customer_slug(ORG, HOST), not_after=9_000_000_000)
    return gov, deleg


def _drain(store, spool, deleg, base, now=LATE + 10):
    return CompletionSpoolWatcher(store, spool_dir=str(spool), owner_pubkey=ensure_owner_keypair().public_key_b64,
                                  delegation=deleg, scope=_customer_slug(ORG, HOST), base_dir=str(base),
                                  now_fn=lambda: now).drain()


def _archived_noop(store, spool, gov, deleg, r, outcome, wrong_tree):
    """The completion of ``r`` drained against a tree with no lease: archived to processed/ as a no-op."""
    emit_completion_signal(engagement_slug=r["slug"], nonce=r["nonce"], outcome=outcome,
                           signers=[("gov", gov.private_key_b64)], spool_dir=str(spool))
    out = _drain(store, spool, deleg, wrong_tree)
    assert out["noop"] == 1 and out["settled"] == 0, out
    (name,) = [p.name for p in (spool / "processed").glob("*.json")]
    return name


def _apply(store, seam, legacy, spool, now=LATE):
    return seam_migrate.run(store, ensure_owner_keypair(), seam=seam, sources=[str(legacy)], spool=spool, apply=True,
                            now=now)


@pytest.mark.parametrize("outcome,refund", [("completed", 0), ("canceled", 30), ("failed", 30)])
def test_a_completed_launch_is_charged_through_its_requeued_completion(trees, monkeypatch, tmp_path, outcome, refund):
    legacy, seam, spool = trees
    s = _store()
    _seat(s)
    r = _reserve(s)                                                        # published in the former tree
    assert _avail(s) == 70
    gov, deleg = _deleg()
    name = _archived_noop(s, spool, gov, deleg, r, outcome, tmp_path / "wrong-tree")
    _move(monkeypatch, seam)
    code, rep = _apply(s, seam, legacy, spool)
    src = rep["sources"][0]
    assert code == 0 and src["status"] == "migrated" and src["requeue"] == [name] and src["held"] == []
    assert (spool / "incoming" / name).is_file() and not (spool / "processed" / name).exists()
    out = _drain(s, spool, deleg, seam)
    assert out["settled"] == 1, out
    assert _avail(s) == 70 + refund                                        # completed: charged; else refunded
    assert is_lease_settled(str(seam), r["slug"], r["nonce"]) and read_credit_lease(str(seam), r["slug"]) is None
    j = sm.read_journal(seam)["sources"][str(legacy)]
    assert j["requeue_planned"] == [name] and j["requeued"] == [name]


def test_a_settled_launchs_completion_stays_archived(trees, monkeypatch, tmp_path):
    legacy, seam, spool = trees
    s = _store()
    _seat(s)
    r = _reserve(s)
    gov, deleg = _deleg()
    name = _archived_noop(s, spool, gov, deleg, r, "completed", tmp_path / "wrong-tree")
    assert _settle(s, r, 30)["ok"]                                         # settled on the former tree
    _move(monkeypatch, seam)
    code, rep = _apply(s, seam, legacy, spool)
    assert code == 0 and rep["sources"][0]["requeue"] == [] and rep["sources"][0]["held"] == []
    assert (spool / "processed" / name).is_file() and not list((spool / "incoming").glob("*.json"))


def test_a_live_launchs_completion_is_left_for_its_window(trees, monkeypatch, tmp_path):
    legacy, seam, spool = trees
    s = _store()
    _seat(s)
    r = _reserve(s)
    gov, deleg = _deleg()
    name = _archived_noop(s, spool, gov, deleg, r, "completed", tmp_path / "wrong-tree")
    _move(monkeypatch, seam)
    code, rep = _apply(s, seam, legacy, spool, now=NOW + 60)               # the window is still open
    assert code == 0 and rep["sources"][0]["requeue"] == []
    assert (spool / "processed" / name).is_file()


def test_an_expired_launch_without_a_completion_is_held(trees, monkeypatch):
    legacy, seam, spool = trees
    s = _store()
    _seat(s)
    r = _reserve(s)
    for sub in ("incoming", "working", "processed", "rejected"):
        (spool / sub).mkdir(parents=True)
    _move(monkeypatch, seam)
    code, rep = _apply(s, seam, legacy, spool)
    src = rep["sources"][0]
    assert code == 1 and src["status"] == "migrated"                       # committed, and listed for the owner
    assert src["held"] == [{"slug": r["slug"], "nonce": r["nonce"], "why": "no archived completion"}]
    assert sm.held_launches(seam) == {(r["slug"], r["nonce"])}
    assert _avail(s) == 70                                                  # still debited: no money moved


def test_a_held_launch_is_never_settled_by_the_sweep(trees, monkeypatch):
    legacy, seam, spool = trees
    s = _store()
    _seat(s)
    r = _reserve(s)
    for sub in ("incoming", "working", "processed", "rejected"):
        (spool / sub).mkdir(parents=True)
    _move(monkeypatch, seam)
    assert _apply(s, seam, legacy, spool)[0] == 1
    gate = LaunchGate(s)
    for apply in (False, True):
        out = ops_sweeps.sweep_abandoned_reservations(gate, now=LATE + 90_000, ttl_s=50, apply=apply,
                                                      completion_spool=str(spool))
        rows = [x for x in out["items"] if x["slug"] == r["slug"]]
        assert [x["status"] for x in rows] == ["legacy_hold"], out
    assert _avail(s) == 70 and not is_lease_settled(str(seam), r["slug"], r["nonce"])


def test_the_scan_checkpoint_is_removed(trees, monkeypatch, tmp_path):
    legacy, seam, spool = trees
    s = _store()
    _seat(s)
    r = _reserve(s)
    gov, deleg = _deleg()
    _archived_noop(s, spool, gov, deleg, r, "completed", tmp_path / "wrong-tree")
    (spool / ".settle-scan.json").write_text("{}")
    _move(monkeypatch, seam)
    assert _apply(s, seam, legacy, spool)[0] == 0
    assert not (spool / ".settle-scan.json").exists()


def test_a_checkpoint_from_another_seam_is_not_continued(tmp_path, monkeypatch):
    """The checkpoint carries the real path of the seam its pass listed: another seam is one full read."""
    from sigil import settle_checkpoint as sc
    from sigil.governor import launch_settlement as ls
    from sigil.spine.store import SpineStore
    store = SpineStore(tmp_path / "spine.jsonl")
    store.append(kind="event", source="x", actor="y", payload={"a": 1})
    pub = ensure_owner_keypair().public_key_b64
    starts: "list[int]" = []
    real = ls.scan_settlements_since

    def _spy(*a, **k):
        starts.append(k.get("since_seq"))
        return real(*a, **k)
    monkeypatch.setattr(ls, "scan_settlements_since", _spy)
    kw = dict(keys=[("org", "cust_a", "n")], path=tmp_path / ".settle-scan.json", scope="*", listed_from=0,
              listing_clean=True, now=100.0)
    sc.scan(store, pub, seam=str(tmp_path / "seam-a"), **kw)
    sc.scan(store, pub, seam=str(tmp_path / "seam-a"), **kw)
    sc.scan(store, pub, seam=str(tmp_path / "seam-b"), **kw)
    assert starts[0] == -1 and starts[1] != -1 and starts[2] == -1         # full, continued, full again


def test_a_held_launch_a_later_launch_superseded_is_never_released(trees, monkeypatch):
    legacy, seam, spool = trees
    s = _store()
    _seat(s, credits=200)
    r = _reserve(s)
    for sub in ("incoming", "working", "processed", "rejected"):
        (spool / sub).mkdir(parents=True)
    _move(monkeypatch, seam)
    assert _apply(s, seam, legacy, spool)[0] == 1                          # held for the owner
    later = _reserve(s, now=LATE + 10)                                     # a later launch replaces it on the seam
    assert later["nonce"] != r["nonce"]
    gate = LaunchGate(s)
    for apply in (False, True):
        out = ops_sweeps.sweep_superseded_reservations(gate, now=LATE + 700_000, ttl_s=50, apply=apply,
                                                       completion_spool=str(spool))
        rows = [x for x in out["items"] if x["nonce"] == r["nonce"]]
        assert [x["status"] for x in rows] == ["legacy_hold"], out
    assert not is_lease_settled(str(seam), r["slug"], r["nonce"])


def test_a_completion_is_requeued_only_once_its_lease_is_on_the_seam(trees, monkeypatch, tmp_path):
    legacy, seam, spool = trees
    s = _store()
    _seat(s)
    r = _reserve(s)
    gov, deleg = _deleg()
    _archived_noop(s, spool, gov, deleg, r, "completed", tmp_path / "wrong-tree")
    _move(monkeypatch, seam)
    seen = []

    def _at(label):
        if label.startswith("requeue:"):
            seen.append(read_credit_lease(str(seam), r["slug"]) is not None)
    monkeypatch.setattr(seam_migrate, "_fault", _at)
    assert _apply(s, seam, legacy, spool)[0] == 0
    assert seen == [True]                                                  # the drain will always find the lease


def test_a_settled_launch_with_its_bundle_left_keeps_its_completion_archived(trees, monkeypatch, tmp_path):
    """Settled on the spine (a refund) while its bundle is still in the former tree: never requeued."""
    legacy, seam, spool = trees
    s = _store()
    _seat(s)
    r = _reserve(s)
    gov, deleg = _deleg()
    name = _archived_noop(s, spool, gov, deleg, r, "canceled", tmp_path / "wrong-tree")
    monkeypatch.setenv("VIGIL_BASE_DIR", str(tmp_path / "third-tree"))
    assert _settle(s, r, 0)["refunded"] == 30                              # settled; the former tree keeps the bundle
    assert read_credit_lease(str(legacy), r["slug"]) is not None
    _move(monkeypatch, seam)
    code, rep = _apply(s, seam, legacy, spool)
    assert code == 0 and rep["sources"][0]["leases"][0]["state"] == "settled"
    assert rep["sources"][0]["requeue"] == [] and (spool / "processed" / name).is_file()
    assert _avail(s) == 100
