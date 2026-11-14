"""`sigil seam migrate --apply` — every guarantee a launch-seam record carries holds on the seam after the move.

Before the move the processes resolved the former seam directory (``VIGIL_BASE_DIR`` = the legacy tree); after it
they resolve the seam the units set. ``seam migrate --apply`` carries each record class with its own rule, so:
  * a launch that COMPLETED and was settled before the move stays settled: a later cancel moves nothing;
  * a STARTED launch stays started: a cancel is refused (it settles through its completion);
  * a settled lease cannot be published again;
  * settlement / paused-past-expiry markers are the union of both trees, floors the max, a pause is carried once;
  * a differing owner-signed file or key is a conflict (nothing committed for that source);
  * the run is crash-safe: a failure at ANY write leaves the source ``applying`` and a re-run reaches exactly the
    state an uninterrupted run reaches, with one audit record.
With no former tree at all, every flow behaves exactly as before (negative control).

Sovereign leg: PYTHONPATH=apps/sigil:integration:packages/core/vigil_core.

Mutation-verify targets (each neuter reds a NAMED test here):
  * settlement markers written to the seam only, no union    -> test_a_completed_launch_stays_settled_after_the_move
  * bundles of unsettled leases not copied                  -> test_a_started_launch_stays_started_after_the_move
  * floor overwritten instead of max                        -> test_a_higher_floor_on_the_seam_is_kept
  * pauses merged by full union instead of journaled delta  -> test_a_pause_lifted_on_the_seam_is_not_reapplied
  * commit before verify / the digest re-check removed      -> test_a_former_tree_changed_during_apply_is_not_committed
  * the audit record written on every run                   -> test_one_audit_record_per_committed_source
"""
from __future__ import annotations

import json
import os
import shutil
from pathlib import Path
from typing import Any

import pytest

from sigil import seam_migrate
from sigil.governor.identity import ensure_owner_keypair
from sigil.spine.store import SpineStore
from sigil.ui.launch_gate import LaunchGate
from sigil.ui.provision import ProvisionDenied, build_provisioner
from vigil_integration import seam_migration as sm
from vigil_integration.live.credit_lease_broker import (
    is_lease_settled, read_credit_lease, record_lease_settlement, settlement_path,
)
from vigil_integration.live.credit_lease_pause import (
    clear_lease_pause, is_lease_paused, paused_past_expiry, record_lease_pause, record_paused_past_expiry,
)

from tests.test_seam_migrate import (  # type: ignore
    LATE, NOW, ORG, _avail, _move, _reserve, _seat, _settle, _store, _tree_bytes, make_trees,
)


@pytest.fixture
def trees(monkeypatch, tmp_path):
    return make_trees(monkeypatch, tmp_path)


def _apply(store, seam, legacy, *, now=LATE, spool=None):
    return seam_migrate.run(store, ensure_owner_keypair(), seam=seam, sources=[str(legacy)], spool=spool,
                            apply=True, now=now)


def _seam_state(seam):
    """The seam's records (the journal directory and its lock file are the migration's own)."""
    return {k: v for k, v in _tree_bytes(seam).items() if not k.startswith(".seam-migration/")}


def _cancel(store, r, now=LATE):
    return build_provisioner(store).launch_cancel("u", ORG, r["lease"], now=now)


# ── the money guarantees ──────────────────────────────────────────────────────────────────────────────────────

def test_a_completed_launch_stays_settled_after_the_move(trees, monkeypatch):
    legacy, seam, _ = trees
    s = _store()
    _seat(s)
    r = _reserve(s)
    assert _settle(s, r, 30)["refunded"] == 0 and _avail(s) == 70          # completed: charged; marker only
    _move(monkeypatch, seam)
    code, rep = _apply(s, seam, legacy)
    assert code == 0 and rep["sources"][0]["status"] == "migrated", rep
    out = _cancel(s, r)
    assert out["refunded"] == 0 and out.get("already_settled") is True and _avail(s) == 70


def test_a_started_launch_stays_started_after_the_move(trees, monkeypatch):
    legacy, seam, spool = trees
    s = _store()
    _seat(s)
    r = _reserve(s)                                                        # started (published), unsettled
    for sub in ("incoming", "working", "processed", "rejected"):          # the drain's spool: no completion yet
        (spool / sub).mkdir(parents=True)
    _move(monkeypatch, seam)
    assert _apply(s, seam, legacy, now=NOW + 60, spool=spool)[0] == 0
    with pytest.raises(ProvisionDenied, match="has been started"):
        _cancel(s, r, now=NOW + 120)
    assert _avail(s) == 70
    assert read_credit_lease(str(seam), r["slug"]).signed_lease.document.nonce == r["nonce"]


def test_a_settled_lease_cannot_be_published_again_after_the_move(trees, monkeypatch):
    legacy, seam, _ = trees
    s = _store()
    _seat(s)
    r = _reserve(s)
    assert _settle(s, r, 30)["ok"]
    _move(monkeypatch, seam)
    assert _apply(s, seam, legacy)[0] == 0
    out = LaunchGate(s).publish_lease(signed_lease=r["lease"], expect_org_id=ORG)
    assert not out["ok"]
    assert read_credit_lease(str(seam), r["slug"]) is None


def test_with_no_former_tree_every_flow_is_unchanged(trees, monkeypatch):
    """Negative control: nothing to carry; a cancel of a reserved, unstarted launch refunds as always."""
    legacy, seam, _ = trees
    _move(monkeypatch, seam)
    s = _store()
    _seat(s)
    shutil.rmtree(legacy)
    code, rep = seam_migrate.run(s, ensure_owner_keypair(), seam=seam, sources=[], apply=True, now=NOW)
    assert code == 0 and rep["sources"] == []
    r = _reserve(s, publish=False)
    assert _cancel(s, r, now=NOW + 60)["refunded"] == 30 and _avail(s) == 100


# ── merge rules ───────────────────────────────────────────────────────────────────────────────────────────────

def test_settlement_and_past_expiry_markers_are_the_union(trees):
    legacy, seam, _ = trees
    record_lease_settlement(str(legacy), "cust_a", "n1")
    record_lease_settlement(str(seam), "cust_a", "n2")
    record_paused_past_expiry(str(legacy), "cust_a", "p1")
    record_paused_past_expiry(str(seam), "cust_a", "p2")
    assert _apply(_store(), seam, legacy)[0] == 0
    assert all(is_lease_settled(str(seam), "cust_a", n) for n in ("n1", "n2"))
    assert paused_past_expiry(str(seam), "cust_a", "p1") and paused_past_expiry(str(seam), "cust_a", "p2")
    assert json.loads(settlement_path(str(seam), "cust_a").read_text())["nonces"] == ["n1", "n2"]


def _floor_file(tree: Path, n: int) -> None:
    from types import SimpleNamespace

    from vigil_core.highwater import advance_highwater
    advance_highwater(tree / ".credit-lease-highwater" / "cust_a.json", SimpleNamespace(entry_count=n, last_seq=n))


def test_a_lower_floor_on_the_seam_is_raised(trees):
    from vigil_core.highwater import load_highwater
    legacy, seam, _ = trees
    _floor_file(legacy, 50)
    _floor_file(seam, 10)
    assert _apply(_store(), seam, legacy)[0] == 0
    assert load_highwater(seam / ".credit-lease-highwater" / "cust_a.json")["last_seq"] == 50


def test_a_higher_floor_on_the_seam_is_kept(trees):
    from vigil_core.highwater import load_highwater
    legacy, seam, _ = trees
    _floor_file(legacy, 50)
    _floor_file(seam, 90)
    assert _apply(_store(), seam, legacy)[0] == 0
    assert load_highwater(seam / ".credit-lease-highwater" / "cust_a.json")["last_seq"] == 90


def test_a_floor_raised_on_the_seam_during_the_migration_is_never_lowered(trees, monkeypatch):
    """The offense engine may arm (raise a floor on the seam) while the migration runs: the carry is a max."""
    from vigil_core.highwater import load_highwater
    legacy, seam, _ = trees
    _floor_file(legacy, 50)
    _floor_file(seam, 10)

    def _engine_arms(label):
        if label.startswith("floor:"):
            _floor_file(seam, 90)
    monkeypatch.setattr(seam_migrate, "_fault", _engine_arms)
    assert _apply(_store(), seam, legacy)[0] == 0
    assert load_highwater(seam / ".credit-lease-highwater" / "cust_a.json")["last_seq"] == 90


def test_verify_refuses_to_commit_what_is_not_on_the_seam(trees, monkeypatch):
    from vigil_integration.live import credit_lease_broker
    legacy, seam, _ = trees
    s = _store()
    _seat(s)
    r = _reserve(s)
    assert _settle(s, r, 30)["ok"]
    monkeypatch.setattr(credit_lease_broker, "record_lease_settlement", lambda *a, **k: None)
    code, rep = _apply(s, seam, legacy)
    assert code == 1 and rep["sources"][0]["status"] == "aborted" and "verify" in rep["sources"][0]["error"]
    assert sm.read_journal(seam)["sources"][str(legacy)]["state"] == "applying"


def test_a_pause_lifted_on_the_seam_is_not_reapplied(trees):
    legacy, seam, _ = trees
    s = _store()
    record_lease_pause(str(legacy), "cust_a", "n1")
    assert _apply(s, seam, legacy)[0] == 0
    assert is_lease_paused(str(seam), "cust_a", "n1")
    clear_lease_pause(str(seam), "cust_a", "n1")                          # the customer resumed on the seam
    record_lease_settlement(str(legacy), "cust_b", "x")                    # the former tree drifted
    assert sm.unmigrated_legacy(seam, [str(legacy)])[0]["reason"] == "changed_since"
    assert _apply(s, seam, legacy)[0] == 0
    assert not is_lease_paused(str(seam), "cust_a", "n1")                 # never paused again by a re-run
    assert is_lease_settled(str(seam), "cust_b", "x")
    assert sm.unmigrated_legacy(seam, [str(legacy)]) == []


def test_the_governance_key_is_copied_when_absent(trees):
    legacy, seam, _ = trees
    (legacy / "offense-governance.key").write_bytes(b"sealed-key-bytes")
    os.chmod(legacy / "offense-governance.key", 0o600)
    assert _apply(_store(), seam, legacy)[0] == 0
    assert (seam / "offense-governance.key").read_bytes() == b"sealed-key-bytes"
    assert oct((seam / "offense-governance.key").stat().st_mode & 0o777) == "0o600"


def test_a_differing_governance_key_is_a_conflict_and_nothing_is_committed(trees):
    legacy, seam, _ = trees
    s = _store()
    (legacy / "offense-governance.key").write_bytes(b"legacy-key")
    (seam / "offense-governance.key").write_bytes(b"seam-key")
    record_lease_settlement(str(legacy), "cust_a", "n1")
    before, tip = _seam_state(seam), s.next_seq
    code, rep = _apply(s, seam, legacy)
    assert code == 1 and rep["sources"][0]["status"] == "conflict"
    assert _seam_state(seam) == before and s.next_seq == tip               # nothing carried, no record
    assert not sm.journal_path(seam).exists() or not (sm.read_journal(seam) or {}).get("sources")


def test_owner_state_in_the_former_tree_is_untouched_and_not_carried(trees):
    legacy, seam, _ = trees
    for name, body in (("webauthn-credentials.json", "{}"), ("cockpit-bootstrap-token", "tok")):
        (legacy / name).write_text(body)
    (legacy / "hostcmd").mkdir()
    (legacy / "hostcmd" / "x.json").write_text("{}")
    record_lease_settlement(str(legacy), "cust_a", "n1")
    before = _tree_bytes(legacy)
    assert _apply(_store(), seam, legacy)[0] == 0
    assert _tree_bytes(legacy) == before                                   # the former tree is never modified
    for name in ("webauthn-credentials.json", "cockpit-bootstrap-token", "hostcmd"):
        assert not (seam / name).exists()


# ── conflicts, refusals, records ──────────────────────────────────────────────────────────────────────────────

def test_a_newer_lease_on_the_seam_commits_nothing_and_a_rerun_is_idempotent(trees, monkeypatch):
    from sigil.ui.target_authorization import add_customer_target
    legacy, seam, _ = trees
    s = _store()
    _seat(s)
    _reserve(s)
    _move(monkeypatch, seam)
    assert add_customer_target("apme.cm", org_id=ORG, store=s, now=NOW + 50)["ok"]
    _reserve(s, now=NOW + 100)
    before = _seam_state(seam)
    for _ in range(2):
        code, rep = _apply(s, seam, legacy)
        assert code == 1 and rep["sources"][0]["status"] == "conflict"
        assert _seam_state(seam) == before


def test_running_as_root_over_service_owned_trees_is_refused(trees, monkeypatch):
    from sigil import ops_sweeps
    legacy, seam, _ = trees
    record_lease_settlement(str(legacy), "cust_a", "n1")
    monkeypatch.setattr(ops_sweeps, "root_apply_refusal", lambda *a, **k: "the seam directory is owned by uid 1000")
    ensure_owner_keypair()
    with pytest.raises(seam_migrate.MigrateRefused, match="running as root"):
        _apply(_store(), seam, legacy)
    assert list(seam.iterdir()) == []


def test_a_former_tree_changed_during_apply_is_not_committed(trees, monkeypatch):
    legacy, seam, _ = trees
    s = _store()
    record_lease_settlement(str(legacy), "cust_a", "n1")

    def _drift(label):
        if label.startswith("marker:"):
            record_lease_settlement(str(legacy), "cust_late", "z")         # a process still writing the old tree
    monkeypatch.setattr(seam_migrate, "_fault", _drift)
    code, rep = _apply(s, seam, legacy)
    assert code == 1 and rep["sources"][0]["status"] == "aborted" and "changed" in rep["sources"][0]["error"]
    assert sm.read_journal(seam)["sources"][str(legacy)]["state"] == "applying"
    assert not any((r.payload or {}).get("signal") == seam_migrate.AUDIT_SIGNAL for r in s.iter_records())


def test_one_audit_record_per_committed_source(trees):
    legacy, seam, _ = trees
    s = _store()
    record_lease_settlement(str(legacy), "cust_a", "nonce-qz-1")
    assert _apply(s, seam, legacy)[0] == 0
    assert _apply(s, seam, legacy)[1]["sources"][0]["status"] == "migrated"     # a re-run: nothing new
    recs = [r.payload for r in s.iter_records() if (r.payload or {}).get("signal") == seam_migrate.AUDIT_SIGNAL]
    assert len(recs) == 1
    p = recs[0]
    assert p["from"] == str(legacy) and p["to"] == str(seam) and p["counts"] == {"settlements": 1}
    assert not {"nonce", "nonces", "amount", "refunded"} & set(p) and p["sig"]       # no nonce, no amount
    assert "nonce-qz-1" not in json.dumps(p)
    j = sm.read_journal(seam)["sources"][str(legacy)]
    assert j["state"] == "complete" and j["inventory"]["digest"] == sm.inventory(legacy)["digest"]


# ── crash safety ──────────────────────────────────────────────────────────────────────────────────────────────

def _template(tmp: Path, monkeypatch) -> "tuple[Path, Path, Path]":
    """A legacy tree with every carried class, its spine, and a completion spool holding the archived completion of
    an expired launch (requeued) while another expired launch has none (held)."""
    from tests.test_seam_migrate_requeue import _archived_noop, _deleg  # type: ignore
    s = SpineStore(tmp / "spine.jsonl")
    legacy, spool = tmp / "legacy", tmp / "spool"
    monkeypatch.setenv("VIGIL_BASE_DIR", str(legacy))
    _seat(s)
    r1 = _reserve(s)
    assert _settle(s, r1, 30)["ok"]
    r2 = _reserve(s, now=NOW + 100)
    gov, deleg = _deleg()
    _archived_noop(s, spool, gov, deleg, r2, "completed", tmp / "wrong-tree")
    (spool / ".settle-scan.json").write_text("{}")
    record_lease_pause(str(legacy), r2["slug"], r2["nonce"])
    record_paused_past_expiry(str(legacy), "cust_old", "p1")
    _floor_file(legacy, 7)
    (legacy / "offense-governance.key").write_bytes(b"k")
    (legacy / "approval-nonces").mkdir()
    (legacy / "approval-nonces" / ("ab" * 32)).write_text("n\n")
    return legacy, tmp / "spine.jsonl", spool


def _clone(tmp: Path, legacy: Path, spine: Path, spool: Path, k: Any = "ref") -> "tuple[Path, Path, SpineStore, Path]":
    d = tmp / f"run-{k}"
    shutil.copytree(legacy, d / "legacy", symlinks=True)
    shutil.copytree(spool, d / "spool", symlinks=True)
    shutil.copy(spine, d / "spine.jsonl")
    (d / "seam").mkdir()
    return d / "legacy", d / "seam", SpineStore(d / "spine.jsonl"), d / "spool"


def _normalized(seam: Path, legacy: Path, spool: Path) -> "tuple[dict, dict, dict]":
    tree = {k: v for k, v in _tree_bytes(seam).items() if not k.startswith(".seam-migration/")}
    j = sm.read_journal(seam)
    src = j["sources"][os.path.realpath(legacy)]
    src = {k: v for k, v in src.items() if k not in ("started_at", "completed_at")}
    return tree, src, {k: v for k, v in _tree_bytes(spool).items() if not k.endswith(".lock")}


def test_a_failure_at_any_write_is_finished_by_a_rerun(tmp_path, monkeypatch, trees):
    tmpl = tmp_path / "tmpl"
    tmpl.mkdir()
    legacy0, spine0, spool0 = _template(tmpl, monkeypatch)
    ref_l, ref_d, ref_s, ref_sp = _clone(tmp_path, legacy0, spine0, spool0)
    labels: "list[str]" = []
    monkeypatch.setattr(seam_migrate, "_fault", labels.append)
    code, rep = _apply(ref_s, ref_d, ref_l, spool=ref_sp)
    assert code == 0 and len(rep["sources"][0]["requeue"]) == 1, rep          # the expired launch is requeued
    ref = _normalized(ref_d, ref_l, ref_sp)
    assert any(x.startswith("requeue:") for x in labels) and "checkpoint" in labels, labels
    for k in range(len(labels)):
        lk, dk, sk, spk = _clone(tmp_path, legacy0, spine0, spool0, k)
        calls = {"n": 0}

        def _boom(label, _k=k, _c=calls):
            _c["n"] += 1
            if _c["n"] == _k + 1:
                raise OSError(f"injected at {label}")
        monkeypatch.setattr(seam_migrate, "_fault", _boom)
        code, rep = _apply(sk, dk, lk, spool=spk)
        assert code == 1 and rep["sources"][0]["status"] == "aborted" and "injected" in rep["sources"][0]["error"]
        j = sm.read_journal(dk) if sm.journal_path(dk).exists() else None
        assert j is None or j["sources"][os.path.realpath(lk)]["state"] == "applying"
        monkeypatch.setattr(seam_migrate, "_fault", lambda label: None)
        _apply(sk, dk, lk, spool=spk)
        got = _normalized(dk, lk, spk)
        assert got[0] == ref[0], labels[k]
        assert got[1] == ref[1], labels[k]
        assert got[2] == ref[2], labels[k]
        audits = [r for r in sk.iter_records() if (r.payload or {}).get("signal") == seam_migrate.AUDIT_SIGNAL]
        assert len(audits) == 1, labels[k]


def test_no_settle_interleaves_with_the_migration(trees, monkeypatch):
    """The migration holds the settle lock from its re-plan to its commit: a settle in between is told to retry."""
    legacy, seam, _ = trees
    s = _store()
    _seat(s)
    r = _reserve(s)
    monkeypatch.setenv("VIGIL_SETTLE_LOCK_WAIT_S", "0.2")
    _move(monkeypatch, seam)
    got = []

    def _concurrent_settle(label):
        if label.startswith("copy:credit-launch-leases/"):
            got.append(LaunchGate(s).settle_launch(signed_lease=r["lease"], consumed_units=0, now=LATE))
    monkeypatch.setattr(seam_migrate, "_fault", _concurrent_settle)
    assert _apply(s, seam, legacy)[0] == 1                                 # migrated; the expired launch is held
    assert len(got) == 1 and got[0]["ok"] is False and got[0].get("retry") is True, got
    assert _avail(s) == 70                                                  # nothing moved


def test_an_unreadable_pause_marker_on_the_seam_is_a_conflict(trees):
    """A pause marker the seam cannot read holds every launch of its slug; it is never overwritten by a carry."""
    legacy, seam, _ = trees
    record_lease_pause(str(legacy), "cust_a", "n1")
    (seam / "credit-lease-pauses").mkdir()
    (seam / "credit-lease-pauses" / "cust_a.json").write_text("{corrupt")
    code, rep = _apply(_store(), seam, legacy)
    assert code == 1 and rep["sources"][0]["status"] == "conflict"
    assert (seam / "credit-lease-pauses" / "cust_a.json").read_text() == "{corrupt"
