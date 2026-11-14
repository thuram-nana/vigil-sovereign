"""`sigil seam migrate --apply` commits only what it verified on the seam, carries a model grant only for a live launch,
and hands completions to the drain only under the spool lock.

Each guarantee here is checked on its own (no other check backs it up in the scenario):
  * the seam holding a later launch's lease for a SETTLED legacy launch is no conflict: the source commits;
  * a model grant is carried only for a live, unsettled legacy launch (never a settled launch's or a slug without one);
  * a file that appears on the seam with other bytes while it is being carried aborts the commit (the source stays
    ``applying``; a re-run finishes it);
  * a carried file whose seam copy changed before VERIFY aborts the commit;
  * a single-use floor missing on the seam at VERIFY aborts the commit;
  * a launch whose completion is already waiting for the drain is not requeued again;
  * an archived completion moves back to the drain only while the requeue holds the spool lock.

Sovereign leg: PYTHONPATH=apps/sigil:integration:packages/core/vigil_core.

Mutation-verify targets (each neuter reds a NAMED test here):
  * a settled legacy slug's later seam lease made a conflict -> test_a_later_lease_for_a_settled_legacy_launch_commits
  * the model-grant live filter dropped                       -> test_a_model_grant_is_carried_only_for_a_live_launch
  * the copy "differs" abort dropped                          -> test_a_file_appearing_on_the_seam_during_the_copy_aborts
  * the carried-bytes verify dropped                          -> test_a_carried_file_changed_on_the_seam_aborts
  * the floor verify dropped                                  -> test_a_floor_missing_on_the_seam_at_verify_aborts
  * the requeue's pending exclusion dropped                   -> test_a_completion_already_waiting_is_not_requeued
  * the requeue's spool lock dropped                          -> test_the_requeue_moves_completions_under_the_spool_lock
"""
from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from sigil import seam_migrate
from vigil_integration import seam_migration as sm
from vigil_integration.jobs.completion_signal import emit_completion_signal
from vigil_integration.live.credit_lease_broker import read_credit_lease, record_lease_settlement

from tests.test_seam_migrate import NOW, _move, _reserve, _seat, _settle, _store, make_trees  # type: ignore
from tests.test_seam_migrate_requeue import _apply, _archived_noop, _deleg  # type: ignore


@pytest.fixture
def trees(monkeypatch, tmp_path):
    return make_trees(monkeypatch, tmp_path)


def _aborted(rep, seam, legacy, why: str) -> None:
    src = rep["sources"][0]
    assert src["status"] == "aborted" and why in src["error"], src
    assert sm.read_journal(seam)["sources"][str(legacy)]["state"] == "applying"


def test_a_later_lease_for_a_settled_legacy_launch_commits(trees, monkeypatch, tmp_path):
    """The legacy bundle is of a launch settled (on the spine) elsewhere; the seam holds a later launch's lease for the
    same target: nothing to decide — the source commits and the seam keeps the later lease."""
    legacy, seam, _ = trees
    s = _store()
    _seat(s)
    old = _reserve(s)                                                      # published in the former tree
    monkeypatch.setenv("VIGIL_BASE_DIR", str(tmp_path / "third-tree"))
    assert _settle(s, old, 0)["refunded"] == 30                            # settled; the former tree keeps the bundle
    _move(monkeypatch, seam)
    rel = _target_authorization(legacy)                                    # the same authorization on the seam
    (seam / rel).parent.mkdir(parents=True)
    shutil.copyfile(legacy / rel, seam / rel)
    new = _reserve(s, now=NOW + 100)                                       # a later launch published on the seam
    code, rep = _apply(s, seam, legacy, None)
    src = rep["sources"][0]
    assert code == 0 and src["status"] == "migrated" and src["conflicts"] == [], src
    assert src["leases"] == [{"slug": old["slug"], "nonce": old["nonce"], "state": "settled",
                              "action": "superseded_settled"}]
    assert read_credit_lease(str(seam), new["slug"]).signed_lease.document.nonce == new["nonce"]


@pytest.mark.parametrize("which", ["live", "settled_nonce", "no_lease"])
def test_a_model_grant_is_carried_only_for_a_live_launch(trees, monkeypatch, tmp_path, which):
    legacy, seam, spool = trees
    for sub in ("incoming", "working", "processed", "rejected"):
        (spool / sub).mkdir(parents=True)
    s = _store()
    _seat(s, credits=200)
    first = _reserve(s)
    assert _settle(s, first, 30)["ok"]                                     # an earlier launch, settled
    live = _reserve(s, now=NOW + 100)                                      # the target's current, live launch
    slug, nonce = {"live": (live["slug"], live["nonce"]), "settled_nonce": (live["slug"], first["nonce"]),
                   "no_lease": ("cust_without_a_lease", live["nonce"])}[which]
    grants = legacy / "model-grants"
    grants.mkdir()
    (grants / f"{slug}.json").write_text(json.dumps({"nonce": nonce, "engagement_slug": slug}))
    _move(monkeypatch, seam)
    code, rep = _apply(s, seam, legacy, spool, now=NOW + 200)
    assert code == 0 and rep["sources"][0]["status"] == "migrated", rep
    carried = (seam / "model-grants" / f"{slug}.json").is_file()
    assert carried is (which == "live")


def _target_authorization(legacy: Path) -> str:
    (rel,) = [str(p.relative_to(legacy)) for p in (legacy / "target-authorizations").glob("*.json")]
    return rel


def test_a_file_appearing_on_the_seam_during_the_copy_aborts(trees, monkeypatch):
    legacy, seam, _ = trees
    s = _store()
    _seat(s)                                                               # an owner-signed target authorization
    rel = _target_authorization(legacy)
    _move(monkeypatch, seam)

    def _race(label):
        if label == f"copy:{rel}":
            (seam / rel).parent.mkdir(parents=True, exist_ok=True)
            (seam / rel).write_text('{"another": "authorization"}')       # written on the seam meanwhile
    monkeypatch.setattr(seam_migrate, "_fault", _race)
    code, rep = _apply(s, seam, legacy, None)
    assert code == 1
    _aborted(rep, seam, legacy, "appeared on the seam with different content")


def test_a_carried_file_changed_on_the_seam_aborts(trees, monkeypatch):
    """Already on the seam with the former directory's bytes at PLAN (nothing to copy), then changed before VERIFY."""
    legacy, seam, _ = trees
    s = _store()
    _seat(s)
    rel = _target_authorization(legacy)
    (seam / rel).parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(legacy / rel, seam / rel)
    _move(monkeypatch, seam)

    def _change(label):
        if label == "journal:applying":
            (seam / rel).write_text('{"changed": true}')
    monkeypatch.setattr(seam_migrate, "_fault", _change)
    code, rep = _apply(s, seam, legacy, None)
    assert code == 1
    _aborted(rep, seam, legacy, "is not on the seam with the former directory's content")


def test_a_floor_missing_on_the_seam_at_verify_aborts(trees, monkeypatch):
    from types import SimpleNamespace

    from vigil_core.highwater import advance_highwater
    legacy, seam, _ = trees
    floor = Path(".credit-lease-highwater") / "cust_a.json"
    advance_highwater(legacy / floor, SimpleNamespace(entry_count=50, last_seq=50))
    record_lease_settlement(str(legacy), "cust_a", "n1")                   # a write after the floor is raised

    def _lose(label):
        if label.startswith("marker:"):
            (seam / floor).unlink()
    monkeypatch.setattr(seam_migrate, "_fault", _lose)
    code, rep = _apply(_store(), seam, legacy, None)
    assert code == 1
    _aborted(rep, seam, legacy, "below the former directory's")


def test_a_completion_already_waiting_is_not_requeued(trees, monkeypatch, tmp_path):
    """The drain already has a completion for the launch in incoming/: the archived one stays archived."""
    legacy, seam, spool = trees
    s = _store()
    _seat(s)
    r = _reserve(s)
    gov, deleg = _deleg()
    name = _archived_noop(s, spool, gov, deleg, r, "completed", tmp_path / "wrong-tree")
    emit_completion_signal(engagement_slug=r["slug"], nonce=r["nonce"], outcome="canceled",
                           signers=[("gov", gov.private_key_b64)], spool_dir=str(spool))
    waiting = sorted(p.name for p in (spool / "incoming").glob("*.json"))
    assert len(waiting) == 1
    _move(monkeypatch, seam)
    code, rep = _apply(s, seam, legacy, spool)
    src = rep["sources"][0]
    assert code == 0 and src["requeue"] == [] and src["held"] == [], src
    assert (spool / "processed" / name).is_file()
    assert sorted(p.name for p in (spool / "incoming").glob("*.json")) == waiting


def test_the_requeue_moves_completions_under_the_spool_lock(trees, monkeypatch, tmp_path):
    from vigil_integration.live import seam_lock
    legacy, seam, spool = trees
    s = _store()
    _seat(s)
    r = _reserve(s)
    gov, deleg = _deleg()
    name = _archived_noop(s, spool, gov, deleg, r, "completed", tmp_path / "wrong-tree")
    _move(monkeypatch, seam)
    held: "list[str]" = []
    real = seam_lock.locked_file

    class _Spy:
        def __init__(self, path, **kw):
            self._cm, self._name = real(path, **kw), Path(path).name

        def __enter__(self):
            out = self._cm.__enter__()
            held.append(self._name)
            return out

        def __exit__(self, *exc):
            held.remove(self._name)
            return self._cm.__exit__(*exc)
    monkeypatch.setattr(seam_lock, "locked_file", _Spy)
    seen: "list[bool]" = []

    def _at(label):
        if label.startswith("requeue:"):
            seen.append(".spool.lock" in held)
    monkeypatch.setattr(seam_migrate, "_fault", _at)
    code, rep = _apply(s, seam, legacy, spool)
    assert code == 0 and rep["sources"][0]["requeue"] == [name]
    assert seen == [True] and ".spool.lock" not in held
