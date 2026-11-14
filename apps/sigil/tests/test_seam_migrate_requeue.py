"""`sigil seam migrate --apply` — an expired launch's archived completion reaches the settle drain again.

A completion the settle drain archived as a no-op because it read another directory than the one the cockpit
published the lease in (``processed/``) is handed back to the drain (``incoming/``) once the lease is on the seam: the
drain verifies it under its delegation and settles the launch on the seam at the completion's outcome — completed is
charged, canceled or failed is refunded. Every UNSETTLED legacy launch's completion is selected, whether its window was
still open when the migration ran or had closed, so a run that ended is settled at its outcome exactly once whenever
the upgrade happens; a settled launch's completion stays archived. An expired, unsettled launch with no completion
anywhere in the spool is HELD for the owner, and so is every unsettled launch without a completion found when the spool
is absent, is not laid out as the settle drain's spool, or cannot be read in full: both reservation sweeps report it
``legacy_hold`` and never settle it. The drain's scan checkpoint is removed (the next pass reads the whole spine), and a
checkpoint naming another seam is never continued. `sigil seam migrate` reads the spool the configured settle drain
drains (its unit, drop-ins and env file) and refuses a spool named on the command line that is not that one.

Sovereign leg: PYTHONPATH=apps/sigil:integration:packages/core/vigil_core.

Mutation-verify targets (each neuter reds a NAMED test here):
  * requeue before the lease is on the seam                 -> test_a_completed_launch_is_charged_through_its_requeued_completion
  * a settled launch's completion requeued                  -> test_a_settled_launchs_completion_stays_archived
  * only an expired launch's completion requeued            -> test_a_live_launchs_archived_completion_is_requeued_and_charged
  * the report plans only an expired launch's requeue        -> test_the_report_lists_a_live_launchs_archived_completion
  * a live launch held while the spool was read in full     -> test_a_live_launchs_archived_completion_is_requeued_and_charged
  * an unreadable spool not holding a live launch           -> test_a_live_launch_is_held_when_the_spool_cannot_be_read
  * legacy_hold not honoured by the sweep                    -> test_a_held_launch_is_never_settled_by_the_sweep
  * the scan checkpoint kept                                 -> test_the_scan_checkpoint_is_removed
  * the checkpoint's seam identity dropped                   -> test_a_checkpoint_from_another_seam_is_not_continued
  * a directory that is not the drain's spool read as clean  -> test_a_directory_that_is_not_the_drains_spool_holds_every_unsettled_launch
  * any one drain subdirectory taken for the spool          -> test_a_directory_that_is_not_the_drains_spool_holds_every_unsettled_launch
  * the report not holding what --apply holds                -> test_the_report_holds_what_the_apply_holds
  * a quarantined completion not counted as waiting          -> test_a_launch_with_a_quarantined_completion_is_neither_requeued_nor_held
  * the CLI ignoring the drain unit's spool (drop-in)        -> test_the_cli_reads_the_spool_the_configured_drain_drains
  * a named spool that is not the drain's accepted          -> test_the_cli_refuses_a_spool_that_is_not_the_drains
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


@pytest.mark.parametrize("outcome,refund", [("completed", 0), ("canceled", 30)])
def test_a_live_launchs_archived_completion_is_requeued_and_charged(trees, monkeypatch, tmp_path, outcome, refund):
    """The run ended (its completion archived as a no-op by a drain that read another directory) while its window was
    still open at the upgrade: the completion is requeued, the drain settles it on the seam at its outcome, and the
    abandoned sweep after the window finds it settled — charged exactly once, whenever the migration ran."""
    legacy, seam, spool = trees
    s = _store()
    _seat(s)
    r = _reserve(s)
    gov, deleg = _deleg()
    name = _archived_noop(s, spool, gov, deleg, r, outcome, tmp_path / "wrong-tree")
    _move(monkeypatch, seam)
    code, rep = _apply(s, seam, legacy, spool, now=NOW + 60)               # the window is still open
    src = rep["sources"][0]
    assert code == 0 and src["leases"][0]["state"] == "live", rep
    assert src["requeue"] == [name] and src["held"] == []
    assert (spool / "incoming" / name).is_file() and not (spool / "processed" / name).exists()
    assert _drain(s, spool, deleg, seam, now=NOW + 120)["settled"] == 1
    assert _avail(s) == 70 + refund and is_lease_settled(str(seam), r["slug"], r["nonce"])
    gate = LaunchGate(s)
    out = ops_sweeps.sweep_abandoned_reservations(gate, now=LATE + 90_000, ttl_s=50, apply=True,
                                                  completion_spool=str(spool))
    assert [x for x in out["items"] if x["slug"] == r["slug"]] == [], out
    assert _drain(s, spool, deleg, seam, now=LATE + 90_100)["settled"] == 0
    assert _avail(s) == 70 + refund                                        # exactly once


def test_the_report_lists_a_live_launchs_archived_completion(trees, monkeypatch, tmp_path):
    """Report-only shows the requeue --apply will make for a launch whose window is still open; nothing moves."""
    legacy, seam, spool = trees
    s = _store()
    _seat(s)
    r = _reserve(s)
    gov, deleg = _deleg()
    name = _archived_noop(s, spool, gov, deleg, r, "completed", tmp_path / "wrong-tree")
    _move(monkeypatch, seam)
    code, rep = seam_migrate.run(s, ensure_owner_keypair(), seam=seam, sources=[str(legacy)], spool=spool,
                                 apply=False, now=NOW + 60)
    assert code == 0 and rep["sources"][0]["requeue"] == [name] and rep["sources"][0]["held"] == []
    assert (spool / "processed" / name).is_file() and not list((spool / "incoming").glob("*.json"))


def test_a_live_launch_with_no_completion_is_neither_requeued_nor_held(trees, monkeypatch):
    """A run still going at the upgrade: nothing to requeue, nothing held — its completion reaches the drain on the
    seam, where its lease now is."""
    legacy, seam, spool = trees
    s = _store()
    _seat(s)
    r = _reserve(s)
    for sub in ("incoming", "working", "processed", "rejected"):
        (spool / sub).mkdir(parents=True)
    _move(monkeypatch, seam)
    code, rep = _apply(s, seam, legacy, spool, now=NOW + 60)
    assert code == 0 and rep["sources"][0]["requeue"] == [] and rep["sources"][0]["held"] == []
    assert sm.held_launches(seam) == set() and read_credit_lease(str(seam), r["slug"]) is not None


@pytest.mark.parametrize("damage", ["unreadable_archive", "unlistable_archive", "no_spool"])
def test_a_live_launch_is_held_when_the_spool_cannot_be_read(trees, monkeypatch, tmp_path, damage):
    """An archived completion the migration cannot read (or no spool to read) could be this launch's: held for the
    owner, never left for the abandoned sweep to refund."""
    legacy, seam, spool = trees
    s = _store()
    _seat(s)
    r = _reserve(s)
    for sub in ("incoming", "working", "processed", "rejected"):
        (spool / sub).mkdir(parents=True)
    if damage == "unreadable_archive":
        (spool / "processed" / ("0" * 64 + ".json")).write_text("{truncated")
    if damage == "unlistable_archive":
        real = seam_migrate._spool_names

        def _names(d):
            if d.name == "processed":
                raise PermissionError(13, "Permission denied", str(d))
            return real(d)
        monkeypatch.setattr(seam_migrate, "_spool_names", _names)
    _move(monkeypatch, seam)
    code, rep = _apply(s, seam, legacy, tmp_path / "no-such-spool" if damage == "no_spool" else spool, now=NOW + 60)
    src = rep["sources"][0]
    assert code == 1 and src["status"] == "migrated" and src["requeue"] == []
    assert [(h["slug"], h["nonce"]) for h in src["held"]] == [(r["slug"], r["nonce"])]
    assert sm.held_launches(seam) == {(r["slug"], r["nonce"])}
    gate = LaunchGate(s)
    out = ops_sweeps.sweep_abandoned_reservations(gate, now=LATE + 90_000, ttl_s=50, apply=True,
                                                  completion_spool=str(spool))
    assert [x["status"] for x in out["items"] if x["slug"] == r["slug"]] == ["legacy_hold"], out
    assert _avail(s) == 70


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


@pytest.mark.parametrize("window", ["open", "closed"])
@pytest.mark.parametrize("where", ["empty_dir", "spool_parent", "partial_layout"])
def test_a_directory_that_is_not_the_drains_spool_holds_every_unsettled_launch(trees, monkeypatch, tmp_path, window,
                                                                               where):
    """The migration is handed a directory that is not the settle drain's completion spool (an empty directory, or
    the spool's parent): an archived completion of any unsettled launch cannot be ruled out, so every one is HELD for
    the owner — never left for the abandoned sweep to refund a run that completed — and nothing is written there. A
    directory with only some of the drain's subdirectories was never laid out by the drain: not its spool either."""
    legacy, seam, spool = trees
    s = _store()
    _seat(s)
    r = _reserve(s)
    gov, deleg = _deleg()
    name = _archived_noop(s, spool, gov, deleg, r, "completed", tmp_path / "wrong-tree")   # the real spool's archive
    wrong = spool.parent if where == "spool_parent" else tmp_path / "not-a-spool"
    wrong.mkdir(exist_ok=True)
    if where == "partial_layout":
        for sub in ("incoming", "processed"):
            (wrong / sub).mkdir()
    before = sorted(p.name for p in wrong.iterdir())
    _move(monkeypatch, seam)
    for apply in (False, True):
        code, rep = seam_migrate.run(s, ensure_owner_keypair(), seam=seam, sources=[str(legacy)], spool=wrong,
                                     apply=apply, now=NOW + 60 if window == "open" else LATE)
        src = rep["sources"][0]
        assert code == (1 if apply else 0) and src["requeue"] == [], rep
        assert [(h["slug"], h["nonce"]) for h in src["held"]] == [(r["slug"], r["nonce"])]
        assert "is not the settle drain's completion spool" in src["held"][0]["why"]
    assert sm.held_launches(seam) == {(r["slug"], r["nonce"])}
    assert sorted(p.name for p in wrong.iterdir()) == before                # no lock, no move, no checkpoint there
    assert (spool / "processed" / name).is_file()
    _drain(s, spool, deleg, seam, now=LATE + 10)
    out = ops_sweeps.sweep_abandoned_reservations(LaunchGate(s), now=LATE + 90_000, ttl_s=50, apply=True,
                                                  completion_spool=str(spool))
    assert [x["status"] for x in out["items"] if x["slug"] == r["slug"]] == ["legacy_hold"], out
    assert _avail(s) == 70 and not is_lease_settled(str(seam), r["slug"], r["nonce"])     # still debited: held


@pytest.mark.parametrize("where", ["no_spool", "not_a_spool"])
def test_the_report_holds_what_the_apply_holds(trees, monkeypatch, tmp_path, where):
    """Report-only lists a live launch as held for an absent spool, or a directory that is not the drain's spool,
    exactly as --apply then holds it."""
    legacy, seam, _ = trees
    s = _store()
    _seat(s)
    r = _reserve(s)
    spool = tmp_path / "no-such-spool"
    if where == "not_a_spool":
        spool.mkdir()
    _move(monkeypatch, seam)
    seen = []
    for apply in (False, True):
        code, rep = seam_migrate.run(s, ensure_owner_keypair(), seam=seam, sources=[str(legacy)], spool=spool,
                                     apply=apply, now=NOW + 60)
        seen.append([(h["slug"], h["nonce"], h["why"]) for h in rep["sources"][0]["held"]])
    why = ("no completion spool to inspect" if where == "no_spool" else
           f"{spool} is not the settle drain's completion spool")
    assert seen == [[(r["slug"], r["nonce"], why)]] * 2


def test_a_launch_with_a_quarantined_completion_is_neither_requeued_nor_held(trees, monkeypatch, tmp_path):
    """A live launch whose completion sits in rejected/ (quarantined: the drain's unit stays failed until the operator
    clears it) besides an archived copy in processed/ is left to the drain and the operator: nothing is requeued,
    nothing held, and the abandoned sweep refunds nothing while the quarantined completion is there."""
    legacy, seam, spool = trees
    s = _store()
    _seat(s)
    r = _reserve(s)
    gov, deleg = _deleg()
    name = _archived_noop(s, spool, gov, deleg, r, "completed", tmp_path / "wrong-tree")
    (spool / "rejected" / name).write_bytes((spool / "processed" / name).read_bytes())
    _move(monkeypatch, seam)
    code, rep = _apply(s, seam, legacy, spool, now=NOW + 60)
    src = rep["sources"][0]
    assert code == 0 and src["requeue"] == [] and src["held"] == [], rep
    assert (spool / "processed" / name).is_file() and not list((spool / "incoming").glob("*.json"))
    out = ops_sweeps.sweep_abandoned_reservations(LaunchGate(s), now=LATE + 90_000, ttl_s=50, apply=True,
                                                  completion_spool=str(spool))
    assert [x["status"] for x in out["items"] if x["slug"] == r["slug"]] == ["completion_pending"], out
    assert _avail(s) == 70


def _cli_host(monkeypatch, tmp_path, spool, *, dropin: bool, unit: bool = True):
    """A test HOME with the shipped settle-drain unit installed (``unit``); ``dropin``: its spool set by a drop-in."""
    import shutil
    from pathlib import Path
    home = tmp_path / "home-cli"
    d = home / ".config" / "systemd" / "user"
    d.mkdir(parents=True)
    repo = Path(__file__).resolve().parents[3]
    if unit:
        shutil.copy(repo / "infra/systemd/vigil-settle-drain.service", d / "vigil-settle-drain.service")
    if unit and dropin:
        (d / "vigil-settle-drain.service.d").mkdir()
        (d / "vigil-settle-drain.service.d" / "spool.conf").write_text(
            f"[Service]\nEnvironment=VIGIL_SETTLE_SPOOL={spool}\n")
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.delenv("VIGIL_SETTLE_SPOOL", raising=False)


def _cli_exit(monkeypatch, store, tmp_path, argv) -> int:
    from sigil import cli, config
    monkeypatch.setattr(cli, "SpineStore", lambda *a, **k: store)
    monkeypatch.setattr(config, "SPINE_PATH", tmp_path / "default-spine" / "spine.jsonl")
    with pytest.raises(SystemExit) as ex:
        cli.main(argv)
    return int(ex.value.code or 0)


def test_the_cli_reads_the_spool_the_configured_drain_drains(trees, monkeypatch, tmp_path, capsys):
    """The drain's spool is set by a drop-in: `sigil seam migrate --apply` reads THAT spool (what systemd gives the
    drain), so the archived completion is requeued and settled at its outcome — never held, never refunded."""
    legacy, seam, spool = trees
    s = _store()
    _seat(s)
    r = _reserve(s)
    gov, deleg = _deleg()
    name = _archived_noop(s, spool, gov, deleg, r, "completed", tmp_path / "wrong-tree")
    _cli_host(monkeypatch, tmp_path, spool, dropin=True)
    _move(monkeypatch, seam)
    argv = ["seam", "migrate", "--from", str(legacy), "--to", str(seam), "--apply", "--json"]
    assert _cli_exit(monkeypatch, s, tmp_path, argv) == 0, capsys.readouterr().err
    src = __import__("json").loads(capsys.readouterr().out)["sources"][0]
    assert src["requeue"] == [name] and src["held"] == []
    assert _drain(s, spool, deleg, seam, now=NOW + 120)["settled"] == 1
    assert _avail(s) == 70 and is_lease_settled(str(seam), r["slug"], r["nonce"])          # charged, exactly once


@pytest.mark.parametrize("named", ["not_a_spool", "not_the_units", "env_not_the_units"])
def test_the_cli_refuses_a_spool_that_is_not_the_drains(trees, monkeypatch, tmp_path, capsys, named):
    """A completion spool named on the command line (or exported) that is not laid out as the drain's spool, or is
    not the one the configured drain drains, is refused (exit 2) before anything is read or written."""
    legacy, seam, spool = trees
    s = _store()
    _seat(s)
    _reserve(s)
    for sub in seam_migrate.DRAIN_SPOOL_SUBDIRS:
        (spool / sub).mkdir(parents=True)
    other = tmp_path / ("plain-dir" if named == "not_a_spool" else "other-spool")
    other.mkdir()
    if named != "not_a_spool":
        for sub in seam_migrate.DRAIN_SPOOL_SUBDIRS:
            (other / sub).mkdir()
    _cli_host(monkeypatch, tmp_path, spool, dropin=True, unit=named != "not_a_spool")
    _move(monkeypatch, seam)
    argv = ["seam", "migrate", "--from", str(legacy), "--to", str(seam), "--apply"]
    if named == "env_not_the_units":
        monkeypatch.setenv("VIGIL_SETTLE_SPOOL", str(other))
    else:
        argv += ["--completion-spool", str(other)]
    tip = s.next_seq
    assert _cli_exit(monkeypatch, s, tmp_path, argv) == 2
    err = capsys.readouterr().err
    assert ("is not the settle drain's completion spool" if named == "not_a_spool" else "the configured settle "
            "drain drains") in err
    assert not sm.journal_path(seam).exists() and s.next_seq == tip and list(seam.iterdir()) == []
